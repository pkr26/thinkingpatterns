#!/usr/bin/env python3
"""Run isolated complete-file mutation shards with frozen inputs and baselines.

python3 web/tools/run-mutation-shards.py 4 --include-data
Normal dependencies/source stay unchanged. An isolated runner installs exact
Vitest 4.1.10; --runner-node-modules can reuse a verified runner. First-pass
survivors still require broader behavioral replay and causal review.
"""
import argparse
import concurrent.futures
import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = {"src/brain/lexicon.ts", "src/locales/en.ts", "src/locales/es.ts", "src/locales/preauth.ts"}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def oracle_execution(payload):
    """Record runner faults as observations, never as behavioral kill credit."""
    zero_tests = []
    watchdog_kills = []
    for source, file in payload.get("files", {}).items():
        for mutant in file["mutants"]:
            record = {"source": source, "id": mutant["id"], "status": mutant["status"],
                      "static": mutant.get("static", False), "reason": mutant.get("statusReason", "")}
            if mutant.get("testsCompleted") == 0:
                zero_tests.append(record)
            if mutant["status"] == "Killed" and re.search(r"(?:Test|Hook) timed out|Worker exited unexpectedly|unhandled error|Test runner.*(?:failed|error)", record["reason"], re.I):
                watchdog_kills.append(record)
    return {"zero_test_observations": zero_tests, "watchdog_kill_observations": watchdog_kills}


def command(args, cwd, log_path):
    with log_path.open("w") as log:
        return subprocess.run(args, cwd=cwd, stdout=log, stderr=subprocess.STDOUT).returncode


def input_paths():
    paths = []
    for directory in ["src", "tests", "public", "tools"]:
        paths.extend(path for path in (ROOT / directory).rglob("*") if path.is_file() and "__pycache__" not in path.parts)
    paths.extend(ROOT / name for name in ["package.json", "package-lock.json", "vite.config.ts", "tsconfig.json", "index.html", "stryker.config.json"])
    paths.extend(path for path in (ROOT.parent / "shared").rglob("*") if path.is_file())
    paths.append(ROOT.parent / "deploy/nginx/mindpattern.conf.example")
    return sorted(paths)


def freeze(destination):
    paths = input_paths()
    before = {str(path.relative_to(ROOT.parent)): digest(path) for path in paths}
    for path in paths:
        target = destination / path.relative_to(ROOT.parent)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
    after = {str(path.relative_to(ROOT.parent)): digest(path) for path in input_paths()}
    copied = {name: digest(destination / name) for name in before}
    if before != after or before != copied:
        raise RuntimeError("Source changed while freezing inputs; retry")
    return before


def bootstrap(snapshot, scratch, supplied, reports):
    if supplied:
        modules = Path(supplied).resolve()
    else:
        package = scratch / "runner/web"
        package.mkdir(parents=True)
        for name in ["package.json", "package-lock.json"]:
            shutil.copy2(snapshot / "web" / name, package / name)
        if command(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], package, reports / "runner-install.log"):
            raise RuntimeError("Runner npm ci failed")
        if command(["npm", "install", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact", "vitest@4.1.10", "@vitest/coverage-v8@4.1.10"], package, reports / "runner-vitest4-install.log"):
            raise RuntimeError("Isolated Vitest 4 install failed")
        modules = package / "node_modules"
    versions = {}
    for name, expected in [("vitest", "4.1.10"), ("@stryker-mutator/core", "10.0.0"), ("@stryker-mutator/vitest-runner", "10.0.0")]:
        version = json.loads((modules / name / "package.json").read_text())["version"]
        if version != expected:
            raise RuntimeError(f"Runner {name} must be {expected}, found {version}")
        versions[name] = version
    installed = {str(path.relative_to(modules)): digest(path) for path in sorted(modules.rglob("package.json")) if path.is_file()}
    locks = {name: digest(modules.parent / name) for name in ["package.json", "package-lock.json"] if (modules.parent / name).exists()}
    write_json(reports / "runner-dependencies.json", {"node": subprocess.check_output(["node", "--version"], text=True).strip(), "versions": versions,
               "runner_directory": str(modules), "locks": locks, "installed_package_manifests": installed})
    return modules


def selectors(package, source):
    if source == "public/theme-init.js":
        return ["tests/theme.test.ts"]
    if source == "src/brain/lexicon.ts":
        return ["tests/brainBehavior.test.ts"]
    if source == "src/crisisPhrases.ts":
        return ["tests/crisisBehavior.test.ts"]
    if source.startswith("src/locales/"):
        return ["tests/catalogOutput.test.ts"]
    focused = {
        "src/App.tsx": ["tests/appMutationBehavior.test.tsx"],
        "src/ui.tsx": ["tests/ui.test.tsx", "tests/interaction.test.tsx", "tests/uiPresentation.test.tsx", "tests/moodBehavior.test.tsx", "tests/tokenConsumers.test.tsx"],
        "src/main.tsx": ["tests/main.test.tsx"],
        "src/audio/recorder.ts": ["tests/voiceRecorder.test.tsx", "tests/recorderBehavior.test.tsx", "tests/audioVoice.test.ts"],
        "src/sessionLock.ts": ["tests/sessionLock.test.tsx", "tests/lifecycleBehavior.test.tsx"],
        "src/patientOperation.ts": ["tests/lifecycleBehavior.test.tsx"],
        "src/tabLockdown.ts": ["tests/tabLockdown.test.ts"],
        "src/crisis.tsx": ["tests/crisis.test.tsx", "tests/crisisPresentation.test.tsx", "tests/interaction.test.tsx"],
        "src/localRotation.ts": ["tests/localRotation.idb.test.ts", "tests/localRotation.test.ts", "tests/rotationContract.test.ts"],
        "src/crypto/patient.ts": ["tests/crypto.test.ts", "tests/crypto.pins.test.ts", "tests/interop.test.ts", "tests/audioVoice.test.ts", "tests/cryptoSchemaBoundaries.test.ts", "tests/patientWireBehavior.test.ts"],
        "src/entryVersions.ts": ["tests/stores.test.ts", "tests/encryptedMetadataBehavior.test.ts"],
        "src/entryId.ts": ["tests/storageBehavior.test.ts"],
        "src/historyFind.ts": ["tests/storageBehavior.test.ts"],
        "src/measureCadence.ts": ["tests/storageBehavior.test.ts"],
        "src/moodLog.ts": ["tests/stores.test.ts", "tests/gapFill.test.ts", "tests/encryptedMetadataBehavior.test.ts"],
        "src/offlineQueue.ts": ["tests/queue.test.ts", "tests/auditRegressions.test.ts"],
        "src/patternMutes.ts": ["tests/storageBehavior.test.ts"],
        "src/pendingMeasure.ts": ["tests/storageBehavior.test.ts"],
        "src/questionFeedback.ts": ["tests/storageBehavior.test.ts"],
        "src/stateSeqGuard.ts": ["tests/storageBehavior.test.ts"],
        "src/thresholdNotice.ts": ["tests/storageBehavior.test.ts"],
        "src/reauth.ts": ["tests/reauth.test.ts"],
        "src/genericQuestions.ts": ["tests/contractPins.test.ts", "tests/i18n.test.ts"],
        "src/api/client.ts": ["tests/api.test.ts", "tests/apiSurface.test.ts"],
        "src/vault.ts": ["tests/vault.test.ts"],
        "src/platform.ts": ["tests/platform.test.ts", "tests/platformBehavior.test.ts"],
        "src/strings.ts": ["tests/catalogOutput.test.ts", "tests/languageLifecycle.test.ts"],
        "src/kvstore.ts": ["tests/kvstore.idb.test.ts"],
        "src/brain/stats.ts": ["tests/brainVectors.test.ts", "tests/brainStatsBehavior.test.ts"],
        "src/crisisDialog.ts": ["tests/smallStateBehavior.test.ts"],
        "src/crypto/envelope.ts": ["tests/envelope.test.ts", "tests/envelopeBoundaryBehavior.test.ts", "tests/crypto.test.ts"],
        "src/dates.ts": ["tests/smallConsumerContracts.test.ts"],
        "src/errors.ts": ["tests/smallConsumerContracts.test.ts"],
        "src/localErasure.ts": ["tests/localErasure.test.ts"],
        "src/measures.ts": ["tests/measures.test.tsx", "tests/smallStateBehavior.test.ts"],
        "src/ownerStorage.ts": ["tests/smallConsumerContracts.test.ts", "tests/localErasure.test.ts"],
        "src/safetyPlan.ts": ["tests/safetyPlan.test.tsx"],
        "src/sync.ts": ["tests/sync.test.ts"],
        "src/tokens.ts": ["tests/tokenConsumers.test.tsx", "tests/themeBehavior.test.ts", "tests/ui.test.tsx"],
        "src/views/History.tsx": ["tests/history.test.tsx", "tests/historyPresentation.test.tsx"],
        "src/views/Entry.tsx": ["tests/entry.test.tsx", "tests/entryVoiceUi.test.tsx", "tests/entryPresentation.test.tsx"],
        "src/views/LoginView.tsx": ["tests/login.test.tsx", "tests/loginPresentation.test.tsx"],
        "src/views/Measures.tsx": ["tests/measures.test.tsx", "tests/measuresPresentation.test.tsx", "tests/measuresMutationBehavior.test.tsx", "tests/measuresPatternsInitialDom.test.tsx"],
        "src/views/Onboarding.tsx": ["tests/onboarding.test.tsx", "tests/onboardingPresentation.test.tsx"],
        "src/views/Privacy.tsx": ["tests/i18nViews.test.tsx", "tests/a11y.test.tsx", "tests/privacyPresentation.test.tsx"],
        "src/views/Question.tsx": ["tests/patterns.test.tsx", "tests/questionPresentation.test.tsx"],
        "src/views/SafetyPlan.tsx": ["tests/safetyPlan.test.tsx", "tests/planPresentation.test.tsx"],
        "src/views/Share.tsx": ["tests/settings.test.tsx", "tests/sharePresentation.test.tsx"],
        "src/views/Patterns.tsx": ["tests/patterns.test.tsx", "tests/patternsPresentation.test.tsx", "tests/patternsMutationBehavior.test.tsx", "tests/measuresPatternsInitialDom.test.tsx", "tests/patternsNativeDisclosure.test.tsx"],
        "src/views/Settings.tsx": ["tests/settings.test.tsx", "tests/settingsPresentation.test.tsx"],
    }
    if source in focused:
        return focused[source]
    module = "../" + source.rsplit(".", 1)[0]
    return [str(test.relative_to(package)) for test in sorted((package / "tests").rglob("*.test.*"))
            if re.search(r"[\"']" + re.escape(module) + r"(?:\.[tj]sx?)?[\"']", test.read_text())] or ["tests/**/*.test.ts", "tests/**/*.test.tsx"]


def wrapper(package, selected, setup_file=None, test_name_pattern=None):
    path = package / "vitest.shard.config.ts"
    for test in selected:
        if not any(char in test for char in "*?[") and not (package / test).is_file():
            raise RuntimeError(f"Selected oracle does not exist in frozen package: {test}")
    # mergeConfig concatenates include arrays and silently selects all tests.
    path.write_text('import { defineConfig } from "vitest/config";\nimport base from "./vite.config";\n'
                    'export default defineConfig({...base, test: {...base.test, update: "none", testTimeout: 120000, hookTimeout: 120000, include: '
                    + json.dumps(selected) + (", setupFiles: " + json.dumps([setup_file]) if setup_file else "")
                    + (", testNamePattern: " + json.dumps(test_name_pattern) if test_name_pattern else "") + ', exclude: ["tests/brainArtifact.test.ts", "tests/crisisArtifact.test.ts", "tests/designTokens.test.ts", "tests/audioArtifact.test.ts"], coverage: {...base.test?.coverage, enabled: false}}});\n')
    return path


def config_for(source, report, timeout, mutant_workers=1):
    # testFiles forces runtime activation even for top-level static mutants.
    # Selecting via the Vitest wrapper preserves activation before imports.
    return {"testRunner": "vitest", "vitest": {"configFile": "vitest.shard.config.ts", "related": False},
            "mutate": [source], "inPlace": True, "disableTypeChecks": False, "coverageAnalysis": "perTest", "concurrency": mutant_workers,
            "timeoutMS": timeout, "reporters": ["json", "progress", "clear-text"], "jsonReporter": {"fileName": str(report)},
            "thresholds": {"break": 55}, "incremental": False, "tempDirName": "stryker-tmp", "allowConsoleColors": False}


def canary(package, reports, timeout):
    (package / "runner-witness.ts").write_text('export const visible = "visible";\nexport const unchecked = "opaque";\nexport function choice(value: boolean) { return value ? true : false; }\nexport const externalSnapshot = "external";\nexport const inlineSnapshot = "inline";\n')
    (package / "runner-witness.test.ts").write_text('import { expect, it } from "vitest";\nimport { visible, unchecked, choice, externalSnapshot, inlineSnapshot } from "./runner-witness";\nit("static and runtime witness", () => { expect(visible).toBe("visible"); expect(typeof unchecked).toBe("string"); expect(choice(true)).toBe(true); expect(choice(false)).toBe(false); });\nit("external snapshot witness", () => { expect(externalSnapshot).toMatchSnapshot(); });\nit("inline snapshot witness", () => { expect(inlineSnapshot).toMatchInlineSnapshot(\'"inline"\'); });\n')
    snapshots = package / "__snapshots__"
    snapshots.mkdir(exist_ok=True)
    snapshot = snapshots / "runner-witness.test.ts.snap"
    snapshot.write_text('// Vitest Snapshot v1, https://vitest.dev/guide/snapshot.html\n\nexports[`external snapshot witness 1`] = `"external"`;\n')
    wrapper(package, ["runner-witness.test.ts"])
    output = reports / "runner-witness.json"
    output.unlink(missing_ok=True)
    write_json(package / "stryker.shard.json", config_for("runner-witness.ts", output, timeout))
    code = command([str(package / "node_modules/.bin/stryker"), "run", "stryker.shard.json"], package, reports / "runner-witness.log")
    if not output.exists():
        raise RuntimeError(f"Runner witness failed without a report (exit {code})")
    mutants = json.loads(output.read_text())["files"]["runner-witness.ts"]["mutants"]
    static = [mutant for mutant in mutants if mutant.get("static")]
    if not any(m["status"] == "Killed" for m in static) or not any(m["status"] == "Survived" for m in static):
        raise RuntimeError("Runner did not distinguish static kill and survivor witnesses")
    if not any(m["status"] == "Killed" and not m.get("static") for m in mutants):
        raise RuntimeError("Runner did not execute runtime kill witness")
    if any(m["status"] not in ["Killed", "Survived"] or not m.get("testsCompleted") for m in mutants):
        raise RuntimeError("Runner witness has unexecuted/error/timeout controls")
    for line in [4, 5]:
        observed = [m for m in mutants if m["location"]["start"]["line"] == line]
        if not observed or any(m["status"] != "Killed" for m in observed):
            raise RuntimeError(f"Runner snapshot mismatch witness failed at line {line}")
    if snapshot.read_text() != '// Vitest Snapshot v1, https://vitest.dev/guide/snapshot.html\n\nexports[`external snapshot witness 1`] = `"external"`;\n':
        raise RuntimeError("Mutation runner changed its external snapshot oracle")
    snapshot.unlink()
    for name in ["runner-witness.ts", "runner-witness.test.ts"]:
        (package / name).unlink()


def run_lane(worker, sources, snapshot, scratch, modules, reports, timeout, selected_tests, mutant_workers, replay, presentation_only=False, setup_file=None, test_name_pattern=None):
    lane = scratch / f"worker-{worker}"
    shutil.copytree(snapshot, lane)
    package = lane / "web"
    (package / "node_modules").symlink_to(modules, target_is_directory=True)
    for source in sources:
        label = source.replace("/", "__").rsplit(".", 1)[0]
        report = reports / (label + ".json")
        report.unlink(missing_ok=True)
        selected = selected_tests or selectors(package, source)
        if presentation_only:
            selected = [test for test in selected if "Presentation.test." in test]
            if not selected:
                raise RuntimeError(f"{source}: no public presentation oracle is configured")
        effective_setup = setup_file or ("tests/helpers/browserSetup.ts" if source == "src/strings.ts" else None)
        wrapper_path = wrapper(package, selected, effective_setup, test_name_pattern)
        pristine_hash = digest(package / source)
        if replay and replay[source]["source_sha256"] != pristine_hash:
            raise RuntimeError(f"{source}: replay source differs from frozen current source; run the complete changed file")
        baseline = reports / (label + "-baseline.json")
        baseline.unlink(missing_ok=True)
        args = [str(package / "node_modules/.bin/vitest"), "run", "--config", "vitest.shard.config.ts", "--coverage.enabled=false", "--maxWorkers=1", "--reporter=json", "--outputFile", str(baseline)]
        code = command(args, package, reports / (label + "-baseline.log"))
        if code or not baseline.exists() or not json.loads(baseline.read_text()).get("numPassedTests"):
            raise RuntimeError(f"{source}: pristine selector baseline failed or ran zero tests")
        config = config_for(source, report, timeout, mutant_workers)
        if replay:
            config["mutate"] = replay[source]["ranges"]
        write_json(package / "stryker.shard.json", config)
        code = command([str(package / "node_modules/.bin/stryker"), "run", "stryker.shard.json"], package, reports / (label + ".log"))
        if not report.exists():
            raise RuntimeError(f"{source}: no fresh report; runner exit {code}")
        restored = digest(package / source) == pristine_hash
        if not restored:
            raise RuntimeError(f"{source}: Stryker did not restore source")
        payload = json.loads(report.read_text())
        file = payload["files"].get(source)
        if not file or hashlib.sha256(file["source"].encode()).hexdigest() != pristine_hash:
            raise RuntimeError(f"{source}: report source differs from frozen input")
        counts = {}
        for mutant in file["mutants"]:
            counts[mutant["status"]] = counts.get(mutant["status"], 0) + 1
        metadata = {"source": source, "source_sha256": pristine_hash, "source_restored": restored, "selectors": selected, "snapshot": "inputs.json",
                    "runner": "runner-dependencies.json", "runner_witness": "runner-witness.json", "baseline": baseline.name, "baseline_sha256": digest(baseline),
                    "config": config, "vitest_wrapper_sha256": digest(wrapper_path), "report_sha256": digest(report), "exit_code": code,
                    "counts": counts, "scratch_directory": str(package), "setup_file": effective_setup, "test_name_pattern": test_name_pattern,
                    "oracle_execution": oracle_execution(payload)}
        if replay:
            metadata["replay"] = replay[source]
        write_json(reports / (label + "-metadata.json"), metadata)
        print(json.dumps(metadata), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workers", type=int, nargs="?", default=2)
    parser.add_argument("--reports", type=Path, default=ROOT / "reports/mutation/shards")
    parser.add_argument("--runner-node-modules", type=Path)
    parser.add_argument("--include-data", action="store_true")
    parser.add_argument("--source", action="append", help="Targeted full-file replay; omit for the whole runtime scope")
    parser.add_argument("--replay-report", type=Path, help="Replay unresolved operator ranges from a report with identical current source; preserve the original full inventory for merging")
    parser.add_argument("--replay-id", action="append", help="Limit a remediation replay to an unresolved id from its input report; repeat as needed")
    parser.add_argument("--operator-range", action="append", help="Run an explicit current-source Stryker range (file:startLine:startColumn-endLine:endColumn); produces a partial report for merging with a full current inventory")
    parser.add_argument("--test", action="append", help="Override Vitest include with a path/glob; repeat for multiple consumer test files")
    parser.add_argument("--setup-file", help="Use a source-free test setup when target imports must occur inside consumer test bodies")
    parser.add_argument("--test-name-pattern", help="Select bounded consumer cases within the included files; retained in the wrapper and pristine baseline")
    parser.add_argument("--presentation-only", action="store_true", help="Use the target view's public rendered surface oracles; replay interaction survivors separately")
    parser.add_argument("--mutant-workers", type=int, default=1, help="Stryker workers per isolated file lane (default: 1)")
    parser.add_argument("--timeout-ms", type=int, default=2000)
    parser.add_argument("--canary-only", action="store_true")
    args = parser.parse_args()
    if args.workers < 1 or args.mutant_workers < 1 or args.timeout_ms < 1:
        parser.error("workers and timeout must be positive")
    reports = args.reports.resolve()
    reports.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="fathom-web-mutation-"))
    snapshot = scratch / "snapshot"
    manifest = freeze(snapshot)
    write_json(reports / "inputs.json", {"files": manifest, "snapshot_directory": str(snapshot), "launcher_sha256": digest(Path(__file__))})
    modules = bootstrap(snapshot, scratch, args.runner_node_modules, reports)
    witness = scratch / "witness"
    shutil.copytree(snapshot, witness)
    package = witness / "web"
    (package / "node_modules").symlink_to(modules, target_is_directory=True)
    canary(package, reports, args.timeout_ms)
    if args.canary_only:
        print(json.dumps({"canary": "passed", "scratch_directory": str(scratch)}), flush=True)
        return
    sources = sorted(str(path.relative_to(snapshot / "web")) for path in (snapshot / "web/src").rglob("*") if path.suffix in [".ts", ".tsx"])
    sources += ["public/theme-init.js"]
    if not args.include_data:
        sources = [source for source in sources if source not in DATA]
    if args.source:
        requested = set(args.source)
        if requested - (set(sources) | DATA):
            parser.error(f"Out-of-scope source: {sorted(requested - (set(sources) | DATA))}")
        sources = sorted(requested)
    replay = None
    if args.operator_range and args.replay_report:
        parser.error("Explicit operator ranges and report replay are separate selection modes")
    if args.operator_range:
        replay = {}
        for requested_range in args.operator_range:
            match = re.fullmatch(r"(.+):(\d+):(\d+)-(\d+):(\d+)", requested_range)
            if not match or match[1] not in sources:
                parser.error(f"Invalid/out-of-scope operator range: {requested_range}")
            source = match[1]
            selected = replay.setdefault(source, {"selection": "explicit_current_source_ranges", "source_sha256": digest(snapshot / "web" / source), "ranges": []})
            selected["ranges"].append(requested_range)
        sources = sorted(replay)
    if args.replay_report:
        input_report = args.replay_report.resolve()
        replay = {}
        payload = json.loads(input_report.read_text())
        for source, file in payload["files"].items():
            if args.source and source not in args.source:
                continue
            ranges = sorted({f'{source}:{m["location"]["start"]["line"]}:{m["location"]["start"]["column"] - 1}-{m["location"]["end"]["line"]}:{m["location"]["end"]["column"] - 1}'
                             for m in file["mutants"] if (not args.replay_id or str(m["id"]) in args.replay_id) and (m["status"] != "Killed" or m.get("testsCompleted") == 0 or re.search(r"timed out|beforeAll|afterAll|beforeEach|afterEach|hook", m.get("statusReason", ""), re.I))})
            if ranges:
                replay[source] = {"input_report": str(input_report), "input_report_sha256": digest(input_report),
                                  "source_sha256": hashlib.sha256(file["source"].encode()).hexdigest(), "ranges": ranges}
                if args.replay_id:
                    replay[source]["selected_input_ids"] = args.replay_id
        if not replay:
            parser.error("Replay report has no unresolved operator ranges")
        sources = sorted(replay)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(run_lane, worker, sources[worker::args.workers], snapshot, scratch, modules, reports, args.timeout_ms, args.test, args.mutant_workers, replay, args.presentation_only, args.setup_file, args.test_name_pattern) for worker in range(args.workers)]
        for future in futures:
            future.result()


if __name__ == "__main__":
    main()
