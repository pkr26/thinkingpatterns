#!/usr/bin/env python3
"""Behavioral mutation campaign (2026-09-18).

Mutants are grouped into the six campaigns from the testing strategy:
  A  mini-brain statistics (BH FDR, effect gates, 30-day threshold, probe)
  B  pattern lifecycle (replication gating, fading/archival)
  C  crypto & memory boundaries (zeroization, single-use, AAD)
  D  clinical boundaries (LLM sanitizer, evidence binding)
  E  crisis handling (suppress tier, question interlock, on-device detect)
  F  zero-knowledge sharing & clients (fingerprint, role gates, KDF, storage)

For every mutant: snapshot the target file's bytes, apply ONE semantic
mutation, run the targeted test suite, restore the bytes exactly (the work
tree carries uncommitted changes, so restoration is byte-wise — never git),
and record killed/survived + the failing tests.

A mutant is KILLED when the command exits non-zero (test failure, probe
FAIL, or timeout — a hang is an observable behavior change). Survivors are
re-verified against the full suite afterwards by the campaign driver.

Usage:
  python3 harness.py            # run all campaigns
  python3 harness.py A C        # run only campaigns A and C
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_DIR = pathlib.Path(__file__).resolve().parent / "results"
OUT_DIR.mkdir(exist_ok=True)

PY = ".venv/bin/python"


def backend_pytest(*targets: str, extra: tuple[str, ...] = ()) -> dict:
    return {
        "cwd": "backend",
        "cmd": [PY, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider",
                "-m", "not slow", *extra, *targets],
        "timeout": 900,
        "kind": "pytest",
    }


def backend_full() -> dict:
    return {
        "cwd": "backend",
        "cmd": [PY, "-m", "pytest", "-q", "--no-header", "-p", "no:cacheprovider",
                "-m", "not slow"],
        "timeout": 1800,
        "kind": "pytest",
    }


def probe() -> dict:
    return {
        "cwd": "backend",
        "cmd": [PY, "probe_brain.py"],
        "timeout": 300,
        "kind": "probe",
    }


def vitest(cwd: str, *targets: str) -> dict:
    return {
        "cwd": cwd,
        "cmd": ["npx", "vitest", "run", *targets],
        "timeout": 600,
        "kind": "vitest",
    }


MUTANTS: list[dict] = [
    # ---------------------------------------------------------------- A. statistics
    dict(
        id="A1", campaign="A", name="BH q-threshold doubled (q=0.05 -> 0.10)",
        expectation="FDR simulations / brain noise regressions must fail",
        file="backend/app/services/statsig.py",
        find="        if pvalues[idx] <= q * rank / m:",
        replace="        if pvalues[idx] <= 2.0 * q * rank / m:",
        tests=backend_pytest("tests/test_statsig.py", "tests/test_brain.py"),
    ),
    dict(
        id="A2", campaign="A", name="BH rank multiplier dropped (p <= q, no k/m)",
        expectation="step-up correction disabled -> false discoveries flow",
        file="backend/app/services/statsig.py",
        find="        if pvalues[idx] <= q * rank / m:",
        replace="        if pvalues[idx] <= q:",
        tests=backend_pytest("tests/test_statsig.py", "tests/test_brain.py"),
    ),
    dict(
        id="A3", campaign="A", name="BH rejects one hypothesis beyond the step-up cutoff",
        expectation="exact rejection set is pinned",
        file="backend/app/services/statsig.py",
        find="    for idx in order[:cutoff_rank]:",
        replace="    for idx in order[:cutoff_rank + 1]:",
        tests=backend_pytest("tests/test_statsig.py"),
    ),
    dict(
        id="A4", campaign="A", name="engine-wide ALPHA inflated 0.05 -> 0.25",
        expectation="noise-regression tests must fail",
        file="backend/app/services/brain.py",
        find="ALPHA = 0.05",
        replace="ALPHA = 0.25",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="A5", campaign="A", name="Cohen's d effect gate zeroed (0.5 -> 0.0)",
        expectation="trivial-effect patterns must be refused by regressions",
        file="backend/app/services/brain.py",
        find="MOOD_MIN_EFFECT = 0.5  # Cohen's d",
        replace="MOOD_MIN_EFFECT = 0.0  # Cohen's d",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="A6", campaign="A", name="effect gate AND -> OR (mood_correlation + link)",
        expectation="a significant-but-trivial effect must not surface",
        file="backend/app/services/brain.py",
        find="gate_ok=abs(delta) >= MOOD_MIN_DELTA and abs(effect) >= MOOD_MIN_EFFECT,",
        replace="gate_ok=abs(delta) >= MOOD_MIN_DELTA or abs(effect) >= MOOD_MIN_EFFECT,",
        count=2,
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="A7", campaign="A", name="30-day gate lowered to >= 1 active day",
        expectation="progressive revelation must stay server-enforced at 30",
        file="backend/app/services/threshold.py",
        find="    phase = Phase.INSIGHT if active >= threshold else Phase.BASELINE",
        replace="    phase = Phase.INSIGHT if active >= 1 else Phase.BASELINE",
        tests=backend_pytest("tests/test_threshold.py", "tests/test_insights_api.py",
                             "tests/test_brain_api.py"),
    ),
    dict(
        id="A8", campaign="A", name="temporal weekday gate disabled (ground-truth probe)",
        expectation="probe_brain.py must FAIL: planted 'work on Sundays' missed",
        file="backend/app/services/brain.py",
        find="            gate_ok = k >= TEMPORAL_MIN_DAY_K and fraction >= TEMPORAL_MIN_FRACTION",
        replace="            gate_ok = False and k >= TEMPORAL_MIN_DAY_K and fraction >= TEMPORAL_MIN_FRACTION",
        tests=probe(),
    ),
    dict(
        id="A9", campaign="A", name="probe corpus: Sunday 'work' plant replaced by neutral text",
        expectation="probe_brain.py must FAIL: scenario A no longer present",
        file="backend/probe_brain.py",
        find='        if wd == 6:\n            text = "big deadline pressure at work again, boss emailed twice about monday"',
        replace='        if wd == 6:\n            text = "quiet sunday, made tea and read a bit"',
        tests=probe(),
    ),
    # ---------------------------------------------------------------- B. lifecycle
    dict(
        id="B1", campaign="B", name="statistical kinds promote without replication",
        expectation="single lucky p-value must stay a candidate",
        file="backend/app/services/brain.py",
        find="            if record.kind in STATISTICAL_KINDS:\n                if _replication_satisfied(record, signal, prior_evidence):\n                    record.state = \"emerging\"",
        replace="            if record.kind in STATISTICAL_KINDS:\n                if True:\n                    record.state = \"emerging\"",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="B2", campaign="B", name="replication spread requirement dropped (return True)",
        expectation="consecutive same-window recomputes must not count as independent",
        file="backend/app/services/brain.py",
        find="    return spread >= REPLICATION_MIN_SPREAD_DAYS",
        replace="    return True",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="B3", campaign="B", name="GRACE_DAYS 7 -> 7000 (patterns never fade)",
        expectation="stale patterns must transition to fading",
        file="backend/app/services/brain.py",
        find="GRACE_DAYS = 7  # unqualified days before active → fading",
        replace="GRACE_DAYS = 7000  # unqualified days before active → fading",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="B4", campaign="B", name="ARCHIVE_DAYS 45 -> 4500 (fading never archives)",
        expectation="fading patterns must archive after the window",
        file="backend/app/services/brain.py",
        find="ARCHIVE_DAYS = 45  # unqualified days before fading → archived",
        replace="ARCHIVE_DAYS = 4500  # unqualified days before fading → archived",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    dict(
        id="B5", campaign="B", name="evidence half-life 45 -> 45000 days (no decay)",
        expectation="strength/confidence must decay with evidence age",
        file="backend/app/services/brain.py",
        find="HALF_LIFE_DAYS = 45.0  # recent mentions outweigh old ones; the brain forgets",
        replace="HALF_LIFE_DAYS = 45000.0  # recent mentions outweigh old ones; the brain forgets",
        tests=backend_pytest("tests/test_brain.py"),
    ),
    # ---------------------------------------------------------------- C. crypto/memory
    dict(
        id="C1", campaign="C", name="zeroize() body removed (keys never scrubbed)",
        expectation="post-destroy/post-run zero assertions must fail",
        file="backend/app/security/enclave.py",
        find="def zeroize(key: bytearray) -> None:\n    for i in range(len(key)):\n        key[i] = 0",
        replace="def zeroize(key: bytearray) -> None:\n    pass",
        tests=backend_pytest("tests/test_enclave.py"),
    ),
    dict(
        id="C2", campaign="C", name="SecureProcessingContext.run no longer scrubs key copies",
        expectation="working key + context key must be zero after run",
        file="backend/app/security/enclave.py",
        find="        finally:\n            for buf in buffers:\n                buf.zeroize()\n            zeroize(key_material)\n            zeroize(self._key)",
        replace="        finally:\n            for buf in buffers:\n                buf.zeroize()",
        tests=backend_pytest("tests/test_enclave.py"),
    ),
    dict(
        id="C3", campaign="C", name="keystore.pop does not consume the token (reuse possible)",
        expectation="single-use-by-mechanism test must fail on second pop",
        file="backend/app/security/enclave.py",
        find="            # Only the authorized caller consumes the store-owned buffer.\n            del self._keys[token]\n            return key",
        replace="            # Only the authorized caller consumes the store-owned buffer.\n            return key",
        tests=backend_pytest("tests/test_enclave.py", "tests/test_mutation_pins.py"),
    ),
    dict(
        id="C4", campaign="C", name="decrypt ignores AAD (context binding dropped)",
        expectation="wrong-AAD/cross-context tamper tests + vectors must fail",
        file="backend/app/security/crypto.py",
        find="        return AESGCM(key).decrypt(nonce, ciphertext, aad)",
        replace="        return AESGCM(key).decrypt(nonce, ciphertext, None)",
        tests=backend_pytest("tests/test_crypto.py", "tests/test_encrypt_vectors.py"),
    ),
    dict(
        id="C5", campaign="C", name="build_aad drops the first binding part (user/entry)",
        expectation="AAD canonicalization + API blob-relocation tests must fail",
        file="backend/app/security/crypto.py",
        find='    return json.dumps(list(parts), separators=(",", ":"), ensure_ascii=True).encode("utf-8")',
        replace='    return json.dumps(list(parts)[1:], separators=(",", ":"), ensure_ascii=True).encode("utf-8")',
        tests=backend_pytest("tests/test_crypto.py", "tests/test_contract_pins.py"),
    ),
    # ---------------------------------------------------------------- D. clinical
    dict(
        id="D1", campaign="D", name="diagnosis words removed from _CLINICAL_TERMS",
        expectation="sanitizer tests must catch 'diagnosed' narratives",
        file="backend/app/services/llm.py",
        find='        "diagnosis",\n        "diagnose",\n        "diagnosed",\n    }\n)',
        replace="    }\n)",
        tests=backend_pytest("tests/test_llm.py"),
    ),
    dict(
        id="D2", campaign="D", name="narrative digit ban removed (statistics/dosages pass)",
        expectation="minted-number rejection tests must fail",
        file="backend/app/services/llm.py",
        find="    if any(ch.isdigit() for ch in text):\n        return None",
        replace="    if False:\n        return None",
        tests=backend_pytest("tests/test_llm.py"),
    ),
    dict(
        id="D3", campaign="D", name="narrative may echo crisis language",
        expectation="crisis-echo rejection tests must fail",
        file="backend/app/services/llm.py",
        find="    if crisis.matches_dialog(text) or crisis.matches_suppress(text):\n        return None\n    return text",
        replace="    if False:\n        return None\n    return text",
        tests=backend_pytest("tests/test_llm.py"),
    ),
    dict(
        id="D4", campaign="D", name="surfaced cards ship empty evidence_dates",
        expectation="'Why am I seeing this?' payload binding must be pinned",
        file="backend/app/services/brain.py",
        find='                    "evidence_dates": list(record.evidence_dates),',
        replace='                    "evidence_dates": [],',
        tests=backend_pytest("tests/test_brain.py", "tests/test_insights_api.py"),
    ),
    # ---------------------------------------------------------------- E. crisis
    dict(
        id="E1", campaign="E", name="backend suppress tier always returns False",
        expectation="suppression contract tests + question interlock must fail",
        file="backend/app/services/crisis.py",
        find="    variants = _match_variants(text)\n    return any(SUPPRESS_RE.search(v) for v in variants[:2]) or any(\n        SUPPRESS_CONCAT_RE.search(v) for v in (variants[2],)\n    )",
        replace="    return False",
        tests=backend_pytest("tests/test_crisis.py", "tests/test_questions.py",
                             "tests/test_llm.py"),
    ),
    dict(
        id="E2", campaign="E", name="backend dialog tier always returns False",
        expectation="dialog-tier detection tests must fail",
        file="backend/app/services/crisis.py",
        find="    variants = _match_variants(text)\n    return any(DIALOG_RE.search(v) for v in variants[:2]) or any(\n        DIALOG_CONCAT_RE.search(v) for v in (variants[2],)\n    )",
        replace="    return False",
        tests=backend_pytest("tests/test_crisis.py"),
    ),
    dict(
        id="E3", campaign="E", name="question interlock label tripwire disabled",
        expectation="crisis-adjacent labels must never become questions",
        file="backend/app/services/questions.py",
        find="    if crisis.matches_suppress(pattern.label):\n        return True",
        replace="    if False:\n        return True",
        tests=backend_pytest("tests/test_questions.py", "tests/test_crisis.py"),
    ),
    dict(
        id="E4", campaign="E", name="mobile detectCrisisLanguage -> false (false negatives)",
        expectation="on-device dialog-tier corpus tests must fail",
        file="mobile/src/crisisDetect.ts",
        find="  const [primary, orphan, concat] = matchVariants(text);\n  return (\n    DIALOG_PATTERNS.some((p) => p.test(primary) || p.test(orphan)) ||\n    DIALOG_CONCAT_PATTERNS.some((p) => p.test(concat))\n  );",
        replace="  const [primary, orphan, concat] = matchVariants(text);\n  return false;",
        tests=vitest("mobile", "tests/crisisDetect.test.ts", "tests/crisisDialog.test.ts"),
    ),
    dict(
        id="E5", campaign="E", name="mobile matchesCrisisSuppress -> false (quoting returns)",
        expectation="non-quoting card + question suppression tests must fail",
        file="mobile/src/crisisDetect.ts",
        find="  const [primary, orphan, concat] = matchVariants(text);\n  return (\n    SUPPRESS_PATTERNS.some((p) => p.test(primary) || p.test(orphan)) ||\n    SUPPRESS_CONCAT_PATTERNS.some((p) => p.test(concat))\n  );",
        replace="  const [primary, orphan, concat] = matchVariants(text);\n  return false;",
        tests=vitest("mobile", "tests/crisisPhrases.test.ts", "tests/securityFixes.test.ts"),
    ),
    # ---------------------------------------------------------------- F. sharing & clients
    dict(
        id="F1", campaign="F", name="mobile fingerprint hashes base64 text, not the DER key",
        expectation="cross-platform fingerprint pin must fail (substituted-key check dead)",
        file="mobile/src/crypto/sharing.ts",
        find='  const digest = engine.createHash("sha256").update(Buffer.from(therapistPubSpkiB64, "base64")).digest();',
        replace='  const digest = engine.createHash("sha256").update(Buffer.from(therapistPubSpkiB64, "utf8")).digest();',
        tests=vitest("mobile", "tests/crypto.test.ts", "tests/securityFixes.test.ts"),
    ),
    dict(
        id="F2", campaign="F", name="portal fingerprint hashes base64 text, not the DER key",
        expectation="portal fingerprint pin must fail",
        file="portal/src/crypto.ts",
        find='  const digest = new Uint8Array(await subtle().digest("SHA-256", unb64(spkiB64)));',
        replace='  const digest = new Uint8Array(await subtle().digest("SHA-256", new TextEncoder().encode(spkiB64)));',
        tests=vitest("portal", "tests/crypto.test.ts"),
    ),
    dict(
        id="F3", campaign="F", name="journal role gate disabled (therapist token writes entries)",
        expectation="403 role-rejection tests must fail",
        file="backend/app/deps.py",
        find='    if user.role != ROLE_USER:\n        raise ApiError(\n            status_code=403,\n            detail="therapist accounts cannot access journal endpoints",',
        replace='    if False:\n        raise ApiError(\n            status_code=403,\n            detail="therapist accounts cannot access journal endpoints",',
        tests=backend_pytest("tests/test_therapist_api.py", "tests/test_entries_api.py"),
    ),
    dict(
        id="F4", campaign="F", name="therapist role gate disabled (patient token reads portal routes)",
        expectation="mirrored 403 role-rejection tests must fail",
        file="backend/app/deps.py",
        find='    if user.role != ROLE_THERAPIST:\n        raise ApiError(\n            status_code=403,\n            detail="not a therapist account",',
        replace='    if False:\n        raise ApiError(\n            status_code=403,\n            detail="not a therapist account",',
        tests=backend_pytest("tests/test_therapist_api.py"),
    ),
    dict(
        id="F5", campaign="F", name="mobile PBKDF2 iterations 600_000 -> 1_000",
        expectation="KDF contract + cross-platform vector tests must fail",
        file="mobile/src/crypto/kdf.ts",
        find="export const KDF_ITERATIONS = 600_000;",
        replace="export const KDF_ITERATIONS = 1_000;",
        tests=vitest("mobile", "tests/crypto.test.ts", "tests/vectors.test.ts"),
    ),
    dict(
        id="F6", campaign="F", name="portal PBKDF2 iterations 600_000 -> 1_000",
        expectation="portal KDF contract tests must fail",
        file="portal/src/crypto.ts",
        find="export const KDF_ITERATIONS = 600_000;",
        replace="export const KDF_ITERATIONS = 1_000;",
        tests=vitest("portal", "tests/crypto.test.ts"),
    ),
    dict(
        id="F7", campaign="F", name="backend KDF iteration floor 100_000 -> 1",
        expectation="downgrade-refusal tests must fail",
        file="backend/app/security/kdf.py",
        find="MIN_ITERATIONS = 100_000",
        replace="MIN_ITERATIONS = 1",
        tests=backend_pytest("tests/test_kdf.py"),
    ),
    dict(
        id="F8", campaign="F", name="keychain write failure falls back to plaintext AsyncStorage",
        expectation="fail-closed custody tests must fail",
        file="mobile/src/secureStore.ts",
        find='    if (!result) throw new Error("device secure storage rejected the session key");',
        replace='    if (!result) { await AsyncStorage.setItem(LEGACY_DEVICE_KEY_STORAGE, keyB64); return; }',
        tests=vitest("mobile", "tests/secureStore.test.ts"),
    ),
]


def parse_failures(kind: str, output: str) -> list[str]:
    fails: list[str] = []
    if kind == "pytest":
        fails = re.findall(r"^(FAILED|ERROR) (\S+)", output, re.M)
    elif kind == "vitest":
        fails = re.findall(r"^FAIL {2}(\S+)", output, re.M)
        if not fails:
            fails = re.findall(r"× (\S.*)", output, re.M)
    elif kind == "probe":
        fails = re.findall(r"^(FAIL.*)$", output, re.M)
    seen, ordered = set(), []
    for f in fails:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered[:8]


# pytest exit codes that mean the ORACLE (not the code under test) is
# broken: 2 interrupted, 3 internal error, 4 usage error (a renamed or
# deleted test file lands here), 5 no tests collected. Counting any of
# these as KILLED would print PASSED while verifying nothing — they are
# SETUP-ERRORs, reported loudly, never kills.
PYTEST_SETUP_EXITS = {2, 3, 4, 5}


def oracle_setup_error(kind: str, returncode: int, output: str) -> str | None:
    """Why this non-zero exit is a broken oracle rather than a kill, or None."""
    if kind != "pytest":
        return None
    if returncode in PYTEST_SETUP_EXITS:
        return f"pytest exited {returncode} (oracle broken, not a kill)"
    if "no tests ran" in output:
        return "pytest collected no tests (oracle broken, not a kill)"
    return None


def run_mutant(m: dict) -> dict:
    target = ROOT / m["file"]
    original = target.read_bytes()
    text = original.decode("utf-8")
    n = text.count(m["find"])
    want = m.get("count", 1)
    if n < want:
        return {**m, "killed": None, "status": "SETUP-ERROR",
                "detail": f"find-string matched {n} times, expected {want}"}
    mutated = text.replace(m["find"], m["replace"], want)
    target.write_text(mutated)
    t0 = time.monotonic()
    try:
        env = dict(os.environ, CI="true")
        proc = subprocess.run(
            m["tests"]["cmd"], cwd=ROOT / m["tests"]["cwd"],
            capture_output=True, text=True, timeout=m["tests"]["timeout"], env=env,
        )
        elapsed = round(time.monotonic() - t0, 1)
        out = (proc.stdout or "") + (proc.stderr or "")
        setup_error = oracle_setup_error(m["tests"]["kind"], proc.returncode, out)
        if setup_error:
            # The oracle could not run (renamed test file, collection
            # crash, bad flag): a KILLED verdict here would verify
            # nothing. Fail loudly instead of green.
            return {**m, "killed": None, "status": "SETUP-ERROR",
                    "detail": setup_error, "returncode": proc.returncode,
                    "seconds": elapsed, "output_tail": out[-1500:]}
        killed = proc.returncode != 0
        return {**m, "killed": killed, "status": "KILLED" if killed else "SURVIVED",
                "failing_tests": parse_failures(m["tests"]["kind"], out),
                "returncode": proc.returncode, "seconds": elapsed,
                "output_tail": out[-1500:]}
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - t0, 1)
        out = ((exc.stdout or b"").decode(errors="replace")
               + (exc.stderr or b"").decode(errors="replace"))
        return {**m, "killed": True, "status": "KILLED (timeout — hang is observable)",
                "failing_tests": [], "seconds": elapsed, "output_tail": out[-1500:]}
    finally:
        target.write_bytes(original)
        if target.read_bytes() != original:
            raise RuntimeError(f"RESTORE FAILED for {m['id']} — {m['file']}")


def main() -> None:
    wanted = sys.argv[1:]
    todo = [m for m in MUTANTS if not wanted or m["campaign"] in wanted]
    print(f"{len(todo)} mutants queued\n", flush=True)
    results = []
    for m in todo:
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        r = run_mutant(m)
        results.append(r)
        print(f"    -> {r['status']} ({r.get('seconds', '?')}s)"
              + (f"  first fail: {r['failing_tests'][0]}" if r.get("failing_tests") else "")
              + ("\n    !! " + r.get("detail", "") if r["status"] == "SETUP-ERROR" else ""),
              flush=True)
    killed = sum(1 for r in results if r["killed"])
    done = [r for r in results if r["killed"] is not None]
    print(f"\n{killed}/{len(done)} killed, {len(done) - killed} survived", flush=True)
    stamp = time.strftime("%Y-%m-%dT%H%M%S")
    path = OUT_DIR / f"mutation_results_{stamp}.json"
    path.write_text(json.dumps(results, indent=2))
    print(f"results: {path}")


if __name__ == "__main__":
    main()
