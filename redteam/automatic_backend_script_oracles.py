"""Behavior oracles for offline backend tooling and deterministic outputs."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import dataclasses
import hashlib
import importlib
import io
import json
import random
import runpy
import sys
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
CONTRACT = ROOT / "redteam/automatic_backend_contracts/runtime_outputs.json"


@pytest.fixture(autouse=True)
def bounded_synthetic_work(monkeypatch, request):
    """Small supplied corpora must finish within their random-draw budget.

    Date-loop regressions should fail this termination contract in the test
    call, before accumulating an unbounded corpus or timing out the runner.
    """
    original = random.Random
    limit = 100000 if "monte_carlo" in request.node.name else 10000

    class BoundedRandom(original):
        def __init__(self, *args, **kwargs):
            self._draws = 0
            super().__init__(*args, **kwargs)

        def __getattribute__(self, name):
            value = super().__getattribute__(name)
            if name not in ("random", "uniform", "gauss", "randrange", "choice"):
                return value

            def draw(*args, **kwargs):
                self._draws += 1
                assert self._draws <= limit, (
                    "utility exceeded deterministic input draw budget"
                )
                return value(*args, **kwargs)

            return draw

    monkeypatch.setattr(random, "Random", BoundedRandom)


def normalize(value):
    if dataclasses.is_dataclass(value):
        return normalize(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [normalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted(normalize(item) for item in value)
    if isinstance(value, date):
        return value.isoformat()
    return value


def seed_cases():
    module = importlib.import_module("scripts.seed_demo")
    out = {
        f"{days}:{seed}:{long}": normalize(
            module.build_corpus(date(2026, 9, 4), days, seed, long)
        )
        for days, seed, long in [
            (1, 7, False),
            (30, 7, False),
            (84, 7, False),
            (220, 7, True),
            (84, 42, False),
            (31, 11, False),
            (36, 2, False),
            (85, 1, False),
            (221, 11, True),
            (220, 8, True),
            (220, 18, True),
        ]
    }
    out["implicit_default"] = normalize(module.build_corpus(date(2026, 9, 4), 84, 7))
    out["assets"] = {
        name: normalize(getattr(module, name))
        for name in (
            "FILLERS",
            "SLEEP_WORRY",
            "POSITIVE",
            "NEGATIVE",
            "GUITAR_VARIANTS",
        )
    }
    return out


def mc_cases(monkeypatch):
    module = importlib.import_module("scripts.mc_phi_eff")
    output = {"ar1": [module.ar1(random.Random(117), phi, 7) for phi in (0, 0.5, 0.8)]}
    records = []

    def detect(samples):
        records.append(normalize(samples))
        return [type("Signal", (), {"pvalue": 0.01 if len(records) % 2 else 0.2})()]

    monkeypatch.setattr(module.brain, "_detect_mood_shift", detect)
    output["cells"] = [module.run_cell(n, phi, 3) for n, phi in [(21, 0.5), (40, 0.8)]]
    output["samples"] = records
    monkeypatch.setattr(module, "run_cell", lambda n, phi, reps: (n / 100, phi / 10))
    original = module.brain._MOOD_SHIFT_PHI_EFF_K, module.brain._MOOD_SHIFT_PHI_EFF_MAX
    text = io.StringIO()
    with contextlib.redirect_stdout(text):
        module.scan(3)
        module.final(3)
    output["report"] = text.getvalue()
    output["restored"] = [
        module.brain._MOOD_SHIFT_PHI_EFF_K == original[0],
        module.brain._MOOD_SHIFT_PHI_EFF_MAX == original[1],
    ]
    return normalize(output)


def probe_cases():
    from app.services import brain

    update, calls, previous = brain.update, [], [None]

    def traced(state, entries, today):
        calls.append(
            {
                "day": normalize(today),
                "dates": normalize([e.entry_date for e in entries]),
                "state_is_none": state is None,
                "threads_previous_state": state is previous[0],
                "last_two_entries": normalize(entries[-2:]),
            }
        )
        result = update(state, entries, today)
        previous[0] = result.new_state
        return result

    text = io.StringIO()
    with pytest.MonkeyPatch.context() as patch, contextlib.redirect_stdout(text):
        patch.setattr(brain, "update", traced)
        namespace = runpy.run_path(str(BACKEND / "probe_brain.py"), run_name="__main__")
    # Every declared phrase is part of the ground-truth scenario, including
    # variants not selected by this particular fixed random seed.
    assets = (
        "start",
        "end",
        "FILLERS",
        "SLEEP_VARIANTS",
        "FAMILY_DAYS",
        "SLEEP_PHRASE_DAYS",
        "GUITAR_VARIANTS",
        "GUITAR_EARLY",
        "GUITAR_LATE_COUNT",
        "SCATTERED_WORK_DAYS",
        "_TAGLESS_NEUTRALS",
        "_TAGLESS_THEME",
        "_TAGLESS_NEGATIVES",
        "guitar_late_days",
        "mood",
        "filler_uses",
    )
    return {
        "report": text.getvalue(),
        "entries": normalize(namespace["entries"]),
        "mixed": normalize(namespace["_mixed_corpora"]()),
        "tagless_genuine": normalize(namespace["_tagless_corpus"](True)),
        "tagless_overlap": normalize(namespace["_tagless_corpus"](False)),
        "assets": {name: normalize(namespace[name]) for name in assets},
        "kind_filters": {
            kind: normalize(namespace["surfaced_kinds"](kind))
            for kind in (
                "temporal",
                "mood_correlation",
                "rumination",
                "mood_shift",
                "topic",
                "link",
                "absent",
            )
        },
        "analysis_calls": calls,
        "failures": namespace["PROBE_FAILURES"],
    }


def help_case(script, monkeypatch):
    import os
    import subprocess
    import tempfile

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run(
            [sys.executable, str(BACKEND / script), "--help"],
            cwd=directory,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_seed_demo_reproduces_documented_corpora():
    assert seed_cases() == json.loads(CONTRACT.read_text())["seed"]


def seed_endpoint_samples(monkeypatch):
    import math

    module = importlib.import_module("scripts.seed_demo")
    original = random.Random
    outputs = {}
    for profile in (
        "upper",
        "lower",
        "threshold",
        "negative_threshold",
        "skip_threshold",
    ):

        class EndpointRandom(original):
            def __init__(self, seed, selected_profile=profile):
                self.carry = 0.0
                self.profile = selected_profile
                super().__init__(seed)

            def uniform(self, low, high):
                phi = 0.05 if high == 0.15 else 0.60
                if self.profile in ("upper", "skip_threshold"):
                    value = high
                elif (
                    self.profile == "lower"
                    or self.profile == "negative_threshold"
                    and high == 0.15
                ):
                    value = low
                elif high == 0.15:
                    value = high
                else:
                    target = -0.35 if self.profile == "negative_threshold" else 0.35
                    value = (target - 0.05 - phi * self.carry) / (1 - phi)
                    if not low <= value <= high:
                        value = max(low, min(high, value))
                    else:
                        for _ in range(4):
                            computed = 0.05 + phi * self.carry + (1 - phi) * value
                            if computed == target:
                                break
                            value = math.nextafter(
                                value, math.inf if computed < target else -math.inf
                            )
                assert low <= value <= high
                self.carry = phi * self.carry + (1 - phi) * value
                return value

            def random(self):
                return 0.85 if self.profile == "skip_threshold" else 0.0

            def randrange(self, stop):
                return 0

            def choice(self, values):
                return values[0]

        with monkeypatch.context() as patch:
            patch.setattr(random, "Random", EndpointRandom)
            outputs[profile] = normalize(module.build_corpus(date(2026, 9, 4), 84, 7))
    return outputs


def test_seed_demo_positive_negative_and_exact_threshold_samples(monkeypatch):
    assert (
        seed_endpoint_samples(monkeypatch)
        == json.loads(CONTRACT.read_text())["seed_endpoints"]
    )


def test_monte_carlo_samples_and_scan_restore_tuning(monkeypatch):
    assert mc_cases(monkeypatch) == json.loads(CONTRACT.read_text())["mc"]


def test_monte_carlo_cli_dispatch_and_defaults(monkeypatch, capsys):
    from app.services import brain

    monkeypatch.setattr(brain, "_detect_mood_shift", lambda samples: [])
    for arguments, reps in (([], 400), (["final", "2"], 2)):
        monkeypatch.setattr(sys, "argv", ["mc_phi_eff.py", *arguments])
        runpy.run_path(str(BACKEND / "scripts/mc_phi_eff.py"), run_name="__main__")
        assert capsys.readouterr().out == "".join(
            f"n={n:3d} phi={p:.1f} reps={reps} alarm=0.000 P(p<=.05)=0.000\n"
            for n in (21, 40, 90)
            for p in (0.0, 0.5, 0.8)
        )
    monkeypatch.setattr(sys, "argv", ["mc_phi_eff.py", "scan", "1"])
    runpy.run_path(str(BACKEND / "scripts/mc_phi_eff.py"), run_name="__main__")
    assert capsys.readouterr().out == "".join(
        f"k={k:4.1f} cap={cap:4.2f} 0.000 0.000 0.000 0.000\n"
        for k in (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0)
        for cap in (0.99, 2.2)
    )
    monkeypatch.setattr(sys, "argv", ["mc_phi_eff.py", "unknown"])
    with pytest.raises(KeyError) as caught:
        runpy.run_path(str(BACKEND / "scripts/mc_phi_eff.py"), run_name="__main__")
    assert caught.value.args == ("unknown",)


def test_monte_carlo_boundary_p_values_and_tuning_matrix(monkeypatch, capsys):
    module = importlib.import_module("scripts.mc_phi_eff")
    from datetime import timedelta

    samples = []
    results = iter(
        (
            [],
            [SimpleNamespace(pvalue=0.05)],
            [SimpleNamespace(pvalue=0.051)],
            [SimpleNamespace(pvalue=0.001)],
        )
    )

    def detect(series):
        samples.append(series)
        return next(results)

    monkeypatch.setattr(module.brain, "_detect_mood_shift", detect)
    assert module.run_cell(21, 0.999, 4) == (0.75, 0.5)
    rng = random.Random(20260927 + 21 * 1000 + int(0.999 * 100))
    for series in samples:
        assert series == list(
            zip(
                [date(2026, 1, 1) + timedelta(days=i) for i in range(21)],
                module.ar1(rng, 0.999, 21),
            )
        )
    original = module.brain._MOOD_SHIFT_PHI_EFF_K, module.brain._MOOD_SHIFT_PHI_EFF_MAX
    matrix = []

    def cell(n, phi, reps):
        matrix.append(
            (
                n,
                phi,
                reps,
                module.brain._MOOD_SHIFT_PHI_EFF_K,
                module.brain._MOOD_SHIFT_PHI_EFF_MAX,
            )
        )
        return 0.1, 0.06

    monkeypatch.setattr(module, "run_cell", cell)
    module.scan(2)
    assert matrix == [
        (n, phi, 2, k, cap)
        for k in (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0)
        for cap in (0.99, 2.2)
        for n, phi in ((21, 0.5), (21, 0.8), (40, 0.5), (40, 0.8))
    ]
    assert (
        module.brain._MOOD_SHIFT_PHI_EFF_K,
        module.brain._MOOD_SHIFT_PHI_EFF_MAX,
    ) == original
    assert capsys.readouterr().out == "".join(
        f"k={k:4.1f} cap={cap:4.2f} 0.060 0.060 0.060 0.060\n"
        for k in (1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 8.0, 10.0)
        for cap in (0.99, 2.2)
    )


def test_monte_carlo_documented_cli_imports_without_pythonpath(tmp_path):
    import os
    import subprocess

    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "scripts/mc_phi_eff.py", "final", "1"],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert (
        len(result.stdout.splitlines()) == 9 and "n= 21 phi=0.0 reps=1" in result.stdout
    )


def test_brain_probe_inputs_and_ground_truth_report():
    assert probe_cases() == json.loads(CONTRACT.read_text())["probe"]


@pytest.mark.parametrize(
    "script",
    [
        "bootstrap_entry_guards.py",
        "scripts/seed_demo.py",
        "scripts/loadtest.py",
        "scripts/seal_legacy_audit.py",
    ],
)
def test_offline_cli_help_contract(script, monkeypatch):
    assert (
        help_case(script, monkeypatch)
        == json.loads(CONTRACT.read_text())["help"][script]
    )


@pytest.mark.parametrize("kind", ["lexicon", "brain_vectors", "crypto_vectors"])
def test_generators_preserve_released_artifacts(kind, tmp_path, monkeypatch, capsys):
    if kind == "lexicon":
        module = importlib.import_module("scripts.dump_brain_lexicon")
        expected = json.loads((ROOT / "shared/brain_lexicon.json").read_text())
        output = tmp_path / "lexicon.json"
        ts = [tmp_path / "mobile.ts", tmp_path / "web.ts"]
        monkeypatch.setattr(module, "OUT", output)
        monkeypatch.setattr(module, "TS_OUTS", tuple(ts))
        module.main()
        assert json.loads(output.read_text()) == expected
        assert (
            output.read_text()
            == json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
        )
        for path in ts:
            text = path.read_text()
            assert text.startswith(module.TS_PRELUDE) and text.endswith(";\n")
            assert json.loads(text[len(module.TS_PRELUDE) : -2]) == expected
        assert capsys.readouterr().out == (
            f"wrote {output} ({output.stat().st_size} bytes, "
            f"{len(expected['sentiment_lexicon'])} sentiment words) and 2 TS modules\n"
        )
    elif kind == "brain_vectors":
        module = importlib.import_module("scripts.gen_brain_vectors")
        expected = json.loads((ROOT / "shared/brain_vectors.json").read_text())
        output = tmp_path / "brain_vectors.json"
        monkeypatch.setattr(module, "OUT", output)
        assert normalize(module.build_payload()) == expected
        module.main()
        assert json.loads(output.read_text()) == expected
        assert output.read_text() == json.dumps(expected, indent=1) + "\n"
        assert capsys.readouterr().out == (
            f"wrote {output}: {len(expected['sentiment'])} sentiment vectors, "
            f"{len(expected['updates'])} full-engine update cases, "
            f"{len(expected['stats']['erfc'])} erfc, "
            f"{len(expected['stats']['pearson'])} pearson, "
            f"{len(expected['stats']['fisher_z'])} fisher-z\n"
        )
    else:
        module = importlib.import_module("scripts.generate_vectors")
        expected = json.loads((ROOT / "shared/vectors.json").read_text())
        expected["review_annotation"] = "retain this scalar"
        expected["metadata"] = {"operator": "reviewer", "scope": "manual"}
        monkeypatch.setattr(module.kdf, "KDF_ITERATIONS", 2)
        monkeypatch.setattr(module.kdf, "MIN_ITERATIONS", 1)
        shared = tmp_path / "shared"
        shared.mkdir()
        output = shared / "vectors.json"
        # The hand-maintained sections must survive regeneration verbatim.
        output.write_text(json.dumps(expected, indent=1) + "\n")
        monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
        module.main()
        generated = json.loads(
            (
                ROOT / "redteam/automatic_backend_contracts/crypto_vectors_small.json"
            ).read_text()
        )
        expected.update(generated)
        assert json.loads(output.read_text()) == expected
        assert output.read_text() == json.dumps(expected, indent=1) + "\n"
        assert capsys.readouterr().out == (
            f"wrote 4 vectors + 6 encrypt vectors + 4 envelope vectors -> {output}\n"
            "preserved hand-maintained sections: wrap_vectors (3), aad_edge_cases (17), review_annotation (1), metadata (2)\n"
        )


@pytest.mark.parametrize("kind", ["lexicon", "brain_vectors", "crypto_vectors"])
def test_generator_cli_paths_and_entrypoint(kind, tmp_path):
    import os
    import shutil
    import subprocess

    script, artifact = {
        "lexicon": ("dump_brain_lexicon.py", "brain_lexicon.json"),
        "brain_vectors": ("gen_brain_vectors.py", "brain_vectors.json"),
        "crypto_vectors": ("generate_vectors.py", "vectors.json"),
    }[kind]
    backend = tmp_path / "backend"
    (backend / "scripts").mkdir(parents=True)
    (backend / "app").symlink_to(BACKEND / "app", target_is_directory=True)
    shutil.copyfile(BACKEND / "scripts" / script, backend / "scripts" / script)
    (tmp_path / "shared").mkdir()
    for client in ("mobile", "web"):
        (tmp_path / client / "src/brain").mkdir(parents=True)
    target = tmp_path / "shared" / artifact
    expected = json.loads((ROOT / "shared" / artifact).read_text())
    if kind == "crypto_vectors":
        target.write_text(json.dumps(expected, indent=1) + "\n")
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(backend / "scripts" / script)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("wrote ")
    assert str(target) in result.stdout
    assert json.loads(target.read_text()) == expected
    if kind == "lexicon":
        for client in ("mobile", "web"):
            assert (tmp_path / client / "src/brain/lexicon.ts").read_text() == (
                ROOT / client / "src/brain/lexicon.ts"
            ).read_text()


def test_crypto_generator_derivation_and_tamper(monkeypatch):
    module = importlib.import_module("scripts.generate_vectors")
    monkeypatch.setattr(module.kdf, "KDF_ITERATIONS", 3)
    monkeypatch.setattr(module.kdf, "MIN_ITERATIONS", 1)
    password, salt = "ü-secret", b"0123456789abcdef"
    master, auth, data = module.derive_keys(password, salt)
    expected = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 3, 32)
    assert master == expected
    assert auth == module.kdf.derive_auth_key(expected)
    assert data == module.kdf.derive_data_key(expected)
    assert len({master, auth, data}) == 3
    monkeypatch.setattr(module.kdf, "derive_master_key", lambda *a: b"x" * 32)
    with pytest.raises(AssertionError) as caught:
        module.derive_keys(password, salt)
    assert str(caught.value) == "PBKDF2 implementations disagree!"
    blob = bytes(range(40))
    assert module._tamper(blob) == blob[:20] + bytes([blob[20] ^ 1]) + blob[21:]
    assert blob == bytes(range(40))


def test_crypto_generator_refuses_invalid_existing_data(tmp_path, monkeypatch, capsys):
    module = importlib.import_module("scripts.generate_vectors")
    monkeypatch.setattr(module.kdf, "KDF_ITERATIONS", 2)
    monkeypatch.setattr(module.kdf, "MIN_ITERATIONS", 1)
    monkeypatch.setattr(module, "REPO_ROOT", tmp_path)
    path = tmp_path / "shared/vectors.json"
    path.parent.mkdir()
    for invalid in ("{broken", "[1, 2]"):
        path.write_text(invalid)
        with pytest.raises(SystemExit) as caught:
            module.main()
        if invalid == "{broken":
            try:
                json.loads(invalid)
            except json.JSONDecodeError as error:
                expected = (
                    f"refusing to regenerate: {path} exists but is not valid JSON ({error}); "
                    "fix or remove the file by hand so hand-maintained sections are not lost"
                )
        else:
            expected = (
                f"refusing to regenerate: {path} has a top-level list, "
                "expected a JSON object; fix the file by hand so hand-maintained sections are not lost"
            )
        assert str(caught.value) == expected
        assert path.read_text() == invalid
    path.unlink()
    module.main()
    assert capsys.readouterr().out == (
        f"wrote 4 vectors + 6 encrypt vectors + 4 envelope vectors -> {path}\n"
        "preserved hand-maintained sections: none\n"
    )
    generated = json.loads(
        (
            ROOT / "redteam/automatic_backend_contracts/crypto_vectors_small.json"
        ).read_text()
    )
    assert path.read_text() == json.dumps(generated, indent=2) + "\n"
    for indent in (1, 2, 3, 4, "\t"):
        path.write_text(json.dumps(generated, indent=indent) + "\n")
        module.main()
        assert path.read_text() == json.dumps(generated, indent=indent) + "\n"
    path.write_text("{}\n")
    module.main()
    assert path.read_text() == json.dumps(generated, indent=1) + "\n"
    fresh = tmp_path / "new" / "campaign"
    monkeypatch.setattr(module, "REPO_ROOT", fresh)
    module.main()
    assert (fresh / "shared/vectors.json").read_text() == json.dumps(
        generated, indent=2
    ) + "\n"


def test_brain_generator_precision_and_full_corpus_inputs(monkeypatch):
    module = importlib.import_module("scripts.gen_brain_vectors")
    records = {}
    for name in ("z", "a"):
        records[name] = SimpleNamespace(
            pid=name,
            kind="topic",
            label="topic-" + name,
            first_seen="2026-08-02",
            last_seen="2026-09-01",
            first_qualified="2026-08-09",
            last_qualified="2026-08-16",
            occurrences=3,
            state="established",
            qualification_days=["2026-08-09", "2026-08-16"],
            evidence_dates=["2026-08-02"],
            detail={"value": 0.12345678945, "integer": 2, "word": "keep"},
        )
    calls = []

    def update(state, corpus, today):
        calls.append(
            {
                "state": normalize(state),
                "corpus": normalize(corpus),
                "today": normalize(today),
            }
        )
        return SimpleNamespace(surfaced=[records["z"]], new_state={"patterns": records})

    monkeypatch.setattr(module.brain, "update", update)
    monkeypatch.setattr(
        module.brain, "sentiment_components", lambda tokens: (0.123456789, 0.876543211)
    )
    payload = module.build_payload()
    for row in payload["sentiment"]:
        assert row["pa"] == 0.123457 and row["na"] == 0.876543
    for result in payload["updates"]:
        assert result["case"]["surfaced"][0]["detail"] == {
            "value": 0.123456789,
            "integer": 2,
            "word": "keep",
        }
        assert [row["pid"] for row in result["case"]["state"]] == ["a", "z"]
        for record in result["case"]["state"]:
            assert record["detail"] == {
                "value": 0.123456789,
                "integer": 2,
                "word": "keep",
            }
    assert calls == json.loads(CONTRACT.read_text())["brain_generator_inputs"]


def test_load_probe_phase_measures_wall_time(monkeypatch, capsys):
    module = importlib.import_module("scripts.loadtest")
    clock = iter((10, 11, 12, 13, 14, 15, 17, 20))
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: next(clock)))

    async def success():
        return True

    async def false():
        return False

    async def failure():
        raise ValueError("transport failure")

    result = asyncio.run(module.phase(None, "phase", [success(), false(), failure()]))
    assert result.label == "phase" and result.latencies == [1]
    assert result.failures == 2 and result.elapsed == 10
    assert capsys.readouterr().out == (
        "  phase: n=1 fail=2 p50=1.000s p95=1.000s "
        "max=1.000s completion-rate=0.10/s (wall 10.0s)\n"
    )


def test_probe_failure_records_reject_false_ground_truth(monkeypatch, capsys):
    from app.services import brain

    monkeypatch.setattr(
        brain,
        "update",
        lambda state, entries, today: SimpleNamespace(
            new_state={"patterns": {}}, surfaced=[]
        ),
    )
    with pytest.raises(
        SystemExit, match=r"probe_brain: 9 check\(s\) failed:"
    ) as caught:
        runpy.run_path(str(BACKEND / "probe_brain.py"), run_name="__main__")
    assert str(caught.value).startswith("probe_brain: 9 check(s) failed: [") and str(
        caught.value
    ).endswith("]")
    report = capsys.readouterr().out
    assert report.count("  FAIL  ") == 9
    assert report.count("  PASS  ") == 2


@pytest.mark.parametrize(
    "fault,target",
    [
        ("temporal", "A temporal:work (Sundays, surfaced)"),
        ("correlation", "A mood_correlation:work lower (within-weekday, surfaced)"),
        ("rumination", "B rumination (THE sleep cluster, surfaced)"),
        ("shift", "C mood_shift:lower (surfaced)"),
        ("topic", "D topic:guitar (rising, varied phrasing, surfaced)"),
        ("link", "E link:family lower (surfaced)"),
        ("inertia", "F inertia (mixed corpus, surfaced)"),
        ("instability", "G instability (mixed corpus, surfaced)"),
        ("false_link", "H no confound/false associations"),
        ("false_correlation", "H no confound/false associations"),
        ("false_topic", "H no confound/false associations"),
        ("genuine", "I tag-less genuine tie surfaces (text-scored mood path)"),
        (
            "tautology",
            "J tag-less lexical overlap alone mints nothing (tautology broken)",
        ),
    ],
)
def test_probe_rejects_individual_wrong_analysis_results(
    fault, target, monkeypatch, capsys
):
    from app.services import brain

    def card(kind, label, **detail):
        return SimpleNamespace(
            kind=kind,
            label=label,
            pid=kind + ":" + label,
            detail={
                "direction": "lower",
                "trend": "rising",
                "mood_delta": -0.2,
                "p_value": 0.01,
                **detail,
            },
            state="established",
            occurrences=3,
        )

    main = [
        card("temporal", "work"),
        card("mood_correlation", "work"),
        card("rumination", "sleep"),
        card("mood_shift", "decline"),
        card("topic", "guitar"),
        card("link", "family"),
    ]
    poison = {
        "temporal": (0, card("temporal", "other")),
        "correlation": (1, card("mood_correlation", "work", direction="higher")),
        "rumination": (2, card("rumination", "other")),
        "shift": (3, card("mood_shift", "decline", direction="higher")),
        "topic": (4, card("topic", "guitar", trend="falling")),
        "link": (5, card("link", "other")),
    }
    if fault in poison:
        index, wrong = poison[fault]
        main[index] = wrong
    if fault == "false_link":
        main.append(card("link", "unplanted"))
    if fault == "false_correlation":
        main.append(card("mood_correlation", "unplanted"))
    if fault == "false_topic":
        main.append(card("topic", "unplanted"))

    def analysis(state, entries, today):
        if len(entries) == 70:
            surfaced = [card("inertia", "carryover"), card("instability", "spread")]
            if fault == "inertia":
                surfaced = surfaced[1:]
            if fault == "instability":
                surfaced = surfaced[:1]
        elif len(entries) >= 104:
            genuine = any("grim and miserable" in entry.text for entry in entries)
            surfaced = [card("mood_correlation", "sleep")] if genuine else []
            if genuine and fault == "genuine":
                surfaced = [card("mood_correlation", "sleep", direction="higher")]
            if not genuine and fault == "tautology":
                surfaced = [card("mood_correlation", "sleep")]
        else:
            surfaced = main
        return SimpleNamespace(
            new_state={"patterns": {p.pid: p for p in surfaced}}, surfaced=surfaced
        )

    monkeypatch.setattr(brain, "update", analysis)
    with pytest.raises(SystemExit):
        runpy.run_path(str(BACKEND / "probe_brain.py"), run_name="__main__")
    assert "  FAIL  " + target in capsys.readouterr().out


def test_probe_retries_when_first_card_is_not_surfaced(monkeypatch, capsys):
    from datetime import timedelta

    from app.services import brain

    update, end = brain.update, date(2026, 9, 4)
    calls = []

    def delayed(state, entries, today):
        calls.append((len(entries), today))
        result = update(state, entries, today)
        surfaced = result.surfaced
        if len(entries) == 70 and today == end:
            surfaced = []
        if today == end + timedelta(days=1):
            surfaced = [p for p in surfaced if p.kind != "mood_shift"]
        return SimpleNamespace(new_state=result.new_state, surfaced=surfaced)

    monkeypatch.setattr(brain, "update", delayed)
    namespace = runpy.run_path(str(BACKEND / "probe_brain.py"), run_name="__main__")
    assert namespace["PROBE_FAILURES"] == []
    assert (60, end + timedelta(days=1)) in calls and (
        60,
        end + timedelta(days=2),
    ) in calls
    assert [d for n, d in calls if n == 70] == [
        end,
        end + timedelta(days=7),
        end,
        end + timedelta(days=7),
    ]


def test_probe_accepts_already_surfaced_mixed_cards_without_retry(monkeypatch, capsys):
    from app.services import brain

    update, end = brain.update, date(2026, 9, 4)
    calls = []

    def qualified(state, entries, today):
        result = update(state, entries, today)
        if len(entries) == 70:
            calls.append(today)
            return SimpleNamespace(
                new_state=result.new_state,
                surfaced=[
                    SimpleNamespace(kind="inertia"),
                    SimpleNamespace(kind="instability"),
                ],
            )
        return result

    monkeypatch.setattr(brain, "update", qualified)
    namespace = runpy.run_path(str(BACKEND / "probe_brain.py"), run_name="__main__")
    assert namespace["PROBE_FAILURES"] == []
    assert calls == [end, end]


def test_probe_random_skip_excludes_exact_probability_boundary(monkeypatch):
    original = random.Random

    class BoundaryRandom(original):
        def random(self):
            return 0.9

    monkeypatch.setattr(random, "Random", BoundaryRandom)
    specification = importlib.util.spec_from_file_location(
        "bounded_probe_example", BACKEND / "probe_brain.py"
    )
    module = importlib.util.module_from_spec(specification)
    with pytest.raises(SystemExit):
        specification.loader.exec_module(module)
    assert module.entries == []


def test_seal_snapshot_digest_size_and_attestation(tmp_path, monkeypatch):
    module = importlib.import_module("scripts.seal_legacy_audit")
    assert module.MAX_ROWS == 100000 and module.MAX_SNAPSHOT_BYTES == 128 * 1024 * 1024
    value = {"z": 1, "a": "é"}
    raw = module.canonical_snapshot(value)
    assert raw == b'{"a":"\\u00e9","z":1}\n'
    digest = hashlib.sha256(raw).hexdigest()
    assertion = "Reviewed independent pre-MAC archive and reconciled every row."
    assert module.verify_attestation(raw, digest, assertion) is None
    for bad in ("", "0" * 64):
        with pytest.raises(ValueError) as caught:
            module.verify_attestation(raw, bad, assertion)
        assert str(caught.value) == "reviewed snapshot digest does not match"
    for assertion in ("x" * 39, " " * 40, "x" * 8193):
        with pytest.raises(ValueError) as caught:
            module.verify_attestation(raw, digest, assertion)
        assert (
            str(caught.value)
            == "a specific operator attestation of independent legacy provenance is required"
        )
    for size in (40, 8192):
        assert module.verify_attestation(raw, digest, "x" * size) is None
    monkeypatch.setattr(module, "MAX_SNAPSHOT_BYTES", len(raw))
    assert module.canonical_snapshot(value) == raw
    monkeypatch.setattr(module, "MAX_SNAPSHOT_BYTES", len(raw) - 1)
    with pytest.raises(ValueError) as caught:
        module.canonical_snapshot(value)
    assert (
        str(caught.value)
        == "snapshot exceeds the bounded migration size; use a reviewed partitioned migration"
    )
    private = tmp_path / "snapshot.json"
    module.write_private(private, raw)
    assert private.read_bytes() == raw and private.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        module.write_private(private, b"replace")
    assert private.read_bytes() == raw


def load_cli_case(
    monkeypatch,
    users,
    entries,
    days_back,
    *,
    database=False,
    baseline=False,
    tokenless=False,
    analyzer=None,
    sampled_indices=None,
):
    module = importlib.import_module("scripts.loadtest")
    import datetime

    from app.security import crypto, kdf

    class Today(date):
        @classmethod
        def today(cls):
            return cls(2026, 10, 5)

    monkeypatch.setattr(datetime, "date", Today)
    monkeypatch.setenv("LOADTEST_PASSWORD", "synthetic-password")
    arguments = [
        "loadtest.py",
        "--users",
        str(users),
        "--entries-per-user",
        str(entries),
        "--days-back",
        str(days_back),
    ]
    if database:
        arguments += ["--db-url", "sqlite+aiosqlite:///synthetic.db"]
    monkeypatch.setattr(sys, "argv", arguments)
    if sampled_indices is not None:
        # Exercise selected arithmetic boundaries without allocating the
        # entire requested stress-test corpus.
        original_range = range
        monkeypatch.setattr(
            module,
            "range",
            lambda count: (
                sampled_indices if count == entries else original_range(count)
            ),
            raising=False,
        )
    requests, phases, sql, resources = [], [], [], []

    class Client:
        def __init__(self, **options):
            assert options == {"base_url": "http://localhost:8000", "timeout": 120}
            self.registered = set()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            resources.append("http-close")

        async def post(self, path, **kwargs):
            captured = normalize(kwargs)
            if path == "/api/v1/auth/register":
                name = kwargs["json"]["username"]
                status = 400 if tokenless else (409 if name in self.registered else 201)
                self.registered.add(name)
                body = {"token": "token-" + name, "user_id": "uid-" + name}
            elif path == "/api/v1/auth/login":
                name = kwargs["json"]["username"]
                status, body = 200, {"token": "token-" + name, "user_id": "uid-" + name}
            elif path == "/api/v1/entries":
                token = kwargs["headers"]["Authorization"].removeprefix("Bearer ")
                name = token.removeprefix("token-") if token != "None" else "load0"
                salt = hashlib.sha256(
                    ("mindpattern-loadtest:" + name).encode()
                ).digest()[:16]
                master = hashlib.pbkdf2_hmac(
                    "sha256", b"synthetic-password", salt, 1000
                )
                key = kdf.derive_data_key(master)
                uid = "uid-" + name if token != "None" else ""
                blob = base64.b64decode(kwargs["json"]["blob"])
                captured["json"]["blob"] = json.loads(
                    crypto.decrypt(
                        key,
                        blob,
                        crypto.build_aad(
                            "entry", uid, kwargs["json"]["client_entry_id"]
                        ),
                    )
                )
                status, body = 201, {}
            elif path == "/api/v1/processing/sessions":
                status, body = 201, {"session_token": "once"}
            elif path == "/api/v1/insights/recompute":
                status, body = (
                    200,
                    {
                        "phase": "baseline" if baseline else "insight",
                        "analyzer": analyzer
                        if analyzer is not None
                        else ("none" if baseline else "brain"),
                        "active_days": entries,
                    },
                )
            else:
                raise AssertionError(path)
            requests.append([path, captured])
            return SimpleNamespace(status_code=status, json=lambda: body)

    monkeypatch.setattr(module.httpx, "AsyncClient", Client)

    async def phase(client, label, coros):
        outcomes = await asyncio.gather(*coros)
        phases.append([label, outcomes])
        return module.Stats(
            label, [0.1 for x in outcomes if x], sum(not x for x in outcomes), 1
        )

    monkeypatch.setattr(module, "phase", phase)
    if database:
        import sqlalchemy.ext.asyncio
        from app import db

        class Engine:
            async def dispose(self):
                resources.append("db-dispose")

        engine = Engine()

        def make_engine(url):
            assert url == "sqlite+aiosqlite:///synthetic.db"
            resources.append("db-open")
            return engine

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                resources.append("session-close")

            async def execute(self, query):
                params = query.compile().params
                assert str(query).endswith("WHERE users.id = :id_1")
                assert set(params) == {"created_at", "id_1"}
                age = (
                    datetime.datetime.now(datetime.timezone.utc) - params["created_at"]
                )
                assert days_back + 2 <= age.total_seconds() / 86400 < days_back + 2.001
                sql.append(params["id_1"])

            async def commit(self):
                resources.append("commit")

        def sessions(value):
            assert value is engine
            return Session

        monkeypatch.setattr(sqlalchemy.ext.asyncio, "create_async_engine", make_engine)
        monkeypatch.setattr(db, "build_sessionmaker", sessions)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert asyncio.run(module.main()) == 0
    return {
        "requests": requests,
        "phases": phases,
        "report": output.getvalue(),
        "sql": sql,
        "resources": resources,
    }


def test_load_cli_synthetic_runs(monkeypatch):
    expected = json.loads(CONTRACT.read_text())["load_cli"]
    cases = [
        (2, 32, 35, {}),
        (1, 3, 1, {"baseline": True}),
        (1, 32, 35, {"baseline": True}),
        (2, 30, 30, {"database": True}),
        (1, 2, 3, {"tokenless": True}),
        (1, 30, 30, {"baseline": True}),
        (1, 32, 35, {"analyzer": "none"}),
        (1, 32, 35, {"baseline": True, "analyzer": "brain"}),
    ]
    for index, (users, entries, days, options) in enumerate(cases):
        with monkeypatch.context() as patch:
            assert (
                load_cli_case(patch, users, entries, days, **options)
                == expected[str(index)]
            )


def test_load_cli_date_stratification_retains_integer_precision(monkeypatch):
    from datetime import timedelta

    count, days, index = 10**17, 100000, 9999999999999999
    result = load_cli_case(monkeypatch, 1, count, days, sampled_indices=[index])
    entries = [
        request["json"]
        for path, request in result["requests"]
        if path == "/api/v1/entries"
    ]
    assert len(entries) == 1
    expected = (date(2026, 10, 5) - timedelta(days=9999)).isoformat()
    assert entries[0]["entry_date"] == expected
    assert entries[0]["blob"]["created_at"] == expected


def test_load_cli_refuses_unconfirmed_remote_or_missing_password(monkeypatch, capsys):
    module = importlib.import_module("scripts.loadtest")
    monkeypatch.setattr(sys, "argv", ["loadtest.py", "--url", "https://example.test"])
    assert asyncio.run(module.main()) == 2
    assert capsys.readouterr().err == (
        "REFUSING to load-probe non-loopback target https://example.test without --yes-prod: "
        "this tool registers accounts, burns scrypt CPU and drives the full "
        "recompute pipeline against a live server. Re-run with --yes-prod if "
        "that is genuinely the intent.\n"
    )
    monkeypatch.setattr(sys, "argv", ["loadtest.py"])
    monkeypatch.delenv("LOADTEST_PASSWORD", raising=False)

    def fail_prompt(prompt):
        assert prompt == "loadtest account password: "
        raise EOFError

    monkeypatch.setattr(module.getpass, "getpass", fail_prompt)
    assert asyncio.run(module.main()) == 2
    assert (
        capsys.readouterr().err
        == "no password given (LOADTEST_PASSWORD or prompt) — refusing to run\n"
    )


def test_load_cli_defaults_loopback_and_password_prompt(monkeypatch):
    module = importlib.import_module("scripts.loadtest")

    class Parsed(BaseException):
        pass

    parsed, options = [], []
    original = module.argparse.ArgumentParser.parse_args

    def parse(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        parsed.append(vars(result))
        return result

    def client(**kwargs):
        options.append(kwargs)
        raise Parsed

    monkeypatch.setattr(module.argparse.ArgumentParser, "parse_args", parse)
    monkeypatch.setattr(module.httpx, "AsyncClient", client)
    monkeypatch.delenv("LOADTEST_PASSWORD", raising=False)
    prompts = []
    monkeypatch.setattr(
        module.getpass,
        "getpass",
        lambda text: prompts.append(text) or "synthetic-password",
    )
    for argv in (
        [],
        ["--url", "http://127.0.0.1:8000"],
        ["--url", "http://[::1]:8000"],
        ["--url", "https://example.test", "--yes-prod"],
    ):
        monkeypatch.setattr(sys, "argv", ["loadtest.py", *argv])
        with pytest.raises(Parsed):
            asyncio.run(module.main())
        assert parsed[-1] == {
            "url": "http://localhost:8000" if not argv else argv[1],
            "yes_prod": "--yes-prod" in argv,
            "users": 20,
            "entries_per_user": 32,
            "days_back": 35,
            "db_url": None,
        }
        assert options[-1] == {"base_url": parsed[-1]["url"], "timeout": 120}
    assert prompts == ["loadtest account password: "] * 4


def test_load_cli_documented_cwd_runs_real_protocol_without_pythonpath():
    import os
    import subprocess
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    requests = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            requests.append(self.path)
            json.loads(self.rfile.read(int(self.headers["Content-Length"]))) if int(
                self.headers.get("Content-Length", 0)
            ) else None
            if self.path.endswith("/auth/register"):
                status, body = (
                    201,
                    {"token": "synthetic-token", "user_id": "synthetic-user"},
                )
            elif self.path.endswith("/auth/login"):
                status, body = (
                    200,
                    {"token": "synthetic-token", "user_id": "synthetic-user"},
                )
            elif self.path.endswith("/processing/sessions"):
                status, body = 201, {"session_token": "single-use"}
            elif self.path.endswith("/insights/recompute"):
                status, body = (
                    200,
                    {"phase": "baseline", "analyzer": "none", "active_days": 3},
                )
            else:
                assert self.path == "/api/v1/entries"
                status, body = 201, {}
            encoded = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    env = dict(
        os.environ,
        LOADTEST_PASSWORD="synthetic-password",
        NO_PROXY="127.0.0.1,localhost,::1",
    )
    env.pop("PYTHONPATH", None)
    try:
        result = subprocess.run(
            [
                sys.executable,
                "scripts/loadtest.py",
                "--url",
                f"http://127.0.0.1:{server.server_port}",
                "--users",
                "1",
                "--entries-per-user",
                "3",
                "--days-back",
                "3",
            ],
            cwd=BACKEND,
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert result.returncode == 0, result.stderr
    for label, count in (
        ("register", 1),
        ("login", 1),
        ("create-entry", 3),
        ("recompute", 1),
    ):
        assert f"{label}: n={count} fail=0 " in result.stdout
    assert len(requests) == 7 and requests.count("/api/v1/entries") == 3


def seed_cli_case(
    monkeypatch,
    *,
    rerun=False,
    database=False,
    long=False,
    missing=False,
    prompted=False,
    throttled=False,
):
    module = importlib.import_module("scripts.seed_demo")
    import datetime

    from app.security import crypto, kdf

    class Today(date):
        @classmethod
        def today(cls):
            return cls(2026, 10, 5)

    monkeypatch.setattr(module, "date", Today)
    arguments = ["seed_demo.py"]
    if not prompted:
        arguments += ["--password", "synthetic-password"]
    if long:
        arguments += ["--long"]
    if database:
        arguments += ["--db-url", "sqlite+aiosqlite:///synthetic.db"]
    monkeypatch.setattr(sys, "argv", arguments)
    requests, resources, derivations, corpus_args = [], [], [], []
    monkeypatch.setattr(
        module.getpass,
        "getpass",
        lambda prompt: resources.append(["prompt", prompt]) or "synthetic-password",
    )

    def master(password, salt):
        derivations.append([password, base64.b64encode(salt).decode()])
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)

    monkeypatch.setattr(module.keyderive, "derive_master_key", master)
    salt = hashlib.sha256(b"mindpattern-seed-demo:demo").digest()[:16]
    data_key = kdf.derive_data_key(
        hashlib.pbkdf2_hmac("sha256", b"synthetic-password", salt, 1000)
    )
    rows = [
        {
            "text": "ordinary notes",
            "date": "2026-10-03",
            "sentiment": -0.25,
            "tags": ["painting"],
        },
        {"text": "another day", "date": "2026-10-05", "sentiment": 0.4},
        {"text": "after the duplicate", "date": "2026-10-04", "sentiment": 0.1},
    ]

    def corpus(*args):
        corpus_args.append(normalize(args))
        return rows

    monkeypatch.setattr(module, "build_corpus", corpus)
    monkeypatch.setattr(
        module.time, "sleep", lambda seconds: resources.append(["sleep", seconds])
    )

    class Response:
        def __init__(self, status, body=None):
            self.status_code, self.body = status, body or {}

        def json(self):
            return self.body

        def raise_for_status(self):
            if not 200 <= self.status_code < 300:
                raise AssertionError(self.status_code)

    class Client:
        def __init__(self, **options):
            assert options == {"base_url": "http://127.0.0.1:8000", "timeout": 30}
            self.entry_attempts = 0

        def post(self, path, **kwargs):
            captured = normalize(kwargs)
            if path == "/api/auth/register":
                status, body = (
                    (409 if rerun else 201),
                    {"token": "access-token", "user_id": "uid-123456"},
                )
            elif path == "/api/auth/login":
                status, body = 200, {"token": "access-token", "user_id": "uid-123456"}
            elif path == "/api/entries":
                self.entry_attempts += 1
                captured["json"]["blob"] = json.loads(
                    crypto.decrypt(
                        data_key,
                        base64.b64decode(kwargs["json"]["blob"]),
                        crypto.build_aad(
                            "entry", "uid-123456", kwargs["json"]["client_entry_id"]
                        ),
                    )
                )
                status, body = (
                    (
                        429
                        if throttled or self.entry_attempts <= 2
                        else (409 if self.entry_attempts == 4 else 201)
                    ),
                    {},
                )
            elif path == "/api/processing/sessions":
                status, body = 201, {"session_token": "processing"}
            elif path == "/api/insights/recompute":
                status, body = (
                    200,
                    {
                        "phase": "insight",
                        "active_days": 32,
                        "analyzer": "brain",
                        "patterns_stored": 2,
                        "question_stored": True,
                    },
                )
            else:
                raise AssertionError(path)
            requests.append([path, captured])
            return Response(status, body)

        def get(self, path, **kwargs):
            assert path == "/api/insights" and kwargs == {
                "headers": {"Authorization": "Bearer access-token"}
            }
            requests.append([path, kwargs])
            if missing:
                return Response(200)
            body = {
                "stats": {
                    "patterns": [
                        {
                            "kind": "temporal",
                            "label": "work",
                            "detail": {"pattern_state": "established"},
                        },
                        {"kind": "topic", "label": "guitar-" + "a" * 70, "detail": {}},
                    ]
                }
            }
            encrypted = crypto.encrypt(
                data_key,
                json.dumps(body).encode(),
                crypto.build_aad("insights", "uid-123456", "patterns"),
            )
            return Response(200, {"blob": base64.b64encode(encrypted).decode()})

    monkeypatch.setattr(module.httpx, "Client", Client)
    if database:
        import sqlalchemy.ext.asyncio
        from app import db

        class Engine:
            async def dispose(self):
                resources.append("dispose")

        engine = Engine()

        def make_engine(url):
            assert url == "sqlite+aiosqlite:///synthetic.db"
            resources.append("engine")
            return engine

        class Session:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *args):
                resources.append("session-close")

            async def execute(self, query):
                params = query.compile().params
                assert str(query).endswith("WHERE users.id = :id_1")
                assert (
                    set(params) == {"created_at", "id_1"}
                    and params["id_1"] == "uid-123456"
                )
                expected_days = 222 if long else 86
                age = (
                    datetime.datetime.now(datetime.timezone.utc) - params["created_at"]
                )
                assert (
                    expected_days <= age.total_seconds() / 86400 < expected_days + 0.001
                )
                resources.append("backdate")

            async def commit(self):
                resources.append("commit")

        def sessions(value):
            assert value is engine
            return Session

        monkeypatch.setattr(sqlalchemy.ext.asyncio, "create_async_engine", make_engine)
        monkeypatch.setattr(db, "build_sessionmaker", sessions)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        if throttled:
            with pytest.raises(AssertionError) as caught:
                module.main()
            assert str(caught.value) == "429"
        else:
            status = module.main()
            assert status == (1 if missing else 0)
    return {
        "requests": requests,
        "resources": resources,
        "derivations": derivations,
        "corpus_args": corpus_args,
        "report": output.getvalue(),
    }


def test_seed_demo_cli_encryption_retry_and_login(monkeypatch):
    expected = json.loads(CONTRACT.read_text())["seed_cli"]
    for index, options in enumerate(
        (
            {"database": True},
            {"rerun": True, "long": True, "missing": True},
            {"prompted": True},
            {"throttled": True},
        )
    ):
        with monkeypatch.context() as patch:
            assert seed_cli_case(patch, **options) == expected[str(index)]


def test_seed_demo_refuses_empty_password(monkeypatch, capsys):
    module = importlib.import_module("scripts.seed_demo")
    monkeypatch.setattr(sys, "argv", ["seed_demo.py", "--password", ""])
    with pytest.raises(SystemExit) as caught:
        module.main()
    assert caught.value.code == 2
    assert capsys.readouterr().err.endswith(
        "seed_demo.py: error: password must not be empty\n"
    )


def test_seal_snapshot_checks_existing_macs_and_every_owner(monkeypatch):
    module = importlib.import_module("scripts.seal_legacy_audit")
    from datetime import datetime, timedelta, timezone

    from app import models
    from app.api import _audit as audit

    now = datetime(2026, 10, 5, tzinfo=timezone.utc)
    key = bytes(range(32))
    settings = SimpleNamespace(
        audit_mac_secret_hex=key.hex(),
        audit_journal_path="reviewed.journal",
        access_log_retention_days=31,
    )
    rows = [
        models.AccessLog(
            id="row-" + owner,
            actor_id="operator",
            actor_role="therapist",
            user_id=owner,
            action="read",
            at=now,
            chain_seq=2,
            prev_hash="a" * 64,
            entry_hash="b" * 64,
            entry_mac=None,
        )
        for owner in ("u1", "u2")
    ]
    rows[0].entry_mac = audit.compute_entry_mac(key, "u1", 2, "b" * 64)
    heads = {"u3": {"seq": 9, "hash": "c" * 64}}
    monkeypatch.setattr(
        audit,
        "read_journal_heads",
        lambda path: heads if path == "reviewed.journal" else None,
    )
    monkeypatch.setattr(models, "utcnow", lambda: now)
    calls, queries = [], []

    async def verify(session, owner, **kwargs):
        calls.append((owner, kwargs))
        return SimpleNamespace(ok=True)

    monkeypatch.setattr(audit, "verify_access_log_chain", verify)

    class Session:
        async def scalars(self, query):
            queries.append(query)
            return SimpleNamespace(all=lambda: rows)

    session = Session()
    encoded, actual = asyncio.run(module.snapshot_rows(session, settings))
    assert actual == rows
    assert json.loads(encoded) == {
        "format": "mindpattern-legacy-audit-review-v1",
        "journal_heads": heads,
        "rows": [
            {
                "id": r.id,
                "actor_id": "operator",
                "actor_role": "therapist",
                "user_id": r.user_id,
                "action": "read",
                "at": audit.canonical_occurred_at(now),
                "chain_seq": 2,
                "prev_hash": "a" * 64,
                "entry_hash": "b" * 64,
                "entry_mac": r.entry_mac,
            }
            for r in rows
        ],
    }
    assert calls == [
        (
            owner,
            {
                "mac_keys": {},
                "journal_path": "reviewed.journal",
                "retention_cutoff": now - timedelta(days=31),
                "journal_heads": heads,
            },
        )
        for owner in ("u1", "u2", "u3")
    ]
    assert queries[0].compile().params == {"param_1": 100001}
    assert "ORDER BY access_log.user_id, access_log.chain_seq" in str(queries[0])
    monkeypatch.setattr(module, "MAX_ROWS", 1)
    with pytest.raises(ValueError) as caught:
        asyncio.run(module.snapshot_rows(session, settings))
    assert (
        str(caught.value)
        == "audit row limit exceeded; use a reviewed partitioned migration"
    )
    monkeypatch.setattr(module, "MAX_ROWS", 2)
    assert asyncio.run(module.snapshot_rows(session, settings))[1] == rows
    monkeypatch.setattr(module, "MAX_ROWS", 100000)
    rows[0].entry_mac = "invalid"
    with pytest.raises(ValueError) as caught:
        asyncio.run(module.snapshot_rows(session, settings))
    assert (
        str(caught.value)
        == "an existing MAC is invalid; investigate instead of resealing"
    )
    rows[0].entry_mac = None

    async def invalid(*args, **kwargs):
        return SimpleNamespace(ok=False)

    monkeypatch.setattr(audit, "verify_access_log_chain", invalid)
    with pytest.raises(ValueError) as caught:
        asyncio.run(module.snapshot_rows(session, settings))
    assert (
        str(caught.value)
        == "audit hash/link/journal verification failed; investigate instead of resealing"
    )
    rows[0].entry_hash = None
    rows[0].entry_mac = audit.compute_entry_mac(key, "u1", 2, "")
    with pytest.raises(ValueError) as caught:
        asyncio.run(module.snapshot_rows(session, settings))
    assert (
        str(caught.value)
        == "audit hash/link/journal verification failed; investigate instead of resealing"
    )


def test_seal_cli_requires_review_inputs_and_reports_operator_errors(
    monkeypatch, capsys
):
    module = importlib.import_module("scripts.seal_legacy_audit")
    calls = []

    async def run(args):
        calls.append(vars(args))

    monkeypatch.setattr(module, "run", run)
    monkeypatch.setattr(
        sys, "argv", ["seal_legacy_audit.py", "snapshot", "--output", "review.json"]
    )
    module.main()
    assert calls.pop() == {"command": "snapshot", "output": "review.json"}
    values = {
        "snapshot": "review.json",
        "sha256": "digest",
        "attestation": "operator.txt",
        "receipt": "receipt.json",
    }
    arguments = [
        "seal_legacy_audit.py",
        "seal",
        *[item for name, value in values.items() for item in ("--" + name, value)],
    ]
    for confirm in ([], ["--maintenance-confirmed"]):
        monkeypatch.setattr(sys, "argv", arguments + confirm)
        module.main()
        assert calls.pop() == {
            "command": "seal",
            **values,
            "maintenance_confirmed": bool(confirm),
        }
    for omitted in (None, "output", *values):
        if omitted is None:
            argv = ["seal_legacy_audit.py"]
        elif omitted == "output":
            argv = ["seal_legacy_audit.py", "snapshot"]
        else:
            argv = [
                item
                for name, value in values.items()
                if name != omitted
                for item in ("--" + name, value)
            ]
        if omitted not in (None, "output"):
            argv = ["seal_legacy_audit.py", "seal", *argv]
        monkeypatch.setattr(sys, "argv", argv)
        with pytest.raises(SystemExit) as caught:
            module.main()
        assert caught.value.code == 2 and calls == []
        capsys.readouterr()

    async def denied(args):
        raise ValueError("operator review mismatch")

    monkeypatch.setattr(module, "run", denied)
    monkeypatch.setattr(
        sys, "argv", ["seal_legacy_audit.py", "snapshot", "--output", "review.json"]
    )
    with pytest.raises(SystemExit) as caught:
        module.main()
    assert caught.value.code == 1
    assert capsys.readouterr().err == "operator review mismatch\n"


def test_seal_portable_snapshot_imports_runtime_dependencies(tmp_path):
    """The offline utility resolves its app package from any working directory."""
    import os
    import subprocess

    driver = """
import asyncio, importlib.util, json, sys
from types import SimpleNamespace
spec = importlib.util.spec_from_file_location('offline_seal', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
class Session:
    async def scalars(self, statement):
        return SimpleNamespace(all=lambda: [])
settings = SimpleNamespace(audit_mac_secret_hex='00' * 32,
    audit_journal_path='', access_log_retention_days=31)
snapshot, rows = asyncio.run(module.snapshot_rows(Session(), settings))
assert rows == []
print(snapshot.decode(), end='')
"""
    env = dict(os.environ, MINDPATTERN_ENV="development")
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, "-c", driver, str(BACKEND / "scripts/seal_legacy_audit.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {
        "format": "mindpattern-legacy-audit-review-v1",
        "journal_heads": {},
        "rows": [],
    }
    assert result.stdout.endswith("\n")


@pytest.mark.parametrize(
    "script",
    [
        "dump_brain_lexicon",
        "gen_brain_vectors",
        "generate_vectors",
        "loadtest",
        "mc_phi_eff",
        "seal_legacy_audit",
        "seed_demo",
    ],
)
def test_utility_imports_local_app_before_ambient_name_collision(script, tmp_path):
    """Library callers can have a different package named app on their path."""
    import os
    import subprocess

    shadow = tmp_path / "ambient"
    (shadow / "app").mkdir(parents=True)
    (shadow / "app/__init__.py").write_text(
        "raise RuntimeError('ambient app package was imported')\n"
    )
    driver = """
import asyncio, importlib.util, pathlib, sys
from types import SimpleNamespace
sys.path.insert(0, sys.argv[2])
spec = importlib.util.spec_from_file_location('offline_utility', sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
if pathlib.Path(sys.argv[1]).stem == 'seal_legacy_audit':
    class Session:
        async def scalars(self, statement):
            return SimpleNamespace(all=lambda: [])
    settings = SimpleNamespace(audit_mac_secret_hex='00' * 32,
        audit_journal_path='', access_log_retention_days=31)
    snapshot, rows = asyncio.run(module.snapshot_rows(Session(), settings))
    assert rows == []
import app
print(pathlib.Path(app.__file__).resolve())
"""
    env = dict(os.environ, MINDPATTERN_ENV="development")
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            driver,
            str(BACKEND / "scripts" / (script + ".py")),
            str(shadow),
        ],
        cwd=BACKEND,
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == str((BACKEND / "app/__init__.py").resolve())


@pytest.mark.parametrize(
    "variant",
    [
        "new",
        "existing",
        "postgres",
        "changed",
        "maintenance",
        "invalid_mac",
        "invalid_endpoints",
        "invalid_first_seq",
        "invalid_first_hash",
        "invalid_head_hash",
        "missing_key",
        "missing_hash",
        "missing_endpoint",
        "snapshot",
        "snapshot_bound",
        "snapshot_oversize",
        "attestation_bound",
        "attestation_oversize",
        "presealed",
        "multiple",
        "missing_first",
        "missing_last",
        "legacy_key_zero",
    ],
)
def test_seal_transaction_and_resource_cleanup(variant, tmp_path, monkeypatch, capsys):
    module = importlib.import_module("scripts.seal_legacy_audit")
    from datetime import datetime, timezone

    from app import db, main, models, singleprocess
    from app.api import _audit as audit
    from app.config import Settings

    key, now = bytes(range(32)), datetime(2026, 10, 5, tzinfo=timezone.utc)
    settings = SimpleNamespace(
        database_url="sqlite+aiosqlite:///offline.db",
        token_secret="guard",
        audit_mac_secret_hex=key.hex(),
        audit_mac_key_version=2,
        audit_mac_keyring={2: key},
    )
    legacy_key = bytes(reversed(range(32)))
    if variant == "legacy_key_zero":
        settings.audit_mac_keyring[1] = legacy_key
    reviewed = b"reviewed audit data\n"
    if variant in ("snapshot_bound", "snapshot_oversize"):
        reviewed += b" " * (512 - len(reviewed))
    snapshot, assertion, receipt = (
        tmp_path / name for name in ("snapshot", "assertion", "receipt")
    )
    snapshot.write_bytes(reviewed)
    attestation = "Independent archive review reconciled these pre-MAC audit rows."
    if variant in ("attestation_bound", "attestation_oversize"):
        attestation += " " * (
            (32768 if variant == "attestation_bound" else 32769) - len(attestation)
        )
    assertion.write_text(attestation)
    args = SimpleNamespace(
        command="snapshot" if variant == "snapshot" else "seal",
        output=str(tmp_path / "export"),
        maintenance_confirmed=variant != "maintenance",
        snapshot=str(snapshot),
        sha256=hashlib.sha256(reviewed).hexdigest(),
        attestation=str(assertion),
        receipt=str(receipt),
    )
    if variant in ("snapshot_bound", "snapshot_oversize"):
        monkeypatch.setattr(
            module,
            "MAX_SNAPSHOT_BYTES",
            len(reviewed) if variant == "snapshot_bound" else len(reviewed) - 1,
        )
    row = models.AccessLog(
        id="row",
        user_id="owner",
        chain_seq=4,
        at=now,
        entry_hash=None
        if variant in ("missing_hash", "missing_endpoint", "missing_first")
        else "a" * 64,
        entry_mac=None,
    )
    if variant in ("presealed", "missing_endpoint", "missing_first"):
        row.entry_mac = audit.compute_entry_mac(key, "owner", 4, row.entry_hash or "")
        row.mac_key_version = 1
    records = [row]
    if variant in ("multiple", "missing_first", "missing_last"):
        second = models.AccessLog(
            id="row2",
            user_id="owner",
            chain_seq=5,
            at=now,
            prev_hash="a" * 64,
            entry_hash=None if variant == "missing_last" else "b" * 64,
            entry_mac=None,
        )
        if variant == "missing_last":
            second.entry_mac = audit.compute_entry_mac(key, "owner", 5, "")
        records.append(second)
    state = None
    if variant in (
        "existing",
        "invalid_mac",
        "invalid_endpoints",
        "invalid_first_seq",
        "invalid_first_hash",
        "invalid_head_hash",
        "missing_key",
        "legacy_key_zero",
    ):
        state = models.AuditChainState(
            user_id="owner",
            head_seq=4,
            head_hash="a" * 64,
            head_at=now,
            first_retained_seq=4,
            first_retained_hash="a" * 64,
            state_version=1,
            mac_key_version=2,
            updated_at=now,
        )
        if variant == "legacy_key_zero":
            state.mac_key_version = 0
        state.state_mac = audit.compute_chain_state_mac(
            legacy_key if variant == "legacy_key_zero" else key, state
        )
        if variant == "invalid_mac":
            state.state_mac = "bad"
        if variant == "invalid_endpoints":
            state.head_seq = 5
        if variant == "invalid_first_seq":
            state.first_retained_seq = 3
        if variant == "invalid_first_hash":
            state.first_retained_hash = "b" * 64
        if variant == "invalid_head_hash":
            state.head_hash = "b" * 64
        if variant == "missing_key":
            settings.audit_mac_keyring = {}
    events, added, queries = [], [], []

    class Session:
        async def __aenter__(self):
            events.append("session-enter")
            return self

        async def __aexit__(self, *args):
            events.append("session-exit")

        async def execute(self, query):
            queries.append(str(query))

        async def get(self, cls, owner):
            assert cls is models.AuditChainState and owner == "owner"
            return state

        def add(self, value):
            added.append(value)

        async def commit(self):
            assert receipt.exists(), "receipt must precede commit"
            events.append("commit")

    session = Session()
    engine = SimpleNamespace(
        dialect=SimpleNamespace(
            name="postgresql" if variant == "postgres" else "sqlite"
        )
    )

    async def dispose():
        events.append("dispose")

    engine.dispose = dispose

    def sessions(value):
        assert value is engine
        return lambda: session

    def build_engine(url):
        assert url == settings.database_url
        events.append("engine")
        return engine

    @contextlib.contextmanager
    def guard(secret, url):
        assert secret == "guard" and url == settings.database_url
        events.append("guard-enter")
        try:
            yield
        finally:
            events.append("guard-exit")

    async def acquire(value):
        assert value is engine
        events.append("acquire")
        return "lease"

    async def release(value):
        assert value == "lease"
        events.append("release")

    async def rows(*args):
        events.append("snapshot")
        return (b"changed" if variant == "changed" else reviewed), records

    monkeypatch.setattr(Settings, "from_env", lambda: settings)
    monkeypatch.setattr(db, "build_engine", build_engine)
    monkeypatch.setattr(db, "build_sessionmaker", sessions)
    monkeypatch.setattr(main, "_acquire_cross_host_guard", acquire)
    monkeypatch.setattr(main, "_release_cross_host_guard", release)
    monkeypatch.setattr(singleprocess, "single_process_guard", guard)
    monkeypatch.setattr(models, "utcnow", lambda: now)
    monkeypatch.setattr(module, "snapshot_rows", rows)
    failures = {
        "changed": "database or journal changed after review; create and independently review a new snapshot",
        "maintenance": "stop every API/worker/maintenance writer and explicitly confirm maintenance",
        "invalid_mac": "existing audit chain state MAC is invalid; investigate instead of resealing",
        "missing_key": "existing audit chain state MAC is invalid; investigate instead of resealing",
        "missing_hash": "reviewed audit row has no hash; investigate instead of sealing",
        "missing_endpoint": "reviewed audit chain has no endpoint hash; investigate instead of sealing",
        "snapshot_oversize": "snapshot exceeds size bound",
        "attestation_oversize": "attestation exceeds size bound",
    }
    for name in ("missing_first", "missing_last"):
        failures[name] = (
            "reviewed audit chain has no endpoint hash; investigate instead of sealing"
        )
    for name in (
        "invalid_endpoints",
        "invalid_first_seq",
        "invalid_first_hash",
        "invalid_head_hash",
    ):
        failures[name] = (
            "audit chain state changed after review; create and independently review a new snapshot"
        )
    if variant in failures:
        with pytest.raises(ValueError) as caught:
            asyncio.run(module.run(args))
        assert str(caught.value) == failures[variant]
        assert "commit" not in events and not receipt.exists()
    else:
        asyncio.run(module.run(args))
        if variant == "snapshot":
            assert Path(args.output).read_bytes() == reviewed
            assert capsys.readouterr().out == args.sha256 + "\n"
        else:
            assert row.entry_mac == audit.compute_entry_mac(key, "owner", 4, "a" * 64)
            assert row.mac_key_version == (1 if variant == "presealed" else 2)
            if variant == "multiple":
                assert second.entry_mac == audit.compute_entry_mac(
                    key, "owner", 5, "b" * 64
                )
                assert second.mac_key_version == 2
            current = state if state is not None else added[0]
            assert (
                current.head_seq,
                current.head_hash,
                current.first_retained_seq,
                current.first_retained_hash,
                current.state_version,
                current.updated_at,
                current.mac_key_version,
                current.head_at,
            ) == (
                5 if variant == "multiple" else 4,
                "b" * 64 if variant == "multiple" else "a" * 64,
                4,
                "a" * 64,
                1,
                now,
                2,
                now,
            )
            assert current.state_mac == audit.compute_chain_state_mac(key, current)
            assert queries == [
                "LOCK TABLE access_log IN EXCLUSIVE MODE"
                if variant == "postgres"
                else "BEGIN IMMEDIATE"
            ]
            assert json.loads(receipt.read_bytes()) == {
                "reviewed_sha256": args.sha256,
                "attestation": attestation,
                "sealed_rows": 0
                if variant == "presealed"
                else (2 if variant == "multiple" else 1),
                "at": now.isoformat(),
                "claim": "operator-reviewed legacy snapshot; no retrospective authenticity proof",
            }
            assert (
                capsys.readouterr().out
                == f"sealed {0 if variant == 'presealed' else (2 if variant == 'multiple' else 1)} reviewed legacy rows\n"
            )
    assert events[-1] == "dispose"
    if variant not in (
        "maintenance",
        "snapshot",
        "snapshot_oversize",
        "attestation_oversize",
    ):
        assert events[-3:] == ["release", "guard-exit", "dispose"]


def test_load_probe_statistics_and_key_schedule():
    from app.security import kdf
    from scripts import loadtest

    stats = loadtest.Stats("write")
    assert stats.elapsed == 0 and stats.failures == 0 and stats.latencies == []
    assert stats.summary() == "write: ALL FAILED (0)"
    for value in (0.3, 0.1, 0.5, 0.2, 0.4):
        stats.record(value, True)
    stats.record(10, False)
    stats.elapsed = 2
    assert stats.latencies == [0.3, 0.1, 0.5, 0.2, 0.4]
    assert stats.failures == 1
    assert stats.summary() == (
        "write: n=5 fail=1 p50=0.300s p95=0.500s "
        "max=0.500s completion-rate=2.50/s (wall 2.0s)"
    )
    stats.elapsed = 0
    assert "completion-rate=nan/s" in stats.summary()
    stats.elapsed = 0.5
    assert "completion-rate=10.00/s" in stats.summary()
    large = loadtest.Stats("large", list(range(100)), 0, 10)
    assert large.summary() == (
        "large: n=100 fail=0 p50=50.000s p95=95.000s "
        "max=99.000s completion-rate=10.00/s (wall 10.0s)"
    )
    master = hashlib.pbkdf2_hmac(
        "sha256", b"synthetic-password", b"0123456789abcdef", 1000
    )
    assert loadtest.derive("synthetic-password", b"0123456789abcdef", None) == (
        kdf.derive_auth_key(master),
        kdf.derive_data_key(master),
    )


def test_load_probe_http_protocol_and_outcomes(monkeypatch):
    from app.security import crypto
    from scripts import loadtest

    class Response:
        def __init__(self, status, body=None):
            self.status_code, self.body = status, body or {}

        def json(self):
            return self.body

    class Client:
        def __init__(self, responses):
            self.responses, self.calls = responses, []

        async def post(self, path, **kwargs):
            self.calls.append((path, kwargs))
            return self.responses.pop(0)

    async def scenarios():
        client = Client([Response(201, {"token": "access-token", "user_id": "uid"})])
        user = loadtest.LoadUser(client, 7, "synthetic-password")
        assert user.name == "load7"
        assert user.salt == hashlib.sha256(b"mindpattern-loadtest:load7").digest()[:16]
        assert user.token is None and user.user_id is None and user.data_key is None
        assert user.expect_analysis is False and user.last_recompute_state == "not-run"
        assert await user.register() is True
        assert user.token == "access-token" and user.user_id == "uid"
        path, request = client.calls[0]
        assert path == "/api/v1/auth/register"
        auth, data = loadtest.derive(user.password, user.salt, None)
        assert request == {
            "json": {
                "username": "load7",
                "salt": base64.b64encode(user.salt).decode(),
                "verifier": base64.b64encode(auth).decode(),
                "age_attestation": "minimum_age_confirmed_v1",
            }
        }
        assert user.data_key == data
        for status, wanted in [(201, True), (409, True), (400, False)]:
            client.responses = [Response(status)]
            assert await user.create_entry("2026-09-04", "neutral notes") is wanted
            path, request = client.calls[-1]
            assert path == "/api/v1/entries"
            assert request["headers"] == {"Authorization": "Bearer access-token"}
            assert request["json"]["client_entry_id"] == "load-2026-09-04"
            assert request["json"]["entry_date"] == "2026-09-04"
            body = json.loads(
                crypto.decrypt(
                    data,
                    base64.b64decode(request["json"]["blob"]),
                    crypto.build_aad("entry", "uid", "load-2026-09-04"),
                )
            )
            assert body == {
                "v": 1,
                "text": "neutral notes",
                "sentiment": None,
                "created_at": "2026-09-04",
            }
        for phase, analyzer, expected in [
            ("insight", "brain", True),
            ("insight", "llm", True),
            ("baseline", "none", False),
            ("insight", "none", False),
        ]:
            user.expect_analysis = True
            client.responses = [
                Response(201, {"session_token": "processing"}),
                Response(
                    200, {"phase": phase, "analyzer": analyzer, "active_days": 30}
                ),
            ]
            assert await user.recompute() is expected
            assert (
                user.last_recompute_state
                == f"phase={phase} analyzer={analyzer} active_days=30"
            )
            assert client.calls[-2] == (
                "/api/v1/processing/sessions",
                {
                    "headers": {"Authorization": "Bearer access-token"},
                    "json": {"data_key": base64.b64encode(data).decode()},
                },
            )
            assert client.calls[-1] == (
                "/api/v1/insights/recompute",
                {
                    "headers": {
                        "Authorization": "Bearer access-token",
                        "X-Processing-Token": "processing",
                    }
                },
            )
        client.responses = [
            Response(409),
            Response(200, {"token": "login-token", "user_id": "uid2"}),
        ]
        assert await user.register() is True
        assert user.token == "login-token" and user.user_id == "uid2"
        assert client.calls[-1] == (
            "/api/v1/auth/login",
            {
                "json": {
                    "username": "load7",
                    "verifier": base64.b64encode(auth).decode(),
                }
            },
        )
        client.responses = [Response(503)]
        assert await user.register() is False
        client.responses = [Response(401)]
        assert await user.login() is False
        client.responses = [Response(401)]
        assert await user.recompute() is False
        client.responses = [
            Response(201, {"session_token": "processing"}),
            Response(503),
        ]
        assert await user.recompute() is False

    asyncio.run(scenarios())


def test_bootstrap_requires_explicit_trust_and_releases_resources(monkeypatch, capsys):
    module = importlib.import_module("bootstrap_entry_guards")
    from app.config import Settings

    calls = []
    settings = Settings(environment="development")

    class Engine:
        async def dispose(self):
            calls.append("dispose")

    engine = Engine()

    @contextlib.contextmanager
    def guard(secret, url):
        assert secret == settings.token_secret and url == settings.database_url
        calls.append("enter")
        yield
        calls.append("exit")

    async def acquire(value):
        assert value is engine
        calls.append("acquire")
        return "lease"

    async def release(value):
        assert value == "lease"
        calls.append("release")

    async def bootstrap(factory, supplied):
        assert factory == "sessions" and supplied is settings
        calls.append("bootstrap")
        return 4

    monkeypatch.setattr(
        sys, "argv", ["bootstrap_entry_guards.py", "--trusted-bootstrap"]
    )
    monkeypatch.setattr(module.Settings, "from_env", lambda: settings)
    monkeypatch.setattr(module, "build_engine", lambda url: engine)
    monkeypatch.setattr(module, "build_sessionmaker", lambda e: "sessions")
    monkeypatch.setattr(module, "single_process_guard", guard)
    monkeypatch.setattr(module, "_acquire_cross_host_guard", acquire)
    monkeypatch.setattr(module, "_release_cross_host_guard", release)
    monkeypatch.setattr(module, "bootstrap_trusted_entries", bootstrap)
    asyncio.run(module.main())
    assert calls == ["enter", "acquire", "bootstrap", "exit", "release", "dispose"]
    assert (
        capsys.readouterr().out
        == "Trusted entry bootstrap complete: 4 rows; ciphertext unchanged\n"
    )
