"""Regression tests for the 2026-09-22 independent-audit round 3.

Findings verified-but-open in the round-2 remediation tree, now pinned:

* NEW-1: the weekly mutation workflow's survivor counter counted LINES
  containing "survived" — mutmut 2.4.4 prints ONE grouped header
  ("Survived 🙁 (500)") plus bare id-range lines, so 500 real survivors
  parsed as 1 and the ceiling of 25 could never trip. The parser now
  sums the header's own "(N)"; these tests execute the ACTUAL python
  block shipped inside .github/workflows/mutation.yml against synthetic
  results files in both formats.
* Consent-revival cap gap: re-activating a revoked consent (same pair,
  same row) skipped the ACTIVE-only grant-cap checks entirely (2026-09-21
  audit B-5 checked new rows only), so a patient at the cap could exceed
  it by one via revival. Revivals now count; a wrap REFRESH of an
  already-active row still must not (it adds no live grant).
* Foreign-store load cap direction: _stored_from_dict truncated an
  over-cap evidence/qualification list to the OLDEST N days (the merge
  path keeps the NEWEST N), so a hand-edited or foreign store with >60
  days would silently lose its high-water mark and reopen the D-1
  replication-bypass shape the 2026-09-21 audit fixed.
* A-8 wording: middleware-SYNTHESIZED envelopes (413/429/400/408/500)
  on the deprecated /api mount carried no Deprecation header while
  README promised "every response it serves".
* H.9d ratchet: the grandfathered set of slow-marked security pins is
  frozen — a slow-marked test never runs inside mutation campaigns, so
  silently growing that set would remove pins from exactly the runs that
  guard the code they pin.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path
from datetime import date, timedelta

import pytest

from app.api import consents as consents_module
from app.middleware import HardeningMiddleware
from app.services import brain
from tests.helpers import ClientEmulator, TherapistEmulator

REPO_ROOT = Path(__file__).resolve().parents[2]


# --- consent revival respects the ACTIVE-only cap (B-5 gap) -------------------------


async def test_reviving_a_revoked_consent_respects_the_active_cap(client, monkeypatch):
    # Cap 3 during setup so the three initial grants all land; lowered to
    # 2 before the revival attempt (the patient then sits AT the cap with
    # two live grants plus the revoked row being revived).
    monkeypatch.setattr(consents_module, "MAX_CONSENTS_PER_PATIENT", 3)
    patient = ClientEmulator("r3-revive", "deep-password")
    await patient.register(client)

    clinicians: list[TherapistEmulator] = []
    grants = []
    for i in range(3):
        clinician = TherapistEmulator(f"r3-revive-t{i}", "deep-password")
        await clinician.register(client)
        code = await clinician.create_pairing_code(client)
        lookup = await patient.pairing_lookup(client, code)
        granted = await patient.grant_consent(
            client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
        )
        assert granted["status"] == 201, granted
        clinicians.append(clinician)
        grants.append(granted)

    # Revoke the third grant: the patient now holds two active grants (to
    # therapists 0 and 1) plus a revoked row for therapist 2.
    revoked = await client.delete(
        f"/api/consents/{grants[2]['body']['id']}",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert revoked.status_code in (200, 204), revoked.text
    monkeypatch.setattr(consents_module, "MAX_CONSENTS_PER_PATIENT", 2)

    # Reviving therapist 2's grant would add a THIRD live share while the
    # patient is at the cap — it must 413 exactly like a brand-new grant.
    code = await clinicians[2].create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    revived = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert revived["status"] == 413, revived
    assert revived["body"]["code"] == "payload_too_large"


async def test_wrap_refresh_of_an_active_consent_at_cap_still_allowed(client, monkeypatch):
    monkeypatch.setattr(consents_module, "MAX_CONSENTS_PER_PATIENT", 2)
    patient = ClientEmulator("r3-refresh", "deep-password")
    await patient.register(client)
    clinician = TherapistEmulator("r3-refresh-t", "deep-password")
    await clinician.register(client)

    other = TherapistEmulator("r3-refresh-t2", "deep-password")
    await other.register(client)
    code = await other.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted

    code = await clinician.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted

    # The patient is AT the cap, but re-granting the SAME already-active
    # pair is a wrap refresh: it adds no live grant and must stay allowed
    # (the therapist's note history rides that row).
    code = await clinician.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    refreshed = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert refreshed["status"] == 201, refreshed


# --- foreign-store load keeps the NEWEST cap window (D-1 hardening) ------------------


def test_foreign_store_load_keeps_newest_evidence_days():
    day0 = date(2026, 6, 14)
    evidence = [(day0 + timedelta(days=i)).isoformat() for i in range(70)]
    qualification = [(day0 + timedelta(days=i)).isoformat() for i in range(70)]
    record = {
        "kind": "topic",
        "label": "work",
        "state": "candidate",
        "first_seen": evidence[0],
        "last_seen": evidence[-1],
        "occurrences": 200,
        "evidence_dates": evidence,
        "qualification_days": qualification,
    }
    store = json.dumps({"v": brain.STATE_VERSION, "patterns": {"topic:work": record}}).encode()

    loaded = brain.load_state(store)
    stored = loaded["patterns"]["topic:work"]

    # The cap window is the NEWEST 60 days (the merge-side invariant at
    # update(): evidence[-EVIDENCE_DATES_CAP:]). The pre-fix load path
    # sliced [:60] of the ascending list — silently keeping the OLDEST
    # window and losing the high-water mark the replication gate reads.
    assert stored.evidence_dates == evidence[-60:]
    assert stored.evidence_dates[-1] == evidence[-1]
    assert stored.qualification_days == qualification[-60:]


# --- middleware-synthesized envelopes carry the legacy Deprecation header (A-8) ------


def _http_scope(path, headers=()):
    return {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": list(headers),
        "client": ("127.0.0.1", 1234),
        "state": {},
    }


async def _call_asgi(app, scope, incoming):
    messages = list(incoming)
    sent = []

    async def receive():
        return messages.pop(0) if messages else {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    return sent


async def _oversize_response(path):
    """Drive HardeningMiddleware into its SYNTHESIZED 413 path (the body
    exceeds max_body_bytes before the app is ever reached)."""
    middleware = HardeningMiddleware(lambda *_: None, max_body_bytes=8, body_read_timeout_seconds=5)
    scope = _http_scope(path, [(b"content-length", b"64")])
    body = b"x" * 64
    sent = await _call_asgi(
        middleware, scope, [{"type": "http.request", "body": body, "more_body": False}]
    )
    assert sent, "middleware produced no response"
    start = sent[0]
    assert start["type"] == "http.response.start"
    assert start["status"] == 413
    return {name.lower(): value for name, value in start["headers"]}


async def test_synthesized_413_on_legacy_mount_carries_deprecation_header():
    headers = await _oversize_response("/api/auth/salt")
    assert headers.get(b"deprecation") == b"true"


async def test_synthesized_413_on_canonical_mount_has_no_deprecation_header():
    headers = await _oversize_response("/api/v1/auth/salt")
    assert b"deprecation" not in headers


# --- NEW-1: the mutation-gate parser counts grouped headers, not lines ---------------


def _extract_mutation_gate_script() -> str:
    """Pull the ACTUAL python block out of .github/workflows/mutation.yml
    (the step that enforces MAX_SURVIVING_MUTANTS), so this test pins the
    shipped logic rather than a copy of it."""
    text = (REPO_ROOT / ".github" / "workflows" / "mutation.yml").read_text(encoding="utf-8")
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if "python - <<'EOF'" in line:
            start = i + 1
            # The heredoc shares the YAML block's uniform indent; strip
            # exactly that prefix so nested blocks keep their own indent.
            indent = len(line) - len(line.lstrip())
            break
    assert start is not None, "mutation.yml no longer embeds a python heredoc"
    body: list[str] = []
    for line in lines[start:]:
        if line.strip() == "EOF":
            break
        body.append(line[indent:] if line.startswith(" " * indent) else line)
    assert body, "empty heredoc extracted"
    return "\n".join(body)


def _run_gate(script: str, results_text: str, tmp_path: Path) -> subprocess.CompletedProcess:
    (tmp_path / "mutmut-results.txt").write_text(results_text, encoding="utf-8")
    script_path = tmp_path / "gate.py"
    script_path.write_text(script, encoding="utf-8")
    env = {
        **os.environ,
        "MAX_SURVIVING_MUTANTS": "25",
        "MUTANTS_MIN_PROCESSED": "1",
    }
    return subprocess.run(
        [sys.executable, str(script_path)],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


# Byte-faithful mutmut 2.4.4 `mutmut results` shape: ONE grouped header
# per status (with the count in parentheses), then filename groups and
# bare id-range lines that carry no status word. (cache.py print_stuff.)
_GROUPED_500 = """To apply a mutant on disk:
    mutmut apply <id>

To show a mutant:
    mutmut show <id>

Timed out \u23f0 (2)
---- app/services/brain.py (2) ----

2

Survived \U0001f641 (500)
---- app/services/brain.py (300) ----

1-300
---- app/security/kdf.py (200) ----

1-200
"""

_HEALTHY = """To apply a mutant on disk:
    mutmut apply <id>

Timed out \u23f0 (1)
---- app/services/brain.py (1) ----

7

Survived \U0001f641 (3)
---- app/security/kdf.py (3) ----

1-3
"""


def test_mutation_gate_counts_grouped_survivor_headers(tmp_path):
    # 500 real survivors must breach the 25 ceiling. The pre-fix parser
    # counted lines containing "survived" — exactly 1 here — and passed.
    proc = _run_gate(_extract_mutation_gate_script(), _GROUPED_500, tmp_path)
    assert proc.returncode != 0, "500 survivors must fail the ceiling"
    assert "surviving mutants: 500" in proc.stdout, proc.stdout + proc.stderr


def test_mutation_gate_passes_a_healthy_campaign(tmp_path):
    proc = _run_gate(_extract_mutation_gate_script(), _HEALTHY, tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "surviving mutants: 3" in proc.stdout


def test_mutation_gate_still_refuses_unparseable_results(tmp_path):
    # F-7 guard must survive the NEW-1 fix: an empty or crashed-campaign
    # results file may not count as zero survivors.
    proc = _run_gate(_extract_mutation_gate_script(), "", tmp_path)
    assert proc.returncode != 0


def test_mutation_gate_refuses_an_unrecognized_per_line_format(tmp_path):
    # A hypothetical per-mutant listing with no "(N)" status headers
    # cannot be ACCOUNTED for — the F-7 completeness guard refuses it
    # rather than guessing a survivor count from an unrecognized format
    # (fail closed; the per-line counter in the workflow only matters for
    # formats that also carry at least one "(N)" header).
    per_line = "survived: app/security/kdf.py::hkdf_sha256:1\n" * 30
    proc = _run_gate(_extract_mutation_gate_script(), per_line, tmp_path)
    assert proc.returncode != 0
    # sys.exit(message) lands on stderr; the accounting line on stdout.
    assert "campaign incomplete" in proc.stdout + proc.stderr


# --- H.9d: the slow-marker set is frozen (documented convention + ratchet) -----------


def test_slow_marker_grandfathered_set_is_frozen():
    """`slow`-marked tests never run inside mutation campaigns
    (scripts/mutmut_runner.sh deselects -m 'not slow'), so a NEW slow
    marker on a security pin would silently remove it from exactly the
    runs that guard the code it pins. The convention (documented at
    backend/pyproject.toml's marker): only the byte-for-byte crypto pins
    that genuinely need minutes are grandfathered. Growing the set is a
    deliberate act — update it here, with a reason, in the same change."""
    slow_files = {
        path.name
        for path in (Path(__file__).resolve().parent).glob("test_*.py")
        if path.name != Path(__file__).name  # this file documents the marker by name
        and "pytest.mark.slow" in path.read_text(encoding="utf-8")
    }
    assert slow_files == {
        "test_encrypt_vectors.py",
        "test_kdf.py",
    }, (
        "backend/tests gained a `slow` marker outside the grandfathered "
        "crypto-pin set; see the H.9d convention in backend/pyproject.toml. "
        f"Files now marked slow: {sorted(slow_files)}"
    )


def test_mutation_runner_still_deselects_slow_tests():
    runner = (Path(__file__).resolve().parents[1] / "scripts" / "mutmut_runner.sh").read_text(
        encoding="utf-8"
    )
    assert "-m 'not slow'" in runner or "-m \"not slow\"" in runner
