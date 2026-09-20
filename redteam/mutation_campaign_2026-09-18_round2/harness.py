#!/usr/bin/env python3
"""Behavioral mutation campaign, round 2 (2026-09-18).

Ten campaigns from the post-round-1 strategy, over the areas round 1 did
not reach. Same discipline as round 1: snapshot the target file's bytes,
apply ONE semantic mutation, run the targeted suite(s), restore the bytes
exactly (the work tree carries uncommitted changes, so restoration is
byte-wise — never git), record killed/survived + the failing tests.

  G  brain-engine detectors round 2 (EWMA chart, MinHash/LSH, lag-1 links,
     replication independence, residuals, lifecycle boundaries). Every G
     mutant runs against BOTH the unit suite and probe_brain.py — the
     oracle question is whether the ground-truth probe alone catches it.
  H  the 30-day threshold (distinct-vs-total days, 29/30/31 boundaries,
     streak grace, backdating/forward-dating windows, baseline-phase
     reveal-nothing).
  I  crypto contracts & pairing (HKDF info swap, nonce reuse, pairing-code
     TTL + single-use burn, and TAMPERED shared/*.json contract files that
     must fail every consumer's pins).
  J  crisis suppression, deeper round (pool-side belt-and-braces, sensitive
     flag on cards, rumination classifier, split-variant matching, benign
     masking, mobile pre-encryption dialog tier, crisis reachability).
  K  fail-closed ops (env normalization, secret floor, SQLite refusal,
     docs off, header set, body cap, entry quota).
  L  idiographic isolation (pooled instead of within-person baselines,
     population sleep norm, cross-user threshold leak, language gate).
  M  mobile sync/queue (duplicate suppression, origin pin, capacity,
     session-expired custody, retry accounting, quarantine).
  N  REDTEAM-AS-ORACLE: mutate a security control and check whether the
     redteam/ harnesses notice (FINDING) or stay blind (MISSED). This
     measures harness quality the way mutation score measures test
     quality. Verdict semantics invert: CAUGHT = the harness reported a
     FINDING for the targeted audit; MISSED = the regression sailed
     through the attack harness.

A mutant is KILLED when any of its commands exits non-zero (or times out —
a hang is an observable behavior change) — EXCEPT pytest exits that mean
the oracle itself is broken (2/3/4/5: interrupted, internal error, usage
error, nothing collected — e.g. a renamed or deleted pin-test file);
those are SETUP-ERRORs, never kills, so oracle rot cannot green the gate.
Survivors are re-verified against the full fast suite by the campaign driver.

Usage:
  python3 harness.py            # run all campaigns
  python3 harness.py G H        # run only campaigns G and H
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
# The redteam-oracle commands run with cwd=redteam/, where the relative
# PY does not resolve — use the root venv absolutely (or an explicit
# override for CI, where the interpreter lives elsewhere).
ROOT_PY = os.environ.get("MUTATION_PY") or str(ROOT / ".venv" / "bin" / "python")


def backend_pytest(*targets: str, extra: tuple[str, ...] = ()) -> dict:
    return {
        "cwd": "backend",
        "cmd": [PY, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider",
                "-m", "not slow", *extra, *targets],
        "timeout": 900,
        "kind": "pytest",
    }


def probe() -> dict:
    return {
        "cwd": "backend",
        "cmd": [PY, "probe_brain.py"],
        "timeout": 300,
        "kind": "probe",
    }


def vitest(*targets: str) -> dict:
    return {
        "cwd": "mobile",
        "cmd": ["npx", "vitest", "run", "--no-coverage", *targets],
        "timeout": 600,
        "kind": "vitest",
    }


def redteam(script: str, *oracle_substrings: str) -> dict:
    return {
        "cwd": "redteam",
        "cmd": [ROOT_PY, script],
        "timeout": 900,
        "kind": "redteam",
        "oracle": list(oracle_substrings),
    }


# The suite + probe pair used for every brain-engine mutant (the probe is
# the round-2 oracle question: does ground truth alone catch it?).
def brain_suite() -> list[dict]:
    return [backend_pytest("tests/test_brain.py", "tests/test_patterns.py"), probe()]


MUTANTS: list[dict] = [
    # ---------------------------------------------------------------- G. brain round 2
    dict(
        id="G1", campaign="G", name="EWMA lambda 0.18 -> 1.0 (no smoothing; chart becomes Shewhart)",
        expectation="EWMA chart regressions must fail",
        file="backend/app/services/brain.py",
        find="MOOD_SHIFT_LAMBDA = 0.18",
        replace="MOOD_SHIFT_LAMBDA = 1.0",
        tests=brain_suite(),
    ),
    dict(
        id="G2", campaign="G", name="EWMA control limit 2.7sigma -> 1.0sigma (false alarms)",
        expectation="AR(1) false-alarm regression sim must fail",
        file="backend/app/services/brain.py",
        find="MOOD_SHIFT_LIMIT = 2.7",
        replace="MOOD_SHIFT_LIMIT = 1.0",
        tests=brain_suite(),
    ),
    dict(
        id="G3", campaign="G", name="EWMA baseline seeded over the WHOLE window (no post-baseline points)",
        expectation="probe scenario: the planted mood shift must vanish",
        file="backend/app/services/brain.py",
        find="baseline = day_sentiments[: max(MOOD_SHIFT_BASELINE_MIN, n // 4)]",
        replace="baseline = day_sentiments[:n]",
        tests=brain_suite(),
    ),
    dict(
        id="G4", campaign="G", name="EWMA autocorrelation limit inflation disabled",
        expectation="stationary AR(1) series must false-alarm <=2/12 (regression sim)",
        file="backend/app/services/brain.py",
        find="    if phi is not None and phi >= 0.35:",
        replace="    if False:",
        tests=brain_suite(),
    ),
    dict(
        id="G5", campaign="G", name="EWMA run rule 3 -> 1 (single point beyond limit = shift)",
        expectation="sustained-run requirement must be pinned",
        file="backend/app/services/brain.py",
        find="MOOD_SHIFT_RUN = 3",
        replace="MOOD_SHIFT_RUN = 1",
        tests=brain_suite(),
    ),
    dict(
        id="G6", campaign="G", name="MinHash NUM_PERM 64 -> 8 (signature collapse)",
        expectation="phrase clustering precision/determinism pins must fail",
        file="backend/app/services/phrases.py",
        find="NUM_PERM = 64",
        replace="NUM_PERM = 8",
        tests=[backend_pytest("tests/test_phrases.py", "tests/test_brain.py"), probe()],
    ),
    dict(
        id="G7", campaign="G", name="LSH BANDS 16 -> 32 (band/row split changed; recall-only?)",
        expectation="oracle question: is the banding itself observable?",
        file="backend/app/services/phrases.py",
        find="BANDS = 16",
        replace="BANDS = 32",
        tests=[backend_pytest("tests/test_phrases.py", "tests/test_brain.py"), probe()],
    ),
    dict(
        id="G8", campaign="G", name="Jaccard confirmation threshold 0.5 -> 0.1 (unrelated sentences cluster)",
        expectation="unrelated-pair non-clustering pin must fail",
        file="backend/app/services/phrases.py",
        find="DEFAULT_JACCARD = 0.5",
        replace="DEFAULT_JACCARD = 0.1",
        tests=[backend_pytest("tests/test_phrases.py", "tests/test_brain.py"), probe()],
    ),
    dict(
        id="G9", campaign="G", name="lag-1 link direction flipped (exposed/unexposed swapped)",
        expectation="link direction copy + probe scenario E must fail",
        file="backend/app/services/brain.py",
        find="        delta = sum(unexposed) / len(unexposed) - sum(exposed) / len(exposed)",
        replace="        delta = sum(exposed) / len(exposed) - sum(unexposed) / len(unexposed)",
        tests=brain_suite(),
    ),
    dict(
        id="G10", campaign="G", name="link outcome day lag-1 -> lag-0 (same-day mood, not day-after)",
        expectation="the day-after claim must not become a same-day claim unnoticed",
        file="backend/app/services/brain.py",
        find="        exposed = [day_residuals[cur] for _, cur in exposed_pairs]",
        replace="        exposed = [day_residuals[prev] for prev, _ in exposed_pairs]",
        tests=brain_suite(),
    ),
    dict(
        id="G11", campaign="G", name="link transitions admit gap==2 only (day-after excluded)",
        expectation="probe scenario E (day-after family link) must FAIL",
        file="backend/app/services/brain.py",
        find="        if 1 <= gap <= LINK_MAX_GAP_DAYS:",
        replace="        if gap == LINK_MAX_GAP_DAYS:",
        tests=brain_suite(),
    ),
    dict(
        id="G12", campaign="G", name="evidence-date replication: new-evidence requirement -> True",
        expectation="consecutive same-corpus recomputes must not count as independent",
        file="backend/app/services/brain.py",
        find="    if record.kind in EVIDENCE_DATE_KINDS:\n        return any(_iso(day) not in prior_evidence for day in signal.evidence_days)",
        replace="    if record.kind in EVIDENCE_DATE_KINDS:\n        return True",
        tests=brain_suite(),
    ),
    dict(
        id="G13", campaign="G", name="REPLICATION_MIN_SPREAD_DAYS 2 -> 1 (consecutive days independent)",
        expectation="window-stat fluke re-qualification must be pinned",
        file="backend/app/services/brain.py",
        find="REPLICATION_MIN_SPREAD_DAYS = 2",
        replace="REPLICATION_MIN_SPREAD_DAYS = 1",
        tests=brain_suite(),
    ),
    dict(
        id="G14", campaign="G", name="lifecycle boundary: GRACE_DAYS 7 -> 6",
        expectation="exact fade boundary pin (round 1 only tested 7->7000)",
        file="backend/app/services/brain.py",
        find="GRACE_DAYS = 7  # unqualified days before active → fading",
        replace="GRACE_DAYS = 6  # unqualified days before active → fading",
        tests=brain_suite(),
    ),
    dict(
        id="G15", campaign="G", name="lifecycle boundary: ARCHIVE_DAYS 45 -> 44",
        expectation="exact archive boundary pin",
        file="backend/app/services/brain.py",
        find="ARCHIVE_DAYS = 45  # unqualified days before fading → archived",
        replace="ARCHIVE_DAYS = 44  # unqualified days before fading → archived",
        tests=brain_suite(),
    ),
    dict(
        id="G16", campaign="G", name="lifecycle boundary: CONFIRM_AGE_DAYS 21 -> 0 (instant confirm)",
        expectation="emerging must not confirm without age",
        file="backend/app/services/brain.py",
        find="CONFIRM_AGE_DAYS = 21  # emerging → confirmed by age",
        replace="CONFIRM_AGE_DAYS = 0  # emerging → confirmed by age",
        tests=brain_suite(),
    ),
    dict(
        id="G17", campaign="G", name="lifecycle boundary: evidence half-life 45 -> 44 days",
        expectation="exact decay boundary pin (round 1 only tested x1000)",
        file="backend/app/services/brain.py",
        find="HALF_LIFE_DAYS = 45.0  # recent mentions outweigh old ones; the brain forgets",
        replace="HALF_LIFE_DAYS = 44.0  # recent mentions outweigh old ones; the brain forgets",
        tests=brain_suite(),
    ),
    dict(
        id="G18", campaign="G", name="residuals dropped: day residuals = raw moods (v2 confound, day level)",
        expectation="probe zero-false-associations gate — the oracle question",
        file="backend/app/services/brain.py",
        find="    day_residuals = {day: mood - baselines.get(day, mood) for day, mood in day_sentiments}",
        replace="    day_residuals = dict(day_sentiments)",
        tests=brain_suite(),
    ),
    dict(
        id="G19", campaign="G", name="residuals dropped: per-entry residuals = raw moods (v2 confound, entry level)",
        expectation="probe zero-false-associations gate — the oracle question",
        file="backend/app/services/brain.py",
        find="        (entry, tokens, themes, sentiment - baselines.get(entry.entry_date, sentiment))",
        replace="        (entry, tokens, themes, sentiment)",
        tests=brain_suite(),
    ),
    dict(
        id="G20", campaign="G", name="topic presence cluster-cover bar 0.8 -> 1.1 (never suppresses)",
        expectation="boilerplate presence must stay suppressed (40/40 noise pin)",
        file="backend/app/services/brain.py",
        find="TOPIC_PRESENCE_CLUSTER_COVER = 0.8",
        replace="TOPIC_PRESENCE_CLUSTER_COVER = 1.1",
        tests=brain_suite(),
    ),
    # ---------------------------------------------------------------- H. threshold
    dict(
        id="H1", campaign="H", name="active days counted with duplicates (total entries, not distinct)",
        expectation="one-day-30-entries must NOT unlock",
        file="backend/app/services/threshold.py",
        find="    return len({d for d in dates if d is not None})",
        replace="    return len([d for d in dates if d is not None])",
        tests=backend_pytest("tests/test_threshold.py", "tests/test_insights_api.py"),
    ),
    dict(
        id="H2", campaign="H", name="threshold boundary 30 -> 29 active days unlock",
        expectation="29 active days must stay baseline",
        file="backend/app/services/threshold.py",
        find="    phase = Phase.INSIGHT if active >= threshold else Phase.BASELINE",
        replace="    phase = Phase.INSIGHT if active >= threshold - 1 else Phase.BASELINE",
        tests=backend_pytest("tests/test_threshold.py", "tests/test_insights_api.py"),
    ),
    dict(
        id="H3", campaign="H", name="threshold boundary off-by-one strict (31st day unlocks)",
        expectation="30 active days must unlock on day 30 exactly",
        file="backend/app/services/threshold.py",
        find="    phase = Phase.INSIGHT if active >= threshold else Phase.BASELINE",
        replace="    phase = Phase.INSIGHT if active > threshold else Phase.BASELINE",
        tests=backend_pytest("tests/test_threshold.py", "tests/test_insights_api.py"),
    ),
    dict(
        id="H4", campaign="H", name="streak grace widened 1 -> 2 missed days",
        expectation="streak must die after one silent day",
        file="backend/app/services/threshold.py",
        find="    if day not in (today, today - timedelta(days=1)):",
        replace="    if day not in (today, today - timedelta(days=2)):",
        tests=backend_pytest("tests/test_threshold.py"),
    ),
    dict(
        id="H5", campaign="H", name="backdating window opened to 400 days before account",
        expectation="bulk backdating must not fast-forward the gate",
        file="backend/app/api/entries.py",
        find="    earliest = min(created_day, today) - timedelta(days=BACKDATE_GRACE_DAYS)",
        replace="    earliest = min(created_day, today) - timedelta(days=400)",
        tests=backend_pytest("tests/test_entries_api.py", "tests/test_threshold.py",
                             "tests/test_api_hardening_r3.py"),
    ),
    dict(
        id="H6", campaign="H", name="forward-dating grace widened to 6 days",
        expectation="timezone grace is exactly +1 day",
        file="backend/app/api/entries.py",
        find="    if entry_date > today + timedelta(days=FORWARD_GRACE_DAYS):",
        replace="    if entry_date > today + timedelta(days=6):",
        tests=backend_pytest("tests/test_entries_api.py", "tests/test_api_hardening_r3.py"),
    ),
    dict(
        id="H7", campaign="H", name="baseline-phase recompute proceeds to analysis anyway",
        expectation="pre-threshold must decrypt nothing (device-local only)",
        file="backend/app/api/insights.py",
        find="    if state.phase is not Phase.INSIGHT:\n        # BASELINE: reveal nothing, decrypt nothing, analyze nothing. Any",
        replace="    if False:\n        # BASELINE: reveal nothing, decrypt nothing, analyze nothing. Any",
        tests=backend_pytest("tests/test_insights_api.py", "tests/test_threshold.py",
                             "tests/test_brain_api.py"),
    ),
    # ---------------------------------------------------------------- I. crypto contract & pairing
    dict(
        id="I1", campaign="I", name="HKDF info swap: auth_key derived with the data-key info string",
        expectation="the server would receive the DATA key at login — vectors + auth tests must fail",
        file="backend/app/security/kdf.py",
        find='AUTH_INFO = b"mindpattern/auth/v1"',
        replace='AUTH_INFO = b"mindpattern/data/v1"',
        tests=backend_pytest("tests/test_kdf.py", "tests/test_encrypt_vectors.py",
                             "tests/test_auth_api.py"),
    ),
    dict(
        id="I2", campaign="I", name="mobile HKDF info swap (auth arm returns the data-key info)",
        expectation="cross-platform vector tests must fail",
        file="mobile/src/crypto/kdf.ts",
        find='return Buffer.from("mindpattern/auth/v1", "utf8");',
        replace='return Buffer.from("mindpattern/data/v1", "utf8");',
        tests=vitest("tests/crypto.test.ts", "tests/vectors.test.ts"),
    ),
    dict(
        id="I3", campaign="I", name="encrypt() nonce is fixed zeros (GCM nonce reuse under one key)",
        expectation="two encryptions of different plaintexts must never share a nonce",
        file="backend/app/security/crypto.py",
        find="    return encrypt_with_nonce(key, plaintext, aad, os.urandom(NONCE_SIZE))",
        replace="    return encrypt_with_nonce(key, plaintext, aad, bytes(NONCE_SIZE))",
        tests=backend_pytest("tests/test_crypto.py", "tests/test_encrypt_vectors.py"),
    ),
    dict(
        id="I4", campaign="I", name="pairing-code burn drops the expiry condition (expired code redeems)",
        expectation="15-minute code lifetime must be enforced at redemption",
        file="backend/app/api/consents.py",
        find="                .where(\n                    PairingCode.id == code_row.id,\n                    PairingCode.consumed_at.is_(None),\n                    PairingCode.expires_at > now,\n                )",
        replace="                .where(\n                    PairingCode.id == code_row.id,\n                    PairingCode.consumed_at.is_(None),\n                )",
        tests=backend_pytest("tests/test_therapist_api.py", "tests/test_sharing_crypto.py"),
    ),
    dict(
        id="I5", campaign="I", name="pairing-code burn writes NULL (code never consumes; reuse possible)",
        expectation="single-use-by-atomic-update tests must fail on second redeem",
        file="backend/app/api/consents.py",
        find="                .values(consumed_at=now)",
        replace="                .values(consumed_at=None)",
        tests=backend_pytest("tests/test_therapist_api.py", "tests/test_sharing_crypto.py"),
    ),
    dict(
        id="I6", campaign="I", name="contract: shared/vectors.json first blob byte flipped",
        expectation="backend vectors + mobile vectors + portal crypto pins must ALL fail",
        file="shared/vectors.json",
        find="foxHAf4MU",
        replace="foxHAf4MV",
        tests=[
            backend_pytest("tests/test_encrypt_vectors.py", "tests/test_contract_pins.py"),
            vitest("tests/vectors.test.ts", "tests/crypto.test.ts"),
            {
                "cwd": "portal",
                "cmd": ["npx", "vitest", "run", "--no-coverage", "tests/crypto.test.ts"],
                "timeout": 300,
                "kind": "vitest",
            },
        ],
    ),
    dict(
        id="I7", campaign="I", name="contract: crisis_phrases.json drops the primary dialog pattern",
        expectation="backend sync pins + mobile crisisPhrases pins must BOTH fail",
        file="shared/crisis_phrases.json",
        find='"\\\\bsuicid(?:e|al)\\\\b",',
        replace="",
        tests=[
            backend_pytest("tests/test_crisis.py", "tests/test_phrases.py"),
            vitest("tests/crisisPhrases.test.ts", "tests/crisisDetect.test.ts"),
        ],
    ),
    dict(
        id="I8", campaign="I", name="contract: generic_questions.json breaks the question invariant",
        expectation="backend + mobile question-invariant pins must BOTH fail",
        file="shared/generic_questions.json",
        find="What took up most space in your mind today?",
        replace="What took up most space in your mind today",
        tests=[
            backend_pytest("tests/test_questions.py", "tests/test_contract_pins.py"),
            vitest("tests/genericQuestions.test.ts"),
        ],
    ),
    # ---------------------------------------------------------------- J. crisis deeper
    dict(
        id="J1", campaign="J", name="question pool belt-and-braces suppress filter removed",
        expectation="no rendered question may quote suppress-tier content",
        file="backend/app/services/questions.py",
        find="    pool = [q for q in pool if not crisis.matches_suppress(q)]",
        replace="    pool = pool",
        tests=backend_pytest("tests/test_questions.py", "tests/test_crisis.py"),
    ),
    dict(
        id="J2", campaign="J", name="surfaced cards never carry detail.sensitive",
        expectation="crisis-adjacent cards must render non-quoting on BOTH clients",
        file="backend/app/services/brain.py",
        find="    if crisis.matches_suppress(record.label):\n        return True",
        replace="    if False:\n        return True",
        tests=backend_pytest("tests/test_brain.py", "tests/test_crisis.py",
                             "tests/test_questions.py"),
    ),
    dict(
        id="J3", campaign="J", name="rumination classifier disabled (worries surface as neutral phrases)",
        expectation="negative recurring clusters must be framed as rumination",
        file="backend/app/services/brain.py",
        find="        is_rumination = allow_rumination and (",
        replace="        is_rumination = False and (",
        tests=brain_suite(),
    ),
    dict(
        id="J4", campaign="J", name="split-variant matching dropped (primary form only)",
        expectation="orphan-join/concat bypass corpus must fail (s u i c i d e)",
        file="backend/app/services/crisis.py",
        find="    return (\n        _primary_join(tokens),\n        _orphan_glue(tokens),\n        _concat_join(tokens),\n    )",
        replace="    return (\n        _primary_join(tokens),\n    )",
        tests=backend_pytest("tests/test_crisis.py", "tests/test_questions.py"),
    ),
    dict(
        id="J5", campaign="J", name="benign-compound masking narrowed (suicide squad unmasked)",
        expectation="benign movie titles must not fire the dialog tier",
        file="backend/app/services/crisis.py",
        find='    "suicide squad",\n    "suicide silence",',
        replace='    "suicide silence",',
        tests=backend_pytest("tests/test_crisis.py"),
    ),
    dict(
        id="J6", campaign="J", name="mobile pre-encryption dialog tier skipped on save",
        expectation="crisis-flagged saves must offer support before encryption",
        file="mobile/src/screens/EntryScreen.tsx",
        find="      const crisisLanguage = detectCrisisLanguage(trimmed);",
        replace="      const crisisLanguage = false as ReturnType<typeof detectCrisisLanguage>;",
        tests=vitest(),
    ),
    dict(
        id="J7", campaign="J", name="mobile: Crisis screen unreachable from every stack",
        expectation="one-tap-from-every-screen guarantee (login/locked/main)",
        file="mobile/src/navigation.tsx",
        find='          <Stack.Screen name="Crisis" component={CrisisScreen} options={{ title: "Get help" }} />',
        replace="          ",
        count=3,
        tests=vitest("tests/navigation.test.tsx"),
    ),
    # ---------------------------------------------------------------- K. fail-closed ops
    dict(
        id="K1", campaign="K", name="environment normalization drops .lower() (PRODUCTION escapes gates)",
        expectation="case typos must hit production gates",
        file="backend/app/config.py",
        find="        self.environment = self.environment.strip().lower()",
        replace="        self.environment = self.environment.strip()",
        tests=backend_pytest("tests/test_hardening.py", "tests/test_ops_hardening_2026_09_17.py"),
    ),
    dict(
        id="K2", campaign="K", name="32-char token-secret floor removed",
        expectation="short secrets must refuse to boot outside development",
        file="backend/app/config.py",
        find='            if len(self.token_secret.strip()) < 32:',
        replace="            if len(self.token_secret.strip()) < 1:",
        tests=backend_pytest("tests/test_hardening.py", "tests/test_ops_hardening_2026_09_17.py"),
    ),
    dict(
        id="K3", campaign="K", name="SQLite accepted outside development",
        expectation="non-development DBs must be shared engines",
        file="backend/app/config.py",
        find='            if self.database_url.startswith("sqlite"):',
        replace="            if False:",
        tests=backend_pytest("tests/test_hardening.py", "tests/test_ops_hardening_2026_09_17.py"),
    ),
    dict(
        id="K4", campaign="K", name="OpenAPI docs always mounted",
        expectation="/docs must 404 outside development",
        file="backend/app/main.py",
        find='        docs_url="/docs" if is_development else None,',
        replace='        docs_url="/docs",',
        tests=backend_pytest("tests/test_hardening.py", "tests/test_api_hardening_r3.py", "tests/test_mutation_pins_2026_09_18b.py"),
    ),
    dict(
        id="K5", campaign="K", name="HSTS header dropped from the response set",
        expectation="every response carries the full header set",
        file="backend/app/middleware.py",
        find='    (b"strict-transport-security", b"max-age=31536000; includeSubDomains"),\n',
        replace="",
        tests=backend_pytest("tests/test_hardening.py", "tests/test_api_hardening_r3.py", "tests/test_mutation_pins.py"),
    ),
    dict(
        id="K6", campaign="K", name="request body cap effectively removed (x 1,000,000)",
        expectation="2 MiB cap must 413 before parsing",
        file="backend/app/middleware.py",
        find="        self.max_body_bytes = max_body_bytes",
        replace="        self.max_body_bytes = max_body_bytes * 1_000_000",
        tests=backend_pytest("tests/test_api_hardening_r3.py", "tests/test_hardening.py"),
    ),
    dict(
        id="K7", campaign="K", name="per-account entry-count quota check disabled",
        expectation="quota-exceeded must 413",
        file="backend/app/api/entries.py",
        find="    if count >= settings.max_entries_per_user:",
        replace="    if False:",
        tests=backend_pytest("tests/test_entries_api.py", "tests/test_api_hardening_r3.py"),
    ),
    # ---------------------------------------------------------------- L. idiographic isolation
    dict(
        id="L1", campaign="L", name="personal baseline half-window 7 -> 180 days (baseline = pooled norm)",
        expectation="the v2 confound returns: a trend must not manufacture ties (probe oracle)",
        file="backend/app/services/brain.py",
        find="BASELINE_HALF_WINDOW = 7  # personal baseline = +/- this many days around a day",
        replace="BASELINE_HALF_WINDOW = 180  # personal baseline = +/- this many days around a day",
        tests=brain_suite(),
    ),
    dict(
        id="L2", campaign="L", name="poor-sleep split against a fixed 3.0 norm (not the user's own median)",
        expectation="the split must be within-person (own median)",
        file="backend/app/services/brain.py",
        find="        poor_sleep_days = {day for day, q in day_sleep_mean.items() if q < median}",
        replace="        poor_sleep_days = {day for day, q in day_sleep_mean.items() if q < 3.0}",
        tests=backend_pytest("tests/test_structured_channels.py", "tests/test_brain.py"),
    ),
    dict(
        id="L3", campaign="L", name="threshold date query inverted (counts OTHER users' active days)",
        expectation="the core product promise: one user's activity must never unlock another's",
        file="backend/app/api/insights.py",
        find="                select(Entry.entry_date)\n                .distinct()\n                .where(Entry.user_id == user_id)\n                .order_by(Entry.entry_date.asc())",
        replace="                select(Entry.entry_date)\n                .distinct()\n                .where(Entry.user_id != user_id)\n                .order_by(Entry.entry_date.asc())",
        tests=backend_pytest("tests/test_threshold.py", "tests/test_insights_api.py",
                             "tests/test_adversarial.py"),
    ),
    dict(
        id="L4", campaign="L", name="language-gate hit floor 0.10 -> 0.0 (gate always passes)",
        expectation="non-English prose must not feed English-lexicon detectors",
        file="backend/app/services/brain.py",
        find="LANGUAGE_HIT_FLOOR = 0.10",
        replace="LANGUAGE_HIT_FLOOR = 0.0",
        tests=brain_suite(),
    ),
    dict(
        id="L5", campaign="L", name="client mood-tag clamp removed (out-of-range tags flow into stats)",
        expectation="tags must be clamped to the engine scale",
        file="backend/app/services/brain.py",
        find="            sentiment = max(-1.0, min(1.0, entry.sentiment))",
        replace="            sentiment = entry.sentiment",
        tests=brain_suite(),
    ),
    # ---------------------------------------------------------------- M. sync/queue
    dict(
        id="M1", campaign="M", name="rejected-list duplicate suppression removed",
        expectation="recovered entries must not duplicate on requeue",
        file="mobile/src/offlineQueue.ts",
        find="  for (const item of items) {\n    if (!ids.has(item.clientEntryId)) {\n      existing.push(item);\n      ids.add(item.clientEntryId);\n    }\n  }",
        replace="  for (const item of items) {\n    existing.push(item);\n    ids.add(item.clientEntryId);\n  }",
        tests=vitest("tests/offlineQueue.test.ts", "tests/offlineQueue.pins.test.ts"),
    ),
    dict(
        id="M2", campaign="M", name="flush origin pin removed (queue may upload after origin switch)",
        expectation="origin-switched flush must stop; entries never cross origins",
        file="mobile/src/offlineQueue.ts",
        find="    if (scope.origin !== (await currentOrigin())) return sent;",
        replace="    if (false) return sent;",
        tests=vitest("tests/offlineQueue.test.ts", "tests/client.originSwitch.test.ts",
                     "tests/reconnectFlush.test.ts"),
    ),
    dict(
        id="M3", campaign="M", name="queue capacity bypass (MAX_QUEUE_LENGTH never enforced)",
        expectation="enqueue past 200 must throw QueueFullError",
        file="mobile/src/offlineQueue.ts",
        find="    if (queue.length >= MAX_QUEUE_LENGTH) throw new QueueFullError();",
        replace="    if (false) throw new QueueFullError();",
        tests=vitest("tests/offlineQueue.test.ts", "tests/offlineQueue.pins.test.ts"),
    ),
    dict(
        id="M4", campaign="M", name="session-expired flush drops entries (no rejected-store custody)",
        expectation="unsent entries must be preserved for recovery",
        file="mobile/src/offlineQueue.ts",
        find="        if (wipedSince(peek.generation)) return false;\n        await appendRejected(scope, queue, peek.generation);",
        replace="        if (wipedSince(peek.generation)) return false;",
        tests=vitest("tests/offlineQueue.test.ts", "tests/offlineQueue.pins.test.ts"),
    ),
    dict(
        id="M5", campaign="M", name="retry accounting frozen (attempts never increments)",
        expectation="exponential backoff must advance per attempt",
        file="mobile/src/offlineQueue.ts",
        find="            attempts: attempts + 1,",
        replace="            attempts: attempts,",
        tests=vitest("tests/offlineQueue.test.ts", "tests/offlineQueue.pins.test.ts"),
    ),
    dict(
        id="M6", campaign="M", name="corrupt queue deleted without quarantine",
        expectation="unparseable bytes must be quarantined, not discarded",
        file="mobile/src/offlineQueue.ts",
        find="  } catch {\n    await appendQuarantine(scope, raw, generation);\n    if (!wipedSince(generation)) await AsyncStorage.removeItem(key);\n    return [];\n  }",
        replace="  } catch {\n    if (!wipedSince(generation)) await AsyncStorage.removeItem(key);\n    return [];\n  }",
        tests=vitest("tests/offlineQueue.test.ts", "tests/offlineQueue.pins.test.ts"),
    ),
    # ---------------------------------------------------------------- N. redteam-as-oracle
    # Verdict semantics: CAUGHT = the harness reported FINDING for the
    # targeted audit (the harness works); MISSED = harness stayed BLOCKED
    # while the control was weakened (harness blind spot -> pin the harness).
    dict(
        id="N1", campaign="N", name="oracle: keystore pop no longer consumes (reuse) vs a_crypto.py",
        expectation="a_crypto must downgrade single-use to FINDING",
        file="backend/app/security/enclave.py",
        find="            del self._keys[token]\n            return key",
        replace="            return key",
        tests=redteam("a_crypto.py", "single-use"),
    ),
    dict(
        id="N2", campaign="N", name="oracle: KDF floor 100k -> 1 vs a_crypto.py",
        expectation="a_crypto must flag the KDF downgrade",
        file="backend/app/security/kdf.py",
        find="MIN_ITERATIONS = 100_000",
        replace="MIN_ITERATIONS = 1",
        tests=redteam("a_crypto.py", "kdf", "iteration"),
    ),
    dict(
        id="N3", campaign="N", name="oracle: suppress tier -> False vs e_crisis.py",
        expectation="e_crisis must flood FINDINGs on the bypass corpus",
        file="backend/app/services/crisis.py",
        find="    variants = _match_variants(text)\n    return any(SUPPRESS_RE.search(v) for v in variants[:2]) or any(\n        SUPPRESS_CONCAT_RE.search(v) for v in (variants[2],)\n    )",
        replace="    return False",
        tests=redteam("e_crisis.py", "suppress-bypass", "contract-drift"),
    ),
    dict(
        id="N4", campaign="N", name="oracle: engine ALPHA 0.05 -> 0.5 vs e2_brain.py",
        expectation="e2 must flag pure-noise surfacing",
        file="backend/app/services/brain.py",
        find="ALPHA = 0.05",
        replace="ALPHA = 0.5",
        tests=redteam("e2_brain.py", "pure-noise", "trend-manufactured"),
    ),
    dict(
        id="N5", campaign="N", name="oracle: body cap removed vs c_api.py",
        expectation="c_api must flag oversized-body acceptance",
        file="backend/app/middleware.py",
        find="        self.max_body_bytes = max_body_bytes",
        replace="        self.max_body_bytes = max_body_bytes * 1_000_000",
        tests=redteam("c_api.py", "oversized-body", "deep-json"),
    ),
    dict(
        id="N6", campaign="N", name="oracle: entry quota off vs c_api.py",
        expectation="c_api must flag quota bypass",
        file="backend/app/api/entries.py",
        find="    if count >= settings.max_entries_per_user:",
        replace="    if False:",
        tests=redteam("c_api.py", "entry-quota"),
    ),
    dict(
        id="N7", campaign="N", name="oracle: backdating window 400 days vs c_api.py",
        expectation="c_api must flag threshold inflation via backdating",
        file="backend/app/api/entries.py",
        find="    earliest = min(created_day, today) - timedelta(days=BACKDATE_GRACE_DAYS)",
        replace="    earliest = min(created_day, today) - timedelta(days=400)",
        tests=redteam("c_api.py", "backdating", "threshold-inflation"),
    ),
    dict(
        id="N8", campaign="N", name="oracle: account verifier check disabled vs b_auth.py",
        expectation="b_auth must flag verifier replay",
        file="backend/app/api/account.py",
        find="    if not hmac.compare_digest(candidate, bytes(user.verifier)):",
        replace="    if False:",
        tests=redteam("b_auth.py", "verifier"),
    ),
    dict(
        id="N9", campaign="N", name="oracle: account deletion keeps rows vs h_privacy.py",
        expectation="h_privacy must flag failed erasure",
        file="backend/app/api/account.py",
        find="            await session.execute(delete(Entry).where(Entry.user_id == user.id))",
        replace="            pass",
        tests=redteam("h_privacy.py", "erasure"),
    ),
    dict(
        id="N10", campaign="N", name="oracle: LLM digit ban removed vs d_llm.py",
        expectation="d_llm sanitizer corpus must flag minted numbers",
        file="backend/app/services/llm.py",
        find="    if any(ch.isdigit() for ch in text):\n        return None",
        replace="    if False:\n        return None",
        tests=redteam("d_llm.py", ""),
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
    elif kind == "redteam":
        fails = re.findall(r"^AUDIT\|(\S+)\|(FINDING|ERROR)\|(.*)$", output, re.M)
        fails = [f"{a} [{b}]" for a, b, _ in fails]
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


def run_command(spec: dict, mutant_id: str) -> tuple[bool, str | None, list[str], str, float]:
    """One command against the mutated tree.

    Returns (failed, setup_error, failures, output, seconds).

    For redteam-oracle commands the FULL output is kept: the audit scripts
    exit 0 even when they report FINDING verdicts, so the oracle must read
    the AUDIT| lines rather than the exit code."""
    env = dict(os.environ, CI="true")
    env["PATH"] = str(ROOT / ".tools/node/bin") + os.pathsep + env.get("PATH", "")
    # Never write .pyc during mutant runs: CPython validates bytecode by
    # source mtime at SECOND granularity, so a same-size mutant applied and
    # reverted inside one clock second can leave the MUTATED bytecode
    # cached while the source is restored — poisoning every later run
    # (found live during this campaign: threshold.py answered with the H4
    # mutant's behavior on a byte-clean tree).
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            spec["cmd"], cwd=ROOT / spec["cwd"], capture_output=True, text=True,
            timeout=spec["timeout"], env=env,
        )
        elapsed = round(time.monotonic() - t0, 1)
        out = (proc.stdout or "") + (proc.stderr or "")
        keep = out if spec["kind"] == "redteam" else out[-1500:]
        return (proc.returncode != 0,
                oracle_setup_error(spec["kind"], proc.returncode, out),
                parse_failures(spec["kind"], out), keep, elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - t0, 1)
        out = ((exc.stdout or b"").decode(errors="replace")
               + (exc.stderr or b"").decode(errors="replace"))
        return True, None, [], out, elapsed


def oracle_verdict(spec: dict, output_tail: str) -> tuple[bool, str]:
    """For redteam-oracle mutants: CAUGHT when a targeted audit FINDING appears."""
    wanted = spec.get("oracle", [])
    lines = [ln for ln in output_tail.splitlines() if ln.startswith("AUDIT|")]
    findings = [ln for ln in lines if "|FINDING|" in ln or "|ERROR|" in ln]
    hits = [ln for ln in findings if not wanted or any(w in ln for w in wanted)]
    if hits:
        return True, hits[0]
    if not wanted:
        return bool(findings), (findings[0] if findings else "no FINDING anywhere")
    return False, "targeted audits stayed non-FINDING: " + (
        "; ".join(ln for ln in lines if any(w in ln for w in wanted)) or "no matching audit lines"
    )


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
    specs = m["tests"] if isinstance(m["tests"], list) else [m["tests"]]
    # Corpus-regenerating harnesses poison their fixtures when run under a
    # mutant (found live: e_crisis re-exported every crisis sample as
    # suppress=false while the engine was mutated). Snapshot the corpus
    # artefacts around redteam-oracle runs and restore them after.
    corpus_paths = [ROOT / "redteam" / "crisis_corpus.json",
                    ROOT / "redteam" / "aad_corpus.json"]
    corpus_backup = {p: p.read_bytes() for p in corpus_paths if p.exists()}
    # Same hazard, found live 2026-09-19 via the PR gate: the redteam
    # scripts WRITE redteam/results/*.json on every run, so an oracle-mutant
    # replay records mutant-conditioned verdicts into TRACKED files.
    # Snapshot the whole results directory alongside the corpora.
    results_dir = ROOT / "redteam" / "results"
    results_backup = {p: p.read_bytes() for p in results_dir.glob("*.json")} if results_dir.is_dir() else {}
    try:
        per_cmd: list[dict] = []
        killed = False
        for spec in specs:
            failed, setup_error, failures, out, seconds = run_command(spec, m["id"])
            per_cmd.append({"kind": spec["kind"], "cmd": " ".join(spec["cmd"][:6]),
                            "failed": failed, "setup_error": setup_error,
                            "failures": failures, "seconds": seconds,
                            "output": out if spec["kind"] == "redteam" else ""})
            if setup_error:
                # The oracle could not run (renamed test file, collection
                # crash, bad flag): a KILLED verdict here would verify
                # nothing. Fail loudly instead of green.
                return {**m, "killed": None, "status": "SETUP-ERROR",
                        "detail": f"{spec['kind']}: {setup_error}",
                        "commands": per_cmd}
            if failed:
                killed = True
                break  # first failing oracle is enough
        if m["campaign"] == "N":
            caught, detail = oracle_verdict(specs[0], per_cmd[0]["output"] if per_cmd else "")
            return {**m, "killed": caught,
                    "status": "CAUGHT" if caught else "MISSED",
                    "detail": detail, "commands": per_cmd}
        status = "KILLED" if killed else "SURVIVED"
        return {**m, "killed": killed, "status": status, "commands": per_cmd}
    finally:
        for p, original_corpus in corpus_backup.items():
            p.write_bytes(original_corpus)
        for p, original_results in results_backup.items():
            if p.read_bytes() != original_results:
                p.write_bytes(original_results)
        target.write_bytes(original)
        if target.read_bytes() != original:
            raise RuntimeError(f"RESTORE FAILED for {m['id']} — {m['file']}")
        # Belt and braces for the stale-bytecode hazard above: drop any
        # cached bytecode produced while the mutant was on disk.
        pkg = target.parent / "__pycache__"
        if pkg.is_dir():
            stem = target.stem
            for cache in pkg.glob(f"{stem}.*.pyc"):
                cache.unlink(missing_ok=True)


def main() -> None:
    wanted = sys.argv[1:]
    todo = [m for m in MUTANTS if not wanted or m["campaign"] in wanted]
    print(f"{len(todo)} mutants queued\n", flush=True)
    results = []
    for m in todo:
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        r = run_mutant(m)
        results.append(r)
        if r["status"] == "SETUP-ERROR":
            print(f"    !! {r.get('detail', '')}", flush=True)
        else:
            which = " / ".join(
                f"{c['kind']}:{'fail' if c['failed'] else 'pass'}({c['seconds']}s)"
                for c in r.get("commands", [])
            )
            print(f"    -> {r['status']}  [{which}]"
                  + (f"  first: {r['commands'][0]['failures'][0]}"
                     if r.get("commands") and r["commands"][0]["failures"] else "")
                  + (f"  | {r.get('detail', '')}" if r["campaign"] == "N" else ""),
                  flush=True)
    killed = sum(1 for r in results if r["killed"])
    done = [r for r in results if r["killed"] is not None]
    print(f"\n{killed}/{len(done)} killed/caught, {len(done) - killed} survived/missed", flush=True)
    stamp = time.strftime("%Y-%m-%dT%H%M%S")
    path = OUT_DIR / f"mutation_results_{stamp}.json"
    path.write_text(json.dumps(results, indent=2))
    print(f"results: {path}")


if __name__ == "__main__":
    main()
