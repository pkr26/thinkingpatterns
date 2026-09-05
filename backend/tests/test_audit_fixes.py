"""Regression tests for the post-red-team remediation pass.

Every test here pins a fix for a confirmed audit finding; see the audit
report for the original exploit narratives.
"""

from __future__ import annotations

import asyncio
import base64
import json
import random
import time
from datetime import date, timedelta

import pytest

from app.config import Settings
from app.security import crypto
from app.services import brain, phrases, questions, statsig
from app.services.patterns import JournalEntry, Pattern
from tests.helpers import ClientEmulator, daterange

T0 = date(2026, 9, 4)


# --- finding 1: client-controlled inner created_at bricked recomputes -------------------


async def test_inner_date_far_from_outer_is_rejected_not_500(client):
    emu = ClientEmulator("innerdate", "pw-inner-date")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    # 31 clean days cross the insight threshold, so the recompute actually
    # decrypts and parses; the LAST entry carries the poisoned inner date.
    days = daterange(31, T0)
    for i, d in enumerate(days):
        if i == 30:
            body = {"v": 1, "text": "i cant sleep my mind wont stop",
                    "sentiment": None, "created_at": "3000-01-01"}
            blob = base64.b64encode(crypto.encrypt(
                emu.data_key, json.dumps(body).encode(),
                crypto.build_aad("entry", emu.user_id, f"e-inner-{i}"),
            )).decode()
        else:
            blob = emu.encrypt_entry("i cant sleep my mind wont stop", d, f"e-inner-{i}")
        response = await client.post("/api/entries", headers=emu.headers, json={
            "client_entry_id": f"e-inner-{i}", "blob": blob, "entry_date": d.isoformat(),
        })
        assert response.status_code == 201, response.text

    token = await emu.open_processing_session(client)
    response = await client.post("/api/insights/recompute",
                                 headers={**emu.headers, "X-Processing-Token": token})
    # Pre-fix: OverflowError escaping the handler -> 500, forever (the new
    # brain state never persisted, so every future recompute re-crashed).
    assert response.status_code == 400
    assert response.json()["detail"] == "entry payload malformed"


def test_decay_strength_tolerates_future_dates():
    # 2.0 ** +7900 used to raise OverflowError inside update(); the weight
    # per day is now capped at 1.0.
    strength = brain._decay_strength([date(3000, 1, 1), T0], T0)
    assert 0.0 <= strength <= 1.0
    # Past-day half-life math is unchanged.
    assert brain._decay_strength([T0 - timedelta(days=45)], T0) == pytest.approx(
        1 / brain.EVIDENCE_FULL / 2
    )


async def test_matching_inner_date_still_analyzes(client):
    emu = ClientEmulator("innerok", "pw-inner-ok")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    for d in daterange(32, T0):
        await emu.create_entry(client, "an ordinary day with work and sleep", d)
    result = await emu.recompute(client)
    assert result["phase"] == "insight"


# --- finding: config fail-open outside exact "production" ------------------------------


def test_staging_with_empty_secret_refuses_to_boot():
    with pytest.raises(RuntimeError, match="TOKEN_SECRET"):
        Settings(environment="staging", token_secret="",
                 database_url="sqlite+aiosqlite://")


def test_env_value_is_normalized_case_and_whitespace():
    # "Production " must hit the production gates (SQLite rejection), not
    # sail past an exact-string comparison.
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        Settings(environment=" Production ", token_secret="x" * 45,
                 database_url="sqlite+aiosqlite:///./x.db")
    with pytest.raises(RuntimeError, match="at least 32"):
        Settings(environment="PRODUCTION", token_secret="abc",
                 database_url="postgresql+asyncpg://u:p@h/db")


def test_numeric_env_ranges_abort_startup():
    for bad in ({"token_ttl_seconds": 0}, {"auth_rate_window": 0},
                {"unlock_threshold_days": -1}):
        with pytest.raises(RuntimeError, match="must be >= 1"):
            Settings(environment="development", database_url="sqlite+aiosqlite://", **bad)
    with pytest.raises(RuntimeError, match="must be >= 1024"):
        Settings(environment="development", database_url="sqlite+aiosqlite://",
                 max_body_bytes=10)


# --- finding: quota check-then-insert race ---------------------------------------------


async def test_concurrent_entry_creates_respect_quota(client, app):
    emu = ClientEmulator("quorarace", "pw-quota-race")
    await emu.register(client)
    app.state.settings.max_entries_per_user = 5

    async def create(i: int):
        return await client.post(
            "/api/entries", headers=emu.headers,
            json={"client_entry_id": f"e-race-{i}",
                  "blob": emu.encrypt_entry("x", T0, f"e-race-{i}"),
                  "entry_date": T0.isoformat()},
        )

    responses = await asyncio.gather(*(create(i) for i in range(20)))
    created = [r for r in responses if r.status_code == 201]
    rejected = [r for r in responses if r.status_code == 413]
    # Pre-fix: all 20 could succeed (each saw the quota un-consumed). The
    # per-user lock serializes check+insert and the quota holds exactly.
    assert len(created) == 5, [r.status_code for r in responses]
    assert len(rejected) == 15


# --- finding: per-username login bucket semantics ---------------------------------------


async def test_unknown_name_flood_never_consumes_login_buckets(client, app):
    from app.cache import FixedWindowCounter

    emu = ClientEmulator("lockvictim", "pw-lock-victim")
    await emu.register(client)
    wrong = base64.b64encode(b"\x00" * 32).decode()
    # Flood with requests for an UNKNOWN username: pre-fix every request
    # consumed a login-name:<name> bucket; now nothing is recorded.
    # (7 floods + 2 more logins below keep us inside the per-IP auth limit.)
    for _ in range(7):
        await client.post("/api/auth/login",
                          json={"username": "no-such-user-anywhere", "verifier": wrong})
    counter: FixedWindowCounter = app.state.rate_counter
    assert not any(k.startswith("login-name:") for k in counter._hits)

    # A failed verification for a REAL account still counts (brute-force
    # throttle intact), and the count lives under the namespaced key.
    await client.post("/api/auth/login",
                      json={"username": emu.username, "verifier": wrong})
    assert any(k.startswith(f"login-name:{emu.username}") for k in counter._hits)

    # And while under the limit, the legitimate user still gets in.
    r = await client.post("/api/auth/login",
                          json={"username": emu.username, "verifier": emu.auth_key_b64})
    assert r.status_code == 200


# --- finding: rate counter eviction churn ----------------------------------------------


def test_eviction_prefers_single_hit_garbage_over_multi_hit_victim():
    from app.cache import MAX_TRACKED_KEYS, FixedWindowCounter

    counter = FixedWindowCounter()
    now = 1000.0
    counter.hit("login-name:victim", 60, now=now)   # count 1
    counter.hit("login-name:victim", 60, now=now + 1)  # count 2
    for i in range(MAX_TRACKED_KEYS + 50):
        counter.hit(f"garbage-{i}", 60, now=now + 2)
    # The victim's active bucket must survive the garbage flood with its
    # count intact (pre-fix 10k fresh keys evicted it mid-window).
    assert counter.check("login-name:victim", 60, now=now + 3).count == 2


def test_ipv6_addresses_aggregate_to_64():
    from app.cache import _aggregate_host

    a = _aggregate_host("2001:db8:abcd:1234:1111:2222:3333:4444")
    b = _aggregate_host("2001:db8:abcd:1234:9999:8888:7777:6666")
    assert a == b and a.endswith("/64")
    assert _aggregate_host("203.0.113.9") == "203.0.113.9"
    assert _aggregate_host("not-a-host") == "not-a-host"


# --- finding: statistics honesty --------------------------------------------------------


def test_welch_two_constant_groups_is_no_evidence():
    # Crafted constant mood tags used to fabricate p ~ 1e-22 / d = 16.
    t, p = statsig.welch_test([-0.6] * 12, [0.2] * 12, variance_floor=0.05)
    assert t == 0.0 and p == 1.0


def test_dynamics_detectors_carry_pvalues_into_the_family():
    # Strong recent inertia (r1 ~ 0.9) vs weak earlier + rising variance:
    # both signals must now carry real p-values (they used to bypass the
    # Benjamini-Hochberg family with pvalue=None).
    rng = random.Random(7)
    day_sentiments, day_residuals = [], {}
    prev = 0.0
    for i in range(120):
        d = T0 - timedelta(days=119 - i)
        if i < 80:
            r = rng.uniform(-0.03, 0.03)   # quiet iid baseline
        elif i < 90:
            r = rng.uniform(-0.03, 0.03)   # buffer
        else:
            prev = 0.9 * prev + rng.uniform(-0.06, 0.06)  # sticky + volatile
            r = prev * 3.0
        day_sentiments.append((d, r))
        day_residuals[d] = r
    signals = brain._detect_mood_dynamics(day_sentiments, day_residuals, T0)
    kinds = {s.kind for s in signals}
    assert {"inertia", "instability"} <= kinds
    for s in signals:
        assert s.pvalue is not None and 0.0 <= s.pvalue <= 1.0
        assert s.detail.get("p_value") is not None


def test_mood_shift_signal_carries_pvalue():
    days = daterange(60, T0)
    series = [-0.05] * 30 + [-0.9] * 30  # sustained late drop
    signals = brain._detect_mood_shift(list(zip(days, series)))
    assert signals, "a real sustained shift must still fire"
    for s in signals:
        assert s.pvalue is not None and 0.0 <= s.pvalue <= 1.0


def test_ewma_limits_are_autocorrelation_aware():
    # Stationary AR(1) phi=0.5 mood with NO shift: the iid-variance chart
    # fired on ~18% of windows pre-fix; the inflated limits must hold.
    rng = random.Random(1234)
    fired = 0
    for trial in range(12):
        days = daterange(90, T0 - timedelta(days=trial))
        prev = 0.0
        series = []
        for _ in days:
            prev = 0.5 * prev + rng.uniform(-0.5, 0.5)
            series.append(prev)
        fired += bool(brain._detect_mood_shift(list(zip(days, series))))
    assert fired <= 2, f"EWMA fired {fired}/12 on stationary AR(1) mood"


def test_corpus_boilerplate_never_becomes_a_topic():
    # "unique day N" in every entry used to surface as topic:unique.
    entries = [JournalEntry(f"unique day {i} again", T0 - timedelta(days=60 - i), None)
               for i in range(31)]
    result = brain.update(brain.load_state(None), entries, T0)
    assert not any(p.kind == "topic" for p in result.surfaced)


def test_pattern_labels_are_capped_at_write_time():
    worry = "worry " * 100  # ~600-char sentence, within the clustering token cap
    entries = [JournalEntry(worry + f"variant{i}", T0 - timedelta(days=k), -0.8)
               for i, k in enumerate((30, 20, 10, 5, 2, 0))]
    state = brain.update(brain.load_state(None), entries, T0).new_state
    assert state["patterns"], "the near-duplicate worry should cluster"
    for record in state["patterns"].values():
        label = record.label if hasattr(record, "label") else record["label"]
        assert len(label) <= 200


def test_phrase_clustering_is_bounded_on_adversarial_buckets():
    # Hundreds of distinct near-variants of one sentence used to cost
    # O(bucket^2) signature comparisons (minutes at 4000 variants).
    days = daterange(60, T0)
    refs = []
    for i, d in enumerate(days * 5):
        token = "vary" + "a" * (i % 20 + 1) + "z" * (i % 7 + 1)
        refs.append(phrases.SentenceRef(
            text=f"everything is falling apart because {token}", day=d))
    start = time.monotonic()
    phrases.near_duplicate_clusters(refs)
    assert time.monotonic() - start < 10.0


# --- finding: LLM sanitizer --------------------------------------------------------------


def test_llm_numeric_details_reject_nonfinite():
    from app.services.llm import sanitize_pattern
    kept = sanitize_pattern(
        {"kind": "mood_shift", "label": "mood",
         "detail": {"shift": float("inf"), "baseline": float("nan"), "current": 0.4}},
        ["my mood today"],
    )
    assert kept is not None
    assert "shift" not in kept.detail and "baseline" not in kept.detail
    assert kept.detail["current"] == 0.4


def test_llm_labels_are_corpus_grounded_and_url_free():
    from app.services.llm import sanitize_pattern
    corpus = ["work was heavy and sleep was short"]
    # Prompt-injected instruction label: rejected.
    assert sanitize_pattern(
        {"kind": "temporal", "label": "URGENT call 555-0134 now"}, corpus) is None
    # Ungrounded content word: rejected.
    assert sanitize_pattern({"kind": "temporal", "label": "guitar"}, corpus) is None
    # Grounded label passes.
    kept = sanitize_pattern({"kind": "temporal", "label": "work"}, corpus)
    assert kept is not None and kept.label == "work"


def test_llm_bool_occurrences_not_an_int():
    from app.services.llm import sanitize_pattern
    kept = sanitize_pattern(
        {"kind": "temporal", "label": "work", "occurrences": True}, ["work day"])
    assert kept is not None and kept.occurrences == 0


# --- finding: crisis interlock ------------------------------------------------------------


def test_crisis_labels_never_generate_reflective_questions():
    crisis = Pattern("rumination", "I want to disappear and not wake up", 7, 0.9, {})
    pool = questions.build_pool([crisis])
    assert pool, "generic pool must remain"
    assert all("disappear" not in q.lower() for q in pool)
    # Non-crisis labels still render their templates.
    ok = Pattern("rumination", "I can't focus on anything", 7, 0.9, {})
    assert any("can't focus" in q for q in questions.build_pool([ok]))


# --- finding: SQLite FK enforcement -------------------------------------------------------


async def test_sqlite_foreign_keys_are_enforced(app):
    from sqlalchemy import text

    async with app.state.engine.begin() as conn:
        status = (await conn.execute(text("PRAGMA foreign_keys"))).scalar()
    assert status == 1


# --- finding: analysis caps ----------------------------------------------------------------


def test_parse_entries_caps_text_totals():
    from app.api.insights import (
        MAX_ANALYSIS_TEXT_CHARS,
        MAX_ANALYSIS_TOTAL_CHARS,
        _parse_entries,
    )
    plains, dates = [], []
    for _ in range(30):
        text = "word " * 90_000  # ~450 KB per entry; 30 entries >> the total cap
        plains.append(bytearray(json.dumps(
            {"v": 1, "text": text, "sentiment": None, "created_at": "2026-09-01"}).encode()))
        dates.append(date(2026, 9, 1))
    entries = _parse_entries(plains, dates)
    assert all(len(e.text) <= MAX_ANALYSIS_TEXT_CHARS for e in entries)
    assert sum(len(e.text) for e in entries) <= MAX_ANALYSIS_TOTAL_CHARS + MAX_ANALYSIS_TEXT_CHARS


def test_parse_entries_rejects_bool_sentiment():
    from app.api.insights import _parse_entries
    payload = json.dumps(
        {"v": 1, "text": "x", "sentiment": True, "created_at": "2026-09-01"})
    with pytest.raises(ValueError):
        _parse_entries([bytearray(payload.encode())], [date(2026, 9, 1)])


# --- finding: single-use enforcement was a scheduling accident ---------------------------


def test_keystore_pop_is_atomic_single_use():
    from app.security.enclave import InMemoryKeyStore, KeyNotFound

    store = InMemoryKeyStore()
    key = b"k" * 32
    token = store.create(key, ttl_seconds=300, owner="u1")
    # First pop wins and consumes; a concurrent second pop cannot reuse it.
    assert store.pop(token, owner="u1") == key
    try:
        store.pop(token, owner="u1")
        raised = False
    except KeyNotFound:
        raised = True
    assert raised
