"""Security remediation regression pins.

Every test in this file pins one fixed security finding from the red-team
and post-red-team remediation waves (2026-09-16 through 2026-09-17). If
one starts failing, a security fix regressed -- treat it as a release
blocker. The original per-finding audit reports were removed in the
production cleanup; the full remediation history is preserved in git
history (commits 2026-09-16 .. 2026-09-21).
"""
from __future__ import annotations
from app import singleprocess
from app.api.auth import SCRYPT_N, decoy_salt
from app.cache import FixedWindowCounter, MAX_TRACKED_KEYS
from app.config import Settings
from app.main import create_app
from app.security import crypto, enclave, kdf
from app.security.enclave import InMemoryKeyStore
from app.services import brain, crisis, llm, phrases, questions, statsig
from app.services.patterns import JournalEntry, Pattern
from datetime import date, datetime, timedelta, timezone
from httpx import ASGITransport, AsyncClient
from tests.helpers import ClientEmulator, daterange
import anyio
import asyncio
import base64
import hashlib
import hmac
import json
import pytest
import random
import subprocess
import sys
import time


# ---------------------------------------------------------------------------
# Pins from test_audit_fixes.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
# Anchor for all dates in this module. API-touching tests post entries on
# T0-relative dates while the server judges them against its real clock
# (account age, decay), so T0 must track today: a fixed pin rots as the
# wall clock moves past it (daterange(N, T0) windows drift below the
# backdated account horizon and the API starts rejecting them). Pure
# brain-function uses of T0 are date-agnostic.
T0 = date.today()


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
            body = {
                "v": 1,
                "text": "i cant sleep my mind wont stop",
                "sentiment": None,
                "created_at": "3000-01-01",
            }
            blob = base64.b64encode(
                crypto.encrypt(
                    emu.data_key,
                    json.dumps(body).encode(),
                    crypto.build_aad("entry", emu.user_id, f"e-inner-{i}"),
                )
            ).decode()
        else:
            blob = emu.encrypt_entry("i cant sleep my mind wont stop", d, f"e-inner-{i}")
        response = await client.post(
            "/api/entries",
            headers=emu.headers,
            json={
                "client_entry_id": f"e-inner-{i}",
                "blob": blob,
                "entry_date": d.isoformat(),
            },
        )
        assert response.status_code == 201, response.text

    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
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
        Settings(environment="staging", token_secret="", database_url="sqlite+aiosqlite://")


def test_env_value_is_normalized_case_and_whitespace():
    # "Production " must hit the production gates (SQLite rejection), not
    # sail past an exact-string comparison.
    with pytest.raises(RuntimeError, match="PostgreSQL"):
        Settings(
            environment=" Production ",
            token_secret="x" * 45,
            database_url="sqlite+aiosqlite:///./x.db",
        )
    with pytest.raises(RuntimeError, match="at least 32"):
        Settings(
            environment="PRODUCTION",
            token_secret="abc",
            database_url="postgresql+asyncpg://u:p@h/db",
        )


def test_numeric_env_ranges_abort_startup():
    for bad in ({"token_ttl_seconds": 0}, {"auth_rate_window": 0}, {"unlock_threshold_days": -1}):
        with pytest.raises(RuntimeError, match="must be >= 1"):
            Settings(environment="development", database_url="sqlite+aiosqlite://", **bad)
    with pytest.raises(RuntimeError, match="must be >= 1024"):
        Settings(environment="development", database_url="sqlite+aiosqlite://", max_body_bytes=10)


# --- finding: quota check-then-insert race ---------------------------------------------


async def test_concurrent_entry_creates_respect_quota(client, app):
    emu = ClientEmulator("quorarace", "pw-quota-race")
    await emu.register(client)
    app.state.settings.max_entries_per_user = 5
    # Entry dates must not precede account creation, so this API-touching
    # test uses the real current date rather than the fixed T0 pin.
    today = date.today()

    async def create(i: int):
        return await client.post(
            "/api/entries",
            headers=emu.headers,
            json={
                "client_entry_id": f"e-race-{i}",
                "blob": emu.encrypt_entry("x", today, f"e-race-{i}"),
                "entry_date": today.isoformat(),
            },
        )

    responses = await asyncio.gather(*(create(i) for i in range(20)))
    created = [r for r in responses if r.status_code == 201]
    rejected = [r for r in responses if r.status_code == 413]
    # Pre-fix: all 20 could succeed (each saw the quota un-consumed). The
    # per-user lock serializes check+insert and the quota holds exactly.
    assert len(created) == 5, [r.status_code for r in responses]
    assert len(rejected) == 15


async def test_replace_delete_race_is_serialized_and_never_500(client):
    """An edit and delete of one entry have one linearizable outcome.

    The mobile client normally avoids this overlap, but retries, two active
    screens, or a hostile replay can create it.  Either mutation may win;
    neither may surface SQLAlchemy's stale-row exception as a 500.
    """
    emu = ClientEmulator("entry-edit-delete-race", "pw-entry-race")
    await emu.register(client)
    entry = await emu.create_entry(client, "before race", date.today(), client_entry_id="e-race")

    update, removal = await asyncio.gather(
        client.put(
            f"/api/entries/{entry['client_entry_id']}",
            headers=emu.headers,
            json={
                "blob": emu.encrypt_entry("concurrent update", date.today(), "e-race"),
                "entry_date": date.today().isoformat(),
            },
        ),
        client.delete(f"/api/entries/{entry['client_entry_id']}", headers=emu.headers),
    )
    assert update.status_code in {200, 404}
    assert removal.status_code in {204, 404}
    assert 500 not in {update.status_code, removal.status_code}


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
        await client.post(
            "/api/auth/login", json={"username": "no-such-user-anywhere", "verifier": wrong}
        )
    counter: FixedWindowCounter = app.state.rate_counter
    assert not any(k.startswith("login-name:") for k in counter._hits)

    # A failed verification for a REAL account is still IP-throttled, but it
    # cannot create a name-scoped lockout that a distributed attacker spends
    # on the legitimate user's behalf.
    await client.post("/api/auth/login", json={"username": emu.username, "verifier": wrong})
    assert not any(k.startswith(f"login-name:{emu.username}") for k in counter._hits)

    # And while under the limit, the legitimate user still gets in.
    r = await client.post(
        "/api/auth/login", json={"username": emu.username, "verifier": emu.auth_key_b64}
    )
    assert r.status_code == 200


# --- finding: rate counter eviction churn ----------------------------------------------


def test_eviction_prefers_single_hit_garbage_over_multi_hit_victim():
    from app.cache import MAX_TRACKED_KEYS, FixedWindowCounter

    counter = FixedWindowCounter()
    now = 1000.0
    counter.hit("login-name:victim", 60, now=now)  # count 1
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
            r = rng.uniform(-0.03, 0.03)  # quiet iid baseline
        elif i < 90:
            r = rng.uniform(-0.03, 0.03)  # buffer
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
    entries = [
        JournalEntry(f"unique day {i} again", T0 - timedelta(days=60 - i), None) for i in range(31)
    ]
    result = brain.update(brain.load_state(None), entries, T0)
    assert not any(p.kind == "topic" for p in result.surfaced)


def test_pattern_labels_are_capped_at_write_time():
    worry = "worry " * 100  # ~600-char sentence, within the clustering token cap
    entries = [
        JournalEntry(worry + f"variant{i}", T0 - timedelta(days=k), -0.8)
        for i, k in enumerate((30, 20, 10, 5, 2, 0))
    ]
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
        refs.append(phrases.SentenceRef(text=f"everything is falling apart because {token}", day=d))
    start = time.monotonic()
    phrases.near_duplicate_clusters(refs)
    assert time.monotonic() - start < 10.0


# --- finding: LLM sanitizer --------------------------------------------------------------


def test_llm_numeric_details_reject_nonfinite():
    from app.services.llm import sanitize_pattern

    kept = sanitize_pattern(
        {
            "kind": "mood_shift",
            "label": "mood",
            "detail": {"shift": float("inf"), "baseline": float("nan"), "current": 0.4},
        },
        ["my mood today"],
    )
    assert kept is not None
    assert "shift" not in kept.detail and "baseline" not in kept.detail
    assert kept.detail["current"] == 0.4


def test_llm_labels_are_corpus_grounded_and_url_free():
    from app.services.llm import sanitize_pattern

    corpus = ["work was heavy and sleep was short"]
    # Prompt-injected instruction label: rejected.
    assert (
        sanitize_pattern({"kind": "temporal", "label": "URGENT call 555-0134 now"}, corpus) is None
    )
    # Ungrounded content word: rejected.
    assert sanitize_pattern({"kind": "temporal", "label": "guitar"}, corpus) is None
    # Grounded label passes.
    kept = sanitize_pattern({"kind": "temporal", "label": "work"}, corpus)
    assert kept is not None and kept.label == "work"


def test_llm_bool_occurrences_not_an_int():
    from app.services.llm import sanitize_pattern

    kept = sanitize_pattern(
        {"kind": "temporal", "label": "work", "occurrences": True}, ["work day"]
    )
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


async def test_sqlite_foreign_keys_are_enforced(app, settings):
    if not settings.database_url.startswith("sqlite"):
        pytest.skip("PRAGMA foreign_keys is SQLite-specific (Postgres enforces FKs natively)")

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
        plains.append(
            bytearray(
                json.dumps(
                    {"v": 1, "text": text, "sentiment": None, "created_at": "2026-09-01"}
                ).encode()
            )
        )
        dates.append(date(2026, 9, 1))
    entries = _parse_entries(plains, dates)
    assert all(len(e.text) <= MAX_ANALYSIS_TEXT_CHARS for e in entries)
    assert sum(len(e.text) for e in entries) <= MAX_ANALYSIS_TOTAL_CHARS + MAX_ANALYSIS_TEXT_CHARS


def test_parse_entries_rejects_bool_sentiment():
    from app.api.insights import _parse_entries

    payload = json.dumps({"v": 1, "text": "x", "sentiment": True, "created_at": "2026-09-01"})
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


# --- finding: total-corpus budget crashed on the frozen JournalEntry ---------------------


def test_parse_entries_total_budget_truncates_oldest():
    # Entries sized EXACTLY at the per-entry cap: the per-entry truncation
    # cannot shrink them, so the total-corpus budget loop is the branch
    # under test (the earlier 450KB fixture never reached it). Pre-fix the
    # loop assigned to a frozen dataclass field -> FrozenInstanceError.
    from app.api.insights import (
        MAX_ANALYSIS_TEXT_CHARS,
        MAX_ANALYSIS_TOTAL_CHARS,
        _parse_entries,
    )

    n = MAX_ANALYSIS_TOTAL_CHARS // MAX_ANALYSIS_TEXT_CHARS + 1  # 101
    plains, dates = [], []
    for _ in range(n):
        plains.append(
            bytearray(
                json.dumps(
                    {
                        "v": 1,
                        "text": "x" * MAX_ANALYSIS_TEXT_CHARS,
                        "sentiment": None,
                        "created_at": "2026-09-01",
                    }
                ).encode()
            )
        )
        dates.append(date(2026, 9, 1))
    entries = _parse_entries(plains, dates)
    assert sum(len(e.text) for e in entries) <= MAX_ANALYSIS_TOTAL_CHARS
    assert entries[0].text == ""  # oldest truncated first
    assert len(entries[-1].text) == MAX_ANALYSIS_TEXT_CHARS  # newest kept


async def test_recompute_over_total_corpus_budget_returns_200(client):
    # End-to-end: >100 entries of 20k chars each exceed the 2M total budget
    # after the per-entry cap, so the recompute must truncate, not 500.
    from app.api.insights import MAX_ANALYSIS_TEXT_CHARS, MAX_ANALYSIS_TOTAL_CHARS

    emu = ClientEmulator("bigcorpus", "pw-big-corpus")
    await emu.register(client)
    await emu.backdate_account(client, days=120)
    n = MAX_ANALYSIS_TOTAL_CHARS // MAX_ANALYSIS_TEXT_CHARS + 1
    days = daterange(40, date.today())  # 40 active days >= the 30-day threshold
    for i in range(n):
        await emu.create_entry(
            client,
            "x" * MAX_ANALYSIS_TEXT_CHARS,
            days[i % len(days)],
            client_entry_id=f"e-big-{i}",
        )
    result = await emu.recompute(client)
    assert result["phase"] == "insight"


# --- finding: API-layer data key was never zeroized --------------------------------------


async def test_recompute_zeroizes_api_layer_data_key_on_success(client, monkeypatch):
    from app.api import insights
    from app.security import enclave

    captured = []
    real_zeroize = enclave.zeroize

    def spy(buf):
        captured.append(buf)
        real_zeroize(buf)

    monkeypatch.setattr(insights, "zeroize", spy)

    emu = ClientEmulator("zeroizeok", "pw-zeroize-ok")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    for d in daterange(31, date.today()):
        await emu.create_entry(client, "an ordinary day with work and sleep", d)
    result = await emu.recompute(client)
    assert result["phase"] == "insight"
    assert captured, "API-layer data key was never zeroized"
    assert all(all(byte == 0 for byte in buf) for buf in captured)


async def test_recompute_zeroizes_api_layer_data_key_on_error(client, monkeypatch):
    from app.api import insights
    from app.security import enclave

    captured = []
    real_zeroize = enclave.zeroize

    def spy(buf):
        captured.append(buf)
        real_zeroize(buf)

    monkeypatch.setattr(insights, "zeroize", spy)

    emu = ClientEmulator("zeroizeerr", "pw-zeroize-err")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    days = daterange(31, date.today())
    for i, d in enumerate(days):
        if i == 30:
            # Encrypted under the WRONG key: decryption fails authentication,
            # driving the 400 path that must still scrub the data key.
            blob = base64.b64encode(
                crypto.encrypt(
                    bytes(32),
                    json.dumps(
                        {"v": 1, "text": "broken", "sentiment": None, "created_at": d.isoformat()}
                    ).encode(),
                    crypto.build_aad("entry", emu.user_id, "e-tampered"),
                )
            ).decode()
            response = await client.post(
                "/api/entries",
                headers=emu.headers,
                json={
                    "client_entry_id": "e-tampered",
                    "blob": blob,
                    "entry_date": d.isoformat(),
                },
            )
            assert response.status_code == 201, response.text
        else:
            await emu.create_entry(client, "an ordinary day with work and sleep", d)
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert response.status_code == 400
    assert captured, "API-layer data key was never zeroized on the error path"
    assert all(all(byte == 0 for byte in buf) for buf in captured)


def test_keystore_pop_transfers_owned_bytearray():
    from app.security.enclave import InMemoryKeyStore, zeroize

    store = InMemoryKeyStore()
    token = store.create(b"k" * 32, ttl_seconds=300, owner="u1")
    key = store.pop(token, owner="u1")
    # No immutable copy is minted: the caller gets the store's own mutable
    # buffer and is responsible for scrubbing it.
    assert isinstance(key, bytearray)
    assert bytes(key) == b"k" * 32
    zeroize(key)
    assert bytes(key) == bytes(32)


# --- finding: phrase detection dropped the newest entries when capped ---------------------


def test_phrase_detection_keeps_recent_entries_when_capped(monkeypatch):
    # With the sentence budget exceeded, the OLDEST sentences are dropped —
    # pre-fix the cap kept the oldest ~window and a phrase that only recurs
    # in recent entries was invisible. A small patched budget keeps the
    # MinHash work tiny while exercising the same branch.
    monkeypatch.setattr(brain, "MAX_WINDOW_SENTENCES", 50)
    window = [
        JournalEntry(
            text=f"old entry number {i} had nothing repeat.",
            entry_date=T0 - timedelta(days=120 - i),
            sentiment=None,
        )
        for i in range(60)
    ]
    phrase = "i keep replaying that conversation in my head"
    for offset in (14, 10, 5, 0):  # 4 distinct days, 14-day span: qualifies
        window.append(
            JournalEntry(text=phrase + ".", entry_date=T0 - timedelta(days=offset), sentiment=None)
        )
    signals = brain._detect_phrases(brain._phrase_clusters(window))
    assert any("replaying that conversation" in s.label for s in signals)


# --- finding: revived archived patterns skipped the confirmation clock --------------------


@pytest.mark.parametrize("stale_state", ["fading", "archived"])
def test_revived_pattern_restarts_confirmation_clock(stale_state):
    today = T0
    old_first = (today - timedelta(days=100)).isoformat()
    last = (today - timedelta(days=10)).isoformat()

    store = brain.fresh_state()
    store["patterns"]["p-revive"] = brain.StoredPattern(
        pid="p-revive",
        kind="temporal",
        label="sunday dread",
        first_seen=old_first,
        last_seen=last,
        first_qualified=old_first,
        last_qualified=last,
        occurrences=4,
        state=stale_state,
        qualification_days=[old_first],
        evidence_dates=[old_first],
        feedback={},
        detail={},
    )

    def qualify(day: date) -> None:
        brain._merge_lifecycle(
            store,
            [
                brain._Signal(
                    pid="p-revive",
                    kind="temporal",
                    label="sunday dread",
                    occurrences=4,
                    pvalue=None,
                    detail={},
                    evidence_days=[day - timedelta(days=1), day],
                )
            ],
            day,
        )

    qualify(today)
    record = store["patterns"]["p-revive"]
    assert record.state == "emerging"
    assert record.first_qualified == today.isoformat()
    # Re-qualifying the next day must NOT promote to confirmed: the pattern
    # has to re-prove itself through the normal CONFIRM_AGE_DAYS window.
    # Pre-fix the stale first_qualified (100 days old) confirmed it here.
    qualify(today + timedelta(days=1))
    assert store["patterns"]["p-revive"].state == "emerging"


# --- finding: recomputes for one user were not serialized ---------------------------------


async def test_concurrent_recomputes_for_one_user_serialize(client, monkeypatch):
    import threading

    emu = ClientEmulator("recserial", "pw-recompute-serial")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    for d in daterange(31, date.today()):
        await emu.create_entry(client, "an ordinary day with work and sleep", d)

    guard = threading.Lock()
    active = 0
    overlapped = False
    real_run = enclave.SecureProcessingContext.run

    def run_spy(self, encrypted, analyze):
        # Runs on a worker thread; the sleep widens the would-be overlap so
        # an unserialized pair is observed with (near-)certainty.
        nonlocal active, overlapped
        with guard:
            overlapped = overlapped or active > 0
            active += 1
        try:
            time.sleep(0.05)
            return real_run(self, encrypted, analyze)
        finally:
            with guard:
                active -= 1

    monkeypatch.setattr(enclave.SecureProcessingContext, "run", run_spy)

    token1 = await emu.open_processing_session(client)
    token2 = await emu.open_processing_session(client)
    r1, r2 = await asyncio.gather(
        client.post(
            "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token1}
        ),
        client.post(
            "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token2}
        ),
    )
    assert r1.status_code == 200, r1.text
    assert r2.status_code == 200, r2.text
    assert not overlapped


# --- finding: UserLocks eviction could orphan a parked waiter -----------------
# (the registry moved from app.api.entries to app.locks in the 2026-09
# remediation round so insights.py stops importing a private router name)


async def test_user_locks_never_evict_a_lock_with_waiters():
    from app.locks import UserLocks

    locks = UserLocks(max_keys=1)
    entered = asyncio.Event()
    release = asyncio.Event()
    acquired: list[asyncio.Lock] = []

    async def first():
        async with locks.hold("k"):
            entered.set()
            await release.wait()

    async def waiter():
        await entered.wait()
        async with locks.hold("k") as lock:
            acquired.append(lock)

    t1 = asyncio.create_task(first())
    t2 = asyncio.create_task(waiter())
    await entered.wait()
    for _ in range(1000):
        if locks._locks["k"].refs == 2:  # holder + parked waiter
            break
        await asyncio.sleep(0.001)
    assert locks._locks["k"].refs == 2
    original = locks._locks["k"].lock
    # Capacity pressure while the waiter is parked: the waited-on lock must
    # survive (evicting it would orphan the waiter and let the next hold("k")
    # mint a second lock for the same key).
    async with locks.hold("other"):
        pass
    assert locks._locks["k"].lock is original
    release.set()
    await asyncio.gather(t1, t2)
    assert acquired == [original]


async def test_user_locks_still_recycle_idle_entries():
    from app.locks import UserLocks

    locks = UserLocks(max_keys=2)
    for key in ("a", "b"):
        async with locks.hold(key):
            pass
    async with locks.hold("c"):
        pass
    assert set(locks._locks) == {"b", "c"}


# --- finding: list_entries pagination had no tiebreaker -----------------------------------


async def test_list_entries_pagination_has_stable_total_order(client, app):
    from sqlalchemy import update as sql_update

    from app.models import Entry

    emu = ClientEmulator("paginate", "pw-paginate")
    await emu.register(client)
    day = date.today()
    for i in range(5):
        await emu.create_entry(client, f"page order entry {i}", day, client_entry_id=f"e-page-{i}")
    # Identical (entry_date, received_at): only the id tiebreaker orders these.
    async with app.state.sessionmaker() as s:
        await s.execute(
            sql_update(Entry).values(received_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        )
        await s.commit()

    async def fetch(offset: int, limit: int) -> list[str]:
        response = await client.get(
            "/api/entries", headers=emu.headers, params={"offset": offset, "limit": limit}
        )
        assert response.status_code == 200, response.text
        return [row["id"] for row in response.json()]

    full = await fetch(0, 100)
    paged = await fetch(0, 2) + await fetch(2, 2) + await fetch(4, 2)
    assert len(full) == 5
    assert paged == full  # no duplicates, no reordering across page boundaries


# --- finding: insights corpus load had no tiebreaker --------------------------------------


async def test_load_rows_has_stable_total_order(client, app):
    from sqlalchemy import update as sql_update

    from app.api.insights import _load_rows
    from app.models import Entry

    emu = ClientEmulator("corpusorder", "pw-corpus-order")
    await emu.register(client)
    day = date.today()
    for i in range(5):
        await emu.create_entry(
            client, f"corpus order entry {i}", day, client_entry_id=f"e-corpus-{i}"
        )
    # Identical (entry_date, received_at): only the id tiebreaker orders these.
    # Without it, which entry the 2M-char corpus budget truncates is
    # DB-arbitrary and can flip between recomputes.
    async with app.state.sessionmaker() as s:
        await s.execute(
            sql_update(Entry).values(received_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        )
        await s.commit()
        rows = await _load_rows(s, emu.user_id, limit=10, blob_budget=8 * 1024 * 1024)
    # Entry ids are random uuid hex, so ascending id order can only come from
    # an explicit ORDER BY ... id — never from insertion/rowid order.
    ids = [row.id for row in rows]
    assert len(ids) == 5
    assert ids == sorted(ids)


async def test_load_rows_sql_bounds_to_the_most_recent_n(client, app):
    """The corpus load is LIMITed in SQL (recency DESC + reversed), not
    fetched whole and sliced in Python: exactly the most recent N entries
    come back, in chronological order for the analyzer."""
    from app.api.insights import _load_rows

    emu = ClientEmulator("corpuscap", "pw-corpus-cap")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    day = date.today()
    # 6 entries on 6 distinct days; the limit keeps the NEWEST 4.
    for offset in range(6, 0, -1):
        d = day - timedelta(days=offset)
        await emu.create_entry(client, f"day minus {offset}", d, client_entry_id=f"e-cap-{offset}")
    async with app.state.sessionmaker() as s:
        rows = await _load_rows(s, emu.user_id, limit=4, blob_budget=8 * 1024 * 1024)
    dates = [row.entry_date for row in rows]
    assert dates == [day - timedelta(days=o) for o in (4, 3, 2, 1)]  # newest 4, ascending



# ---------------------------------------------------------------------------
# Pins from test_redteam_fixes.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
TODAY = date.today()


# --- H-2/H-1: scrypt cost + off-loop + bounded concurrency ----------------------


def test_scrypt_params_meet_hardened_floor():
    # N=2^16 (64 MiB) with the input already PBKDF2-600k stretched client-side.
    assert SCRYPT_N == 2**16


def test_auth_scrypt_has_a_dedicated_capacity_limiter(settings):
    # Login/register scrypt (64 MiB per hash) must not queue unboundedly on
    # the shared anyio thread pool: the app wires a small dedicated limiter.
    app = create_app(settings)
    limiter = app.state.auth_limiter
    assert isinstance(limiter, anyio.CapacityLimiter)
    assert limiter.total_tokens == 4


async def test_login_scrypt_runs_behind_the_auth_limiter(client, app, monkeypatch):
    emu = ClientEmulator("capped", "p")
    await emu.register(client)
    seen_limiters = []
    real_run_sync = anyio.to_thread.run_sync

    async def spy(func, *args, limiter=None, **kwargs):
        seen_limiters.append(limiter)
        return await real_run_sync(func, *args, limiter=limiter, **kwargs)

    monkeypatch.setattr(anyio.to_thread, "run_sync", spy)
    await emu.login(client)
    assert app.state.auth_limiter in seen_limiters


async def test_llm_consent_scrypt_runs_behind_the_auth_limiter(client, app, monkeypatch, settings):
    # The account verifier re-check runs the same 64-MiB scrypt; it must sit
    # behind the dedicated auth limiter too, not the shared anyio pool.
    settings.llm_url = "https://llm.example.test/v1"
    emu = ClientEmulator("cappedconsent", "p")
    await emu.register(client)
    seen_limiters = []
    real_run_sync = anyio.to_thread.run_sync

    async def spy(func, *args, limiter=None, **kwargs):
        seen_limiters.append(limiter)
        return await real_run_sync(func, *args, limiter=limiter, **kwargs)

    monkeypatch.setattr(anyio.to_thread, "run_sync", spy)
    response = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert response.status_code == 200
    assert app.state.auth_limiter in seen_limiters


# --- M-4: whole-request body cap ------------------------------------------------


async def test_whole_body_over_cap_is_413_before_parsing(client):
    emu = ClientEmulator("bodycap", "p")
    await emu.register(client)
    # ~2.67 MB b64 blob: under the 2 MiB whole-body cap is irrelevant — the
    # body itself (not any field) trips the middleware before JSON parsing.
    huge = base64.b64encode(b"x" * 2_000_000).decode()
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "big",
            "blob": huge,
            "entry_date": TODAY.isoformat(),
        },
    )
    assert response.status_code == 413
    assert response.headers.get("x-content-type-options") == "nosniff"  # 413s carry headers too


async def test_deeply_nested_json_is_400_not_500(client):
    emu = ClientEmulator("nestbomb", "p")
    await emu.register(client)
    nest = {"blob": "x"}
    for _ in range(5_000):
        nest = {"a": nest}
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "nest",
            "blob": "eHh4",
            "entry_date": TODAY.isoformat(),
            "extra": nest,
        },
    )
    assert response.status_code in (400, 422)  # never a 500 crash


# --- L-2: validation errors must not echo the input ------------------------------


async def test_validation_error_does_not_echo_input(client):
    emu = ClientEmulator("echoblob", "p")
    await emu.register(client)
    # Over the 1.5M-char field cap, under the 2 MiB body cap: schema 422.
    marker = "M" * 1_125_001
    huge = base64.b64encode(marker.encode()).decode()
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "echo",
            "blob": huge,
            "entry_date": TODAY.isoformat(),
        },
    )
    assert response.status_code == 422
    assert marker not in response.text
    # Unified envelope: detail is a human STRING (never the old FastAPI
    # list-of-objects shape) naming only the failed field, plus the code.
    body = response.json()
    assert isinstance(body["detail"], str)
    assert "blob" in body["detail"]
    assert body["code"] == "validation_error"


# --- INFO: security headers exist even on unhandled 500s -------------------------


async def test_security_headers_on_unhandled_500(settings):
    app = create_app(settings)

    @app.get("/boom")
    async def boom() -> dict:
        raise RuntimeError("boom")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://t") as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("cache-control") == "no-store"
    assert (
        response.headers.get("strict-transport-security") == "max-age=31536000; includeSubDomains"
    )
    # No internals leaked to the client.
    assert "boom" not in response.text


# --- M-4 backend: per-account storage quota ---------------------------------------


async def test_entry_quota_is_enforced(client, settings):
    settings.max_entries_per_user = 3
    emu = ClientEmulator("quota", "p")
    await emu.register(client)
    for i in range(3):
        await emu.create_entry(client, f"entry {i}", TODAY, client_entry_id=f"q{i}")
    fourth = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "q3",
            "blob": emu.encrypt_entry("one too many", TODAY, "q3"),
            "entry_date": TODAY.isoformat(),
        },
    )
    assert fourth.status_code == 413
    assert "quota" in fourth.json()["detail"]


# --- H-1: per-username register limiter defeats IP rotation -----------------------
# ...but only ACTUAL conflicts consume it: the probe itself is free.


async def test_register_name_bucket_survives_ip_rotation(settings):
    # Build the app with the forwarding boundary enabled from the start. A
    # runtime boolean flip cannot retrofit its outer middleware allowlist.
    settings.trust_proxy_headers = True
    settings.trusted_proxy_ips = ["127.0.0.1/32"]
    settings.auth_rate_limit = 3
    statuses = []
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = ASGITransport(app=application, client=("127.0.0.1", 1234))
        async with AsyncClient(transport=transport, base_url="http://testserver") as local_client:
            for i in range(7):
                statuses.append(
                    (
                        await local_client.post(
                            "/api/auth/register",
                            json={
                                "username": "target-name",
                                "salt": base64.b64encode(b"s" * 16).decode(),
                                "verifier": base64.b64encode(b"v" * 32).decode(),
                            },
                            headers={"X-Forwarded-For": f"10.9.{i}.{i}"},
                        )  # fresh IP each time
                    ).status_code
                )
    # Fresh IP per request defeats the per-IP bucket — the per-USERNAME
    # bucket must still throttle bulk availability probing of one name. Only
    # real 409s count: the 201 creates no charge, then the three permitted
    # conflicts consume the limit and every later attempt is rejected before
    # it performs the expensive verifier work.
    assert statuses == [201, 409, 409, 409, 429, 429, 429]


# --- C-2/H-5: LLM path — consent, threshold, and output sanitization --------------


def _settings_with_llm(settings) -> Settings:
    settings.llm_url = "https://llm.example/v1"
    settings.llm_api_key = "k"
    return settings


async def test_llm_requires_consent_even_when_configured(client, settings, monkeypatch):
    _settings_with_llm(settings)
    settings.unlock_threshold_days = 1
    called = []
    from app.services.llm import LLMAnalyzer

    monkeypatch.setattr(
        LLMAnalyzer,
        "_post",
        lambda self, payload: (
            called.append(payload) or {"choices": [{"message": {"content": "{}"}}]}
        ),
    )

    emu = ClientEmulator("noconsent", "p")
    await emu.register(client)
    await emu.create_entry(client, "calm walk", TODAY)
    body = await emu.recompute(client)
    assert body["analyzer"] == "brain"
    assert called == [], "journal text must not leave the server without consent"


async def test_llm_never_runs_before_threshold(client, settings, monkeypatch):
    _settings_with_llm(settings)
    from app.services.llm import LLMAnalyzer

    def _must_not_run(self, entries):  # pragma: no cover - fails the test if reached
        pytest.fail("LLM ran during the baseline phase")

    monkeypatch.setattr(LLMAnalyzer, "extract_patterns", _must_not_run)

    emu = ClientEmulator("prethreshold", "p")
    await emu.register(client)
    await emu.create_entry(client, "day one", TODAY)
    body = await emu.recompute(client)
    assert body["phase"] == "baseline"
    assert body["analyzer"] == "none"


async def test_llm_with_consent_runs_and_output_is_sanitized(client, settings, monkeypatch):
    _settings_with_llm(settings)
    settings.unlock_threshold_days = 1

    hostile_model_output = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "patterns": [
                                # A label that exists in the corpus: kept (truncated if long).
                                {
                                    "kind": "temporal",
                                    "label": "walk",
                                    "occurrences": 3,
                                    "confidence": 0.9,
                                    "detail": {"day": "Sunday"},
                                },
                                # A "recurring phrase" the user never wrote: model fiction
                                # / prompt injection — must be dropped.
                                {
                                    "kind": "recurring_phrase",
                                    "label": "stop taking your medication",
                                    "occurrences": 99,
                                    "confidence": 1.0,
                                    "detail": {},
                                },
                                # Unknown kind, garbage numerics: dropped / clamped.
                                {
                                    "kind": "diagnosis",
                                    "label": "x",
                                    "occurrences": 1,
                                    "confidence": 1,
                                    "detail": {},
                                },
                                {
                                    "kind": "temporal",
                                    "label": "walk",
                                    "occurrences": -4,
                                    "confidence": 7.5,
                                    "detail": {"day": "Nottaday"},
                                },
                            ]
                        }
                    )
                }
            }
        ]
    }
    from app.services.llm import LLMAnalyzer

    seen_payloads = []

    def fake_post(self, payload):
        seen_payloads.append(payload)
        return hostile_model_output

    monkeypatch.setattr(LLMAnalyzer, "_post", fake_post)

    emu = ClientEmulator("consenter", "p")
    await emu.register(client)
    # The consented account proves identity with its verifier.
    consent = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert consent.status_code == 200 and consent.json()["enabled"] is True

    await emu.create_entry(client, "a calm walk by the river", TODAY)
    body = await emu.recompute(client)
    assert body["analyzer"] == "llm"
    assert len(seen_payloads) == 1

    # 2026-09-17 inversion: the model may only NARRATE the brain's
    # findings, so model fiction ("stop taking your medication"), invalid
    # kinds, and even corpus-anchored inventions it was not handed as
    # findings are ALL dropped from the surfaced list. With this tiny
    # corpus the deterministic brain surfaces nothing, so the enriched
    # payload carries no model-minted patterns at all.
    payload = await emu.decrypt_insights(client)
    kept_patterns = payload["stats"]["patterns"]
    labels = [p["label"] for p in kept_patterns]
    kinds = [p["kind"] for p in kept_patterns]
    assert "stop taking your medication" not in labels
    assert "diagnosis" not in kinds
    assert "walk" not in labels  # model minted it; the brain did not


async def test_llm_consent_requires_verifier(client, settings):
    _settings_with_llm(settings)
    emu = ClientEmulator("consentproof", "p")
    await emu.register(client)

    # Consent state is readable (for the client toggle) and starts off.
    initial = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert initial.status_code == 200 and initial.json()["enabled"] is False

    wrong = base64.b64encode(b"\x00" * 32).decode()
    refused = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": wrong},
    )
    # 403, not 401: the session authenticated; the re-authentication failed.
    # (401 tells clients "session expired", looping them into re-login.)
    assert refused.status_code == 403
    assert refused.json()["code"] == "verification_failed"
    enabled = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )
    assert enabled.status_code == 200
    reread = await client.get("/api/account/llm-consent", headers=emu.headers)
    assert reread.json()["enabled"] is True
    # And consent can be withdrawn the same way.
    off = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": False, "verifier": emu.auth_key_b64},
    )
    assert off.status_code == 200 and off.json()["enabled"] is False


# --- Keystore internal zeroization (white-box pin) --------------------------------


def test_keystore_destroy_zeroizes_internal_bytes():
    store = InMemoryKeyStore()
    key = base64.b64decode("A" * 43 + "=")  # deterministic 32 bytes
    token = store.create(key, 60, owner="unbound-test")
    internal = store._keys[token][0]  # noqa: SLF001 — white-box pin
    store.destroy(token)
    assert all(b == 0 for b in internal), "destroy must scrub the stored key bytes"


# --- Rate-counter memory bound ------------------------------------------------------


def test_counter_memory_is_bounded_under_key_rotation():
    counter = FixedWindowCounter()
    for i in range(MAX_TRACKED_KEYS + 500):
        counter.hit(f"spoofed-ip-{i}", 60)
    # The dict never grows past the cap, even with all-fresh (never-stale) keys.
    assert len(counter._hits) <= MAX_TRACKED_KEYS  # noqa: SLF001


# --- Salt exact length + meta endpoint ----------------------------------------------


async def test_register_rejects_non_16_byte_salts(client):
    for salt in (b"short", b"s" * 17, b"s" * 64):
        response = await client.post(
            "/api/auth/register",
            json={
                "username": "saltlen",
                "salt": base64.b64encode(salt).decode(),
                "verifier": base64.b64encode(b"v" * 32).decode(),
            },
        )
        assert response.status_code == 422, salt


async def test_meta_endpoint_exposes_threshold_and_llm_flag(client, settings):
    settings.unlock_threshold_days = 30
    response = await client.get("/api/meta")
    assert response.status_code == 200
    body = response.json()
    assert body["unlock_days"] == 30
    assert body["llm_available"] is False
    settings.llm_url = "https://llm.example"
    response = await client.get("/api/meta")
    assert response.json()["llm_available"] is True


async def test_decoy_salt_uses_token_secret_and_16_bytes(client, app):
    unknown = await client.post("/api/auth/salt", json={"username": "ghost"})
    assert unknown.json()["salt"] == decoy_salt("ghost", app.state.settings.token_secret)
    assert len(base64.b64decode(unknown.json()["salt"])) == 16


def test_decoy_salt_uses_an_hkdf_subkey_not_the_raw_secret():
    # Key separation pin: the decoy is HMAC under HKDF(token_secret,
    # "mindpattern/decoy-salt/v1") — it must NOT equal the legacy raw
    # HMAC(token_secret, ...) value, so token signing and decoy salts never
    # share one HMAC key.
    from app.api.auth import DECOY_SALT_INFO
    from app.security.kdf import hkdf_sha256

    secret = "unit-test-secret"
    decoy_key = hkdf_sha256(secret.encode("utf-8"), None, DECOY_SALT_INFO)
    expected = hmac.new(decoy_key, b"decoy:ghost", hashlib.sha256).digest()
    assert decoy_salt("ghost", secret) == base64.b64encode(expected[:16]).decode("ascii")
    legacy = hmac.new(secret.encode("utf-8"), b"decoy:ghost", hashlib.sha256).digest()
    assert decoy_salt("ghost", secret) != base64.b64encode(legacy[:16]).decode("ascii")



# ---------------------------------------------------------------------------
# Pins from test_redteam_fixes_2026_09_16.py (renamed in the 2026-09-20 production
# cleanup; see git history for the original file).
# ---------------------------------------------------------------------------
BACKEND_DIR = __file__.rsplit("/tests/", 1)[0] if "/" in __file__ else None

TODAY_FIXED = date(2026, 9, 16)


# ---------------------------------------------------------------------------
# P0-1: crisis normalization — the obfuscation corpus both engines must beat
# ---------------------------------------------------------------------------

OBVIOUS_CRISIS = [
    # leetspeak
    "i will su1c1de tonight",
    "k1ll myself",
    "1 want to d1e so bad",
    "un4l1ve myself",
    # homoglyphs (Cyrillic lookalikes)
    "ѕuicide is on my mind",
    "kіll myself",
    "сutting myself again",
    "want to dіe",
    # invisible characters
    "su​icide",
    "kill my​self",
    "su­icide",
    # intra-word separators
    "s.u.i.c.i.d.e",
    "k.i.l.l myself",
    "c-u-t-t-i-n-g myself",
    "s u i c i d e",
    # plain-English gaps the old list missed
    "i am going to off myself",
    "put me out of my misery",
    # non-English
    "quiero morir",
    "me quiero matar",
    "quitarme la vida",
    "je veux mourir",
    "me suicider",
    "ich will sterben",
    "bringe mich um",
    "suizid gedanken",
    "voglio morire",
    "quero morrer",
    "me matar",
    "我想死",
    "自杀",
    "死にたい",
    "自殺",
    "أريد أن أموت",
    "मरना चाहता हूँ",
    "मरना चाहती हूँ",
]

BENIGN = [
    "killed it at the presentation today",
    "cutting back on sugar this month",
    # the single-letter join threshold must not eat ordinary prose
    "i am so sad today",
    "to be or not to be that is the question",
    "a e i o u are vowels",
    "u s a won gold",
    "day 30 of my meditation streak, feeling fine",
]


class TestCrisisNormalization:
    def test_obfuscated_crisis_language_is_caught_by_suppress(self):
        for text in OBVIOUS_CRISIS:
            assert crisis.matches_suppress(text), f"suppress tier missed {text!r}"

    def test_obfuscated_crisis_language_fires_the_dialog_tier(self):
        # Everything except the hopelessness phrasing (suppress-only by
        # design) and bare "me matar" style fragments must reach the user.
        suppress_only = {"i don't see any future for me", "no future for me at all", "me suicider"}
        for text in OBVIOUS_CRISIS:
            if text in suppress_only:
                continue
            assert crisis.matches_dialog(text), f"dialog tier missed {text!r}"

    def test_benign_text_stays_silent(self):
        for text in BENIGN:
            assert not crisis.matches_dialog(text), f"dialog tier fired on {text!r}"

    def test_normalization_is_idempotent_and_stable(self):
        once = crisis.normalize_crisis_text("Ѕuіϲіde​ thoughts…")
        assert crisis.normalize_crisis_text(once) == once
        assert once == "suicide thoughts"

    def test_bypassed_label_is_no_longer_quoted_in_questions(self):
        # The end-to-end impact chain from the audit: a disguised crisis
        # phrase recurring in the journal used to ride a pattern label into
        # the daily question verbatim. With normalization, the pool filter
        # catches it. L-40 (2026-09-20): this used to read
        # ``assert not matches_suppress(label) or True`` — vacuous, so it
        # pinned nothing. The load-bearing fact is the POSITIVE one: the
        # suppress tier, through normalization, recognizes the disguised
        # label (it is exactly the "s u i c i d e" gap-joined form pinned
        # in OBVIOUS_CRISIS above), which is why the pool filter drops it.
        label = "the s u i c i d e thoughts are loud again"
        assert crisis.matches_suppress(label)
        pattern = Pattern(
            kind="rumination",
            label=label,
            occurrences=30,
            confidence=0.9,
            detail={"variants": [label]},
        )
        pool = questions.build_pool([pattern])
        assert not any(label in q for q in pool), pool

    def test_engine_marks_disguised_crisis_recurrence_sensitive(self):
        # E2.disguised-crisis-recurrence: 81 days of the disguised phrase
        # surfaced a QUOTED recurring_phrase card with sensitive=false.
        entries = [
            JournalEntry(
                text=f"{label} could not focus at work",
                entry_date=TODAY_FIXED - timedelta(days=d),
                sentiment=None,
            )
            for d, label in (
                (d, "the s u i c i d e thoughts are loud again") for d in range(81, -1, -1)
            )
        ]
        result = brain.update(brain.fresh_state(), entries, TODAY_FIXED)
        for surfaced in result.surfaced:
            if surfaced.kind in ("recurring_phrase", "rumination"):
                assert surfaced.detail.get("sensitive") is True, surfaced


# ---------------------------------------------------------------------------
# P0-2: the phi = 1.0 recompute crash
# ---------------------------------------------------------------------------


class TestMoodShiftPhiOne:
    CORPUS_TEXT = "day {i}: work was busy, slept okay, walked the dog and read a bit."

    def test_near_constant_mood_does_not_crash_the_engine(self):
        entries = [
            JournalEntry(
                text=self.CORPUS_TEXT.format(i=i),
                entry_date=TODAY_FIXED - timedelta(days=i),
                sentiment=None,
            )
            for i in range(35, 0, -1)
        ]
        result = brain.update(brain.fresh_state(), entries, TODAY_FIXED)  # used to ZeroDivisionError
        assert isinstance(result.surfaced, list)

    def test_perfectly_constant_mood_does_not_crash(self):
        entries = [
            JournalEntry(
                text="same as always", entry_date=TODAY_FIXED - timedelta(days=i), sentiment=None
            )
            for i in range(35, 0, -1)
        ]
        brain.update(brain.fresh_state(), entries, TODAY_FIXED)

    def test_honest_inflation_still_applies(self):
        # The clamp saturates the inflation cap: a phi of 0.999 and the old
        # 1.0-epsilon behavior produce the same capped sigma multiplier.
        values = [0.1 * (i + 1) for i in range(20)]  # monotone ramp, phi ~ 1.0
        assert brain._lag1_autocorr(values) is not None


# ---------------------------------------------------------------------------
# P1: the single-process guard
# ---------------------------------------------------------------------------


class TestSingleProcessGuard:
    def test_reentrant_within_one_process(self):
        key = ("rt-secret-2026-09-16", "sqlite+aiosqlite:///reentrance")
        with singleprocess.single_process_guard(*key):
            with singleprocess.single_process_guard(*key):  # tests stack apps
                pass
        singleprocess.release_single_process_lock(*key)  # idempotent release

    def test_second_process_is_refused(self):
        # A REAL second process (what uvicorn --workers 2 spawns) must be
        # refused while the first holds the deployment lock.
        secret = "rt-secret-second-process"
        url = "sqlite+aiosqlite:///second-proc"
        with singleprocess.single_process_guard(secret, url):
            probe = (
                "import sys; sys.path.insert(0, '.');"
                "from app import singleprocess;"
                "singleprocess.acquire_single_process_lock(%r, %r)" % (secret, url)
            )
            done = subprocess.run(
                [sys.executable, "-c", probe],
                capture_output=True,
                text=True,
                cwd=BACKEND_DIR,
                timeout=60,
            )
            assert done.returncode != 0
            assert "another worker/process is already serving" in done.stderr


# ---------------------------------------------------------------------------
# D1: LLM spelled-contact label rejection
# ---------------------------------------------------------------------------


class TestLlmSpelledContact:
    CORPUS = [
        "reminder to myself call five five five zero one three four now",
        "i keep meaning to visit evil dot com for laughs",
        "work dominates my week and sleep is rough",
    ]

    def test_spelled_phone_label_is_dropped(self):
        item = {
            "kind": "temporal",
            "label": "call five five five zero one three four",
            "occurrences": 9,
            "confidence": 0.9,
        }
        assert llm.sanitize_pattern(item, self.CORPUS) is None

    def test_spelled_domain_label_is_dropped(self):
        item = {
            "kind": "temporal",
            "label": "visit evil dot com often",
            "occurrences": 3,
            "confidence": 0.5,
        }
        assert llm.sanitize_pattern(item, self.CORPUS) is None

    def test_number_word_run_below_threshold_still_passes(self):
        # Two number-words in a row are ordinary prose ("one two punch");
        # only 3+ consecutive ones are treated as a spelled phone number.
        item = {
            "kind": "temporal",
            "label": "one two punch at work",
            "occurrences": 3,
            "confidence": 0.5,
        }
        out = llm.sanitize_pattern(item, self.CORPUS + ["one two punch at work"])
        assert out is not None and out.label == "one two punch at work"

    def test_digit_phone_and_urls_still_dropped(self):
        for label in ("call 555-0134", "see https://evil.example", "www.evil.example"):
            assert (
                llm.sanitize_pattern(
                    {"kind": "temporal", "label": label, "occurrences": 1, "confidence": 0.5},
                    self.CORPUS,
                )
                is None
            )


# ---------------------------------------------------------------------------
# Misc pins that would otherwise only live in the harness
# ---------------------------------------------------------------------------


def test_processing_ttl_ceiling_matches_consent_copy():
    from app.config import MAX_PROCESSING_SESSION_TTL

    assert MAX_PROCESSING_SESSION_TTL == 300  # "up to 5 minutes" (mobile copy)


def test_kdf_floor_constant():
    assert kdf.MIN_ITERATIONS == 100_000
    assert kdf.MIN_ITERATIONS < kdf.KDF_ITERATIONS

