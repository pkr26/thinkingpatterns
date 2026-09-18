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
from datetime import date, datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.security import crypto, enclave
from app.services import brain, phrases, questions, statsig
from app.services.patterns import JournalEntry, Pattern
from tests.helpers import ClientEmulator, daterange

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
