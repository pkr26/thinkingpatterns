"""Recompute contracts over real AEAD envelopes and independent SQLite sessions."""

from __future__ import annotations

import base64
import json
from contextlib import asynccontextmanager
from datetime import timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import delete, select, update

from app.api import insights
from app.db import build_sessionmaker
from app.deps import ApiError
from app.locks import UserLocks
from app.models import Consent, Entry, Insight, User
from app.security import crypto, sharing
from app.security.enclave import InMemoryKeyStore, KeyNotFound
from app.security.entry_guard import seal_entry_guard, validate_entry_guard
from app.services import brain, questions
from app.services.patterns import Pattern
from tests.test_full_backend_collection_mutation import (
    NOW,
    OTHER,
    OWNER,
    account,
    collection_db,  # noqa: F401
    envelope,
)

# Fixture imports are requested explicitly as parameters.
# ruff: noqa: F811
KEY = bytes(range(32))


class RecordingStore(InMemoryKeyStore):
    popped = None

    def pop(self, *args, **kwargs):
        self.popped = super().pop(*args, **kwargs)
        return self.popped


@pytest_asyncio.fixture
async def recompute_db(collection_db, monkeypatch):
    db = collection_db
    db.settings.unlock_threshold_days = 3
    db.request.app.state.sessionmaker = build_sessionmaker(db.engine)
    db.request.app.state.key_store = RecordingStore()
    db.factory = db.request.app.state.sessionmaker
    db.key_store = db.request.app.state.key_store
    db.clock = NOW.date()
    db.calls = []
    db.cards = [
        Pattern(
            "temporal",
            "work",
            12,
            0.875,
            {"day": "Monday", "pattern_pid": "work-pid", "is_new": True, "last_seen": "2026-10-03"},
        ),
        Pattern(
            "rumination",
            "same thought",
            9,
            0.8,
            {
                "pattern_pid": "thought-pid",
                "sensitive": True,
                "pattern_state": "fading",
                "last_seen": "2026-10-04",
            },
        ),
        Pattern(
            "topic",
            "family",
            8,
            0.7,
            {"pattern_pid": "family-pid", "pattern_state": "active", "trend": "steady"},
        ),
    ]
    db.stats = {"language": "es", "days": 3, "custom": "retained"}
    monkeypatch.setattr(insights, "_utc_today", lambda: db.clock)
    monkeypatch.setattr(insights, "utcnow", lambda: NOW)
    monkeypatch.setattr(insights, "lifecycle_locks", UserLocks())
    monkeypatch.setattr(insights, "_recompute_locks", UserLocks())

    def analyze(state, entries, today, **events):
        db.calls.append((state, entries, today, events))
        new_state = {**state, "history": [[today.isoformat(), ["processed"]]]}
        return SimpleNamespace(new_state=new_state, surfaced=db.cards, stats=db.stats)

    monkeypatch.setattr(brain, "update", analyze)
    rows = []
    for i in range(3):
        day = NOW.date() - timedelta(days=2 - i)
        row = Entry(
            id=f"{i + 1:032x}",
            user_id=OWNER,
            client_entry_id=f"journal-{i}",
            entry_date=day,
            received_at=NOW,
            content_version=1,
        )
        payload = {"text": f"entry {i}", "created_at": day.isoformat(), "sentiment": i / 4}
        row.blob = crypto.encrypt(
            KEY, json.dumps(payload).encode(), crypto.entry_aad_v2(OWNER, row.client_entry_id, 1)
        )
        # Legacy bootstrap seal: successful v2 observation must make it sticky.
        seal_entry_guard(row, db.settings, v2_bound=False)
        rows.append(row)
    db.session.add_all(rows)
    await db.session.commit()
    db.rows = rows
    yield db


def token(db):
    return db.key_store.create(KEY, 60, owner=OWNER)


async def call(db, feedback=None):
    return await insights.recompute(db.request, db.owner, token(db), feedback)


async def stored(db):
    async with db.factory() as session:
        return list((await session.scalars(select(Insight).where(Insight.user_id == OWNER))).all())


def decrypt(row):
    aad = (
        crypto.build_aad("question", OWNER, row.for_date.isoformat())
        if row.kind == "question"
        else crypto.build_aad("insights", OWNER, row.kind)
    )
    return json.loads(crypto.decrypt(KEY, bytes(row.blob), aad))


async def prior(db, corrupt=False):
    state = brain.fresh_state()
    state["muted"] = {"remembered-pid": True}
    blob = crypto.encrypt(
        KEY, brain.dump_state(state), crypto.build_aad("insights", OWNER, "brain")
    )
    if corrupt:
        blob = blob[:-1] + bytes([blob[-1] ^ 1])
    db.session.add(
        Insight(
            id="c" * 32,
            user_id=OWNER,
            kind="brain",
            for_date=None,
            blob=blob,
            state_seq=7,
            created_at=NOW,
        )
    )
    await db.session.commit()
    return state


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "has_state,feedback_day", [(True, 0), (True, 1), (False, 0), (False, None)]
)
async def test_recompute_separates_real_entry_state_and_feedback_plaintexts(
    recompute_db, has_state, feedback_day
):
    db = recompute_db
    expected = await prior(db) if has_state else brain.fresh_state()
    events = {
        "feedback": [{"pid": "work-pid", "resonated": False}],
        "muted": ["muted-pid"],
        "unmuted": ["remembered-pid"],
        "v": brain.STATE_VERSION,
        "history": [["2000-01-01", ["hostile brain-memory injection"]]],
        "patterns": {},
    }
    fb = None
    if feedback_day is not None:
        fb = base64.b64encode(
            crypto.encrypt(
                KEY,
                json.dumps(events).encode(),
                crypto.build_aad(
                    "feedback", OWNER, (NOW.date() - timedelta(days=feedback_day)).isoformat()
                ),
            )
        ).decode()
    response = await call(db, fb)
    assert response.model_dump() == dict(
        phase="insight",
        active_days=3,
        streak=3,
        days_remaining=0,
        patterns_stored=3,
        question_stored=True,
        analyzer="brain",
        patterns_new=1,
        patterns_fading=1,
        state_seq=8 if has_state else 1,
    )
    assert len(db.calls) == 1
    state, entries, today, received = db.calls[0]
    assert state == expected
    assert [(e.text, e.entry_date, e.sentiment) for e in entries] == [
        (f"entry {i}", NOW.date() - timedelta(days=2 - i), i / 4) for i in range(3)
    ]
    assert today == NOW.date()
    assert received == (
        dict(feedback=[("work-pid", False)], muted=["muted-pid"], unmuted=["remembered-pid"])
        if fb
        else dict(feedback=None, muted=None, unmuted=None)
    )
    by_kind = {row.kind: row for row in await stored(db)}
    assert set(by_kind) == {"brain", "patterns", "question"}
    assert decrypt(by_kind["patterns"]) == {
        "v": 2,
        "phase": "insight",
        "state_seq": response.state_seq,
        "stats": {**db.stats, "patterns": [p.to_dict() for p in db.cards]},
    }
    expected["history"] = [[today.isoformat(), ["processed"]]]
    assert decrypt(by_kind["brain"]) == json.loads(brain.dump_state(expected))
    assert {row.state_seq for row in by_kind.values()} == {response.state_seq}
    q = decrypt(by_kind["question"])
    assert q["for_date"] == today.isoformat()
    assert q["question"] == questions.question_for_today(OWNER, db.cards, today, language="es")
    assert set(q) == {"for_date", "question", "pattern_pid"}
    assert db.key_store.popped == bytearray(32)
    async with db.factory() as session:
        fresh = list((await session.scalars(select(Entry))).all())
        assert all(validate_entry_guard(r, db.settings) for r in fresh)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "feedback",
        "feedback-without-state",
        "entry-with-state",
        "state",
        "state-and-malformed-entry",
        "feedback-format",
    ],
)
async def test_recompute_crypto_retry_ladder_preserves_error_identity_and_amnesia(
    recompute_db, case
):
    db = recompute_db
    before = (
        await prior(db, corrupt=case in {"state", "state-and-malformed-entry"})
        if case != "feedback-without-state"
        else brain.fresh_state()
    )
    if case == "entry-with-state":
        db.rows[0].blob = crypto.encrypt(
            b"z" * 32, b"{}", crypto.entry_aad_v2(OWNER, db.rows[0].client_entry_id, 1)
        )
        seal_entry_guard(db.rows[0], db.settings, v2_bound=False)
    if case == "state-and-malformed-entry":
        db.rows[0].blob = crypto.encrypt(
            KEY, b"{invalid private text", crypto.entry_aad_v2(OWNER, db.rows[0].client_entry_id, 1)
        )
        seal_entry_guard(db.rows[0], db.settings, v2_bound=False)
    await db.session.commit()
    feedback = None
    if case in {"feedback", "feedback-without-state"}:
        feedback = base64.b64encode(
            crypto.encrypt(
                KEY,
                b'{"feedback":[]}',
                crypto.build_aad("feedback", OWNER, (NOW.date() - timedelta(days=2)).isoformat()),
            )
        ).decode()
    if case == "feedback-format":
        feedback = "not_base64"
    if case == "state":
        result = await call(db)
        assert result.state_seq == 8
        assert db.calls[0][0] == brain.fresh_state()
        assert len(db.calls[0][1]) == 3
    else:
        expected = {
            "feedback": (400, "feedback blob failed authentication", "feedback_blob_invalid"),
            "feedback-without-state": (
                400,
                "feedback blob failed authentication",
                "feedback_blob_invalid",
            ),
            "entry-with-state": (400, "entry blob failed authentication", "entry_blob_invalid"),
            "state-and-malformed-entry": (
                400,
                "entry payload malformed",
                "entry_payload_malformed",
            ),
            "feedback-format": (422, "feedback_blob must be base64", "validation_error"),
        }[case]
        with pytest.raises(ApiError) as failure:
            await call(db, feedback)
        envelope(failure, *expected)
        assert [(r.kind, r.state_seq) for r in await stored(db)] == (
            [] if case == "feedback-without-state" else [("brain", 7)]
        )
        if case in {"feedback", "feedback-without-state"}:
            assert db.calls[0][0] == before
    assert db.key_store.popped == bytearray(32)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "language,pin",
    [("es", False), ("en", False), ("other", False), (None, False), ("es", True), ("es", "empty")],
)
async def test_recompute_questions_use_detected_language_and_pin_only_this_account_today(
    recompute_db, language, pin
):
    db = recompute_db
    if language is None:
        db.stats.pop("language")
    else:
        db.stats["language"] = language
    db.session.add_all(
        [
            Insight(
                id=f"{i + 20:032x}",
                user_id=uid,
                kind=kind,
                for_date=day,
                blob=b"previous opaque",
                state_seq=3,
                created_at=NOW,
            )
            for i, (uid, kind, day) in enumerate(
                [
                    (OTHER, "question", NOW.date()),
                    (OWNER, "question", NOW.date() - timedelta(days=1)),
                    (OWNER, "patterns", NOW.date()),
                ]
            )
        ]
    )
    pinned = None
    if pin is True:
        pinned = Insight(
            id="d" * 32,
            user_id=OWNER,
            kind="question",
            for_date=NOW.date(),
            blob=b"same-day question",
            state_seq=4,
            created_at=NOW,
        )
        db.session.add(pinned)
    if pin == "empty":
        db.cards = []
    await db.session.commit()
    response = await call(db)
    rows = await stored(db)
    daily = [r for r in rows if r.kind == "question" and r.for_date == NOW.date()]
    assert response.question_stored is (pin != "empty")
    if pin is True:
        assert [(r.id, bytes(r.blob), r.state_seq) for r in daily] == [
            (pinned.id, b"same-day question", 4)
        ]
    elif pin == "empty":
        assert daily == []
    else:
        assert len(daily) == 1
        effective = "es" if language == "es" else "en"
        payload = decrypt(daily[0])
        assert payload["question"] == questions.question_for_today(
            OWNER, db.cards, NOW.date(), language=effective
        )
        assert payload["for_date"] == NOW.date().isoformat()
        assert isinstance(payload["question"], str)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["inactive", "epoch", "missing", "baseline"])
async def test_recompute_reauthorizes_inside_lifecycle_fence(recompute_db, monkeypatch, change):
    db = recompute_db
    locks = UserLocks()
    names = []

    @asynccontextmanager
    async def hold(name):
        names.append(name)
        async with locks.hold(name):
            async with db.factory() as session:
                if change == "missing":
                    await session.execute(delete(Entry).where(Entry.user_id == OWNER))
                    await session.execute(delete(User).where(User.id == OWNER))
                elif change == "baseline":
                    await session.execute(delete(Entry).where(Entry.id != db.rows[0].id))
                else:
                    await session.execute(
                        update(User)
                        .where(User.id == OWNER)
                        .values(
                            **({"is_active": False} if change == "inactive" else {"token_epoch": 3})
                        )
                    )
                await session.commit()
            yield
            assert db.key_store.popped == bytearray(32)

    monkeypatch.setattr(insights, "lifecycle_locks", SimpleNamespace(hold=hold))
    if change == "baseline":
        response = await call(db)
        assert response.model_dump() == dict(
            phase="baseline",
            active_days=1,
            streak=0,
            days_remaining=2,
            patterns_stored=0,
            question_stored=False,
            analyzer="none",
            patterns_new=0,
            patterns_fading=0,
            state_seq=0,
        )
    else:
        with pytest.raises(ApiError) as failure:
            await call(db)
        envelope(
            failure,
            *(
                (401, "invalid token", "unauthorized")
                if change == "epoch"
                else (410, "account no longer exists", "account_deleted")
            ),
        )
    assert names == [f"llm-lifecycle:{OWNER}"]
    assert db.calls == []
    assert await stored(db) == []
    assert db.key_store.popped == bytearray(32)


@pytest.mark.asyncio
async def test_recompute_metrics_worker_limiter_and_lock_cleanup_cover_success_and_failed_acquire(
    recompute_db, monkeypatch
):
    db = recompute_db
    observations = []
    db.request.app.state.metrics = SimpleNamespace(observe_recompute=observations.append)
    import anyio

    limiter = anyio.CapacityLimiter(1)
    db.request.app.state.analyze_limiter = limiter
    run_sync = anyio.to_thread.run_sync
    workers = []

    async def threaded(fn, *args, limiter=None):
        workers.append(limiter)
        return await run_sync(fn, *args, limiter=limiter)

    monkeypatch.setattr(insights.anyio.to_thread, "run_sync", threaded)
    names, exits = [], []
    locks = UserLocks()

    @asynccontextmanager
    async def hold(name):
        names.append(name)
        async with locks.hold(name):
            try:
                yield
            finally:
                exits.append(name)
                if name.startswith("llm"):
                    assert db.key_store.popped == bytearray(32)

    monkeypatch.setattr(insights, "lifecycle_locks", SimpleNamespace(hold=hold))
    monkeypatch.setattr(insights, "_recompute_locks", SimpleNamespace(hold=hold))
    ticks = iter([10.0, 14.25])
    monkeypatch.setattr(insights, "time", SimpleNamespace(monotonic=lambda: next(ticks)))
    await call(db)
    assert observations == [4.25]
    assert workers == [limiter]
    assert names == [f"llm-lifecycle:{OWNER}", f"insights:{OWNER}"]
    assert exits == names[::-1]
    exit_failed = []

    class FailedAcquisition:
        async def __aenter__(self):
            raise RuntimeError("lock refused")

        async def __aexit__(self, *args):
            exit_failed.append(args)

    monkeypatch.setattr(
        insights, "lifecycle_locks", SimpleNamespace(hold=lambda name: FailedAcquisition())
    )
    ticks = iter([20.0, 22.0])
    with pytest.raises(RuntimeError, match="lock refused"):
        await call(db)
    assert observations == [4.25, 2.0]
    assert exit_failed == []
    assert db.key_store.popped == bytearray(32)


async def therapist(
    db, identifier, status="active", disclosure=None, public="valid", active=True, user_id=OWNER
):
    private = ec.generate_private_key(ec.SECP256R1())
    encoded = base64.b64encode(
        private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    user = account(
        identifier,
        role="therapist",
        is_active=active,
        wrap_pub_key=encoded if public == "valid" else public,
        patients_revision=9,
    )
    consent = Consent(
        id=identifier,
        user_id=user_id,
        therapist_id=identifier,
        status=status,
        disclosure=disclosure or insights.SHARING_DISCLOSURE_VERSION,
        granted_at=NOW,
    )
    db.session.add(user)
    await db.session.flush()
    db.session.add(consent)
    await db.session.commit()
    return private, consent


@pytest.mark.asyncio
async def test_recompute_therapist_summaries_are_real_ecies_json_with_permission_filtering(
    recompute_db,
):
    db = recompute_db
    valid = []
    for i, changes in enumerate(
        [
            {"public": ""},
            {"public": "invalid key"},
            {},
            {"status": "revoked"},
            {"disclosure": "legacy"},
            {"active": False},
            {"user_id": OTHER},
            {},
        ],
        30,
    ):
        private, consent = await therapist(db, f"{i:032x}", **changes)
        if not changes:
            valid.append((private, consent))
    response = await call(db)
    assert response.patterns_stored == 3
    async with db.factory() as session:
        consents = list((await session.scalars(select(Consent).order_by(Consent.id))).all())
        users = {r.id: r for r in (await session.scalars(select(User))).all()}
    expected_ids = {c.id for _, c in valid}
    assert {c.id for c in consents if c.summary_blob is not None} == expected_ids
    for private, original in valid:
        c = next(c for c in consents if c.id == original.id)
        plain = sharing.unwrap_summary_payload(
            private, c.summary_eph_pub, c.summary_blob, OWNER, c.therapist_id
        )
        assert (
            plain
            == b'{"v":1,"patterns":3,"sensitive":true,"newest":"2026-10-04","for_date":"2026-10-05"}'
        )
        assert json.loads(plain)["sensitive"] is True
        assert c.summary_updated_at == NOW
    assert {u.id for u in users.values() if u.patients_revision == 10} == expected_ids
    assert all(
        u.patients_revision == 9
        for uid, u in users.items()
        if uid not in {OWNER, OTHER} | expected_ids
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [100, 101, 102])
async def test_recompute_summary_cardinality_has_exact_inclusive_limit(recompute_db, count):
    db = recompute_db
    for i in range(count):
        identifier = f"{i + 200:032x}"
        db.session.add(account(identifier, role="therapist", wrap_pub_key="invalid"))
        await db.session.flush()
        db.session.add(
            Consent(
                id=identifier,
                user_id=OWNER,
                therapist_id=identifier,
                status="active",
                disclosure=insights.SHARING_DISCLOSURE_VERSION,
            )
        )
    await db.session.commit()
    if count == 100:
        assert (await call(db)).patterns_stored == 3
    else:
        with pytest.raises(ApiError) as failure:
            await call(db)
        envelope(
            failure, 413, "active sharing exceeds the supported summary size", "payload_too_large"
        )
        assert await stored(db) == []
    assert db.key_store.popped == bytearray(32)


@pytest.mark.asyncio
@pytest.mark.parametrize("race", ["revoked", "legacy", "inactive"])
async def test_recompute_summary_write_rechecks_changed_grant_and_therapist(
    recompute_db, monkeypatch, race
):
    db = recompute_db
    private, original = await therapist(db, "e" * 32)
    real = sharing.wrap_summary_payload
    changed = False
    original_factory = db.factory

    @asynccontextmanager
    async def factory():
        nonlocal changed
        if changed:
            async with original_factory() as session:
                if race == "inactive":
                    await session.execute(
                        update(User).where(User.id == original.therapist_id).values(is_active=False)
                    )
                else:
                    await session.execute(
                        update(Consent)
                        .where(Consent.id == original.id)
                        .values(
                            **(
                                {"status": "revoked"}
                                if race == "revoked"
                                else {"disclosure": "legacy"}
                            )
                        )
                    )
                await session.commit()
            changed = False
        async with original_factory() as session:
            yield session

    def wrap(*args):
        nonlocal changed
        answer = real(*args)
        changed = True
        return answer

    monkeypatch.setattr(sharing, "wrap_summary_payload", wrap)
    db.request.app.state.sessionmaker = factory
    await call(db)
    async with original_factory() as session:
        consent = await session.get(Consent, original.id)
        user = await session.get(User, original.therapist_id)
        assert consent.summary_blob is None
        assert user.patients_revision == 9


@pytest.mark.parametrize("language", ["en", "es"])
def test_chosen_pattern_owner_matches_real_deduplicated_language_rotation(language):
    day = NOW.date()
    patterns = [
        Pattern("rumination", "A calm thought", 8, 0.9, {"pattern_pid": "owner"}),
        Pattern("rumination", "A calm thought", 7, 0.8, {"pattern_pid": "duplicate"}),
        Pattern("temporal", "work", 12, 0.8, {"pattern_pid": "work", "day": "Monday"}),
        Pattern(
            "temporal",
            "private topic",
            100,
            0.9,
            {"sensitive": True, "pattern_pid": "excluded-sensitive", "day": "Tuesday"},
        ),
        Pattern(
            "rumination", "Muted thought", 99, 0.9, {"muted": True, "pattern_pid": "excluded-muted"}
        ),
    ]
    owners = {}
    for p in sorted(
        [
            p
            for p in patterns
            if not questions.pattern_is_sensitive(p) and not questions.pattern_is_muted(p)
        ],
        key=questions.feedback_rank,
    ):
        for text in questions.render_pattern_questions(p, language):
            owners.setdefault(text, p.detail["pattern_pid"])
    pool = questions.build_pool(patterns, language=language)
    boundary_indices = {0, 2, 3, 5, 6, len(pool) - 1}
    accounts = {}
    for i in range(10000):
        uid = f"owner-routing-{i}"
        index = (day.toordinal() + questions.user_rotation_offset(uid)) % len(pool)
        if index in boundary_indices:
            accounts.setdefault(index, uid)
        if set(accounts) == boundary_indices:
            break
    assert set(accounts) == boundary_indices
    observed = set()
    for uid in accounts.values():
        selected = questions.question_for_today(uid, patterns, day, language=language)
        expected = owners.get(selected)
        if language == "en":
            actual = insights._chosen_pattern_pid(day, patterns, uid)
        else:
            actual = insights._chosen_pattern_pid(day, patterns, uid, language=language)
        assert actual == expected
        observed.add(actual)
    assert observed == {"owner", "work", None}
    assert insights._chosen_pattern_pid(day, [], OWNER, language=language) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mode",
    [
        "empty",
        "baseline",
        "missing-token",
        "foreign-token",
        "expired-token",
        "blob-budget",
        "guard-tamper",
        "entry-tamper",
        "entry-json",
    ],
)
async def test_recompute_public_gates_and_exact_error_envelopes(recompute_db, mode):
    db = recompute_db
    given = token(db)
    if mode == "empty":
        await db.session.execute(delete(Entry))
    elif mode == "baseline":
        db.settings.unlock_threshold_days = 10
    elif mode == "missing-token":
        given = None
    elif mode == "foreign-token":
        given = db.key_store.create(KEY, 60, owner=OTHER)
    elif mode == "expired-token":
        given = db.key_store.create(KEY, 60, now=0, owner=OWNER)
    elif mode == "blob-budget":
        db.settings.analysis_blob_budget = 1
    elif mode == "guard-tamper":
        db.rows[0].aad_guard_mac = "0" * 64
    elif mode == "entry-tamper":
        db.rows[0].blob = crypto.encrypt(
            b"z" * 32, b"{}", crypto.entry_aad_v2(OWNER, db.rows[0].client_entry_id, 1)
        )
        seal_entry_guard(db.rows[0], db.settings, v2_bound=False)
    elif mode == "entry-json":
        db.rows[0].blob = crypto.encrypt(
            KEY,
            b"{private malformed text",
            crypto.entry_aad_v2(OWNER, db.rows[0].client_entry_id, 1),
        )
        seal_entry_guard(db.rows[0], db.settings, v2_bound=False)
    await db.session.commit()
    if mode == "baseline":
        foreign = db.key_store.create(KEY, 60, owner=OTHER)
        response = await insights.recompute(db.request, db.owner, given, None)
        assert response.model_dump() == dict(
            phase="baseline",
            active_days=3,
            streak=3,
            days_remaining=7,
            patterns_stored=0,
            question_stored=False,
            analyzer="none",
            patterns_new=0,
            patterns_fading=0,
            state_seq=0,
        )
        with pytest.raises(KeyNotFound):
            db.key_store.get(given, owner=OWNER)
        assert db.key_store.get(foreign, owner=OTHER) == bytearray(KEY)
    else:
        wanted = {
            "empty": (400, "no entries to analyze", "bad_request"),
            "missing-token": (
                401,
                "missing processing session token",
                "processing_session_required",
            ),
            "foreign-token": (
                403,
                "processing session missing or expired",
                "processing_session_invalid",
            ),
            "expired-token": (
                403,
                "processing session missing or expired",
                "processing_session_invalid",
            ),
            "blob-budget": (
                413,
                "analysis blob budget is smaller than the newest entry; refusing to analyze an empty corpus",
                "payload_too_large",
            ),
            "guard-tamper": (400, "entry blob failed authentication", "entry_blob_invalid"),
            "entry-tamper": (400, "entry blob failed authentication", "entry_blob_invalid"),
            "entry-json": (400, "entry payload malformed", "entry_payload_malformed"),
        }[mode]
        with pytest.raises(ApiError) as failure:
            await insights.recompute(db.request, db.owner, given, None)
        envelope(failure, *wanted)
        if mode == "foreign-token":
            assert db.key_store.get(given, owner=OTHER) == bytearray(KEY)
    assert db.calls == []
    assert await stored(db) == []
    if db.key_store.popped is not None:
        assert db.key_store.popped == bytearray(32)


@pytest.mark.asyncio
async def test_recompute_http_accepts_embedded_feedback_envelope(recompute_db):
    from fastapi import FastAPI
    from httpx import ASGITransport, AsyncClient

    from app.cache import SlidingWindowCounter

    db = recompute_db
    application = FastAPI()
    application.state = db.request.app.state
    application.state.rate_counter = SlidingWindowCounter()
    application.include_router(insights.router)

    async def owner():
        return db.owner

    application.dependency_overrides[insights.require_regular_user] = owner
    feedback = base64.b64encode(
        crypto.encrypt(
            KEY, b'{"feedback":[]}', crypto.build_aad("feedback", OWNER, NOW.date().isoformat())
        )
    ).decode()
    async with AsyncClient(
        transport=ASGITransport(app=application), base_url="http://test"
    ) as client:
        response = await client.post(
            "/insights/recompute",
            headers={"X-Processing-Token": token(db)},
            json={"feedback_blob": feedback},
        )
    assert response.status_code == 200, response.text
    assert response.json()["analyzer"] == "brain"
    assert len(db.calls) == 1
    assert db.calls[0][3] == dict(feedback=[], muted=[], unmuted=[])


@pytest.mark.asyncio
@pytest.mark.parametrize("foreign_key", [True, False])
async def test_recompute_write_failures_preserve_account_deletion_identity(
    recompute_db, monkeypatch, foreign_key
):
    from sqlalchemy.exc import IntegrityError

    db = recompute_db
    if foreign_key:
        # Legacy envelopes need no v2 promotion write before the insight
        # insert, letting a real concurrent deletion hit its FK boundary.
        for i, row in enumerate(db.rows):
            payload = {"text": f"entry {i}", "created_at": row.entry_date.isoformat()}
            row.blob = crypto.encrypt(
                KEY,
                json.dumps(payload).encode(),
                crypto.build_aad("entry", OWNER, row.client_entry_id),
            )
            seal_entry_guard(row, db.settings, v2_bound=False)
        await db.session.commit()
        factory = db.factory
        deleted = False

        @asynccontextmanager
        async def concurrent_deletion():
            nonlocal deleted
            if db.calls and not deleted:
                async with factory() as session:
                    await session.execute(delete(Entry).where(Entry.user_id == OWNER))
                    await session.execute(delete(User).where(User.id == OWNER))
                    await session.commit()
                deleted = True
            async with factory() as session:
                yield session

        db.request.app.state.sessionmaker = concurrent_deletion
        with pytest.raises(ApiError) as failure:
            await call(db)
        envelope(failure, 410, "account no longer exists", "account_deleted")
        assert deleted
    else:
        # A different database failure must keep its original identity.
        fault = IntegrityError("insert", None, RuntimeError("database unavailable"))

        async def fail(*args, **kwargs):
            raise fault

        monkeypatch.setattr(insights, "_replace_insight", fail)
        with pytest.raises(IntegrityError) as failure:
            await call(db)
        assert failure.value is fault
    assert db.key_store.popped == bytearray(32)
    assert await stored(db) == []
