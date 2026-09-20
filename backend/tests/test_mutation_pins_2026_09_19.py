"""Mutation pins, round 3 (2026-09-19 campaign).

Every test here pins one genuine survivor of the 2026-09-19 backend
infrastructure campaign (redteam/mutation_campaign_2026-09-19/, campaigns
O-T). Each was hand-verified: applying the exact campaign mutant makes the
pin fail; the clean tree passes.

The two unpinned genuine survivors are documented residuals in the campaign
report: O6 (note re-fetch therapist scoping — unreachable behind the
still-scoped pre-lock read) and S10 (recompute-lock keying — masked by the
outer per-user lifecycle fence).
"""

from __future__ import annotations

import asyncio
from datetime import date
from types import SimpleNamespace

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError

from app.cache import client_key
from app.locks import UserLocks
from app.security.enclave import InMemoryKeyStore, KeyStoreFull
from tests.helpers import ClientEmulator, TherapistEmulator, daterange

TODAY = date.today()


# --- O2: suspended account must be refused on routes without a fresh re-check


async def test_suspended_account_is_refused_on_insights_reads(client, app):
    """The /entries routes re-check is_active under their lifecycle fence;
    GET /insights has no such re-check — require_user itself must refuse a
    deactivated account there. (Kills mutant O2.)"""
    from sqlalchemy import update

    from app.models import User

    emu = ClientEmulator("pins-o2", "pw-pins-o2")
    await emu.register(client)
    await emu.create_entry(client, "an ordinary day", TODAY, client_entry_id="pins-o2-e1")

    async with app.state.sessionmaker() as session:
        await session.execute(update(User).where(User.id == emu.user_id).values(is_active=False))
        await session.commit()

    response = await client.get("/api/insights", headers=emu.headers)
    assert response.status_code == 401
    assert response.json()["code"] == "unauthorized"


# --- O10: therapist registration honors the enrollment-token gate


async def test_therapist_registration_requires_the_enrollment_token(client, settings):
    """When an enrollment token is configured, a wrong or absent
    X-Therapist-Enrollment-Token must answer a flat 404; the right one
    registers. (Kills mutant O10.)"""
    settings.therapist_sharing_enabled = True
    settings.therapist_enrollment_token = "t" * 32

    def payload(emu: TherapistEmulator) -> dict:
        return {
            "username": emu.username,
            "salt": emu.salt_b64,
            "verifier": emu.auth_key_b64,
            "display_name": emu.display_name,
            "wrap_pub_key": emu.wrap_pub_key,
            "wrap_key_blob": emu.wrap_key_blob_b64(),
        }

    wrong = TherapistEmulator("pins-o10-wrong", "pw")
    no_header = await client.post("/api/therapist/register", json=payload(wrong))
    assert no_header.status_code == 404
    assert no_header.json()["code"] == "not_found"

    bad_header = await client.post(
        "/api/therapist/register",
        json=payload(TherapistEmulator("pins-o10-bad", "pw")),
        headers={"X-Therapist-Enrollment-Token": "wrong-token-of-at-least-some-length"},
    )
    assert bad_header.status_code == 404

    right = TherapistEmulator("pins-o10-right", "pw")
    accepted = await client.post(
        "/api/therapist/register",
        json=payload(right),
        headers={"X-Therapist-Enrollment-Token": "t" * 32},
    )
    assert accepted.status_code == 201, accepted.text


# --- P5: paginated entry order must be fully deterministic


async def test_entry_page_ordering_carries_the_id_tiebreak(client, app):
    """The page METADATA query (the one that sizes rows with LENGTH and
    paginates) must order by (entry_date, received_at, id): without the id
    tiebreak, rows sharing date+receipt time can swap across pages. The
    later blob-fetch query keeps its own full ordering, so only the
    metadata query distinguishes the mutant. (Kills mutant P5.)"""
    emu = ClientEmulator("pins-p5", "pw-pins-p5")
    await emu.register(client)
    await emu.create_entry(client, "one", TODAY, client_entry_id="pins-p5-a")
    await emu.create_entry(client, "two", TODAY, client_entry_id="pins-p5-b")

    statements: list[str] = []

    @event.listens_for(app.state.engine.sync_engine, "before_cursor_execute")
    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(statement)

    response = await client.get("/api/entries", headers=emu.headers)
    assert response.status_code == 200

    lowered = [s.lower() for s in statements]
    metadata_queries = [
        q for q in lowered if "length(" in q and "from entries" in q and "order by" in q
    ]
    assert metadata_queries, statements
    for query in metadata_queries:
        ordering = query.split("order by", 1)[1]
        assert "entry_date" in ordering and "received_at" in ordering and "id" in ordering, query


# --- P6 (REPURPOSED 2026-09-20, audit H-12): a same-day recompute must
# NOT rewrite the stored question blob. The old pin asserted the opposite
# (fresh ciphertext on every same-day recompute) and the audit proved that
# behavior breaks "one question per day, stable within the day" — a
# recompute after an evening entry served a different question than the one
# the user may already have answered. The day's question is now pinned on
# first write; the pin asserts byte-identical stability.


async def test_same_day_recompute_preserves_the_question_blob(client):
    """Audit H-12: recompute with an extra pattern -> SAME question for the
    same day. The rotation pool changing underneath must never change an
    already-served (possibly already-answered) question."""
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator("pins-p6", "pw-pins-p6")
    await emu.register(client)
    await seed_corpus(client, emu, days=32)
    await emu.recompute(client)
    first = (await client.get("/api/questions/today", headers=emu.headers)).json()["blob"]
    assert first

    await emu.create_entry(
        client, "a late evening note about sleep", TODAY, client_entry_id="pins-p6-extra"
    )
    await emu.recompute(client)
    second = (await client.get("/api/questions/today", headers=emu.headers)).json()["blob"]

    assert second == first, "same-day recompute changed the pinned daily question"


# --- Q1: the legacy entry-page byte budget is exactly 2 MiB (independent of
#     the code under test — the existing test imported the constant, so the
#     mutant scaled the test along with the budget).


async def test_legacy_entry_page_budget_is_two_mebibytes(client, app):
    """2 x ~1.05 MiB entries exceed the 2 MiB legacy response budget: an
    unpaged request must 413. Constants here are independent literals by
    design. (Kills mutant Q1.)"""
    from app.models import Entry

    emu = ClientEmulator("pins-q1", "pw-pins-q1")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Entry(
                    user_id=emu.user_id,
                    client_entry_id=f"pins-q1-{index}",
                    blob=bytes([index + 1]) * 1_100_000,
                    entry_date=TODAY,
                )
                for index in range(2)
            ]
        )
        await session.commit()

    legacy = await client.get("/api/entries", headers=emu.headers, params={"limit": 25})
    assert legacy.status_code == 413
    assert legacy.json()["code"] == "payload_too_large"

    paged = await client.get(
        "/api/entries", headers=emu.headers, params={"limit": 25, "page_bytes": 2 * 1024 * 1024}
    )
    assert paged.status_code == 200
    assert len(paged.json()) == 1  # only ONE ~1.05 MiB entry fits per budgeted page


# --- Q9: the therapist caseload cap is enforced at grant time


async def test_grant_rejects_when_the_therapist_caseload_is_full(client, app):
    """100 existing consent rows (any status) cap the therapist's caseload;
    the 101st pair must 413 without burning the pairing code. The filler
    count is an independent literal: reading MAX_PATIENTS_PER_THERAPIST
    here would scale the pin with the mutant. (Kills mutant Q9.)"""
    from app.models import Consent, User, new_id

    therapist = TherapistEmulator("pins-q9-th", "pw")
    patient = ClientEmulator("pins-q9-pt", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)

    async with app.state.sessionmaker() as session:
        filler = [
            User(
                id=new_id(),
                username=f"pins-q9-filler-{index}",
                salt="s" * 24,
                verifier=b"v" * 64,
                scrypt_salt=b"k" * 16,
            )
            for index in range(100)
        ]
        session.add_all(filler)
        await session.flush()
        session.add_all(
            Consent(
                user_id=row.id,
                therapist_id=therapist.user_id,
                status="revoked",
            )
            for row in filler
        )
        await session.commit()

    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )
    assert result["status"] == 413
    assert result["body"]["code"] == "payload_too_large"


# --- R8: a losing concurrent same-pair grant answers the 409 contract


class _GrantRaceSession:
    """Proxy over a real session whose commit fails with a unique violation
    the moment the pairing-code claim UPDATE has run (the commit-time race
    the 409 mapping exists for)."""

    def __init__(self, inner, error: Exception):
        self._inner = inner
        self._error = error
        self._armed = False

    async def execute(self, statement, *args, **kwargs):
        if "update pairing_codes" in str(statement).lower():
            self._armed = True
        return await self._inner.execute(statement, *args, **kwargs)

    async def commit(self):
        if self._armed:
            raise self._error
        return await self._inner.commit()

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def __aenter__(self):
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)


async def test_concurrent_pair_grant_answers_conflict_not_500(client, app, monkeypatch):
    """The grant commit's IntegrityError must map to the retryable 409
    envelope, never leak as a 500. (Kills mutant R8.)"""
    patient = ClientEmulator("pins-r8", "pw-pins-r8")
    therapist = TherapistEmulator("pins-r8-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)

    original_factory = app.state.sessionmaker
    boom = IntegrityError(
        "INSERT INTO consents ...",
        {},
        RuntimeError("UNIQUE constraint failed: uq_consents_user_therapist"),
    )

    def factory():
        return _GrantRaceSession(original_factory(), boom)

    monkeypatch.setattr(app.state, "sessionmaker", factory)

    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )
    assert result["status"] == 409
    assert result["body"]["code"] == "conflict"


# --- R10: only unique violations are retried during pairing-code allocation


async def test_pairing_code_creation_only_retries_unique_violations():
    """A non-unique IntegrityError during code creation must propagate
    immediately, never be retried. Direct route call with fakes: the clean
    handler re-raises on the FIRST non-unique failure, while the
    retry-everything mutant grinds through all five attempts and answers its
    503 ApiError instead. (Kills mutant R10.)"""
    from app.api import therapist as therapist_api
    from app.deps import ApiError

    boom = IntegrityError(
        "INSERT INTO pairing_codes ...",
        {},
        RuntimeError("FOREIGN KEY constraint failed"),
    )

    class FakeSession:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        async def execute(self, statement, *args, **kwargs):
            return SimpleNamespace(rowcount=0)

        async def commit(self):
            raise boom

        async def rollback(self):
            return None

        def add(self, obj):
            return None

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=SimpleNamespace(token_secret="s" * 40, access_log_retention_days=730)
            )
        )
    )
    user = SimpleNamespace(id="therapist-r10")

    with pytest.raises(IntegrityError):
        await therapist_api.create_pairing_code(
            request=request,
            user=user,
            session=FakeSession(),  # type: ignore[arg-type]
        )

    # Positive control: a UNIQUE violation is retried (bounded), surfacing
    # as the 503 allocation error rather than a raw leak.
    unique_boom = IntegrityError(
        "INSERT INTO pairing_codes ...",
        {},
        RuntimeError("UNIQUE constraint failed: uq_pairing_codes_code_hash"),
    )

    class RetryingSession(FakeSession):
        async def commit(self):
            raise unique_boom

    with pytest.raises(ApiError) as info:
        await therapist_api.create_pairing_code(
            request=request,
            user=user,
            session=RetryingSession(),  # type: ignore[arg-type]
        )
    assert info.value.status_code == 503


# --- S3: the per-owner processing-session cap


def test_keystore_per_owner_session_cap():
    """Four live sessions per account; the fifth is refused without evicting
    anyone else's. (Kills mutant S3.)"""
    store = InMemoryKeyStore(max_sessions=64, max_sessions_per_owner=4)
    key = bytes(range(32))
    for _ in range(4):
        store.create(key, ttl_seconds=60, owner="user-a")
    with pytest.raises(KeyStoreFull, match="for account"):
        store.create(key, ttl_seconds=60, owner="user-a")
    # The cap is per owner: another account is unaffected.
    store.create(key, ttl_seconds=60, owner="user-b")


# --- C3 (round 1, re-pinned 2026-09-19): pop() consumes the token


def test_keystore_pop_is_single_use_by_mechanism():
    """A second pop of the same token must fail: pop() is an atomic consume
    under the store lock. Re-pinned by the round-3 campaign after the PR
    gate found the round-1 pin had rotted (no suite still exercised a
    double-pop)."""
    from app.security.enclave import KeyNotFound

    store = InMemoryKeyStore()
    key = bytes(range(32))
    token = store.create(key, ttl_seconds=60, owner="user-a")

    popped = store.pop(token, owner="user-a")
    assert bytes(popped) == key
    with pytest.raises(KeyNotFound):
        store.pop(token, owner="user-a")


# --- S5: a snapshot marker AHEAD of the server is still a conflict


async def test_ahead_of_server_snapshot_marker_also_conflicts(client):
    """expected_revision diverging in EITHER direction must 409: a client
    holding a marker from a future/rolled-back state must not receive a
    silently wrong page. (Kills mutant S5.)"""
    emu = ClientEmulator("pins-s5", "pw-pins-s5")
    await emu.register(client)
    await emu.create_entry(client, "day one", TODAY, client_entry_id="pins-s5-e1")

    current = await client.get("/api/entries", headers=emu.headers)
    assert current.status_code == 200
    revision = int(current.headers["X-Entries-Revision"])

    ahead = await client.get(
        "/api/entries", headers=emu.headers, params={"expected_revision": str(revision + 5)}
    )
    assert ahead.status_code == 409
    assert ahead.json()["code"] == "collection_changed"


# --- S6/S7: a threshold regression must stop serving the stored blob


async def _regressed_account(client, app, username: str) -> ClientEmulator:
    from tests.test_insights_api import seed_corpus

    emu = ClientEmulator(username, f"pw-{username}")
    await emu.register(client)
    await emu.backdate_account(client, days=40)
    ids_by_day = {}
    for day in daterange(32, TODAY):
        entry_id = f"{username}-{day.isoformat()}"
        ids_by_day[day] = entry_id
        await emu.create_entry(
            client, "a day with work and some sleep", day, client_entry_id=entry_id
        )
    await emu.recompute(client)
    blob = (await client.get("/api/insights", headers=emu.headers)).json()["blob"]
    assert blob is not None  # insight phase: the blob is legitimately served
    # Delete 3 days: 29 distinct active days — back below the threshold.
    for day in sorted(ids_by_day)[:3]:
        response = await client.delete(f"/api/entries/{ids_by_day[day]}", headers=emu.headers)
        assert response.status_code == 204
    return emu


async def test_insights_blob_not_served_after_threshold_regression(client, app):
    """Baseline reveals nothing — not even a blob stored while the account
    WAS in the insight phase. (Kills mutant S6.)"""
    emu = await _regressed_account(client, app, "pins-s6")

    summary = await client.get("/api/insights", headers=emu.headers)
    assert summary.status_code == 200
    body = summary.json()
    assert body["phase"] == "baseline"
    assert body["blob"] is None


async def test_therapist_insights_read_phase_gates_the_blob(client, app):
    """The therapist's view of a regressed account must match the patient's:
    no blob in baseline. (Kills mutant S7.)"""
    from tests.helpers import patient_wrap_for

    emu = await _regressed_account(client, app, "pins-s7")
    therapist = TherapistEmulator("pins-s7-th", "pw")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    wrap = patient_wrap_for(emu, therapist.wrap_pub_key, therapist.user_id or "")
    from app.api.consents import SHARING_DISCLOSURE_VERSION

    granted = await client.post(
        "/api/consents",
        headers={**emu.headers, "X-Account-Verifier": emu.auth_key_b64},
        json={"code": code, **wrap, "disclosure": SHARING_DISCLOSURE_VERSION},
    )
    assert granted.status_code == 201, granted.text

    response = await client.get(
        f"/api/therapist/patients/{emu.user_id}/insights", headers=therapist.headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["phase"] == "baseline"
    assert body["blob"] is None


# --- S10 (recompute-lock keying) is NOT pinned: the per-user recompute lock
# sits nested inside the per-user lifecycle fence the route takes first, so
# two recomputes for one account serialize at the OUTER lock today and the
# inner-lock mutant (S10) is API-unobservable. It guards a future refactor
# that drops the fence, not the current shape — see the campaign report.


# --- T6: a forwarded identity is only trusted for an allowlisted peer


class _FakeRequest:
    def __init__(self, state: dict, client_host: str):
        self.state = SimpleNamespace(**state)
        self.client = SimpleNamespace(host=client_host)


def test_forwarded_identity_requires_the_trusted_peer_decision():
    """trust_proxy_headers=True is NOT sufficient: the middleware's
    authenticated peer decision (state.mindpattern_trusted_proxy) gates the
    forwarded value. A direct client must stay keyed on its socket address
    even when it forges X-Forwarded-For. (Kills mutant T6.)"""
    forged = _FakeRequest(
        {"mindpattern_trusted_proxy": False, "mindpattern_forwarded_client": "2001:db8::9"},
        client_host="203.0.113.7",
    )
    assert client_key(forged, trust_proxy_headers=True) == "203.0.113.7"
    assert client_key(forged, trust_proxy_headers=False) == "203.0.113.7"

    authenticated = _FakeRequest(
        {"mindpattern_trusted_proxy": True, "mindpattern_forwarded_client": "2001:db8::9"},
        client_host="10.0.0.8",
    )
    assert client_key(authenticated, trust_proxy_headers=True) == "2001:db8::/64"


# --- T8: absent keys stay on the overflow lock until it drains


async def test_absent_keys_stay_on_the_overflow_lock_until_it_drains():
    """While the overflow lock is live, an absent key must JOIN it (even if a
    stale registry slot could be evicted): otherwise the same key can hold a
    fresh dedicated lock concurrently with its own earlier overflow-held
    section. (Kills mutant T8.)"""
    locks = UserLocks(max_keys=1)

    k1_acquired = asyncio.Event()
    k1_release = asyncio.Event()

    async def hold_k1():
        async with locks.hold("K1"):
            k1_acquired.set()
            await k1_release.wait()

    k1_task = asyncio.create_task(hold_k1())
    await k1_acquired.wait()

    overflow_started = asyncio.Event()
    observed = []

    async def hold_k2_first():
        async with locks.hold("K2"):  # registry full with live K1 -> overflow
            overflow_started.set()
            await asyncio.sleep(0.5)

    first = asyncio.create_task(hold_k2_first())
    await overflow_started.wait()
    k1_release.set()
    await k1_task  # K1's slot is now a STALE registry entry

    async def hold_k2_second():
        async with locks.hold("K2"):  # same key, overflow still live
            observed.append(first.done())

    second = asyncio.create_task(hold_k2_second())
    await asyncio.gather(first, second)

    assert observed == [True], "the same key ran concurrently with its overflow-held section"
