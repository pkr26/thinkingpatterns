"""Focused regression coverage for API race and byte-paging fail-closed paths.

These tests deliberately exercise paths that a normal single-process request
rarely reaches: a worker changing a row between metadata and blob reads, a
deleted account winning a lifecycle race, and explicit response-size limits.
They use small fakes only where reproducing a second process would otherwise
make the test nondeterministic.
"""

from __future__ import annotations

import base64
import json
from datetime import date, datetime, timezone
from types import SimpleNamespace

import anyio
import pytest
from fastapi import Response
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app.deps import ApiError
from app.models import Entry, Insight, TherapistNote, User
from tests.helpers import ClientEmulator, TherapistEmulator, patient_wrap_for


async def _grant(client, patient: ClientEmulator, therapist: TherapistEmulator) -> dict:
    code = await therapist.create_pairing_code(client)
    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )
    assert result["status"] == 201, result
    return result["body"]


class _ScalarRows:
    def __init__(self, rows):
        self._rows = list(rows)

    def first(self):
        return self._rows[0] if self._rows else None

    def all(self):
        return list(self._rows)


class _Result:
    def __init__(self, *, rows=(), scalar_rows=()):
        self._rows = list(rows)
        self._scalar_rows = list(scalar_rows)

    def all(self):
        return list(self._rows)

    def scalars(self):
        return _ScalarRows(self._scalar_rows)


class _PageSession:
    """Tiny async-session double for deterministic streaming export races."""

    bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

    def __init__(self, results):
        self._results = list(results)
        self.expunged = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def execute(self, statement):
        assert self._results, "unexpected export query"
        return self._results.pop(0)

    def expunge(self, row):
        self.expunged.append(row)


class _PageFactory:
    def __init__(self, pages):
        self._pages = list(pages)

    def __call__(self):
        assert self._pages, "export opened more page sessions than expected"
        return self._pages.pop(0)


class _FreshExportSession:
    def __init__(self, fresh):
        self._fresh = fresh
        self.commits = 0

    async def execute(self, statement):
        return _Result(scalar_rows=[] if self._fresh is None else [self._fresh])

    async def commit(self):
        self.commits += 1


class _EntryPagingRaceSession:
    """Metadata says one row fits; the subsequent blob lookup disagrees."""

    bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

    def __init__(self, user: User, *, fetched_rows, metadata_size: int, actual_size: int):
        self.user = user
        self.fetched_rows = fetched_rows
        self.metadata_size = metadata_size
        self.actual_size = actual_size
        self.executions = 0

    async def get(self, model, user_id, *, populate_existing=False):
        assert model is User
        assert user_id == self.user.id
        assert populate_existing is True
        return self.user

    async def scalar(self, statement):
        # Snapshot revision reads are intentionally separate from the
        # metadata/blob race this double models.
        return self.user.entries_revision

    async def execute(self, statement):
        self.executions += 1
        if self.executions == 1:
            return _Result(rows=[("entry-race", self.metadata_size)])
        return _Result(scalar_rows=self.fetched_rows)


def _race_user(user_id: str) -> User:
    return User(
        id=user_id,
        username=f"{user_id}-name",
        salt="c2FsdA==",
        verifier=b"v",
        scrypt_salt=b"s",
        is_active=True,
        token_epoch=1,
        entries_revision=0,
    )


async def test_entry_paging_retries_when_metadata_row_disappears():
    """A second worker's delete must not turn into a fake empty final page."""
    from app.api import entries as entries_api

    user = _race_user("paging-disappeared")
    session = _EntryPagingRaceSession(user, fetched_rows=[], metadata_size=32, actual_size=0)
    with pytest.raises(ApiError, match="entries changed while paging") as raised:
        await entries_api.list_entries(
            Response(), user=user, session=session, since=None, offset=0, limit=1, page_bytes=64
        )
    assert raised.value.status_code == 409
    assert raised.value.code == "conflict"


async def test_entry_paging_retries_when_blob_grows_after_metadata():
    """A second worker's blob growth must not exceed the advertised budget."""
    from app.api import entries as entries_api

    user = _race_user("paging-grew")
    row = SimpleNamespace(id="entry-race", blob=b"x" * 65)
    session = _EntryPagingRaceSession(
        user, fetched_rows=[row], metadata_size=32, actual_size=len(row.blob)
    )
    with pytest.raises(ApiError, match="entries changed while paging") as raised:
        await entries_api.list_entries(
            Response(), user=user, session=session, since=None, offset=0, limit=1, page_bytes=64
        )
    assert raised.value.status_code == 409
    assert raised.value.code == "conflict"


async def test_entries_replacement_invalid_and_missing_ids_are_both_not_found(client):
    emu = ClientEmulator("replace-gaps", "pw")
    await emu.register(client)
    payload = {
        "blob": emu.encrypt_entry("replacement", date.today(), "valid-entry"),
        "entry_date": date.today().isoformat(),
    }

    malformed = await client.put("/api/entries/!!!", headers=emu.headers, json=payload)
    missing = await client.put("/api/entries/valid-entry", headers=emu.headers, json=payload)

    assert malformed.status_code == 404
    assert malformed.json()["code"] == "not_found"
    assert missing.status_code == 404
    assert missing.json()["code"] == "not_found"


async def test_entries_byte_page_stops_after_a_fitting_row_before_later_oversize(client, app):
    """A later oversized row advances the cursor after, never before, a row."""
    emu = ClientEmulator("entry-byte-gap", "pw")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Entry(
                    user_id=emu.user_id,
                    client_entry_id="fits-first",
                    blob=b"a" * 512,
                    entry_date=date.today(),
                ),
                Entry(
                    user_id=emu.user_id,
                    client_entry_id="oversize-second",
                    blob=b"b" * 2_048,
                    entry_date=date.today(),
                ),
            ]
        )
        await session.commit()

    page = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 2, "page_bytes": 1_024},
    )
    assert page.status_code == 200, page.text
    assert [row["client_entry_id"] for row in page.json()] == ["fits-first"]
    assert page.headers["X-Next-Offset"] == "1"


async def test_export_returns_busy_when_the_admission_slot_is_occupied(client, app):
    """Export admission protects the DB pool before any stream cursor opens."""
    emu = ClientEmulator("export-slot", "pw")
    await emu.register(client)
    limiter = anyio.CapacityLimiter(1)
    holder = object()
    limiter.acquire_on_behalf_of_nowait(holder)
    app.state.export_limiter = limiter
    try:
        response = await client.get("/api/account/export", headers=emu.headers)
    finally:
        limiter.release_on_behalf_of(holder)

    assert response.status_code == 503
    assert response.json()["code"] == "service_unavailable"
    assert response.headers["Retry-After"] == "1"


async def test_llm_consent_enable_fails_closed_without_a_configured_provider(client):
    emu = ClientEmulator("no-llm-provider", "pw")
    await emu.register(client)

    response = await client.put(
        "/api/account/llm-consent",
        headers=emu.headers,
        json={"enabled": True, "verifier": emu.auth_key_b64},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "llm_unavailable"


def test_export_byte_length_uses_postgres_octets():
    from app.api import account as account_api

    postgres = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))
    assert account_api._export_blob_length(postgres, Entry.blob).name == "octet_length"


async def test_export_releases_admission_slot_when_account_disappears_before_snapshot():
    """A stale authenticated request must release its slot before returning 401."""
    from app.api import account as account_api

    class RecordingLimiter:
        def __init__(self):
            self.acquired = []
            self.released = []

        def acquire_on_behalf_of_nowait(self, borrower):
            self.acquired.append(borrower)

        def release_on_behalf_of(self, borrower):
            self.released.append(borrower)

    limiter = RecordingLimiter()
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(export_limiter=limiter, sessionmaker=SimpleNamespace())
        )
    )
    with pytest.raises(ApiError, match="invalid token") as raised:
        await account_api.export_account(
            request,
            user=_race_user("vanished-export"),
            session=_FreshExportSession(None),
        )
    assert raised.value.status_code == 401
    assert limiter.acquired == limiter.released


async def _collect_export(account_api, *, fresh: User, pages: list[_PageSession]) -> dict:
    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(export_limiter=None, sessionmaker=_PageFactory(pages))
        )
    )
    response = await account_api.export_account(
        request, user=fresh, session=_FreshExportSession(fresh)
    )
    chunks = [chunk async for chunk in response.body_iterator]
    return json.loads("".join(chunks))


async def test_export_skips_disappeared_entry_metadata_and_keeps_scanning():
    """Metadata/blob races advance the cursor instead of truncating exports."""
    from app.api import account as account_api

    fresh = _race_user("export-entry-disappeared")
    now = datetime.now(timezone.utc)
    metadata = [("gone-entry", date.today(), now, 32)]
    bundle = await _collect_export(
        account_api,
        fresh=fresh,
        pages=[
            _PageSession([_Result(rows=[])]),  # shares
            _PageSession([_Result(rows=metadata), _Result(scalar_rows=[])]),
            _PageSession([_Result(rows=[])]),  # later entry page
            _PageSession([_Result(rows=[])]),  # insights
        ],
    )
    assert bundle["entries"] == []
    assert bundle["insights"] == []


async def test_export_skips_disappeared_insight_metadata_and_keeps_scanning():
    from app.api import account as account_api

    fresh = _race_user("export-insight-disappeared")
    metadata = [("gone-insight", datetime.now(timezone.utc), 32)]
    bundle = await _collect_export(
        account_api,
        fresh=fresh,
        pages=[
            _PageSession([_Result(rows=[])]),  # shares
            _PageSession([_Result(rows=[])]),  # entries
            _PageSession([_Result(rows=metadata), _Result(scalar_rows=[])]),
            _PageSession([_Result(rows=[])]),  # later insight page
        ],
    )
    assert bundle["entries"] == []
    assert bundle["insights"] == []


async def test_export_repages_entries_when_blob_grew_after_metadata(monkeypatch):
    """A stale size estimate cannot cause an entry to disappear from export."""
    from app.api import account as account_api

    monkeypatch.setattr(account_api, "EXPORT_PAGE_BLOB_BYTES", 10)
    fresh = _race_user("export-entry-growth")
    now = datetime.now(timezone.utc)
    first = Entry(
        id="entry-first",
        user_id=fresh.id,
        client_entry_id="entry-first",
        blob=b"a" * 8,
        entry_date=date.today(),
        received_at=now,
    )
    second = Entry(
        id="entry-second",
        user_id=fresh.id,
        client_entry_id="entry-second",
        blob=b"b" * 8,
        entry_date=date.today(),
        received_at=now,
    )
    first_metadata = [
        (first.id, first.entry_date, first.received_at, 1),
        (second.id, second.entry_date, second.received_at, 1),
    ]
    second_metadata = [(second.id, second.entry_date, second.received_at, 1)]
    bundle = await _collect_export(
        account_api,
        fresh=fresh,
        pages=[
            _PageSession([_Result(rows=[])]),
            _PageSession(
                [
                    _Result(rows=first_metadata),
                    _Result(scalar_rows=[first]),
                    _Result(scalar_rows=[second]),
                ]
            ),
            _PageSession([_Result(rows=second_metadata), _Result(scalar_rows=[second])]),
            _PageSession([_Result(rows=[])]),
            _PageSession([_Result(rows=[])]),
        ],
    )
    assert [row["client_entry_id"] for row in bundle["entries"]] == ["entry-first", "entry-second"]


async def test_export_repages_insights_when_blob_grew_after_metadata(monkeypatch):
    from app.api import account as account_api

    monkeypatch.setattr(account_api, "EXPORT_PAGE_BLOB_BYTES", 10)
    fresh = _race_user("export-insight-growth")
    now = datetime.now(timezone.utc)
    first = Insight(
        id="insight-first",
        user_id=fresh.id,
        kind="first",
        for_date=None,
        blob=b"a" * 8,
        created_at=now,
    )
    second = Insight(
        id="insight-second",
        user_id=fresh.id,
        kind="second",
        for_date=None,
        blob=b"b" * 8,
        created_at=now,
    )
    first_metadata = [(first.id, first.created_at, 1), (second.id, second.created_at, 1)]
    second_metadata = [(second.id, second.created_at, 1)]
    bundle = await _collect_export(
        account_api,
        fresh=fresh,
        pages=[
            _PageSession([_Result(rows=[])]),
            _PageSession([_Result(rows=[])]),
            _PageSession(
                [
                    _Result(rows=first_metadata),
                    _Result(scalar_rows=[first]),
                    _Result(scalar_rows=[second]),
                ]
            ),
            _PageSession([_Result(rows=second_metadata), _Result(scalar_rows=[second])]),
            _PageSession([_Result(rows=[])]),
        ],
    )
    assert [row["kind"] for row in bundle["insights"]] == ["first", "second"]


async def test_llm_consent_fails_closed_when_user_disappears_after_reauthentication(
    monkeypatch, settings
):
    """A delete racing the verifier work cannot resurrect an account's consent."""
    from app.api import account as account_api

    async def skip_verifier(*args, **kwargs):
        return None

    class MissingUserSession:
        async def execute(self, statement):
            return _Result(scalar_rows=[])

    monkeypatch.setattr(account_api, "_require_verifier", skip_verifier)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    body = account_api.LlmConsentRequest(enabled=False, verifier="proof")
    with pytest.raises(ApiError, match="account not found") as raised:
        await account_api.set_llm_consent(
            body=body,
            request=request,
            user=_race_user("deleted-before-consent"),
            session=MissingUserSession(),
        )
    assert raised.value.status_code == 404


async def test_pairing_with_a_deactivated_therapist_stays_flat_not_found(client, app):
    """A valid-looking code must not disclose a therapist that has closed."""
    patient = ClientEmulator("inactive-patient", "pw")
    therapist = TherapistEmulator("inactive-therapist", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(User).where(User.id == therapist.user_id).values(is_active=False)
        )
        await session.commit()

    lookup = await patient.pairing_lookup(client, code)
    grant = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )

    assert lookup["status"] == 404
    assert lookup["body"]["code"] == "not_found"
    assert grant["status"] == 404
    assert grant["body"]["code"] == "not_found"


async def test_stale_sharing_disclosure_is_rejected_without_burning_code(client):
    patient = ClientEmulator("stale-disclosure", "pw")
    therapist = TherapistEmulator("stale-disclosure-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    wrap = patient_wrap_for(patient, therapist.wrap_pub_key, therapist.user_id or "")

    response = await client.post(
        "/api/consents",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={"code": code, **wrap, "disclosure": "v0"},
    )

    assert response.status_code == 409
    assert response.json()["code"] == "disclosure_outdated"
    assert (await patient.pairing_lookup(client, code))["status"] == 200


async def test_revoke_fails_as_deleted_account_when_lifecycle_recheck_loses_race(monkeypatch):
    """A stale bearer may pass auth, but must not revoke after deletion."""
    from app.api import consents as consents_api

    async def skip_verifier(*args, **kwargs):
        return None

    class DeletedUserSession:
        async def get(self, model, user_id, *, populate_existing=False):
            assert model is User
            assert populate_existing is True
            return None

    monkeypatch.setattr(consents_api, "_require_verifier", skip_verifier)
    with pytest.raises(ApiError, match="account not found") as raised:
        await consents_api.revoke_consent(
            "consent-id",
            request=SimpleNamespace(),
            user=_race_user("deleted-before-revoke"),
            session=DeletedUserSession(),
            x_account_verifier="proof",
        )
    assert raised.value.status_code == 404
    assert raised.value.code == "not_found"


async def test_grant_rechecks_pairing_code_after_waiting_for_sharing_locks(client, monkeypatch):
    """A code consumed while a request queues must not be granted from stale state."""
    from app.api import consents as consents_api

    patient = ClientEmulator("grant-code-race", "pw")
    therapist = TherapistEmulator("grant-code-race-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    original = consents_api._live_code
    calls = 0

    async def disappears_on_recheck(session, supplied_code, secret):
        nonlocal calls
        calls += 1
        if calls == 2:
            return None
        return await original(session, supplied_code, secret)

    monkeypatch.setattr(consents_api, "_live_code", disappears_on_recheck)
    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )

    assert result["status"] == 404
    assert result["body"]["code"] == "not_found"


async def test_grant_rejects_pairing_code_reissued_to_different_therapist(client, monkeypatch):
    """The lock is selected from the preflight therapist and must not drift."""
    from app.api import consents as consents_api

    patient = ClientEmulator("grant-reissued", "pw")
    therapist = TherapistEmulator("grant-reissued-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    original = consents_api._therapist_for_code
    calls = 0

    async def changes_on_recheck(session, code_row):
        nonlocal calls
        calls += 1
        if calls == 2:
            return SimpleNamespace(id="another-therapist")
        return await original(session, code_row)

    monkeypatch.setattr(consents_api, "_therapist_for_code", changes_on_recheck)
    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )

    assert result["status"] == 404
    assert result["body"]["code"] == "not_found"


async def test_grant_fails_when_patient_is_deactivated_while_waiting(client, app, monkeypatch):
    """The fresh patient read is the authority, not the token-time user row."""
    from app.api import consents as consents_api

    patient = ClientEmulator("grant-patient-gone", "pw")
    therapist = TherapistEmulator("grant-patient-gone-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    original = consents_api._live_code
    calls = 0

    async def deactivate_before_second_live_check(session, supplied_code, secret):
        nonlocal calls
        calls += 1
        if calls == 2:
            async with app.state.sessionmaker() as writer:
                await writer.execute(
                    update(User).where(User.id == patient.user_id).values(is_active=False)
                )
                await writer.commit()
        return await original(session, supplied_code, secret)

    monkeypatch.setattr(consents_api, "_live_code", deactivate_before_second_live_check)
    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )

    assert result["status"] == 404
    assert result["body"]["code"] == "not_found"


async def test_grant_fails_closed_when_atomic_pairing_claim_loses_race(client, monkeypatch):
    """The conditional update, not the earlier SELECT, decides code ownership."""
    from app.api import consents as consents_api

    patient = ClientEmulator("grant-claim-race", "pw")
    therapist = TherapistEmulator("grant-claim-race-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    monkeypatch.setattr(consents_api, "db_rowcount", lambda result: 0)

    result = await patient.grant_consent(
        client, code, therapist.wrap_pub_key, therapist.user_id or ""
    )

    assert result["status"] == 404
    assert result["body"]["code"] == "not_found"


def test_entries_classifies_missing_driver_context_as_nonunique():
    from app.api import entries as entries_api

    assert entries_api._is_unique_violation(SimpleNamespace(orig=None)) is False


async def test_entry_replacement_quota_rejects_growth_without_changing_row(settings):
    from app.api import entries as entries_api

    class QuotaSession:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        async def execute(self, statement):
            return SimpleNamespace(scalar_one=lambda: 10)

    settings.max_user_blob_bytes = 10
    with pytest.raises(ApiError) as raised:
        await entries_api._assert_replacement_within_quota(
            QuotaSession(), _race_user("replace-quota"), old_size=1, incoming=2, settings=settings
        )
    assert raised.value.code == "blob_quota_exceeded"


async def test_entry_nonunique_commit_error_is_not_mislabeled_as_a_conflict(settings):
    """Only duplicate-key errors become 409; integrity faults must propagate."""
    from app.api import entries as entries_api

    class NonUniqueCommitSession:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        def __init__(self, user):
            self.user = user
            self.executions = 0
            self.rolled_back = False

        async def get(self, model, user_id, *, populate_existing=False):
            return self.user

        async def scalar(self, statement):
            return self.user.entries_revision

        async def execute(self, statement):
            self.executions += 1
            if self.executions == 1:
                return SimpleNamespace(one=lambda: (0, 0))
            if self.executions == 2:
                return SimpleNamespace(scalar_one_or_none=lambda: None)
            return SimpleNamespace(rowcount=1)

        async def refresh(self, user, attribute_names=None):
            if attribute_names == ["entries_revision"]:
                user.entries_revision += 1

        def add(self, row):
            pass

        async def commit(self):
            raise IntegrityError("INSERT", {}, Exception("CHECK constraint failed"))

        async def rollback(self):
            self.rolled_back = True

    user = _race_user("entry-nonunique")
    session = NonUniqueCommitSession(user)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    body = entries_api.EntryCreate(
        client_entry_id="nonunique-entry",
        blob=base64.b64encode(b"x" * 64).decode(),
        entry_date=date.today(),
    )
    with pytest.raises(IntegrityError, match="CHECK constraint failed"):
        await entries_api.create_entry(body=body, request=request, user=user, session=session)
    assert session.rolled_back is True


async def test_therapist_entry_paging_stops_after_selected_row_before_oversize(client, app):
    patient = ClientEmulator("therapist-entry-budget", "pw")
    therapist = TherapistEmulator("therapist-entry-budget-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    await _grant(client, patient, therapist)
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Entry(
                    user_id=patient.user_id,
                    client_entry_id="evidence-fits",
                    blob=b"a" * 512,
                    entry_date=date.today(),
                ),
                Entry(
                    user_id=patient.user_id,
                    client_entry_id="evidence-oversize",
                    blob=b"b" * 2_048,
                    entry_date=date.today(),
                ),
            ]
        )
        await session.commit()

    response = await client.get(
        f"/api/therapist/patients/{patient.user_id}/entries",
        headers=therapist.headers,
        params={"limit": 2, "page_bytes": 1_024},
    )
    assert response.status_code == 200, response.text
    assert [row["client_entry_id"] for row in response.json()] == ["evidence-fits"]
    assert response.headers["X-Next-Offset"] == "1"


async def test_therapist_long_patient_ids_are_flat_not_found_everywhere(client):
    therapist = TherapistEmulator("long-patient-id", "pw")
    await therapist.register(client)
    impossible_id = "x" * 33

    for suffix in ("insights", "entries", "notes"):
        response = await client.get(
            f"/api/therapist/patients/{impossible_id}/{suffix}", headers=therapist.headers
        )
        assert response.status_code == 404
        assert response.json()["code"] == "not_found"


async def test_therapist_notes_reject_a_stored_row_over_explicit_response_budget(client, app):
    patient = ClientEmulator("note-page-budget", "pw")
    therapist = TherapistEmulator("note-page-budget-th", "pw")
    await patient.register(client)
    await therapist.register(client)
    await _grant(client, patient, therapist)
    now = datetime.now(timezone.utc)
    async with app.state.sessionmaker() as session:
        session.add(
            TherapistNote(
                therapist_id=therapist.user_id,
                user_id=patient.user_id,
                client_note_id="stored-too-large",
                blob=b"x" * 2_048,
                created_at=now,
                updated_at=now,
            )
        )
        await session.commit()

    response = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        params={"limit": 10, "page_bytes": 1_024},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"


async def test_note_id_cannot_retarget_another_patient(client):
    """Therapist queue retries remain idempotent only for the original chart."""
    first = ClientEmulator("note-id-first", "pw")
    second = ClientEmulator("note-id-second", "pw")
    therapist = TherapistEmulator("note-id-therapist", "pw")
    await first.register(client)
    await second.register(client)
    await therapist.register(client)
    await _grant(client, first, therapist)
    await _grant(client, second, therapist)

    original = await client.post(
        f"/api/therapist/patients/{first.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "cross-chart-id",
            "blob": therapist.encrypt_note(first, "cross-chart-id", "first chart"),
        },
    )
    retarget = await client.post(
        f"/api/therapist/patients/{second.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "cross-chart-id",
            "blob": therapist.encrypt_note(second, "cross-chart-id", "second chart"),
        },
    )

    assert original.status_code == 201, original.text
    assert retarget.status_code == 409
    assert retarget.json()["code"] == "conflict"


def test_therapist_binary_helpers_and_note_quota_fail_closed():
    """Driver and quota error branches have deterministic unit coverage."""
    from app.api import therapist as therapist_api

    with pytest.raises(ApiError, match="must be base64"):
        therapist_api._decode_b64("not base64!", "key")
    assert therapist_api._is_unique_violation(SimpleNamespace(orig=None)) is False
    assert therapist_api._is_unique_violation(SimpleNamespace(orig=SimpleNamespace(pgcode="23505")))
    assert not therapist_api._is_unique_violation(SimpleNamespace(orig=Exception("foreign key")))
    postgres = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))
    assert therapist_api._note_blob_length(postgres).name == "octet_length"
    with pytest.raises(ApiError, match="at least"):
        therapist_api._decode_note_blob(base64.b64encode(b"tiny").decode())


async def test_therapist_note_quota_rejects_count_and_total_byte_overflow():
    from app.api import therapist as therapist_api

    class QuotaSession:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        def __init__(self, count: int, total: int):
            self.count = count
            self.total = total

        async def execute(self, statement):
            return SimpleNamespace(one=lambda: (self.count, self.total))

    with pytest.raises(ApiError) as count_error:
        await therapist_api._assert_note_quota(
            QuotaSession(therapist_api.MAX_NOTES_PER_PATIENT, 0),
            "therapist",
            "patient",
            1,
            is_new=True,
        )
    assert count_error.value.code == "quota_exceeded"

    with pytest.raises(ApiError) as bytes_error:
        await therapist_api._assert_note_quota(
            QuotaSession(0, therapist_api.MAX_NOTE_BYTES_PER_PATIENT),
            "therapist",
            "patient",
            1,
            is_new=False,
        )
    assert bytes_error.value.code == "blob_quota_exceeded"
