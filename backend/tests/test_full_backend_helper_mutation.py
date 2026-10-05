"""Returned-data, cryptographic wire and boundary contracts for API helpers."""

from __future__ import annotations

import base64
import hashlib
import json
from contextlib import asynccontextmanager
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from fastapi import Response
from sqlalchemy import update
from sqlalchemy.dialects import postgresql

from app.api import _custody, _paging, _sharing_state
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError
from app.models import Base, Consent, ConsentEvent, User
from app.schemas import TherapistCustodyRequest, TherapistPasswordRequest

MAXIMUM = 2**63 - 1
OWNER = "a" * 32
OTHER = "b" * 32


def envelope(failure, status, detail, code):
    assert (failure.value.status_code, failure.value.detail, failure.value.code) == (
        status,
        detail,
        code,
    )


def test_paging_canonical_snapshot_boundaries_and_retry_envelopes():
    for value, expected in ((None, None), ("0", 0), ("1", 1), (str(MAXIMUM), MAXIMUM)):
        assert _paging.parse_expected_revision(value) == expected
    for value in (str(MAXIMUM + 1), "01", "+1", " 1", "١", 1):
        with pytest.raises(ApiError) as failure:
            _paging.parse_expected_revision(value)
        envelope(
            failure,
            422,
            "expected_revision must be a canonical non-negative decimal",
            "validation_error",
        )
    for expected in (None, 7):
        _paging.assert_expected_revision(
            expected, 7, collection="notes", header_name="X-Notes-Revision"
        )
    with pytest.raises(ApiError) as failure:
        _paging.assert_expected_revision(6, 7, collection="notes", header_name="X-Notes-Revision")
    envelope(failure, 409, "notes changed while paging; retry the request", "collection_changed")
    assert failure.value.headers == {"X-Notes-Revision": "7"}
    assert _paging.collection_changed_error("notes", "X-Notes-Revision").headers is None
    assert _paging.collection_changed_error("notes", "X-Notes-Revision", 0).headers == {
        "X-Notes-Revision": "0"
    }


def test_byte_pages_preserve_exact_fit_prefix_and_history_flags():
    def choose(rows, limit, more=False):
        return _paging.select_byte_page(
            rows,
            more_after_request=more,
            page_bytes=limit,
            hard_budget=2 * 1024 * 1024,
            collection="notes",
        )

    exact = choose([("a", 3), ("b", 2)], 5)
    assert exact.selected == [("a", 3), ("b", 2)] and exact.has_more is False
    with pytest.raises(FrozenInstanceError):
        exact.has_more = True
    assert choose([], 5).selected == []
    assert choose([("a", 3), ("b", 3), ("c", 1)], 5).selected == [("a", 3)]
    assert choose([("a", 3), ("b", 6), ("c", 1)], 5).selected == [("a", 3)]
    assert choose([("a", 5)], 5).selected == [("a", 5)]
    assert choose([("a", 1), ("b", 2), ("c", 3)], 5).selected == [("a", 1), ("b", 2)]
    assert choose([("a", 3)], 5, True).has_more is True
    assert choose([("a", 3), ("b", 3)], 5).has_more is True
    assert choose([("a", 1)], None).has_more is False
    with pytest.raises(ApiError) as failure:
        choose([("a", 6)], 5)
    envelope(
        failure,
        413,
        "an item in this notes page exceeds the requested page byte budget",
        "payload_too_large",
    )
    hard = _paging.select_byte_page(
        [("a", 2 * 1024 * 1024)],
        more_after_request=False,
        page_bytes=None,
        hard_budget=2 * 1024 * 1024,
        collection="notes",
    )
    assert hard.selected == [("a", 2 * 1024 * 1024)]
    with pytest.raises(ApiError) as failure:
        choose([("a", 2 * 1024 * 1024 + 1)], None)
    envelope(
        failure,
        413,
        "requested notes page exceeds the 2 MiB ciphertext budget; upgrade to a byte-paginating client",
        "payload_too_large",
    )


def test_fetch_validation_and_response_continuations_are_snapshot_safe():
    rows = [SimpleNamespace(id="b", blob=b"12"), SimpleNamespace(id="a", blob=b"123")]
    assert _paging.verify_fetched_page(
        ["a", "b"], rows, byte_limit=5, collection="notes", header_name="X-Notes", revision=7
    ) == [rows[1], rows[0]]
    with pytest.raises(ApiError) as failure:
        _paging.verify_fetched_page(
            ["a", "b"], rows, byte_limit=4, collection="notes", header_name="X-Notes", revision=7
        )
    envelope(failure, 409, "notes changed while paging; retry the request", "collection_changed")
    for more, returned, expected in (
        (False, 2, None),
        (True, 0, None),
        (True, 1, "8"),
        (True, 2, "9"),
    ):
        response = Response()
        _paging.emit_page_headers(
            response,
            revision=7,
            header_name="X-Notes",
            has_more=more,
            rows_returned=returned,
            offset=7,
        )
        assert response.headers["X-Notes"] == "7"
        assert response.headers.get("X-Next-Offset") == expected


def body(password=False, **changes):
    values = dict(
        verifier=base64.b64encode(b"v" * 32).decode(),
        operation_id="00000000-0000-0000-0000-000000000001",
        expected_custody_version=3,
        custody_version=4,
        notes_keyring_blob=base64.b64encode(b"n" * 60).decode(),
    )
    if password:
        values.update(
            new_salt=base64.b64encode(b"s" * 16).decode(),
            new_verifier=base64.b64encode(b"v" * 32).decode(),
            wrap_pub_key="public",
            wrap_key_blob=base64.b64encode(b"w" * 60).decode(),
        )
    values.update(changes)
    return (TherapistPasswordRequest if password else TherapistCustodyRequest)(**values)


def digest(value, action):
    return hashlib.sha256(
        action.encode()
        + b"\0"
        + json.dumps(value.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def test_custody_decoding_canonical_digest_and_revision_boundaries():
    for count in (1, 3):
        encoded = base64.b64encode(b"v" * count).decode()
        assert _custody._decode(encoded, 1, 3) == b"v" * count
    for encoded in (
        "!!!!" + base64.b64encode(b"v").decode(),
        base64.b64encode(b"v" * 4).decode(),
        "",
    ):
        with pytest.raises(ApiError) as failure:
            _custody._decode(encoded, 1, 3)
        envelope(failure, 422, "invalid key material", "validation_error")
    for action in ("custody", "password"):
        assert _custody._digest(body(), action) == digest(body(), action)
    _custody._check_version(SimpleNamespace(custody_version=3), body())
    for current, requested, status, detail, code in (
        (3, 5, 422, "custody version must advance by one", "validation_error"),
        (2, 4, 409, "custody changed; reload account", "conflict"),
    ):
        with pytest.raises(ApiError) as failure:
            _custody._check_version(
                SimpleNamespace(custody_version=current), body(custody_version=requested)
            )
        envelope(failure, status, detail, code)
    user = SimpleNamespace(notes_revision=MAXIMUM - 1)
    _custody._advance_notes_snapshot(user)
    assert user.notes_revision == MAXIMUM
    with pytest.raises(ApiError) as failure:
        _custody._advance_notes_snapshot(user)
    envelope(failure, 503, "unable to advance notes revision", "service_unavailable")
    assert user.notes_revision == MAXIMUM


@pytest.fixture
def custody_seams(monkeypatch):
    events = []

    @asynccontextmanager
    async def hold(key):
        events.append(("lock", key))
        yield

    async def verifier(*args):
        events.append(("verify", args[1]))

    async def audit(session, **kwargs):
        events.append(("audit", kwargs))

    @asynccontextmanager
    async def slot(request):
        yield

    async def hash_off_loop(value, salt, **kwargs):
        events.append(("hash", value, salt, kwargs))
        return hashlib.sha256(value + salt).digest()

    monkeypatch.setattr(_custody, "lifecycle_locks", SimpleNamespace(hold=hold))
    monkeypatch.setattr(_custody, "sharing_locks", SimpleNamespace(hold=hold))
    monkeypatch.setattr(_custody, "_require_verifier", verifier)
    monkeypatch.setattr(_custody, "append_access_log", audit)
    monkeypatch.setattr(_custody, "auth_work_slot", slot)
    monkeypatch.setattr(_custody, "hash_verifier_off_loop", hash_off_loop)
    monkeypatch.setattr(_custody, "_auth_limiter", lambda request: "limiter")
    return events


def user(**changes):
    values = dict(
        id=OWNER,
        role="therapist",
        is_active=True,
        token_epoch=2,
        custody_version=3,
        notes_revision=8,
        wrap_pub_key="public",
        custody_operation_id=None,
        custody_operation_digest=None,
        custody_operation_epoch=None,
    )
    values.update(changes)
    return SimpleNamespace(**values)


class Session:
    def __init__(self, value):
        self.value = value
        self.commits = 0

    async def scalar(self, statement):
        return self.value

    async def get(self, *args):
        return self.value

    async def commit(self):
        self.commits += 1


def request(epoch=2, jti="live", revoked=False, version=1):
    destroyed = []
    revocations = []

    async def checked(session, value):
        revocations.append(value)
        return revoked

    return SimpleNamespace(
        state=SimpleNamespace(custody_token_epoch=epoch, custody_token_jti=jti),
        app=SimpleNamespace(
            state=SimpleNamespace(
                settings=SimpleNamespace(
                    auth_token_secret="secret", auth_secret_version=version, scrypt_n=1024
                ),
                token_revocations=SimpleNamespace(is_revoked_checked=checked),
                key_store=SimpleNamespace(destroy_all_for_owner=destroyed.append),
            )
        ),
        destroyed=destroyed,
        revocations=revocations,
    )


async def test_install_custody_persists_all_retry_custody_and_audit_fields(custody_seams):
    fresh = user()
    session = Session(fresh)
    value = body()
    await _custody.install_custody(value, request(), fresh, session)
    assert (fresh.custody_version, fresh.notes_revision, fresh.token_epoch) == (4, 9, 2)
    assert fresh.notes_keyring_blob == b"n" * 60
    assert (
        fresh.custody_operation_id,
        fresh.custody_operation_digest,
        fresh.custody_operation_epoch,
    ) == (value.operation_id, digest(value, "custody"), 2)
    assert session.commits == 1
    assert custody_seams[0] == ("lock", f"llm-lifecycle:{OWNER}")
    assert custody_seams[1] == ("lock", _custody.sharing_therapist_lock_key(OWNER))
    assert custody_seams[-1] == (
        "audit",
        dict(actor_id=OWNER, actor_role="therapist", user_id=OWNER, action="notes_custody_install"),
    )


@pytest.mark.parametrize("changed", ["epoch", "digest", "empty_digest"])
async def test_install_retry_rejects_reused_operation_with_different_custody(
    changed, custody_seams
):
    value = body()
    fresh = user(
        custody_operation_id=value.operation_id,
        custody_operation_epoch=2,
        custody_operation_digest=digest(value, "custody"),
    )
    if changed == "epoch":
        fresh.custody_operation_epoch = 1
    else:
        fresh.custody_operation_digest = "other" if changed == "digest" else None
    session = Session(fresh)
    with pytest.raises(ApiError) as failure:
        await _custody.install_custody(value, request(), fresh, session)
    envelope(failure, 409, "operation identifier already used", "conflict")
    assert session.commits == 0


async def test_install_rejects_stale_authentication_and_excess_keyring(custody_seams):
    fresh = user()
    session = Session(fresh)
    with pytest.raises(ApiError) as failure:
        await _custody.install_custody(body(), request(), user(token_epoch=1), session)
    envelope(failure, 401, "invalid token", "unauthorized")
    with pytest.raises(ApiError) as failure:
        await _custody.install_custody(
            body(notes_keyring_blob=base64.b64encode(b"n" * 65537).decode()),
            request(),
            fresh,
            session,
        )
    envelope(failure, 422, "invalid key material", "validation_error")


@pytest.mark.parametrize("value", [None, user(is_active=False), user(role="user")])
async def test_fresh_custody_requires_active_therapist_with_exact_error(value):
    with pytest.raises(ApiError) as failure:
        await _custody._fresh(Session(value), OWNER)
    envelope(failure, 401, "invalid token", "unauthorized")


async def test_password_retry_authentication_preserves_legacy_and_rotated_token_state(monkeypatch):
    payload = {"uid": OWNER, "ep": 2, "ksv": 2, "jti": "live", "purpose": "therapist"}
    monkeypatch.setattr(_custody.tokens, "verify_token", lambda token, secret: payload)
    fresh = user()
    session = Session(fresh)
    req = request(version=2)
    assert await _custody.require_password_retry_therapist(req, "Bearer live", session) is fresh
    assert (req.state.custody_token_epoch, req.state.custody_token_jti) == (2, "live")
    assert req.revocations == ["live"] and session.commits == 1
    payload.clear()
    payload.update(uid=OWNER)
    fresh.token_epoch = 1
    req = request()
    assert await _custody.require_password_retry_therapist(req, "Bearer live", session) is fresh
    assert req.state.custody_token_epoch == 1 and req.state.custody_token_jti is None


@pytest.mark.parametrize("variant", ["revoked", "purpose", "inactive", "patient", "scheme"])
async def test_password_retry_authentication_failure_envelopes(monkeypatch, variant):
    payload = {"uid": OWNER, "ep": 2, "ksv": 1, "jti": "live"}
    fresh = user()
    req = request(revoked=variant == "revoked")
    if variant == "purpose":
        payload["purpose"] = "other"
    if variant == "inactive":
        fresh.is_active = False
    if variant == "patient":
        fresh.role = "user"
    monkeypatch.setattr(_custody.tokens, "verify_token", lambda token, secret: payload)
    with pytest.raises(ApiError) as failure:
        await _custody.require_password_retry_therapist(
            req, "Basic live" if variant == "scheme" else "Bearer live", Session(fresh)
        )
    if variant == "patient":
        envelope(failure, 403, "not a therapist account", "forbidden")
    else:
        envelope(failure, 401, "invalid token", "unauthorized")


async def test_password_transaction_changes_credentials_and_evicts_owner_keys(custody_seams):
    fresh = user()
    session = Session(fresh)
    req = request()
    value = body(True)
    await _custody.change_password(value, req, fresh, session)
    assert fresh.salt == base64.b64encode(b"s" * 16).decode()
    assert fresh.verifier == hashlib.sha256(b"v" * 32 + fresh.scrypt_salt).digest()
    assert len(fresh.scrypt_salt) >= 16
    assert (fresh.wrap_key_blob, fresh.notes_keyring_blob) == (b"w" * 60, b"n" * 60)
    assert (fresh.custody_version, fresh.notes_revision, fresh.token_epoch) == (4, 9, 3)
    assert (
        fresh.custody_operation_id,
        fresh.custody_operation_digest,
        fresh.custody_operation_epoch,
    ) == (value.operation_id, digest(value, "password"), 3)
    assert req.destroyed == [OWNER] and session.commits == 2
    assert custody_seams[0] == ("lock", f"llm-lifecycle:{OWNER}")
    assert custody_seams[-1] == (
        "audit",
        dict(
            actor_id=OWNER,
            actor_role="therapist",
            user_id=OWNER,
            action="therapist_password_change",
        ),
    )


@pytest.mark.parametrize("variant", ["epoch", "revoked", "keyring"])
async def test_password_mutation_rejects_bad_authentication_and_oversized_blobs(
    variant, custody_seams
):
    req = request(epoch=1 if variant == "epoch" else 2, revoked=variant == "revoked")
    fresh = user()
    changes = {}
    if variant == "keyring":
        changes["notes_keyring_blob"] = base64.b64encode(b"n" * 65537).decode()
    with pytest.raises(ApiError) as failure:
        await _custody.change_password(body(True, **changes), req, fresh, Session(fresh))
    if variant in ["epoch", "revoked"]:
        envelope(failure, 401, "invalid token", "unauthorized")
    else:
        envelope(failure, 422, "invalid key material", "validation_error")


async def test_consent_events_use_patient_lock_and_exact_retained_limits():
    class CountSession:
        def __init__(self, count):
            self.count = count
            self.calls = []
            self.added = []

        async def scalar(self, statement):
            self.calls.append(
                str(
                    statement.compile(
                        dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}
                    )
                )
            )
            return OWNER if len(self.calls) == 1 else self.count

        def add(self, event):
            self.added.append(event)

    for increasing, maximum in ((True, 9798), (False, 10000)):
        for count in (0, maximum - 1, maximum):
            session = CountSession(count)
            event = ConsentEvent(user_id=OWNER, kind="llm", action="granted")
            if count == maximum:
                with pytest.raises(ApiError) as failure:
                    await _sharing_state.add_consent_event(
                        session, event, permission_increasing=increasing
                    )
                envelope(
                    failure,
                    413,
                    "consent history has reached the retained safety limit",
                    "payload_too_large",
                )
                assert session.added == []
            else:
                await _sharing_state.add_consent_event(
                    session, event, permission_increasing=increasing
                )
                assert session.added == [event]
            assert f"users.id = '{OWNER}'" in session.calls[0] and "FOR UPDATE" in session.calls[0]
            assert f"consent_events.user_id = '{OWNER}'" in session.calls[1]


async def database():
    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    return engine, build_sessionmaker(engine)


def account(identifier, **changes):
    values = dict(
        id=identifier,
        username=identifier,
        salt="salt",
        verifier=b"verifier",
        scrypt_salt=b"scrypt",
        is_active=True,
    )
    values.update(changes)
    return User(**values)


async def test_sharing_revision_updates_deduplicate_and_fence_saturation():
    engine, factory = await database()
    try:
        async with factory() as session:
            session.add_all(
                [
                    account(OWNER, consents_revision=5, patients_revision=7),
                    account(OTHER, consents_revision=MAXIMUM, patients_revision=MAXIMUM),
                ]
            )
            await session.commit()
            await _sharing_state.advance_sharing_revisions(
                session, patient_ids=[OWNER, OWNER], therapist_ids=[OWNER]
            )
            await session.commit()
            await session.refresh(await session.get(User, OWNER))
            fresh = await session.get(User, OWNER)
            assert (fresh.consents_revision, fresh.patients_revision) == (6, 8)
            for identifiers in ([OTHER], ["missing"]):
                with pytest.raises(ApiError) as failure:
                    await _sharing_state.advance_sharing_revisions(session, patient_ids=identifiers)
                envelope(failure, 503, "unable to advance sharing snapshot", "service_unavailable")
                await session.rollback()
    finally:
        await engine.dispose()


async def test_fresh_reload_observes_committed_account_deactivation():
    engine, factory = await database()
    try:
        async with factory() as session:
            value = account(OWNER, role="therapist")
            session.add(value)
            await session.commit()
            async with engine.begin() as connection:
                await connection.execute(
                    update(User).where(User.id == OWNER).values(is_active=False)
                )
            with pytest.raises(ApiError) as failure:
                await _custody._fresh(session, OWNER)
            envelope(failure, 401, "invalid token", "unauthorized")
    finally:
        await engine.dispose()


async def test_therapist_token_admission_refreshes_an_existing_identity_map(monkeypatch):
    engine, factory = await database()
    try:
        async with factory() as session:
            value = account(OWNER, role="therapist", token_epoch=2)
            session.add(value)
            await session.commit()
            async with engine.begin() as connection:
                await connection.execute(
                    update(User).where(User.id == OWNER).values(is_active=False)
                )
            monkeypatch.setattr(
                _custody.tokens,
                "verify_token",
                lambda token, secret: {
                    "uid": OWNER,
                    "purpose": "therapist",
                    "ep": 2,
                    "ksv": 1,
                },
            )
            with pytest.raises(ApiError) as failure:
                await _custody.require_password_retry_therapist(request(), "Bearer live", session)
            envelope(failure, 401, "invalid token", "unauthorized")
    finally:
        await engine.dispose()


@pytest.mark.parametrize("therapist", [False, True])
async def test_account_deletion_fences_only_unsaturated_counterpart_snapshots(therapist):
    engine, factory = await database()
    try:
        async with factory() as session:
            session.add_all(
                [
                    account(OWNER),
                    account(OTHER, consents_revision=MAXIMUM, patients_revision=MAXIMUM),
                    account("c" * 32, consents_revision=7, patients_revision=9),
                ]
            )
            await session.commit()
            for counterpart in (OTHER, "c" * 32):
                session.add(
                    Consent(
                        user_id=counterpart if therapist else OWNER,
                        therapist_id=OWNER if therapist else counterpart,
                        scope="full",
                        status="active",
                    )
                )
            await session.commit()
            await _sharing_state.advance_counterpart_revisions_for_deletion(
                session, account_id=OWNER, therapist=therapist
            )
            await session.commit()
            await session.refresh(await session.get(User, OTHER))
            await session.refresh(await session.get(User, "c" * 32))
            saturated = await session.get(User, OTHER)
            normal = await session.get(User, "c" * 32)
            assert (saturated.consents_revision, saturated.patients_revision) == (MAXIMUM, MAXIMUM)
            assert (normal.consents_revision, normal.patients_revision) == (
                (8, 9) if therapist else (7, 10)
            )
    finally:
        await engine.dispose()
