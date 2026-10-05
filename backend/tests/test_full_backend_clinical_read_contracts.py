"""Public clinical reads, native roster limits and key-rotation boundaries."""

# Imported pytest fixtures are intentionally requested again as parameters.
# ruff: noqa: F811

from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest
from fastapi import FastAPI, Response
from sqlalchemy import select

from app.api import therapist
from app.deps import ApiError
from app.models import AccessLog, Consent, Entry, Insight, Measure, User
from app.schemas import TherapistRegisterRequest, WrapKeyRotateRequest
from tests.test_full_backend_authentication_mutation import (
    AUTH_KEY,
    authentication_db,  # noqa: F401
    hash_proof,
    seed_consent,
    sharing_db,  # noqa: F401
)
from tests.test_full_backend_collection_mutation import (
    BLOB,
    NOW,
    OTHER,
    OWNER,
    account,
    b64,
    collection_db,  # noqa: F401
    envelope,
)


def test_clinical_roster_history_and_ciphertext_query_contracts():
    app = FastAPI()
    app.include_router(therapist.router)
    paths = app.openapi()["paths"]
    specs = {
        "/therapist/patients": {"limit": (100, 1, 200), "offset": (0, 0, 1000)},
        "/therapist/access-log": {"limit": (50, 1, 200)},
        "/therapist/patients/{user_id}/entries": {
            "limit": (25, 1, 25),
            "offset": (0, 0, 100000),
            "page_bytes": (None, 1, 2097152),
        },
        "/therapist/patients/{user_id}/measures": {
            "limit": (200, 1, 500),
            "offset": (0, 0, 100000),
            "page_bytes": (None, 1, 2097152),
        },
    }
    for path, expected in specs.items():
        parameters = {p["name"]: p["schema"] for p in paths[path]["get"]["parameters"]}
        for name, (default, minimum, maximum) in expected.items():
            schema = parameters[name]
            numeric = next(
                (x for x in schema.get("anyOf", []) if x.get("type") == "integer"), schema
            )
            assert (schema.get("default"), numeric["minimum"], numeric["maximum"]) == (
                default,
                minimum,
                maximum,
            ), (path, name)


@pytest.mark.asyncio
async def test_clinician_self_retains_empty_legacy_key_fields(authentication_db):
    db = authentication_db
    db.other.wrap_pub_key = None
    db.other.wrap_key_blob = None
    db.other.display_name = None
    out = await therapist.therapist_me(db.other)
    assert (out.display_name, out.wrap_pub_key, out.wrap_key_blob) == (OTHER, "", "")


@pytest.mark.asyncio
async def test_clinician_action_history_keeps_deleted_patients_and_exact_tie_cursors(sharing_db):
    db = sharing_db
    rows = [
        AccessLog(
            id=f"{i:032x}",
            user_id=owner,
            actor_id=actor,
            actor_role="therapist",
            action=f"event-{i}",
            at=at,
            chain_seq=i,
        )
        for i, owner, actor, at in [
            (5, OWNER, OTHER, NOW),
            (4, "dead" * 8, OTHER, NOW - timedelta(seconds=1)),
            (3, OWNER, OTHER, NOW - timedelta(seconds=1)),
            (2, OTHER, OTHER, NOW - timedelta(seconds=2)),
            (1, OWNER, OWNER, NOW + timedelta(seconds=1)),
        ]
    ]
    db.session.add_all(rows)
    await db.session.commit()
    first = Response()
    out = await therapist.read_own_access_log(first, db.other, db.session, 2, None)
    assert [r.action for r in out] == ["event-5", "event-4"]
    assert [r.patient_name for r in out] == [OWNER, None]
    cursor = f"{(NOW - timedelta(seconds=1)).isoformat()}|{4:032x}"
    assert first.headers["X-Next-Cursor"] == cursor
    second = Response()
    out = await therapist.read_own_access_log(second, db.other, db.session, 2, cursor)
    assert [r.action for r in out] == ["event-3", "event-2"]
    assert [r.patient_name for r in out] == [OWNER, None]
    assert "X-Next-Cursor" not in second.headers


async def chart_rows(db, kind, sizes=(28, 60, 28)):
    model = Entry if kind == "entries" else Measure
    rows = []
    for i, size in enumerate(sizes):
        common = dict(
            id=f"{i + 1:032x}", user_id=OWNER, blob=bytes([65 + i]) * size, received_at=NOW
        )
        if model is Entry:
            common.update(client_entry_id=f"e-{i}", entry_date=NOW.date() - timedelta(days=2 - i))
        else:
            common.update(client_measure_id=f"m-{i}", measure_date=NOW.date() - timedelta(days=i))
        rows.append(model(**common))
    db.session.add_all(rows)
    setattr(db.owner, f"{kind}_revision", 5)
    await db.session.commit()
    return rows


async def read_chart(
    db, kind, response, *, offset=0, limit=2, budget=None, revision="5", patient=OWNER
):
    if kind == "entries":
        return await therapist.read_patient_entries(
            patient, response, db.other, db.session, None, None, offset, limit, budget, revision
        )
    return await therapist.read_patient_measures(
        patient, response, db.other, db.session, limit, offset, budget, revision
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["entries", "measures"])
async def test_private_chart_pages_preserve_bytes_order_revision_and_empty_audit(sharing_db, kind):
    db = sharing_db
    await seed_consent(db)
    rows = await chart_rows(db, kind)
    for offset, expected, continuation in [(0, rows[:2], "2"), (2, rows[2:], None), (3, [], None)]:
        response = Response()
        db.audit.clear()
        out = await read_chart(db, kind, response, offset=offset)
        assert [(r.id, r.blob) for r in out] == [(r.id, b64(r.blob)) for r in expected]
        assert response.headers[f"X-{kind.title()}-Revision"] == "5"
        assert response.headers.get("X-Next-Offset") == continuation
        assert [(r["actor_id"], r["user_id"], r["action"]) for r in db.audit] == [
            (OTHER, OWNER, f"read_{kind}")
        ]
    response = Response()
    out = await read_chart(db, kind, response, limit=3, budget=28)
    assert [(r.id, r.blob) for r in out] == [(rows[0].id, b64(rows[0].blob))]
    assert response.headers["X-Next-Offset"] == "1"


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["entries", "measures"])
@pytest.mark.parametrize("failure_kind", ["revision", "item", "long_id"])
async def test_private_chart_refusals_identify_the_exact_scope(sharing_db, kind, failure_kind):
    db = sharing_db
    await seed_consent(db)
    await chart_rows(db, kind)
    arguments = {"revision": "5"}
    if failure_kind == "revision":
        arguments["revision"] = "4"
        expected = (
            409,
            f"{kind} changed while paging; retry the request",
            "collection_changed",
            {f"X-{kind.title()}-Revision": "5"},
        )
    elif failure_kind == "item":
        arguments["budget"] = 27
        label = "evidence entry" if kind == "entries" else "measure"
        expected = (
            413,
            f"an item in this {label} page exceeds the requested page byte budget",
            "payload_too_large",
            None,
        )
    else:
        arguments["patient"] = "a" * 33
        expected = (404, "patient not found", "not_found", None)
    with pytest.raises(ApiError) as failure:
        await read_chart(db, kind, Response(), **arguments)
    envelope(failure, *expected)


@pytest.mark.asyncio
async def test_clinical_entry_native_two_mib_budget_accepts_exact_boundary_and_refuses_extra(
    sharing_db,
):
    db = sharing_db
    await seed_consent(db)
    rows = await chart_rows(db, "entries", (1048576, 1048576, 28))
    response = Response()
    out = await read_chart(db, "entries", response, limit=25, budget=2097152)
    assert [r.id for r in out] == [r.id for r in rows[:2]]
    assert response.headers["X-Next-Offset"] == "2"
    with pytest.raises(ApiError) as failure:
        await read_chart(db, "entries", Response(), limit=25)
    envelope(
        failure,
        413,
        "requested evidence entry page exceeds the 2 MiB ciphertext budget; upgrade to a byte-paginating client",
        "payload_too_large",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "count,status", [(100, "active"), (101, "active"), (1000, "revoked"), (1001, "revoked")]
)
async def test_native_roster_caps_count_active_and_retained_relationships_separately(
    sharing_db, count, status
):
    db = sharing_db
    people = [account(f"{i:032x}") for i in range(1, count + 1)]
    db.session.add_all(people)
    await db.session.flush()
    db.session.add_all(
        [
            Consent(
                id=f"{i:032x}",
                user_id=patient.id,
                therapist_id=OTHER,
                status=status,
                disclosure="v3",
                granted_at=NOW,
            )
            for i, patient in enumerate(people, 1)
        ]
    )
    await db.session.commit()
    if count in (101, 1001):
        with pytest.raises(ApiError) as failure:
            await therapist.list_patients(db.request, Response(), db.other, db.session, 1, 0, "0")
        detail = (
            "patient list exceeds the supported caseload size"
            if status == "active"
            else "retained patient history exceeds the supported list size"
        )
        envelope(failure, 413, detail, "payload_too_large")
    else:
        response = Response()
        out = await therapist.list_patients(db.request, response, db.other, db.session, 1, 0, "0")
        assert [r.user_id for r in out] == [people[-1].id]
        assert response.headers["X-Patients-Revision"] == "0"
        assert response.headers["X-Next-Offset"] == "1"


@pytest.mark.asyncio
@pytest.mark.parametrize("retired_own", [False, True])
async def test_roster_retirement_is_specific_to_the_current_clinician(sharing_db, retired_own):
    db = sharing_db
    await seed_consent(db)
    extra = account("d" * 32, is_active=False)
    clinician = account("e" * 32, role="therapist")
    db.session.add_all([extra, clinician])
    await db.session.flush()
    db.session.add(
        Consent(
            user_id=extra.id,
            therapist_id=OTHER if retired_own else clinician.id,
            status="revoked",
            granted_at=NOW,
        )
    )
    await db.session.commit()
    if retired_own:
        with pytest.raises(ApiError) as failure:
            await therapist.list_patients(db.request, Response(), db.other, db.session, 100, 0, "0")
        envelope(
            failure,
            409,
            "patients changed while paging; retry the request",
            "collection_changed",
            {"X-Patients-Revision": "0"},
        )
        assert db.audit == [], "the initial stale-roster refusal must not fetch any chart"
    else:
        out = await therapist.list_patients(
            db.request, Response(), db.other, db.session, 100, 0, "0"
        )
        assert [r.user_id for r in out] == [OWNER]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "phase,disclosure,status",
    [
        ("insight", "v3", "active"),
        ("baseline", "v3", "active"),
        ("insight", "v1", "active"),
        ("insight", "v3", "revoked"),
    ],
)
async def test_roster_summary_obeys_current_phase_disclosure_and_grant(
    sharing_db, phase, disclosure, status
):
    db = sharing_db
    db.settings.unlock_threshold_days = 3
    await seed_consent(
        db,
        status=status,
        disclosure=disclosure,
        summary_blob=BLOB,
        summary_eph_pub=db.spki,
        summary_updated_at=NOW,
    )
    if phase == "insight":
        await chart_rows(db, "entries")
    out = await therapist.list_patients(db.request, Response(), db.other, db.session, 100, 0, "0")
    assert len(out) == 1 and out[0].user_id == OWNER
    serves = phase == "insight" and disclosure == "v3" and status == "active"
    assert out[0].summary_blob == (b64(BLOB) if serves else None)
    assert out[0].summary_eph_pub == (db.spki if serves else None)
    assert out[0].wrapped_key == (b64(BLOB) if status == "active" else None)
    assert [(r["user_id"], r["action"]) for r in db.audit] == [(OWNER, "list_patients")]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "has_latest,phase", [(False, "insight"), (True, "baseline"), (True, "insight")]
)
async def test_clinical_insights_keep_the_authoritative_sequence_without_leaking_old_blob(
    sharing_db, has_latest, phase
):
    db = sharing_db
    db.settings.unlock_threshold_days = 3
    await seed_consent(db)
    if phase == "insight":
        await chart_rows(db, "entries")
    if has_latest:
        db.session.add(
            Insight(user_id=OWNER, kind="patterns", blob=BLOB, state_seq=7, created_at=NOW)
        )
        await db.session.commit()
    out = await therapist.read_patient_insights(db.request, OWNER, db.other, db.session)
    assert out.phase == phase
    assert out.blob == (b64(BLOB) if has_latest and phase == "insight" else None)
    assert out.state_seq == (7 if has_latest else 0)
    assert [(r["user_id"], r["action"]) for r in db.audit] == [(OWNER, "read_insights")]


@pytest.mark.asyncio
@pytest.mark.parametrize("size", [28, 768, 27])
async def test_clinician_registration_and_private_wrap_repair_accept_exact_envelope_bounds(
    sharing_db, size, monkeypatch
):
    from app.api import account as account_api, auth

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    body = TherapistRegisterRequest(
        username="new_clinician",
        display_name="New Clinician",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
        wrap_pub_key=db.spki,
        wrap_key_blob=b64(b"x" * size),
    )
    if size == 27:
        with pytest.raises(ApiError) as failure:
            await therapist.register_therapist(body, db.request, db.session, None)
        envelope(failure, 422, "wrap_key_blob must be 28-1024 bytes", "validation_error")
    else:
        out = await therapist.register_therapist(body, db.request, db.session, None)
        stored = await db.session.get(User, out.user_id)
        assert stored.wrap_key_blob == b"x" * size
        assert len(stored.scrypt_salt) >= 16
        assert stored.verifier == hash_proof(AUTH_KEY, stored.scrypt_salt)
        assert [(r["actor_role"], r["action"]) for r in db.audit] == [
            ("therapist", "account_created")
        ]
    db.other.notes_keyring_blob = BLOB
    db.other.custody_version = 3
    await db.session.commit()
    rotate = WrapKeyRotateRequest(
        wrap_pub_key=db.spki, wrap_key_blob=b64(b"x" * size), expected_custody_version=3
    )
    if size == 27:
        with pytest.raises(ApiError) as failure:
            await therapist.rotate_wrap_key(rotate, db.request, db.other, db.session, b64(AUTH_KEY))
        envelope(failure, 422, "wrap_key_blob must be 28-1024 bytes", "validation_error")
    else:
        await therapist.rotate_wrap_key(rotate, db.request, db.other, db.session, b64(AUTH_KEY))
        await db.session.refresh(db.other)
        assert db.other.wrap_pub_key == db.spki and db.other.wrap_key_blob == b"x" * size
        assert db.audit[-1]["action"] == "wrap_key_rotate"


def replacement_spki():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    return b64(
        ec.derive_private_key(11, ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["salt", "verifier", "wrap_key_blob"])
async def test_clinician_registration_rejects_noncanonical_encoding_before_account_creation(
    sharing_db, field
):
    db = sharing_db
    values = dict(
        username="strict_clinician",
        display_name="Strict Clinician",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
        wrap_pub_key=db.spki,
        wrap_key_blob=b64(BLOB),
    )
    values[field] = "!!!!" + values[field]
    body = TherapistRegisterRequest(**values)
    with pytest.raises(ApiError) as failure:
        await therapist.register_therapist(body, db.request, db.session, None)
    detail = (
        "wrap_key_blob must be base64"
        if field == "wrap_key_blob"
        else "salt and verifier must be base64"
    )
    envelope(failure, 422, detail, "validation_error")
    assert (
        await db.session.scalar(select(User.id).where(User.username == "strict_clinician")) is None
    )


@pytest.mark.asyncio
async def test_clinician_registration_real_unique_race_returns_the_safe_conflict(
    sharing_db, monkeypatch
):
    db = sharing_db
    body = TherapistRegisterRequest(
        username="raced_clinician",
        display_name="Raced Clinician",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
        wrap_pub_key=db.spki,
        wrap_key_blob=b64(BLOB),
    )
    original, inserted = db.session.flush, False

    async def collision(*args, **kwargs):
        nonlocal inserted
        if not inserted:
            inserted = True
            await db.session.execute(
                User.__table__.insert().values(
                    id="f" * 32,
                    username="raced_clinician",
                    salt="salt",
                    verifier=b"proof",
                    scrypt_salt=b"salt",
                )
            )
        return await original(*args, **kwargs)

    monkeypatch.setattr(db.session, "flush", collision)
    with pytest.raises(ApiError) as failure:
        await therapist.register_therapist(body, db.request, db.session, None)
    envelope(failure, 409, "username already taken", "conflict")
    assert db.audit == []


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [100, 101])
async def test_replacement_identity_revokes_exact_native_caseload_and_refuses_overflow(
    sharing_db, monkeypatch, count
):
    from app.api import account as account_api, auth
    from app.models import ConsentEvent

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    db.other.notes_keyring_blob = BLOB
    db.other.custody_version = 3
    people = [account(f"{i:032x}") for i in range(1, count + 1)]
    db.session.add_all(people)
    await db.session.flush()
    db.session.add_all(
        [
            Consent(
                id=f"{i:032x}",
                user_id=p.id,
                therapist_id=OTHER,
                status="active",
                disclosure="v3",
                wrapped_key=BLOB,
                ephemeral_pub=db.spki,
                summary_blob=BLOB,
                share_voice=True,
                granted_at=NOW,
            )
            for i, p in enumerate(people, 1)
        ]
    )
    await db.session.commit()
    new_key = replacement_spki()
    body = WrapKeyRotateRequest(
        wrap_pub_key=new_key, wrap_key_blob=b64(BLOB), expected_custody_version=3
    )
    if count == 101:
        with pytest.raises(ApiError) as failure:
            await therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
        envelope(
            failure, 413, "active sharing exceeds the supported rotation size", "payload_too_large"
        )
        assert db.audit == []
    else:
        await therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
        grants = (
            await db.session.scalars(select(Consent).execution_options(populate_existing=True))
        ).all()
        assert len(grants) == 100
        assert all(
            (g.status, g.wrapped_key, g.ephemeral_pub, g.summary_blob, g.share_voice)
            == ("revoked", None, None, None, False)
            for g in grants
        )
        facts = (await db.session.scalars(select(ConsentEvent))).all()
        assert len(facts) == 100
        assert all(
            (f.kind, f.action, f.disclosure, f.share_voice) == ("sharing", "withdrawn", "v3", True)
            for f in facts
        )
        await db.session.refresh(db.other)
        assert db.other.wrap_pub_key == new_key and db.other.wrap_key_blob == BLOB
        assert db.audit[-1]["action"] == "wrap_key_rotate"
        assert len([r for r in db.audit if r["action"] == "sharing_identity_revoke"]) == 100


@pytest.mark.asyncio
async def test_replacement_identity_waits_for_each_active_patients_pending_rotation(
    sharing_db, monkeypatch
):
    from app.api import account as account_api, auth
    from app.models import RekeyJournal

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    db.other.notes_keyring_blob = BLOB
    db.other.custody_version = 3
    await seed_consent(db)
    db.session.add(RekeyJournal(user_id=OWNER))
    await db.session.commit()
    body = WrapKeyRotateRequest(
        wrap_pub_key=replacement_spki(), wrap_key_blob=b64(BLOB), expected_custody_version=3
    )
    with pytest.raises(ApiError) as failure:
        await therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
    envelope(
        failure,
        409,
        "an active patient must finish their pending key rotation first",
        "rekey_in_progress",
    )
    assert db.audit == []


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["rotate", "delete"])
@pytest.mark.parametrize("change", ["epoch", "retirement", "missing"])
async def test_credential_mutations_reauthorize_the_account_after_a_queued_lifecycle(
    sharing_db, monkeypatch, operation, change
):
    from sqlalchemy import delete, update
    from sqlalchemy.ext.asyncio import async_sessionmaker

    from app.api import account as account_api, auth

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    proof_ready = asyncio.Event()
    original_proof = therapist._require_verifier

    async def proven(*args, **kwargs):
        result = await original_proof(*args, **kwargs)
        proof_ready.set()
        return result

    monkeypatch.setattr(therapist, "_require_verifier", proven)
    db.other.notes_keyring_blob = BLOB
    db.other.custody_version = 3
    await db.session.commit()
    body = WrapKeyRotateRequest(
        wrap_pub_key=replacement_spki(), wrap_key_blob=b64(BLOB), expected_custody_version=3
    )
    call = (
        therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
        if operation == "rotate"
        else therapist.delete_therapist_account(db.request, db.other, db.session, b64(AUTH_KEY))
    )
    async with therapist.lifecycle_locks.hold(f"llm-lifecycle:{OTHER}"):
        task = asyncio.create_task(call)
        try:
            await asyncio.wait_for(proof_ready.wait(), timeout=5)
            done, _ = await asyncio.wait({task}, timeout=0.03)
            assert not done, "credential changes must wait for active processing"
            assert db.hash_calls, "password proof must finish before the queued-account check"
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                if change == "missing":
                    await writer.execute(delete(User).where(User.id == OTHER))
                else:
                    values = {"token_epoch": 3} if change == "epoch" else {"is_active": False}
                    await writer.execute(update(User).where(User.id == OTHER).values(**values))
                await writer.commit()
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    with pytest.raises(ApiError) as failure:
        await asyncio.wait_for(task, timeout=1)
    envelope(
        failure,
        *(
            (401, "invalid token", "unauthorized")
            if change == "epoch"
            else (404, "account not found", "not_found")
        ),
    )
    assert db.audit == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "kind",
    ["healthy", "expired", "foreign", "missing_store", "failed_store", "long_id", "feature_off"],
)
async def test_clinician_audio_fetch_preserves_privacy_expiry_and_safe_provider_failures(
    sharing_db, monkeypatch, caplog, kind
):
    from app.models import AudioAttachment, AudioDeletion
    from app.services import audio_store

    db = sharing_db
    await seed_consent(db, share_voice=True)
    key = f"audio/{OWNER}/{'1' * 32}.enc"
    await db.store.put(key, BLOB)
    row = AudioAttachment(
        id="audio-clinical",
        user_id=OTHER if kind == "foreign" else OWNER,
        client_entry_id="voice-1",
        backend="local",
        storage_key=key,
        storage_locator=audio_store.storage_locator(db.store),
        size_bytes=len(BLOB),
        mime_type="audio/webm",
        duration_seconds=3,
        created_at=NOW,
        expires_at=NOW if kind == "expired" else NOW + timedelta(days=1),
    )
    db.session.add(row)
    await db.session.commit()
    if kind == "feature_off":
        db.settings.audio_enabled = False
    if kind == "missing_store":
        monkeypatch.setattr(audio_store, "get_audio_store_cached", lambda _: None)
    if kind == "failed_store":

        async def broken(*args, **kwargs):
            raise audio_store.AudioStoreError("must not echo private provider locator")

        monkeypatch.setattr(type(db.store), "get", broken)
    if kind == "healthy":
        out = await therapist.read_patient_audio(OWNER, row.id, db.request, db.other, db.session)
        assert (out.id, out.blob, out.mime_type, out.duration_seconds) == (
            row.id,
            b64(BLOB),
            "audio/webm",
            3,
        )
        assert [(r["user_id"], r["action"]) for r in db.audit] == [(OWNER, "audio_access")]
    else:
        expected = {
            "expired": (410, "recording expired", "audio_expired"),
            "foreign": (404, "attachment not found", "not_found"),
            "missing_store": (
                503,
                "audio storage is not configured on this server",
                "audio_storage_unconfigured",
            ),
            "failed_store": (502, "audio storage failed", "audio_storage_failed"),
            "long_id": (404, "patient not found", "not_found"),
            "feature_off": (404, "not found", "not_found"),
        }[kind]
        with pytest.raises(ApiError) as failure:
            await therapist.read_patient_audio(
                "a" * 33 if kind == "long_id" else OWNER, row.id, db.request, db.other, db.session
            )
        envelope(failure, *expected)
        assert db.audit == []
        if kind == "expired":
            assert await db.session.get(AudioAttachment, row.id) is None
            tombstone = await db.session.scalar(select(AudioDeletion))
            assert tombstone.storage_key == key
        if kind == "failed_store":
            assert [(r.name, r.getMessage()) for r in caplog.records] == [
                ("mindpattern.therapist", "audio object get failed")
            ]


@pytest.mark.asyncio
@pytest.mark.parametrize("inline_failure", [False, True])
async def test_therapist_erasure_commits_retirement_and_attempts_real_bounded_cleanup(
    sharing_db, monkeypatch, caplog, inline_failure
):
    from app.api import account as account_api, auth
    from app.db import build_sessionmaker
    from app.models import AccountDeletionJob, TherapistNote
    from app.services import account_deletion

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    await seed_consent(db)
    db.session.add_all(
        [
            TherapistNote(
                id=f"{i:032x}",
                therapist_id=OTHER,
                user_id=OWNER,
                client_note_id=f"erase-{i}",
                blob=BLOB,
                created_at=NOW,
                updated_at=NOW,
            )
            for i in range(104)
        ]
    )
    await db.session.commit()
    db.request.app.state.sessionmaker = build_sessionmaker(db.engine)
    db.request.app.state.account_deletion_wakeup = asyncio.Event()
    if inline_failure:

        async def failed(*args, **kwargs):
            raise RuntimeError("sensitive internal database diagnostic")

        monkeypatch.setattr(account_deletion, "purge_one_account_page", failed)
    await therapist.delete_therapist_account(db.request, db.other, db.session, b64(AUTH_KEY))
    await db.session.refresh(db.other)
    assert db.other.is_active is False
    job = await db.session.scalar(select(AccountDeletionJob))
    assert job.user_id == OTHER
    # The inline worker must actually delete a native-size page; a background
    # wakeup alone is insufficient evidence that cleanup was attempted.
    remaining = (await db.session.scalars(select(TherapistNote))).all()
    assert len(remaining) == (104 if inline_failure else 4)
    assert db.request.app.state.account_deletion_wakeup.is_set()
    assert [(r["actor_id"], r["user_id"], r["action"]) for r in db.audit] == [
        (OTHER, OTHER, "account_deleted")
    ]
    if inline_failure:
        assert [(r.name, r.getMessage()) for r in caplog.records] == [
            ("mindpattern.therapist", "bounded therapist purge deferred to background worker")
        ]


@pytest.mark.asyncio
async def test_roster_exact_terminal_page_and_stale_revision_have_authoritative_headers(sharing_db):
    db = sharing_db
    await seed_consent(db)
    response = Response()
    out = await therapist.list_patients(db.request, response, db.other, db.session, 1, 0, "0")
    assert [r.user_id for r in out] == [OWNER]
    assert "X-Next-Offset" not in response.headers
    with pytest.raises(ApiError) as failure:
        await therapist.list_patients(db.request, Response(), db.other, db.session, 1, 0, "1")
    envelope(
        failure,
        409,
        "patients changed while paging; retry the request",
        "collection_changed",
        {"X-Patients-Revision": "0"},
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["entries", "measures"])
async def test_chart_exact_terminal_page_does_not_invent_a_continuation(sharing_db, kind):
    db = sharing_db
    await seed_consent(db)
    rows = await chart_rows(db, kind)
    response = Response()
    out = await read_chart(db, kind, response, limit=3)
    assert [r.id for r in out] == [r.id for r in rows]
    assert "X-Next-Offset" not in response.headers


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["entries", "measures", "insights", "audio"])
async def test_oversized_patient_identifier_refuses_without_waiting_for_clinical_resources(
    sharing_db, operation
):

    db = sharing_db
    if operation in {"entries", "measures"}:
        call = read_chart(db, operation, Response(), revision=None, patient="a" * 33)
    elif operation == "insights":
        call = therapist.read_patient_insights(db.request, "a" * 33, db.other, db.session)
    else:
        call = therapist.read_patient_audio("a" * 33, "missing", db.request, db.other, db.session)
    async with therapist.sharing_locks.hold(therapist.sharing_therapist_lock_key(OTHER)):
        task = asyncio.create_task(call)
        try:
            done, _ = await asyncio.wait({task}, timeout=0.1)
            assert done, "an oversized identifier must refuse before queuing for chart resources"
            with pytest.raises(ApiError) as failure:
                task.result()
            envelope(failure, 404, "patient not found", "not_found")
        finally:
            if not task.done():
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("secret", ["X" * 32, "XXXX"])
async def test_configured_clinician_enrollment_never_accepts_an_absent_header(sharing_db, secret):
    db = sharing_db
    db.settings.therapist_enrollment_token = secret
    body = TherapistRegisterRequest(
        username="gated_clinician",
        display_name="Gated Clinician",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
        wrap_pub_key=db.spki,
        wrap_key_blob=b64(BLOB),
    )
    with pytest.raises(ApiError) as failure:
        await therapist.register_therapist(body, db.request, db.session, None)
    envelope(failure, 404, "not found", "not_found")
    assert db.hash_calls == []


@pytest.mark.asyncio
async def test_wrap_repair_identifies_its_strict_encoded_field(sharing_db, monkeypatch):
    from app.api import account as account_api, auth

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    body = WrapKeyRotateRequest(wrap_pub_key=db.spki, wrap_key_blob="!!!!" + b64(BLOB))
    with pytest.raises(ApiError) as failure:
        await therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
    envelope(failure, 422, "wrap_key_blob must be base64", "validation_error")


@pytest.mark.asyncio
async def test_replacement_identity_withdrawal_uses_the_native_evidence_reserve(
    sharing_db, monkeypatch
):
    from sqlalchemy import func, insert

    from app.api import account as account_api, auth
    from app.models import ConsentEvent

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    db.other.notes_keyring_blob = BLOB
    db.other.custody_version = 3
    await seed_consent(db)
    for start in range(0, 9798, 1000):
        await db.session.execute(
            insert(ConsentEvent),
            [
                dict(id=f"{i:032x}", user_id=OWNER, kind="llm", action="granted", occurred_at=NOW)
                for i in range(start, min(start + 1000, 9798))
            ],
        )
    await db.session.commit()
    body = WrapKeyRotateRequest(
        wrap_pub_key=replacement_spki(), wrap_key_blob=b64(BLOB), expected_custody_version=3
    )
    await therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
    assert await db.session.scalar(select(func.count(ConsentEvent.id))) == 9799
    row = await db.session.scalar(select(ConsentEvent).where(ConsentEvent.action == "withdrawn"))
    assert row.user_id == OWNER and row.kind == "sharing"


@pytest.mark.asyncio
async def test_roster_mixed_active_and_retained_rows_keeps_order_and_audits_each_patient(
    sharing_db,
):
    db = sharing_db
    third = account("d" * 32)
    db.session.add(third)
    await db.session.flush()
    await seed_consent(db, granted_at=NOW)
    db.session.add(
        Consent(
            id="e" * 32,
            user_id=third.id,
            therapist_id=OTHER,
            status="revoked",
            granted_at=NOW - timedelta(seconds=1),
            wrapped_key=None,
        )
    )
    await db.session.commit()
    out = await therapist.list_patients(db.request, Response(), db.other, db.session, 100, 0, "0")
    assert [(r.user_id, r.status, r.wrapped_key) for r in out] == [
        (OWNER, "active", b64(BLOB)),
        (third.id, "revoked", None),
    ]
    assert sorted((r["user_id"], r["action"]) for r in db.audit) == [
        (OWNER, "list_patients"),
        (third.id, "list_patients"),
    ]


@pytest.mark.asyncio
async def test_roster_final_snapshot_refuses_a_real_concurrent_revision_change(
    sharing_db, monkeypatch
):
    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker

    db = sharing_db
    await seed_consent(db)
    real_execute, changed = db.session.execute, False

    async def changed_after_scan(statement, *args, **kwargs):
        nonlocal changed
        result = await real_execute(statement, *args, **kwargs)
        if not changed and "order by consents.granted_at desc" in str(statement).lower():
            changed = True
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(
                    update(User).where(User.id == OTHER).values(patients_revision=1)
                )
                await writer.commit()
        return result

    monkeypatch.setattr(db.session, "execute", changed_after_scan)
    with pytest.raises(ApiError) as failure:
        await therapist.list_patients(db.request, Response(), db.other, db.session, 100, 0, "0")
    envelope(
        failure,
        409,
        "patients changed while paging; retry the request",
        "collection_changed",
        {"X-Patients-Revision": "1"},
    )


@pytest.mark.asyncio
async def test_clinician_audio_waits_for_processing_and_returns_the_latest_kept_recording(
    sharing_db,
):
    from app.api import audio
    from app.db import build_sessionmaker
    from app.models import AudioAttachment
    from tests.test_full_backend_collection_mutation import attachment_body, make_entry

    db = sharing_db
    await seed_consent(db, share_voice=True)
    await make_entry(db, "kept")
    first = await audio.upload_attachment(
        attachment_body("kept"), db.request, db.owner, None, db.session
    )
    cached = await db.session.get(AudioAttachment, first.attachment_id)
    old_key = cached.storage_key
    replacement = b"current recording ciphertext" * 3
    async with build_sessionmaker(db.engine)() as writer:
        patient = await writer.get(User, OWNER)
        await audio.upload_attachment(
            attachment_body("kept", replacement), db.request, patient, None, writer
        )
    assert cached.storage_key == old_key
    db.audit.clear()
    async with therapist.lifecycle_locks.hold(f"llm-lifecycle:{OWNER}"):
        task = asyncio.create_task(
            therapist.read_patient_audio(
                OWNER, first.attachment_id, db.request, db.other, db.session
            )
        )
        try:
            done, _ = await asyncio.wait({task}, timeout=0.1)
            assert not done, "audio serving must wait for active patient processing"
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    out = await asyncio.wait_for(task, timeout=5)
    assert out.blob == b64(replacement) and out.size_bytes == len(replacement)
    assert db.audit[-1]["action"] == "audio_access"


@pytest.mark.asyncio
async def test_patient_and_clinician_registration_share_one_failure_budget_per_username(sharing_db):
    from app.api import auth
    from app.schemas import RegisterRequest

    db = sharing_db
    db.settings.auth_rate_limit = 1
    patient = RegisterRequest(
        username=OTHER,
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
    )
    with pytest.raises(ApiError) as first:
        await auth.register(patient, db.request, db.session)
    assert first.value.status_code == 409
    hashes = len(db.hash_calls)
    clinician = TherapistRegisterRequest(
        username=OTHER,
        display_name="Existing Clinician",
        salt=b64(b"s" * 16),
        verifier=b64(AUTH_KEY),
        age_attestation="minimum_age_confirmed_v1",
        wrap_pub_key=db.spki,
        wrap_key_blob=b64(BLOB),
    )
    with pytest.raises(ApiError) as second:
        await therapist.register_therapist(clinician, db.request, db.session, None)
    assert second.value.status_code == 429
    assert len(db.hash_calls) == hashes


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["entries", "measures"])
async def test_chart_final_revision_failure_names_its_actual_collection(
    sharing_db, monkeypatch, kind
):
    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker

    db = sharing_db
    await seed_consent(db)
    await chart_rows(db, kind)
    model = Entry if kind == "entries" else Measure
    real_execute, changed = db.session.execute, False

    async def changed_after_fetch(statement, *args, **kwargs):
        nonlocal changed
        result = await real_execute(statement, *args, **kwargs)
        columns = getattr(statement, "column_descriptions", [])
        if not changed and any(item.get("expr") is model for item in columns):
            changed = True
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(
                    update(User).where(User.id == OWNER).values({f"{kind}_revision": 6})
                )
                await writer.commit()
        return result

    monkeypatch.setattr(db.session, "execute", changed_after_fetch)
    with pytest.raises(ApiError) as failure:
        await read_chart(db, kind, Response())
    envelope(
        failure,
        409,
        f"{kind} changed while paging; retry the request",
        "collection_changed",
        {f"X-{kind.title()}-Revision": "6"},
    )


@pytest.mark.asyncio
async def test_wrap_identity_rotation_continues_after_a_patient_withdraws_while_it_queues(
    sharing_db, monkeypatch
):
    from sqlalchemy import update

    from app.api import account as account_api, auth
    from app.db import build_sessionmaker

    db = sharing_db
    monkeypatch.setattr(account_api, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    db.other.notes_keyring_blob = BLOB
    db.other.custody_version = 3
    first = await seed_consent(db)
    third = account("d" * 32)
    db.session.add(third)
    await db.session.flush()
    db.session.add(
        Consent(
            id="e" * 32,
            user_id=third.id,
            therapist_id=OTHER,
            status="active",
            granted_at=NOW,
            wrapped_key=BLOB,
            ephemeral_pub=db.spki,
            disclosure="v3",
        )
    )
    await db.session.commit()
    scanned = asyncio.Event()
    real_execute = db.session.execute

    async def observed(statement, *args, **kwargs):
        result = await real_execute(statement, *args, **kwargs)
        if (
            str(statement).lower().startswith("select")
            and "from consents" in str(statement).lower()
        ):
            scanned.set()
        return result

    monkeypatch.setattr(db.session, "execute", observed)
    body = WrapKeyRotateRequest(
        wrap_pub_key=replacement_spki(), wrap_key_blob=b64(BLOB), expected_custody_version=3
    )
    async with therapist.sharing_locks.hold(therapist.sharing_patient_lock_key(OWNER)):
        task = asyncio.create_task(
            therapist.rotate_wrap_key(body, db.request, db.other, db.session, b64(AUTH_KEY))
        )
        try:
            await asyncio.wait_for(scanned.wait(), timeout=5)
            async with build_sessionmaker(db.engine)() as writer:
                await writer.execute(
                    update(Consent)
                    .where(Consent.id == first.id)
                    .values(status="revoked", revoked_at=NOW, wrapped_key=None, ephemeral_pub=None)
                )
                await writer.commit()
        except BaseException:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            raise
    await asyncio.wait_for(task, timeout=5)
    second = await db.session.get(Consent, "e" * 32, populate_existing=True)
    assert second.status == "revoked" and second.wrapped_key is None
    assert (third.id, "sharing_identity_revoke") in [(r["user_id"], r["action"]) for r in db.audit]


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["entries", "measures"])
async def test_chart_metadata_disappearance_has_the_correct_collection_and_durable_audit(
    sharing_db, monkeypatch, kind
):
    from sqlalchemy import delete
    from sqlalchemy.ext.asyncio import async_sessionmaker

    db = sharing_db
    await seed_consent(db)
    rows = await chart_rows(db, kind)
    model = Entry if kind == "entries" else Measure
    real_execute, changed = db.session.execute, False

    async def removed_after_metadata(statement, *args, **kwargs):
        nonlocal changed
        result = await real_execute(statement, *args, **kwargs)
        columns = getattr(statement, "column_descriptions", [])
        if not changed and any(
            item.get("name") == "id" and item.get("entity") is model for item in columns
        ):
            changed = True
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                await writer.execute(delete(model).where(model.id == rows[0].id))
                await writer.commit()
        return result

    monkeypatch.setattr(db.session, "execute", removed_after_metadata)
    with pytest.raises(ApiError) as failure:
        await read_chart(db, kind, Response())
    envelope(
        failure,
        409,
        f"{kind} changed while paging; retry the request",
        "collection_changed",
        {f"X-{kind.title()}-Revision": "5"},
    )
    assert [(r["user_id"], r["action"]) for r in db.audit] == [(OWNER, f"read_{kind}")]


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["withdraw", "remove"])
async def test_roster_fresh_pair_reads_do_not_reuse_stale_grants_or_skip_later_exposures(
    sharing_db, monkeypatch, change
):
    from sqlalchemy import delete, update
    from sqlalchemy.ext.asyncio import async_sessionmaker

    db = sharing_db
    first = await seed_consent(db, granted_at=NOW)
    third = account("d" * 32)
    db.session.add(third)
    await db.session.flush()
    db.session.add(
        Consent(
            id="e" * 32,
            user_id=third.id,
            therapist_id=OTHER,
            status="active",
            granted_at=NOW - timedelta(seconds=1),
            wrapped_key=BLOB,
            ephemeral_pub=db.spki,
        )
    )
    await db.session.commit()
    real_execute, changed = db.session.execute, False

    async def changed_after_metadata(statement, *args, **kwargs):
        nonlocal changed
        result = await real_execute(statement, *args, **kwargs)
        if not changed and "order by consents.granted_at desc" in str(statement).lower():
            changed = True
            async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                statement = (
                    delete(Consent).where(Consent.id == first.id)
                    if change == "remove"
                    else update(Consent)
                    .where(Consent.id == first.id)
                    .values(status="revoked", revoked_at=NOW, wrapped_key=None, ephemeral_pub=None)
                )
                await writer.execute(statement)
                await writer.commit()
        return result

    monkeypatch.setattr(db.session, "execute", changed_after_metadata)
    if change == "withdraw":
        out = await therapist.list_patients(
            db.request, Response(), db.other, db.session, 100, 0, "0"
        )
        assert [(r.user_id, r.status, r.wrapped_key) for r in out] == [
            (OWNER, "revoked", None),
            (third.id, "active", b64(BLOB)),
        ]
    else:
        with pytest.raises(ApiError) as failure:
            await therapist.list_patients(db.request, Response(), db.other, db.session, 100, 0, "0")
        envelope(
            failure,
            409,
            "patients changed while paging; retry the request",
            "collection_changed",
            {"X-Patients-Revision": "0"},
        )
        assert [(r["user_id"], r["action"]) for r in db.audit] == [(third.id, "list_patients")]
