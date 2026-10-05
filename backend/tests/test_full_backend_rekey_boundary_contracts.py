"""Native sharing limits and authorization boundaries during corpus rotation."""

# ruff: noqa: F811 - imported pytest fixtures share names with injected parameters

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from contextlib import asynccontextmanager
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.api import auth, entries, insights, therapist
from app.deps import ApiError
from app.models import AudioAttachment, AudioDeletion, Consent, RekeyJournal, User
from app.schemas import EntryReplace, ProcessingSessionRequest, RekeyConsentWrap
from app.security import crypto
from app.security.entry_guard import validate_entry_guard
from app.services import audio_store
from tests.test_full_backend_authentication_mutation import (
    AUTH_KEY,
    PARAMS,
    authentication_db,  # noqa: F401 - imported fixture dependency
    hash_proof,
)
from tests.test_full_backend_collection_mutation import (
    NOW,
    OTHER,
    OWNER,
    account,
    b64,
    collection_db,  # noqa: F401 - imported fixture dependency
    envelope,
)
from tests.test_full_backend_rekey_contracts import (
    NEW,
    OLD,
    OPERATION,
    body,
    invoke as invoke_rotation,
    rekey_db,  # noqa: F401 - shared isolated fixture
    seed_corpus,
    tokens,
)


def public_key():
    return b64(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )


async def invoke(*args, **options):
    # Even a multi-page test corpus must settle without an unbounded loop.
    return await asyncio.wait_for(invoke_rotation(*args, **options), 5)


async def sharing_rows(db, count=1):
    key = public_key()
    wraps = []
    for index in range(count):
        clinician = f"{index + 10000:032x}"
        identifier = f"{index + 20000:032x}"
        clinician_row = account(clinician, role="therapist", wrap_pub_key=key)
        db.session.add(clinician_row)
        await db.session.flush([clinician_row])
        db.session.add(
            Consent(
                id=identifier,
                user_id=OWNER,
                therapist_id=clinician,
                status="active",
                disclosure="v3",
                ephemeral_pub=key,
                wrapped_key=b"old-wrap",
                granted_at=NOW,
            )
        )
        wraps.append(
            RekeyConsentWrap(
                consent_id=identifier,
                therapist_wrap_pub_key=key,
                ephemeral_pub=key,
                wrapped_key=b64(b"w" * 60),
            )
        )
    await db.session.commit()
    return wraps


@pytest.mark.parametrize("count", [100, 101])
async def test_rekey_native_hundred_live_relationship_boundary_is_exact(rekey_db, count):
    db = rekey_db
    wraps = await sharing_rows(db, count)
    data = body(consent_wraps=wraps[:100])
    if count == 101:
        with pytest.raises(ApiError) as failure:
            await invoke(db, data)
        envelope(
            failure,
            413,
            "active sharing exceeds the supported rotation size",
            "payload_too_large",
        )
        await db.session.refresh(db.owner)
        assert db.owner.token_epoch == 2 and not db.audit
        assert not list((await db.session.scalars(select(RekeyJournal))).all())
    else:
        result = await invoke(db, data)
        assert (result.entries, result.insights, result.measures, result.audio) == (0, 0, 0, 0)
        assert result.consents_rewrapped == 100 and result.credential_rotated
        grants = list((await db.session.scalars(select(Consent))).all())
        assert len(grants) == 100 and all(row.wrapped_key == b"w" * 60 for row in grants)
        await db.session.refresh(db.owner)
        assert db.owner.consents_revision == 1
        clinicians = list(
            (
                await db.session.scalars(
                    select(User).where(User.role == "therapist", User.id != OTHER)
                )
            ).all()
        )
        assert len(clinicians) == 100 and all(row.patients_revision == 1 for row in clinicians)


@pytest.mark.parametrize(
    "variant,detail",
    [
        ("duplicate", "duplicate consent identifier"),
        ("ephemeral", "invalid sharing key"),
        ("therapist", "invalid sharing key"),
        ("encoding", "wrapped_key must be base64"),
        ("short", "invalid consent envelope size"),
        ("long", "invalid consent envelope size"),
    ],
)
async def test_rekey_consent_wrap_validation_is_exact_before_consuming_keys(
    rekey_db, variant, detail
):
    db = rekey_db
    wraps = await sharing_rows(db)
    values = {
        "ephemeral": {"ephemeral_pub": "not-a-public-key"},
        "therapist": {"therapist_wrap_pub_key": "not-a-public-key"},
        "encoding": {"wrapped_key": "!!!!"},
        "short": {"wrapped_key": b64(b"w" * 59)},
        "long": {"wrapped_key": b64(b"w" * 61)},
    }
    wraps = wraps * 2 if variant == "duplicate" else [wraps[0].model_copy(update=values[variant])]
    old, new = tokens(db)
    with pytest.raises(ApiError) as failure:
        await invoke(db, body(consent_wraps=wraps), old, new)
    envelope(failure, 422, detail, "validation_error")
    store = db.request.app.state.key_store
    assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW
    assert not db.audit


async def test_rekey_v2_invalid_kdf_profile_is_a_flat_validation_error(rekey_db):
    db = rekey_db
    db.owner.key_scheme = "v2"
    await db.session.commit()
    invalid = {**PARAMS, "algorithm": "unknown"}
    old, new = tokens(db)
    with pytest.raises(ApiError) as failure:
        await invoke(
            db, body(new_wrapped_data_key=b64(b"w" * 60), new_kdf_params=invalid), old, new
        )
    envelope(
        failure,
        422,
        "kdf_params.algorithm must be 'pbkdf2-sha256' or 'argon2id'",
        "validation_error",
    )
    store = db.request.app.state.key_store
    assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW


@pytest.mark.parametrize("missing", ["old", "new"])
async def test_rekey_requires_each_of_its_two_real_processing_tokens(rekey_db, missing):
    db = rekey_db
    old, new = tokens(db)
    with pytest.raises(ApiError) as failure:
        await insights.rekey(
            db.request,
            body(),
            db.owner,
            None if missing == "old" else old,
            None if missing == "new" else new,
            b64(AUTH_KEY),
        )
    envelope(
        failure,
        422,
        "two processing session tokens required (X-Processing-Token, X-New-Processing-Token)",
        "validation_error",
    )
    store = db.request.app.state.key_store
    assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW


@pytest.mark.parametrize("phase", [1, 2])
@pytest.mark.parametrize("changed", ["inactive", "missing", "revoked"])
async def test_rekey_reauthorizes_each_lifecycle_entry_against_actual_retirement_or_logout(
    rekey_db, monkeypatch, phase, changed
):
    db = rekey_db
    original = insights.lifecycle_locks
    entered = 0

    class RetiringFence:
        @asynccontextmanager
        async def hold(self, key):
            nonlocal entered
            entered += 1
            if entered == phase:
                async with async_sessionmaker(db.engine, expire_on_commit=False)() as writer:
                    if changed == "missing":
                        await writer.execute(delete(User).where(User.id == OWNER))
                    elif changed == "inactive":
                        await writer.execute(
                            update(User).where(User.id == OWNER).values(is_active=False)
                        )
                    else:
                        await db.request.app.state.token_revocations.revoke_durable(
                            writer, db.request.state.mindpattern_token_jti, time.time() + 3600
                        )
                    await writer.commit()
            async with original.hold(key):
                yield

    monkeypatch.setattr(insights, "lifecycle_locks", RetiringFence())
    with pytest.raises(ApiError) as failure:
        await invoke(db)
    envelope(failure, 401, "invalid token", "unauthorized")
    assert not db.audit


async def test_rekey_second_lifecycle_entry_serializes_with_other_real_account_work(
    rekey_db, monkeypatch
):
    db = rekey_db
    at_hash = asyncio.Event()
    continue_hash = asyncio.Event()
    original_hash = auth.hash_verifier_off_loop

    async def new_credentials(key, salt, **options):
        if key == b"v" * 32:
            at_hash.set()
            await asyncio.wait_for(continue_hash.wait(), 2)
        return await original_hash(key, salt, **options)

    monkeypatch.setattr(auth, "hash_verifier_off_loop", new_credentials)
    task = asyncio.create_task(invoke(db))
    try:
        await asyncio.wait_for(at_hash.wait(), 2)
        async with insights.lifecycle_locks.hold(f"llm-lifecycle:{OWNER}"):
            continue_hash.set()
            done, _ = await asyncio.wait({task}, timeout=0.5)
            assert not done and not db.audit
        assert (await asyncio.wait_for(task, 2)).credential_rotated
    finally:
        continue_hash.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)


async def test_rekey_refuses_a_changed_live_therapist_key_before_journal_creation(rekey_db):
    db = rekey_db
    wraps = await sharing_rows(db)
    wraps[0] = wraps[0].model_copy(update={"therapist_wrap_pub_key": public_key()})
    with pytest.raises(ApiError) as failure:
        await invoke(db, body(consent_wraps=wraps))
    envelope(
        failure,
        409,
        "therapist sharing key changed; rebuild the atomic rotation",
        "conflict",
    )
    assert not db.audit and not list((await db.session.scalars(select(RekeyJournal))).all())


async def test_rekey_committed_retry_treats_kdf_mapping_order_as_the_same_payload(rekey_db):
    db = rekey_db
    db.owner.key_scheme = "v2"
    await db.session.commit()
    original = body(new_wrapped_data_key=b64(b"w" * 60), new_kdf_params=PARAMS)
    first = await invoke(db, original)
    reordered = original.model_copy(update={"new_kdf_params": dict(reversed(list(PARAMS.items())))})
    old, new = tokens(db)
    second = await invoke(db, reordered, old, new)
    assert second.model_dump() == first.model_dump()
    store = db.request.app.state.key_store
    assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW
    assert len(db.audit) == 1


async def audio_rows(db, keys):
    rows = []
    for index, key in enumerate(keys):
        identifier = f"{index + 1:032x}"
        client = f"audio-{index}"
        storage_key = f"audio/{OWNER}/{identifier}.enc"
        aad = crypto.build_aad("audio", OWNER, client, "1")
        blob = crypto.encrypt(key, f"recording-{index}".encode(), aad)
        await db.store.put(storage_key, blob)
        row = AudioAttachment(
            id=identifier,
            user_id=OWNER,
            client_entry_id=client,
            backend=db.store.backend,
            storage_key=storage_key,
            storage_locator=audio_store.storage_locator(db.store),
            size_bytes=len(blob),
            mime_type="audio/webm",
            duration_seconds=3,
            content_version=1,
            created_at=NOW,
            expires_at=NOW + timedelta(days=1),
        )
        db.session.add(row)
        rows.append(row)
    await db.session.commit()
    return rows


async def test_rekey_audio_resume_counts_already_new_rows_and_keeps_walking(rekey_db):
    db = rekey_db
    rows = await audio_rows(db, [NEW, OLD])
    original_keys = [row.storage_key for row in rows]
    result = await invoke(db)
    assert result.audio == 2
    for index, row in enumerate(rows):
        await db.session.refresh(row)
        plaintext = crypto.decrypt(
            NEW,
            await db.store.get(row.storage_key, max_bytes=1024),
            crypto.build_aad("audio", OWNER, row.client_entry_id, "1"),
        )
        assert plaintext == f"recording-{index}".encode()
    assert rows[0].storage_key == original_keys[0] and rows[1].storage_key != original_keys[1]
    tombstones = list((await db.session.scalars(select(AudioDeletion))).all())
    assert len(tombstones) == 1 and tombstones[0].storage_key == original_keys[1]


async def test_rekey_partial_audio_put_leaves_a_lease_then_actual_worker_cleans_the_orphan(
    rekey_db, monkeypatch
):
    db = rekey_db
    original = (await audio_rows(db, [OLD]))[0]
    original_key = original.storage_key
    original_put = db.store.put
    uploaded = []

    async def interrupted_upload(key, blob):
        await original_put(key, blob)
        uploaded.append(key)
        raise audio_store.AudioStoreError("interrupted provider response")

    monkeypatch.setattr(db.store, "put", interrupted_upload)
    with pytest.raises(audio_store.AudioStoreError):
        await invoke(db)
    assert len(uploaded) == 1
    orphan = uploaded[0]
    await db.session.refresh(original)
    assert original.storage_key == original_key
    assert await db.store.get(original_key, max_bytes=1024)
    assert await db.store.get(orphan, max_bytes=1024)
    pending = (await db.session.scalars(select(AudioDeletion))).one()
    assert (pending.owner_id, pending.storage_key) == (OWNER, orphan)
    monkeypatch.setattr(audio_store, "utcnow", lambda: NOW + timedelta(minutes=30))
    assert await audio_store.drain_audio_deletions(db.session, db.settings) == 0
    assert await db.store.get(orphan, max_bytes=1024)
    monkeypatch.setattr(audio_store, "utcnow", lambda: NOW + timedelta(hours=1))
    assert await audio_store.drain_audio_deletions(db.session, db.settings) == 1
    with pytest.raises(audio_store.AudioStoreError):
        await db.store.get(orphan, max_bytes=1024)
    assert await db.store.get(original_key, max_bytes=1024)
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2 and not db.audit


async def test_rekey_provider_retry_rewalks_native_batches_and_counts_every_new_generation(
    rekey_db, monkeypatch
):
    db = rekey_db
    entries = await seed_corpus(db, 101)
    audio = (await audio_rows(db, [OLD]))[0]
    original_key = audio.storage_key
    original_put = db.store.put

    async def unavailable(key, blob):
        raise audio_store.AudioStoreError("provider unavailable")

    monkeypatch.setattr(db.store, "put", unavailable)
    with pytest.raises(audio_store.AudioStoreError):
        await invoke(db)
    journal = (await db.session.scalars(select(RekeyJournal))).one()
    assert journal.entries_done == 101 and journal.measures_done == 101
    assert journal.insights_done == 3 and journal.stage == "measures"
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2 and not db.audit
    monkeypatch.setattr(db.store, "put", original_put)
    result = await invoke(db)
    assert (result.entries, result.insights, result.measures, result.audio) == (101, 3, 101, 1)
    assert result.credential_rotated and not result.recovery_invalidated
    assert not list((await db.session.scalars(select(RekeyJournal))).all())
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 3 and len(db.audit) == 1
    for row in entries:
        await db.session.refresh(row)
        assert (
            crypto.decrypt(
                NEW,
                row.blob,
                crypto.entry_aad_v2(OWNER, row.client_entry_id, row.content_version),
            )
            == f"entry-{int(row.id, 16) - 1}".encode()
        )
    await db.session.refresh(audio)
    assert audio.storage_key != original_key


async def test_rekey_over_capacity_refusal_does_not_queue_on_another_clinicians_work(rekey_db):
    db = rekey_db
    wraps = await sharing_rows(db, 101)
    clinician = (await db.session.get(Consent, wraps[0].consent_id)).therapist_id
    async with insights.sharing_locks.hold(insights.sharing_therapist_lock_key(clinician)):
        with pytest.raises(ApiError) as failure:
            await asyncio.wait_for(invoke(db, body(consent_wraps=wraps)), 0.3)
    envelope(
        failure,
        413,
        "active sharing exceeds the supported rotation size",
        "payload_too_large",
    )
    assert not db.audit


async def test_rekey_failed_preflight_releases_its_lifecycle_for_the_next_real_request(rekey_db):
    db = rekey_db
    await sharing_rows(db)
    with pytest.raises(ApiError) as failure:
        await invoke(db)
    envelope(failure, 409, "active sharing changed; rebuild the atomic rotation", "conflict")
    # Retaining an exception for diagnostics must not retain its API lock.
    minted = await asyncio.wait_for(
        insights.create_processing_session(
            ProcessingSessionRequest(data_key=b64(OLD)), db.request, db.owner, db.session
        ),
        0.3,
    )
    assert db.request.app.state.key_store.get(minted.session_token, owner=OWNER) == OLD


async def test_rekey_rejects_legacy_aad_replacement_after_a_real_modern_generation_upgrade(
    rekey_db,
):
    db = rekey_db
    row = (await seed_corpus(db, 1))[0]
    await invoke(db)
    await db.session.refresh(db.owner)
    await db.session.refresh(row)
    assert validate_entry_guard(row, db.settings) is True
    replacement = crypto.encrypt(
        NEW, b"legacy-format replay", crypto.entry_aad_v1(OWNER, row.client_entry_id)
    )
    await entries.replace_entry(
        row.client_entry_id,
        EntryReplace(blob=b64(replacement), entry_date=NOW.date(), content_version=2),
        db.request,
        db.owner,
        db.session,
    )
    await db.session.refresh(row)
    assert row.blob == replacement and validate_entry_guard(row, db.settings) is True
    db.request.state.mindpattern_token_epoch = 3
    old, new = tokens(db, old=NEW, new=b"z" * 32)
    payload = body().model_copy(update={"operation_id": "22345678-1234-1234-1234-123456789abc"})
    with pytest.raises(ApiError) as failure:
        await invoke(db, payload, old, new, b64(b"v" * 32))
    envelope(
        failure,
        400,
        "old key did not authenticate every blob; already-completed batches remain rekeyed and the retry resumes from the journal. Verify the account's current data key and retry.",
        "rekey_key_mismatch",
    )
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 3 and len(db.audit) == 1


async def test_rekey_refuses_tampered_entry_metadata_before_any_ciphertext_write(rekey_db):
    db = rekey_db
    row = (await seed_corpus(db, 1))[0]
    original = bytes(row.blob)
    row.aad_guard_mac = "0" * 64
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await invoke(db)
    envelope(failure, 400, "entry blob failed authentication", "entry_blob_invalid")
    await db.session.refresh(row)
    await db.session.refresh(db.owner)
    assert row.blob == original and db.owner.token_epoch == 2 and not db.audit


async def test_rekey_resumes_its_exact_bound_request_after_real_clinician_erasure(
    rekey_db, monkeypatch
):
    db = rekey_db
    wraps = await sharing_rows(db)
    await audio_rows(db, [OLD])
    data = body(consent_wraps=wraps)
    original_put = db.store.put

    async def unavailable(key, blob):
        raise audio_store.AudioStoreError("provider unavailable")

    monkeypatch.setattr(db.store, "put", unavailable)
    with pytest.raises(audio_store.AudioStoreError):
        await invoke(db, data)
    journal = (await db.session.scalars(select(RekeyJournal))).one()
    assert journal.operation_id == data.operation_id and journal.request_digest
    grant = await db.session.get(Consent, wraps[0].consent_id)
    clinician = await db.session.get(User, grant.therapist_id)
    clinician.scrypt_salt = b"s" * 16
    clinician.verifier = hash_proof(AUTH_KEY, clinician.scrypt_salt)
    await db.session.commit()
    db.request.app.state.account_deletion_wakeup = asyncio.Event()
    db.request.app.state.account_deletion_backlog = False

    async def audit(session, **values):
        db.audit.append(values)

    monkeypatch.setattr(therapist, "append_access_log", audit)
    await therapist.delete_therapist_account(db.request, clinician, db.session, b64(AUTH_KEY))
    assert await db.session.get(Consent, wraps[0].consent_id, populate_existing=True) is None
    monkeypatch.setattr(db.store, "put", original_put)
    result = await invoke(db, data)
    assert result.consents_rewrapped == 0 and result.audio == 1 and result.credential_rotated
    assert [event["action"] for event in db.audit] == [
        "account_deleted",
        "corpus_credential_rotated",
    ]
    assert not list((await db.session.scalars(select(RekeyJournal))).all())


async def test_rekey_skips_revoked_wraps_and_still_updates_the_next_live_relationship(rekey_db):
    db = rekey_db
    wraps = await sharing_rows(db, 2)
    revoked = await db.session.get(Consent, wraps[0].consent_id)
    revoked.status = "revoked"
    revoked.revoked_at = NOW
    await db.session.commit()
    result = await invoke(db, body(consent_wraps=wraps))
    await db.session.refresh(revoked)
    live = await db.session.get(Consent, wraps[1].consent_id, populate_existing=True)
    assert result.consents_rewrapped == 1
    assert revoked.wrapped_key == b"old-wrap" and live.wrapped_key == b"w" * 60


async def test_rekey_does_not_recreate_wraps_for_a_logically_retired_clinician(rekey_db):
    db = rekey_db
    wraps = await sharing_rows(db)
    grant = await db.session.get(Consent, wraps[0].consent_id)
    clinician = await db.session.get(User, grant.therapist_id)
    clinician.is_active = False
    await db.session.commit()
    result = await invoke(db, body(consent_wraps=wraps))
    await db.session.refresh(grant)
    await db.session.refresh(db.owner)
    await db.session.refresh(clinician)
    assert result.consents_rewrapped == 0 and grant.wrapped_key == b"old-wrap"
    assert db.owner.consents_revision == 0 and clinician.patients_revision == 0


async def test_rekey_refuses_a_foreign_only_consent_wrap_before_any_journal_or_write(rekey_db):
    db = rekey_db
    wraps = await sharing_rows(db)
    grant = await db.session.get(Consent, wraps[0].consent_id)
    grant.user_id = OTHER
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await invoke(db, body(consent_wraps=wraps))
    envelope(failure, 409, "active sharing changed; rebuild the atomic rotation", "conflict")
    assert not db.audit and not list((await db.session.scalars(select(RekeyJournal))).all())
    await db.session.refresh(grant)
    assert grant.wrapped_key == b"old-wrap"


async def test_rekey_initial_lifecycle_wait_does_not_consume_processing_sessions(rekey_db):
    db = rekey_db
    old, new = tokens(db)
    async with insights.lifecycle_locks.hold(f"llm-lifecycle:{OWNER}"):
        task = asyncio.create_task(invoke(db, old_token=old, new_token=new))
        try:
            done, _ = await asyncio.wait({task}, timeout=0.3)
            assert not done
            store = db.request.app.state.key_store
            assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_rekey_previous_epoch_can_retry_only_the_original_completed_operation(rekey_db):
    db = rekey_db
    await invoke(db)
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 3 and db.request.state.mindpattern_token_epoch == 2
    data = body().model_copy(update={"operation_id": "22345678-1234-1234-1234-123456789abc"})
    old, new = tokens(db)
    with pytest.raises(ApiError) as failure:
        await invoke(db, data, old, new, b64(b"v" * 32))
    envelope(failure, 401, "invalid token", "unauthorized")
    store = db.request.app.state.key_store
    assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW
    assert len(db.audit) == 1


async def test_rekey_native_foreign_key_commit_failure_returns_gone_and_rolls_back_credentials(
    rekey_db, monkeypatch
):
    db = rekey_db
    # Obtain the real driver diagnostic from the deployed FK schema, then
    # inject that database fault at final commit without changing source.
    async with async_sessionmaker(db.engine, expire_on_commit=False)() as failing:
        failing.add(
            Consent(
                user_id="missing-patient",
                therapist_id=OTHER,
                status="active",
                disclosure="v3",
                ephemeral_pub="unused",
                wrapped_key=b"unused",
                granted_at=NOW,
            )
        )
        with pytest.raises(IntegrityError) as native:
            await failing.commit()
        native_error = native.value
        await failing.rollback()
    assert insights._is_fk_violation(native_error)
    original_commit = AsyncSession.commit

    async def commit(session):
        finalizing = any(
            isinstance(row, User) and row.id == OWNER and row.token_epoch == 3
            for row in session.identity_map.values()
        )
        if finalizing:
            raise native_error
        return await original_commit(session)

    monkeypatch.setattr(AsyncSession, "commit", commit)
    with pytest.raises(ApiError) as failure:
        await invoke(db)
    envelope(failure, 410, "account no longer exists", "account_deleted")
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2 and db.owner.verifier == hash_proof(AUTH_KEY, b"s" * 16)
    assert len(list((await db.session.scalars(select(RekeyJournal))).all())) == 1


async def test_rekey_accepts_a_previously_committed_canonical_operation_after_restart(rekey_db):
    db = rekey_db
    payload = body()
    prior_response = dict(
        entries=0,
        insights=0,
        measures=0,
        audio=0,
        recovery_invalidated=False,
        credential_rotated=True,
        operation_id=OPERATION,
        consents_rewrapped=0,
    )
    # Persisted operation data belongs to the protocol written by the
    # previous deployment. The oracle checks actual retry acceptance, not
    # a source checksum or a literal digest value.
    prior_digest = hashlib.sha256(
        json.dumps(
            {"payload": payload.model_dump(), "old_verifier": b64(AUTH_KEY)},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()
    db.owner.token_epoch = 3
    db.owner.salt = payload.new_salt
    db.owner.verifier = hash_proof(b"v" * 32, db.owner.scrypt_salt)
    db.owner.entries_revision = 1
    db.owner.measures_revision = 1
    db.owner.rekey_operation_id = OPERATION
    db.owner.rekey_operation_digest = prior_digest
    db.owner.rekey_operation_epoch = 3
    db.owner.rekey_operation_result = json.dumps(prior_response)
    await db.session.commit()
    old, new = tokens(db)
    result = await invoke(db, payload, old, new)
    assert result.model_dump() == prior_response
    store = db.request.app.state.key_store
    assert store.get(old, owner=OWNER) == OLD and store.get(new, owner=OWNER) == NEW
    assert not db.audit and not db.flushed


@pytest.mark.parametrize("changed", ["removed", "replaced"])
async def test_rekey_external_audio_pointer_change_during_provider_io_fails_closed(
    rekey_db, monkeypatch, changed
):
    db = rekey_db
    row = (await audio_rows(db, [OLD]))[0]
    identifier = row.id
    original_storage_key = row.storage_key
    original_put = db.store.put
    written = []
    replacement_key = f"audio/{OWNER}/externally-replaced.enc"

    async def changed_pointer(key, value):
        await original_put(key, value)
        written.append(key)
        # Provider I/O occurs outside the pooled transaction. A durable
        # database repair or external writer can invalidate the metadata
        # snapshot independently of this process's lifecycle fence.
        async with async_sessionmaker(db.engine, expire_on_commit=False)() as external:
            statement = (
                delete(AudioAttachment).where(AudioAttachment.id == identifier)
                if changed == "removed"
                else update(AudioAttachment)
                .where(AudioAttachment.id == identifier)
                .values(storage_key=replacement_key)
            )
            await external.execute(statement)
            await external.commit()

    monkeypatch.setattr(db.store, "put", changed_pointer)
    with pytest.raises(ApiError) as failure:
        await invoke(db)
    envelope(failure, 409, "audio changed during rekey", "conflict")
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2 and not db.audit and not db.flushed
    current = await db.session.get(AudioAttachment, identifier, populate_existing=True)
    if changed == "removed":
        assert current is None
    else:
        assert current.storage_key == replacement_key
    assert len(written) == 1 and written[0] != original_storage_key
    pending = list((await db.session.scalars(select(AudioDeletion))).all())
    assert len(pending) == 1 and pending[0].storage_key == written[0]
    assert await db.store.get(original_storage_key)
    assert await db.store.get(written[0])
