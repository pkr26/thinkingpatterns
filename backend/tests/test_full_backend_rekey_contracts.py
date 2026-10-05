"""Real resumable encrypted-corpus rotation and atomic credential contracts."""

# ruff: noqa: F811
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import event, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.api import _audit, account, auth, insights
from app.deps import ApiError
from app.locks import UserLocks
from app.models import (
    AudioAttachment,
    AudioDeletion,
    Consent,
    Entry,
    Insight,
    Measure,
    RekeyJournal,
)
from app.schemas import RekeyConsentWrap, RekeyRequest
from app.security import crypto
from app.security.enclave import InMemoryKeyStore, KeyNotFound
from app.security.entry_guard import seal_entry_guard, validate_entry_guard
from app.services.audio_store import storage_locator
from tests.test_full_backend_authentication_mutation import (
    AUTH_KEY,
    PARAMS,
    authentication_db,
    hash_proof,  # noqa: F401
)
from tests.test_full_backend_collection_mutation import (
    NOW,
    OTHER,
    OWNER,
    b64,
    collection_db,
    envelope,  # noqa: F401
)

OLD = bytearray(b"o" * 32)
NEW = bytearray(b"n" * 32)
OPERATION = "12345678-1234-1234-1234-123456789abc"


@pytest_asyncio.fixture
async def rekey_db(authentication_db, monkeypatch):
    db = authentication_db
    monkeypatch.setattr(account, "hash_verifier_off_loop", auth.hash_verifier_off_loop)
    monkeypatch.setattr(insights, "lifecycle_locks", UserLocks())
    monkeypatch.setattr(insights, "_entry_locks", UserLocks())
    monkeypatch.setattr(insights, "_recompute_locks", UserLocks())
    monkeypatch.setattr(insights, "sharing_locks", UserLocks())
    monkeypatch.setattr(insights, "utcnow", lambda: NOW)
    db.request.app.state.sessionmaker = async_sessionmaker(db.engine, expire_on_commit=False)
    db.request.app.state.key_store = InMemoryKeyStore(max_sessions_per_owner=8)
    db.request.state.mindpattern_token_epoch = 2
    db.request.state.mindpattern_token_jti = "j" * 32
    db.request.app.state.metrics = SimpleNamespace(observe_audit_journal_failure=lambda: None)
    db.flushed = []

    async def flush(session, path, **kw):
        db.flushed.append(path)

    async def audit(session, **values):
        db.audit.append(values)

    monkeypatch.setattr(_audit, "append_access_log", audit)
    monkeypatch.setattr(_audit, "flush_audit_journal", flush)
    yield db


def body(**changes):
    return RekeyRequest(
        operation_id=OPERATION, new_salt=b64(b"s" * 16), new_verifier=b64(b"v" * 32), **changes
    )


def tokens(db, old=OLD, new=NEW):
    store = db.request.app.state.key_store
    return store.create(old, 60, owner=OWNER), store.create(new, 60, owner=OWNER)


async def invoke(db, payload=None, old_token=None, new_token=None, proof=b64(AUTH_KEY)):
    if old_token is None and new_token is None:
        old_token, new_token = tokens(db)
    reads = {}

    def observe(connection, cursor, statement, parameters, context, executemany):
        normalized = statement.lower()
        if not normalized.startswith("select"):
            return
        # These fixtures contain at most 101 entries/measures or one audio
        # object. The native 100-row keyset page needs two populated reads
        # plus a terminal read; a spare read avoids incidental coupling.
        for table in ("entries", "measures", "audio_attachments"):
            if f"from {table}" in normalized:
                reads[table] = reads.get(table, 0) + 1
                assert reads[table] <= 4, f"rotation {table} scan failed to make bounded progress"

    event.listen(db.engine.sync_engine, "before_cursor_execute", observe)
    try:
        return await insights.rekey(
            db.request, payload or body(), db.owner, old_token, new_token, proof
        )
    finally:
        event.remove(db.engine.sync_engine, "before_cursor_execute", observe)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "variant,status,detail,code",
    [
        (
            "missing-proof",
            422,
            "account verifier required (X-Account-Verifier header)",
            "validation_error",
        ),
        (
            "missing-body",
            409,
            "upgrade the client to atomically rotate keys and credentials",
            "upgrade_required",
        ),
        ("bad-salt", 422, "invalid credential encoding", "validation_error"),
        ("bad-verifier", 422, "invalid credential encoding", "validation_error"),
        ("short-salt", 422, "invalid credential size", "validation_error"),
        ("long-salt", 422, "invalid credential size", "validation_error"),
        ("short-verifier", 422, "invalid credential size", "validation_error"),
        ("long-verifier", 422, "invalid credential size", "validation_error"),
        ("v1-envelope", 422, "v1 rotation cannot install a v2 envelope", "validation_error"),
        ("v1-params", 422, "v1 rotation cannot install a v2 envelope", "validation_error"),
        (
            "v2-missing-envelope",
            422,
            "v2 rotation requires the new envelope and KDF parameters",
            "validation_error",
        ),
        (
            "v2-missing-params",
            422,
            "v2 rotation requires the new envelope and KDF parameters",
            "validation_error",
        ),
        ("v2-short-envelope", 422, "invalid data key envelope size", "validation_error"),
        ("v2-long-envelope", 422, "invalid data key envelope size", "validation_error"),
        ("v2-invalid-envelope", 422, "new_wrapped_data_key must be base64", "validation_error"),
        ("wrong-proof", 403, "invalid credentials", "verification_failed"),
        (
            "no-tokens",
            422,
            "two processing session tokens required (X-Processing-Token, X-New-Processing-Token)",
            "validation_error",
        ),
        (
            "missing-new",
            403,
            "new-key processing session missing or expired",
            "processing_session_invalid",
        ),
        ("missing-old", 403, "processing session missing or expired", "processing_session_invalid"),
        (
            "same-key",
            422,
            "a corpus rotation requires a different new data key",
            "validation_error",
        ),
    ],
)
async def test_rekey_validation_refuses_unsafe_credentials_without_partial_writes(
    rekey_db, variant, status, detail, code
):
    db = rekey_db
    data = body()
    proof = b64(AUTH_KEY)
    old, new = tokens(db, new=OLD if variant == "same-key" else NEW)
    if variant.startswith("v2"):
        db.owner.key_scheme = "v2"
        await db.session.commit()
        data.new_kdf_params = PARAMS
        data.new_wrapped_data_key = b64(b"e" * 60)
    changes = {
        "bad-salt": ("new_salt", "!!!!"),
        "bad-verifier": ("new_verifier", "!!!!"),
        "short-salt": ("new_salt", b64(b"s" * 15)),
        "long-salt": ("new_salt", b64(b"s" * 17)),
        "short-verifier": ("new_verifier", b64(b"v" * 31)),
        "long-verifier": ("new_verifier", b64(b"v" * 33)),
        "v1-envelope": ("new_wrapped_data_key", b64(b"e" * 60)),
        "v1-params": ("new_kdf_params", PARAMS),
        "v2-missing-envelope": ("new_wrapped_data_key", None),
        "v2-missing-params": ("new_kdf_params", None),
        "v2-short-envelope": ("new_wrapped_data_key", b64(b"e" * 59)),
        "v2-long-envelope": ("new_wrapped_data_key", b64(b"e" * 61)),
        "v2-invalid-envelope": ("new_wrapped_data_key", "!!!!"),
    }
    if variant in changes:
        setattr(data, *changes[variant])
    if variant == "missing-proof":
        proof = None
    if variant == "missing-body":
        data = None
    if variant == "wrong-proof":
        proof = b64(b"x" * 32)
    if variant == "no-tokens":
        old = new = None
    if variant == "missing-new":
        new = "missing"
    if variant == "missing-old":
        old = "missing"
    with pytest.raises(ApiError) as failure:
        await insights.rekey(db.request, data, db.owner, old, new, proof)
    envelope(failure, status, detail, code)
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2 and db.owner.verifier == hash_proof(AUTH_KEY, b"s" * 16)
    assert not list((await db.session.scalars(select(Entry))).all())
    if variant in ["wrong-proof", "missing-new"]:
        assert db.request.app.state.key_store.get(old, owner=OWNER) == OLD


async def seed_corpus(db, count=3, foreign=True, unknown_last=False):
    rows = []
    for i in range(count):
        cid = f"e{i}"
        key = bytearray(b"x" * 32) if unknown_last and i == count - 1 else OLD
        row = Entry(
            id=f"{i + 1:032x}",
            user_id=OWNER,
            client_entry_id=cid,
            entry_date=NOW.date(),
            received_at=NOW,
            blob=crypto.encrypt(key, f"entry-{i}".encode(), crypto.entry_aad_v2(OWNER, cid, 1)),
            content_version=1,
        )
        seal_entry_guard(row, db.settings, v2_bound=True)
        rows.append(row)
        db.session.add(row)
        db.session.add(
            Measure(
                id=f"{i + 1000:032x}",
                user_id=OWNER,
                client_measure_id=f"m{i}",
                measure_date=NOW.date(),
                blob=crypto.encrypt(
                    OLD, f"measure-{i}".encode(), crypto.build_aad("measure", OWNER, f"m{i}")
                ),
            )
        )
    for kind in ["brain", "patterns"]:
        db.session.add(
            Insight(
                user_id=OWNER,
                kind=kind,
                state_seq=7,
                blob=crypto.encrypt(
                    OLD, b'{"patterns":[],"state_seq":7}', crypto.build_aad("insights", OWNER, kind)
                ),
            )
        )
    db.session.add(
        Insight(
            user_id=OWNER,
            kind="question",
            for_date=NOW.date(),
            state_seq=7,
            blob=crypto.encrypt(
                OLD, b"question?", crypto.build_aad("question", OWNER, NOW.date().isoformat())
            ),
        )
    )
    if foreign:
        db.session.add(
            Measure(
                id="f" * 32,
                user_id=OTHER,
                client_measure_id="foreign",
                measure_date=NOW.date(),
                blob=b"foreign",
            )
        )
    await db.session.commit()
    return rows


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["v1", "v2"])
async def test_native_multibatch_rotation_is_complete_and_exact_retries_do_not_consume_keys(
    rekey_db, scheme
):
    db = rekey_db
    rows = await seed_corpus(db, 101)
    db.owner.recovery_salt = b"r" * 16
    db.owner.recovery_verifier = b"r" * 32
    db.owner.recovery_wrapped_data_key = b"r" * 60
    db.owner.recovery_set_at = NOW
    db.owner.recovery_scheme = 2
    db.owner.entries_revision = 4
    db.owner.measures_revision = 6
    data = body()
    if scheme == "v2":
        db.owner.key_scheme = "v2"
        data.new_kdf_params = PARAMS
        data.new_wrapped_data_key = b64(b"e" * 60)
    await db.session.commit()
    out = await invoke(db, data)
    assert out.model_dump() == dict(
        entries=101,
        insights=3,
        measures=101,
        audio=0,
        recovery_invalidated=True,
        credential_rotated=True,
        operation_id=OPERATION,
        consents_rewrapped=0,
    )
    await db.session.refresh(db.owner)
    assert db.owner.salt == b64(b"s" * 16) and len(db.owner.scrypt_salt) >= 16
    assert db.owner.verifier == hash_proof(b"v" * 32, db.owner.scrypt_salt)
    assert (db.owner.token_epoch, db.owner.entries_revision, db.owner.measures_revision) == (
        3,
        5,
        7,
    )
    assert (
        db.owner.recovery_salt,
        db.owner.recovery_verifier,
        db.owner.recovery_wrapped_data_key,
        db.owner.recovery_set_at,
        db.owner.recovery_scheme,
    ) == (None,) * 5
    if scheme == "v2":
        assert db.owner.wrapped_data_key == b"e" * 60 and json.loads(db.owner.kdf_params) == PARAMS
    assert db.audit == [
        dict(actor_id=OWNER, actor_role="user", user_id=OWNER, action="corpus_credential_rotated")
    ]
    assert len(db.flushed) == 1 and not list((await db.session.scalars(select(RekeyJournal))).all())
    for row in rows:
        await db.session.refresh(row)
        assert validate_entry_guard(row, db.settings) is True
        assert (
            crypto.decrypt(NEW, bytes(row.blob), crypto.entry_aad_v2(OWNER, row.client_entry_id, 1))
            == f"entry-{int(row.id, 16) - 1}".encode()
        )
    measures = list(
        (await db.session.scalars(select(Measure).where(Measure.user_id == OWNER))).all()
    )
    assert len(measures) == 101
    for row in measures:
        assert (
            crypto.decrypt(
                NEW, bytes(row.blob), crypto.build_aad("measure", OWNER, row.client_measure_id)
            )
            == f"measure-{row.client_measure_id[1:]}".encode()
        )
    for row in list((await db.session.scalars(select(Insight))).all()):
        aad = (
            crypto.build_aad("question", OWNER, NOW.date().isoformat())
            if row.kind == "question"
            else crypto.build_aad("insights", OWNER, row.kind)
        )
        plain = crypto.decrypt(NEW, bytes(row.blob), aad)
        if row.kind == "question":
            assert plain == b"question?" and row.state_seq == 7
        else:
            assert json.loads(plain) == dict(patterns=[], state_seq=8) and row.state_seq == 8
    assert (await db.session.get(Measure, "f" * 32)).blob == b"foreign"
    old, new = tokens(db)
    assert (await invoke(db, data, old, new)).model_dump() == out.model_dump()
    assert db.request.app.state.key_store.get(old, owner=OWNER) == OLD
    assert len(db.audit) == 1 and len(db.flushed) == 1
    db.request.state.mindpattern_token_epoch = 3
    assert (await invoke(db, data, old, new)).model_dump() == out.model_dump()
    changed = data.model_copy(update={"new_salt": b64(b"z" * 16)})
    with pytest.raises(ApiError) as failure:
        await invoke(db, changed, old, new)
    envelope(failure, 409, "operation identifier already used", "rekey_operation_conflict")


@pytest.mark.asyncio
async def test_rotation_failure_after_native_hundred_row_commit_keeps_resumable_progress(rekey_db):
    db = rekey_db
    rows = await seed_corpus(db, 101, unknown_last=True)
    with pytest.raises(ApiError) as failure:
        await invoke(db)
    envelope(
        failure,
        400,
        "old key did not authenticate every blob; already-completed batches remain rekeyed and the retry resumes from the journal. Verify the account's current data key and retry.",
        "rekey_key_mismatch",
    )
    journal = (await db.session.scalars(select(RekeyJournal))).one()
    assert journal.entries_done == 100 and journal.entry_cursor == rows[99].id
    for row in rows[:100]:
        await db.session.refresh(row)
        assert (
            crypto.decrypt(NEW, row.blob, crypto.entry_aad_v2(OWNER, row.client_entry_id, 1))
            == f"entry-{int(row.id, 16) - 1}".encode()
        )
    await db.session.refresh(rows[100])
    assert (
        crypto.decrypt(
            b"x" * 32, rows[100].blob, crypto.entry_aad_v2(OWNER, rows[100].client_entry_id, 1)
        )
        == b"entry-100"
    )
    await db.session.refresh(db.owner)
    assert db.owner.token_epoch == 2 and not db.audit


@pytest.mark.asyncio
async def test_rotation_rewraps_live_consent_and_moves_real_audio_by_copy_on_write(rekey_db):
    db = rekey_db
    await seed_corpus(db, 1)
    spki = b64(
        ec.generate_private_key(ec.SECP256R1())
        .public_key()
        .public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )
    db.other.wrap_pub_key = spki
    grant = Consent(
        id="c" * 32,
        user_id=OWNER,
        therapist_id=OTHER,
        status="active",
        disclosure="v3",
        ephemeral_pub=spki,
        wrapped_key=b"old",
        granted_at=NOW,
    )
    db.session.add(grant)
    aad = crypto.build_aad("audio", OWNER, "e0", "1")
    source = crypto.encrypt(OLD, b"recording", aad)
    source_key = f"audio/{OWNER}/" + ("d" * 32) + ".enc"
    await db.store.put(source_key, source)
    attachment = AudioAttachment(
        id="d" * 32,
        user_id=OWNER,
        client_entry_id="e0",
        backend=db.store.backend,
        storage_key=source_key,
        storage_locator=storage_locator(db.store),
        size_bytes=len(source),
        mime_type="audio/webm",
        duration_seconds=3,
        content_version=1,
        created_at=NOW,
        expires_at=NOW,
    )
    db.session.add(attachment)
    await db.session.commit()
    data = body(
        consent_wraps=[
            RekeyConsentWrap(
                consent_id=grant.id,
                therapist_wrap_pub_key=spki,
                ephemeral_pub=spki,
                wrapped_key=b64(b"w" * 60),
            )
        ]
    )
    out = await invoke(db, data)
    assert out.audio == 1 and out.consents_rewrapped == 1
    await db.session.refresh(grant)
    assert grant.wrapped_key == b"w" * 60 and grant.ephemeral_pub == spki
    await db.session.refresh(attachment)
    assert attachment.storage_key != source_key and attachment.storage_locator == storage_locator(
        db.store
    )
    assert (
        crypto.decrypt(NEW, await db.store.get(attachment.storage_key, max_bytes=1024), aad)
        == b"recording"
    )
    assert attachment.size_bytes == len(source)
    tombstones = list((await db.session.scalars(select(AudioDeletion))).all())
    assert len(tombstones) == 1 and tombstones[0].storage_key == source_key
    assert await db.store.get(source_key, max_bytes=1024) == source
    await db.session.refresh(db.owner)
    await db.session.refresh(db.other)
    assert db.owner.consents_revision == 1 and db.other.patients_revision == 1
