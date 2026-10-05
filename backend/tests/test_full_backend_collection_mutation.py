"""Observable collection, quota, lifecycle and provider-dispatch contracts."""

from __future__ import annotations

import asyncio
import base64
import logging
from contextlib import suppress
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
import pytest_asyncio
from fastapi import FastAPI, Response
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.api import audio, entries, measures
from app.cache import SlidingWindowCounter
from app.config import Settings
from app.db import build_engine, build_sessionmaker
from app.deps import ApiError, get_session, require_regular_user
from app.locks import UserLocks
from app.models import AudioAttachment, AudioDeletion, Base, Entry, Measure, User
from app.schemas import (
    AudioAttachmentCreate,
    AudioTranscriptionRequest,
    AudioTranslationRequest,
    EntryCreate,
    EntryReplace,
    MeasureCreate,
)
from app.security.entry_guard import seal_entry_guard, validate_entry_guard
from app.services.audio_store import LocalAudioStore, storage_locator

OWNER = "a" * 32
OTHER = "b" * 32
NOW = datetime(2026, 10, 5, 12, tzinfo=timezone.utc)
TODAY = NOW.date()
MAXIMUM = 2**63 - 1
BLOB = b"encrypted opaque payload" * 2


class FixedDateTime(datetime):
    @classmethod
    def now(cls, tz=None):
        assert tz is timezone.utc
        return NOW


def b64(value):
    return base64.b64encode(value).decode("ascii")


def envelope(failure, status, detail, code, headers=None):
    value = failure.value
    assert (value.status_code, value.detail, value.code, value.headers) == (
        status,
        detail,
        code,
        headers,
    )


def account(identifier, **changes):
    values = dict(
        id=identifier,
        username=identifier,
        salt="salt",
        verifier=b"verifier",
        scrypt_salt=b"salt",
        is_active=True,
        token_epoch=2,
        created_at=NOW - timedelta(days=10),
        voice_consent=True,
    )
    values.update(changes)
    return User(**values)


@pytest_asyncio.fixture
async def collection_db(monkeypatch, tmp_path):
    lifecycle = UserLocks()
    for module in [entries, measures, audio]:
        monkeypatch.setattr(module, "lifecycle_locks", lifecycle)
    monkeypatch.setattr(entries, "_user_locks", UserLocks())
    monkeypatch.setattr(measures, "_user_locks", UserLocks())
    monkeypatch.setattr(audio, "_audio_locks", UserLocks())
    settings = Settings(environment="development")
    settings.audio_enabled = True
    settings.audio_local_dir = str(tmp_path / "objects")
    settings.audio_max_body_bytes = 1024
    settings.audio_max_user_bytes = 1024
    settings.audio_max_duration_seconds = 10
    settings.read_rate_limit = 10000
    settings.entries_rate_limit = 10000
    settings.audio_upload_rate_limit = 10000
    settings.audio_transcribe_rate_limit = 10000
    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = build_sessionmaker(engine)
    audit = []

    async def record(session, **values):
        audit.append(values)

    monkeypatch.setattr(audio, "append_access_log", record)
    monkeypatch.setattr(measures, "append_access_log", record)
    monkeypatch.setattr(audio, "utcnow", lambda: NOW)
    monkeypatch.setattr(entries, "utcnow", lambda: NOW)
    monkeypatch.setattr(entries, "datetime", FixedDateTime)
    monkeypatch.setattr(measures, "_utc_today", lambda: TODAY)
    monkeypatch.setattr(audio.stt, "consent_is_current", lambda user, config: user.voice_consent)
    store = LocalAudioStore(settings.audio_local_dir)
    monkeypatch.setattr(audio, "get_audio_store_cached", lambda config: store)
    monkeypatch.setattr(audio.audio_store_service, "get_audio_store_cached", lambda config: store)
    async with factory() as session:
        owner, other = account(OWNER), account(OTHER)
        session.add_all([owner, other])
        await session.commit()
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(settings=settings)), state=SimpleNamespace()
        )
        yield SimpleNamespace(
            session=session,
            owner=owner,
            other=other,
            settings=settings,
            engine=engine,
            request=request,
            audit=audit,
            store=store,
        )
    await engine.dispose()


@pytest.mark.parametrize(
    "module,decode", [(entries, "_decode_entry_blob"), (measures, "_decode_measure_blob")]
)
def test_ciphertext_decoding_is_strict_and_accepts_exact_envelope_floor(module, decode):
    call = getattr(module, decode)
    assert call(b64(b"x" * 28)) == b"x" * 28
    for value, detail in [
        ("!!!!" + b64(BLOB), "blob must be base64"),
        (b64(b"x" * 27), "blob must be at least 28 bytes"),
    ]:
        with pytest.raises(ApiError) as failure:
            call(value)
        envelope(failure, 422, detail, "validation_error")


@pytest.mark.parametrize(
    "module,validate,past",
    [
        (entries, "_validate_entry_date", "entry_date is before this account existed"),
        (measures, "_validate_measure_date", "measure_date cannot predate the account"),
    ],
)
def test_date_grace_accepts_both_edges_and_rejects_adjacent_days(
    monkeypatch, module, validate, past
):
    if module is entries:
        monkeypatch.setattr(entries, "datetime", FixedDateTime)
    else:
        monkeypatch.setattr(module, "_utc_today", lambda: TODAY)
    call = getattr(module, validate)
    for created in [NOW - timedelta(days=10), NOW + timedelta(days=2), None]:
        user = SimpleNamespace(created_at=created)
        earliest = min(created.date() if created else TODAY, TODAY) - timedelta(days=1)
        call(earliest, user)
        call(TODAY + timedelta(days=1), user)
        for day, detail in [
            (earliest - timedelta(days=1), past),
            (
                TODAY + timedelta(days=2),
                f"{'entry' if module is entries else 'measure'}_date cannot be in the future",
            ),
        ]:
            with pytest.raises(ApiError) as failure:
                call(day, user)
            envelope(failure, 422, detail, "validation_error")


async def test_entry_quota_counts_and_adjusted_bytes_have_exact_inclusive_limits():
    config = SimpleNamespace(max_entries_per_user=1, max_user_blob_bytes=48)
    user = SimpleNamespace(entry_count=0, entry_blob_bytes=0)
    await entries._assert_within_quota(None, user, 48, config)
    for count, total, incoming, detail, code in [
        (1, 0, 28, "storage quota reached (1 entries)", "quota_exceeded"),
        (0, 21, 28, "storage quota reached (total size)", "blob_quota_exceeded"),
    ]:
        user.entry_count, user.entry_blob_bytes = count, total
        with pytest.raises(ApiError) as failure:
            await entries._assert_within_quota(None, user, incoming, config)
        envelope(failure, 413, detail, code)
    user.entry_blob_bytes = 40
    await entries._assert_replacement_within_quota(None, user, 20, 28, config)
    with pytest.raises(ApiError) as failure:
        await entries._assert_replacement_within_quota(None, user, 20, 29, config)
    envelope(failure, 413, "storage quota reached (total size)", "blob_quota_exceeded")


def test_unique_integrity_classification_handles_both_driver_codes_and_other_errors():
    for original in [
        SimpleNamespace(pgcode="23505"),
        SimpleNamespace(sqlstate="23505"),
        RuntimeError("UNIQUE constraint failed"),
    ]:
        assert entries._is_unique_violation(IntegrityError("insert", None, original)) is True
    for original in [None, SimpleNamespace(pgcode="23503"), RuntimeError("foreign key failed")]:
        assert entries._is_unique_violation(IntegrityError("insert", None, original)) is False


@pytest.mark.parametrize(
    "module,revision,increment,header,label",
    [
        (
            entries,
            "entries_revision",
            "_increment_entries_revision",
            "X-Entries-Revision",
            "entries",
        ),
        (
            measures,
            "measures_revision",
            "_increment_measures_revision",
            "X-Measures-Revision",
            "measures",
        ),
    ],
)
async def test_collection_marker_advances_only_its_owner_and_fails_closed_at_saturation(
    collection_db, module, revision, increment, header, label
):
    db = collection_db
    call = getattr(module, increment)
    setattr(db.owner, revision, MAXIMUM - 1)
    setattr(db.other, revision, 7)
    await db.session.commit()
    assert await call(db.session, db.owner) == MAXIMUM
    await db.session.commit()
    await db.session.refresh(db.other)
    assert getattr(db.other, revision) == 7
    with pytest.raises(ApiError) as failure:
        await call(db.session, db.owner)
    envelope(
        failure,
        503,
        f"unable to advance {label} revision; retry shortly",
        "service_unavailable",
        {"Retry-After": "1"},
    )
    await db.session.rollback()
    with pytest.raises(ApiError) as failure:
        await getattr(module, f"current_{label}_revision")(db.session, "missing")
    envelope(failure, 409, f"{label} changed while paging; retry the request", "collection_changed")


@pytest.mark.parametrize(
    "module,fresh",
    [(entries, "_fresh_active_entry_user"), (measures, "_fresh_active_measure_user")],
)
async def test_collection_authentication_refreshes_existing_identity_data(
    collection_db, module, fresh
):
    db = collection_db
    for changes in [{"token_epoch": 3}, {"is_active": False}]:
        async with db.engine.begin() as connection:
            await connection.execute(update(User).where(User.id == OWNER).values(**changes))
        with pytest.raises(ApiError) as failure:
            await getattr(module, fresh)(db.session, OWNER, 2)
        envelope(failure, 401, "invalid token", "unauthorized")
    with pytest.raises(ApiError) as failure:
        await getattr(module, fresh)(db.session, "missing", 2)
    envelope(failure, 401, "invalid token", "unauthorized")


async def test_entry_create_edit_and_delete_keep_counters_versions_and_other_owner(collection_db):
    db = collection_db
    made = await entries.create_entry(
        EntryCreate(client_entry_id="same", blob=b64(BLOB), entry_date=TODAY),
        db.request,
        db.owner,
        db.session,
    )
    assert (made.client_entry_id, made.blob, made.content_version) == ("same", b64(BLOB), 1)
    await db.session.refresh(db.owner)
    assert (db.owner.entry_count, db.owner.entry_blob_bytes, db.owner.entries_revision) == (
        1,
        len(BLOB),
        1,
    )
    await entries.create_entry(
        EntryCreate(client_entry_id="same", blob=b64(BLOB), entry_date=TODAY),
        db.request,
        db.other,
        db.session,
    )
    with pytest.raises(ApiError) as failure:
        await entries.create_entry(
            EntryCreate(client_entry_id="same", blob=b64(BLOB), entry_date=TODAY),
            db.request,
            db.owner,
            db.session,
        )
    envelope(failure, 409, "entry already exists", "conflict")
    changed = await entries.replace_entry(
        "same",
        EntryReplace(blob=b64(BLOB + b"new"), entry_date=TODAY),
        db.request,
        db.owner,
        db.session,
    )
    assert (changed.blob, changed.content_version) == (b64(BLOB + b"new"), 2)
    await db.session.refresh(db.owner)
    assert (db.owner.entry_count, db.owner.entry_blob_bytes, db.owner.entries_revision) == (
        1,
        len(BLOB) + 3,
        2,
    )
    unchanged = await entries.replace_entry(
        "same", EntryReplace(blob=changed.blob, entry_date=TODAY), db.request, db.owner, db.session
    )
    assert unchanged.content_version == 2
    await db.session.refresh(db.owner)
    assert db.owner.entries_revision == 2
    date_edit = await entries.replace_entry(
        "same",
        EntryReplace(blob=changed.blob, entry_date=TODAY - timedelta(days=1)),
        db.request,
        db.owner,
        db.session,
    )
    assert date_edit.content_version == 3 and date_edit.entry_date == TODAY - timedelta(days=1)
    response = Response()
    await entries.delete_entry("same", response, db.request, db.owner, db.session)
    assert response.headers["X-Entries-Revision"] == "4"
    await db.session.refresh(db.owner)
    await db.session.refresh(db.other)
    assert (db.owner.entry_count, db.owner.entry_blob_bytes, db.owner.entries_revision) == (0, 0, 4)
    assert (db.other.entry_count, db.other.entry_blob_bytes, db.other.entries_revision) == (
        1,
        len(BLOB),
        1,
    )
    assert (await entries.get_entry("same", db.other, db.session)).blob == b64(BLOB)
    for identifier in ["same", "bad/id"]:
        with pytest.raises(ApiError) as failure:
            await entries.get_entry(identifier, db.owner, db.session)
        envelope(failure, 404, "entry not found", "not_found")
        with pytest.raises(ApiError) as failure:
            await entries.delete_entry(identifier, Response(), db.request, db.owner, db.session)
        envelope(failure, 404, "entry not found", "not_found")


async def test_entry_edits_preserve_authenticated_aad_and_require_exact_successor(collection_db):
    db = collection_db
    row = Entry(
        user_id=OWNER, client_entry_id="guard", blob=BLOB, entry_date=TODAY, content_version=2
    )
    seal_entry_guard(row, db.settings, v2_bound=True)
    db.session.add(row)
    db.owner.entry_count = 1
    db.owner.entry_blob_bytes = len(BLOB)
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await entries.replace_entry(
            "guard",
            EntryReplace(blob=b64(BLOB + b"change"), entry_date=TODAY, content_version=4),
            db.request,
            db.owner,
            db.session,
        )
    envelope(
        failure,
        409,
        "entry was modified by another device; refetch and retry",
        "version_conflict",
        {"Retry-After": "1"},
    )
    result = await entries.replace_entry(
        "guard",
        EntryReplace(blob=b64(BLOB + b"change"), entry_date=TODAY, content_version=3),
        db.request,
        db.owner,
        db.session,
    )
    assert result.content_version == 3
    await db.session.refresh(row)
    assert validate_entry_guard(row, db.settings) is True
    row.aad_guard_mac = "0" * 64
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await entries.replace_entry(
            "guard",
            EntryReplace(blob=b64(BLOB), entry_date=TODAY),
            db.request,
            db.owner,
            db.session,
        )
    envelope(failure, 400, "entry blob failed authentication", "entry_blob_invalid")


async def test_measure_create_duplicate_quota_and_delete_are_owner_scoped(
    collection_db, monkeypatch
):
    db = collection_db
    db.session.add_all(
        [
            Measure(
                user_id=OWNER, client_measure_id=f"quota-{index}", blob=BLOB, measure_date=TODAY
            )
            for index in range(1999)
        ]
    )
    db.owner.measure_count = 1999
    await db.session.commit()

    async def create(user, identifier):
        return await measures.create_measure(
            MeasureCreate(client_measure_id=identifier, blob=b64(BLOB), measure_date=TODAY),
            db.request,
            user,
            db.session,
        )

    made = await create(db.owner, "same")
    assert (made.client_measure_id, made.blob, made.measure_date) == ("same", b64(BLOB), TODAY)
    await create(db.other, "same")
    await db.session.refresh(db.owner)
    assert (db.owner.measure_count, db.owner.measures_revision) == (2000, 1)
    with pytest.raises(ApiError) as failure:
        await create(db.owner, "same")
    envelope(failure, 409, "measure already exists", "conflict")
    with pytest.raises(ApiError) as failure:
        await create(db.owner, "another")
    envelope(failure, 413, "measure quota exceeded", "quota_exceeded")

    async def verifier(*args):
        pass

    from app.api import account as account_module

    monkeypatch.setattr(account_module, "_require_verifier", verifier)
    response = Response()
    deleted = await measures.delete_measure(
        "same", db.request, response, db.owner, db.session, "verifier"
    )
    assert deleted.measures_revision == 2 and response.headers["X-Measures-Revision"] == "2"
    await db.session.refresh(db.owner)
    await db.session.refresh(db.other)
    assert (db.owner.measure_count, db.owner.measures_revision) == (1999, 2)
    assert (db.other.measure_count, db.other.measures_revision) == (1, 1)
    assert db.audit == [
        dict(actor_id=OWNER, actor_role="user", user_id=OWNER, action="delete_measure")
    ]
    for identifier in ["same", "bad/id"]:
        with pytest.raises(ApiError) as failure:
            await measures.delete_measure(
                identifier, db.request, Response(), db.owner, db.session, "verifier"
            )
        envelope(failure, 404, "measure not found", "not_found")


@pytest.mark.parametrize(
    "original,duplicate",
    [
        (SimpleNamespace(pgcode="23505"), True),
        (SimpleNamespace(sqlstate="23505"), True),
        (RuntimeError("UNIQUE constraint"), True),
        (RuntimeError("foreign key constraint"), False),
        (None, False),
    ],
)
async def test_measure_commit_conflicts_are_classified_without_hiding_other_integrity_failures(
    collection_db, monkeypatch, original, duplicate
):
    db = collection_db
    fault = IntegrityError("insert", None, original)

    async def failed_commit():
        raise fault

    monkeypatch.setattr(db.session, "commit", failed_commit)
    if duplicate:
        with pytest.raises(ApiError) as failure:
            await measures.create_measure(
                MeasureCreate(client_measure_id="fault", blob=b64(BLOB), measure_date=TODAY),
                db.request,
                db.owner,
                db.session,
            )
        envelope(failure, 409, "measure already exists", "conflict")
    else:
        with pytest.raises(IntegrityError) as failure:
            await measures.create_measure(
                MeasureCreate(client_measure_id="fault", blob=b64(BLOB), measure_date=TODAY),
                db.request,
                db.owner,
                db.session,
            )
        assert failure.value is fault


@pytest.mark.parametrize(
    "module,model,id_field,date_field,header",
    [
        (entries, Entry, "client_entry_id", "entry_date", "X-Entries-Revision"),
        (measures, Measure, "client_measure_id", "measure_date", "X-Measures-Revision"),
    ],
)
async def test_collection_pages_return_stable_owner_only_data_and_exact_continuations(
    collection_db, module, model, id_field, date_field, header
):
    db = collection_db
    for index in range(3):
        row = model(
            id=str(index) * 32,
            user_id=OWNER,
            blob=BLOB,
            received_at=NOW,
            **{id_field: f"page-{index}", date_field: TODAY + timedelta(days=index)},
        )
        db.session.add(row)
    db.session.add(
        model(
            id="f" * 32,
            user_id=OTHER,
            blob=BLOB,
            received_at=NOW,
            **{id_field: "foreign", date_field: TODAY},
        )
    )
    await db.session.commit()

    async def listing(response, **changes):
        args = dict(
            response=response,
            user=db.owner,
            session=db.session,
            offset=0,
            limit=2,
            page_bytes=None,
            expected_revision="0",
        )
        if module is entries:
            args.update(since=None, until=None)
        args.update(changes)
        return await getattr(module, "list_entries" if module is entries else "list_measures")(
            **args
        )

    expected = (
        ["page-0", "page-1", "page-2"] if module is entries else ["page-2", "page-1", "page-0"]
    )
    response = Response()
    page = await listing(response)
    assert [getattr(r, id_field) for r in page] == expected[:2]
    assert [r.blob for r in page] == [b64(BLOB)] * 2
    assert response.headers[header] == "0" and response.headers["X-Next-Offset"] == "2"
    last = Response()
    result = await listing(last, offset=2)
    assert [getattr(r, id_field) for r in result] == expected[2:]
    assert "X-Next-Offset" not in last.headers
    empty = Response()
    assert await listing(empty, offset=3) == []
    exact = Response()
    result = await listing(exact, limit=3, page_bytes=len(BLOB) * 2)
    assert len(result) == 2 and exact.headers["X-Next-Offset"] == "2"
    with pytest.raises(ApiError) as failure:
        await listing(Response(), expected_revision="1")
    label = "entries" if module is entries else "measures"
    envelope(
        failure,
        409,
        f"{label} changed while paging; retry the request",
        "collection_changed",
        {header: "0"},
    )
    with pytest.raises(ApiError) as failure:
        await listing(Response(), page_bytes=1)
    singular = "entry" if module is entries else "measure"
    envelope(
        failure,
        413,
        f"an item in this {singular} page exceeds the requested page byte budget",
        "payload_too_large",
    )
    if module is entries:
        bounded = await listing(Response(), since=TODAY, until=TODAY + timedelta(days=1), limit=3)
        assert [r.client_entry_id for r in bounded] == ["page-0"]


def test_audio_decoding_preserves_exact_caps_and_rejects_malformed_or_short_ciphertext():
    config = SimpleNamespace(audio_max_body_bytes=48)
    for call in [audio._decode_audio, audio._decode_blob]:
        assert call(b64(b"x" * 48), config) == b"x" * 48
        with pytest.raises(ApiError) as failure:
            call(b64(b"x" * 49), config)
        envelope(failure, 413, "recording too large", "audio_too_large")
        with pytest.raises(ApiError) as failure:
            call("!!!!" + b64(BLOB), config)
        envelope(
            failure,
            422,
            "audio must be base64" if call is audio._decode_audio else "blob must be base64",
            "validation_error",
        )
    assert audio._decode_blob(b64(b"x" * 28), config) == b"x" * 28
    with pytest.raises(ApiError) as failure:
        audio._decode_blob(b64(b"x" * 27), config)
    envelope(failure, 422, "blob must be at least 28 bytes", "validation_error")


async def test_audio_flag_requires_explicit_enabled_setting():
    for settings in [SimpleNamespace(), SimpleNamespace(audio_enabled=False)]:
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
        with pytest.raises(ApiError) as failure:
            await audio.require_audio_enabled(request)
        envelope(failure, 404, "not found", "not_found")
    await audio.require_audio_enabled(
        SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(audio_enabled=True)))
        )
    )


@pytest.mark.parametrize(
    "text,allowed", [("texto", True), ("texto", False), ("", True), ("", False)]
)
async def test_transcription_and_translation_dispatch_are_durable_consent_scoped(
    collection_db, monkeypatch, text, allowed
):
    db = collection_db
    calls = []

    async def transcribe(blob, mime):
        assert db.audit == [
            dict(actor_id=OWNER, actor_role="user", user_id=OWNER, action="stt_dispatch_attempt")
        ]
        assert not db.session.in_transaction()
        calls.append(("audio", blob, mime))
        return SimpleNamespace(text=text, language_iso="es", language_raw="Spanish")

    async def translate(config, value, language):
        assert db.audit[-1]["action"] == "translation_dispatch_attempt"
        assert not db.session.in_transaction()
        calls.append(("text", value, language))
        return "English"

    monkeypatch.setattr(
        audio.stt, "get_stt", lambda settings: SimpleNamespace(transcribe=transcribe)
    )
    monkeypatch.setattr(audio.stt, "translation_dispatch_allowed", lambda user, settings: allowed)
    monkeypatch.setattr(audio.stt, "translate_to_english", translate)
    db.settings.stt_provider_name = " Provider "
    db.settings.stt_policy_version = " policy-v2 "
    body = AudioTranscriptionRequest(audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1)
    result = await audio.transcribe_recording(body, db.request, db.owner, None, db.session)
    assert result.model_dump() == dict(
        original_text=text,
        language="es",
        language_raw="Spanish",
        english_text="English" if text and allowed else None,
        provider_name="Provider",
        policy_version="policy-v2",
    )
    assert calls == [("audio", BLOB, "audio/webm")] + (
        [("text", text, "es")] if text and allowed else []
    )
    db.audit.clear()
    calls.clear()
    translated = await audio.translate_text(
        AudioTranslationRequest(text="edited", source_lang="fr"),
        db.request,
        db.owner,
        None,
        db.session,
    )
    assert translated.english_text == ("English" if allowed else None)
    assert calls == ([("text", "edited", "fr")] if allowed else [])


async def test_audio_duration_exact_edges_and_stale_epoch_fail_before_provider(
    collection_db, monkeypatch
):
    db = collection_db

    async def transcribe(*args):
        return SimpleNamespace(text="", language_iso=None, language_raw="")

    monkeypatch.setattr(
        audio.stt, "get_stt", lambda settings: SimpleNamespace(transcribe=transcribe)
    )
    monkeypatch.setattr(audio.stt, "translation_dispatch_allowed", lambda *args: False)
    for duration in [1, 10]:
        await audio.transcribe_recording(
            AudioTranscriptionRequest(
                audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=duration
            ),
            db.request,
            db.owner,
            None,
            db.session,
        )
    for encoded, duration, detail in [
        (b64(BLOB), 11, "recording duration exceeds the allowed maximum"),
    ]:
        body = AudioTranscriptionRequest(
            audio_b64=encoded, mime="audio/webm", duration_seconds=duration
        )
        with pytest.raises(ApiError) as failure:
            await audio.transcribe_recording(body, db.request, db.owner, None, db.session)
        envelope(failure, 422, detail, "validation_error")
    async with db.engine.begin() as connection:
        await connection.execute(update(User).where(User.id == OWNER).values(token_epoch=3))
    for call, body in [
        (
            audio.transcribe_recording,
            AudioTranscriptionRequest(audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1),
        ),
        (audio.translate_text, AudioTranslationRequest(text="text")),
    ]:
        stale = SimpleNamespace(id=OWNER, token_epoch=2, voice_consent=True)
        with pytest.raises(ApiError) as failure:
            await call(body, db.request, stale, None, db.session)
        envelope(failure, 401, "invalid token", "unauthorized")
    monkeypatch.setattr(audio.stt, "get_stt", lambda settings: None)
    with pytest.raises(ApiError) as failure:
        await audio.transcribe_recording(
            AudioTranscriptionRequest(audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1),
            db.request,
            db.owner,
            None,
            db.session,
        )
    envelope(failure, 503, "speech-to-text is not configured on this server", "stt_unconfigured")


async def make_entry(db, identifier, user_id=OWNER):
    row = Entry(
        user_id=user_id, client_entry_id=identifier, entry_date=TODAY, blob=BLOB, content_version=1
    )
    seal_entry_guard(row, db.settings, v2_bound=False)
    db.session.add(row)
    await db.session.commit()
    return row


def attachment_body(identifier, blob=BLOB, duration=1):
    return AudioAttachmentCreate(
        client_entry_id=identifier, blob=b64(blob), mime="audio/webm", duration_seconds=duration
    )


async def test_audio_upload_replacement_quota_locators_and_version_metadata(collection_db):
    db = collection_db
    await make_entry(db, "kept")
    await make_entry(db, "other")
    db.settings.audio_max_user_bytes = len(BLOB) * 2
    first = await audio.upload_attachment(
        attachment_body("kept"), db.request, db.owner, None, db.session
    )
    row = await db.session.get(AudioAttachment, first.attachment_id)
    original_key = row.storage_key
    assert row.storage_locator == storage_locator(db.store) and row.content_version == 1
    assert (
        row.user_id,
        row.client_entry_id,
        row.size_bytes,
        row.mime_type,
        row.duration_seconds,
    ) == (OWNER, "kept", len(BLOB), "audio/webm", 1)
    assert not (await db.session.scalars(select(AudioDeletion))).all()
    second = await audio.upload_attachment(
        attachment_body("other"), db.request, db.owner, None, db.session
    )
    assert second.size_bytes == len(BLOB)
    replacement = await audio.upload_attachment(
        attachment_body("kept", BLOB, 10), db.request, db.owner, None, db.session
    )
    assert replacement.attachment_id == first.attachment_id
    await db.session.refresh(row)
    assert row.storage_key != original_key and row.storage_locator == storage_locator(db.store)
    assert row.content_version == 1 and row.duration_seconds == 10
    assert not (db.store.root / original_key).exists()
    fetched = await audio.fetch_attachment(
        first.attachment_id, db.request, db.owner, None, db.session
    )
    assert (fetched.blob, fetched.size_bytes, fetched.client_entry_id) == (
        b64(BLOB),
        len(BLOB),
        "kept",
    )
    with pytest.raises(ApiError) as failure:
        await audio.upload_attachment(
            attachment_body("kept", BLOB + b"x"), db.request, db.owner, None, db.session
        )
    envelope(failure, 413, "audio storage quota reached", "audio_quota_exceeded")
    await audio.delete_attachment(first.attachment_id, db.request, db.owner, None, db.session)
    assert await db.session.get(AudioAttachment, first.attachment_id) is None
    assert (
        await db.session.scalar(select(Entry.id).where(Entry.client_entry_id == "kept"))
    ) is not None


async def test_audio_owner_scoping_expiry_metadata_and_entry_cascade(collection_db):
    db = collection_db
    await make_entry(db, "same")
    await make_entry(db, "same", OTHER)
    made = await audio.upload_attachment(
        attachment_body("same"), db.request, db.owner, None, db.session
    )
    foreign = await audio.upload_attachment(
        attachment_body("same"), db.request, db.other, None, db.session
    )
    assert (await entries.audio_meta_map(db.session, OWNER, ["same"]))[
        "same"
    ].attachment_id == made.attachment_id
    assert await entries.audio_meta_map(db.session, OWNER, []) == {}
    for identifier in [foreign.attachment_id, "missing"]:
        with pytest.raises(ApiError) as failure:
            await audio.fetch_attachment(identifier, db.request, db.owner, None, db.session)
        envelope(failure, 404, "attachment not found", "not_found")
        with pytest.raises(ApiError) as failure:
            await audio.delete_attachment(identifier, db.request, db.owner, None, db.session)
        envelope(failure, 404, "attachment not found", "not_found")
    row = await db.session.get(AudioAttachment, made.attachment_id)
    row.expires_at = NOW
    await db.session.commit()
    assert await entries.audio_meta_map(db.session, OWNER, ["same"]) == {}
    with pytest.raises(ApiError) as failure:
        await audio.fetch_attachment(made.attachment_id, db.request, db.owner, None, db.session)
    envelope(failure, 410, "recording expired", "audio_expired")
    await entries.delete_attachment_for_entry(db.session, db.settings, OTHER, "same")
    await db.session.commit()
    assert await db.session.get(AudioAttachment, foreign.attachment_id) is None
    pending = (await db.session.scalars(select(AudioDeletion))).all()
    assert {r.owner_id for r in pending} == {OWNER, OTHER}


async def test_audio_crash_cleanup_evidence_is_delayed_and_keeps_original_storage_target(
    collection_db, monkeypatch
):
    db = collection_db
    await make_entry(db, "pending")
    from app.services.audio_store import AudioStoreError

    async def fail_put(key, blob):
        raise AudioStoreError("private provider error")

    monkeypatch.setattr(db.store, "put", fail_put)
    with pytest.raises(ApiError) as failure:
        await audio.upload_attachment(
            attachment_body("pending"), db.request, db.owner, None, db.session
        )
    envelope(failure, 502, "audio storage failed; try again", "audio_storage_failed")
    pending = (await db.session.scalars(select(AudioDeletion))).one()
    assert (pending.owner_id, pending.backend, pending.storage_locator) == (
        OWNER,
        "local",
        storage_locator(db.store),
    )
    assert pending.not_before == NOW + timedelta(hours=1)
    assert not (await db.session.scalars(select(AudioAttachment))).all()


@pytest.mark.parametrize("call", [audio.fetch_attachment, audio.delete_attachment])
async def test_attachment_unconfigured_storage_and_revoked_authentication_have_exact_errors(
    collection_db, monkeypatch, call
):
    db = collection_db
    monkeypatch.setattr(audio, "get_audio_store_cached", lambda config: None)
    with pytest.raises(ApiError) as failure:
        await call("missing", db.request, db.owner, None, db.session)
    envelope(
        failure, 503, "audio storage is not configured on this server", "audio_storage_unconfigured"
    )
    monkeypatch.setattr(audio, "get_audio_store_cached", lambda config: db.store)
    async with db.engine.begin() as connection:
        await connection.execute(update(User).where(User.id == OWNER).values(token_epoch=3))
    with pytest.raises(ApiError) as failure:
        await call("missing", db.request, db.owner, None, db.session)
    envelope(failure, 401, "invalid token", "unauthorized")


async def test_collection_routes_validate_boundary_parameters_and_preserve_delete_route(
    collection_db,
):
    db = collection_db
    app = FastAPI()
    app.include_router(entries.router)
    app.include_router(measures.router)
    app.include_router(audio.router)
    app.state.settings = db.settings
    app.state.rate_counter = SlidingWindowCounter()
    app.dependency_overrides[require_regular_user] = lambda: db.owner

    async def session():
        yield db.session

    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        for path in ["/entries", "/measures"]:
            for query in ["offset=100000", "limit=1", "page_bytes=1"]:
                result = await client.get(path + "?" + query)
                assert result.status_code == 200, result.text
            for query in ["offset=100001", "limit=0", "limit=501", "page_bytes=0"]:
                assert (await client.get(path + "?" + query)).status_code == 422
            result = await client.get(path + "?expected_revision=garbage")
            assert result.status_code == 422
        assert (await client.delete("/measures/missing")).status_code == 422
        schema = app.openapi()
        for path, tag in [
            ("/entries", "entries"),
            ("/measures", "measures"),
            ("/audio/transcriptions", "audio"),
        ]:
            assert schema["paths"][path]["post"]["tags"] == [tag]
        assert (
            schema["paths"]["/audio/attachments/{attachment_id}"]["delete"]["responses"].get("204")
            is not None
        )


@pytest.mark.parametrize(
    "operation",
    [
        "entry_create",
        "entry_replace",
        "entry_delete",
        "entry_list",
        "measure_create",
        "measure_list",
        "measure_delete",
        "audio_transcribe",
        "audio_translate",
        "audio_upload",
        "audio_fetch",
        "audio_delete",
    ],
)
async def test_lifecycle_operations_wait_for_account_fence_without_leaking_tasks(
    collection_db, monkeypatch, operation
):
    db = collection_db
    entered = asyncio.Event()
    get = db.session.get

    async def observe(*args, **kwargs):
        entered.set()
        return await get(*args, **kwargs)

    scalar = db.session.scalar

    async def observe_scalar(*args, **kwargs):
        entered.set()
        return await scalar(*args, **kwargs)

    monkeypatch.setattr(db.session, "get", observe)
    monkeypatch.setattr(db.session, "scalar", observe_scalar)
    from app.api import account as account_module

    async def verifier(*args):
        pass

    monkeypatch.setattr(account_module, "_require_verifier", verifier)

    async def transcribe(*args):
        return SimpleNamespace(text="", language_iso=None, language_raw="")

    monkeypatch.setattr(
        audio.stt, "get_stt", lambda settings: SimpleNamespace(transcribe=transcribe)
    )

    async def invoke():
        if operation == "entry_create":
            return await entries.create_entry(
                EntryCreate(client_entry_id="fenced", blob=b64(BLOB), entry_date=TODAY),
                db.request,
                db.owner,
                db.session,
            )
        if operation == "entry_list":
            return await entries.list_entries(
                Response(), db.owner, db.session, None, None, 0, 1, None, None
            )
        if operation == "entry_replace":
            return await entries.replace_entry(
                "missing",
                EntryReplace(blob=b64(BLOB), entry_date=TODAY),
                db.request,
                db.owner,
                db.session,
            )
        if operation == "entry_delete":
            return await entries.delete_entry(
                "missing", Response(), db.request, db.owner, db.session
            )
        if operation == "measure_create":
            return await measures.create_measure(
                MeasureCreate(client_measure_id="fenced", blob=b64(BLOB), measure_date=TODAY),
                db.request,
                db.owner,
                db.session,
            )
        if operation == "measure_list":
            return await measures.list_measures(Response(), db.owner, db.session, 1, 0, None, None)
        if operation == "measure_delete":
            return await measures.delete_measure(
                "missing", db.request, Response(), db.owner, db.session, "verifier"
            )
        if operation == "audio_translate":
            return await audio.translate_text(
                AudioTranslationRequest(text="private"), db.request, db.owner, None, db.session
            )
        if operation == "audio_transcribe":
            return await audio.transcribe_recording(
                AudioTranscriptionRequest(
                    audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1
                ),
                db.request,
                db.owner,
                None,
                db.session,
            )
        if operation == "audio_upload":
            return await audio.upload_attachment(
                attachment_body("missing"), db.request, db.owner, None, db.session
            )
        return await getattr(
            audio, "fetch_attachment" if operation == "audio_fetch" else "delete_attachment"
        )("missing", db.request, db.owner, None, db.session)

    task = None
    try:
        async with entries.lifecycle_locks.hold(f"llm-lifecycle:{OWNER}"):
            task = asyncio.create_task(invoke())
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(entered.wait(), timeout=0.05)
            assert not task.done()
        with suppress(ApiError):
            await asyncio.wait_for(task, timeout=2)
        assert entered.is_set()
    finally:
        if task is not None and not task.done():
            task.cancel()
        if task is not None:
            with suppress(asyncio.CancelledError, ApiError):
                await task


@pytest.mark.parametrize("operation", ["transcribe", "translate", "upload", "fetch", "delete"])
async def test_audio_rechecks_account_activity_before_dispatch_or_object_access(
    collection_db, monkeypatch, operation
):
    db = collection_db

    async def transcribe(*args):
        pytest.fail("deactivated account reached speech provider")

    monkeypatch.setattr(audio.stt, "get_stt", lambda config: SimpleNamespace(transcribe=transcribe))
    async with db.engine.begin() as connection:
        await connection.execute(update(User).where(User.id == OWNER).values(is_active=False))
    with pytest.raises(ApiError) as failure:
        if operation == "transcribe":
            await audio.transcribe_recording(
                AudioTranscriptionRequest(
                    audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1
                ),
                db.request,
                db.owner,
                None,
                db.session,
            )
        elif operation == "translate":
            await audio.translate_text(
                AudioTranslationRequest(text="private"), db.request, db.owner, None, db.session
            )
        elif operation == "upload":
            await audio.upload_attachment(
                attachment_body("missing"), db.request, db.owner, None, db.session
            )
        else:
            await getattr(
                audio, "fetch_attachment" if operation == "fetch" else "delete_attachment"
            )("missing", db.request, db.owner, None, db.session)
    if operation in ["transcribe", "translate"]:
        envelope(failure, 410, "account no longer exists", "account_deleted")
    else:
        envelope(failure, 401, "invalid token", "unauthorized")


async def test_audio_shared_transcription_rate_budget_applies_to_edited_translation(
    collection_db, monkeypatch
):
    db = collection_db
    db.settings.audio_transcribe_rate_limit = 1

    async def transcribe(*args):
        return SimpleNamespace(text="", language_iso=None, language_raw="")

    async def translate(*args):
        return "English"

    monkeypatch.setattr(audio.stt, "get_stt", lambda config: SimpleNamespace(transcribe=transcribe))
    monkeypatch.setattr(audio.stt, "translation_dispatch_allowed", lambda *args: True)
    monkeypatch.setattr(audio.stt, "translate_to_english", translate)
    app = FastAPI()
    app.include_router(audio.router)
    app.state.settings = db.settings
    app.state.rate_counter = SlidingWindowCounter()
    app.dependency_overrides[require_regular_user] = lambda: db.owner

    async def session():
        yield db.session

    app.dependency_overrides[get_session] = session
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.post(
            "/audio/transcriptions",
            json=dict(audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1),
        )
        assert first.status_code == 200, first.text
        edited = await client.post("/audio/translations", json=dict(text="edited transcript"))
        assert edited.status_code == 429, edited.text


async def test_audio_quota_includes_only_live_owner_objects_and_exact_empty_budget(collection_db):
    db = collection_db
    await make_entry(db, "empty")
    db.settings.audio_max_user_bytes = len(BLOB)
    with pytest.raises(ApiError) as failure:
        await audio.upload_attachment(
            attachment_body("empty", BLOB + b"x"), db.request, db.owner, None, db.session
        )
    envelope(failure, 413, "audio storage quota reached", "audio_quota_exceeded")
    made = await audio.upload_attachment(
        attachment_body("empty"), db.request, db.owner, None, db.session
    )
    row = await db.session.get(AudioAttachment, made.attachment_id)
    row.expires_at = NOW
    await db.session.commit()
    await make_entry(db, "after-expiry")
    again = await audio.upload_attachment(
        attachment_body("after-expiry"), db.request, db.owner, None, db.session
    )
    assert again.size_bytes == len(BLOB)
    with pytest.raises(ApiError) as failure:
        await audio.upload_attachment(
            attachment_body("empty"), db.request, db.owner, None, db.session
        )
    envelope(failure, 413, "audio storage quota reached", "audio_quota_exceeded")
    with pytest.raises(ApiError) as failure:
        await audio.upload_attachment(
            attachment_body("after-expiry", duration=11), db.request, db.owner, None, db.session
        )
    envelope(failure, 422, "recording duration exceeds the allowed maximum", "validation_error")


async def test_audio_deletion_reloads_cached_attachment_custody(collection_db):
    db = collection_db
    await make_entry(db, "moved")
    made = await audio.upload_attachment(
        attachment_body("moved"), db.request, db.owner, None, db.session
    )
    cached = await db.session.get(AudioAttachment, made.attachment_id)
    assert cached.user_id == OWNER
    async with db.engine.begin() as connection:
        await connection.execute(
            update(AudioAttachment)
            .where(AudioAttachment.id == made.attachment_id)
            .values(user_id=OTHER)
        )
    with pytest.raises(ApiError) as failure:
        await audio.delete_attachment(made.attachment_id, db.request, db.owner, None, db.session)
    envelope(failure, 404, "attachment not found", "not_found")
    await db.session.refresh(cached)
    assert cached.user_id == OTHER
    assert (await db.session.scalars(select(AudioDeletion))).all() == []


@pytest.mark.parametrize(
    "module,model,field,day",
    [
        (entries, Entry, "client_entry_id", "entry_date"),
        (measures, Measure, "client_measure_id", "measure_date"),
    ],
)
async def test_default_page_is_one_hundred_rows_and_exact_final_page_has_no_continuation(
    collection_db, module, model, field, day
):
    db = collection_db
    db.session.add_all(
        [
            model(user_id=OWNER, blob=BLOB, received_at=NOW, **{field: f"row-{i:03d}", day: TODAY})
            for i in range(101)
        ]
    )
    await db.session.commit()
    app = FastAPI()
    app.include_router(module.router)
    app.state.settings = db.settings
    app.state.rate_counter = SlidingWindowCounter()
    app.dependency_overrides[require_regular_user] = lambda: db.owner

    async def session():
        yield db.session

    app.dependency_overrides[get_session] = session
    path = "/entries" if module is entries else "/measures"
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    ) as client:
        first = await client.get(path)
        assert first.status_code == 200 and len(first.json()) == 100
        assert first.headers["X-Next-Offset"] == "100"
        final = await client.get(path + "?offset=99&limit=2")
        assert final.status_code == 200 and len(final.json()) == 2
        assert "X-Next-Offset" not in final.headers


async def test_speech_provider_failure_uses_only_the_safe_aggregate_application_warning(
    collection_db, monkeypatch, caplog
):
    db = collection_db

    async def failed(*args):
        raise RuntimeError("PRIVATE_TRANSCRIPT_DO_NOT_LOG")

    monkeypatch.setattr(audio.stt, "get_stt", lambda config: SimpleNamespace(transcribe=failed))
    with caplog.at_level(logging.WARNING, logger="mindpattern"):
        with pytest.raises(ApiError) as failure:
            await audio.transcribe_recording(
                AudioTranscriptionRequest(
                    audio_b64=b64(BLOB), mime="audio/webm", duration_seconds=1
                ),
                db.request,
                db.owner,
                None,
                db.session,
            )
    envelope(failure, 502, "speech-to-text provider failed; try again", "stt_upstream")
    # Operators may attach their component handler to the application's
    # logger hierarchy. Provider text and exceptions must never enter it.
    assert [(r.name, r.levelno, r.getMessage(), r.exc_info) for r in caplog.records] == [
        ("mindpattern.audio", logging.WARNING, "stt upstream failed", None)
    ]
    assert db.audit == [
        dict(actor_id=OWNER, actor_role="user", user_id=OWNER, action="stt_dispatch_attempt")
    ]


@pytest.mark.parametrize(
    "module,model,field,day,label,header",
    [
        (entries, Entry, "client_entry_id", "entry_date", "entries", "X-Entries-Revision"),
        (measures, Measure, "client_measure_id", "measure_date", "measures", "X-Measures-Revision"),
    ],
)
async def test_missing_fetched_row_returns_the_collection_specific_retry_contract(
    collection_db, monkeypatch, module, model, field, day, label, header
):
    db = collection_db
    db.session.add(model(user_id=OWNER, blob=BLOB, **{field: "vanished", day: TODAY}))
    await db.session.commit()
    execute = db.session.execute

    async def lose_fetched_rows(statement, *args, **kwargs):
        # Model a worker outside the one-process fence deleting between
        # metadata selection and the full row fetch. The declared retry
        # backstop must remain fail closed and identify its collection.
        description = getattr(statement, "column_descriptions", [])
        if len(description) == 1 and description[0].get("expr") is model:
            statement = statement.where(model.id == "missing")
        return await execute(statement, *args, **kwargs)

    monkeypatch.setattr(db.session, "execute", lose_fetched_rows)
    with pytest.raises(ApiError) as failure:
        if module is entries:
            await entries.list_entries(
                Response(), db.owner, db.session, None, None, 0, 2, None, None
            )
        else:
            await measures.list_measures(Response(), db.owner, db.session, 2, 0, None, None)
    envelope(
        failure,
        409,
        f"{label} changed while paging; retry the request",
        "collection_changed",
        {header: "0"},
    )


@pytest.mark.parametrize(
    "module, model, field, day",
    [
        (entries, Entry, "client_entry_id", "entry_date"),
        (measures, Measure, "client_measure_id", "measure_date"),
    ],
)
async def test_sqlite_blob_byte_queries_work_without_optional_newer_sqlite_functions(
    collection_db, module, model, field, day
):
    db = collection_db
    row = model(user_id=OWNER, blob=BLOB, **{field: "portable", day: TODAY})
    db.session.add(row)
    await db.session.commit()

    def unavailable(value):
        raise NotImplementedError("older supported SQLite has no octet_length")

    async with db.engine.begin() as connection:
        await connection.run_sync(
            lambda c: c.connection.create_function("octet_length", 1, unavailable)
        )
    expression = (
        entries._blob_length(db.session)
        if module is entries
        else measures._measure_blob_length(db.session)
    )
    assert await db.session.scalar(select(expression).where(model.user_id == OWNER)) == len(BLOB)


@pytest.mark.parametrize("kind", ["entries", "measures"])
async def test_legacy_pages_enforce_real_two_mib_budget_and_modern_clients_reach_exact_boundary(
    collection_db, kind
):
    db = collection_db
    if kind == "entries":
        sizes = [1024 * 1024, 1024 * 1024, 28]
        rows = [
            Entry(
                id=f"{index:032x}",
                user_id=OWNER,
                client_entry_id=f"budget-{index}",
                blob=b"x" * size,
                entry_date=TODAY,
                received_at=NOW,
            )
            for index, size in enumerate(sizes)
        ]

        async def read(response, budget):
            return await entries.list_entries(
                response, db.owner, db.session, None, None, 0, 500, budget, None
            )

        label, returned = "entry", 2
    else:
        sizes = [6144] * 341 + [2048, 28]
        rows = [
            Measure(
                id=f"{len(sizes) - index:032x}",
                user_id=OWNER,
                client_measure_id=f"budget-{index}",
                blob=b"x" * size,
                measure_date=TODAY,
                received_at=NOW,
            )
            for index, size in enumerate(sizes)
        ]

        async def read(response, budget):
            return await measures.list_measures(
                response, db.owner, db.session, 500, 0, budget, None
            )

        label, returned = "measure", 342
    db.session.add_all(rows)
    await db.session.commit()
    with pytest.raises(ApiError) as failure:
        await read(Response(), None)
    envelope(
        failure,
        413,
        f"requested {label} page exceeds the 2 MiB ciphertext budget; upgrade to a byte-paginating client",
        "payload_too_large",
    )
    await db.session.rollback()
    await db.session.refresh(db.owner)
    response = Response()
    result = await read(response, 2097152)
    assert len(result) == returned and response.headers["X-Next-Offset"] == str(returned)
    assert sum(len(base64.b64decode(row.blob)) for row in result) == 2097152
