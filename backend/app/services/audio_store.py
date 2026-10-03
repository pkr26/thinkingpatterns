"""Object storage for kept voice recordings (VOICE_PLAN.md P2, 2026-09-29).

The store holds OPAQUE client-side ciphertext only — the server can never
decrypt what it puts and gets here. Two backends:

  * ``S3AudioStore`` — boto3 (thread-offloaded via asyncio.to_thread, the
    same worker-thread discipline the recompute path uses for blocking
    crypto). SSE-S3 server-side encryption at rest as defense-in-depth
    UNDER the client's AES-GCM envelope. Keys are always server-generated
    (``audio/{user_id}/{32-hex}.enc``); the client-supplied
    client_entry_id is never used in a path.
  * ``LocalAudioStore`` — the development/self-host filesystem fallback
    (``MINDPATTERN_AUDIO_LOCAL_DIR``); selected automatically in
    development when no bucket is configured, mirroring the
    get_enricher-style "unconfigured degrades visibly" posture.

Selection (``get_audio_store``): bucket configured → S3; explicit local
dir → local; development default → local under ./data/audio; anything
else → None (attachments answer 503 audio_storage_unconfigured —
transcription is unaffected).

Retention: rows carry ``expires_at``; ``sweep_expired_audio`` deletes
expired rows AFTER their objects (a failed object delete retries next
cycle; an orphaned object cannot happen in that order, and account-level
cascades that remove rows without object deletes are caught by the
optional 31-day S3 lifecycle backstop documented in the plan).
"""

from __future__ import annotations

import asyncio
import logging
import json
import os
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import AudioAttachment, AudioDeletion, User, new_id, utcnow
from ..locks import lifecycle_locks

logger = logging.getLogger("mindpattern.audio_store")

# One sweep deletes at most this many expired attachments per cycle: the
# object deletes fan out through the store's own concurrency, and a
# backlogged deployment catches up over cycles instead of holding one
# long transaction.
SWEEP_BATCH = 500

# Sentinel for "no fetch cap" (the S3 get path keeps a uniform limit+1
# read shape; an int this large is effectively unbounded).
ST_S3_UNCAPPED = 1 << 40


class AudioStoreError(RuntimeError):
    """The object store failed (put/get/delete). Callers map this to 502
    for reads and 503 for writes; never retried inline — the entry itself
    already stands, only the kept recording is at stake."""


def new_storage_key(user_id: str) -> str:
    """Server-generated, traversal-free object key for one attachment.

    The user_id is a server-known 32-hex id and the tail is a fresh uuid;
    nothing client-controlled ever reaches a path.
    """
    return f"audio/{user_id}/{uuid.uuid4().hex}.enc"


class S3AudioStore:
    """boto3-backed store; blocking calls run in worker threads."""

    backend = "s3"

    def __init__(
        self,
        bucket: str,
        region: str = "",
        access_key_id: str = "",
        secret_access_key: str = "",
        endpoint: str = "",
    ) -> None:
        self.bucket = bucket
        self.region = region
        self.endpoint = endpoint.strip()
        self._access_key_id = access_key_id
        self._secret_access_key = secret_access_key
        self._client = None

    def _s3(self):
        if self._client is None:
            import boto3  # imported lazily; absent in minimal dev envs
            from botocore.config import Config

            # 2026-09-29 deep audit (HIGH F2): EXPLICIT transport budgets —
            # botocore's defaults (60s connect/read, many retries) run
            # inside open DB transactions while user locks are held, so a
            # slow or throttled bucket could stall that user's whole
            # lifecycle fence for minutes. Five seconds to connect, ten to
            # read, one retry: object storage for bounded blobs, not a
            # patient-facing hang.
            transport = Config(
                connect_timeout=5,
                read_timeout=10,
                retries={"max_attempts": 1, "mode": "standard"},
            )
            kwargs: dict = {"service_name": "s3"}
            if self.region:
                kwargs["region_name"] = self.region
            if self.endpoint:
                # S3-compatible endpoint override (dev MinIO parity,
                # M4 remediation 2026-09-29): path-style addressing, or
                # boto3 would resolve virtual-hosted buckets against the
                # endpoint host.
                kwargs["endpoint_url"] = self.endpoint
                kwargs["config"] = Config(
                    s3={"addressing_style": "path"},
                    connect_timeout=5,
                    read_timeout=10,
                    retries={"max_attempts": 1, "mode": "standard"},
                )
            else:
                kwargs["config"] = transport
            if self._access_key_id and self._secret_access_key:
                kwargs["aws_access_key_id"] = self._access_key_id
                kwargs["aws_secret_access_key"] = self._secret_access_key
            self._client = boto3.client(**kwargs)
        return self._client

    async def put(self, key: str, blob: bytes) -> None:
        def _put() -> None:
            # SSE-S3: encryption at rest under the client-side envelope —
            # belt and braces, the real opacity guarantee is the AES-GCM
            # the patient's own key provides.
            self._s3().put_object(
                Bucket=self.bucket, Key=key, Body=blob, ServerSideEncryption="AES256"
            )

        try:
            await asyncio.to_thread(_put)
        except Exception as exc:
            raise AudioStoreError(f"s3 put failed: {type(exc).__name__}") from exc

    async def get(self, key: str, *, max_bytes: int | None = None) -> bytes:
        def _get() -> bytes:
            body = self._s3().get_object(Bucket=self.bucket, Key=key)["Body"]
            # The cap makes a compromised/misconfigured bucket unable to
            # turn a fetch into unbounded memory: read one byte past the
            # limit and refuse rather than buffering the object.
            limit = max_bytes if max_bytes is not None else ST_S3_UNCAPPED
            try:
                data = body.read(limit + 1)
                if len(data) > limit:
                    raise ValueError("object exceeds the fetch size limit")
                return data
            finally:
                body.close()

        try:
            return await asyncio.to_thread(_get)
        except Exception as exc:
            raise AudioStoreError(f"s3 get failed: {type(exc).__name__}") from exc

    async def delete(self, key: str) -> None:
        def _delete() -> None:
            self._s3().delete_object(Bucket=self.bucket, Key=key)

        try:
            await asyncio.to_thread(_delete)
        except Exception as exc:
            raise AudioStoreError(f"s3 delete failed: {type(exc).__name__}") from exc


class LocalAudioStore:
    """Filesystem store (dev/self-host). Same key discipline as S3."""

    backend = "local"

    def __init__(self, root: str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        # The key is always server-generated (new_storage_key), but resolve
        # and re-verify containment anyway — a store must never be able to
        # escape its root, even if a future caller passes something odd.
        path = (self.root / key).resolve()
        if self.root not in path.parents:
            raise AudioStoreError("storage key escapes the local root")
        return path

    async def put(self, key: str, blob: bytes) -> None:
        path = self._path(key)

        def _write() -> None:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
            try:
                temporary.write_bytes(blob)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)

        try:
            await asyncio.to_thread(_write)
        except OSError as exc:
            raise AudioStoreError(f"local put failed: {type(exc).__name__}") from exc

    async def get(self, key: str, *, max_bytes: int | None = None) -> bytes:
        path = self._path(key)

        def _read() -> bytes:
            with path.open("rb") as source:
                data = source.read(max_bytes + 1) if max_bytes is not None else source.read()
            if max_bytes is not None and len(data) > max_bytes:
                raise ValueError("object exceeds the fetch size limit")
            return data

        try:
            return await asyncio.to_thread(_read)
        except FileNotFoundError as exc:
            raise AudioStoreError("object missing") from exc
        except (OSError, ValueError) as exc:
            raise AudioStoreError(f"local get failed: {type(exc).__name__}") from exc

    async def delete(self, key: str) -> None:
        path = self._path(key)

        def _delete() -> None:
            path.unlink(True)  # missing_ok: sweep idempotence
            # Prune the now-empty user directory, best-effort (2026-09-29
            # E2E finding): the key layout embeds the account id, and an
            # account erasure that deletes every object but leaves
            # audio/<deleted-user-id>/ behind keeps the erased identity on
            # disk as a directory name. rmdir refuses non-empty dirs, so a
            # concurrent object for the same account simply keeps its dir.
            try:
                path.parent.rmdir()
            except OSError:
                pass

        try:
            await asyncio.to_thread(_delete)
        except OSError as exc:
            raise AudioStoreError(f"local delete failed: {type(exc).__name__}") from exc


def get_audio_store(settings: Settings):
    """The configured store, or None (attachments disabled).

    S3 when a bucket is named (production posture); an explicit local dir
    is a deliberate self-host opt-in valid anywhere; development falls
    back to a scratch dir so the whole contract is testable without S3.
    Production with neither is a misconfiguration the endpoints report
    loudly (503) rather than silently writing container-local disk.
    """
    if settings.audio_bucket.strip():
        return S3AudioStore(
            settings.audio_bucket.strip(),
            settings.audio_bucket_region.strip(),
            settings.audio_aws_access_key_id,
            settings.audio_aws_secret_access_key,
            endpoint=settings.audio_s3_endpoint,
        )
    if settings.audio_local_dir.strip():
        return LocalAudioStore(settings.audio_local_dir.strip())
    if settings.environment == "development":
        return LocalAudioStore("./data/audio")
    return None


# M9 remediation (audit 2026-09-29): routes used to construct a fresh
# store (and therefore a fresh boto3 client — connection pool, TLS
# session, ~100 ms of setup) per request, which also made the class's
# lazy client cache useless. The cached getter keeps ONE live store per
# distinct audio-storage configuration; a settings swap with different
# audio knobs builds a new one on the next call (the live-settings
# discipline), and the previous instance is simply dropped.
_audio_store_cache: dict[tuple, object] = {}


def _audio_store_signature(settings: Settings) -> tuple:
    return (
        settings.audio_bucket.strip(),
        settings.audio_bucket_region.strip(),
        settings.audio_s3_endpoint.strip(),
        settings.audio_local_dir.strip(),
        settings.environment,
        settings.audio_aws_access_key_id,
        settings.audio_aws_secret_access_key,
    )


def get_audio_store_cached(settings: Settings):
    cached = get_audio_store(settings)
    if cached is None:
        return None
    signature = _audio_store_signature(settings)
    shared = _audio_store_cache.get(signature)
    if shared is None:
        _audio_store_cache.clear()
        _audio_store_cache[signature] = cached
        return cached
    if type(shared) is type(cached):
        return shared
    _audio_store_cache.clear()
    _audio_store_cache[signature] = cached
    return cached


def storage_locator(store) -> str | None:
    if isinstance(store, LocalAudioStore):
        value = {"backend": "local", "root": str(store.root)}
    elif isinstance(store, S3AudioStore):
        value = {
            "backend": "s3",
            "bucket": store.bucket,
            "region": store.region,
            "endpoint": store.endpoint,
        }
    else:
        return None  # Test/provider adapters retain their configured store.
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def store_for_object(settings: Settings, row):
    store = get_audio_store_cached(settings)
    if store is None or store.backend != row.backend:
        raise AudioStoreError("original audio backend is unavailable")
    locator = getattr(row, "storage_locator", None)
    if locator is not None and locator != storage_locator(store):
        # DB metadata cannot authorize arbitrary local paths or cloud buckets.
        # Preserve the tombstone/row until the operator restores the original
        # target or performs an explicitly validated storage migration.
        raise AudioStoreError("original audio storage target is unavailable")
    return store


async def advance_audio_revision(session: AsyncSession, owner: str) -> None:
    from ..db import rowcount
    from ..deps import ApiError

    result = await session.execute(
        update(User)
        .where(User.id == owner, User.entries_revision < 2**63 - 1)
        .values(entries_revision=User.entries_revision + 1)
    )
    if rowcount(result) != 1:
        raise ApiError(
            status_code=503,
            detail="unable to advance attachment revision",
            code="service_unavailable",
        )


def enqueue_audio_delete(session: AsyncSession, row, *, store=None, not_before=None) -> str:
    identifier = new_id()
    if getattr(session, "info", None) is not None:
        session.info.setdefault("mindpattern_audio_deletions_pending", []).append(identifier)
    session.add(
        AudioDeletion(
            id=identifier,
            backend=row.backend,
            storage_key=row.storage_key,
            storage_locator=getattr(row, "storage_locator", None)
            or (storage_locator(store) if store is not None else None),
            not_before=not_before or utcnow(),
        )
    )
    return identifier


async def drain_audio_deletions(
    session: AsyncSession, settings: Settings, *, identifiers=None, limit: int = 50
) -> int:
    query = (
        select(AudioDeletion)
        .where(AudioDeletion.not_before <= utcnow())
        .order_by(AudioDeletion.not_before)
        .limit(limit)
    )
    if identifiers is not None:
        query = query.where(AudioDeletion.id.in_(identifiers))
    rows = list((await session.scalars(query)).all())
    await session.commit()  # No pooled transaction across provider I/O.
    removed = 0
    for row in rows:
        try:
            await store_for_object(settings, row).delete(row.storage_key)
        except AudioStoreError:
            row.attempts += 1
            row.not_before = utcnow() + timedelta(seconds=min(3600, 30 * 2 ** min(row.attempts, 7)))
            logger.warning("audio deletion deferred: tombstone %s", row.id)
        else:
            await session.delete(row)
            removed += 1
        await session.commit()
    return removed


async def sweep_expired_audio(
    session: AsyncSession, store, settings: Settings | None = None
) -> int:
    """Atomically expire rows and retain retryable object tombstones."""
    now = utcnow()
    identifiers = list(
        (
            await session.execute(
                select(AudioAttachment.id, AudioAttachment.user_id)
                .where(AudioAttachment.expires_at <= now)
                .order_by(AudioAttachment.expires_at)
                .limit(SWEEP_BATCH)
            )
        ).all()
    )
    await session.commit()
    swept = 0
    pending_ids = []
    for identifier, owner in identifiers:
        async with lifecycle_locks.hold(f"llm-lifecycle:{owner}"):
            row = await session.get(AudioAttachment, identifier, populate_existing=True)
            if row is not None and row.expires_at <= utcnow():
                pending_ids.append(enqueue_audio_delete(session, row, store=store))
                await session.delete(row)
                await advance_audio_revision(session, owner)
                await session.commit()
                swept += 1
    if settings is not None:
        await drain_audio_deletions(session, settings, identifiers=pending_ids)
    elif store is not None:
        # Compatibility for direct sweep callers with one explicitly supplied store.
        rows = list(
            (
                await session.scalars(
                    select(AudioDeletion).where(AudioDeletion.id.in_(pending_ids))
                )
            ).all()
        )
        for tombstone in rows:
            if tombstone.backend != store.backend or tombstone.storage_locator not in (
                None,
                storage_locator(store),
            ):
                continue
            try:
                await store.delete(tombstone.storage_key)
            except AudioStoreError:
                continue
            await session.delete(tombstone)
        await session.commit()
    return swept


def attachment_expiry(settings: Settings):
    """The expires_at instant for a freshly stored attachment."""
    return utcnow() + timedelta(days=settings.audio_retention_days)
