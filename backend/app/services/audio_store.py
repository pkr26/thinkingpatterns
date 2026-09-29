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
import uuid
from datetime import timedelta
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..models import AudioAttachment, utcnow

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

    def __init__(self, bucket: str, region: str = "", access_key_id: str = "",
                 secret_access_key: str = "", endpoint: str = "") -> None:
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

            kwargs: dict = {"service_name": "s3"}
            if self.region:
                kwargs["region_name"] = self.region
            if self.endpoint:
                # S3-compatible endpoint override (dev MinIO parity,
                # M4 remediation 2026-09-29): path-style addressing, or
                # boto3 would resolve virtual-hosted buckets against the
                # endpoint host.
                kwargs["endpoint_url"] = self.endpoint
                kwargs["config"] = Config(s3={"addressing_style": "path"})
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
            data = body.read(limit + 1)
            if len(data) > limit:
                raise ValueError("object exceeds the fetch size limit")
            return data

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
            path.write_bytes(blob)

        try:
            await asyncio.to_thread(_write)
        except OSError as exc:
            raise AudioStoreError(f"local put failed: {type(exc).__name__}") from exc

    async def get(self, key: str, *, max_bytes: int | None = None) -> bytes:
        path = self._path(key)

        def _read() -> bytes:
            data = path.read_bytes()
            if max_bytes is not None and len(data) > max_bytes:
                raise ValueError("object exceeds the fetch size limit")
            return data

        try:
            return await asyncio.to_thread(_read)
        except FileNotFoundError as exc:
            raise AudioStoreError("object missing") from exc
        except OSError as exc:
            raise AudioStoreError(f"local get failed: {type(exc).__name__}") from exc

    async def delete(self, key: str) -> None:
        path = self._path(key)
        try:
            await asyncio.to_thread(path.unlink, True)  # missing_ok: sweep idempotence
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


async def sweep_expired_audio(session: AsyncSession, store) -> int:
    """Delete one batch of expired attachments (objects first, then rows).

    Returns the number swept (0 when the feature/store is unconfigured —
    the recurring task treats that as a cheap no-op, not an error). Row
    deletion only happens after its object delete succeeded, so a store
    outage cannot orphan rows; an orphaned OBJECT (rows removed by the
    account cascade) is the documented S3-lifecycle backstop's job.
    """
    if store is None:
        return 0
    now = utcnow()
    rows = (
        (
            await session.execute(
                select(AudioAttachment)
                .where(AudioAttachment.expires_at < now)
                .order_by(AudioAttachment.expires_at.asc())
                .limit(SWEEP_BATCH)
            )
        )
        .scalars()
        .all()
    )
    swept = 0
    for row in rows:
        try:
            await store.delete(row.storage_key)
        except AudioStoreError:
            logger.warning(
                "audio sweep: object delete failed for %s; retrying next cycle",
                row.id,
            )
            continue
        await session.delete(row)
        swept += 1
    if swept:
        await session.commit()
    return swept


def attachment_expiry(settings: Settings):
    """The expires_at instant for a freshly stored attachment."""
    return utcnow() + timedelta(days=settings.audio_retention_days)
