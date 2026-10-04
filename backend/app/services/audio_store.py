"""Object storage for kept voice recordings (docs/plans/voice-plan.md P2, 2026-09-29).

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

Retention: rows carry ``expires_at``. Expiry atomically replaces the row
with a retryable deletion tombstone; a provider failure never loses the
deletion intent. Inventory reconciliation independently removes untracked
objects and force-retries tombstoned objects once the configured lifecycle
ceiling is reached, for both S3 and the local self-host store.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import Settings
from ..locks import lifecycle_locks
from ..models import (
    AudioAttachment,
    AudioDeletion,
    AudioInventoryCursor,
    User,
    new_id,
    utcnow,
)

logger = logging.getLogger("mindpattern.audio_store")

# One sweep deletes at most this many expired attachments per cycle: the
# object deletes fan out through the store's own concurrency, and a
# backlogged deployment catches up over cycles instead of holding one
# long transaction.
SWEEP_BATCH = 500

# Inventory reconciliation deliberately advances only one bounded page per
# sweep.  The durable cursor below makes that limit fair: a large store is
# covered over successive cycles instead of materializing every object/key
# and every matching database row in one process-sized list.
INVENTORY_BATCH = 500

# A drain commits ownership before provider I/O. This comfortably exceeds
# the S3 transport's bounded connect/read/retry budget, and a crashed or
# cancelled worker leaves a tombstone that becomes retryable after the lease.
DELETION_LEASE_SECONDS = 300

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
            raise AudioStoreError("object-store put failed") from exc

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
            raise AudioStoreError("object-store get failed") from exc

    async def delete(self, key: str) -> None:
        def _delete() -> None:
            self._s3().delete_object(Bucket=self.bucket, Key=key)

        try:
            await asyncio.to_thread(_delete)
        except Exception as exc:
            raise AudioStoreError("object-store delete failed") from exc

    async def inventory_page(
        self, *, after_key: str | None, limit: int
    ) -> tuple[list[tuple[str, datetime]], str | None]:
        """Return one lexicographically ordered, bounded S3 inventory page."""

        if limit < 1:
            raise ValueError("inventory page limit must be positive")

        def _list() -> tuple[list[tuple[str, datetime]], str | None]:
            kwargs: dict = {
                "Bucket": self.bucket,
                "Prefix": "audio/",
                "MaxKeys": limit,
            }
            if after_key:
                kwargs["StartAfter"] = after_key
            response = self._s3().list_objects_v2(**kwargs)
            raw_items = sorted(response.get("Contents", []), key=lambda item: str(item["Key"]))
            # MaxKeys is authoritative for S3, but bound a non-conforming
            # adapter/response as defense in depth.
            provider_has_more = bool(response.get("IsTruncated")) or len(raw_items) > limit
            raw_items = raw_items[:limit]
            found: list[tuple[str, datetime]] = []
            for item in raw_items:
                modified = item.get("LastModified")
                if not isinstance(modified, datetime):
                    # Advancing past an object whose age cannot be evaluated
                    # would silently defeat the lifecycle ceiling.
                    raise ValueError("inventory object has no modification timestamp")
                found.append((str(item["Key"]), modified))
            next_after = found[-1][0] if provider_has_more and found else None
            return found, next_after

        try:
            return await asyncio.to_thread(_list)
        except Exception as exc:
            raise AudioStoreError("object-store inventory failed") from exc


class LocalAudioStore:
    """Filesystem store (dev/self-host). Same key discipline as S3.

    Inventory is backed by a small derived SQLite manifest.  A new
    reconciliation cycle walks the object tree once, in bounded-memory
    batches, and every continuation page is then an indexed keyset query.
    The manifest is not an authority: put/delete maintain it eagerly and a
    cycle-start scan repairs crash windows and discovers orphaned files.
    """

    backend = "local"
    _MANIFEST_NAME = ".mindpattern-audio-inventory.sqlite3"
    _MANIFEST_BATCH = 500

    def __init__(self, root: str) -> None:
        self.root = Path(root).expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self._manifest_path = self.root / self._MANIFEST_NAME
        self._manifest_lock = threading.RLock()
        self._reconcile_lock = threading.Lock()
        self._manifest_initialized = False
        # A process restart reconciles before trusting a persisted manifest,
        # including when the database cursor resumes in the middle of a cycle.
        self._manifest_reconciled = False

    def _reset_manifest_unlocked(self) -> None:
        """Discard only the derived index after corruption; audio survives."""
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = Path(f"{self._manifest_path}{suffix}")
            if candidate.is_symlink():
                raise AudioStoreError("local audio inventory index is unsafe")
            candidate.unlink(missing_ok=True)

    @contextmanager
    def _manifest_connection_unlocked(self) -> Iterator[sqlite3.Connection]:
        if self._manifest_path.is_symlink():
            raise AudioStoreError("local audio inventory index is unsafe")

        if self._manifest_initialized:
            connection = sqlite3.connect(self._manifest_path, timeout=5)
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
        else:

            def open_and_prepare() -> sqlite3.Connection:
                candidate = sqlite3.connect(self._manifest_path, timeout=5)
                try:
                    candidate.execute("PRAGMA journal_mode=DELETE")
                    candidate.execute("PRAGMA synchronous=FULL")
                    candidate.executescript(
                        """
                        CREATE TABLE IF NOT EXISTS manifest_meta (
                            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                            generation INTEGER NOT NULL
                        );
                        INSERT OR IGNORE INTO manifest_meta (singleton, generation)
                        VALUES (1, 0);
                        CREATE TABLE IF NOT EXISTS manifest_objects (
                            object_key TEXT PRIMARY KEY,
                            modified_ns INTEGER NOT NULL,
                            seen_generation INTEGER NOT NULL
                        );
                        """
                    )
                    verdict = candidate.execute("PRAGMA quick_check").fetchone()
                    if verdict is None or verdict[0] != "ok":
                        raise sqlite3.DatabaseError("inventory index integrity check failed")
                    candidate.commit()
                    os.chmod(self._manifest_path, 0o600)
                    return candidate
                except BaseException:
                    candidate.close()
                    raise

            try:
                connection = open_and_prepare()
            except sqlite3.DatabaseError:
                # This file is only a cache of the filesystem. Rebuilding it
                # is safer than carrying forward a corrupt ordering view.
                self._reset_manifest_unlocked()
                connection = open_and_prepare()
            self._manifest_initialized = True
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _manifest_upsert_unlocked(self, key: str, path: Path) -> None:
        try:
            modified_ns = path.stat().st_mtime_ns
        except FileNotFoundError:
            return
        with self._manifest_connection_unlocked() as connection:
            generation = int(
                connection.execute(
                    "SELECT generation FROM manifest_meta WHERE singleton = 1"
                ).fetchone()[0]
            )
            connection.execute(
                """INSERT INTO manifest_objects
                       (object_key, modified_ns, seen_generation)
                   VALUES (?, ?, ?)
                   ON CONFLICT(object_key) DO UPDATE SET
                       modified_ns = excluded.modified_ns,
                       seen_generation = excluded.seen_generation""",
                (key, modified_ns, generation),
            )

    def _reconcile_manifest(self) -> None:
        """Walk the filesystem once and publish a crash-repaired generation."""
        # Separate from the short SQLite lock: put/delete must be able to
        # publish into the active generation while a long tree walk runs,
        # but two inventory callers may not interleave different generations.
        with self._reconcile_lock:
            self._reconcile_manifest_generation()

    def _reconcile_manifest_generation(self) -> None:
        with self._manifest_lock:
            with self._manifest_connection_unlocked() as connection:
                generation = (
                    int(
                        connection.execute(
                            "SELECT generation FROM manifest_meta WHERE singleton = 1"
                        ).fetchone()[0]
                    )
                    + 1
                )
                connection.execute(
                    "UPDATE manifest_meta SET generation = ? WHERE singleton = 1",
                    (generation,),
                )

        batch: list[Path] = []

        def publish(paths: list[Path]) -> None:
            if not paths:
                return
            with self._manifest_lock:
                rows: list[tuple[str, int, int]] = []
                for path in paths:
                    try:
                        if not path.is_file():
                            continue
                        key = path.relative_to(self.root).as_posix()
                        modified_ns = path.stat().st_mtime_ns
                    except (FileNotFoundError, ValueError):
                        continue
                    rows.append((key, modified_ns, generation))
                if rows:
                    with self._manifest_connection_unlocked() as connection:
                        connection.executemany(
                            """INSERT INTO manifest_objects
                                   (object_key, modified_ns, seen_generation)
                               VALUES (?, ?, ?)
                               ON CONFLICT(object_key) DO UPDATE SET
                                   modified_ns = excluded.modified_ns,
                                   seen_generation = excluded.seen_generation""",
                            rows,
                        )

        for path in self.root.glob("audio/**/*.enc"):
            batch.append(path)
            if len(batch) >= self._MANIFEST_BATCH:
                publish(batch)
                batch = []
        publish(batch)
        with self._manifest_lock:
            with self._manifest_connection_unlocked() as connection:
                # Eager put() calls use the current generation, so objects
                # created while the scan was in flight are retained even if
                # the directory iterator had already passed their location.
                connection.execute(
                    "DELETE FROM manifest_objects WHERE seen_generation < ?",
                    (generation,),
                )
        self._manifest_reconciled = True

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
                with self._manifest_lock:
                    self._manifest_upsert_unlocked(key, path)
            finally:
                temporary.unlink(missing_ok=True)

        try:
            await asyncio.to_thread(_write)
        except (OSError, sqlite3.Error) as exc:
            raise AudioStoreError("local audio put failed") from exc

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
            raise AudioStoreError("local audio get failed") from exc

    async def delete(self, key: str) -> None:
        path = self._path(key)

        def _delete() -> None:
            path.unlink(True)  # missing_ok: sweep idempotence
            with self._manifest_lock:
                with self._manifest_connection_unlocked() as connection:
                    connection.execute("DELETE FROM manifest_objects WHERE object_key = ?", (key,))
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
        except (OSError, sqlite3.Error) as exc:
            raise AudioStoreError("local audio delete failed") from exc

    async def inventory_page(
        self, *, after_key: str | None, limit: int
    ) -> tuple[list[tuple[str, datetime]], str | None]:
        """Return a bounded page from one crash-reconciled manifest."""

        if limit < 1:
            raise ValueError("inventory page limit must be positive")

        def _list() -> tuple[list[tuple[str, datetime]], str | None]:
            # Reconcile once after every process start and once at the start
            # of each completed cursor cycle. Continuations never walk the
            # object tree again.
            if not self._manifest_reconciled or after_key is None:
                self._reconcile_manifest()
            with self._manifest_lock:
                with self._manifest_connection_unlocked() as connection:
                    if after_key is None:
                        candidates = connection.execute(
                            """SELECT object_key, modified_ns
                                 FROM manifest_objects
                                ORDER BY object_key
                                LIMIT ?""",
                            (limit + 1,),
                        ).fetchall()
                    else:
                        candidates = connection.execute(
                            """SELECT object_key, modified_ns
                                 FROM manifest_objects
                                WHERE object_key > ?
                                ORDER BY object_key
                                LIMIT ?""",
                            (after_key, limit + 1),
                        ).fetchall()
            raw_has_more = len(candidates) > limit
            inspected = candidates[:limit]
            found: list[tuple[str, datetime]] = []
            missing: list[str] = []
            for key, indexed_modified_ns in inspected:
                path = self._path(key)
                try:
                    modified_ns = path.stat().st_mtime_ns
                except FileNotFoundError:
                    missing.append(key)
                    continue
                modified = datetime.fromtimestamp(modified_ns / 1_000_000_000, timezone.utc)
                found.append((key, modified))
                if modified_ns != int(indexed_modified_ns):
                    with self._manifest_lock:
                        self._manifest_upsert_unlocked(key, path)
            if missing:
                with self._manifest_lock:
                    with self._manifest_connection_unlocked() as connection:
                        connection.executemany(
                            "DELETE FROM manifest_objects WHERE object_key = ?",
                            [(key,) for key in missing],
                        )
            # If a page consisted partly (or wholly) of concurrently removed
            # files, advance across the inspected raw keys rather than
            # rescanning them. An empty page with a continuation is supported
            # by reconcile_audio_inventory.
            next_after = inspected[-1][0] if raw_has_more and inspected else None
            return found, next_after

        try:
            return await asyncio.to_thread(_list)
        except (OSError, sqlite3.Error) as exc:
            raise AudioStoreError("local audio inventory failed") from exc


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
            owner_id=getattr(row, "user_id", None),
            backend=row.backend,
            storage_key=row.storage_key,
            storage_locator=getattr(row, "storage_locator", None)
            or (storage_locator(store) if store is not None else None),
            not_before=not_before or utcnow(),
        )
    )
    return identifier


async def drain_audio_deletions(
    session: AsyncSession,
    settings: Settings,
    *,
    identifiers=None,
    limit: int = 50,
    failure_observer=None,
) -> int:
    from ..db import rowcount

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
        lease_until = utcnow() + timedelta(seconds=DELETION_LEASE_SECONDS)
        claim = await session.execute(
            update(AudioDeletion)
            .where(AudioDeletion.id == row.id, AudioDeletion.not_before <= utcnow())
            .values(not_before=lease_until)
            .returning(AudioDeletion.attempts)
        )
        attempts_before = claim.scalar_one_or_none()
        await session.commit()
        if attempts_before is None:
            continue
        owned = (
            AudioDeletion.id == row.id,
            AudioDeletion.not_before == lease_until,
        )
        try:
            await store_for_object(settings, row).delete(row.storage_key)
        except AudioStoreError:
            if failure_observer is not None:
                failure_observer()
            # A preloaded batch can outlive another drain's failed attempt
            # and retry delay. The claim returns the DB's current count;
            # using the stale ORM snapshot would reset exponential backoff.
            attempts = attempts_before + 1
            await session.execute(
                update(AudioDeletion)
                .where(*owned)
                .values(
                    attempts=attempts,
                    not_before=utcnow() + timedelta(seconds=min(3600, 30 * 2 ** min(attempts, 7))),
                )
            )
            logger.warning("audio deletion deferred after object-store failure")
        else:
            deleted = await session.execute(delete(AudioDeletion).where(*owned))
            removed += rowcount(deleted)
        await session.commit()
    return removed


async def sweep_expired_audio(
    session: AsyncSession, store, settings: Settings | None = None
) -> int:
    """Atomically expire rows and retain retryable object tombstones."""
    now = utcnow()
    ceiling_days = (
        (settings.audio_lifecycle_ceiling_days or settings.audio_retention_days + 1)
        if settings is not None
        else None
    )
    expiry_clause = AudioAttachment.expires_at <= now
    if ceiling_days is not None:
        from sqlalchemy import or_

        expiry_clause = or_(
            expiry_clause,
            AudioAttachment.created_at <= now - timedelta(days=ceiling_days),
        )
    identifiers = list(
        (
            await session.execute(
                select(AudioAttachment.id, AudioAttachment.user_id)
                .where(expiry_clause)
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
            if row is not None and (
                row.expires_at <= utcnow()
                or (
                    ceiling_days is not None
                    and row.created_at <= utcnow() - timedelta(days=ceiling_days)
                )
            ):
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


async def reconcile_audio_inventory(
    session: AsyncSession,
    store,
    settings: Settings,
    *,
    progress_observer=None,
) -> int:
    """Enforce the ceiling for one bounded, durable inventory page."""
    inventory_page = getattr(store, "inventory_page", None)
    if not callable(inventory_page):
        if progress_observer is not None:
            progress_observer(scanned=0, backlog=False, cycle_completed=True)
        return 0
    current_locator = storage_locator(store)
    store_id = hashlib.sha256(
        f"{store.backend}\0{current_locator or ''}".encode("utf-8")
    ).hexdigest()
    cursor = await session.get(AudioInventoryCursor, store_id)
    after_key = cursor.after_key if cursor is not None else None
    inventory, next_after = await inventory_page(after_key=after_key, limit=INVENTORY_BATCH)
    inventory_keys = [key for key, _modified in inventory]
    if not inventory_keys:
        if cursor is None:
            session.add(
                AudioInventoryCursor(store_id=store_id, after_key=next_after, updated_at=utcnow())
            )
        else:
            cursor.after_key = next_after
            cursor.updated_at = utcnow()
        await session.commit()
        if progress_observer is not None:
            progress_observer(
                scanned=0,
                backlog=next_after is not None,
                cycle_completed=next_after is None,
            )
        return 0
    attachment_keys = set(
        (
            await session.scalars(
                select(AudioAttachment.storage_key).where(
                    AudioAttachment.backend == store.backend,
                    (AudioAttachment.storage_locator == current_locator)
                    | (AudioAttachment.storage_locator.is_(None)),
                    AudioAttachment.storage_key.in_(inventory_keys),
                )
            )
        ).all()
    )
    tombstones = list(
        (
            await session.scalars(
                select(AudioDeletion)
                .where(
                    AudioDeletion.backend == store.backend,
                    (AudioDeletion.storage_locator == current_locator)
                    | (AudioDeletion.storage_locator.is_(None)),
                    AudioDeletion.storage_key.in_(inventory_keys),
                )
                .order_by(AudioDeletion.id)
                .limit(INVENTORY_BATCH)
            )
        ).all()
    )
    tombstones_by_key: dict[str, list[AudioDeletion]] = {}
    for row in tombstones:
        tombstones_by_key.setdefault(row.storage_key, []).append(row)
    ceiling_days = settings.audio_lifecycle_ceiling_days or settings.audio_retention_days + 1
    cutoff = utcnow() - timedelta(days=ceiling_days)
    removed = 0
    deferred = 0
    failure_classes: set[str] = set()
    deleted_tombstone_ids: list[str] = []
    for key, modified in inventory:
        if key in attachment_keys:
            continue
        key_tombstones = tombstones_by_key.get(key, [])
        force_tombstone = any(row.created_at <= cutoff for row in key_tombstones)
        if modified > cutoff and not force_tombstone:
            continue
        try:
            await store.delete(key)
        except AudioStoreError:
            deferred += 1
            # The provider exception is normalized at the store boundary;
            # log only this allowlisted class, never a subclass name or
            # message supplied by a third-party SDK.
            failure_classes.add("AudioStoreError")
            continue
        removed += 1
        if key_tombstones:
            deleted_tombstone_ids.extend(row.id for row in key_tombstones)
    if deleted_tombstone_ids:
        await session.execute(
            delete(AudioDeletion).where(AudioDeletion.id.in_(deleted_tombstone_ids))
        )
    if cursor is None:
        session.add(
            AudioInventoryCursor(store_id=store_id, after_key=next_after, updated_at=utcnow())
        )
    else:
        cursor.after_key = next_after
        cursor.updated_at = utcnow()
    await session.commit()
    if deferred:
        logger.warning(
            "audio lifecycle reconciliation deferred %d object(s); storage error class(es): %s",
            deferred,
            ",".join(sorted(failure_classes)),
        )
    if progress_observer is not None:
        progress_observer(
            scanned=len(inventory),
            backlog=next_after is not None,
            cycle_completed=next_after is None,
        )
    return removed


async def audio_deletion_backlog(session: AsyncSession) -> tuple[int, float]:
    """Aggregate deletion backlog count and oldest age, with no object ids."""
    from sqlalchemy import func

    count, oldest = (
        await session.execute(
            select(func.count(AudioDeletion.id), func.min(AudioDeletion.created_at))
        )
    ).one()
    age = max(0.0, (utcnow() - oldest).total_seconds()) if oldest is not None else 0.0
    return int(count or 0), age


def attachment_expiry(settings: Settings):
    """The expires_at instant for a freshly stored attachment."""
    return utcnow() + timedelta(days=settings.audio_retention_days)
