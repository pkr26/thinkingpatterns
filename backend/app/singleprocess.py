"""Single-process deployment guard.

Every concurrency primitive in this service is deliberately in-process:
the rate-limit counter (cache.py), the per-user asyncio locks (locks.py),
and the processing-session keystore (security/enclave.py). Running more
than one worker per instance fragments all three — the 2026-09-16 red-team
campaign demonstrated, against a live ``uvicorn --workers 2``: one
"single-use" session token answering 6 recomputes, a 5/min bucket admitting
9 of 12 requests, and the entry quota being exceeded (README documents
single-process as the deployment contract; nothing used to enforce it).

This guard makes the contract load-bearing: the first process to boot holds
an exclusive file lock keyed by the deployment identity (token secret +
database URL); any SECOND process serving the same deployment refuses to
start. Same-process re-entrancy (the test suite creating many apps) is
allowed via a module-level holder map.

Lock-file placement (2026-09-19 hardening). The file used to sit directly
in the SHARED temp directory under a predictable name with default
permissions, which made the guard itself an attack surface for any local
user: pre-holding the flock permanently blocked boot, the file's existence
leaked a keyed digest of (token secret, database URL) plus the service PID
to every reader, and ``open(..., "a+b").truncate(0)`` followed symlinks.
The file now lives in a private per-uid 0700 subdirectory (or an explicit
``MINDPATTERN_LOCK_DIR``), is created 0600, and is opened with
``O_NOFOLLOW`` so a symlink planted at the path fails boot LOUDLY instead
of truncating the symlink's target. Residual, documented honestly: a
process running as the SAME uid can still pre-hold the lock (that is what
an advisory flock is), and if something unlinks the lock file mid-run a
second boot would create a fresh inode and silently fragment the
in-process guarantees — bare-metal deployments should point
``MINDPATTERN_LOCK_DIR`` at a persistent, un-cleaned directory (inside the
container image the default private /tmp subdir already is one).

Not covered: multiple HOSTS sharing one database — that was never a
supported topology (the in-memory guarantees do not cross hosts regardless
of this lock); the README and docker-compose remain the contract for that.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import logging
import os
import tempfile
from types import TracebackType

from sqlalchemy.engine import URL, make_url

logger = logging.getLogger("mindpattern")

LOCK_DIR_ENV = "MINDPATTERN_LOCK_DIR"

# path -> (lock file descriptor, reference count). Repeated create_app() in
# ONE process (the test suite does this constantly, sometimes with
# OVERLAPPING lifespans) never conflicts with itself, and — since
# 2026-09-20 (M-27) — the flock is only dropped when the OUTERMOST scope
# exits: re-entrancy is refcounted, so an early inner release can no longer
# leave the outer scope serving with no lock held.
_held: dict[str, tuple[int, int]] = {}


class MultipleWorkersError(RuntimeError):
    """Another process is already serving this deployment."""


class LockPathError(RuntimeError):
    """The lock path exists but is not a safe regular file to lock."""


def _normalized_database_url(database_url: str) -> str:
    """Canonical spelling of the database URL for identity hashing (M-28).

    The deployment identity used to be the literal (secret, URL) string, so
    ``localhost`` vs ``127.0.0.1``, IPv6 bracket spellings, reordered query
    parameters, or a ``./``-prefixed SQLite path each derived a DIFFERENT
    lock path — two processes could then serve one database silently. Parsing
    through ``sqlalchemy.make_url`` and re-rendering collapses the spelling
    variants before hashing:

    * query parameters are re-emitted in sorted order
      (``?a=1&b=2`` == ``?b=2&a=1``),
    * loopback host spellings (``localhost`` / ``127.0.0.1`` / ``::1``)
      collapse to ``127.0.0.1`` when no port distinguishes them,
    * a PostgreSQL URL with no explicit port is materialized as the driver
      default ``:5432`` (``host/db`` == ``host:5432/db``),
    * SQLite database paths are ``os.path.normpath``-ed
      (``./mindpattern.db`` == ``mindpattern.db``).

    Deliberately NOT collapsed: credentials (a different user/password is a
    different deployment), non-loopback hostname aliases (DNS-level identity
    is environment knowledge this process must not guess), and ports. A URL
    sqlalchemy cannot parse falls back to the raw string, preserving the
    pre-normalization behavior for exotic spellings rather than refusing to
    boot.
    """
    try:
        url = make_url(database_url)
    except Exception:
        return database_url
    host = url.host
    if host is not None and host in ("localhost", "127.0.0.1", "::1"):
        host = "127.0.0.1"
    port = url.port
    if port is None and url.get_backend_name() == "postgresql":
        port = 5432
    database = url.database
    if url.get_backend_name() == "sqlite" and database:
        database = os.path.normpath(database)
    return URL.create(
        drivername=url.drivername,
        username=url.username,
        password=url.password,
        host=host,
        port=port,
        database=database,
        query=dict(sorted(url.query.items())),
    ).render_as_string(hide_password=False)


def _lock_dir() -> str:
    """A directory only this uid can write to.

    ``MINDPATTERN_LOCK_DIR`` wins when set (deployments on shared hosts
    should point it at a persistent private directory); the default is a
    per-uid 0700 subdir of the temp directory, so other local users can
    neither create nor read the lock file.
    """
    override = os.environ.get(LOCK_DIR_ENV, "").strip()
    if override:
        base = override
        os.makedirs(base, mode=0o700, exist_ok=True)
    else:
        base = os.path.join(tempfile.gettempdir(), f"mindpattern-{os.getuid()}")
        os.makedirs(base, mode=0o700, exist_ok=True)
    # makedirs' mode is only applied at creation: tighten a pre-existing
    # directory too, best-effort (a shared host may have created it looser).
    try:
        os.chmod(base, 0o700)
    except OSError:
        logger.warning("could not tighten permissions on lock dir %r", base)
    return base


def _lock_path(token_secret: str, database_url: str) -> str:
    digest = hashlib.sha256(
        f"mindpattern:{token_secret}:{_normalized_database_url(database_url)}".encode("utf-8")
    ).hexdigest()[:24]
    return os.path.join(_lock_dir(), f"mindpattern-single-{digest}.lock")


def acquire_single_process_lock(token_secret: str, database_url: str) -> str:
    """Raise MultipleWorkersError if another process holds the deployment."""
    path = _lock_path(token_secret, database_url)
    held = _held.get(path)
    if held is not None:
        # This process already holds the flock: re-entrant acquire just
        # deepens the reference count. Dropping the lock here (the
        # pre-2026-09-20 behavior) would leave an OUTER overlapping scope
        # serving with no flock — exactly what this guard exists to prevent.
        _held[path] = (held[0], held[1] + 1)
        return path
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise LockPathError(
                f"single-process lock path {path!r} is a symlink; refusing to "
                "lock or truncate it. Remove the symlink (or set "
                f"{LOCK_DIR_ENV} to a private directory) and restart."
            ) from exc
        raise
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        raise MultipleWorkersError(
            "another worker/process is already serving this deployment: the "
            "rate limiter, per-user locks, and processing-session keystore "
            "are all in-process (see locks.py / cache.py / enclave.py). Run "
            "ONE worker per instance; put shared counters/locks in Redis &c. "
            "before ever scaling horizontally."
        ) from None
    # Unlink detection (best-effort, at boot): if the path no longer leads
    # to our inode somebody removed the lock file after a previous run
    # acquired it — a tmp-cleaner pattern that would let the NEXT boot
    # silently fragment every in-process guarantee. Loud warning, not a
    # crash: this process holds a valid exclusive lock on a live inode.
    try:
        if os.stat(path).st_ino != os.fstat(fd).st_ino:
            logger.warning(
                "single-process lock path %r no longer names the locked "
                "inode; an external unlinked it — a second boot could now "
                "fragment in-process guarantees. Point %s at a persistent "
                "directory.",
                path,
                LOCK_DIR_ENV,
            )
    except OSError:
        pass
    os.ftruncate(fd, 0)
    os.write(fd, f"pid={os.getpid()}\n".encode())
    _held[path] = (fd, 1)
    return path


def release_single_process_lock(token_secret: str, database_url: str) -> None:
    path = _lock_path(token_secret, database_url)
    held = _held.get(path)
    if held is None:
        return
    fd, refs = held
    if refs > 1:
        # Inner scope of an overlapping acquisition: only drop the count.
        # The flock must outlive every scope that entered under it.
        _held[path] = (fd, refs - 1)
        return
    del _held[path]
    try:
        fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


class single_process_guard:
    """Context manager wrapper for the lifespan."""

    def __init__(self, token_secret: str, database_url: str) -> None:
        self._token_secret = token_secret
        self._database_url = database_url

    def __enter__(self) -> "single_process_guard":
        acquire_single_process_lock(self._token_secret, self._database_url)
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        release_single_process_lock(self._token_secret, self._database_url)
