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

Not covered: multiple HOSTS sharing one database — that was never a
supported topology (the in-memory guarantees do not cross hosts regardless
of this lock); the README and docker-compose remain the contract for that.
"""

from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import tempfile
from types import TracebackType

logger = logging.getLogger("mindpattern")

# token -> lock file handle, so repeated create_app() in ONE process (the
# test suite does this constantly) never conflicts with itself.
_held: dict[str, "os.IOBase"] = {}


class MultipleWorkersError(RuntimeError):
    """Another process is already serving this deployment."""


def _lock_path(token_secret: str, database_url: str) -> str:
    digest = hashlib.sha256(
        f"mindpattern:{token_secret}:{database_url}".encode("utf-8")
    ).hexdigest()[:24]
    return os.path.join(tempfile.gettempdir(), f"mindpattern-single-{digest}.lock")


def acquire_single_process_lock(token_secret: str, database_url: str) -> str:
    """Raise MultipleWorkersError if another process holds the deployment."""
    path = _lock_path(token_secret, database_url)
    existing = _held.get(path)
    if existing is not None:
        return path  # this process already holds it (re-entrant)
    fd = open(path, "a+b")
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        fd.close()
        raise MultipleWorkersError(
            "another worker/process is already serving this deployment: the "
            "rate limiter, per-user locks, and processing-session keystore "
            "are all in-process (see locks.py / cache.py / enclave.py). Run "
            "ONE worker per instance; put shared counters/locks in Redis &c. "
            "before ever scaling horizontally."
        ) from None
    fd.truncate(0)
    fd.write(f"pid={os.getpid()}\n".encode())
    fd.flush()
    _held[path] = fd
    return path


def release_single_process_lock(token_secret: str, database_url: str) -> None:
    path = _lock_path(token_secret, database_url)
    fd = _held.pop(path, None)
    if fd is None:
        return
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
    finally:
        fd.close()


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
