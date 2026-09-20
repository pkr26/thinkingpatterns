"""Single-process lock hardening pins (2026-09-19 remediation).

The audit's finding: the deployment guard's flock sat in the SHARED temp
directory under a predictable name with default permissions — any local
user could pre-hold it (permanent unprivileged boot DoS), read the keyed
deployment digest + PID from it, and the acquire path followed symlinks
(``open("a+b").truncate(0)``). These tests pin the hardened contract:
private 0700 directory, 0600 lock file, O_NOFOLLOW, and loud failure on a
planted symlink.
"""

from __future__ import annotations

import fcntl
import os
import stat
import tempfile

import pytest

os.environ.setdefault("MINDPATTERN_ENV", "development")

from app import singleprocess  # noqa: E402
from app.singleprocess import (  # noqa: E402
    LockPathError,
    MultipleWorkersError,
    acquire_single_process_lock,
    release_single_process_lock,
)


@pytest.fixture()
def isolated_lock_dir(tmp_path, monkeypatch):
    """Each test gets its own lock directory via the env override."""
    lock_dir = tmp_path / "locks"
    monkeypatch.setenv(singleprocess.LOCK_DIR_ENV, str(lock_dir))
    yield lock_dir
    # Drop anything this test acquired so later tests start clean.
    for path in list(singleprocess._held):
        fd = singleprocess._held.pop(path)
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _identity(tag: str) -> tuple[str, str]:
    return f"secret-{tag}", f"sqlite+aiosqlite:///{tag}"


def test_lock_file_private_dir_and_mode(isolated_lock_dir):
    token, db = _identity("perms")
    path = acquire_single_process_lock(token, db)
    assert os.path.dirname(path) == str(isolated_lock_dir)
    mode = stat.S_IMODE(os.stat(path).st_mode)
    dir_mode = stat.S_IMODE(os.stat(isolated_lock_dir).st_mode)
    assert mode == 0o600, oct(mode)
    assert dir_mode == 0o700, oct(dir_mode)
    release_single_process_lock(token, db)


def test_default_dir_is_per_uid_private(monkeypatch, tmp_path):
    # No override: the lock lands in a per-uid 0700 subdir of the temp dir.
    monkeypatch.delenv(singleprocess.LOCK_DIR_ENV, raising=False)
    # gettempdir() caches its answer; override the cache for this test.
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path), raising=False)
    token, db = _identity("defaultdir")
    try:
        path = acquire_single_process_lock(token, db)
        expected_root = os.path.join(str(tmp_path), f"mindpattern-{os.getuid()}")
        assert os.path.dirname(path) == expected_root
        assert stat.S_IMODE(os.stat(expected_root).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    finally:
        release_single_process_lock(token, db)


def test_preheld_lock_blocks_boot(isolated_lock_dir):
    token, db = _identity("preheld")
    path = singleprocess._lock_path(token, db)
    # A separate open() is a separate lock description even in-process:
    # holding it here stands in for the attacker/second worker.
    attacker = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(attacker, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(MultipleWorkersError):
            acquire_single_process_lock(token, db)
    finally:
        os.close(attacker)
    # Once released, boot succeeds.
    assert acquire_single_process_lock(token, db) == path
    release_single_process_lock(token, db)


def test_symlink_at_lock_path_fails_loudly(isolated_lock_dir):
    token, db = _identity("symlink")
    isolated_lock_dir.mkdir(parents=True, exist_ok=True)
    canary = isolated_lock_dir.parent / "canary.txt"
    canary.write_text("precious content\n")
    path = singleprocess._lock_path(token, db)
    os.symlink(canary, path)
    with pytest.raises((LockPathError, OSError)):
        acquire_single_process_lock(token, db)
    # The canary was NOT truncated through the symlink.
    assert canary.read_text() == "precious content\n"


def test_reentrancy_within_process(isolated_lock_dir):
    token, db = _identity("reentrant")
    first = acquire_single_process_lock(token, db)
    second = acquire_single_process_lock(token, db)
    assert first == second
    release_single_process_lock(token, db)
    release_single_process_lock(token, db)  # second release is a no-op


def test_release_allows_next_holder(isolated_lock_dir):
    token, db = _identity("release")
    path = acquire_single_process_lock(token, db)
    release_single_process_lock(token, db)
    nxt = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(nxt, fcntl.LOCK_EX | fcntl.LOCK_NB)  # must not raise
    finally:
        os.close(nxt)


def test_guard_context_manager_roundtrip(isolated_lock_dir):
    token, db = _identity("ctx")
    with singleprocess.single_process_guard(token, db):
        assert singleprocess._lock_path(token, db) in singleprocess._held
    assert singleprocess._lock_path(token, db) not in singleprocess._held


def test_distinct_deployments_do_not_conflict(isolated_lock_dir):
    t1, d1 = _identity("deployA")
    t2, d2 = _identity("deployB")
    p1 = acquire_single_process_lock(t1, d1)
    p2 = acquire_single_process_lock(t2, d2)
    assert p1 != p2
    release_single_process_lock(t1, d1)
    release_single_process_lock(t2, d2)
