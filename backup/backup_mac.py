#!/usr/bin/env python3
"""Create or verify an authenticated backup sidecar.

OpenSSL ``enc`` deliberately does not offer an AEAD mode.  The backup worker
therefore encrypts its pg_dump with AES-256-CBC/PBKDF2 and authenticates the
result with a domain-separated HMAC-SHA-256.  Keeping this tiny operation in
Python avoids placing BACKUP_KEY in a process argument (which ``openssl dgst
-hmac`` would do) and gives operators one exact verification command.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DOMAIN = b"mindpattern-backup-hmac-v1"


def _resolve_backup_key() -> str:
    """Resolve the backup key exactly like app.config._secret_env.

    2026-09-28 audit (CRITICAL): the compose backup worker delivers the key
    as a mounted FILE (BACKUP_KEY_FILE=/run/secrets/backup_key) and sets the
    plain env var to "" — the old env-only read raised on every run, so the
    entrypoint's && chain failed and zero backups were published. Resolution
    order mirrors backend/app/config.py: env BACKUP_KEY first (dev overlay
    path), else the file named by BACKUP_KEY_FILE with surrounding
    whitespace stripped. The env var is deliberately NOT exported in
    compose: keeping it out of the container environment preserves the
    docker-inspect posture the file mount was introduced for.
    """
    raw = os.environ.get("BACKUP_KEY", "").strip()
    if raw:
        return _validate_secret(raw)
    file_name = os.environ.get("BACKUP_KEY_FILE", "").strip()
    if not file_name:
        raise RuntimeError("BACKUP_KEY is required (env BACKUP_KEY or file BACKUP_KEY_FILE)")
    try:
        with open(file_name, encoding="utf-8") as handle:
            content = handle.read().strip()
    except OSError as exc:
        raise RuntimeError(f"BACKUP_KEY_FILE={file_name!r} could not be read: {exc}") from exc
    if not content:
        raise RuntimeError(f"BACKUP_KEY_FILE={file_name!r} is empty")
    return _validate_secret(content)


def _validate_secret(secret: str) -> str:
    # OpenSSL's fd passphrase reader is line-based. Reject values it would
    # silently truncate instead of authenticating under a different key.
    if any(char in secret for char in "\r\n\x00") or len(secret.encode()) > 256:
        raise RuntimeError("backup key must be a single line of at most 256 UTF-8 bytes")
    return secret


def _openssl(secret: str, source, destination, *, decrypt: bool) -> int:
    """Keep the one resolved secret out of argv and the child environment."""
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, secret.encode("utf-8") + b"\n")
        os.close(write_fd)
        write_fd = -1
        env = os.environ.copy()
        env.pop("BACKUP_KEY", None)
        result = subprocess.run(
            ["openssl", "enc", "-d" if decrypt else "-e", "-aes-256-cbc",
             "-salt", "-pbkdf2", "-iter", "600000", "-pass", f"fd:{read_fd}"],
            stdin=source, stdout=destination, env=env, pass_fds=(read_fd,), check=False,
        )
        return result.returncode
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def _crypt_file(action: str, ciphertext: Path, sidecar: Path, *, seal: bool = False) -> int:
    secret = _resolve_backup_key()
    if action == "encrypt":
        fd = os.open(ciphertext, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as destination:
            result = _openssl(secret, sys.stdin.buffer, destination, decrypt=False)
        if result == 0 and seal:
            _write_tag(ciphertext, sidecar, secret)
        return result
    # Authenticate a private ciphertext snapshot, then decrypt that snapshot.
    # Holding the original fd defeats path replacement, but does not stop an
    # in-place writer changing its bytes after verification. Use disk-backed
    # scratch beside the backup by default: dumps can exceed /tmp's tmpfs cap.
    # A read-only source may use an explicit writable BACKUP_SNAPSHOT_DIR.
    scratch = os.environ.get("BACKUP_SNAPSHOT_DIR") or str(ciphertext.parent)
    with ciphertext.open("rb") as source, tempfile.TemporaryFile(dir=scratch) as snapshot:
        mac_key = hmac.new(secret.encode("utf-8"), DOMAIN, hashlib.sha256).digest()
        digest = hmac.new(mac_key, digestmod=hashlib.sha256)
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            snapshot.write(chunk)
        actual = base64.b64encode(digest.digest())
        if not hmac.compare_digest(actual, sidecar.read_bytes().strip()):
            raise RuntimeError("HMAC mismatch; refusing to decrypt")
        snapshot.flush()
        snapshot.seek(0)
        return _openssl(secret, snapshot, sys.stdout.buffer, decrypt=True)


def _tag(ciphertext: Path, secret: str | None = None) -> bytes:
    if secret is None:
        secret = _resolve_backup_key()
    mac_key = hmac.new(secret.encode("utf-8"), DOMAIN, hashlib.sha256).digest()
    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    with ciphertext.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return base64.b64encode(digest.digest())


def _write_tag(ciphertext: Path, sidecar: Path, secret: str) -> None:
    actual = _tag(ciphertext, secret)
    fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(actual + b"\n")


def _prune(directory: Path, days: str) -> int:
    """Delete backup artifacts at the precise retention cutoff.

    `find -mtime +N` rounds to day buckets and therefore retains a nominal
    N-day backup for almost N+2 days. This helper owns the exact wall-clock
    policy used by the compose worker: all final ciphertexts and sidecars at
    or before `now - N*24h` are removed. Orphan sidecars are safe and are
    deliberately eligible too.
    """
    try:
        retention_days = int(days)
    except ValueError as exc:
        raise RuntimeError("retention days must be a positive whole number") from exc
    if retention_days < 1 or str(retention_days) != days:
        raise RuntimeError("retention days must be a positive whole number")
    cutoff = time.time() - retention_days * 86_400
    removed = 0
    for child in directory.iterdir():
        if not (
            child.name.startswith("mindpattern-")
            and (child.name.endswith(".dump.enc") or child.name.endswith(".dump.enc.hmac"))
        ):
            continue
        if child.stat().st_mtime <= cutoff:
            child.unlink()
            removed += 1
    return removed


def main(argv: list[str]) -> int:
    if argv[1:2] in (["encrypt"], ["decrypt"]):
        if len(argv) not in (3, 4):
            print("usage: mindpattern-backup-mac {encrypt CIPHERTEXT [SIDECAR]|decrypt CIPHERTEXT [SIDECAR]}", file=sys.stderr)
            return 64
        ciphertext = Path(argv[2])
        sidecar = Path(argv[3]) if len(argv) == 4 else Path(f"{ciphertext}.hmac")
        try:
            return _crypt_file(argv[1], ciphertext, sidecar, seal=argv[1] == "encrypt" and len(argv) == 4)
        except (OSError, RuntimeError) as exc:
            print(f"backup {argv[1]} failed: {exc}", file=sys.stderr)
            return 1
    if argv[1:2] == ["prune"]:
        if len(argv) != 4:
            print("usage: mindpattern-backup-mac prune DIRECTORY DAYS", file=sys.stderr)
            return 64
        try:
            removed = _prune(Path(argv[2]), argv[3])
        except (OSError, RuntimeError) as exc:
            print(f"backup retention cleanup failed: {exc}", file=sys.stderr)
            return 1
        print(f"backup retention cleanup removed {removed} artifact(s)")
        return 0
    if len(argv) not in (3, 4) or argv[1] not in {"write", "verify"}:
        print(
            "usage: mindpattern-backup-mac {write CIPHERTEXT SIDECAR|verify CIPHERTEXT [SIDECAR]|prune DIRECTORY DAYS}",
            file=sys.stderr,
        )
        return 64
    ciphertext = Path(argv[2])
    sidecar = Path(argv[3]) if len(argv) == 4 else Path(f"{ciphertext}.hmac")
    try:
        actual = _tag(ciphertext)
        if argv[1] == "write":
            # Backup metadata is sensitive too.  Do not inherit a permissive
            # process umask for a newly-created tag file (the compose worker
            # writes a temporary sidecar and renames it atomically).
            fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(actual + b"\n")
            return 0
        expected = sidecar.read_bytes().strip()
    except (OSError, RuntimeError) as exc:
        print(f"backup integrity check failed: {exc}", file=sys.stderr)
        return 1
    if not hmac.compare_digest(actual, expected):
        print("backup integrity check failed: HMAC mismatch", file=sys.stderr)
        return 1
    print("backup integrity verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
