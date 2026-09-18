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
import sys
import time
from pathlib import Path

DOMAIN = b"mindpattern-backup-hmac-v1"


def _tag(ciphertext: Path) -> bytes:
    secret = os.environ.get("BACKUP_KEY")
    if not secret:
        raise RuntimeError("BACKUP_KEY is required")
    mac_key = hmac.new(secret.encode("utf-8"), DOMAIN, hashlib.sha256).digest()
    digest = hmac.new(mac_key, digestmod=hashlib.sha256)
    with ciphertext.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return base64.b64encode(digest.digest())


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
