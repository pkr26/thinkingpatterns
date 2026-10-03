#!/usr/bin/env python3
"""Offline, operator-attested migration of genuine pre-MAC audit rows.

A new MAC authenticates the operator's reviewed snapshot from this point
forward. It cannot prove that a legacy row was truthful before review.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import sys
from typing import TYPE_CHECKING

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sqlalchemy import select, text

if TYPE_CHECKING:
    from app.config import Settings
    from app.models import AccessLog

MAX_ROWS = 100_000
MAX_SNAPSHOT_BYTES = 128 * 1024 * 1024


def canonical_snapshot(value: dict) -> bytes:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode() + b"\n"
    )
    if len(encoded) > MAX_SNAPSHOT_BYTES:
        raise ValueError(
            "snapshot exceeds the bounded migration size; use a reviewed partitioned migration"
        )
    return encoded


def verify_attestation(snapshot: bytes, expected_digest: str, attestation: str) -> None:
    if not hmac.compare_digest(hashlib.sha256(snapshot).hexdigest(), expected_digest):
        raise ValueError("reviewed snapshot digest does not match")
    if not 40 <= len(attestation.strip()) <= 8192:
        raise ValueError(
            "a specific operator attestation of independent legacy provenance is required"
        )


def write_private(path: Path, contents: bytes) -> None:
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
        handle.write(contents)
        handle.flush()
        os.fsync(handle.fileno())


async def snapshot_rows(session, settings: Settings) -> tuple[bytes, list[AccessLog]]:
    from app.api._audit import (
        canonical_occurred_at,
        compute_entry_mac,
        read_journal_heads,
        verify_access_log_chain,
    )
    from app.models import AccessLog, utcnow

    rows = list(
        (
            await session.scalars(
                select(AccessLog)
                .order_by(AccessLog.user_id, AccessLog.chain_seq)
                .limit(MAX_ROWS + 1)
            )
        ).all()
    )
    if len(rows) > MAX_ROWS:
        raise ValueError("audit row limit exceeded; use a reviewed partitioned migration")
    key = bytes.fromhex(settings.audit_mac_secret_hex)
    for row in rows:
        if row.entry_mac is not None and not hmac.compare_digest(
            row.entry_mac, compute_entry_mac(key, row.user_id, row.chain_seq, row.entry_hash or "")
        ):
            raise ValueError("an existing MAC is invalid; investigate instead of resealing")
    heads = read_journal_heads(settings.audit_journal_path) if settings.audit_journal_path else {}
    from datetime import timedelta

    cutoff = utcnow() - timedelta(days=settings.access_log_retention_days)
    for owner in sorted({row.user_id for row in rows} | set(heads)):
        proof = await verify_access_log_chain(
            session,
            owner,
            journal_path=settings.audit_journal_path or None,
            retention_cutoff=cutoff,
            journal_heads=heads,
        )
        if not proof.ok:
            raise ValueError(
                "audit hash/link/journal verification failed; investigate instead of resealing"
            )
    value = {
        "format": "mindpattern-legacy-audit-review-v1",
        "journal_heads": heads,
        "rows": [
            {
                "id": row.id,
                "actor_id": row.actor_id,
                "actor_role": row.actor_role,
                "user_id": row.user_id,
                "action": row.action,
                "at": canonical_occurred_at(row.at),
                "chain_seq": row.chain_seq,
                "prev_hash": row.prev_hash,
                "entry_hash": row.entry_hash,
                "entry_mac": row.entry_mac,
            }
            for row in rows
        ],
    }
    return canonical_snapshot(value), rows


async def run(args) -> None:
    from app.config import Settings
    from app.db import build_engine, build_sessionmaker
    from app.main import _acquire_cross_host_guard, _release_cross_host_guard
    from app.models import utcnow
    from app.api._audit import compute_entry_mac
    from app.singleprocess import single_process_guard

    settings = Settings.from_env()
    engine = build_engine(settings.database_url)
    try:
        if args.command == "snapshot":
            async with build_sessionmaker(engine)() as session:
                snapshot, _ = await snapshot_rows(session, settings)
            write_private(Path(args.output), snapshot)
            print(hashlib.sha256(snapshot).hexdigest())
            return
        if not args.maintenance_confirmed:
            raise ValueError(
                "stop every API/worker/maintenance writer and explicitly confirm maintenance"
            )
        path = Path(args.snapshot)
        if path.stat().st_size > MAX_SNAPSHOT_BYTES:
            raise ValueError("snapshot exceeds size bound")
        reviewed = path.read_bytes()
        attestation_path = Path(args.attestation)
        if attestation_path.stat().st_size > 32768:
            raise ValueError("attestation exceeds size bound")
        attestation = attestation_path.read_text()
        verify_attestation(reviewed, args.sha256, attestation)
        with single_process_guard(settings.token_secret, settings.database_url):
            guard = await _acquire_cross_host_guard(engine)
            try:
                async with build_sessionmaker(engine)() as session:
                    if engine.dialect.name == "postgresql":
                        await session.execute(text("LOCK TABLE access_log IN EXCLUSIVE MODE"))
                    else:
                        await session.execute(text("BEGIN IMMEDIATE"))
                    current, rows = await snapshot_rows(session, settings)
                    if not hmac.compare_digest(reviewed, current):
                        raise ValueError(
                            "database or journal changed after review; create and independently review a new snapshot"
                        )
                    key = bytes.fromhex(settings.audit_mac_secret_hex)
                    changed = 0
                    for row in rows:
                        if row.entry_mac is None:
                            row.entry_mac = compute_entry_mac(
                                key, row.user_id, row.chain_seq, row.entry_hash
                            )
                            changed += 1
                    # Prepare receipt before commit so an unwritable destination
                    # cannot silently omit the operator's provenance record.
                    receipt = canonical_snapshot(
                        {
                            "reviewed_sha256": args.sha256,
                            "attestation": attestation,
                            "sealed_rows": changed,
                            "at": utcnow().isoformat(),
                            "claim": "operator-reviewed legacy snapshot; no retrospective authenticity proof",
                        }
                    )
                    write_private(Path(args.receipt), receipt)
                    await session.commit()
                    print(f"sealed {changed} reviewed legacy rows")
            finally:
                await _release_cross_host_guard(guard)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("snapshot")
    snapshot.add_argument("--output", required=True)
    seal = commands.add_parser("seal")
    for name in ("snapshot", "sha256", "attestation", "receipt"):
        seal.add_argument("--" + name, required=True)
    seal.add_argument("--maintenance-confirmed", action="store_true")
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except (ValueError, OSError, RuntimeError) as exc:
        parser.exit(1, str(exc) + "\n")


if __name__ == "__main__":
    main()
