"""Authenticated, sticky AAD history independent of rebuildable brain state.

Trust boundary: the application and its versioned MAC keyring are trusted;
entry ciphertext/metadata may be tampered with. The seal prevents modifying
or removing a guard, not replaying an earlier valid signed entry record
(including its ciphertext). Such coherent rollback needs an independent
freshness anchor.
Online request paths never adopt an unsealed row. The explicit one-time
bootstrap trusts the operator's pre-upgrade database snapshot.
"""

from __future__ import annotations

import hashlib
import hmac
import json

from ..models import Entry, new_id
from .crypto import TamperError, entry_aad_candidates, entry_aad_v2

DOMAIN = b"mindpattern/entry-aad-guard/v1"


def _mac(row: Entry, key: bytes) -> str:
    purpose_key = hmac.new(key, DOMAIN, hashlib.sha256).digest()
    value = [
        "entry-aad-guard/v1",
        row.id,
        row.user_id,
        row.client_entry_id,
        row.content_version,
        row.aad_guard_version,
        row.aad_guard_key_version,
        hashlib.sha256(row.blob).hexdigest(),
    ]
    return hmac.new(
        purpose_key,
        json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii"),
        hashlib.sha256,
    ).hexdigest()


def seal_entry_guard(row: Entry, settings, *, v2_bound: bool) -> None:
    """Sign an authorized write or positively authenticated observation."""
    if row.id is None:
        row.id = new_id()
    if row.content_version is None:
        row.content_version = 1
    row.aad_guard_version = 2 if v2_bound else 0
    row.aad_guard_key_version = settings.audit_mac_key_version
    row.aad_guard_mac = _mac(row, settings.audit_mac_keyring[row.aad_guard_key_version])


def validate_entry_guard(row: Entry, settings) -> bool:
    """Return the authenticated sticky bit; absence and tampering fail closed."""
    if (
        type(row.content_version) is not int
        or not 1 <= row.content_version <= 2**63 - 1
        or type(row.aad_guard_version) is not int
        or row.aad_guard_version not in (0, 2)
        or type(row.aad_guard_key_version) is not int
        or not isinstance(row.blob, bytes)
        or not all(
            isinstance(value, str) and value for value in (row.id, row.user_id, row.client_entry_id)
        )
    ):
        raise TamperError("entry AAD guard is absent or invalid")
    key = settings.audit_mac_keyring.get(row.aad_guard_key_version)
    if (
        key is None
        or not isinstance(row.aad_guard_mac, str)
        or not row.aad_guard_mac.isascii()
        or not hmac.compare_digest(row.aad_guard_mac, _mac(row, key))
    ):
        raise TamperError("entry AAD guard is absent or invalid")
    return row.aad_guard_version == 2


def guarded_entry_aads(row: Entry, settings):
    if validate_entry_guard(row, settings):
        return (entry_aad_v2(row.user_id, row.client_entry_id, row.content_version),)
    return entry_aad_candidates(row.user_id, row.client_entry_id, row.content_version)


def guard_values(row: Entry) -> dict:
    return {
        "aad_guard_version": row.aad_guard_version,
        "aad_guard_key_version": row.aad_guard_key_version,
        "aad_guard_mac": row.aad_guard_mac,
    }


async def bootstrap_trusted_entries(sessionmaker, settings, *, batch_size: int = 8) -> int:
    """One-time, offline adoption of an operator-verified pre-upgrade snapshot.

    Caller holds the deployment ownership locks. A durable migration marker
    prevents accidental reinitialization; interrupted bootstrap may resume,
    but existing seals must still authenticate. Ciphertext is never changed.
    """
    from sqlalchemy import select

    from ..models import EntryGuardBootstrap, utcnow

    async with sessionmaker() as session:
        marker = await session.get(EntryGuardBootstrap, 1)
        if marker is None or marker.completed_at is not None:
            raise RuntimeError("trusted entry bootstrap is unavailable or already complete")
    cursor = None
    total = 0
    while True:
        async with sessionmaker() as session:
            query = select(Entry).order_by(Entry.id).limit(batch_size)
            if cursor is not None:
                query = query.where(Entry.id > cursor)
            rows = list((await session.scalars(query)).all())
            if not rows:
                break
            for row in rows:
                if (
                    row.aad_guard_version == 0
                    and row.aad_guard_key_version is None
                    and row.aad_guard_mac is None
                ):
                    seal_entry_guard(row, settings, v2_bound=False)
                else:
                    validate_entry_guard(row, settings)
            cursor = rows[-1].id
            total += len(rows)
            await session.commit()
    async with sessionmaker() as session:
        marker = await session.get(EntryGuardBootstrap, 1)
        if marker is None or marker.completed_at is not None:
            raise RuntimeError("trusted entry bootstrap marker changed")
        marker.completed_at = utcnow()
        await session.commit()
    return total
