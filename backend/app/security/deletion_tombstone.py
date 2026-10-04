"""Integrity-protected, bounded account-deletion authentication evidence."""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

from ..config import MAX_TOKEN_TTL_SECONDS
from ..models import AccountDeletionTombstone, User


def _canonical_timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return str(int(value.astimezone(timezone.utc).timestamp()))


def _canonical_payload(row: AccountDeletionTombstone) -> bytes:
    return "\n".join(
        (
            str(row.record_version),
            row.user_id,
            row.role,
            str(row.token_epoch),
            str(row.auth_secret_version),
            _canonical_timestamp(row.deleted_at),
            _canonical_timestamp(row.expires_at),
        )
    ).encode("utf-8")


def compute_deletion_tombstone_mac(secret: str, row: AccountDeletionTombstone) -> str:
    return hmac.new(secret.encode("utf-8"), _canonical_payload(row), hashlib.sha256).hexdigest()


def new_deletion_tombstone(
    user: User,
    *,
    secret: str,
    auth_secret_version: int,
    now: datetime,
) -> AccountDeletionTombstone:
    # Whole-second timestamps make the authenticated serialization identical
    # across PostgreSQL and SQLite and across process restarts.
    deleted_at = datetime.fromtimestamp(int(now.timestamp()), timezone.utc)
    row = AccountDeletionTombstone(
        user_id=user.id,
        role=user.role,
        token_epoch=user.token_epoch,
        auth_secret_version=auth_secret_version,
        deleted_at=deleted_at,
        expires_at=deleted_at + timedelta(seconds=MAX_TOKEN_TTL_SECONDS),
        record_version=1,
        record_mac="",
    )
    row.record_mac = compute_deletion_tombstone_mac(secret, row)
    return row


def verifies_deletion_tombstone(
    row: AccountDeletionTombstone,
    *,
    secret: str,
    auth_secret_version: int,
    now: datetime,
) -> bool:
    if row.record_version != 1:
        return False
    if row.auth_secret_version != auth_secret_version:
        return False
    if row.expires_at <= now:
        return False
    expected = compute_deletion_tombstone_mac(secret, row)
    return hmac.compare_digest(row.record_mac, expected)
