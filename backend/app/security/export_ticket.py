"""Bounded, single-use capabilities for native browser account downloads.

Only token digests and authorization metadata are retained, never bearers or
account content. Like processing sessions, tickets are process-local under the
enforced single-process deployment contract and disappear on restart.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass

EXPORT_TICKET_TTL = 60
EXPORT_TICKET_CAPACITY = 1024
EXPORT_TICKETS_PER_USER = 2


@dataclass(frozen=True)
class ExportGrant:
    user_id: str
    token_epoch: int
    token_jti: str | None
    token_expires: float
    secret_fingerprint: str
    expires_at: float


def secret_fingerprint(secret: str, version: int) -> str:
    return hashlib.sha256(f"{version}:{secret}".encode()).hexdigest()


class ExportTicketStore:
    """Synchronous operations are atomic on the application's event loop."""

    def __init__(self) -> None:
        self._tickets: dict[str, ExportGrant] = {}

    @staticmethod
    def _digest(ticket: str) -> str:
        return hashlib.sha256(ticket.encode("ascii")).hexdigest()

    def issue(
        self,
        *,
        user_id: str,
        token_epoch: int,
        token_jti: str | None,
        token_expires: float,
        secret_fingerprint: str,
    ) -> str:
        now = time.monotonic()
        self._tickets = {
            key: grant
            for key, grant in self._tickets.items()
            if grant.expires_at > now and grant.token_expires > time.time()
        }
        mine = [key for key, grant in self._tickets.items() if grant.user_id == user_id]
        while len(mine) >= EXPORT_TICKETS_PER_USER:
            self._tickets.pop(mine.pop(0))
        if len(self._tickets) >= EXPORT_TICKET_CAPACITY:
            raise RuntimeError("export ticket capacity reached")
        ticket = secrets.token_urlsafe(32)
        self._tickets[self._digest(ticket)] = ExportGrant(
            user_id,
            token_epoch,
            token_jti,
            token_expires,
            secret_fingerprint,
            now + EXPORT_TICKET_TTL,
        )
        return ticket

    def consume(self, ticket: str) -> ExportGrant | None:
        grant = self._tickets.pop(self._digest(ticket), None)
        if (
            grant is None
            or grant.expires_at <= time.monotonic()
            or grant.token_expires <= time.time()
        ):
            return None
        return grant

    def clear(self) -> None:
        self._tickets.clear()
