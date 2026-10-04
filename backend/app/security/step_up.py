"""Short-lived, one-use, action-bound re-authentication proofs."""

from __future__ import annotations

import asyncio
import hashlib
import secrets
import time
from dataclasses import dataclass

STEP_UP_TTL_SECONDS = 120
STEP_UP_MAX_PROOFS = 10_000
STEP_UP_MAX_PER_USER = 8


@dataclass(frozen=True)
class _Proof:
    user_id: str
    action: str
    token_jti: str | None
    token_epoch: int
    expires_at: float
    issued_at: float


class StepUpProofStore:
    """Process-local proof store under the enforced single-host contract.

    Only SHA-256 digests are retained.  Consumption removes a proof before
    judging its binding, giving replay, wrong-action and expiry the same
    one-shot failure semantics.
    """

    def __init__(self) -> None:
        self._proofs: dict[str, _Proof] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("ascii", "strict")).hexdigest()

    async def issue(
        self, *, user_id: str, action: str, token_jti: str | None, token_epoch: int
    ) -> tuple[str, int]:
        now = time.monotonic()
        async with self._lock:
            self._proofs = {
                digest: proof for digest, proof in self._proofs.items() if proof.expires_at > now
            }
            mine = sorted(
                (
                    (digest, proof)
                    for digest, proof in self._proofs.items()
                    if proof.user_id == user_id
                ),
                key=lambda item: item[1].issued_at,
            )
            while len(mine) >= STEP_UP_MAX_PER_USER:
                digest, _ = mine.pop(0)
                self._proofs.pop(digest, None)
            if len(self._proofs) >= STEP_UP_MAX_PROOFS:
                raise RuntimeError("step-up proof capacity exhausted")
            token = secrets.token_urlsafe(32)
            self._proofs[self._digest(token)] = _Proof(
                user_id=user_id,
                action=action,
                token_jti=token_jti,
                token_epoch=token_epoch,
                expires_at=now + STEP_UP_TTL_SECONDS,
                issued_at=now,
            )
            return token, STEP_UP_TTL_SECONDS

    async def consume(
        self,
        token: str,
        *,
        user_id: str,
        action: str,
        token_jti: str | None,
        token_epoch: int,
    ) -> bool:
        try:
            digest = self._digest(token)
        except (UnicodeEncodeError, AttributeError):
            return False
        async with self._lock:
            proof = self._proofs.pop(digest, None)
        if proof is None or proof.expires_at <= time.monotonic():
            return False
        return (
            proof.user_id == user_id
            and proof.action == action
            and proof.token_jti == token_jti
            and proof.token_epoch == token_epoch
        )
