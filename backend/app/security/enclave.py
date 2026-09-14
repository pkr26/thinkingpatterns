"""Secure processing enclave (v1: in-process seam; TEE is a deploy concern).

The client delivers its data key into a short-lived, memory-only session
(over TLS) so the "mini-brain" can decrypt entries. Keys are held as
``bytearray`` so every exit path (use, destroy, expiry, account deletion)
can overwrite the bytes, not just drop the reference. What zeroization
covers — and honestly does not — is documented on SecureProcessingContext:
Python strings produced by the analyzer are immutable and linger until GC;
the buffers the enclave owns are the ones that get scrubbed — including the
single working copy of the data key a run decrypts with (minting a fresh
``bytes(key)`` per ITEM would leave N immutable key copies unzeroized
until GC; one bytearray per run is scrubbed on every exit path instead).

Processing sessions are single-use: the key is destroyed the moment a
recompute consumes it (success or failure), so the keystore never holds a
usable key longer than one request.
"""

from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable, Sequence

from .crypto import KEY_SIZE, SecureBuffer, TamperError, decrypt

EncryptedItem = tuple[bytes | None, bytes]  # (aad, blob)


def zeroize(key: bytearray) -> None:
    for i in range(len(key)):
        key[i] = 0


class KeyNotFound(Exception):
    """Raised when a processing-session token is unknown or expired."""


class InMemoryKeyStore:
    """Memory-only, TTL-bounded store for per-session data keys.

    Keys deliberately never touch the database or any other persistence —
    if the process dies, they are gone and the client simply opens a new
    processing session. Each session is bound to the user who opened it;
    a token issued for one account cannot drive a recompute for another.
    """

    def __init__(self) -> None:
        self._keys: dict[str, tuple[bytearray, float, str | None]] = {}
        self._lock = threading.Lock()

    def create(
        self, key: bytes | bytearray, ttl_seconds: int, now: float | None = None, owner: str | None = None
    ) -> str:
        if len(key) != KEY_SIZE:
            raise ValueError(f"key must be {KEY_SIZE} bytes")
        if ttl_seconds <= 0:
            raise ValueError("ttl must be positive")
        token = secrets.token_urlsafe(32)
        current = now if now is not None else time.time()
        with self._lock:
            # Sessions are short-lived; purge stale ones so repeated creates
            # cannot grow the store unboundedly.
            self._purge_expired_locked(current)
            self._keys[token] = (bytearray(key), current + ttl_seconds, owner)
        return token

    def get(self, token: str, now: float | None = None, owner: str | None = None) -> bytes:
        """Fetch (and do NOT destroy) the key for *token*.

        Returns an owned copy: the caller may destroy the session (which
        zeroizes the store's internal bytes) and still use the returned key
        for the current operation. The caller is responsible for zeroizing
        its copy when done (SecureProcessingContext does).
        """
        current = now if now is not None else time.time()
        with self._lock:
            entry = self._keys.get(token)
            if entry is not None:
                key, expiry, bound_owner = entry
                if current >= expiry:
                    zeroize(key)
                    del self._keys[token]
                    raise KeyNotFound("processing session expired")
                if owner is not None and bound_owner is not None and owner != bound_owner:
                    raise KeyNotFound("processing session belongs to another user")
                return bytes(key)
            self._purge_expired_locked(current)
            raise KeyNotFound("unknown processing session")

    def pop(self, token: str, now: float | None = None, owner: str | None = None) -> bytearray:
        """Atomically fetch AND consume the key for *token* (single-use).

        get()-then-destroy() enforced single use only by scheduling accident
        — nothing marked the token consumed between the two calls, so any
        future `await` inserted there (or a keystore shared across workers)
        would let N concurrent requests reuse one uploaded key. pop() makes
        the mechanism real: under the store lock, exactly one caller wins.

        On success the store's OWN bytearray is handed over (ownership
        transfers; no immutable bytes copy is minted to linger until GC).
        The store keeps no reference, and the caller is responsible for
        zeroizing it on every exit path — the recompute endpoint does so in
        a finally around the whole processing run.
        """
        current = now if now is not None else time.time()
        with self._lock:
            entry = self._keys.pop(token, None)
            if entry is None:
                self._purge_expired_locked(current)
                raise KeyNotFound("unknown processing session")
            key, expiry, bound_owner = entry
            if current >= expiry:
                zeroize(key)
                raise KeyNotFound("processing session expired")
            if owner is not None and bound_owner is not None and owner != bound_owner:
                zeroize(key)
                raise KeyNotFound("processing session belongs to another user")
            return key

    def destroy(self, token: str) -> bool:
        with self._lock:
            entry = self._keys.pop(token, None)
            if entry is None:
                return False
            zeroize(entry[0])
            return True

    def destroy_all_for_owner(self, owner: str) -> int:
        """Wipe every session belonging to *owner* (account deletion path)."""
        with self._lock:
            doomed = [t for t, (_, _, o) in self._keys.items() if o == owner]
            for t in doomed:
                zeroize(self._keys[t][0])
                del self._keys[t]
            return len(doomed)

    def purge_expired(self, now: float | None = None) -> int:
        with self._lock:
            return self._purge_expired_locked(now if now is not None else time.time())

    def _purge_expired_locked(self, now: float) -> int:
        expired = [t for t, (_, exp, _) in self._keys.items() if now >= exp]
        for t in expired:
            zeroize(self._keys[t][0])
            del self._keys[t]
        return len(expired)

    def __len__(self) -> int:
        with self._lock:
            return len(self._keys)


_open_plaintext_windows = 0
_windows_lock = threading.Lock()


def plaintext_windows() -> int:
    """Observability hook: number of SecureProcessingContexts currently open."""
    with _windows_lock:
        return _open_plaintext_windows


class SecureProcessingContext:
    """decrypt -> analyze -> re-encrypt -> zeroize.

    Zeroization scope (deliberate, documented): the key, the ONE working
    key copy this run mints for the whole item batch, and the plaintext
    bytearrays this context owns are overwritten on exit. The analyzer it
    calls unavoidably creates Python str copies of plaintext (immutable,
    GC-reclaimed) — the "milliseconds" claim in old marketing copy only ever
    applied to the buffers owned here. A process memory image taken during
    or shortly after a run can still contain analyzer strings; TEE-style
    guarantees are deployment work (see PLAN.md).
    """

    def __init__(self, key: bytes | bytearray) -> None:
        if len(key) != KEY_SIZE:
            raise ValueError(f"key must be {KEY_SIZE} bytes")
        self._key = bytearray(key)

    def run(self, encrypted: Sequence[EncryptedItem], analyze: Callable[[list[bytearray]], object]):
        global _open_plaintext_windows
        buffers: list[SecureBuffer] = []
        with _windows_lock:
            _open_plaintext_windows += 1
        # One working copy of the key for the WHOLE batch: decrypt() took
        # bytes(self._key) per item, so an N-entry recompute left N
        # immutable key copies to the GC. bytearray is bytes-like for
        # AESGCM, so the same buffer can drive every decryption and then be
        # scrubbed with the rest.
        key_material = bytearray(self._key)
        try:
            for aad, blob in encrypted:
                plaintext = decrypt(key_material, blob, aad)
                buffers.append(SecureBuffer(plaintext))
            return analyze([buf.data for buf in buffers])
        finally:
            for buf in buffers:
                buf.zeroize()
            zeroize(key_material)
            zeroize(self._key)
            with _windows_lock:
                _open_plaintext_windows -= 1


def run_isolated(
    key: bytes | bytearray,
    encrypted: Sequence[EncryptedItem],
    analyze: Callable[[list[bytearray]], object],
):
    """One-shot helper: a context that lives for exactly one analyze call."""
    return SecureProcessingContext(key).run(encrypted, analyze)


__all__ = [
    "EncryptedItem",
    "InMemoryKeyStore",
    "KeyNotFound",
    "SecureProcessingContext",
    "TamperError",
    "plaintext_windows",
    "run_isolated",
    "zeroize",
]
