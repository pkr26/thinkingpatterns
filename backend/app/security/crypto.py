"""AES-256-GCM envelope encryption.

Wire format:  nonce(12) || ciphertext || tag(16)

The AAD (additional authenticated data) binds every blob to its owner and
purpose — user_id, entry id and context — so a malicious or buggy server
cannot move a blob between entries or users without the client detecting
tampering at decryption time.

This module is the server-side *reference implementation* of the envelope
format; the mobile client implements the identical format (see
mobile/src/crypto/ and shared/vectors.json for cross-platform test vectors).
"""

from __future__ import annotations

import json
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MIN_BLOB_SIZE = NONCE_SIZE + TAG_SIZE


class CryptoError(Exception):
    """Base class for envelope crypto failures."""


class TamperError(CryptoError):
    """Raised when a blob fails GCM authentication (wrong key, AAD, or bits)."""


def generate_key() -> bytes:
    """Generate a fresh 256-bit key (testing / enclave bootstrap only)."""
    return os.urandom(KEY_SIZE)


def encrypt(key: bytes, plaintext: bytes, aad: bytes | None = None) -> bytes:
    """Encrypt and authenticate *plaintext* under *key*, returning the envelope.

    The nonce is ALWAYS fresh and random — deterministic output is a
    nonce-reuse hazard, so the fixed-nonce path is deliberately NOT
    reachable through this function. Test-vector generation uses
    :func:`encrypt_with_nonce` below (unmistakably named, never called in
    production paths, and asserted absent from them by tests).
    """
    return encrypt_with_nonce(key, plaintext, aad, os.urandom(NONCE_SIZE))


def encrypt_with_nonce(
    key: bytes,
    plaintext: bytes,
    aad: bytes | None,
    nonce: bytes,
) -> bytes:
    """Fixed-nonce encryption — TEST/VECTOR GENERATION ONLY (never import
    from a request path). shared/vectors.json pins this output."""
    if len(key) != KEY_SIZE:
        raise CryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(nonce) != NONCE_SIZE:
        raise CryptoError(f"nonce must be {NONCE_SIZE} bytes, got {len(nonce)}")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + ciphertext


def decrypt(key: bytes | bytearray, blob: bytes, aad: bytes | None = None) -> bytes:
    """Verify and decrypt an envelope; raises TamperError on any mismatch.

    ``key`` is any bytes-like: AESGCM accepts bytearray, and the enclave
    deliberately passes ONE reusable mutable buffer (zeroized after the
    batch) instead of an immutable per-call copy that would linger until GC.
    """
    if len(key) != KEY_SIZE:
        raise CryptoError(f"key must be {KEY_SIZE} bytes, got {len(key)}")
    if len(blob) < MIN_BLOB_SIZE:
        raise TamperError(f"blob too short: {len(blob)} bytes")
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise TamperError("authentication failed") from exc


def build_aad(*parts: str) -> bytes:
    """Canonical unambiguous AAD: JSON array of the binding parts.

    ``ensure_ascii=True`` (explicit: it is a cross-platform contract, not a
    style choice) means every non-ASCII code unit is escaped as \\uXXXX, so
    the AAD bytes are pure ASCII regardless of the parts' content. The mobile
    client implements the identical escaping (see mobile/src/crypto/aad.ts);
    shared/vectors.json pins the behavior with non-ASCII vectors.
    """
    return json.dumps(list(parts), separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# --- entry AAD versions (2026-09-20 audit fix M-2) -----------------------------
#
# v1 bound only ("entry", user_id, client_entry_id): a malicious server could
# replay a previously stored, cryptographically valid ciphertext for the same
# id (e.g. the pre-edit version) because GCM authenticates WHO/WHAT a blob
# belongs to, never WHICH VERSION. v2 adds the entry's monotonic
# content_version as a fourth AAD part, so a version-echo lie and the
# ciphertext can no longer travel together: the client (and the server's own
# recompute) also keeps a per-id high-water mark.
#
# Legacy v1 blobs remain decryptable (both platforms try v2 then v1); every
# new write and every server-side rekey encrypts under v2.

ENTRY_CONTEXT = "entry"


def entry_aad_v1(user_id: str, client_entry_id: str) -> bytes:
    """Legacy three-part entry AAD (pre-2026-09-20 blobs)."""
    return build_aad(ENTRY_CONTEXT, user_id, client_entry_id)


def entry_aad_v2(user_id: str, client_entry_id: str, content_version: int) -> bytes:
    """Four-part entry AAD binding the row's monotonic content version."""
    return build_aad(ENTRY_CONTEXT, user_id, client_entry_id, str(content_version))


def entry_aad_candidates(
    user_id: str, client_entry_id: str, content_version: int
) -> tuple[bytes, bytes]:
    """AADs to try when decrypting an entry of unknown generation (v2 first)."""
    return (
        entry_aad_v2(user_id, client_entry_id, content_version),
        entry_aad_v1(user_id, client_entry_id),
    )


class SecureBuffer:
    """Best-effort zeroizable container for plaintext inside the enclave.

    Python cannot guarantee memory erasure (immutable copies may exist), but
    every buffer the enclave owns is passed through zeroize() on exit so the
    observable plaintext lifetime is bounded to the processing window.
    """

    __slots__ = ("_buf",)

    def __init__(self, data: bytes | bytearray | memoryview) -> None:
        self._buf = bytearray(data)

    @property
    def data(self) -> bytearray:
        return self._buf

    def zeroize(self) -> None:
        for i in range(len(self._buf)):
            self._buf[i] = 0

    def is_zeroized(self) -> bool:
        return all(b == 0 for b in self._buf)

    def __len__(self) -> int:
        return len(self._buf)
