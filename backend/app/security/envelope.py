"""Random data-key envelope (v2 key scheme) — reference implementation.

The v1 key schedule derives the DATA key directly from the password, so a
password change re-keys the whole corpus (O(corpus) server-side work the
client must drive through POST /processing/rekey) and any weakening of the
password weakens stored ciphertext retroactively. The v2 scheme, delivered
2026-09-26, inserts a random envelope between the two:

    data_key  = random 32 bytes                       (client-generated)
    kek       = HKDF-SHA256(ikm    = password-derived key per kdf_params,
                           salt   = the account's client KDF salt,
                           info   = "mindpattern/envelope/v2", 32 bytes)
    nonce     = random 96 bits
    aad       = canonical JSON {"context": "envelope",
                                "kdf_params": <canonical kdf_params blob>,
                                "username": <account name>}
    wrapped   = AES-256-GCM(kek, data_key, nonce, aad)
               wire format nonce(12) || ct(32) || tag(16) — 60 bytes

The server stores ``wrapped`` opaquely: the KEK input never leaves the
client, so a database dump yields the data key only against the password
(no better than v1) while a PASSWORD CHANGE becomes O(1) — unwrap locally
with the old password, re-wrap under a fresh salt + kdf_params, upload.
The same random data key keeps encrypting the corpus, keeps riding
processing sessions, and keeps being wrapped to therapists' public keys
unchanged; only its password-locker rotates.

DELIBERATE DEVIATION from the original remediation sketch (which bound the
server ``user_id`` into the AAD): the server generates the user id at
INSERT time, so a client wrapping at REGISTRATION cannot know it — binding
it would force a re-wrap round trip on every fresh account. The bound
value is the account's USERNAME instead: unique, immutable after
registration (the 409 availability check depends on it), and known to the
client before the account exists. The binding goal is met unchanged — a
wrap cannot be replayed onto a different account (wrong name, wrong AAD,
authentication failure), and a kdf_params change forces a genuine re-wrap
because the old blob's binding names the old cost parameters. Non-ASCII
usernames ride the same ensure_ascii escaping as crypto.build_aad.

Like security/sharing.py, the wrap/unwrap functions here exist so the
cross-platform vectors in shared/vectors.json are generated and verified
against an independent third implementation; the SERVER's request paths
only validate shapes and store bytes (it has no input that can decrypt
the blob).
"""

from __future__ import annotations

import json

from .crypto import KEY_SIZE, NONCE_SIZE, TamperError, decrypt, encrypt_with_nonce
from .kdf import hkdf_sha256

ENVELOPE_KEK_INFO = b"mindpattern/envelope/v2"
ENVELOPE_CONTEXT = "envelope"
#: nonce(12) + ct(32) + tag(16): the wrapped 32-byte data key's exact size.
WRAPPED_DATA_KEY_BYTES = NONCE_SIZE + KEY_SIZE + 16


def envelope_kek(password_derived_key: bytes, salt: bytes) -> bytes:
    """KEK = HKDF-SHA256(password-derived key, salt, "mindpattern/envelope/v2").

    ``password_derived_key`` is whatever the account's kdf_params produce
    from the password (PBKDF2 master key today; an Argon2id hash when a
    client adopts that blob). Reusing the ACCOUNT salt (not a fresh one)
    is deliberate: the salt already travels to the client pre-login via
    POST /auth/salt, so the envelope needs no additional hand-off, and
    the HKDF info label domain-separates the KEK from the auth/data labels
    derived over the same salt.
    """
    if len(password_derived_key) < 16:
        raise ValueError("password-derived key material must be at least 16 bytes")
    return hkdf_sha256(password_derived_key, salt=salt, info=ENVELOPE_KEK_INFO, length=32)


def envelope_aad(username: str, kdf_params: dict[str, int | str]) -> bytes:
    """Canonical AAD binding the wrap to (context, account, KDF params).

    Key order is FIXED (not sorted) because the field order is itself part
    of the pinned vectors: {"context","kdf_params","username"} serialized
    compact, ASCII-only. kdf_params must already be canonical
    (kdf.validate_kdf_params) — this function does not re-validate so the
    stored blob and its AAD can never disagree by a normalization step.
    """
    payload = {
        "context": ENVELOPE_CONTEXT,
        "kdf_params": kdf_params,
        "username": username,
    }
    return json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def wrap_data_key(
    data_key: bytes,
    *,
    kek: bytes,
    username: str,
    kdf_params: dict[str, int | str],
    nonce: bytes,
) -> bytes:
    """Wrap the random data key under the password-derived KEK.

    The nonce is a REQUIRED argument: the server never wraps in a request
    path (it cannot build the KEK), so every caller is vector/test code
    and deterministic output is the point — mirroring
    crypto.encrypt_with_nonce's unmistakable fixed-nonce discipline.
    """
    if len(data_key) != KEY_SIZE:
        raise ValueError(f"data_key must be {KEY_SIZE} bytes")
    if len(kek) != KEY_SIZE:
        raise ValueError(f"kek must be {KEY_SIZE} bytes")
    return encrypt_with_nonce(kek, data_key, envelope_aad(username, kdf_params), nonce)


def unwrap_data_key(
    wrapped: bytes,
    *,
    kek: bytes,
    username: str,
    kdf_params: dict[str, int | str],
) -> bytes:
    """Verify + open the envelope; TamperError on any mismatch.

    Raises ValueError (not TamperError) for a structurally impossible blob
    so callers can distinguish "not an envelope" from "wrong password /
    tampered bytes" — a wrong password produces TamperError, exactly like
    every other GCM surface in this package.
    """
    if len(wrapped) != WRAPPED_DATA_KEY_BYTES:
        raise ValueError(f"wrapped data key must be exactly {WRAPPED_DATA_KEY_BYTES} bytes")
    if len(kek) != KEY_SIZE:
        raise ValueError(f"kek must be {KEY_SIZE} bytes")
    return decrypt(kek, wrapped, envelope_aad(username, kdf_params))


__all__ = [
    "ENVELOPE_CONTEXT",
    "ENVELOPE_KEK_INFO",
    "TamperError",
    "WRAPPED_DATA_KEY_BYTES",
    "envelope_aad",
    "envelope_kek",
    "unwrap_data_key",
    "wrap_data_key",
]
