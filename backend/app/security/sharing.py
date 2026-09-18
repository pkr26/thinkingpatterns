"""Zero-knowledge sharing crypto — the server-side reference implementation.

Wrap format (an ECIES-style construction over P-256, implemented
identically by the mobile app and the therapist portal):

    shared = ECDH(ephemeral_priv, therapist_pub)      # 32-byte X coordinate
    kek    = HKDF-SHA256(shared,
                         salt = ephemeral_spki_der || therapist_spki_der,
                         info = "mindpattern/wrap/v1", 32 bytes)
    wrap   = AES-256-GCM(kek, data_key,
                         aad = build_aad("consent-wrap", user_id, therapist_id))

Public keys travel as base64 **SPKI DER** (91 bytes for P-256) so every
platform imports them natively: node:crypto / react-native-quick-crypto
``createPublicKey({format: "der", type: "spki"})``, WebCrypto
``importKey("spki", …)``, Python ``load_der_public_key``.

The HKDF salt pins BOTH public keys into the KEK: a wrap produced against
one therapist key can never be replayed as a wrap against another. The AAD
pins the (patient, therapist) pair, so a blob cannot be relocated between
consent rows without the portal detecting tampering — the same
relocation-defense the entry blobs carry.

The server itself runs only the VALIDATION half of this module (parsing
therapist-registered public keys and grant-time ephemeral keys). Wrap runs
on the patient's device; unwrap runs in the therapist's browser. The wrap
and unwrap functions here exist so the cross-platform test vectors in
shared/vectors.json are generated and verified against a third, independent
implementation (the same standing the AES-GCM envelope module has).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_private_key,
    load_der_public_key,
)

from . import crypto
from .kdf import hkdf_sha256

WRAP_INFO = b"mindpattern/wrap/v1"
WRAP_CONTEXT = "consent-wrap"

# Therapist-portal key schedule (implemented by the portal in WebCrypto;
# pinned here as the contract, like the patient labels in kdf.py):
#   wrap key:  HKDF-SHA256(master, info="mindpattern/portal-wrap/v1")
#              -> encrypts the P-256 private key blob (AAD binds the
#                 therapist's username — known before registration)
#   note key:  HKDF-SHA256(master, info="mindpattern/portal-notes/v1")
#              -> encrypts note blobs
PORTAL_WRAP_INFO = b"mindpattern/portal-wrap/v1"
PORTAL_NOTES_INFO = b"mindpattern/portal-notes/v1"
THERAPIST_KEY_CONTEXT = "therapist-key"
NOTE_CONTEXT = "note"

# b64(91 bytes SPKI DER) = 124 chars — the schema caps match exactly.
SPKI_P256_B64_CHARS = 124
SPKI_P256_DER_BYTES = 91

# Pairing codes: 8 chars from a 31-symbol ambiguous-free alphabet
# (no 0/O, 1/I/L) ≈ 39.6 bits of entropy. Short-lived (15 min) and
# single-use; the server stores only an HMAC of the code.
PAIRING_ALPHABET = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
PAIRING_CODE_CHARS = 8
PAIRING_TTL_SECONDS = 900

_PAIRING_DIGEST_INFO = b"mindpattern/pairing-digest/v1"


class SharingError(ValueError):
    """Malformed key material (never raised for mere authentication failure
    of a wrap — that is TamperError from the envelope layer)."""


def _load_public(spki_der: bytes) -> ec.EllipticCurvePublicKey:
    """Parse + validate a P-256 SPKI public key. Any other curve, key type,
    or trailing garbage is rejected: the grant path must not store a key
    that no honest unwrap could ever use."""
    try:
        key = load_der_public_key(spki_der)
    except (ValueError, InvalidKey) as exc:
        raise SharingError("not a valid SPKI public key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey):
        raise SharingError("public key must be elliptic-curve")
    if not isinstance(key.curve, ec.SECP256R1):
        raise SharingError("public key must be P-256 (prime256v1)")
    return key


def validate_public_key_b64(b64: str) -> bytes:
    """Decode + validate a base64 SPKI P-256 public key; returns the DER
    bytes. Raises SharingError on anything malformed."""
    try:
        der = base64.b64decode(b64, validate=True)
    except (ValueError, TypeError) as exc:
        raise SharingError("public key must be base64") from exc
    _load_public(der)
    return der


def _kek(shared: bytes, ephemeral_der: bytes, therapist_der: bytes) -> bytes:
    return hkdf_sha256(shared, salt=ephemeral_der + therapist_der, info=WRAP_INFO, length=32)


def wrap_data_key(
    data_key: bytes,
    therapist_pub_b64: str,
    user_id: str,
    therapist_id: str,
    ephemeral_private: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[str, str]:
    """Reference implementation of the patient-side wrap.

    Returns ``(ephemeral_pub_b64, wrapped_b64)``. Test/vector code may pass
    a fixed ephemeral key; production callers (none on the server) generate
    one per grant. Mirrors mobile/src/crypto/sharing.ts and the portal.
    """
    if len(data_key) != crypto.KEY_SIZE:
        raise SharingError(f"data_key must be {crypto.KEY_SIZE} bytes")
    therapist_der = validate_public_key_b64(therapist_pub_b64)
    therapist_pub = _load_public(therapist_der)
    eph = ephemeral_private or ec.generate_private_key(ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), therapist_pub)
    eph_der = eph.public_key().public_bytes(
        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
    )
    kek = _kek(shared, eph_der, therapist_der)
    aad = crypto.build_aad(WRAP_CONTEXT, user_id, therapist_id)
    wrapped = crypto.encrypt(kek, data_key, aad)
    return base64.b64encode(eph_der).decode("ascii"), base64.b64encode(wrapped).decode("ascii")


def unwrap_data_key(
    therapist_private: ec.EllipticCurvePrivateKey,
    ephemeral_pub_b64: str,
    wrapped: bytes,
    user_id: str,
    therapist_id: str,
    therapist_pub_der: bytes | None = None,
) -> bytes:
    """Reference implementation of the portal-side unwrap. The portal knows
    its own public DER (or it is re-derived from the private key); the KEK
    salt needs it, so it is recomputed when not supplied."""
    eph_der = validate_public_key_b64(ephemeral_pub_b64)
    eph_pub = _load_public(eph_der)
    shared = therapist_private.exchange(ec.ECDH(), eph_pub)
    if therapist_pub_der is None:
        therapist_pub_der = therapist_private.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
    kek = _kek(shared, eph_der, therapist_pub_der)
    aad = crypto.build_aad(WRAP_CONTEXT, user_id, therapist_id)
    return crypto.decrypt(kek, wrapped, aad)


def load_private_key_pkcs8(der: bytes) -> ec.EllipticCurvePrivateKey:
    """Parse a PKCS8 DER P-256 private key (the plaintext of the therapist's
    stored wrap_key_blob, after the portal decrypts it)."""
    try:
        key = load_der_private_key(der, password=None)
    except (ValueError, TypeError, InvalidKey) as exc:
        raise SharingError("not a valid PKCS8 private key") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise SharingError("private key must be P-256 (prime256v1)")
    return key


# --- pairing codes ------------------------------------------------------------


def generate_pairing_code() -> str:
    alphabet = PAIRING_ALPHABET
    n = len(alphabet)
    # Rejection sampling (2026-09-17 audit): 256 % 31 == 8, so indexing by
    # byte % n favors the first 8 symbols. Drawing only bytes below the
    # largest complete multiple of n keeps every symbol equally likely
    # (~0.4 bits of the code's entropy reclaimed). Rejection is rare and
    # bounded — the loop refills from os.urandom in small batches.
    limit = 256 - (256 % n)
    chars: list[str] = []
    while len(chars) < PAIRING_CODE_CHARS:
        for byte in os.urandom(PAIRING_CODE_CHARS * 2):
            if byte < limit:
                chars.append(alphabet[byte % n])
                if len(chars) == PAIRING_CODE_CHARS:
                    break
    return "".join(chars)


def pairing_code_digest(code: str, secret: str) -> str:
    """HMAC-SHA256 of a pairing code under an HKDF subkey of the token
    secret (key separation, same standing as the decoy-salt key): a database
    leak yields digests, not live codes."""
    digest_key = hkdf_sha256(secret.encode("utf-8"), None, _PAIRING_DIGEST_INFO)
    return hmac.new(digest_key, code.strip().upper().encode("ascii"), hashlib.sha256).hexdigest()


def normalize_pairing_code(code: str) -> str:
    """Codes are typed by humans from a screen: case-insensitive, forgiving
    of surrounding whitespace. The character set itself is not remapped —
    an ambiguous typo stays a wrong code (404), never a different grant."""
    return code.strip().upper()
