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

# Pairing codes: 8 chars from a 30-symbol ambiguous-free alphabet
# (no 0/O, 1/I/L, and no U — kept out with the other confusables when the
# set was fixed; vectors pin the alphabet byte-for-byte, so it must not
# change) = 8 × log2(30) ≈ 39.25 (~39.2) bits of entropy. Short-lived
# (15 min) and single-use; the server stores only an HMAC of the code.
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
    return _ecies_wrap(
        data_key,
        therapist_pub_b64,
        user_id,
        therapist_id,
        WRAP_CONTEXT,
        require_key_size=True,
        ephemeral_private=ephemeral_private,
    )


def _ecies_wrap(
    plaintext: bytes,
    therapist_pub_b64: str,
    user_id: str,
    therapist_id: str,
    context: str,
    *,
    require_key_size: bool = False,
    ephemeral_private: ec.EllipticCurvePrivateKey | None = None,
) -> tuple[str, str]:
    """The ECIES construction shared by every server→therapist wrap: an
    ephemeral P-256 key per wrap, ECDH against the therapist's public key,
    HKDF salted by BOTH public keys, AES-256-GCM with the AAD pinning the
    (context, user, therapist) triple — the context separates the roles so
    a key wrap can never be replayed as a summary wrap or vice versa."""
    if require_key_size and len(plaintext) != crypto.KEY_SIZE:
        raise SharingError(f"data_key must be {crypto.KEY_SIZE} bytes")
    therapist_der = validate_public_key_b64(therapist_pub_b64)
    therapist_pub = _load_public(therapist_der)
    eph = ephemeral_private or ec.generate_private_key(ec.SECP256R1())
    shared = eph.exchange(ec.ECDH(), therapist_pub)
    eph_der = eph.public_key().public_bytes(
        encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
    )
    kek = _kek(shared, eph_der, therapist_der)
    aad = crypto.build_aad(context, user_id, therapist_id)
    wrapped = crypto.encrypt(kek, plaintext, aad)
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
    return _ecies_unwrap(
        therapist_private,
        ephemeral_pub_b64,
        wrapped,
        user_id,
        therapist_id,
        WRAP_CONTEXT,
        therapist_pub_der=therapist_pub_der,
    )


def _ecies_unwrap(
    therapist_private: ec.EllipticCurvePrivateKey,
    ephemeral_pub_b64: str,
    wrapped: bytes,
    user_id: str,
    therapist_id: str,
    context: str,
    *,
    therapist_pub_der: bytes | None = None,
) -> bytes:
    eph_der = validate_public_key_b64(ephemeral_pub_b64)
    eph_pub = _load_public(eph_der)
    shared = therapist_private.exchange(ec.ECDH(), eph_pub)
    if therapist_pub_der is None:
        therapist_pub_der = therapist_private.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo
        )
    kek = _kek(shared, eph_der, therapist_pub_der)
    aad = crypto.build_aad(context, user_id, therapist_id)
    return crypto.decrypt(kek, wrapped, aad)


# --- caseload summaries ----------------------------------------------------------

SUMMARY_CONTEXT = "caseload-summary"
SUMMARY_MAX_BYTES = 512


def wrap_summary_payload(
    summary: bytes,
    therapist_pub_b64: str,
    user_id: str,
    therapist_id: str,
) -> tuple[str, str]:
    """Wrap a small per-consent caseload summary to the therapist's public
    key (the recompute path's server-side counterpart of the patient-side
    data-key wrap — same construction, different AAD context, arbitrary
    bounded payload). The plaintext exists only inside the processing
    session, exactly like the patterns it summarizes."""
    if len(summary) > SUMMARY_MAX_BYTES:
        raise SharingError("summary payload too large")
    return _ecies_wrap(summary, therapist_pub_b64, user_id, therapist_id, SUMMARY_CONTEXT)


def unwrap_summary_payload(
    therapist_private: ec.EllipticCurvePrivateKey,
    ephemeral_pub_b64: str,
    wrapped: bytes,
    user_id: str,
    therapist_id: str,
) -> bytes:
    """The portal-side counterpart (reference implementation; the portal
    implements the same WebCrypto derivation)."""
    return _ecies_unwrap(
        therapist_private, ephemeral_pub_b64, wrapped, user_id, therapist_id, SUMMARY_CONTEXT
    )


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
    # Rejection sampling (2026-09-17 audit): 256 % 30 == 16, so indexing by
    # byte % n favors the first 16 symbols. Drawing only bytes below the
    # largest complete multiple of n keeps every symbol equally likely
    # (the modulo bias costs only ~0.003 bits/char, but the reclaim is
    # free). Rejection is rare and bounded — the loop refills from
    # os.urandom in small batches. The limit derives from the ACTUAL
    # alphabet length, so it stays correct if the set ever changes.
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
    # The public lookup/grant endpoints intentionally answer every malformed
    # code as the same flat 404.  Normalize here as well as at their boundary
    # so a direct caller can never turn a non-ASCII code into UnicodeEncodeError
    # (and therefore a 500) while deriving its harmless non-match digest.
    return hmac.new(
        digest_key, normalize_pairing_code(code).encode("ascii"), hashlib.sha256
    ).hexdigest()


def normalize_pairing_code(code: str) -> str:
    """Codes are typed by humans from a screen: case-insensitive, forgiving
    of surrounding whitespace. Invalid/non-ASCII characters normalize to a
    guaranteed non-code, so an ambiguous typo stays a flat 404 rather than
    being remapped to a different grant or raising during ASCII HMAC input."""
    # Check the ORIGINAL user input before trimming or case conversion:
    # Unicode uppercase mappings such as ß -> SS could otherwise turn a
    # non-ASCII typo into a valid generated code and accidentally redeem
    # somebody else's share. ASCII whitespace remains intentionally forgiving.
    if not code.isascii():
        return ""
    normalized = code.strip().upper()
    if any(char not in PAIRING_ALPHABET for char in normalized):
        return ""
    return normalized
