"""Client-side key schedule (reference implementation).

    master_key = PBKDF2-HMAC-SHA256(password, salt, 600_000)
    auth_key   = HKDF-SHA256(master_key, info="mindpattern/auth/v1")   # sent to server
    data_key   = HKDF-SHA256(master_key, info="mindpattern/data/v1")   # NEVER sent,
                                                       # except into a processing session

The server stores scrypt(auth_key) and can therefore verify logins without
ever holding a key that decrypts entries. The mobile client derives the same
three values locally (shared/vectors.json pins the exact bytes on both
platforms).
"""

from __future__ import annotations

import hashlib
import hmac
import json

KDF_ITERATIONS = 600_000
# Runtime floor for caller-supplied iteration counts. The server cannot
# verify a client's work factor (it never sees the password), but the
# shared libraries on BOTH platforms refuse to derive below this — a
# modified client can still bypass its own floor, yet no honest code path,
# future refactor, or copy-pasted caller can silently downgrade the 600k
# contract (2026-09-16 red-team finding A4).
MIN_ITERATIONS = 100_000
AUTH_INFO = b"mindpattern/auth/v1"
DATA_INFO = b"mindpattern/data/v1"
MIN_SALT_SIZE = 8


def derive_master_key(
    password: str | bytes, salt: bytes, iterations: int = KDF_ITERATIONS
) -> bytes:
    """Derive the 256-bit master key from the user's password."""
    if isinstance(password, str):
        password = password.encode("utf-8")
    if len(salt) < MIN_SALT_SIZE:
        raise ValueError(f"salt must be at least {MIN_SALT_SIZE} bytes")
    if iterations < MIN_ITERATIONS:
        raise ValueError(
            f"iterations must be at least {MIN_ITERATIONS} "
            f"(got {iterations}; the cross-platform contract is {KDF_ITERATIONS})"
        )
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations)


def hkdf_sha256(ikm: bytes, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    """HKDF-SHA256 (RFC 5869) extract-and-expand."""
    if length < 1 or length > 255 * 32:
        raise ValueError("invalid HKDF output length")
    salt = salt if salt else b"\x00" * hashlib.sha256().digest_size
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_auth_key(master_key: bytes) -> bytes:
    """Key whose scrypt hash the server stores for login verification."""
    return hkdf_sha256(master_key, None, AUTH_INFO)


def derive_data_key(master_key: bytes) -> bytes:
    """Key that encrypts entries, insights and questions.

    v1 accounts derive the data key DIRECTLY from the password-derived
    master key, which couples "change the password" to "re-encrypt the
    whole corpus". v2 accounts (2026-09-26 envelope remediation) keep a
    RANDOM 32-byte data key and wrap it under a KEK derived from the
    password (see security/envelope.py); the master key still exists and
    still splits into auth/data labels so the login verifier and the v1
    flows stay byte-compatible — but for a v2 account the HKDF data label
    is never used to protect storage.
    """
    return hkdf_sha256(master_key, None, DATA_INFO)


# --- versioned kdf_params blob (2026-09-26 crypto-architecture wave) -----------
#
# Accounts can now DECLARE which client-side KDF produced their keys:
#
#     {"algorithm": "pbkdf2-sha256", "iterations": 600000, "version": 1}
#     {"algorithm": "argon2id", "memory_kib": 65536, "parallelism": 1,
#      "iterations": 3, "version": 1}
#
# The server VALIDATES the structure and bounds and stores the canonical
# JSON verbatim — it NEVER computes the KDF (the only password-derived
# value the server ever hashes is the login verifier, which is KDF-blind:
# scrypt(auth_key) proves possession regardless of how the client derived
# auth_key). Argon2id params are therefore accepted and persisted today
# WITHOUT argon2-cffi in the dependency tree: a client that adopts
# Argon2id (the blob is the adoption enabler) is fully functional against
# this server, while the SHIPPED client params stay pbkdf2-600k — the
# documented WebCrypto tradeoff (no native Argon2id in browsers/react-
# native-quick-crypto without a WASM dependency).
#
# Canonicalization matters cryptographically: the blob is embedded in the
# v2 key-envelope AAD (envelope.py), so two spellings of the same params
# ("iterations": 600000 vs 6.0e5, or reordered keys) MUST map to one
# canonical JSON or a re-wrapped envelope stops authenticating. The
# canonical form is compact-separators, sort_keys, ensure_ascii JSON of
# the validated dict — ints only, no optional fields, no extra fields.

KDF_ALGO_PBKDF2 = "pbkdf2-sha256"
KDF_ALGO_ARGON2ID = "argon2id"
KDF_PARAMS_VERSION = 1
#: Shipped-client parameters — the constant every current client derives
#: with, echoed here so the server and README can name the default without
#: importing a second source of truth.
KDF_PARAMS_DEFAULT: dict[str, int | str] = {
    "algorithm": KDF_ALGO_PBKDF2,
    "iterations": KDF_ITERATIONS,
    "version": KDF_PARAMS_VERSION,
}

#: Bounds (structure AND cost): a malicious or buggy client must not be
#: able to persist params that make honest clients burn unbounded CPU, and
#: a typo (iterations: 6000000 vs 600000, memory 19 MiB vs 19 KiB) must
#: fail loudly at the boundary instead of locking the account's envelope.
PBKDF2_MAX_ITERATIONS = 10_000_000  # 10M ≈ tens of seconds of KDF per unlock
ARGON2_MIN_MEMORY_KIB = 19 * 1024  # 19 MiB — the RFC 9106 recommended floor
ARGON2_MAX_MEMORY_KIB = 256 * 1024  # 256 MiB ceiling
ARGON2_MIN_ITERATIONS = 2  # t >= 2 per RFC 9106 low-resource profile guidance
# Symmetric ceiling for argon2id passes, mirroring PBKDF2's 10M cap: a
# missing ceiling let a buggy or hostile client persist t values (t=1e9,
# say) that honest re-validation (parse_kdf_params_json re-validates every
# read) would keep honoring forever and any future server-side argon2
# consumer would burn unbounded CPU on. Honest params sit at t=2-10; the
# cap only bounds the pathological tail, exactly like the memory ceiling.
ARGON2_MAX_ITERATIONS = 10_000_000
ARGON2_MAX_PARALLELISM = 4
#: Storage/AAD bound: canonical JSON of any valid blob fits comfortably.
KDF_PARAMS_MAX_JSON_CHARS = 256


class KdfParamsError(ValueError):
    """Malformed kdf_params blob (structure or bounds). The API layer maps
    this to a 422 validation_error — never a 500."""


def validate_kdf_params(params: object) -> dict[str, int | str]:
    """Validate structure + bounds and return the CANONICAL dict.

    Strict by design: unknown keys are rejected (not ignored) so the AAD
    canonicalization rule ("the bytes you sent are the bytes that bind")
    can never be silently narrowed, and bools are rejected explicitly
    (``isinstance(True, int)`` in Python — JSON true is not a cost).
    """
    if not isinstance(params, dict):
        raise KdfParamsError("kdf_params must be a JSON object")
    allowed = {"algorithm", "version", "iterations", "memory_kib", "parallelism"}
    unknown = set(params) - allowed
    if unknown:
        raise KdfParamsError(f"kdf_params has unknown fields: {sorted(unknown)}")
    algorithm = params.get("algorithm")
    if algorithm not in (KDF_ALGO_PBKDF2, KDF_ALGO_ARGON2ID):
        raise KdfParamsError(
            f"kdf_params.algorithm must be {KDF_ALGO_PBKDF2!r} or {KDF_ALGO_ARGON2ID!r}"
        )
    version = params.get("version")
    if isinstance(version, bool) or not isinstance(version, int) or version != KDF_PARAMS_VERSION:
        raise KdfParamsError(f"kdf_params.version must be {KDF_PARAMS_VERSION}")
    canonical: dict[str, int | str] = {
        "algorithm": algorithm,
        "version": KDF_PARAMS_VERSION,
    }
    if algorithm == KDF_ALGO_PBKDF2:
        if {"memory_kib", "parallelism"} & set(params):
            raise KdfParamsError("pbkdf2-sha256 kdf_params carry iterations only")
        iterations = _require_int(params, "iterations")
        if not MIN_ITERATIONS <= iterations <= PBKDF2_MAX_ITERATIONS:
            raise KdfParamsError(
                f"kdf_params.iterations must be {MIN_ITERATIONS}-{PBKDF2_MAX_ITERATIONS} "
                "for pbkdf2-sha256"
            )
        canonical["iterations"] = iterations
    else:
        required = {"iterations", "memory_kib", "parallelism"}
        missing = required - set(params)
        if missing:
            raise KdfParamsError(f"argon2id kdf_params require {sorted(missing)}")
        iterations = _require_int(params, "iterations")
        if not ARGON2_MIN_ITERATIONS <= iterations <= ARGON2_MAX_ITERATIONS:
            raise KdfParamsError(
                f"kdf_params.iterations must be "
                f"{ARGON2_MIN_ITERATIONS}-{ARGON2_MAX_ITERATIONS} for argon2id"
            )
        memory_kib = _require_int(params, "memory_kib")
        if not ARGON2_MIN_MEMORY_KIB <= memory_kib <= ARGON2_MAX_MEMORY_KIB:
            raise KdfParamsError(
                "kdf_params.memory_kib must be "
                f"{ARGON2_MIN_MEMORY_KIB}-{ARGON2_MAX_MEMORY_KIB} (19-256 MiB)"
            )
        parallelism = _require_int(params, "parallelism")
        if not 1 <= parallelism <= ARGON2_MAX_PARALLELISM:
            raise KdfParamsError(f"kdf_params.parallelism must be 1-{ARGON2_MAX_PARALLELISM}")
        canonical["iterations"] = iterations
        canonical["memory_kib"] = memory_kib
        canonical["parallelism"] = parallelism
    return canonical


def _require_int(params: dict, field: str) -> int:
    """Fetch a cost integer or fail loudly. isinstance narrowing (bool is an
    int in Python — JSON true is not a cost) keeps mypy and the runtime
    check in exact agreement."""
    value = params.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise KdfParamsError(f"kdf_params.{field} must be an integer")
    return value


def canonical_kdf_params_json(params: dict[str, int | str]) -> str:
    """The one serialization of a validated blob (storage AND envelope AAD).

    sort_keys + compact separators + ensure_ascii: byte-identical on every
    platform that honors JSON ordering the same way the entry-AAD builder
    does (see crypto.build_aad for the same cross-platform reasoning).
    """
    return json.dumps(params, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def parse_kdf_params_json(stored: str | None) -> dict[str, int | str] | None:
    """Re-validate a stored blob on read (fail closed: a tampered or
    hand-edited column answers None, never a half-parsed dict)."""
    if not stored:
        return None
    try:
        parsed = json.loads(stored)
    except (ValueError, TypeError):
        return None
    try:
        return validate_kdf_params(parsed)
    except KdfParamsError:
        return None
