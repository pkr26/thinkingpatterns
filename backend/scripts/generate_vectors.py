"""Generate shared/vectors.json — cross-platform crypto test vectors.

Each vector pins the exact bytes produced by the client-side crypto stack
(PBKDF2 master key, HKDF auth/data keys, AES-256-GCM envelope with AAD) at
production parameters (600k iterations). The mobile repo verifies the same
file with Node's webcrypto (mobile/tools/verify_vectors.mjs), proving the
React Native implementation matches the backend byte-for-byte.

The PBKDF2 result is cross-checked between hashlib.pbkdf2_hmac and
cryptography's PBKDF2HMAC before writing, so a bug in either implementation
cannot silently poison the vectors.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.security import crypto, kdf  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]

CASES = [
    {
        "password": "correct horse battery staple",
        "salt": bytes(range(16)),
        "plaintext": b"Sunday night again. The deadline dread is back.",
        "aad": ["entry", "user-1234", "entry-2026-09-01-a"],
    },
    {
        "password": "p@ssw0rd-ïñ-unicode",
        "salt": bytes(range(16, 32)),
        "plaintext": b'{"v":1,"text":"good morning","sentiment":0.5,"created_at":"2026-09-02"}',
        "aad": ["insights", "user-abcd", "patterns"],
    },
    # Non-ASCII AAD parts pin the ensure_ascii cross-platform contract: the
    # canonical AAD is ASCII-only bytes (every UTF-16 unit >= 0x7F escaped as
    # \uXXXX, astral chars as surrogate pairs). Python's json.dumps and the
    # mobile client's escaper must agree byte-for-byte or blobs encrypted on
    # one platform become undecryptable on the other.
    {
        "password": "unicode-aad-case",
        "salt": bytes(range(32, 48)),
        "plaintext": b"non-ascii AAD binding check",
        "aad": ["entry", "ünïcode-user", "entrée-🧠-1"],
    },
    {
        "password": "astral-aad-case",
        "salt": bytes(range(48, 64)),
        "plaintext": b"astral AAD binding check",
        "aad": ["insights", "user-🧠-brain", "patterns"],
    },
]

# Fixed-nonce encrypt vectors pin the OTHER direction: the decrypt-only
# vectors above prove both platforms can read Python's output, but nothing
# pinned what the mobile encrypt() emits (it uses a random nonce, so its
# output cannot be pinned transitively). Here the nonce is fixed and the
# exact blob bytes are stored, so each platform's encrypt() is checked
# byte-for-byte against output the other platform independently decrypts.
# AAD is stored as PARTS (context, userId, itemId) — never the pre-built
# bytes — so consumers are forced through their own AAD builder. A null
# aad_parts pins the AAD-less path used by secureStore.ts's device-key store.
ENCRYPT_CASES = [
    {
        "password": "encrypt-pin-ascii",
        "salt": bytes(range(64, 80)),
        "plaintext": b"Feeling calmer after the morning walk.",
        "aad_parts": ["entry", "user-777", "entry-2026-09-07-morning"],
        "nonce": bytes(range(12, 24)),
    },
    # Non-ASCII/astral user and entry ids: the blob only matches if the AAD
    # builder reproduces Python's ensure_ascii escaping byte-for-byte.
    {
        "password": "encrypt-pin-ünïcode",
        "salt": bytes(range(80, 96)),
        "plaintext": b"fixed-nonce encrypt pin with astral AAD binding",
        "aad_parts": ["entry", "üsér-🧠", "entrée-🌙-42"],
        "nonce": bytes(range(23, 11, -1)),
    },
    # 2-part moodlog AAD, exactly as mobile/src/moodLog.ts builds it.
    {
        "password": "encrypt-pin-moodlog",
        "salt": bytes(range(96, 112)),
        "plaintext": b'[{"date":"2026-09-07","value":0.75}]',
        "aad_parts": ["moodlog", "user-555"],
        "nonce": bytes(range(24, 36)),
    },
    # 2-part unlockproof AAD with the production proof plaintext
    # (mobile/src/unlockProof.ts PROOF_PLAINTEXT).
    {
        "password": "encrypt-pin-unlockproof",
        "salt": bytes(range(112, 128)),
        "plaintext": b"mindpattern-unlock-proof/v1",
        "aad_parts": ["unlockproof", "user-888"],
        "nonce": bytes(range(35, 23, -1)),
    },
    # Empty plaintext: pins the nonce||tag-only blob shape both ways.
    {
        "password": "encrypt-pin-empty",
        "salt": bytes(range(128, 144)),
        "plaintext": b"",
        "aad_parts": ["entry", "user-000", "entry-empty"],
        "nonce": bytes(range(36, 48)),
    },
    # No AAD at all: the path mobile/src/secureStore.ts's device-key store
    # encrypts through. aad_parts null forces consumers to omit AAD.
    {
        "password": "encrypt-pin-no-aad",
        "salt": bytes(range(144, 160)),
        "plaintext": b"device-local secret without aad binding",
        "aad_parts": None,
        "nonce": bytes(range(47, 35, -1)),
    },
]


# --- v2 key-scheme vectors (2026-09-26 crypto-architecture wave) ---------------
#
# Three NEW cross-platform pins, all append-only under their own top-level
# section "envelope_vectors" (existing sections keep their exact entries):
#   1. The FOUR-PART v2 entry AAD (context, user, id, content_version) —
#      the pre-2026-09-20 blobs above are all three-part; nothing pinned
#      what a current client emits for the version-bound binding.
#   2. A TAMPERED-blob NEGATIVE vector: same inputs, one flipped
#      ciphertext byte, "expect": "tamper" — platforms must fail
#      authentication, never return plaintext or a 500.
#   3. The random data-key ENVELOPE construction (security/envelope.py):
#      KEK = HKDF-SHA256(master_key, salt, "mindpattern/envelope/v2"),
#      wrapped = AES-256-GCM(kek, random 32-byte data_key) with AAD
#      canonical JSON {context, kdf_params, user_id}, plus its own tampered
#      negative. kdf_params stay pbkdf2-sha256 here: the server never
#      computes Argon2id (no dependency, by design) and vectors must be
#      generatable by every platform's shipped crypto stack.
ENVELOPE_ENTRY_CASE = {
    "password": "envelope-entry-v2-pin",
    "salt": bytes(range(160, 176)),
    "plaintext": b'{"v":1,"text":"version-bound AAD pin","sentiment":0.1,"created_at":"2026-09-26"}',
    # The FOUR-PART v2 binding: the fourth part is the row's monotonic
    # content_version (2026-09-20 audit fix M-2).
    "aad_parts": ["entry", "user-909", "entry-2026-09-26-v2", "3"],
    "nonce": bytes(range(48, 60)),
}

ENVELOPE_WRAP_CASE = {
    "password": "envelope-wrap-pin",
    "salt": bytes(range(176, 192)),
    # Canonical pbkdf2 blob exactly as kdf.validate_kdf_params emits it.
    "kdf_params": {"algorithm": "pbkdf2-sha256", "iterations": kdf.KDF_ITERATIONS, "version": 1},
    # The AAD binds the account USERNAME (unique, immutable, client-known
    # before registration) — not the server-generated user id, which cannot
    # exist at first-wrap time (see security/envelope.py's deviation note).
    "username": "envelope-wrap-user",
    "data_key": bytes(range(200, 232)),  # the RANDOM 32-byte data key (pinned for the vector)
    "nonce": bytes(range(60, 72)),
}


def _tamper(blob: bytes) -> bytes:
    """Flip one ciphertext byte in the middle of the envelope — guaranteed
    inside ct||tag (past the 12-byte nonce), guaranteed to break GCM."""
    mutated = bytearray(blob)
    mutated[len(blob) // 2] ^= 0x01
    return bytes(mutated)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes, bytes]:
    """PBKDF2 master key, cross-checked between two implementations."""
    via_hashlib = kdf.derive_master_key(password, salt, kdf.KDF_ITERATIONS)
    via_cryptography = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=kdf.KDF_ITERATIONS
    ).derive(password.encode("utf-8"))
    assert via_hashlib == via_cryptography, "PBKDF2 implementations disagree!"
    master = via_hashlib
    return master, kdf.derive_auth_key(master), kdf.derive_data_key(master)


def main() -> None:
    vectors = []
    for case in CASES:
        salt = case["salt"]
        master, auth_key, data_key = derive_keys(case["password"], salt)
        aad = crypto.build_aad(*case["aad"])
        nonce = bytes(range(12))  # deterministic nonce for vector stability
        ciphertext = AESGCM(data_key).encrypt(nonce, case["plaintext"], aad)

        vectors.append(
            {
                "password": case["password"],
                "salt": base64.b64encode(salt).decode(),
                "iterations": kdf.KDF_ITERATIONS,
                "master_key": base64.b64encode(master).decode(),
                "auth_key": base64.b64encode(auth_key).decode(),
                "data_key": base64.b64encode(data_key).decode(),
                "plaintext": base64.b64encode(case["plaintext"]).decode(),
                "aad": base64.b64encode(aad).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "blob": base64.b64encode(nonce + ciphertext).decode(),
            }
        )

    encrypt_vectors = []
    for case in ENCRYPT_CASES:
        salt = case["salt"]
        _, _, data_key = derive_keys(case["password"], salt)
        aad = crypto.build_aad(*case["aad_parts"]) if case["aad_parts"] else None
        nonce = case["nonce"]
        assert len(nonce) == crypto.NONCE_SIZE
        # AESGCM directly (not crypto.encrypt) keeps generation independent
        # of the function the backend test pins against these bytes.
        ciphertext = AESGCM(data_key).encrypt(nonce, case["plaintext"], aad)

        encrypt_vectors.append(
            {
                "password": case["password"],
                "salt": base64.b64encode(salt).decode(),
                "iterations": kdf.KDF_ITERATIONS,
                "data_key": base64.b64encode(data_key).decode(),
                "plaintext": base64.b64encode(case["plaintext"]).decode(),
                "aad_parts": case["aad_parts"],
                "nonce": base64.b64encode(nonce).decode(),
                "blob": base64.b64encode(nonce + ciphertext).decode(),
            }
        )

    envelope_vectors = []
    # (1) four-part v2 entry AAD pin + (2) its tampered negative.
    entry_case = ENVELOPE_ENTRY_CASE
    _, _, entry_data_key = derive_keys(entry_case["password"], entry_case["salt"])
    entry_aad = crypto.build_aad(*entry_case["aad_parts"])
    # Wire format nonce||ct||tag — the same shape every other encrypt
    # vector section pins.
    entry_blob = entry_case["nonce"] + AESGCM(entry_data_key).encrypt(
        entry_case["nonce"], entry_case["plaintext"], entry_aad
    )
    envelope_vectors.append(
        {
            "kind": "entry-aad-v2",
            "password": entry_case["password"],
            "salt": base64.b64encode(entry_case["salt"]).decode(),
            "iterations": kdf.KDF_ITERATIONS,
            "data_key": base64.b64encode(entry_data_key).decode(),
            "plaintext": base64.b64encode(entry_case["plaintext"]).decode(),
            "aad_parts": entry_case["aad_parts"],
            "nonce": base64.b64encode(entry_case["nonce"]).decode(),
            "blob": base64.b64encode(entry_blob).decode(),
        }
    )
    envelope_vectors.append(
        {
            "kind": "entry-aad-v2-tampered",
            "password": entry_case["password"],
            "salt": base64.b64encode(entry_case["salt"]).decode(),
            "iterations": kdf.KDF_ITERATIONS,
            "data_key": base64.b64encode(entry_data_key).decode(),
            "aad_parts": entry_case["aad_parts"],
            "blob": base64.b64encode(_tamper(entry_blob)).decode(),
            # NEGATIVE vector: consumers must raise their tamper error.
            "expect": "tamper",
        }
    )
    # (3) the random data-key envelope (security/envelope.py) + its tampered
    # negative. Built through the REAL module (not AESGCM directly) so the
    # pin is the reference implementation's own output — the same standing
    # the sharing wrap vectors have.
    from app.security import envelope as key_envelope

    wrap_case = ENVELOPE_WRAP_CASE
    wrap_master, _, _ = derive_keys(wrap_case["password"], wrap_case["salt"])
    canonical_params = kdf.validate_kdf_params(wrap_case["kdf_params"])
    kek = key_envelope.envelope_kek(wrap_master, wrap_case["salt"])
    wrap_aad = key_envelope.envelope_aad(wrap_case["username"], canonical_params)
    wrapped = key_envelope.wrap_data_key(
        wrap_case["data_key"],
        kek=kek,
        username=wrap_case["username"],
        kdf_params=canonical_params,
        nonce=wrap_case["nonce"],
    )
    envelope_vectors.append(
        {
            "kind": "key-envelope-wrap",
            "password": wrap_case["password"],
            "salt": base64.b64encode(wrap_case["salt"]).decode(),
            "iterations": kdf.KDF_ITERATIONS,
            "master_key": base64.b64encode(wrap_master).decode(),
            "kdf_params": canonical_params,
            "kek": base64.b64encode(kek).decode(),
            "username": wrap_case["username"],
            "data_key": base64.b64encode(wrap_case["data_key"]).decode(),
            "aad": base64.b64encode(wrap_aad).decode(),
            "nonce": base64.b64encode(wrap_case["nonce"]).decode(),
            "wrapped": base64.b64encode(wrapped).decode(),
        }
    )
    envelope_vectors.append(
        {
            "kind": "key-envelope-wrap-tampered",
            "password": wrap_case["password"],
            "salt": base64.b64encode(wrap_case["salt"]).decode(),
            "iterations": kdf.KDF_ITERATIONS,
            "master_key": base64.b64encode(wrap_master).decode(),
            "kdf_params": canonical_params,
            "kek": base64.b64encode(kek).decode(),
            "username": wrap_case["username"],
            "aad": base64.b64encode(wrap_aad).decode(),
            "wrapped": base64.b64encode(_tamper(wrapped)).decode(),
            "expect": "tamper",
        }
    )

    out = REPO_ROOT / "shared" / "vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    # MERGE, never overwrite: shared/vectors.json also carries hand-maintained
    # sections (wrap_vectors, aad_edge_cases) that have no generator. A
    # wholesale rewrite would silently delete half the cross-platform crypto
    # contract, and the mobile verifier (mobile/tools/verify_vectors.mjs)
    # fails closed when those sections are missing. Only the sections this
    # script actually generates are replaced; every other key is preserved
    # as-is (value AND position) from the existing file.
    GENERATED_SECTIONS = ("vectors", "encrypt_vectors", "envelope_vectors")
    existing_text = out.read_text() if out.exists() else ""
    try:
        existing = json.loads(existing_text) if existing_text else {}
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"refusing to regenerate: {out} exists but is not valid JSON ({exc}); "
            "fix or remove the file by hand so hand-maintained sections are not lost"
        ) from exc
    if not isinstance(existing, dict):
        raise SystemExit(
            f"refusing to regenerate: {out} has a top-level {type(existing).__name__}, "
            "expected a JSON object; fix the file by hand so hand-maintained "
            "sections are not lost"
        )
    # Keep the preserved sections byte-stable: reuse the existing file's
    # exact serialization (the committed file is indent=1; a fresh file
    # defaults to indent=2). Anything that already round-trips is canonical.
    indent = 2
    for candidate in (1, 2, 3, 4, "\t"):
        if existing_text and json.dumps(existing, indent=candidate) + "\n" == existing_text:
            indent = candidate
            break
    preserved = {k: v for k, v in existing.items() if k not in GENERATED_SECTIONS}
    payload = dict(existing)
    payload.update(
        {
            "vectors": vectors,
            "encrypt_vectors": encrypt_vectors,
            "envelope_vectors": envelope_vectors,
        }
    )
    out.write_text(json.dumps(payload, indent=indent) + "\n")
    preserved_names = (
        ", ".join(
            f"{k} ({len(v) if isinstance(v, (list, dict)) else 1})" for k, v in preserved.items()
        )
        or "none"
    )
    print(
        f"wrote {len(vectors)} vectors + {len(encrypt_vectors)} encrypt vectors + "
        f"{len(envelope_vectors)} envelope vectors -> {out}\n"
        f"preserved hand-maintained sections: {preserved_names}"
    )


if __name__ == "__main__":
    main()
