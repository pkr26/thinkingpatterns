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
    {"password": "correct horse battery staple", "salt": bytes(range(16)),
     "plaintext": b"Sunday night again. The deadline dread is back.",
     "aad": ["entry", "user-1234", "entry-2026-09-01-a"]},
    {"password": "p@ssw0rd-ïñ-unicode", "salt": bytes(range(16, 32)),
     "plaintext": b'{"v":1,"text":"good morning","sentiment":0.5,"created_at":"2026-09-02"}',
     "aad": ["insights", "user-abcd", "patterns"]},
    # Non-ASCII AAD parts pin the ensure_ascii cross-platform contract: the
    # canonical AAD is ASCII-only bytes (every UTF-16 unit >= 0x7F escaped as
    # \uXXXX, astral chars as surrogate pairs). Python's json.dumps and the
    # mobile client's escaper must agree byte-for-byte or blobs encrypted on
    # one platform become undecryptable on the other.
    {"password": "unicode-aad-case", "salt": bytes(range(32, 48)),
     "plaintext": b"non-ascii AAD binding check",
     "aad": ["entry", "ünïcode-user", "entrée-🧠-1"]},
    {"password": "astral-aad-case", "salt": bytes(range(48, 64)),
     "plaintext": b"astral AAD binding check",
     "aad": ["insights", "user-🧠-brain", "patterns"]},
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
    {"password": "encrypt-pin-ascii", "salt": bytes(range(64, 80)),
     "plaintext": b"Feeling calmer after the morning walk.",
     "aad_parts": ["entry", "user-777", "entry-2026-09-07-morning"],
     "nonce": bytes(range(12, 24))},
    # Non-ASCII/astral user and entry ids: the blob only matches if the AAD
    # builder reproduces Python's ensure_ascii escaping byte-for-byte.
    {"password": "encrypt-pin-ünïcode", "salt": bytes(range(80, 96)),
     "plaintext": b"fixed-nonce encrypt pin with astral AAD binding",
     "aad_parts": ["entry", "üsér-🧠", "entrée-🌙-42"],
     "nonce": bytes(range(23, 11, -1))},
    # 2-part moodlog AAD, exactly as mobile/src/moodLog.ts builds it.
    {"password": "encrypt-pin-moodlog", "salt": bytes(range(96, 112)),
     "plaintext": b'[{"date":"2026-09-07","value":0.75}]',
     "aad_parts": ["moodlog", "user-555"],
     "nonce": bytes(range(24, 36))},
    # 2-part unlockproof AAD with the production proof plaintext
    # (mobile/src/unlockProof.ts PROOF_PLAINTEXT).
    {"password": "encrypt-pin-unlockproof", "salt": bytes(range(112, 128)),
     "plaintext": b"mindpattern-unlock-proof/v1",
     "aad_parts": ["unlockproof", "user-888"],
     "nonce": bytes(range(35, 23, -1))},
    # Empty plaintext: pins the nonce||tag-only blob shape both ways.
    {"password": "encrypt-pin-empty", "salt": bytes(range(128, 144)),
     "plaintext": b"",
     "aad_parts": ["entry", "user-000", "entry-empty"],
     "nonce": bytes(range(36, 48))},
    # No AAD at all: the path mobile/src/secureStore.ts's device-key store
    # encrypts through. aad_parts null forces consumers to omit AAD.
    {"password": "encrypt-pin-no-aad", "salt": bytes(range(144, 160)),
     "plaintext": b"device-local secret without aad binding",
     "aad_parts": None,
     "nonce": bytes(range(47, 35, -1))},
]


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

        vectors.append({
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
        })

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

        encrypt_vectors.append({
            "password": case["password"],
            "salt": base64.b64encode(salt).decode(),
            "iterations": kdf.KDF_ITERATIONS,
            "data_key": base64.b64encode(data_key).decode(),
            "plaintext": base64.b64encode(case["plaintext"]).decode(),
            "aad_parts": case["aad_parts"],
            "nonce": base64.b64encode(nonce).decode(),
            "blob": base64.b64encode(nonce + ciphertext).decode(),
        })

    out = REPO_ROOT / "shared" / "vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {"vectors": vectors, "encrypt_vectors": encrypt_vectors}
    out.write_text(json.dumps(payload, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors + {len(encrypt_vectors)} encrypt vectors -> {out}")


if __name__ == "__main__":
    main()
