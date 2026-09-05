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


def main() -> None:
    vectors = []
    for case in CASES:
        salt = case["salt"]
        # Cross-check the two PBKDF2 implementations against each other.
        via_hashlib = kdf.derive_master_key(case["password"], salt, kdf.KDF_ITERATIONS)
        via_cryptography = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt, iterations=kdf.KDF_ITERATIONS
        ).derive(case["password"].encode("utf-8"))
        assert via_hashlib == via_cryptography, "PBKDF2 implementations disagree!"

        master = via_hashlib
        auth_key = kdf.derive_auth_key(master)
        data_key = kdf.derive_data_key(master)
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

    out = REPO_ROOT / "shared" / "vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"vectors": vectors}, indent=2) + "\n")
    print(f"wrote {len(vectors)} vectors -> {out}")


if __name__ == "__main__":
    main()
