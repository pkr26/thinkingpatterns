"""Fixed-nonce encrypt vectors: pin the client->server direction byte-for-byte.

The decrypt-only vectors in shared/vectors.json prove both platforms can read
Python-generated blobs, but mobile encrypt() uses a random nonce, so nothing
pinned what the client emits. The "encrypt_vectors" family fixes that: each
entry carries a FIXED nonce and the exact blob bytes, so both platforms'
encrypt() is checked against bytes the other platform independently decrypts.
AAD is stored as parts so every consumer goes through its own builder.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.security import crypto, kdf

VECTORS_PATH = Path(__file__).resolve().parents[2] / "shared" / "vectors.json"


def _encrypt_vectors() -> list[dict]:
    # Hard failure, never a silent skip: vectors.json is committed, so a
    # missing file means a broken checkout, not "not generated yet".
    assert VECTORS_PATH.exists(), (
        f"shared/vectors.json not found at {VECTORS_PATH} — it is committed; "
        "restore it (or regenerate with scripts/generate_vectors.py)"
    )
    data = json.loads(VECTORS_PATH.read_text())
    return data["encrypt_vectors"]


def _data_key(vector: dict) -> bytes:
    salt = base64.b64decode(vector["salt"])
    master = kdf.derive_master_key(vector["password"], salt, vector["iterations"])
    return kdf.derive_data_key(master)


@pytest.mark.slow
def test_fixed_nonce_encrypt_reproduces_blob_byte_for_byte():
    vectors = _encrypt_vectors()
    assert len(vectors) >= 2, "expected at least one ASCII and one non-ASCII case"
    for vector in vectors:
        aad = crypto.build_aad(*vector["aad_parts"]) if vector["aad_parts"] else None
        blob = crypto.encrypt_with_nonce(
            _data_key(vector),
            base64.b64decode(vector["plaintext"]),
            aad,
            base64.b64decode(vector["nonce"]),
        )
        assert base64.b64encode(blob).decode() == vector["blob"]


@pytest.mark.slow
def test_backend_decrypts_fixed_nonce_blob():
    """The same pinned blob bytes the mobile test reproduces must decrypt here."""
    for vector in _encrypt_vectors():
        aad = crypto.build_aad(*vector["aad_parts"]) if vector["aad_parts"] else None
        plaintext = crypto.decrypt(
            _data_key(vector), base64.b64decode(vector["blob"]), aad
        )
        assert base64.b64encode(plaintext).decode() == vector["plaintext"]


def test_encrypt_nonce_seam_rejects_wrong_size():
    """2026-09-16: the seam moved OUT of encrypt() into encrypt_with_nonce —
    production encrypt() has no nonce parameter at all (finding A5)."""
    key = crypto.generate_key()
    with pytest.raises(TypeError):
        crypto.encrypt(key, b"data", None, b"short")  # type: ignore[call-arg]
    with pytest.raises(crypto.CryptoError):
        crypto.encrypt_with_nonce(key, b"data", None, b"short")
    # Production behavior: fresh random nonce per call, always.
    assert crypto.encrypt(key, b"data") != crypto.encrypt(key, b"data")
