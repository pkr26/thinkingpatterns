"""Key schedule: separation, sensitivity, RFC vectors, pinned production vectors."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from app.security import kdf

VECTORS_PATH = Path(__file__).resolve().parents[2] / "shared" / "vectors.json"


def test_deterministic():
    a = kdf.derive_master_key("password", b"0123456789abcdef", 100)
    b = kdf.derive_master_key("password", b"0123456789abcdef", 100)
    assert a == b


def test_password_sensitivity():
    base = kdf.derive_master_key("password", b"0123456789abcdef", 100)
    for variant in ("Password", "password ", "passwor"):
        assert kdf.derive_master_key(variant, b"0123456789abcdef", 100) != base


def test_salt_sensitivity():
    base = kdf.derive_master_key("password", b"0123456789abcdef", 100)
    assert kdf.derive_master_key("password", b"fedcba9876543210", 100) != base


def test_iteration_sensitivity():
    assert (kdf.derive_master_key("p", b"0123456789abcdef", 100)
            != kdf.derive_master_key("p", b"0123456789abcdef", 101))


def test_rejects_weak_parameters():
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"short", 100)  # salt < 8 bytes
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"0123456789abcdef", 0)
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"0123456789abcdef", -5)


def test_auth_and_data_keys_are_separated():
    master = kdf.derive_master_key("password", b"0123456789abcdef", 100)
    auth = kdf.derive_auth_key(master)
    data = kdf.derive_data_key(master)
    assert auth != data
    assert auth != master
    assert data != master
    assert len(auth) == len(data) == 32


def test_hkdf_rfc5869_test_case_1():
    ikm = b"\x0b" * 22
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    okm = kdf.hkdf_sha256(ikm, salt, info, 42)
    assert okm == bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_hkdf_rfc5869_test_case_3_empty_salt_and_info():
    ikm = b"\x0b" * 22
    okm = kdf.hkdf_sha256(ikm, None, b"", 42)
    assert okm == bytes.fromhex(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_hkdf_length_bounds():
    with pytest.raises(ValueError):
        kdf.hkdf_sha256(b"k", None, b"i", 0)
    with pytest.raises(ValueError):
        kdf.hkdf_sha256(b"k", None, b"i", 255 * 32 + 1)


def test_production_iterations_constant():
    assert kdf.KDF_ITERATIONS == 600_000


@pytest.mark.slow
@pytest.mark.skipif(not VECTORS_PATH.exists(), reason="vectors not generated yet")
def test_pinned_production_vectors():
    """Both vectors must reproduce byte-for-byte at 600k iterations."""
    data = json.loads(VECTORS_PATH.read_text())
    assert len(data["vectors"]) >= 2
    for vector in data["vectors"]:
        salt = base64.b64decode(vector["salt"])
        master = kdf.derive_master_key(vector["password"], salt, vector["iterations"])
        assert base64.b64encode(master).decode() == vector["master_key"]
        assert base64.b64encode(kdf.derive_auth_key(master)).decode() == vector["auth_key"]
        assert base64.b64encode(kdf.derive_data_key(master)).decode() == vector["data_key"]
