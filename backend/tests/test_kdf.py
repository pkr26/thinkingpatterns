"""Key schedule: separation, sensitivity, RFC vectors, pinned production vectors."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from app.security import kdf

VECTORS_PATH = Path(__file__).resolve().parents[2] / "shared" / "vectors.json"


def fast_master(password: str, salt: bytes, iterations: int) -> bytes:
    """Test-side fast derivation. The shipping library floors iterations at
    kdf.MIN_ITERATIONS (2026-09-16 remediation, finding A4) — the floor
    protects production callers, and parameter-semantics tests legitimately
    want cheap counts, so they derive with hashlib directly."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations
    )


def test_deterministic():
    a = fast_master("password", b"0123456789abcdef", 100)
    b = fast_master("password", b"0123456789abcdef", 100)
    assert a == b


def test_password_sensitivity():
    base = fast_master("password", b"0123456789abcdef", 100)
    for variant in ("Password", "password ", "passwor"):
        assert fast_master(variant, b"0123456789abcdef", 100) != base


def test_salt_sensitivity():
    base = fast_master("password", b"0123456789abcdef", 100)
    assert fast_master("password", b"fedcba9876543210", 100) != base


def test_iteration_sensitivity():
    assert (fast_master("p", b"0123456789abcdef", 100)
            != fast_master("p", b"0123456789abcdef", 101))


def test_rejects_weak_parameters():
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"short", kdf.MIN_ITERATIONS)  # salt < 8 bytes
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"0123456789abcdef", 0)
    with pytest.raises(ValueError):
        kdf.derive_master_key("p", b"0123456789abcdef", -5)


def test_iteration_floor_is_enforced():
    """2026-09-16 remediation (red-team finding A4): the library refuses to
    derive below MIN_ITERATIONS so no honest caller can silently downgrade
    the 600k contract; the boundary itself is exactly MIN_ITERATIONS."""
    with pytest.raises(ValueError, match="iterations must be at least"):
        kdf.derive_master_key("p", b"0123456789abcdef", kdf.MIN_ITERATIONS - 1)
    # Exactly at the floor is valid (and equals a raw PBKDF2 of the same cost).
    assert kdf.derive_master_key("p", b"0123456789abcdef", kdf.MIN_ITERATIONS) == fast_master(
        "p", b"0123456789abcdef", kdf.MIN_ITERATIONS
    )
    # The default is still the full production contract.
    assert kdf.KDF_ITERATIONS == 600_000
    assert kdf.MIN_ITERATIONS >= 100_000


def test_auth_and_data_keys_are_separated():
    master = fast_master("password", b"0123456789abcdef", 100)
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
