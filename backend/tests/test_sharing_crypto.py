"""Sharing crypto: the wrap construction and its cross-platform vectors.

shared/vectors.json pins wrap outputs from fixed test keys; these tests
hold the Python reference to those bytes AND to the negative space (wrong
AAD, wrong therapist, malformed keys) that vectors cannot express.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_public_key,
)

from app.security import crypto, sharing
from app.security.kdf import hkdf_sha256

VECTORS_PATH = Path(__file__).resolve().parents[2] / "shared" / "vectors.json"


def _keypair(scalar: int):
    priv = ec.derive_private_key(scalar, ec.SECP256R1())
    pub = base64.b64encode(
        priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode("ascii")
    pkcs8_b64 = base64.b64encode(
        priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    ).decode("ascii")
    return priv, pub, pkcs8_b64


class TestWrapVectors:
    def test_vectors_roundtrip_through_reference(self):
        vectors = json.loads(VECTORS_PATH.read_text())["wrap_vectors"]
        assert len(vectors) >= 3
        for v in vectors:
            t_priv = sharing.load_private_key_pkcs8(base64.b64decode(v["therapist_priv_pkcs8"]))
            unwrapped = sharing.unwrap_data_key(
                t_priv,
                v["ephemeral_pub_spki"],
                base64.b64decode(v["wrapped"]),
                v["user_id"],
                v["therapist_id"],
                therapist_pub_der=base64.b64decode(v["therapist_pub_spki"]),
            )
            assert unwrapped == base64.b64decode(v["data_key"])

    def test_wrap_with_fixed_ephemeral_reproduces_vector_bytes(self):
        vectors = json.loads(VECTORS_PATH.read_text())["wrap_vectors"]
        v = vectors[0]
        e_priv = sharing.load_private_key_pkcs8(base64.b64decode(v["ephemeral_priv_pkcs8"]))
        # Deriving the fixed-nonce pin from the vector's own inputs must
        # reproduce the pinned blob byte-for-byte.
        shared = e_priv.exchange(
            ec.ECDH(), load_der_public_key(base64.b64decode(v["therapist_pub_spki"]))
        )
        kek = hkdf_sha256(
            shared,
            salt=base64.b64decode(v["ephemeral_pub_spki"])
            + base64.b64decode(v["therapist_pub_spki"]),
            info=sharing.WRAP_INFO,
            length=32,
        )
        aad = crypto.build_aad(sharing.WRAP_CONTEXT, v["user_id"], v["therapist_id"])
        blob = crypto.encrypt_with_nonce(
            kek, base64.b64decode(v["data_key"]), aad, base64.b64decode(v["nonce"])
        )
        assert base64.b64encode(blob).decode("ascii") == v["wrapped"]


class TestWrapConstruction:
    def test_wrap_unwrap_roundtrip_random_keys(self):
        t_priv, t_pub, _ = _keypair(0x1234)
        data_key = os.urandom(32)
        eph_b64, wrapped_b64 = sharing.wrap_data_key(data_key, t_pub, "u1", "t1")
        out = sharing.unwrap_data_key(t_priv, eph_b64, base64.b64decode(wrapped_b64), "u1", "t1")
        assert out == data_key

    def test_wrap_is_non_deterministic(self):
        _, t_pub, _ = _keypair(0x1234)
        data_key = os.urandom(32)
        a = sharing.wrap_data_key(data_key, t_pub, "u1", "t1")
        b = sharing.wrap_data_key(data_key, t_pub, "u1", "t1")
        assert a[0] != b[0] and a[1] != b[1]

    def test_wrong_patient_aad_fails(self):
        t_priv, t_pub, _ = _keypair(0x2234)
        data_key = os.urandom(32)
        eph_b64, wrapped_b64 = sharing.wrap_data_key(data_key, t_pub, "u1", "t1")
        with pytest.raises(crypto.TamperError):
            sharing.unwrap_data_key(
                t_priv, eph_b64, base64.b64decode(wrapped_b64), "OTHER-USER", "t1"
            )

    def test_wrong_therapist_aad_fails(self):
        # A wrap cannot be relocated to another therapist's consent row.
        t_priv, t_pub, _ = _keypair(0x3234)
        data_key = os.urandom(32)
        eph_b64, wrapped_b64 = sharing.wrap_data_key(data_key, t_pub, "u1", "t1")
        with pytest.raises(crypto.TamperError):
            sharing.unwrap_data_key(t_priv, eph_b64, base64.b64decode(wrapped_b64), "u1", "t2")

    def test_wrap_for_therapist_a_cannot_unwrap_as_therapist_b(self):
        # The KEK salt pins BOTH public keys: even the same patient data key
        # wrapped for A is not decryptable via B's private key (different
        # ECDH secret AND different salt).
        a_priv, a_pub, _ = _keypair(0x4234)
        b_priv, b_pub, _ = _keypair(0x5234)
        data_key = os.urandom(32)
        eph_b64, wrapped_b64 = sharing.wrap_data_key(data_key, a_pub, "u1", "t-a")
        with pytest.raises(crypto.TamperError):
            sharing.unwrap_data_key(b_priv, eph_b64, base64.b64decode(wrapped_b64), "u1", "t-a")

    def test_wrong_data_key_size_rejected(self):
        _, t_pub, _ = _keypair(0x6234)
        with pytest.raises(sharing.SharingError):
            sharing.wrap_data_key(b"short", t_pub, "u1", "t1")


class TestKeyValidation:
    def test_valid_public_key_accepted(self):
        _, t_pub, _ = _keypair(0x7234)
        der = sharing.validate_public_key_b64(t_pub)
        assert len(der) == sharing.SPKI_P256_DER_BYTES

    def test_not_base64_rejected(self):
        with pytest.raises(sharing.SharingError):
            sharing.validate_public_key_b64("!!not-base64!!")

    def test_wrong_curve_rejected(self):
        priv = ec.generate_private_key(ec.SECP384R1())
        der = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(sharing.SharingError):
            sharing.validate_public_key_b64(base64.b64encode(der).decode("ascii"))

    def test_non_ec_key_rejected(self):
        # An RSA SPKI parses as a public key but is not elliptic-curve.
        from cryptography.hazmat.primitives.asymmetric import rsa

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        der = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        with pytest.raises(sharing.SharingError):
            sharing.validate_public_key_b64(base64.b64encode(der).decode("ascii"))

    def test_garbage_der_rejected(self):
        with pytest.raises(sharing.SharingError):
            sharing.validate_public_key_b64(base64.b64encode(b"\x30\x03\x02\x01\x05").decode())

    def test_private_key_pkcs8_roundtrip_and_rejection(self):
        priv, _, pkcs8_b64 = _keypair(0x8234)
        loaded = sharing.load_private_key_pkcs8(base64.b64decode(pkcs8_b64))
        assert loaded.curve.name == "secp256r1"
        with pytest.raises(sharing.SharingError):
            sharing.load_private_key_pkcs8(b"not a key")
        # A PKCS8 RSA key parses but is not P-256.
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_der = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
        )
        with pytest.raises(sharing.SharingError):
            sharing.load_private_key_pkcs8(rsa_der)


class TestPairingCodes:
    def test_generate_format(self):
        for _ in range(20):
            code = sharing.generate_pairing_code()
            assert len(code) == sharing.PAIRING_CODE_CHARS
            assert all(c in sharing.PAIRING_ALPHABET for c in code)

    def test_digest_deterministic_and_secret_dependent(self):
        assert (
            sharing.pairing_code_digest("AB2C4D6F", "s1")
            == sharing.pairing_code_digest("ab2c4d6f", "s1")  # case-insensitive
            == sharing.pairing_code_digest("  ab2c4d6f  ", "s1")
        )
        assert sharing.pairing_code_digest("AB2C4D6F", "s1") != sharing.pairing_code_digest(
            "AB2C4D6F", "s2"
        )
        assert sharing.pairing_code_digest("AB2C4D6F", "s1") != sharing.pairing_code_digest(
            "AB2C4D6G", "s1"
        )

    def test_normalize(self):
        assert sharing.normalize_pairing_code(" ab2c ") == "AB2C"

    def test_non_ascii_or_invalid_code_is_a_safe_non_match(self):
        # The public endpoints deliberately flatten malformed pairing codes
        # to 404. Digest derivation must therefore never throw UnicodeEncodeError
        # for a direct caller either.
        assert sharing.normalize_pairing_code("\u00e9") == ""
        assert sharing.normalize_pairing_code("\u00df" * 4) == ""
        assert sharing.normalize_pairing_code("\u00a0AB2C4D6F") == ""
        assert sharing.normalize_pairing_code("AB2C-4D6") == ""
        assert sharing.pairing_code_digest("\u00e9", "s1") == sharing.pairing_code_digest("", "s1")
