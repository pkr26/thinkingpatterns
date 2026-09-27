"""Envelope encryption: roundtrip, tamper detection, AAD binding, zeroization."""

from __future__ import annotations

import base64

import pytest

from app.security import crypto
from app.security.crypto import (
    CryptoError,
    SecureBuffer,
    TamperError,
    build_aad,
    decrypt,
    encrypt,
    generate_key,
    KEY_SIZE,
    MIN_BLOB_SIZE,
    NONCE_SIZE,
)


def test_roundtrip_with_and_without_aad():
    key = generate_key()
    aad = build_aad("entry", "user1", "entry-1")
    for plaintext in (b"", b"hello mindpattern", bytes(1024)):
        for aa in (None, aad):
            blob = encrypt(key, plaintext, aa)
            assert decrypt(key, blob, aa) == plaintext


def test_unique_nonce_per_encryption():
    key = generate_key()
    blobs = {encrypt(key, b"same plaintext") for _ in range(20)}
    assert len(blobs) == 20, "nonce reuse would collapse ciphertexts"


def test_ciphertext_hides_plaintext():
    key = generate_key()
    secret = b"deadline dread on sunday"
    blob = encrypt(key, secret)
    assert secret not in blob


def test_bitflip_in_ciphertext_detected():
    key = generate_key()
    blob = bytearray(encrypt(key, b"tamper me"))
    blob[-1] ^= 0x01  # flip one bit inside the GCM tag
    with pytest.raises(TamperError):
        decrypt(key, bytes(blob))


def test_bitflip_in_nonce_detected():
    key = generate_key()
    blob = bytearray(encrypt(key, b"tamper me"))
    blob[0] ^= 0x80
    with pytest.raises(TamperError):
        decrypt(key, bytes(blob))


def test_wrong_key_rejected():
    blob = encrypt(generate_key(), b"secret")
    with pytest.raises(TamperError):
        decrypt(generate_key(), blob)


def test_aad_swap_rejected():
    key = generate_key()
    blob = encrypt(key, b"secret", build_aad("entry", "user1", "e1"))
    with pytest.raises(TamperError):
        decrypt(key, blob, build_aad("entry", "user2", "e1"))  # moved to another user
    with pytest.raises(TamperError):
        decrypt(key, blob, build_aad("entry", "user1", "e2"))  # moved to another entry
    with pytest.raises(TamperError):
        decrypt(key, blob, None)  # AAD stripped


def test_truncated_blob_rejected():
    key = generate_key()
    blob = encrypt(key, b"x" * 100)
    for cut in (0, 1, MIN_BLOB_SIZE - 1):
        with pytest.raises(TamperError):
            decrypt(key, blob[:cut])


def test_wrong_key_size_rejected():
    with pytest.raises(CryptoError):
        encrypt(b"short", b"data")
    with pytest.raises(CryptoError):
        encrypt(b"x" * (KEY_SIZE + 1), b"data")
    with pytest.raises(CryptoError):
        decrypt(b"y" * 16, b"z" * 64)


def test_blob_layout_nonce_prefix():
    key = generate_key()
    blob = encrypt(key, b"payload")
    assert len(blob) == NONCE_SIZE + len(b"payload") + 16


def test_build_aad_canonical_and_unambiguous():
    assert build_aad("a", "b") == build_aad("a", "b")
    assert build_aad("a", "b") != build_aad("ab", "")
    assert build_aad("a", "b") == b'["a","b"]'


def test_secure_buffer_zeroize():
    secret = b"sensitive plaintext"
    buf = SecureBuffer(secret)
    assert len(buf) == len(secret)
    assert not buf.is_zeroized()
    buf.zeroize()
    assert buf.is_zeroized()
    assert all(b == 0 for b in buf.data)


def test_generate_key_shape():
    keys = {generate_key() for _ in range(10)}
    assert len(keys) == 10 and all(len(k) == KEY_SIZE for k in keys)


def test_module_constants_stable():
    # These constants define the wire format; changing them breaks old blobs.
    assert (NONCE_SIZE, KEY_SIZE, MIN_BLOB_SIZE) == (12, 32, 28)


def test_encrypt_with_nonce_absent_from_production_paths():
    """L-1 (2026-09-20): crypto.encrypt()'s docstring promises that
    encrypt_with_nonce — the fixed-nonce seam — is "asserted absent from
    [production paths] by tests". This is that test: a source scan over the
    whole application tree. The only legal reference outside this test file
    is the definition module itself (app/security/crypto.py, whose internal
    delegation from encrypt() IS the seam). Any other app/ module calling
    it would put a caller-chosen nonce into a request path — precisely the
    nonce-reuse hazard the random-nonce contract exists to prevent: a
    repeated nonce under the same AES-GCM key leaks plaintext equality and
    breaks authentication outright.
    """
    from pathlib import Path

    app_root = Path(crypto.__file__).resolve().parents[1]
    # 2026-09-26: app/security/envelope.py joined the allowlist. It is the
    # v2 key-envelope REFERENCE implementation (vector generation only —
    # the same standing security/sharing.py's wrap functions have): its
    # wrap_data_key takes a REQUIRED explicit nonce because deterministic
    # output is the point for pinned vectors. No request path calls it —
    # pinned below by scanning the API layer for BOTH seams.
    definition_module = (app_root / "security" / "crypto.py").resolve()
    envelope_module = (app_root / "security" / "envelope.py").resolve()
    offenders = []
    for source in sorted(app_root.rglob("*.py")):
        if source.resolve() in (definition_module, envelope_module):
            continue
        text = source.read_text(encoding="utf-8")
        if "encrypt_with_nonce(" in text:
            offenders.append(str(source))
    assert not offenders, (
        "encrypt_with_nonce( called outside app/security/{crypto,envelope}.py "
        "(the definition module and the vector-only envelope reference) — a "
        "fixed-nonce seam must never be reachable from a request path: " + str(offenders)
    )
    # The stronger half of the 2026-09-26 update: neither fixed-nonce seam
    # may appear ANYWHERE in the request-path layer (the API layer imports
    # the envelope module only for its size constant).
    api_offenders = []
    for source in sorted((app_root / "api").rglob("*.py")):
        text = source.read_text(encoding="utf-8")
        for seam in ("encrypt_with_nonce(", "envelope.wrap_data_key("):
            if seam in text:
                api_offenders.append(f"{seam} in {source}")
    for extra in (app_root / "main.py", app_root / "middleware.py"):
        text = extra.read_text(encoding="utf-8")
        for seam in ("encrypt_with_nonce(", "envelope.wrap_data_key("):
            if seam in text:
                api_offenders.append(f"{seam} in {extra}")
    assert not api_offenders, "fixed-nonce encryption reachable from the API layer: " + str(
        api_offenders
    )
