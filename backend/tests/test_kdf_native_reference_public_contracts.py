"""Actual reference-library key bytes at its documented supported boundaries."""

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from app.security.kdf import derive_master_key


@pytest.mark.parametrize(
    ("password", "requested_iterations", "reference_iterations"),
    [("雪", None, 600_000), (b"password", 100_000, 100_000)],
)
def test_native_master_key_matches_reference_at_supported_boundaries(
    password, requested_iterations, reference_iterations
):
    salt = b"salt1234"
    password_bytes = password.encode("utf-8") if isinstance(password, str) else password
    expected = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=reference_iterations
    ).derive(password_bytes)
    actual = (
        derive_master_key(password, salt)
        if requested_iterations is None
        else derive_master_key(password, salt, requested_iterations)
    )
    assert actual == expected
