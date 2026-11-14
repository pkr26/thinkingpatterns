"""Actual code-generator output for a declared native entropy-byte input."""

import pytest

from app.security import sharing, totp


@pytest.mark.parametrize(
    "operation, expected",
    [
        (sharing.generate_pairing_code, "Z2345678"),
        (totp.generate_backup_code, "Z23456789A"),
    ],
)
def test_rejection_sampling_keeps_the_last_complete_alphabet_block(
    monkeypatch, operation, expected
):
    # 239 is the last byte in eight complete blocks of the released
    # 30-symbol alphabet. 240 and 255 belong to its incomplete tail.
    # This supplies the entropy interface, not a claimed native RNG sample.
    entropy = bytes([239, 240, 255]) + bytes(range(30))
    monkeypatch.setattr(sharing.os, "urandom", lambda size: entropy[:size])
    assert operation() == expected
