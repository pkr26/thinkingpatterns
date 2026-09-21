"""Regression tests for the 2026-09-21 audit Phase 2, crypto residuals
(C-5/C-6): the date-bound feedback-blob AAD (replay pin lives in
test_feedback_loop.py) and the dedicated decoy-salt secret."""

from __future__ import annotations

import pytest

from app.api.auth import decoy_salt
from app.config import Settings


def _dev_settings(**overrides) -> Settings:
    values = {
        "environment": "development",
        "token_secret": "x" * 40,
        "database_url": "sqlite+aiosqlite://",
    }
    values.update(overrides)
    return Settings(**values)


def test_decoy_secret_validation():
    with pytest.raises(RuntimeError, match="MINDPATTERN_DECOY_SECRET"):
        _dev_settings(decoy_secret="short")
    # Empty keeps the derive-from-token-secret default; a real secret boots.
    _dev_settings(decoy_secret="")
    _dev_settings(decoy_secret="d" * 40)


async def test_unknown_user_salt_follows_the_decoy_secret(client, settings, monkeypatch):
    # With a dedicated secret set, the decoy salt for an unknown username
    # must be derived from IT, not the token secret — rotating
    # MINDPATTERN_TOKEN_SECRET then leaves every decoy salt untouched.
    dedicated = "d" * 40
    monkeypatch.setattr(settings, "decoy_secret", dedicated)
    first = await client.post("/api/auth/salt", json={"username": "ghost-user-9"})
    assert first.status_code == 200
    assert first.json()["salt"] == decoy_salt("ghost-user-9", dedicated)

    # Rotate the token secret: the decoy answer is unchanged (C-6's point).
    monkeypatch.setattr(settings, "token_secret", "t" * 48)
    second = await client.post("/api/auth/salt", json={"username": "ghost-user-9"})
    assert second.json()["salt"] == first.json()["salt"]

    # Unset (empty) falls back to deriving from the token secret.
    monkeypatch.setattr(settings, "decoy_secret", "")
    monkeypatch.setattr(settings, "token_secret", "t" * 48)
    third = await client.post("/api/auth/salt", json={"username": "ghost-user-9"})
    assert third.json()["salt"] == decoy_salt("ghost-user-9", "t" * 48)
