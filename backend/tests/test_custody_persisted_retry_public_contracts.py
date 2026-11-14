"""Public exact retry consumes an actual current-producer persisted receipt."""

import json
import sqlite3
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_app

FIXTURE = Path(__file__).with_name("fixtures") / "custody_current_public_retry_source069"


@pytest.mark.asyncio
async def test_public_custody_exact_retry_survives_restart_with_a_current_persisted_receipt(
    settings, tmp_path
):
    # Both files come from the genuine public source069 registration/MFA,
    # custody204 and exact retry204 flow, exported as a complete native SQLite
    # dump. No test computes or supplies an expected private digest.
    fixture = json.loads((FIXTURE / "current-public-custody-retry.json").read_text())
    database = tmp_path / "owned-current-custody.sqlite"
    with sqlite3.connect(database) as native:
        native.executescript((FIXTURE / "current-public-custody-retry.sql").read_text())
        assert native.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    settings.database_url = "sqlite+aiosqlite:///" + str(database)
    settings.token_secret = fixture["token_secret"]
    settings.scrypt_n = fixture["scrypt_n"]
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        async with AsyncClient(
            transport=ASGITransport(app=application), base_url="http://testserver"
        ) as client:
            login = await client.post(
                "/api/auth/login",
                json={
                    "username": fixture["username"],
                    "verifier": fixture["verifier"],
                    "totp_code": fixture["totp_backup_code"],
                },
            )
            assert login.status_code == 200, login.text
            assert login.json()["user_id"] == fixture["expected_public_user_id"]
            headers = {"Authorization": "Bearer " + login.json()["token"]}
            retry = await client.put(
                "/api/therapist/custody", headers=headers, json=fixture["custody_request"]
            )
            assert retry.status_code == 204, retry.text
            current = await client.get("/api/therapist/me", headers=headers)
            assert current.status_code == 200, current.text
            assert current.json()["custody_version"] == fixture["public_custody_version"]
            assert current.json()["notes_keyring_blob"] == fixture["public_keyring"]
