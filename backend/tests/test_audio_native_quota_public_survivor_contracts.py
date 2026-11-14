"""Actual authenticated audio quota at an admitted Settings minimum."""

import base64
from datetime import datetime, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update

from app.api import audio
from app.config import Settings
from app.db import init_models
from app.main import create_app
from app.models import AudioAttachment
from app.security import crypto
from tests.helpers import ClientEmulator


@pytest.mark.asyncio
async def test_audio_quota_counts_native_ciphertext_and_only_live_owner_bytes(
    monkeypatch, tmp_path
):
    settings = Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        audio_enabled=True,
        audio_local_dir=str(tmp_path / "audio"),
        audio_max_user_bytes=1024,
        audio_max_duration_seconds=10,
        stt_url="https://stt.example.com/v1",
        stt_api_key="supplied-unused-provider-key",
        auth_rate_limit=100,
        audio_upload_rate_limit=100,
    )
    application = create_app(settings)
    now = datetime.now(timezone.utc)
    monkeypatch.setattr(audio, "utcnow", lambda: now)
    try:
        await init_models(application.state.engine)
        async with AsyncClient(
            transport=ASGITransport(app=application), base_url="http://test"
        ) as client:
            owner = ClientEmulator("native-audio-quota", "native-audio-quota-password")
            await owner.register(client)
            consent = await client.put(
                "/api/account/voice-consent",
                headers=owner.headers,
                json={"enabled": True, "verifier": owner.auth_key_b64},
            )
            assert consent.status_code == 200, consent.text
            for identifier in ("expired-slot", "live-slot"):
                await owner.create_entry(
                    client, "native quota entry", now.date(), client_entry_id=identifier
                )

            def body(identifier, size, duration=1):
                blob = crypto.encrypt(
                    owner.data_key,
                    b"x" * (size - 28),
                    crypto.build_aad("audio", owner.user_id, identifier, "1"),
                )
                assert len(blob) == size
                return {
                    "client_entry_id": identifier,
                    "blob": base64.b64encode(blob).decode("ascii"),
                    "mime": "audio/webm",
                    "duration_seconds": duration,
                }

            first = await client.post(
                "/api/v1/audio/attachments",
                headers=owner.headers,
                json=body("expired-slot", 1024),
            )
            assert first.status_code == 201, first.text
            assert first.json()["size_bytes"] == 1024
            async with application.state.sessionmaker() as session:
                await session.execute(
                    update(AudioAttachment)
                    .where(AudioAttachment.id == first.json()["attachment_id"])
                    .values(expires_at=now)
                )
                await session.commit()
            second = await client.post(
                "/api/v1/audio/attachments",
                headers=owner.headers,
                json=body("live-slot", 997),
            )
            assert second.status_code == 201, second.text
            assert second.json()["size_bytes"] == 997
            # The 27 free bytes cannot hold even the empty AES-GCM envelope.
            # An expired slot contributes no bytes that can be subtracted.
            full = await client.post(
                "/api/v1/audio/attachments",
                headers=owner.headers,
                json=body("expired-slot", 28),
            )
            assert full.status_code == 413, full.text
            assert full.json() == {
                "detail": "audio storage quota reached",
                "code": "audio_quota_exceeded",
            }
            duration = await client.post(
                "/api/v1/audio/attachments",
                headers=owner.headers,
                json=body("expired-slot", 28, duration=11),
            )
            assert duration.status_code == 422, duration.text
            assert duration.json() == {
                "detail": "recording duration exceeds the allowed maximum",
                "code": "validation_error",
            }
    finally:
        await application.state.engine.dispose()
