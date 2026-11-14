"""Real opaque-ciphertext limits through authenticated ASGI and owned SQLite."""

import base64

import pytest
from sqlalchemy.engine import make_url

from app.config import Settings
from app.security import crypto
from tests.helpers import ClientEmulator


@pytest.fixture
def settings():
    # Construct the actual admitted minimum, so __post_init__ validates it.
    return Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        max_user_blob_bytes=1024,
        processing_rate_limit=100,
        auth_rate_limit=100,
    )


@pytest.mark.asyncio
async def test_local_insights_preserve_native_ciphertext_floor_and_configured_ceiling(
    client, app, settings
):
    assert settings.max_user_blob_bytes == 1024
    assert make_url(settings.database_url).database in (None, "", ":memory:")
    assert app.state.engine.dialect.name == "sqlite"
    owner = ClientEmulator("native-local-bounds", "native-local-bounds-password")
    await owner.register(client)

    def blob(kind, size):
        # Native AES-GCM emits 12-byte nonce + plaintext + 16-byte tag.
        # Local analysis is opaque; the server does not interpret its JSON.
        plain = b"" if size == 28 else b"{}" + b" " * (size - 30)
        ciphertext = crypto.encrypt(
            owner.data_key, plain, crypto.build_aad("insights", owner.user_id, kind)
        )
        assert len(ciphertext) == size
        return base64.b64encode(ciphertext).decode("ascii")

    sequence = 0
    for size in (28, 1024):
        body = {
            "base_state_seq": sequence,
            "state_blob": blob("brain", size),
            "patterns_blob": blob("patterns", size),
            "analysis_dates": ["2026-10-22"],
        }
        stored = await client.post(
            "/api/insights/local-recompute", headers=owner.headers, json=body
        )
        assert stored.status_code == 200, stored.text
        sequence += 1
        assert stored.json()["state_seq"] == sequence

    valid = {
        "base_state_seq": sequence,
        "state_blob": blob("brain", 28),
        "patterns_blob": blob("patterns", 28),
        "analysis_dates": ["2026-10-22"],
    }
    for field, kind in (("state_blob", "brain"), ("patterns_blob", "patterns")):
        for size in (27, 1025):
            value = (
                base64.b64encode(base64.b64decode(blob(kind, 28))[:-1]).decode("ascii")
                if size == 27
                else blob(kind, size)
            )
            refused = await client.post(
                "/api/insights/local-recompute", headers=owner.headers, json={**valid, field: value}
            )
            assert refused.status_code == 422, refused.text
            assert refused.json() == {
                "detail": "blobs must be within the storage size bounds",
                "code": "validation_error",
            }
        malformed = await client.post(
            "/api/insights/local-recompute",
            headers=owner.headers,
            json={**valid, field: "!!!!" + valid[field]},
        )
        assert malformed.status_code == 422, malformed.text
        assert malformed.json() == {
            "detail": "state_blob and patterns_blob must be base64",
            "code": "validation_error",
        }
