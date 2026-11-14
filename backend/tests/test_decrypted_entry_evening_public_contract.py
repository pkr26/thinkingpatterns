"""Authenticated entry plaintext reaches the actual public recompute validator."""

from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from tests.helpers import ClientEmulator


@pytest.fixture
def settings():
    # A constructor-validated configurable three-day unlock keeps the
    # validation example small; the native analyzer and thresholds run.
    return Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        unlock_threshold_days=3,
        auth_rate_limit=100,
        processing_rate_limit=100,
    )


@pytest.mark.asyncio
async def test_actual_public_recompute_accepts_native_declared_evening_window(client):
    tod = "evening"
    owner = ClientEmulator("native-valid-window-" + tod, "native-valid-window-password")
    await owner.register(client)
    await owner.backdate_account(client, 5)
    today = datetime.now(timezone.utc).date()
    for index in range(3):
        await owner.create_entry(
            client,
            "I enjoy an ordinary walk in the park.",
            today - timedelta(days=2 - index),
            client_entry_id=f"valid-window-{index}",
            content_version=1,
            tod=tod,
        )
    computed = await owner.recompute(client)
    assert computed["phase"] == "insight"
    assert computed["analyzer"] == "brain"
    actual = await owner.decrypt_insights(client)
    assert actual["stats"]["total_entries"] == 3
