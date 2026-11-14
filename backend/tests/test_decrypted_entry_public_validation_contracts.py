"""Authenticated entry plaintext reaches the actual public recompute validator."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.security import crypto
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
@pytest.mark.parametrize(
    "values",
    [
        {"created_at": "two-days-after-outer"},
        {"sentiment": float("inf")},
        {"sentiment": True},
        {"energy": float("inf")},
        {"energy": True},
        {"sleep": 6},
        {"sleep": True},
        {"tags": list("abcdefghi")},
        {"tod": "midnight"},
        {"input_mode": "unsupported"},
        {"created_at": True},
        {"text": True},
        {"tags": [1]},
        {"transcript_lang": "english"},
        {"english_text": True},
    ],
)
async def test_actual_public_recompute_refuses_authenticated_malformed_channels(client, values):
    owner = ClientEmulator("native-refused-channel", "native-refused-channel-password")
    await owner.register(client)
    await owner.backdate_account(client, 5)
    today = datetime.now(timezone.utc).date()
    for index in range(3):
        day = today - timedelta(days=2 - index)
        rid = f"refused-channel-{index}"
        payload = {
            "v": 3,
            "text": "I enjoy an ordinary walk in the park.",
            "created_at": day.isoformat(),
            **(values if index == 0 else {}),
        }
        if payload["created_at"] == "two-days-after-outer":
            payload["created_at"] = (day + timedelta(days=2)).isoformat()
        blob = crypto.encrypt(
            owner.data_key,
            json.dumps(payload).encode(),
            crypto.entry_aad_v2(owner.user_id, rid, 1),
        )
        stored = await client.post(
            "/api/entries",
            headers=owner.headers,
            json={
                "client_entry_id": rid,
                "content_version": 1,
                "blob": base64.b64encode(blob).decode("ascii"),
                "entry_date": day.isoformat(),
            },
        )
        assert stored.status_code == 201, stored.text
    processing = await owner.open_processing_session(client)
    refused = await client.post(
        "/api/insights/recompute",
        headers={**owner.headers, "X-Processing-Token": processing},
    )
    assert refused.status_code == 400, refused.text
    assert refused.json() == {
        "detail": "entry payload malformed",
        "code": "entry_payload_malformed",
    }


@pytest.mark.asyncio
@pytest.mark.parametrize("tod", ["morning", "afternoon", "night"])
async def test_actual_public_recompute_accepts_native_declared_writing_window(client, tod):
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
