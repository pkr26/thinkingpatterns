"""Native authenticated entry channels keep their public recompute meanings."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.security import crypto
from tests.helpers import ClientEmulator


@pytest.fixture
def settings():
    return Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        unlock_threshold_days=3,
        auth_rate_limit=100,
        processing_rate_limit=100,
    )


def _text(word):
    # Actual public text, with nine unknown Latin tokens. No private language
    # or sentiment function output is replaced. This is a declared input
    # reference, with no claim about an external transcription producer.
    return " ".join([word] + ["qzxunknown"] * 9)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    [
        "structured-low",
        "structured-high",
        "date-tolerance",
        "foreign-translation",
        "native-en",
        "native-es",
        "no-detected-language",
        "missing-optional-channels",
        "blank-translation",
    ],
)
async def test_native_authenticated_channels_keep_returned_analysis(client, case):
    owner = ClientEmulator("native-channel-" + case, "native-channel-password")
    await owner.register(client)
    await owner.backdate_account(client, 5)
    today = datetime.now(timezone.utc).date()
    values = {}
    original = _text("adorable")
    expected_language = "en"
    expected_sign = 1
    if case.startswith("structured"):
        values = {
            "sentiment": 0.25,
            "energy": 0.5,
            "sleep": 1 if case == "structured-low" else 5,
            "tags": [f"native-tag-{i}" for i in range(8)],
            "input_mode": "typed" if case == "structured-low" else "voice",
        }
        if case == "structured-high":
            values["tod"] = "night"
    elif case == "foreign-translation":
        original = "bonjour " + " ".join(["qzxunknown"] * 9)
        values = {"transcript_lang": "fr", "english_text": _text("adorable")}
    elif case == "native-en":
        values = {"transcript_lang": "en", "english_text": _text("bad")}
    elif case == "native-es":
        original = _text("abatida")
        values = {"transcript_lang": "es", "english_text": _text("adorable")}
        expected_language = "es"
        expected_sign = -1
    elif case == "no-detected-language":
        original = _text("bad")
        values = {"english_text": _text("adorable")}
        expected_sign = -1
    elif case == "blank-translation":
        values = {"transcript_lang": "fr", "english_text": " "}

    for index in range(3):
        day = today - timedelta(days=2 - index)
        rid = f"native-channel-{index}"
        inner = day + timedelta(days=1) if case == "date-tolerance" else day
        payload = {"v": 3, "text": original, "created_at": inner.isoformat(), **values}
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
    computed = await owner.recompute(client)
    assert computed["phase"] == "insight"
    assert computed["analyzer"] == "brain"
    actual = await owner.decrypt_insights(client)
    stats = actual["stats"]
    assert stats["total_entries"] == 3
    assert stats["language"] == expected_language
    if case.startswith("structured"):
        assert stats["avg_sentiment"] == 0.25
        assert stats["mood_summary"]["explicit_mood"] == 3
    else:
        assert stats["avg_sentiment"] is not None
        assert stats["avg_sentiment"] * expected_sign > 0
