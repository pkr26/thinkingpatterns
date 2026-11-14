"""Public recompute keeps every entry and native rekey preserves its dated question."""

from datetime import datetime, timedelta, timezone

import pytest

from tests.helpers import ClientEmulator


@pytest.mark.asyncio
async def test_public_first_recompute_and_rekey_preserve_the_complete_native_corpus(client):
    owner = ClientEmulator("native-public-question-rekey", "native-original-password")
    await owner.register(client)
    # Model a normal existing account using the shared owned-fixture helper;
    # every entry and the question itself are then written by the public API.
    await owner.backdate_account(client, 40)
    today = datetime.now(timezone.utc).date()
    for index in range(30):
        await owner.create_entry(
            client,
            "I take a quiet walk through the park each evening.",
            today - timedelta(days=29 - index),
            client_entry_id=f"native-rekey-{index}",
            content_version=1,
        )
    computed = await owner.recompute(client)
    assert computed["phase"] == "insight"
    assert computed["question_stored"] is True
    original = await owner.decrypt_insights(client)
    assert original["stats"]["total_entries"] == 30
    question = await owner.decrypt_question(client, today)
    old_key, old_verifier = owner.data_key, owner.auth_key_b64
    owner.derive_new_generation("native-next-password")
    old_processing = await owner.open_processing_session_for(client, old_key)
    new_processing = await owner.open_processing_session_for(client, owner.data_key)
    rotated = await client.post(
        "/api/processing/rekey",
        headers={
            **owner.headers,
            "X-Processing-Token": old_processing,
            "X-New-Processing-Token": new_processing,
            "X-Account-Verifier": old_verifier,
        },
        json=owner.rekey_payload(),
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["entries"] == 30
    assert rotated.json()["insights"] == 3
    await owner.login(client)
    current = await owner.decrypt_insights(client)
    assert current["state_seq"] == original["state_seq"] + 1
    assert current["stats"] == original["stats"]
    assert await owner.decrypt_question(client, today) == question
