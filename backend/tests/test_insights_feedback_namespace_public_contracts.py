"""Accepted feedback extension fields cannot become the persisted brain state."""

import base64
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.security import crypto
from app.services import brain
from app.services.patterns import JournalEntry
from tests.helpers import ClientEmulator

TEXT = "I take a quiet walk through the park each evening."


def native_prior_state_extension(today):
    entries = [
        JournalEntry(text=TEXT, entry_date=today - timedelta(days=29 - index))
        for index in range(30)
    ]
    state = brain.fresh_state()
    for ago in range(15, 0, -1):
        as_of = today - timedelta(days=ago)
        state = brain.update(
            state, [entry for entry in entries if entry.entry_date <= as_of], as_of
        ).new_state
    extension = json.loads(brain.dump_state(state))
    assert extension["patterns"]
    # Unknown extension fields are admitted by the current public feedback
    # parser. The recognized queue is empty. These additional fields come
    # from a genuine native brain producer, not handwritten pattern records.
    extension.pop("muted")
    extension["feedback"] = []
    return extension


@pytest.mark.asyncio
async def test_public_feedback_extensions_do_not_preload_an_unrelated_brain_state(client):
    today = datetime.now(timezone.utc).date()
    payloads = [{"feedback": []}, native_prior_state_extension(today)]
    observations = []
    for index, payload in enumerate(payloads):
        owner = ClientEmulator(f"native-feedback-namespace-{index}", "native-feedback-password")
        await owner.register(client)
        await owner.backdate_account(client, 40)
        for entry_index in range(30):
            await owner.create_entry(
                client,
                TEXT,
                today - timedelta(days=29 - entry_index),
                client_entry_id=f"native-feedback-{entry_index}",
                content_version=1,
            )
        feedback = crypto.encrypt(
            owner.data_key,
            json.dumps(payload).encode(),
            crypto.build_aad("feedback", owner.user_id, today.isoformat()),
        )
        processing = await owner.open_processing_session(client)
        response = await client.post(
            "/api/insights/recompute",
            headers={**owner.headers, "X-Processing-Token": processing},
            json={"feedback_blob": base64.b64encode(feedback).decode("ascii")},
        )
        assert response.status_code == 200, response.text
        stats = (await owner.decrypt_insights(client))["stats"]
        assert stats["total_entries"] == 30
        observations.append(stats)
    # The same native corpus and empty recognized feedback queue must yield
    # the same public decrypted analysis, even with accepted extension keys.
    assert observations[0] == observations[1]
