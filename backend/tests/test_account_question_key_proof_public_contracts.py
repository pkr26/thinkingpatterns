"""Current dated-question AAD through the real public key-envelope upgrade."""

import json
from datetime import datetime, timezone

import pytest

from app.models import Insight
from app.security import crypto, kdf
from app.services import questions
from tests.helpers import ClientEmulator, EnvelopeClientEmulator


@pytest.mark.asyncio
async def test_v1_envelope_upgrade_authenticates_the_current_dated_question(client, app):
    owner = ClientEmulator("native-question-envelope", "native-question-envelope-password")
    await owner.register(client)
    day = datetime.now(timezone.utc).date()
    payload = json.dumps(
        {
            "for_date": day.isoformat(),
            "question": questions.question_for_today(owner.user_id, [], day, language="en"),
            "pattern_pid": None,
        }
    ).encode()
    blob = crypto.encrypt(
        owner.data_key, payload, crypto.build_aad("question", owner.user_id, day.isoformat())
    )
    # This is the actual current question-writer's dated row and AAD shape.
    # No entry ciphertext or other insight kind masks its key-proof branch.
    async with app.state.sessionmaker() as session:
        session.add(
            Insight(user_id=owner.user_id, kind="question", for_date=day, blob=blob, state_seq=1)
        )
        await session.commit()
    migration = EnvelopeClientEmulator.__new__(EnvelopeClientEmulator)
    migration.__dict__.update(owner.__dict__)
    migration.kdf_params = dict(kdf.KDF_PARAMS_DEFAULT)
    wrong_key = bytes([owner.data_key[0] ^ 1]) + owner.data_key[1:]
    assert await migration.upgrade_to_v2(client, key=wrong_key) == 403
    assert (await owner.fetch_envelope(client))["key_scheme"] == "v1"
    assert await migration.upgrade_to_v2(client, key=owner.data_key) == 204
    envelope = await owner.fetch_envelope(client)
    assert envelope["key_scheme"] == "v2"
    assert (
        migration.unwrap(envelope["wrapped_data_key"], owner.password, owner.salt) == owner.data_key
    )
