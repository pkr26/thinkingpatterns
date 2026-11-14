"""Public key-envelope migration accepts admitted legacy dated insight rows."""

import json
from datetime import datetime, timezone

import pytest

from app.models import Insight
from app.security import crypto, kdf
from app.services import brain
from tests.helpers import ClientEmulator, EnvelopeClientEmulator


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["patterns", "brain"])
async def test_v1_envelope_upgrade_authenticates_dated_legacy_insights(client, app, kind):
    owner = ClientEmulator("legacy-envelope-" + kind, "legacy-envelope-password")
    await owner.register(client)
    if kind == "brain":
        state = brain.fresh_state()
        state["state_seq"] = 1
        payload = brain.dump_state(state)
    else:
        payload = json.dumps(
            {"v": 2, "state_seq": 1, "stats": {"language": "en", "patterns": []}}
        ).encode()
    # _replace_insight explicitly admits legacy dated non-question rows.
    # Their date does not change the kind-specific insights AAD.
    blob = crypto.encrypt(
        owner.data_key, payload, crypto.build_aad("insights", owner.user_id, kind)
    )
    async with app.state.sessionmaker() as session:
        session.add(
            Insight(
                user_id=owner.user_id,
                kind=kind,
                for_date=datetime.now(timezone.utc).date(),
                blob=blob,
                state_seq=1,
            )
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
