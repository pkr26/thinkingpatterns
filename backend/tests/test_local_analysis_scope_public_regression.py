"""Public local-analysis date bounds and their effect on stored state."""

import base64
from datetime import date

import pytest
from sqlalchemy import select

from app.models import Insight
from app.security import crypto
from tests.helpers import ClientEmulator


@pytest.mark.asyncio
async def test_local_analysis_rejects_out_of_range_scope_without_writing(client, app):
    owner = ClientEmulator("local-scope-boundary", "local-scope-boundary-password")
    await owner.register(client)

    def encrypted_blob(kind):
        ciphertext = crypto.encrypt(
            owner.data_key, b"{}", crypto.build_aad("insights", owner.user_id, kind)
        )
        return base64.b64encode(ciphertext).decode("ascii")

    payload = {
        "base_state_seq": 0,
        "state_blob": encrypted_blob("brain"),
        "patterns_blob": encrypted_blob("patterns"),
    }
    today = date.today().isoformat()
    for count in (0, 367):
        response = await client.post(
            "/api/insights/local-recompute",
            headers=owner.headers,
            json={**payload, "analysis_dates": [today] * count},
        )
        assert response.status_code == 422, response.text

    async with app.state.sessionmaker() as session:
        stored = (
            await session.scalars(select(Insight).where(Insight.user_id == owner.user_id))
        ).all()
    assert stored == []

    accepted = await client.post(
        "/api/insights/local-recompute",
        headers=owner.headers,
        json={**payload, "analysis_dates": [today] * 366},
    )
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["state_seq"] == 1
