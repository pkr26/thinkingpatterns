"""Controlled native partial-SQLite outage preserves malformed-input refusal."""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from tests.helpers import TherapistEmulator


@pytest.mark.asyncio
async def test_missing_pairing_header_refuses_before_unavailable_pairing_table(client, app):
    therapist = TherapistEmulator("owned-pairing-outage", "owned-pairing-password")
    await therapist.register(client)
    path = "/api/therapist/pairing/sas"
    params = {"patient_user_id": "b" * 32}
    healthy = await client.get(path, headers=therapist.headers, params=params)
    assert healthy.status_code == 404
    assert healthy.json()["code"] == "not_found"
    # This engine is the fresh owned in-memory test fixture. Only its pairing
    # table is removed; authenticated User/session storage remains available.
    assert app.state.engine.url.get_backend_name() == "sqlite"
    assert app.state.engine.url.database in (None, "", ":memory:")
    async with app.state.engine.begin() as connection:
        await connection.execute(text("DROP TABLE pairing_codes"))
    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://owned-fault") as observed:
        response = await observed.get(path, headers=therapist.headers, params=params)
    assert response.status_code == 404
    assert response.json()["code"] == "not_found"
