"""V12: a therapist page refuses ciphertext that grew after metadata sizing."""

from __future__ import annotations

import base64
import json
from datetime import date

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Measure
from app.security import crypto
from tests.helpers import ClientEmulator, TherapistEmulator


async def test_therapist_measure_fetch_refuses_real_blob_growth_and_larger_retry_succeeds(
    client, app, monkeypatch
):
    patient = ClientEmulator("measure-growth-patient", "synthetic-patient-passphrase")
    therapist = TherapistEmulator("measure-growth-therapist", "synthetic-therapist-passphrase")
    await patient.register(client)
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    grant = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert grant["status"] == 201
    identifier = "measure-byte-growth"
    aad = crypto.build_aad("measure", patient.user_id, identifier)
    original_blob = crypto.encrypt(patient.data_key, b'{"v":1,"measure":"phq9","score":4}', aad)
    grown_blob = crypto.encrypt(
        patient.data_key,
        json.dumps({"v": 1, "measure": "phq9", "score": 4, "note": "x" * 1024}).encode(),
        aad,
    )
    created = await client.post(
        "/api/measures",
        headers=patient.headers,
        json={
            "client_measure_id": identifier,
            "measure_date": date.today().isoformat(),
            "blob": base64.b64encode(original_blob).decode(),
        },
    )
    assert created.status_code == 201, created.text
    route = f"/api/therapist/patients/{patient.user_id}/measures"
    parameters = {"page_bytes": len(original_blob), "expected_revision": "1"}
    stable = await client.get(route, headers=therapist.headers, params=parameters)
    assert stable.status_code == 200, stable.text
    assert stable.json()[0]["blob"] == base64.b64encode(original_blob).decode()

    original_execute = AsyncSession.execute
    grew = False

    async def grow_before_real_blob_query(session, statement, *args, **kwargs):
        nonlocal grew
        columns = getattr(statement, "column_descriptions", [])
        if (
            not grew
            and len(columns) == 1
            and columns[0].get("entity") is Measure
            and columns[0].get("name") == "Measure"
        ):
            grew = True
            # A storage writer outside the application revision discipline can
            # change ciphertext between sizing and fetch. Commit the read/audit
            # transaction before that real write (also works with SQLite's
            # shared test connection); do not fabricate metadata or ORM rows.
            await session.commit()
            async with app.state.sessionmaker() as writer:
                await original_execute(
                    writer,
                    update(Measure)
                    .where(
                        Measure.user_id == patient.user_id, Measure.client_measure_id == identifier
                    )
                    .values(blob=grown_blob),
                )
                await writer.commit()
        return await original_execute(session, statement, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(AsyncSession, "execute", grow_before_real_blob_query)
        changed = await client.get(route, headers=therapist.headers, params=parameters)
    assert grew, "the write must occur between metadata sizing and actual blob fetch"
    assert changed.status_code == 409, changed.text
    assert changed.json()["code"] == "collection_changed"
    assert changed.headers["X-Measures-Revision"] == "1"
    assert "blob" not in changed.text

    retry = await client.get(
        route,
        headers=therapist.headers,
        params={"page_bytes": len(grown_blob), "expected_revision": "1"},
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()[0]["blob"] == base64.b64encode(grown_blob).decode()
    assert crypto.decrypt(patient.data_key, base64.b64decode(retry.json()[0]["blob"]), aad)
