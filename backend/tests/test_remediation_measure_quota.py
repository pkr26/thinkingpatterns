"""Real quota/revision controls for the V1, V8 and V9 mutation survivors."""

from __future__ import annotations

import base64
import json
from datetime import date

from sqlalchemy import func, select, update

from app.api import measures as measures_api
from app.models import Measure, User
from app.security import crypto
from tests.helpers import ClientEmulator


def _body(emu, identifier):
    blob = crypto.encrypt(
        emu.data_key,
        json.dumps({"v": 1, "measure": "phq9", "score": 4}).encode(),
        crypto.build_aad("measure", emu.user_id, identifier),
    )
    return {
        "client_measure_id": identifier,
        "measure_date": date.today().isoformat(),
        "blob": base64.b64encode(blob).decode(),
    }


async def _stored_state(app, user_id):
    async with app.state.sessionmaker() as session:
        user = await session.get(User, user_id)
        count = await session.scalar(
            select(func.count()).select_from(Measure).where(Measure.user_id == user_id)
        )
        return count, user.measure_count, user.measures_revision


async def test_real_measure_quota_allows_last_slot_rejects_overflow_and_recovers_after_delete(
    client, app
):
    emu = ClientEmulator("measure-quota-owner", "synthetic-measure-passphrase")
    await emu.register(client)
    # Seed actual encrypted historical records and their maintained counter,
    # avoiding 1,999 HTTP setup calls. The production 2,000-row limit is not
    # monkeypatched. Every measured boundary transition below uses the API.
    async with app.state.sessionmaker() as session:
        for i in range(1999):
            identifier = f"historical-{i}"
            body = _body(emu, identifier)
            session.add(
                Measure(
                    user_id=emu.user_id,
                    client_measure_id=identifier,
                    measure_date=date.today(),
                    blob=base64.b64decode(body["blob"]),
                )
            )
        user = await session.get(User, emu.user_id)
        user.measure_count = user.measures_revision = 1999
        await session.commit()
    assert await _stored_state(app, emu.user_id) == (1999, 1999, 1999)

    last_body = _body(emu, "last-slot")
    accepted = await client.post("/api/measures", headers=emu.headers, json=last_body)
    assert accepted.status_code == 201, accepted.text
    assert accepted.json()["blob"] == last_body["blob"]
    assert await _stored_state(app, emu.user_id) == (2000, 2000, 2000)

    # A replay is still recognizable at quota; it must not charge another
    # slot or turn a completed offline write into an ambiguous quota error.
    duplicate = await client.post("/api/measures", headers=emu.headers, json=last_body)
    assert duplicate.status_code == 409
    assert duplicate.json()["code"] == "conflict"

    overflow = await client.post("/api/measures", headers=emu.headers, json=_body(emu, "overflow"))
    assert overflow.status_code == 413, overflow.text
    assert overflow.json()["code"] == "quota_exceeded"
    assert await _stored_state(app, emu.user_id) == (2000, 2000, 2000)

    # Quota is per owner, and deleting a mistaken measure frees one slot.
    other = ClientEmulator("measure-quota-other", "synthetic-other-passphrase")
    await other.register(client)
    other_created = await client.post(
        "/api/measures", headers=other.headers, json=_body(other, "first")
    )
    assert other_created.status_code == 201, other_created.text
    assert await _stored_state(app, other.user_id) == (1, 1, 1)

    deleted = await client.delete(
        "/api/measures/last-slot", headers={**emu.headers, "X-Account-Verifier": emu.auth_key_b64}
    )
    assert deleted.status_code == 200, deleted.text
    assert await _stored_state(app, emu.user_id) == (1999, 1999, 2001)
    replacement = await client.post(
        "/api/measures", headers=emu.headers, json=_body(emu, "replacement")
    )
    assert replacement.status_code == 201, replacement.text
    assert await _stored_state(app, emu.user_id) == (2000, 2000, 2002)


async def test_unadvanceable_measure_revision_rejects_write_and_rolls_back_insert(client, app):
    emu = ClientEmulator("measure-revision-limit", "synthetic-revision-passphrase")
    await emu.register(client)
    maximum = measures_api.MAX_COLLECTION_REVISION
    async with app.state.sessionmaker() as session:
        user = await session.get(User, emu.user_id)
        user.measures_revision = maximum - 1
        await session.commit()

    # The final representable revision is valid. The following write must
    # fail its real conditional SQL update and roll back the pending insert.
    accepted = await client.post(
        "/api/measures", headers=emu.headers, json=_body(emu, "last-revision")
    )
    assert accepted.status_code == 201, accepted.text
    assert await _stored_state(app, emu.user_id) == (1, 1, maximum)
    refused = await client.post(
        "/api/measures", headers=emu.headers, json=_body(emu, "unmarked-write")
    )
    assert refused.status_code == 503, refused.text
    assert refused.json()["code"] == "service_unavailable"
    assert refused.headers["Retry-After"] == "1"
    assert await _stored_state(app, emu.user_id) == (1, 1, maximum)
    listed = await client.get("/api/measures", headers=emu.headers)
    assert listed.status_code == 200
    assert [row["client_measure_id"] for row in listed.json()] == ["last-revision"]


async def test_measure_page_refuses_real_revision_change_after_assembly_and_retry_succeeds(
    client, app, monkeypatch
):
    emu = ClientEmulator("measure-revision-reader", "synthetic-reader-passphrase")
    await emu.register(client)
    initial = await client.post("/api/measures", headers=emu.headers, json=_body(emu, "first"))
    assert initial.status_code == 201, initial.text
    stable = await client.get("/api/measures", headers=emu.headers)
    assert stable.status_code == 200
    assert stable.headers["X-Measures-Revision"] == "1"
    assert [row["client_measure_id"] for row in stable.json()] == ["first"]

    original = measures_api.current_measures_revision
    calls = 0

    async def change_before_final_database_read(session, user_id):
        nonlocal calls
        calls += 1
        if calls == 2:
            # The page has already selected and serialized the first row.
            # A writer outside this worker's lifecycle lock now commits an
            # actual record and marker change. Close the read transaction
            # for the shared in-memory SQLite connection before that write.
            await session.commit()
            body = _body(emu, "mid-read")
            async with app.state.sessionmaker() as writer:
                writer.add(
                    Measure(
                        user_id=user_id,
                        client_measure_id="mid-read",
                        measure_date=date.today(),
                        blob=base64.b64decode(body["blob"]),
                    )
                )
                await writer.execute(
                    update(User)
                    .where(User.id == user_id)
                    .values(
                        measure_count=User.measure_count + 1,
                        measures_revision=User.measures_revision + 1,
                    )
                )
                await writer.commit()
        # Do not fabricate a revision return value: run the production SQL
        # query against the changed database at both fence boundaries.
        return await original(session, user_id)

    with monkeypatch.context() as patch:
        patch.setattr(measures_api, "current_measures_revision", change_before_final_database_read)
        changed = await client.get(
            "/api/measures", headers=emu.headers, params={"expected_revision": "1"}
        )
    assert calls == 2
    assert changed.status_code == 409, changed.text
    assert changed.json()["code"] == "collection_changed"
    assert changed.headers["X-Measures-Revision"] == "2"
    assert "blob" not in changed.text
    assert await _stored_state(app, emu.user_id) == (2, 2, 2)

    retry = await client.get(
        "/api/measures", headers=emu.headers, params={"expected_revision": "2"}
    )
    assert retry.status_code == 200, retry.text
    assert retry.headers["X-Measures-Revision"] == "2"
    assert {row["client_measure_id"] for row in retry.json()} == {"first", "mid-read"}
