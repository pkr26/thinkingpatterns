"""The consented therapist mirror must reject a page changed during assembly."""

import base64
from datetime import date

from sqlalchemy import update

from app.api import therapist as therapist_api
from app.models import Measure, User
from tests.test_remediation_measure_quota import _body, _stored_state
from tests.test_snapshot_revisions import _shared_pair


async def test_therapist_measure_page_detects_committed_mid_read_write_and_retry_succeeds(
    client, app, monkeypatch
):
    patient, therapist = await _shared_pair(client, "measure-final-fence")
    first_body = _body(patient, "first")
    created = await client.post("/api/measures", headers=patient.headers, json=first_body)
    assert created.status_code == 201, created.text
    path = f"/api/therapist/patients/{patient.user_id}/measures"
    stable = await client.get(path, headers=therapist.headers)
    assert stable.status_code == 200, stable.text
    assert stable.headers["X-Measures-Revision"] == "1"
    assert [(row["client_measure_id"], row["blob"]) for row in stable.json()] == [
        ("first", first_body["blob"])
    ]

    original = therapist_api.current_measures_revision
    calls = 0
    new_body = _body(patient, "mid-read")

    async def commit_before_final_revision_read(session, user_id):
        nonlocal calls
        calls += 1
        if calls == 2:
            # Ciphertext has been assembled under revision1. Simulate a
            # committed writer outside this worker's sharing lock before the
            # real final SQL read. The explicit commit also supports the
            # shared in-memory SQLite connection used by this test profile.
            await session.commit()
            async with app.state.sessionmaker() as writer:
                writer.add(
                    Measure(
                        user_id=user_id,
                        client_measure_id="mid-read",
                        measure_date=date.today(),
                        blob=base64.b64decode(new_body["blob"]),
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
        return await original(session, user_id)

    with monkeypatch.context() as patch:
        patch.setattr(therapist_api, "current_measures_revision", commit_before_final_revision_read)
        changed = await client.get(
            path, headers=therapist.headers, params={"expected_revision": "1"}
        )
    assert calls == 2
    assert changed.status_code == 409, changed.text
    assert changed.json()["code"] == "collection_changed"
    assert changed.headers["X-Measures-Revision"] == "2"
    assert "blob" not in changed.text
    assert await _stored_state(app, patient.user_id) == (2, 2, 2)

    retry = await client.get(path, headers=therapist.headers, params={"expected_revision": "2"})
    assert retry.status_code == 200, retry.text
    assert retry.headers["X-Measures-Revision"] == "2"
    assert {row["client_measure_id"]: row["blob"] for row in retry.json()} == {
        "first": first_body["blob"],
        "mid-read": new_body["blob"],
    }
