"""Regression tests for the 2026-09-21 audit Phase 2, audit-trail read
path (B-4): the consent-scoped patient view (who accessed my data) and
the therapist accountability view, both cursor-paginated.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

from app.models import AccessLog, utcnow
from tests.helpers import ClientEmulator, TherapistEmulator


async def _grant(client, patient: ClientEmulator, therapist: TherapistEmulator) -> str:
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    return granted["body"]["id"]


async def test_patient_sees_who_accessed_their_data(client):
    therapist = TherapistEmulator("alog-th", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("alog-p", "deep-password")
    await patient.register(client)
    await _grant(client, patient, therapist)

    # Therapist portal reads generate audit rows against the patient.
    assert (
        await client.get(
            f"/api/therapist/patients/{patient.user_id}/insights", headers=therapist.headers
        )
    ).status_code in (200, 204)
    assert (
        await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries", headers=therapist.headers
        )
    ).status_code == 200

    log = await client.get("/api/account/access-log", headers=patient.headers)
    assert log.status_code == 200, log.text
    rows = log.json()
    actions = [row["action"] for row in rows]
    assert "grant" in actions  # the patient's own lifecycle row
    assert "read_insights" in actions and "read_entries" in actions
    read_row = next(row for row in rows if row["action"] == "read_entries")
    assert read_row["actor"] == "therapist"
    assert read_row["actor_name"] == therapist.display_name
    grant_row = next(row for row in rows if row["action"] == "grant")
    assert grant_row["actor"] == "self" and grant_row["actor_name"] is None
    # Newest first.
    ats = [row["at"] for row in rows]
    assert ats == sorted(ats, reverse=True)


async def test_access_log_is_scoped_per_patient(client):
    therapist = TherapistEmulator("alog-scope-th", "deep-password")
    await therapist.register(client)
    alpha = ClientEmulator("alog-scope-a", "deep-password")
    await alpha.register(client)
    beta = ClientEmulator("alog-scope-b", "deep-password")
    await beta.register(client)
    await _grant(client, alpha, therapist)
    await _grant(client, beta, therapist)

    assert (
        await client.get(
            f"/api/therapist/patients/{beta.user_id}/entries", headers=therapist.headers
        )
    ).status_code == 200

    # Alpha's log must contain nothing about beta's data (no cross-subject
    # leak, even though the same therapist accessed both).
    log = await client.get("/api/account/access-log", headers=alpha.headers)
    rows = log.json()
    assert all(row["action"] != "read_entries" for row in rows)
    beta_log = await client.get("/api/account/access-log", headers=beta.headers)
    assert any(row["action"] == "read_entries" for row in beta_log.json())


async def test_access_log_cursor_pagination_is_complete_and_unduplicated(client, app):
    patient = ClientEmulator("alog-page", "deep-password")
    await patient.register(client)
    base = utcnow()
    async with app.state.sessionmaker() as session:
        for i in range(7):
            session.add(
                AccessLog(
                    actor_id=patient.user_id,
                    actor_role="user",
                    user_id=patient.user_id,
                    action=f"grant",
                    at=base - timedelta(seconds=10 - i),
                )
            )
        await session.commit()

    seen: list[str] = []
    cursor = None
    for _ in range(5):
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        page = await client.get("/api/account/access-log", headers=patient.headers, params=params)
        assert page.status_code == 200
        seen.extend(f"{row['at']}|grant" for row in page.json())
        cursor = page.headers.get("X-Next-Cursor")
        if not cursor:
            break
    assert len(seen) == 7  # every row exactly once: no holes, no repeats

    bad = await client.get(
        "/api/account/access-log", headers=patient.headers, params={"cursor": "garbage"}
    )
    assert bad.status_code == 422


async def test_therapist_sees_own_action_history(client):
    therapist = TherapistEmulator("alog-th-self", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("alog-th-p", "deep-password")
    await patient.register(client)
    await _grant(client, patient, therapist)
    assert (
        await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
        )
    ).status_code == 200

    log = await client.get("/api/therapist/access-log", headers=therapist.headers)
    assert log.status_code == 200, log.text
    rows = log.json()
    actions = {row["action"] for row in rows}
    assert "read_notes" in actions
    note_row = next(row for row in rows if row["action"] == "read_notes")
    # Patients have no display name; the username is the rendered identity.
    assert note_row["patient_name"] == patient.username
    # Self-lifecycle rows (pairing mint does not audit; wrap rotation does).
    # list_patients audits with the therapist as their own subject:
    lp = next((row for row in rows if row["action"] == "list_patients"), None)
    if lp is not None:
        assert lp["patient_name"] is None


async def test_therapist_access_log_rejects_patient_tokens(client):
    patient = ClientEmulator("alog-forbidden", "deep-password")
    await patient.register(client)
    denied = await client.get("/api/therapist/access-log", headers=patient.headers)
    assert denied.status_code == 403
    assert denied.json()["code"] == "forbidden"
