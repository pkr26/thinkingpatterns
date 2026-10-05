"""Actual live-note fetch versus patient-erasure response ordering."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import account
from app.models import TherapistNote
from app.services import account_deletion
from tests.test_deep_campaign_api import _shared_revision_note


@pytest.mark.parametrize("operation", ["list", "create", "update"])
async def test_live_note_response_linearizes_before_patient_deletion(
    client, monkeypatch, operation
):
    patient, clinician, note = await _shared_revision_note(client, f"live-patient-{operation}")
    path = f"/api/therapist/patients/{patient.user_id}/notes"
    current = await client.get(path, headers=clinician.headers)
    assert current.status_code == 200
    note = next(row for row in current.json() if row["id"] == note["id"])
    fetched, release, deletion_entered, deletion_authorized = (
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
        asyncio.Event(),
    )
    original_execute, original_stage = AsyncSession.execute, account_deletion.stage_account_deletion
    original_refresh = AsyncSession.refresh
    original_proof = account._require_step_up_or_verifier

    async def pause_after_private_fetch(session, statement, *args, **kwargs):
        result = await original_execute(session, statement, *args, **kwargs)
        if operation == "list" and any(
            column.get("expr") is TherapistNote
            for column in getattr(statement, "column_descriptions", [])
        ):
            rows = result.scalars().all()
            assert rows, "the probe must follow a real private live-note fetch"
            await session.commit()
            fetched.set()
            await release.wait()
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: rows))
        return result

    async def pause_after_private_refresh(session, instance, *args, **kwargs):
        result = await original_refresh(session, instance, *args, **kwargs)
        if operation in {"create", "update"} and isinstance(instance, TherapistNote):
            assert instance.blob, "the probe must follow a real private-note refresh"
            await session.commit()
            fetched.set()
            await release.wait()
        return result

    def record_deletion(session, user):
        deletion_entered.set()
        return original_stage(session, user)

    async def record_deletion_proof(*args, **kwargs):
        result = await original_proof(*args, **kwargs)
        if kwargs.get("action") == "account_delete":
            deletion_authorized.set()
        return result

    monkeypatch.setattr(AsyncSession, "execute", pause_after_private_fetch)
    monkeypatch.setattr(AsyncSession, "refresh", pause_after_private_refresh)
    monkeypatch.setattr(account_deletion, "stage_account_deletion", record_deletion)
    monkeypatch.setattr(account, "_require_step_up_or_verifier", record_deletion_proof)
    if operation == "list":
        request = client.get(path, headers=clinician.headers)
    elif operation == "create":
        request = client.post(
            path,
            headers=clinician.headers,
            json={
                "client_note_id": "new-erasure-note",
                "blob": clinician.encrypt_note(patient, "new-erasure-note", "a private note"),
            },
        )
    else:
        request = client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=clinician.headers,
            json={
                "base_version": note["version"],
                "blob": clinician.encrypt_note(patient, "history-note", "updated private note"),
            },
        )
    reading = asyncio.create_task(request)
    await asyncio.wait_for(fetched.wait(), timeout=5)
    deleting = asyncio.create_task(
        client.delete(
            "/api/account",
            headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        )
    )
    try:
        await asyncio.wait_for(deletion_authorized.wait(), timeout=5)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(deletion_entered.wait(), timeout=0.05)
    finally:
        release.set()
        read_response, deletion_response = await asyncio.gather(reading, deleting)
    assert read_response.status_code == (201 if operation == "create" else 200)
    assert deletion_response.status_code == 204
    assert (await client.get(path, headers=clinician.headers)).status_code == 404
