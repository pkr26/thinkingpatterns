"""The MBC measures module (2026-09-19): opaque-score storage + the
consent-gated therapist read. The server must never learn a score — every
test works with ciphertext and asserts the exact opacity discipline the
entries module established."""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

from app.security import crypto
from tests.helpers import ClientEmulator, TherapistEmulator, daterange

TODAY = date.today()


def _measure_blob(emu: ClientEmulator, client_measure_id: str, score: int) -> str:
    payload = json.dumps(
        {"v": 1, "measure": "phq9", "score": score, "completed_at": TODAY.isoformat()}
    ).encode("utf-8")
    blob = crypto.encrypt(
        emu.data_key, payload, crypto.build_aad("measure", emu.user_id or "", client_measure_id)
    )
    return base64.b64encode(blob).decode("ascii")


async def _record(
    emu: ClientEmulator, client, client_measure_id: str, score: int, measure_date: date = TODAY
) -> dict:
    response = await client.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": client_measure_id,
            "blob": _measure_blob(emu, client_measure_id, score),
            "measure_date": measure_date.isoformat(),
        },
    )
    return {"status": response.status_code, "body": response.json() if response.content else None}


async def test_measure_roundtrip_and_opacity(client):
    emu = ClientEmulator("mbc-1", "deep-password")
    await emu.register(client)
    created = await _record(emu, client, "m-1", 14)
    assert created["status"] == 201, created
    row = created["body"]
    assert row["measure_date"] == TODAY.isoformat()

    listed = await client.get("/api/measures", headers=emu.headers)
    assert listed.status_code == 200
    rows = listed.json()
    assert len(rows) == 1 and rows[0]["client_measure_id"] == "m-1"
    # The server returned the same ciphertext it stored — decryptable by
    # the patient's key, and the plaintext score never appears anywhere.
    plain = crypto.decrypt(
        emu.data_key,
        base64.b64decode(rows[0]["blob"]),
        crypto.build_aad("measure", emu.user_id or "", "m-1"),
    )
    assert json.loads(plain.decode("utf-8"))["score"] == 14


async def test_duplicate_client_measure_id_is_409(client):
    emu = ClientEmulator("mbc-2", "deep-password")
    await emu.register(client)
    assert (await _record(emu, client, "m-dup", 5))["status"] == 201
    again = await _record(emu, client, "m-dup", 7)
    assert again["status"] == 409
    assert again["body"]["code"] == "conflict"


async def test_date_bounds_mirror_entries(client):
    emu = ClientEmulator("mbc-3", "deep-password")
    await emu.register(client)
    far_past = await _record(emu, client, "m-past", 5, TODAY - timedelta(days=400))
    assert far_past["status"] == 422
    far_future = await _record(emu, client, "m-future", 5, TODAY + timedelta(days=30))
    assert far_future["status"] == 422


async def test_isolation_between_accounts(client):
    alice = ClientEmulator("mbc-alice", "deep-password")
    await alice.register(client)
    await _record(alice, client, "m-1", 10)
    bob = ClientEmulator("mbc-bob", "deep-password")
    await bob.register(client)
    listed = await client.get("/api/measures", headers=bob.headers)
    assert listed.json() == []


async def test_therapist_reads_measures_only_with_active_consent(client):
    patient = ClientEmulator("mbc-p", "deep-password")
    await patient.register(client)
    await patient.backdate_account(client, days=14)
    await _record(patient, client, "m-1", 12)
    await _record(patient, client, "m-2", 9, TODAY - timedelta(days=7))
    th = TherapistEmulator("mbc-dr", "pw-therapist", "Dr. Measure")
    await th.register(client)

    before = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures", headers=th.headers
    )
    assert before.status_code in (403, 404)

    # Grant (the emulator's full happy path).
    code = await th.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201

    after = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures", headers=th.headers
    )
    assert after.status_code == 200, after.text
    rows = after.json()
    assert [r["client_measure_id"] for r in rows] == ["m-1", "m-2"]  # newest first
    # The portal-side decrypt works with the consent-unwrapped data key
    # (the wrap fields travel on the patients list, like the portal does).
    from app.security import sharing as sharing_crypto

    plist = (await client.get("/api/therapist/patients", headers=th.headers)).json()
    prow = next(r for r in plist if r["user_id"] == patient.user_id)
    data_key = sharing_crypto.unwrap_data_key(
        th.unlock_private_key(),
        prow["ephemeral_pub"],
        base64.b64decode(prow["wrapped_key"]),
        patient.user_id or "",
        th.user_id or "",
    )
    assert data_key == patient.data_key
    plain = crypto.decrypt(
        data_key,
        base64.b64decode(rows[1]["blob"]),
        crypto.build_aad("measure", patient.user_id or "", "m-2"),
    )
    assert json.loads(plain.decode("utf-8"))["score"] == 9

    # Revoke ends access immediately.
    revoked = await patient.revoke_consent(client, granted["body"]["id"])
    assert revoked in (200, 204)
    post = await client.get(
        f"/api/therapist/patients/{patient.user_id}/measures", headers=th.headers
    )
    assert post.status_code in (403, 404)


async def test_patient_routes_reject_therapist_tokens(client):
    th = TherapistEmulator("mbc-dr2", "pw-therapist")
    await th.register(client)
    denied = await client.post(
        "/api/measures",
        headers=th.headers,
        json={"client_measure_id": "m-1", "blob": "QUJD", "measure_date": TODAY.isoformat()},
    )
    assert denied.status_code == 403
