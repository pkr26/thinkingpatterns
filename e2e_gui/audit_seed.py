"""Seed a full live scenario for the portal UI/UX audit (2026-09-28).

Against a RUNNING dev API (real 600k-iteration client crypto end to end):

  * audit-doc (therapist, "Dr. Audit Field") — registered through the
    therapist API with the portal's exact key schedule, so the REAL portal
    UI can sign in with the password below.
  * audit-carol — 70 journal days (Sunday work-deadline anxiety + a
    recurring "can't sleep, mind won't stop" phrase), insight phase,
    measures: PHQ-9 14 w/ item9=2 (today), GAD-7 9 (-3d), PHQ-9 5 (-10d).
    Active consent; 4 therapist notes (one pattern-anchored, one edited
    so it carries revision history).
  * audit-dave  — 70 days (short-sleep Mondays, family-visit Saturdays
    with drained Sundays). Active consent, GAD-7 6.
  * audit-eve   — 10 days, NO recompute (baseline phase), GAD-7 4.
  * audit-frank — 70 days with a recurring crisis-adjacent phrase
    (sensitive card). Consent granted then REVOKED; 2 notes remain.

Everything idempotent-ish: run against a FRESH db file (the script
refuses patient re-registration with a notice, like seed_patients.py).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import os
import sys
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "backend"))
os.environ.setdefault("MINDPATTERN_ENV", "development")

import httpx  # noqa: E402

from app.security import crypto  # noqa: E402
from app.security import kdf as keyderive  # noqa: E402
from app.security import sharing as sharing_crypto  # noqa: E402
from app.security.kdf import hkdf_sha256  # noqa: E402
from tests.helpers import ClientEmulator  # noqa: E402

LIVE_ITERATIONS = 600_000

THERAPIST = "audit-doc"
THERAPIST_PW = "Audit-Doc-2026!x"

CAROL = "audit-carol"
CAROL_PW = "audit-carol-2026"
DAVE = "audit-dave"
DAVE_PW = "audit-dave-2026"
EVE = "audit-eve"
EVE_PW = "audit-eve-2026"
FRANK = "audit-frank"
FRANK_PW = "audit-frank-2026"


class LiveClientEmulator(ClientEmulator):
    """ClientEmulator with the real 600k-iteration key schedule."""

    def __init__(self, username: str, password: str):
        import os as _os

        self.username = username
        self.password = password
        self.salt = _os.urandom(16)
        self.master_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.salt, LIVE_ITERATIONS
        )
        self.auth_key = keyderive.derive_auth_key(self.master_key)
        self.data_key = keyderive.derive_data_key(self.master_key)
        self.user_id: str | None = None
        self.token: str | None = None


from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


class LiveTherapistEmulator:
    """TherapistEmulator's exact crypto with the live 600k KDF."""

    def __init__(self, username: str, password: str, display_name: str):
        self.username = username
        self.password = password
        self.display_name = display_name
        self.salt = os.urandom(16)
        self.master_key = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), self.salt, LIVE_ITERATIONS
        )
        self.auth_key = keyderive.derive_auth_key(self.master_key)
        self.wrap_kek = hkdf_sha256(self.master_key, None, sharing_crypto.PORTAL_WRAP_INFO)
        self.notes_key = hkdf_sha256(self.master_key, None, sharing_crypto.PORTAL_NOTES_INFO)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.wrap_pub_key = base64.b64encode(
            self.private_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            )
        ).decode("ascii")
        self.user_id: str | None = None
        self.token: str | None = None

    @property
    def headers(self) -> dict:
        assert self.token
        return {"Authorization": f"Bearer {self.token}"}

    async def register(self, client: httpx.AsyncClient) -> dict:
        pkcs8 = self.private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        blob = crypto.encrypt(
            self.wrap_kek, pkcs8,
            crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, self.username),
        )
        response = await client.post(
            "/api/therapist/register",
            json={
                "username": self.username,
                "salt": base64.b64encode(self.salt).decode(),
                "verifier": base64.b64encode(self.auth_key).decode(),
                "age_attestation": "minimum_age_confirmed_v1",
                "display_name": self.display_name,
                "wrap_pub_key": self.wrap_pub_key,
                "wrap_key_blob": base64.b64encode(blob).decode(),
            },
        )
        assert response.status_code == 201, response.text
        self.user_id = response.json()["user_id"]
        self.token = response.json()["token"]
        return response.json()

    def wrap_key_blob_b64(self) -> str:
        pkcs8 = self.private_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
        blob = crypto.encrypt(
            self.wrap_kek, pkcs8,
            crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, self.username),
        )
        return base64.b64encode(blob).decode("ascii")

    def encrypt_note(self, patient: LiveClientEmulator, client_note_id: str, text: str) -> str:
        payload = {"v": 1, "text": text}
        aad = crypto.build_aad(
            sharing_crypto.NOTE_CONTEXT, self.user_id or "", patient.user_id or "", client_note_id
        )
        blob = crypto.encrypt(self.notes_key, json.dumps(payload).encode("utf-8"), aad)
        return base64.b64encode(blob).decode("ascii")


# --------------------------------------------------------------- corpora

def days_ending_yesterday(days: int) -> list[date]:
    end = date.today() - timedelta(days=1)
    return [end - timedelta(days=offset) for offset in range(days - 1, -1, -1)]


def carol_text(day: date) -> str:
    if day.weekday() == 6:  # Sunday
        return (
            "Deadline at work looming, the boss piled on another project and a late meeting. "
            "Anxious, stressed, dreading the presentation. can't sleep, mind won't stop."
        )
    if day.day % 5 == 0:
        return "Busy but okay day. Walk by the river, felt calm and grateful. Slept deeply."
    return "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


def dave_text(day: date) -> str:
    if day.weekday() == 0:  # Monday
        return "Slept barely four hours, exhausted at work, snapped at a colleague. Foggy all day."
    if day.weekday() == 5:  # Saturday
        return "Family visit today — loud, busy, everyone asking questions. Glad to see them though."
    if day.weekday() == 6:  # Sunday
        return "The day after family visits, drained and quiet. Didn't get much done."
    return "Steady day at work, gym in the evening, slept fine."


EVE_TEXT = "Quiet day, some reading, a little gardening. Feeling neutral."

def frank_text(day: date) -> str:
    if day.day % 9 == 0:
        return "Rough week. cutting again after the fight, numb for hours afterwards. Skipped dinner."
    return "Went to work, came home, watched something. Same as usual."


# --------------------------------------------------------------- helpers

async def register_patient(client, username: str, password: str):
    emu = LiveClientEmulator(username, password)
    response = await client.post(
        "/api/auth/register",
        json={
            "username": emu.username,
            "salt": emu.salt_b64,
            "verifier": emu.auth_key_b64,
            "age_attestation": "minimum_age_confirmed_v1",
        },
    )
    if response.status_code == 409:
        print(f"  {username}: already exists — skipping (use a fresh db)")
        return None
    assert response.status_code == 201, response.text
    emu.user_id = response.json()["user_id"]
    emu.token = response.json()["token"]
    return emu


async def seed_journal(client, emu, days: int, text_for) -> None:
    for day in days_ending_yesterday(days):
        text = text_for(day)
        for attempt in range(8):
            response = await client.post(
                "/api/entries",
                headers=emu.headers,
                json={
                    "client_entry_id": f"e-{day.isoformat()}",
                    "blob": emu.encrypt_entry(text, day, f"e-{day.isoformat()}", None, 1),
                    "entry_date": day.isoformat(),
                    "content_version": 1,
                },
            )
            if response.status_code == 201:
                break
            assert response.status_code == 429, response.text
            time.sleep(15)
    print(f"  {emu.username}: {days} journal days seeded")


async def record_measure(emu, client, mid: str, payload: dict, day: date) -> None:
    blob = crypto.encrypt(
        emu.data_key, json.dumps(payload).encode("utf-8"),
        crypto.build_aad("measure", emu.user_id or "", mid),
    )
    response = await client.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": mid,
            "blob": base64.b64encode(blob).decode("ascii"),
            "measure_date": day.isoformat(),
        },
    )
    assert response.status_code == 201, response.text


async def recompute(client, emu) -> dict:
    token = await emu.open_processing_session(client)
    response = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": token},
    )
    assert response.status_code == 200, response.text
    insights = await client.get("/api/insights", headers=emu.headers)
    blob = insights.json().get("blob")
    if not blob:
        return {"stats": {"patterns": []}}
    plain = crypto.decrypt(
        emu.data_key, base64.b64decode(blob),
        crypto.build_aad("insights", emu.user_id, "patterns"),
    )
    payload = json.loads(plain.decode("utf-8"))
    print(f"  {emu.username}: recompute → {len(payload['stats']['patterns'])} patterns")
    return payload


async def grant(client, patient, therapist) -> None:
    from app.api.consents import SHARING_DISCLOSURE_VERSION

    code_resp = await client.post("/api/therapist/pairing-codes", headers=therapist.headers)
    assert code_resp.status_code == 201, code_resp.text
    code = code_resp.json()["code"]
    lookup = await client.post(
        "/api/consents/pairing/lookup", headers=patient.headers, json={"code": code}
    )
    assert lookup.status_code == 200, lookup.text
    body = lookup.json()
    eph_b64, wrapped_b64 = sharing_crypto.wrap_data_key(
        patient.data_key, body["wrap_pub_key"], patient.user_id, body["therapist_id"]
    )
    response = await client.post(
        "/api/consents",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        json={
            "code": code,
            "ephemeral_pub": eph_b64,
            "wrapped_key": wrapped_b64,
            "disclosure": SHARING_DISCLOSURE_VERSION,
        },
    )
    assert response.status_code == 201, response.text
    print(f"  {patient.username} → {therapist.username}: consent granted")


async def add_note(client, therapist, patient, text: str, pattern_pid: str | None = None):
    cid = f"n-{os.urandom(6).hex()}"
    blob = therapist.encrypt_note(patient, cid, text)
    response = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={"client_note_id": cid, "pattern_pid": pattern_pid, "blob": blob},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def edit_note(client, therapist, patient, note: dict, text: str, base_version: int):
    cid = note["client_note_id"]
    blob = therapist.encrypt_note(patient, cid, text)
    response = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": blob, "base_version": base_version},
    )
    assert response.status_code == 200, response.text
    return response.json()


async def revoke(client, patient) -> None:
    consents = await client.get("/api/consents", headers=patient.headers)
    rows = consents.json()
    items = rows if isinstance(rows, list) else rows.get("consents", rows.get("items", []))
    target = next(r for r in items if r.get("status") == "active")
    response = await client.delete(
        f"/api/consents/{target['id']}",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert response.status_code in (200, 204), response.text
    print(f"  {patient.username}: consent revoked")


async def backdate_user(db_url: str, user_id: str, days: int) -> None:
    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import create_async_engine
    from app.models import User

    engine = create_async_engine(db_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                update(User)
                .where(User.id == user_id)
                .values(created_at=datetime.now(timezone.utc) - timedelta(days=days + 2))
            )
    finally:
        await engine.dispose()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8001")
    parser.add_argument("--db-url", required=True)
    args = parser.parse_args()
    api = args.api.rstrip("/")

    async with httpx.AsyncClient(base_url=api, timeout=60) as client:
        meta = await client.get("/api/meta")
        print(f"api {api}: {meta.status_code}")

        therapist = LiveTherapistEmulator(THERAPIST, THERAPIST_PW, "Dr. Audit Field")
        # NOTE: /api/auth/salt answers 200 with a decoy salt for unknown
        # users (anti-enumeration), so it cannot detect existence — the
        # register call's 409 is the only honest signal.
        existing = await client.post(
            "/api/therapist/register",
            json={
                "username": therapist.username,
                "salt": base64.b64encode(therapist.salt).decode(),
                "verifier": base64.b64encode(therapist.auth_key).decode(),
                "age_attestation": "minimum_age_confirmed_v1",
                "display_name": therapist.display_name,
                "wrap_pub_key": therapist.wrap_pub_key,
                "wrap_key_blob": therapist.wrap_key_blob_b64(),
            },
        )
        if existing.status_code == 409:
            print(f"  {THERAPIST}: already exists — skipping (fresh db expected)")
        else:
            assert existing.status_code == 201, existing.text
            therapist.user_id = existing.json()["user_id"]
            therapist.token = existing.json()["token"]
            print(f"  {THERAPIST}: registered ({therapist.user_id})")

        carol = await register_patient(client, CAROL, CAROL_PW)
        if carol:
            await backdate_user(args.db_url, carol.user_id, 70)
            await seed_journal(client, carol, 70, carol_text)
            await record_measure(
                carol, client, "m-phq9-flag",
                {"v": 1, "measure": "phq9", "score": 14, "item9": 2,
                 "completed_at": date.today().isoformat()}, date.today())
            await record_measure(
                carol, client, "m-gad7",
                {"v": 1, "measure": "gad7", "score": 9,
                 "completed_at": (date.today() - timedelta(days=3)).isoformat()},
                date.today() - timedelta(days=3))
            await record_measure(
                carol, client, "m-phq9-old",
                {"v": 1, "measure": "phq9", "score": 5, "item9": 0,
                 "completed_at": (date.today() - timedelta(days=10)).isoformat()},
                date.today() - timedelta(days=10))
            await grant(client, carol, therapist)
            payload = await recompute(client, carol)
            pids = [p["detail"].get("pattern_pid") for p in payload["stats"]["patterns"]]
            anchored_pid = next((p for p in pids if p), None)
            await add_note(client, therapist, carol,
                           "Session focus: work stress cycle — Sunday dread before Monday deadlines. "
                           "Explored the anticipation vs. the actual day.")
            anchored = await add_note(
                client, therapist, carol,
                "Pattern note: the sleep-interference phrase keeps recurring with the Sunday entries.",
                pattern_pid=anchored_pid)
            edited = await add_note(client, therapist, carol,
                                    "First contact — intake summary, presenting concerns.")
            await edit_note(client, therapist, carol, edited,
                            "First contact — intake summary. Updated: PHQ-9 14 today, item 9 endorsed "
                            "(see measures). C-SSRS scheduled.", 1)
            print(f"  {CAROL}: 3 notes (1 anchored, 1 with revision history)")

        dave = await register_patient(client, DAVE, DAVE_PW)
        if dave:
            await backdate_user(args.db_url, dave.user_id, 70)
            await seed_journal(client, dave, 70, dave_text)
            await record_measure(
                dave, client, "m-gad7-dave",
                {"v": 1, "measure": "gad7", "score": 6,
                 "completed_at": (date.today() - timedelta(days=2)).isoformat()},
                date.today() - timedelta(days=2))
            await grant(client, dave, therapist)
            await recompute(client, dave)
            await add_note(client, therapist, dave, "Sleep hygiene discussion planned for next session.")

        eve = await register_patient(client, EVE, EVE_PW)
        if eve:
            await backdate_user(args.db_url, eve.user_id, 10)
            await seed_journal(client, eve, 10, lambda d: EVE_TEXT)
            await record_measure(
                eve, client, "m-gad7-eve",
                {"v": 1, "measure": "gad7", "score": 4,
                 "completed_at": date.today().isoformat()}, date.today())
            await grant(client, eve, therapist)
            print(f"  {EVE}: baseline patient (no recompute)")

        frank = await register_patient(client, FRANK, FRANK_PW)
        if frank:
            await backdate_user(args.db_url, frank.user_id, 70)
            await seed_journal(client, frank, 70, frank_text)
            await grant(client, frank, therapist)
            payload = await recompute(client, frank)
            pids = [p["detail"].get("pattern_pid") for p in payload["stats"]["patterns"]]
            anchored_pid = next((p for p in pids if p), None)
            await add_note(client, therapist, frank,
                           "Safety plan reviewed; crisis line on the fridge.")
            await add_note(client, therapist, frank,
                           "Discussed the returning self-harm urges — see the flagged pattern.",
                           pattern_pid=anchored_pid)
            await revoke(client, frank)

    print(
        "\ncredentials:\n"
        f"  therapist {THERAPIST} / {THERAPIST_PW}\n"
        f"  patient {CAROL} / {CAROL_PW} (insight, flagged PHQ-9, notes)\n"
        f"  patient {DAVE} / {DAVE_PW} (insight)\n"
        f"  patient {EVE} / {EVE_PW} (baseline)\n"
        f"  patient {FRANK} / {FRANK_PW} (revoked, notes remain)"
    )


if __name__ == "__main__":
    asyncio.run(main())
