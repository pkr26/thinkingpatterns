"""Seed the two patients for the LIVE portal GUI drill (2026-09-28).

Creates, against the RUNNING dev API (real client crypto end to end — the
server only ever sees opaque blobs):

  * e2e-alice — 70 journal days ending YESTERDAY (so a same-day recompute
    already qualifies statistical patterns: every corpus day is in the
    past, the equivalent of the pytest suite's next-day shim), one
    recompute, and the measures trail: a FLAGGED PHQ-9 (score 14, item 9
    = 2), a GAD-7 (9), an older clean PHQ-9 (5, item 9 = 0).
  * e2e-bob   — 10 journal days ending yesterday, one GAD-7 (4), NO
    recompute: the baseline-phase patient (insights still locked).

Ordering: register -> created_at backdate (direct sqlite write, the
scripts/seed_demo.py idiom — the API rejects entries older than the
account) -> journal -> recompute -> measures.

Idempotence: registration 409 means the account exists; seeding then
skips with a notice (use a fresh --db-url file for a clean drill).

Post-grant refresh:  --recompute-user e2e-alice  logs in and runs one more
recompute so the server (re)writes the caseload summary for every ACTIVE
consent — run it AFTER the browser grant, then reload the portal list.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
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
from tests.helpers import ClientEmulator  # noqa: E402

# The REAL client KDF cost (tests/helpers.py's FAST_ITERATIONS is a pytest
# shortcut; the live web app derives at 600k, so accounts seeded with the
# fast path cannot be opened by the real UI — verifier mismatch).
LIVE_ITERATIONS = 600_000


class LiveClientEmulator(ClientEmulator):
    """ClientEmulator with the real 600k-iteration key schedule, so the
    seeded account is unlockable by the actual web app."""

    def __init__(self, username: str, password: str):
        import hashlib
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


ANXIOUS = (
    "Deadline at work monday, the boss piled on another project and a "
    "late meeting. Anxious, stressed, dreading the presentation."
)
CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."

ALICE = "e2e-alice"
ALICE_PW = "gui-alice-2026"
BOB = "e2e-bob"
BOB_PW = "gui-bob-2026"


def days_ending_yesterday(days: int) -> list[date]:
    end = date.today() - timedelta(days=1)
    return [end - timedelta(days=offset) for offset in range(days - 1, -1, -1)]


async def register(client, username: str, password: str) -> ClientEmulator | None:
    """Fresh emulator + registration; None when the account already exists."""
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
        print(f"  {username}: already exists — skipping seed (use a fresh db file)")
        return None
    assert response.status_code == 201, response.text
    emu.user_id = response.json()["user_id"]
    emu.token = response.json()["token"]
    return emu


async def seed_journal(client, emu: ClientEmulator, days: int) -> None:
    for day in days_ending_yesterday(days):
        text = ANXIOUS if day.weekday() == 6 else CALM
        for attempt in range(6):
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
            time.sleep(12)  # entry rate limit — live server default
    print(f"  {emu.username}: {days} journal days seeded (ending yesterday)")


async def record_measure(emu: ClientEmulator, client, mid: str, payload: dict, day: date) -> None:
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


async def recompute_and_report(client, emu: ClientEmulator) -> dict:
    await emu.recompute(client)
    payload = await decrypt_insights(client, emu)
    print(
        f"  {emu.username}: recompute done — "
        f"{len(payload['stats']['patterns'])} patterns surfaced"
    )
    return payload


async def decrypt_insights(client, emu: ClientEmulator) -> dict:
    response = await client.get("/api/insights", headers=emu.headers)
    assert response.status_code == 200, response.text
    blob = response.json()["blob"]
    assert blob is not None, "insights blob missing after recompute"
    plain = crypto.decrypt(
        emu.data_key, base64.b64decode(blob),
        crypto.build_aad("insights", emu.user_id, "patterns"),
    )
    return json.loads(plain.decode("utf-8"))


async def backdate(db_url: str, user_id: str, days: int) -> None:
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
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--db-url", default="")
    parser.add_argument("--recompute-user", default="", help="login + one recompute, then exit")
    args = parser.parse_args()

    async with httpx.AsyncClient(base_url=args.api, timeout=30) as client:
        if args.recompute_user:
            username, password = (
                (ALICE, ALICE_PW) if args.recompute_user == ALICE else (BOB, BOB_PW)
            )
            # Derive from the SERVER's salt (what the real client does) — a
            # fresh emulator instance's random salt would never match.
            import hashlib

            emu = ClientEmulator(username, password)
            salt_response = await client.post("/api/auth/salt", json={"username": username})
            assert salt_response.status_code == 200, salt_response.text
            emu.salt = base64.b64decode(salt_response.json()["salt"])
            emu.master_key = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), emu.salt, LIVE_ITERATIONS
            )
            emu.auth_key = keyderive.derive_auth_key(emu.master_key)
            emu.data_key = keyderive.derive_data_key(emu.master_key)
            await emu.login(client)
            await recompute_and_report(client, emu)
            print(f"{username}: caseload summaries rewritten for every ACTIVE consent")
            return

        assert args.db_url, "--db-url is required for a first seed (created_at backdate)"
        print(f"seeding against {args.api} (db: {args.db_url})")

        alice = await register(client, ALICE, ALICE_PW)
        if alice is not None:
            await backdate(args.db_url, alice.user_id, 70)
            await seed_journal(client, alice, 70)
            await recompute_and_report(client, alice)
            await record_measure(
                alice, client, "m-phq9-flag",
                {"v": 1, "measure": "phq9", "score": 14, "item9": 2,
                 "completed_at": date.today().isoformat()},
                date.today(),
            )
            await record_measure(
                alice, client, "m-gad7",
                {"v": 1, "measure": "gad7", "score": 9,
                 "completed_at": (date.today() - timedelta(days=3)).isoformat()},
                date.today() - timedelta(days=3),
            )
            await record_measure(
                alice, client, "m-phq9-old",
                {"v": 1, "measure": "phq9", "score": 5, "item9": 0,
                 "completed_at": (date.today() - timedelta(days=10)).isoformat()},
                date.today() - timedelta(days=10),
            )
            print(f"  {ALICE}: measures recorded (phq9 14 w/ item9=2, gad7 9, phq9 5)")

        bob = await register(client, BOB, BOB_PW)
        if bob is not None:
            await backdate(args.db_url, bob.user_id, 10)
            await seed_journal(client, bob, 10)
            await record_measure(
                bob, client, "m-gad7-bob",
                {"v": 1, "measure": "gad7", "score": 4,
                 "completed_at": date.today().isoformat()},
                date.today(),
            )
            print(f"  {BOB}: baseline patient (no recompute), gad7 4 recorded")

    print(
        "\ncredentials:\n"
        f"  patient {ALICE} / {ALICE_PW}  (insight phase, flagged PHQ-9)\n"
        f"  patient {BOB} / {BOB_PW}  (baseline phase)\n"
        "therapist: register through the portal UI (Dr. E2E Gui)"
    )


if __name__ == "__main__":
    asyncio.run(main())
