"""Audit seed addendum: an ACTIVE sensitive-pattern patient + date realism.

  * audit-gina — 70 days with a recurring crisis-adjacent phrase (the
    sensitive card), granted and left ACTIVE so the caseload sensitive
    banner, sensitive-first triage sort, and the non-quoting sensitive
    pattern card all render.
  * Backdates consents (granted_at / revoked_at) and therapist note
    timestamps so the caseload and notes list show varied, realistic
    dates instead of everything "today".
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "backend"))

import audit_seed as s  # noqa: E402

GINA = "audit-gina"
GINA_PW = "audit-gina-2026"


def gina_text(day: date) -> str:
    if day.day % 9 == 0:
        return "Hard stretch. cutting again after the argument, numb the whole evening. Ate nothing."
    if day.weekday() == 6:
        return "Sunday again, low and flat. Didn't leave the flat, just watched series."
    return "Work was fine. Cooked dinner, called my sister, slept okay."


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", default="http://localhost:8001")
    parser.add_argument("--db-file", required=True)
    args = parser.parse_args()

    import httpx

    async with httpx.AsyncClient(base_url=args.api, timeout=60) as client:
        # Re-authenticate the therapist from the first seed run by redoing
        # its deterministic registration attempt against the live salt —
        # simplest correct path: a fresh login with server-salt keys.
        import base64
        import hashlib

        from app.security import kdf as keyderive

        salt_resp = await client.post("/api/auth/salt", json={"username": s.THERAPIST})
        salt = base64.b64decode(salt_resp.json()["salt"])
        master = hashlib.pbkdf2_hmac(
            "sha256", s.THERAPIST_PW.encode(), salt, s.LIVE_ITERATIONS
        )
        auth_key = keyderive.derive_auth_key(master)
        login = await client.post(
            "/api/auth/login",
            json={"username": s.THERAPIST, "verifier": base64.b64encode(auth_key).decode()},
        )
        assert login.status_code == 200, login.text
        therapist = s.LiveTherapistEmulator(s.THERAPIST, s.THERAPIST_PW, "Dr. Audit Field")
        therapist.user_id = login.json()["user_id"]
        therapist.token = login.json()["token"]
        print(f"  {s.THERAPIST}: logged in")

        gina = await s.register_patient(client, GINA, GINA_PW)
        if gina:
            await s.backdate_user(
                f"sqlite+aiosqlite:///{args.db_file}", gina.user_id, 70
            )
            await s.seed_journal(client, gina, 70, gina_text)
            await s.grant(client, gina, therapist)
            await s.recompute(client, gina)

    # --- date realism, directly in sqlite (server offline rules don't apply:
    #     created_at/granted_at are display fields for the drill) ----------
    import sqlite3

    conn = sqlite3.connect(args.db_file)
    now = datetime.now(timezone.utc)
    offsets = {
        "audit-carol": 21,
        "audit-dave": 14,
        "audit-eve": 7,
        "audit-frank": 21,
        GINA: 30,
    }
    for name, days in offsets.items():
        conn.execute(
            """UPDATE consents SET granted_at = ?
               WHERE user_id = (SELECT id FROM users WHERE username = ?)""",
            ((now - timedelta(days=days)).isoformat(), name),
        )
    conn.execute(
        """UPDATE consents SET revoked_at = ?
           WHERE user_id = (SELECT id FROM users WHERE username = 'audit-frank')""",
        ((now - timedelta(days=2)).isoformat(),),
    )
    # Notes: spread carol's three notes across the last three weeks
    # (created_at ASC order preserved), keep updated_at >= created_at.
    conn.execute(
        """UPDATE therapist_notes SET created_at = ? WHERE id = (
             SELECT n.id FROM therapist_notes n JOIN users t ON n.therapist_id = t.id
             JOIN users p ON n.user_id = p.id
             WHERE t.username='audit-doc' AND p.username='audit-carol'
             ORDER BY n.created_at ASC LIMIT 1)""",
        ((now - timedelta(days=19)).isoformat(),),
    )
    conn.execute(
        """UPDATE therapist_notes SET created_at = ? WHERE id = (
             SELECT n.id FROM therapist_notes n JOIN users t ON n.therapist_id = t.id
             JOIN users p ON n.user_id = p.id
             WHERE t.username='audit-doc' AND p.username='audit-carol'
             ORDER BY n.created_at ASC LIMIT 1 OFFSET 1)""",
        ((now - timedelta(days=8)).isoformat(),),
    )
    conn.execute(
        """UPDATE therapist_notes SET created_at = ? WHERE id = (
             SELECT n.id FROM therapist_notes n JOIN users t ON n.therapist_id = t.id
             JOIN users p ON n.user_id = p.id
             WHERE t.username='audit-doc' AND p.username='audit-carol'
             ORDER BY n.created_at ASC LIMIT 1 OFFSET 2)""",
        ((now - timedelta(days=1)).isoformat(),),
    )
    conn.commit()
    rows = conn.execute(
        """SELECT p.username, n.created_at FROM therapist_notes n
           JOIN users p ON n.user_id = p.id
           WHERE p.username = 'audit-carol' ORDER BY n.created_at"""
    ).fetchall()
    for row in rows:
        print(f"  note backdated: {row[0]} {row[1]}")
    conn.close()
    print("addendum done")


if __name__ == "__main__":
    asyncio.run(main())
