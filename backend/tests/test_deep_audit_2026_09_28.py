"""Deep-audit regression pins, 2026-09-28 session.

H-1: recompute must accept the entry payload shape the real clients write.
Every production client (mobile EntryScreen, web Entry) sets created_at to
`new Date().toISOString()` — a FULL ISO timestamp, pinned as the canonical
cross-platform payload by shared/interop_fixtures.json. The inner-date
sanity check parsed it with date.fromisoformat, which rejects any string
with a time component, so an account that saved entries from either client
answered 400 entry_payload_malformed on every recompute once it left the
30-day baseline phase — no patterns, no brain state, no daily question,
forever. The backend suite never saw it because tests/helpers.py builds
the date-only shape. (Found by the 2026-09-28 deep audit, proven red before
the fix: identical corpus 400'd at head~6ff92db.)
"""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

from app.security import crypto, totp
from tests.helpers import ClientEmulator

CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


def test_totp_rejects_unicode_decimal_digits_without_crashing():
    """S-1 (deep audit 2026-09-28): str.isdigit() is True for non-ASCII
    decimal digits, and hmac.compare_digest raises TypeError on non-ASCII
    strings — a six-Arabic-Indic-digit code 500'd the login path. The
    isascii() gate makes it a clean mismatch (None), same as a wrong code."""
    secret = b"k" * 20
    # Each of these used to raise TypeError out of verify_code.
    assert totp.verify_code(secret, "\u0661\u0662\u0663\u0664\u0665\u0666") is None
    assert totp.verify_code(secret, "\u00b9\u00b2\u00b3\u00b9\u00b2\u00b3") is None
    # The ASCII path is unchanged.
    assert totp.verify_code(secret, "000000") is None


async def _seed_client_shaped_entries(client, emu: ClientEmulator, days: int = 31) -> None:
    """Seed exactly what the shipped clients produce: v2 payloads whose
    created_at is a full millisecond-precision UTC timestamp."""
    await emu.backdate_account(client, days=days + 9)
    today = date.today()
    for offset in range(days, 0, -1):
        day = today - timedelta(days=offset)
        client_entry_id = f"e-{day.isoformat()}-audit"
        payload = {
            "v": 2,
            "text": CALM,
            "sentiment": None,
            "created_at": day.isoformat() + "T10:00:00.123Z",
            "tod": "morning",
        }
        aad = crypto.entry_aad_v2(emu.user_id or "", client_entry_id, 1)
        blob = crypto.encrypt(emu.data_key, json.dumps(payload).encode("utf-8"), aad)
        response = await client.post(
            "/api/entries",
            headers=emu.headers,
            json={
                "client_entry_id": client_entry_id,
                "blob": base64.b64encode(blob).decode("ascii"),
                "entry_date": day.isoformat(),
                "content_version": 1,
            },
        )
        assert response.status_code == 201, response.text


async def test_recompute_accepts_client_shaped_created_at(client):
    emu = ClientEmulator("audit-h1", "p")
    await emu.register(client)
    await _seed_client_shaped_entries(client, emu, days=31)

    session_token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert recompute.status_code == 200, recompute.text
    body = recompute.json()
    # The corpus must have been ANALYZED, not merely tolerated: 31 seeded
    # days move the account past the 30-day baseline phase.
    assert body["phase"] != "baseline", body
    assert body["analyzer"] != "none", body


async def test_inner_date_still_rejects_far_dates(client):
    """The sanity check itself must stay strict: a timestamped created_at
    more than a day from the server-validated outer date is a 400, exactly
    as before — the fix widens the accepted WIRE SHAPE, not the tolerance."""
    emu = ClientEmulator("audit-h1b", "p")
    await emu.register(client)
    # Enough honest history to push the account past the baseline phase so
    # the parser actually runs (a lone entry is never analyzed).
    await _seed_client_shaped_entries(client, emu, days=31)

    day = date.today() - timedelta(days=31)
    client_entry_id = "e-far-date"
    payload = {
        "v": 2,
        "text": CALM,
        "sentiment": None,
        "created_at": (day - timedelta(days=9)).isoformat() + "T10:00:00Z",
        "tod": "morning",
    }
    aad = crypto.entry_aad_v2(emu.user_id or "", client_entry_id, 1)
    blob = crypto.encrypt(emu.data_key, json.dumps(payload).encode("utf-8"), aad)
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": client_entry_id,
            "blob": base64.b64encode(blob).decode("ascii"),
            "entry_date": day.isoformat(),
            "content_version": 1,
        },
    )
    assert response.status_code == 201, response.text

    session_token = await emu.open_processing_session(client)
    recompute = await client.post(
        "/api/insights/recompute",
        headers={**emu.headers, "X-Processing-Token": session_token},
    )
    assert recompute.status_code == 400, recompute.text
    assert recompute.json()["code"] == "entry_payload_malformed", recompute.text
