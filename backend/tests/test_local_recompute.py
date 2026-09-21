"""Regression tests for Phase 3 (2026-09-21): the local-recompute
protocol — the server side of the on-device brain (mobile/src/brain/
PORT.md). No processing session, no key shipment; optimistic state_seq
discipline; server-grounded analysis scope.
"""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta

from sqlalchemy import select

from app.models import Insight
from tests.helpers import ClientEmulator

TODAY = date.today()


def _blob(key: bytes, aad: tuple, payload: dict) -> str:
    from app.security import crypto

    raw = crypto.encrypt(key, json.dumps(payload).encode("utf-8"), crypto.build_aad(*aad))
    return base64.b64encode(raw).decode("ascii")


async def _insight_phase_user(client, username: str) -> ClientEmulator:
    from tests.helpers import daterange

    emu = ClientEmulator(username, "deep-password")
    await emu.register(client)
    await emu.backdate_account(client, days=34)
    for day in daterange(32, TODAY):
        await emu.create_entry(client, "quiet day some reading", day, client_entry_id=f"lr-{day.isoformat()}")
    return emu


async def test_local_recompute_stores_blobs_without_a_processing_session(client, app):
    emu = await _insight_phase_user(client, "local-rec-1")

    # The client-shaped payloads (the server never decrypts these).
    state_blob = _blob(emu.data_key, ("insights", emu.user_id, "brain"), {"v": 1, "patterns": {}})
    patterns_blob = _blob(
        emu.data_key, ("insights", emu.user_id, "patterns"), {"v": 1, "stats": {"patterns": []}}
    )
    response = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,  # a plain bearer — NO X-Processing-Token
        json={
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": [TODAY.isoformat()],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["analyzer"] == "local"
    assert body["state_seq"] == 1

    # Both rows landed under the ordinary kinds, seq-advanced, carrying the
    # client's bytes verbatim (the server never decrypts them).
    async with app.state.sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(Insight.kind, Insight.state_seq, Insight.blob).where(
                        Insight.user_id == emu.user_id
                    )
                )
            ).all()
        )
    kinds = {kind: (seq, bytes(blob)) for kind, seq, blob in rows}
    assert kinds["brain"][0] == 1
    assert kinds["patterns"][0] == 1
    assert base64.b64encode(kinds["brain"][1]).decode() == state_blob
    assert base64.b64encode(kinds["patterns"][1]).decode() == patterns_blob


async def test_stale_base_state_seq_conflicts(client):
    emu = await _insight_phase_user(client, "local-rec-2")
    state_blob = _blob(emu.data_key, ("insights", emu.user_id, "brain"), {"v": 1})
    patterns_blob = _blob(emu.data_key, ("insights", emu.user_id, "patterns"), {"v": 1})
    first = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,
        json={
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": [TODAY.isoformat()],
        },
    )
    assert first.status_code == 200
    # A second local run built on the SAME (now stale) state must 409.
    stale = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,
        json={
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": [TODAY.isoformat()],
        },
    )
    assert stale.status_code == 409
    # Building on the NEW seq succeeds.
    fresh = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,
        json={
            "base_state_seq": 1,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": [TODAY.isoformat()],
        },
    )
    assert fresh.status_code == 200
    assert fresh.json()["state_seq"] == 2


async def test_validation_and_scope_grounded(client):
    emu = await _insight_phase_user(client, "local-rec-3")
    state_blob = _blob(emu.data_key, ("insights", emu.user_id, "brain"), {"v": 1})
    patterns_blob = _blob(emu.data_key, ("insights", emu.user_id, "patterns"), {"v": 1})

    bad_dates = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,
        json={
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": ["not-a-date"],
        },
    )
    assert bad_dates.status_code == 422

    empty_dates = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,
        json={
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": [],
        },
    )
    assert empty_dates.status_code == 422

    # A date the account has no entry for is accepted but grounded out of
    # the stored count (patterns_stored counts only real dates).
    ghost = await client.post(
        "/api/insights/local-recompute",
        headers=emu.headers,
        json={
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": ["2020-01-01"],
        },
    )
    assert ghost.status_code == 200
    assert ghost.json()["patterns_stored"] == 0


async def test_therapist_tokens_cannot_reach_the_local_path(client):
    from tests.helpers import TherapistEmulator

    therapist = TherapistEmulator("local-rec-th", "deep-password")
    await therapist.register(client)
    denied = await client.post(
        "/api/insights/local-recompute",
        headers=therapist.headers,
        json={
            "base_state_seq": 0,
            "state_blob": "A" * 40,
            "patterns_blob": "A" * 40,
            "analysis_dates": [TODAY.isoformat()],
        },
    )
    assert denied.status_code == 403
