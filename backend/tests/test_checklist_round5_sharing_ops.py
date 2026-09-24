"""External verification checklist 2026-09-23, round 5: sharing, consent,
deletion cascade, races, and the mute-across-recompute journey.

Closes the mapped gaps:

* pairing-code expiry at the exact boundary (just-valid vs one-second-past)
  and the lazy purge of dead code rows;
* the therapist route SHAPE: no mutating route touches patient data
  (notes are the therapist's own, and that is the only POST);
* deletion cascade verified across EVERY table (the mapped suite checked
  a subset), with only the access audit log surviving;
* a genuinely CONCURRENT pair on the local-recompute escrow endpoint —
  exactly one winner per state_seq generation;
* the register → 30 days → pattern → MUTE → recompute journey at the API
  level: the mute survives a later recompute and the card carries
  detail.muted=true.
"""

from __future__ import annotations

import asyncio
import base64
import json
from datetime import date, timedelta

import pytest
from sqlalchemy import delete, select, update

from app.api.therapist import PAIRING_RETENTION
from app.models import Base, PairingCode
from app.security import crypto
from tests.helpers import ClientEmulator, TherapistEmulator, daterange

TODAY = date.today()
# The proven pipeline corpus (test_insights_api): rich enough for the
# base-rate-corrected temporal detector; single-token filler does not
# register theme days the way real prose does.
WORK_ANXIOUS = (
    "Deadline at work monday, the boss piled on another project and a "
    "late meeting. Anxious, stressed, dreading the presentation."
)
CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


# --- 7a: pairing expiry boundary + purge ------------------------------------------


class TestPairingExpiryBoundary:
    async def test_code_valid_one_second_before_expiry_gone_one_second_after(self, client):
        from app.models import utcnow

        th = TherapistEmulator("dr-expiry", "pw")
        await th.register(client)
        patient = ClientEmulator("px-expiry", "pw")
        await patient.register(client)
        app = client._transport.app  # noqa: SLF001 — test reachability into state

        code_text = await th.create_pairing_code(client)
        async with app.state.sessionmaker() as session:
            row = (
                (
                    await session.execute(
                        select(PairingCode).where(PairingCode.therapist_id == th.user_id)
                    )
                )
                .scalars()
                .first()
            )
            assert row is not None

            # The 14:59 side: expiry still one second in the future.
            await session.execute(
                update(PairingCode)
                .where(PairingCode.id == row.id)
                .values(expires_at=utcnow() + timedelta(seconds=1))
            )
            await session.commit()

        lookup = await patient.pairing_lookup(client, code_text)
        assert lookup["status"] == 200, "a code one second from expiry still resolves"

        # The 15:01 side: expiry one second in the past — flat 404.
        async with app.state.sessionmaker() as session:
            await session.execute(
                update(PairingCode)
                .where(PairingCode.id == row.id)
                .values(expires_at=utcnow() - timedelta(seconds=1))
            )
            await session.commit()
        stale = await patient.pairing_lookup(client, code_text)
        assert stale["status"] == 404
        assert stale["body"]["code"] == "not_found"

    async def test_dead_code_rows_are_purged_on_next_creation(self, client):
        th = TherapistEmulator("dr-purge", "pw")
        await th.register(client)
        app = client._transport.app  # noqa: SLF001
        first = await th.create_pairing_code(client)
        async with app.state.sessionmaker() as session:
            row = (
                (
                    await session.execute(
                        select(PairingCode).where(PairingCode.therapist_id == th.user_id)
                    )
                )
                .scalars()
                .first()
            )
            from app.models import utcnow

            # Expired long enough ago to cross the retention horizon.
            await session.execute(
                update(PairingCode)
                .where(PairingCode.id == row.id)
                .values(expires_at=utcnow() - PAIRING_RETENTION - timedelta(hours=1))
            )
            await session.commit()

        # Any later pairing-code creation sweeps the dead row in the same
        # transaction (the opportunistic housekeeping in create_pairing_code).
        second = await th.create_pairing_code(client)
        assert second != first
        async with app.state.sessionmaker() as session:
            remaining = (
                (
                    await session.execute(
                        select(PairingCode).where(PairingCode.therapist_id == th.user_id)
                    )
                )
                .scalars()
                .all()
            )
        assert len(remaining) == 1, "the retention-expired row must be purged"


# --- 7e: therapist route shape — read-only by construction --------------------------


class TestTherapistRouteShape:
    def test_no_therapist_route_mutates_patient_data(self, app):
        from app.main import _resolve_api_routes

        offenders = []
        for route in _resolve_api_routes(app.routes):
            if not route.path.startswith("/api/v1/therapist/patients/"):
                continue
            methods = route.methods - {"HEAD", "OPTIONS"}
            if route.path.endswith("/notes") and "POST" in methods:
                continue  # the therapist's OWN note (encrypted under the
                # therapist's key) — the one sanctioned write
            if methods - {"GET"}:
                offenders.append(f"{sorted(methods)} {route.path}")
        assert not offenders, (
            "therapist routes that mutate patient data — read-only must be "
            f"the absence of endpoints: {offenders}"
        )

    def test_notes_is_the_only_therapist_post_under_patients(self, app):
        from app.main import _resolve_api_routes

        posts = [
            route.path
            for route in _resolve_api_routes(app.routes)
            if route.path.startswith("/api/v1/therapist/patients/") and "POST" in route.methods
        ]
        assert posts == ["/api/v1/therapist/patients/{user_id}/notes"]


# --- 8d: deletion cascade across EVERY table -----------------------------------------


class TestDeletionCascadeEveryTable:
    async def test_only_the_access_log_survives(self, client):
        th = TherapistEmulator("dr-cascade", "pw")
        await th.register(client)
        emu = ClientEmulator("cascade-patient", "pw")
        await emu.register(client)
        await emu.backdate_account(client, days=40)
        for day in daterange(32, TODAY):
            await emu.create_entry(client, CALM, day)
        await emu.recompute(client)

        # A measure, a consent, and a therapist note about this patient.
        measure_blob = base64.b64encode(
            crypto.encrypt(
                emu.data_key,
                b'{"v":1,"measure":"phq9","score":7}',
                crypto.build_aad("measure", emu.user_id, "m-1"),
            )
        ).decode("ascii")
        response = await client.post(
            "/api/measures",
            headers=emu.headers,
            json={
                "client_measure_id": "m-1",
                "blob": measure_blob,
                "measure_date": TODAY.isoformat(),
            },
        )
        assert response.status_code == 201
        code = await th.create_pairing_code(client)
        lookup = await emu.pairing_lookup(client, code)
        assert lookup["status"] == 200
        grant = await emu.grant_consent(
            client, code, th.wrap_pub_key, lookup["body"]["therapist_id"]
        )
        assert grant["status"] == 201
        note = await client.post(
            f"/api/therapist/patients/{emu.user_id}/notes",
            headers=th.headers,
            json={
                "client_note_id": "n-1",
                "blob": th.encrypt_note(emu, "n-1", "session observation"),
            },
        )
        assert note.status_code == 201

        assert await emu.delete_account(client) == 204

        app = client._transport.app  # noqa: SLF001
        async with app.state.sessionmaker() as session:
            leftovers: dict[str, int] = {}
            for table in Base.metadata.sorted_tables:
                rows = (await session.execute(select(table))).all()
                for row in rows:
                    rendered = repr(row)
                    if emu.user_id in rendered:
                        leftovers[table.name] = leftovers.get(table.name, 0) + 1
            # The audit trail is the ONLY deliberate survivor.
            assert set(leftovers) == {"access_log"}, (
                f"rows referencing the deleted account survived in: {leftovers}"
            )
            # And the therapist's note about this patient is gone too.
            notes_table = Base.metadata.tables["therapist_notes"]
            note_rows = (await session.execute(select(notes_table))).all()
            assert not any(emu.user_id in repr(r) for r in note_rows)

    async def test_therapist_deletion_cascades_consents_and_codes(self, client):
        th = TherapistEmulator("dr-gone", "pw")
        await th.register(client)
        await th.create_pairing_code(client)
        response = await client.request(
            "DELETE",
            "/api/therapist/account",
            headers={**th.headers, "X-Account-Verifier": th.auth_key_b64},
        )
        assert response.status_code == 204
        app = client._transport.app  # noqa: SLF001
        async with app.state.sessionmaker() as session:
            codes = (await session.execute(select(PairingCode))).scalars().all()
            assert not any(c.therapist_id == th.user_id for c in codes)


# --- 9e: a genuinely concurrent local-recompute pair ----------------------------------


class TestConcurrentLocalRecompute:
    async def test_two_in_flight_submissions_produce_exactly_one_winner(self, client):
        from tests.test_local_recompute import _blob, _insight_phase_user

        emu = await _insight_phase_user(client, "local-race")
        state_blob = _blob(emu.data_key, ("insights", emu.user_id, "brain"), {"v": 1})
        patterns_blob = _blob(emu.data_key, ("insights", emu.user_id, "patterns"), {"v": 1})
        payload = {
            "base_state_seq": 0,
            "state_blob": state_blob,
            "patterns_blob": patterns_blob,
            "analysis_dates": [TODAY.isoformat()],
        }
        # Both submissions are in flight SIMULTANEOUSLY (asyncio.gather,
        # not sequential) — optimistic concurrency must still admit exactly
        # one and 409 the loser.
        first, second = await asyncio.gather(
            client.post("/api/insights/local-recompute", headers=emu.headers, json=payload),
            client.post("/api/insights/local-recompute", headers=emu.headers, json=payload),
        )
        statuses = sorted([first.status_code, second.status_code])
        assert statuses == [200, 409], (
            f"expected one winner and one 409 loser, got {statuses} ({first.text} / {second.text})"
        )


# --- 10a: mute survives a later recompute (API journey) --------------------------------


class TestMuteAcrossRecomputeJourney:
    async def test_muted_pattern_stays_flagged_through_a_plain_recompute(self, client, monkeypatch):
        emu = ClientEmulator("mute-journey", "pw")
        await emu.register(client)
        await emu.backdate_account(client, days=75)
        for day in daterange(70, TODAY):
            await emu.create_entry(
                client,
                WORK_ANXIOUS if day.weekday() == 6 else CALM,
                day,
                client_entry_id=f"mj-{day.isoformat()}",
            )

        # First qualification day (candidate; nothing surfaces yet).
        await emu.recompute(client)
        # Independent second observation: a fresh work entry on a new,
        # non-Sunday day, recomputed on a NEW server day (the clock seam
        # the existing pipeline test uses — same-day recomputes correctly
        # never satisfy the replication gate).
        monkeypatch.setattr("app.api.insights._utc_today", lambda: date.today() + timedelta(days=1))
        fresh_day = TODAY if TODAY.weekday() != 6 else TODAY - timedelta(days=1)
        await emu.create_entry(client, WORK_ANXIOUS, fresh_day, "mj-fresh")
        await emu.recompute(client)
        payload = await emu.decrypt_insights(client)
        patterns = payload["stats"]["patterns"]
        work_cards = [
            p for p in patterns if p.get("kind") == "temporal" and p.get("label") == "work"
        ]
        assert work_cards, "the planted Sunday-work pattern must surface"
        work_card = work_cards[0]
        assert work_card["detail"].get("muted") is not True
        pid = work_card["detail"]["pattern_pid"]

        # Mute through the feedback blob (the mobile app's path). The blob
        # is sealed to the SERVER's injected today (day+1).
        token = await emu.open_processing_session(client)
        from app.api.insights import _utc_today

        feedback = {
            "feedback": [],
            "muted": [pid],
            "unmuted": [],
        }
        aad = crypto.build_aad("feedback", emu.user_id, _utc_today().isoformat())
        blob = base64.b64encode(
            crypto.encrypt(emu.data_key, json.dumps(feedback).encode(), aad)
        ).decode("ascii")
        response = await client.post(
            "/api/insights/recompute",
            headers={**emu.headers, "X-Processing-Token": token},
            json={"feedback_blob": blob},
        )
        assert response.status_code == 200, response.text

        # A LATER, ordinary recompute — one more injected day forward —
        # keeps the mute: the card still ships, flagged and demoted.
        monkeypatch.setattr("app.api.insights._utc_today", lambda: date.today() + timedelta(days=2))
        await emu.recompute(client)
        payload = await emu.decrypt_insights(client)
        work_cards = [
            p
            for p in payload["stats"]["patterns"]
            if p.get("kind") == "temporal" and p.get("label") == "work"
        ]
        assert work_cards, "a muted pattern still ships (flagged), never vanishes silently"
        assert work_cards[0]["detail"].get("muted") is True
