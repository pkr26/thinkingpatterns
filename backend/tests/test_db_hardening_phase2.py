"""Regression tests for the 2026-09-21 audit Phase 2, DB hardening
(B-3/B-5/B-6/B-7): server-side pool timeouts, batched rekey updates
(covered end-to-end by the rotation pin suite), active-only consent caps,
the dropped prefix notes index, and the steady-state pairing-code sweep.
Round 2 (2026-09-21) F-9: the consent LIST cap counts ACTIVE rows only.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

import app.main as main_mod
from app.api import consents as consents_module
from app.config import Settings
from app.models import (
    ROLE_THERAPIST,
    Consent,
    PairingCode,
    User,
    new_id,
    utcnow,
)
from tests.helpers import ClientEmulator, TherapistEmulator, patient_wrap_for


def _dev_settings(**overrides) -> Settings:
    values = {
        "environment": "development",
        "token_secret": "x" * 40,
        "database_url": "sqlite+aiosqlite://",
    }
    values.update(overrides)
    return Settings(**values)


# --- B-3: pool timeout knobs are validated ------------------------------------------


def test_db_timeout_settings_have_bounds():
    for name in ("db_statement_timeout_ms", "db_idle_in_transaction_timeout_ms"):
        with pytest.raises(RuntimeError, match=name):
            _dev_settings(**{name: 100})
        with pytest.raises(RuntimeError, match=name):
            _dev_settings(**{name: 10_000_000})
        _dev_settings(**{name: 1_000})  # floor boots
        _dev_settings(**{name: 600_000})  # mid-range boots


# --- B-5: revoked history no longer consumes grant capacity --------------------------


async def test_revoked_consents_do_not_consume_the_patient_cap(client, app, monkeypatch):
    # The real cap is 100; the pin is the counting rule, not the number.
    monkeypatch.setattr(consents_module, "MAX_CONSENTS_PER_PATIENT", 2)
    patient = ClientEmulator("cap-p", "deep-password")
    await patient.register(client)
    # Two REVOKED relationships used to consume the patient's entire grant
    # capacity forever (audit B-5). consents are unique per
    # (patient, therapist), so the history needs distinct therapists.
    former = []
    for i in range(2):
        emu = TherapistEmulator(f"cap-ther-former-{i}", "deep-password")
        await emu.register(client)
        former.append(emu)
    async with app.state.sessionmaker() as session:
        for i, emu in enumerate(former):
            wrap = patient_wrap_for(patient, emu.wrap_pub_key, emu.user_id or "")
            session.add(
                Consent(
                    user_id=patient.user_id,
                    therapist_id=emu.user_id,
                    status="revoked",
                    granted_at=utcnow() - timedelta(days=i + 1),
                    ephemeral_pub=wrap["ephemeral_pub"],
                    wrapped_key=b"r" * 96,
                    disclosure="d1",
                )
            )
        await session.commit()

    # A fresh grant to a THIRD therapist must still succeed: revoked
    # history imposes no ongoing load and must not consume capacity.
    clinician = TherapistEmulator("cap-ther-new", "deep-password")
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted


async def test_revoked_consents_do_not_consume_the_therapist_cap(client, app, monkeypatch):
    monkeypatch.setattr(consents_module, "MAX_PATIENTS_PER_THERAPIST", 2)
    clinician = TherapistEmulator("cap-ther-t", "deep-password")
    await clinician.register(client)
    # Two patients granted, then revoked: the therapist's caseload capacity
    # must be free again.
    for i in range(2):
        patient = ClientEmulator(f"cap-tp-{i}", "deep-password")
        await patient.register(client)
        code = await clinician.create_pairing_code(client)
        lookup = await patient.pairing_lookup(client, code)
        granted = await patient.grant_consent(
            client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
        )
        assert granted["status"] == 201, granted
        revoked = await client.delete(
            f"/api/consents/{granted['body']['id']}",
            headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
        )
        assert revoked.status_code in (200, 204), revoked.text

    fresh_patient = ClientEmulator("cap-tp-new", "deep-password")
    await fresh_patient.register(client)
    code = await clinician.create_pairing_code(client)
    lookup = await fresh_patient.pairing_lookup(client, code)
    granted = await fresh_patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted


# --- Round 2 F-9: the LIST cap counts ACTIVE consents only ---------------------------


async def test_revoked_history_does_not_trip_the_list_cap(client, app):
    """Audit round 2 (2026-09-21) F-9.

    GET /consents used to count ALL rows toward MAX_CONSENTS_PER_PATIENT,
    so a patient with 100 revoked former therapists got a 413 load failure
    on the share screen even with one live share — the read side had not
    followed B-5's ACTIVE-only counting rule. The real cap (100) is used
    un-monkeypatched: 101 total rows is exactly the shape that used to 413.
    """
    patient = ClientEmulator("listcap-p", "deep-password")
    await patient.register(client)
    # Consents are unique per (patient, therapist), so the history needs
    # distinct therapist rows — 100 of them, all revoked. The therapist
    # users are flushed BEFORE the consent rows reference them (SQLite
    # checks FKs per statement).
    former_ids: list[str] = []
    async with app.state.sessionmaker() as session:
        for i in range(100):
            therapist_id = new_id()
            former_ids.append(therapist_id)
            session.add(
                User(
                    id=therapist_id,
                    username=f"listcap-former-{i}",
                    salt="c2FsdA==",
                    verifier=b"v",
                    scrypt_salt=b"s",
                    role=ROLE_THERAPIST,
                    display_name="Former therapist",
                    wrap_pub_key="not-used-by-this-test",
                )
            )
        await session.flush()
        for i, therapist_id in enumerate(former_ids):
            session.add(
                Consent(
                    user_id=patient.user_id,
                    therapist_id=therapist_id,
                    status="revoked",
                    granted_at=utcnow() - timedelta(days=i + 1),
                    revoked_at=utcnow() - timedelta(days=i),
                    ephemeral_pub="not-used-by-this-test",
                    wrapped_key=b"r" * 96,
                    disclosure="d1",
                )
            )
        await session.commit()

    clinician = TherapistEmulator("listcap-dr", "deep-password")
    await clinician.register(client)
    code = await clinician.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted

    listed = await client.get("/api/consents", headers=patient.headers)
    assert listed.status_code == 200, listed.text
    rows = listed.json()
    # The one ACTIVE share is served, not a 413 load failure.
    active = [c for c in rows if c["status"] == "active"]
    assert len(active) == 1
    assert active[0]["therapist_id"] == clinician.user_id
    # The revoked history is RETAINED in full (the complete-list contract:
    # disclosure record + the "stopped on" rows the mobile screen renders),
    # never silently truncated now that it no longer counts toward the cap.
    assert len(rows) == 101


# --- B-7: dead pairing codes are swept even with an idle therapist --------------------


async def test_daily_sweep_prunes_dead_pairing_codes(client, app):
    therapist = TherapistEmulator("sweep-pair", "deep-password")
    await therapist.register(client)
    assert therapist.user_id
    dead_hash = "dead-code-hash-0000"
    async with app.state.sessionmaker() as session:
        session.add(
            PairingCode(
                code_hash=dead_hash,
                therapist_id=therapist.user_id,
                expires_at=utcnow() - timedelta(days=90),
            )
        )
        await session.commit()
        live_code = await therapist.create_pairing_code(client)

    await main_mod._prune_access_log_once(app)

    async with app.state.sessionmaker() as session:
        remaining = set((await session.execute(select(PairingCode.code_hash))).scalars())
        live_hash = (
            await session.execute(
                select(PairingCode.code_hash).where(
                    PairingCode.therapist_id == therapist.user_id
                )
            )
        ).scalars().all()
    assert dead_hash not in remaining
    # The sweep must not eat live codes: the freshly minted one survives.
    assert len(live_hash) == 1 and live_hash[0] != dead_hash
    assert live_code  # the returned plaintext code was minted at all
