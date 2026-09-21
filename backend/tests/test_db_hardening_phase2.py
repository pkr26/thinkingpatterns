"""Regression tests for the 2026-09-21 audit Phase 2, DB hardening
(B-3/B-5/B-6/B-7): server-side pool timeouts, batched rekey updates
(covered end-to-end by the rotation pin suite), active-only consent caps,
the dropped prefix notes index, and the steady-state pairing-code sweep.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import select

import app.main as main_mod
from app.api import consents as consents_module
from app.config import Settings
from app.models import Consent, PairingCode, utcnow
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
