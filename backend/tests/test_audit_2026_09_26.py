"""Regression tests for the 2026-09-26 full-codebase audit remediations.

Each test maps to a finding in AUDIT_FULL_CODEBASE_2026-09-26.md and is
annotated with its finding id, mirroring the repo's convention of pinning
every fix to the audit that demanded it:

  * H-6  — note revision rows/bytes in the chart quota + per-note cap
           with oldest eviction,
  * H-7  — the therapist patient-list cap counts ACTIVE consents only,
  * M-B1 — verifier re-auth runs against the fresh row and every
           verifier-gated route fences on the token epoch (M-2 pattern),
  * M-B2 — caseload summaries are disclosure-gated on write AND serve,
  * M-B3 — post-threshold questions render in the detected language,
  * M-B4 — ES lexicon fold-invariance (dead keys / divergent twins),
  * L-1  — deterministic temporal time-of-day tie-break,
  * L-2  — exotic homoglyphs (ʂ/ᵴ) fold to "s",
  * L-3  — ES corpora score against the ES-winning sentiment merge with
           language-scoped negators,
  * LOW  — the small-batch hardening items (CORS expose list, create_note
           pre-lock commit, local_recompute epoch fence, /meta rate
           bucket, max_body_bytes ceiling, LocalRecomputeRequest schema).
"""

from __future__ import annotations

import base64
import json
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
from fastapi import Request
from sqlalchemy import select, update

from app.deps import ApiError
from tests.helpers import ClientEmulator, TherapistEmulator

# =========================================================================
# H-6 — note revision storage is quota'd and capped
# =========================================================================


async def _note_fixture(client, label: str):
    """A therapist + patient pair with one live note to edit."""
    therapist = TherapistEmulator(f"h6-th-{label}", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator(f"h6-p-{label}", "deep-password")
    await patient.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "h6-note",
            "blob": therapist.encrypt_note(patient, "h6-note", "v0"),
        },
    )
    assert created.status_code == 201, created.text
    return therapist, patient, created.json()


async def test_h6_revision_cap_evicts_oldest_beyond_the_cap(client, monkeypatch):
    """H-6 (2026-09-26): edits past MAX_NOTE_REVISIONS_PER_NOTE evict the
    OLDEST revisions deterministically — the edit history is a bounded
    ring, not an unbounded byte faucet."""
    from app.api import therapist as therapist_api
    from app.models import TherapistNoteRevision

    monkeypatch.setattr(therapist_api, "MAX_NOTE_REVISIONS_PER_NOTE", 3)
    therapist, patient, note = await _note_fixture(client, "cap")

    app = client._transport.app  # noqa: SLF001 — test reachability into state
    for version in range(1, 6):  # five changing edits against a cap of 3
        response = await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=therapist.headers,
            json={"blob": therapist.encrypt_note(patient, "h6-note", f"v{version}")},
        )
        assert response.status_code == 200, response.text

    revisions = await client.get(
        f"/api/therapist/notes/{note['id']}/revisions", headers=therapist.headers
    )
    assert revisions.status_code == 200, revisions.text
    rows = revisions.json()
    assert len(rows) == 3, "the per-note revision cap must bound stored history"

    # The survivors are the three NEWEST superseded blobs (v2, v3, v4 —
    # v0's and v1's revisions were evicted oldest-first), newest first.
    from app.security import crypto as note_crypto

    aad = note_crypto.build_aad(
        "note", therapist.user_id or "", patient.user_id or "", "h6-note"
    )
    texts = [
        json.loads(
            note_crypto.decrypt(therapist.notes_key, base64.b64decode(row["blob"]), aad)
        )["text"]
        for row in rows
    ]
    assert texts == ["v4", "v3", "v2"]

    # The eviction is real at the row level, not just pagination.
    async with app.state.sessionmaker() as session:
        count = len(
            (
                await session.execute(
                    select(TherapistNoteRevision).where(
                        TherapistNoteRevision.note_id == note["id"]
                    )
                )
            )
            .scalars()
            .all()
        )
    assert count == 3

    # The live note still carries the newest text and the chart stays
    # usable after eviction.
    notes = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
    )
    assert notes.status_code == 200
    live = json.loads(
        note_crypto.decrypt(
            therapist.notes_key, base64.b64decode(notes.json()[0]["blob"]), aad
        )
    )["text"]
    assert live == "v5"


async def test_h6_revisions_consume_the_chart_byte_budget(client, monkeypatch):
    """H-6: the byte quota counts revision bytes — once the stored HISTORY
    reaches the budget, further edits refuse (the live notes still fit;
    the preserved superseded blobs do not)."""
    from app.api import therapist as therapist_api

    therapist, patient, note = await _note_fixture(client, "bytes")
    blob_len = len(base64.b64decode(note["blob"]))
    # Budget for exactly two blobs: the first edit fits (live swap + one
    # preserved revision); the second edit's history alone (two revisions
    # plus the live row) overflows it.
    monkeypatch.setattr(therapist_api, "MAX_NOTE_BYTES_PER_PATIENT", blob_len * 2)

    edited = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "h6-note", "v1")},
    )
    assert edited.status_code == 200, edited.text

    refused = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "h6-note", "v2")},
    )
    assert refused.status_code == 413, refused.text
    assert refused.json()["code"] == "blob_quota_exceeded"


# =========================================================================
# H-7 — the patient-list cap counts ACTIVE consents only
# =========================================================================


async def _seed_consent(app, therapist_id: str, label: str, status: str) -> None:
    from app.models import Consent, User, new_id

    async with app.state.sessionmaker() as session:
        patient_id = new_id()
        session.add(
            User(
                id=patient_id,
                username=f"h7-patient-{label}",
                salt="c2FsdA==",
                verifier=b"v",
                scrypt_salt=b"s",
            )
        )
        await session.flush()
        session.add(
            Consent(
                user_id=patient_id,
                therapist_id=therapist_id,
                status=status,
            )
        )
        await session.commit()


async def test_h7_list_cap_counts_active_consents_only(client, app):
    """H-7 (2026-09-26): revoked consents never expire a clinician's
    caseload list — the therapist-side twin of the patient list's F-9
    rule. 100 ACTIVE + 4 revoked rows must still list; a 101st ACTIVE
    row is still the loud 413."""
    therapist = TherapistEmulator("h7-therapist", "deep-password")
    await therapist.register(client)

    for i in range(100):
        await _seed_consent(app, therapist.user_id, f"active-{i}", "active")
    for i in range(4):
        await _seed_consent(app, therapist.user_id, f"revoked-{i}", "revoked")

    listed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert len(body) == 104  # full retained history, active + revoked
    assert sum(1 for row in body if row["status"] == "active") == 100

    # The 413 stays for a genuinely oversized ACTIVE caseload.
    await _seed_consent(app, therapist.user_id, "active-101st", "active")
    oversized = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert oversized.status_code == 413
    assert oversized.json()["code"] == "payload_too_large"


# =========================================================================
# M-B1 — verifier re-auth against the fresh row + epoch fences
# =========================================================================


async def _stale_auth_user(app, user_id: str):
    """The M-B1 race: load the auth-time ORM snapshot, then commit a
    concurrent logout (epoch bump) AFTER it — the request continues with
    a bearer whose epoch is now retired.

    The UPDATE runs with synchronize_session=False: SQLAlchemy's default
    "evaluate" strategy would apply ``token_epoch + 1`` to the loaded
    snapshot in memory, silently re-arming the stale object with the NEW
    epoch (expire_on_commit never gets a chance to matter)."""
    from app.models import User

    async with app.state.sessionmaker() as session:
        stale = await session.get(User, user_id)
        assert stale is not None
        pre_bump_epoch = stale.token_epoch
        await session.execute(
            update(User)
            .where(User.id == user_id)
            .values(token_epoch=pre_bump_epoch + 1)
            .execution_options(synchronize_session=False)
        )
        await session.commit()
        assert stale.token_epoch == pre_bump_epoch, "the snapshot must stay pre-rotation"
        return stale


def _request(app) -> SimpleNamespace:
    return SimpleNamespace(app=app)


async def test_mb1_stale_epoch_cannot_grant_consent(client, app):
    """M-B1: a pre-rotation bearer+verifier pair queued behind the grant
    fences cannot widen disclosure."""
    from app.api import consents as consents_api
    from app.schemas import ConsentGrantRequest
    from tests.helpers import patient_wrap_for

    patient = ClientEmulator("mb1-grant-p", "deep-password")
    await patient.register(client)
    therapist = TherapistEmulator("mb1-grant-th", "deep-password")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)

    stale_user = await _stale_auth_user(app, patient.user_id)
    wrap = patient_wrap_for(patient, therapist.wrap_pub_key, therapist.user_id)
    body = ConsentGrantRequest(code=code, disclosure=consents_api.SHARING_DISCLOSURE_VERSION, **wrap)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as raised:
            await consents_api.grant_consent(
                body=body,
                request=_request(app),
                user=stale_user,
                session=session,
                x_account_verifier=patient.auth_key_b64,
            )
    assert raised.value.status_code == 401
    assert raised.value.code == "unauthorized"
    # The single-use code survives the refusal (nothing was granted) —
    # the re-login is required because the bump retired the test's own
    # bearer too.
    await patient.login(client)
    lookup = await patient.pairing_lookup(client, code)
    assert lookup["status"] == 200


async def test_mb1_stale_epoch_cannot_rewrap_or_revoke(client, app):
    from app.api import consents as consents_api
    from app.schemas import ConsentRewrapRequest
    from tests.helpers import patient_wrap_for

    patient = ClientEmulator("mb1-rr-p", "deep-password")
    await patient.register(client)
    therapist = TherapistEmulator("mb1-rr-th", "deep-password")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    consent_id = granted["body"]["id"]

    stale_user = await _stale_auth_user(app, patient.user_id)
    wrap = patient_wrap_for(patient, therapist.wrap_pub_key, therapist.user_id)
    body = ConsentRewrapRequest(**wrap)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as rewrap_denied:
            await consents_api.rewrap_consent(
                body=body,
                consent_id=consent_id,
                request=_request(app),
                user=stale_user,
                session=session,
                x_account_verifier=patient.auth_key_b64,
            )
        assert rewrap_denied.value.status_code == 401
        with pytest.raises(ApiError) as revoke_denied:
            await consents_api.revoke_consent(
                consent_id,
                request=_request(app),
                user=stale_user,
                session=session,
                x_account_verifier=patient.auth_key_b64,
            )
        assert revoke_denied.value.status_code == 401
    # The grant is untouched by both refusals (re-login: the bump retired
    # the test's own bearer).
    await patient.login(client)
    consents = await patient.list_consents(client)
    assert consents[0]["status"] == "active"


async def test_mb1_stale_epoch_cannot_flip_llm_consent(client, app):
    from app.api import account as account_api
    from app.schemas import LlmConsentRequest

    patient = ClientEmulator("mb1-llm-p", "deep-password")
    await patient.register(client)
    stale_user = await _stale_auth_user(app, patient.user_id)
    body = LlmConsentRequest(enabled=True, verifier=patient.auth_key_b64)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as raised:
            await account_api.set_llm_consent(
                body=body, request=_request(app), user=stale_user, session=session
            )
    assert raised.value.status_code == 401


async def test_mb1_stale_epoch_cannot_delete_account(client, app):
    from app.api import account as account_api

    patient = ClientEmulator("mb1-del-p", "deep-password")
    await patient.register(client)
    stale_user = await _stale_auth_user(app, patient.user_id)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as raised:
            await account_api.delete_account(
                request=_request(app),
                body=None,
                user=stale_user,
                session=session,
                x_account_verifier=patient.auth_key_b64,
            )
    assert raised.value.status_code == 401
    # The account survived the refused deletion: the password still
    # authenticates (only the epoch moved, not the credential).
    relogin = await client.post(
        "/api/auth/login",
        json={"username": patient.username, "verifier": patient.auth_key_b64},
    )
    assert relogin.status_code == 200


async def test_mb1_stale_epoch_cannot_rotate_wrap_key(client, app):
    from app.api import therapist as therapist_api
    from app.schemas import WrapKeyRotateRequest

    therapist = TherapistEmulator("mb1-wrap-th", "deep-password")
    await therapist.register(client)
    stale_user = await _stale_auth_user(app, therapist.user_id)
    body = WrapKeyRotateRequest(
        wrap_pub_key=therapist.wrap_pub_key, wrap_key_blob=therapist.wrap_key_blob_b64()
    )
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as raised:
            await therapist_api.rotate_wrap_key(
                body=body,
                request=_request(app),
                user=stale_user,
                session=session,
                x_account_verifier=therapist.auth_key_b64,
            )
    assert raised.value.status_code == 401


async def test_mb1_stale_epoch_cannot_delete_therapist_account(client, app):
    from app.api import therapist as therapist_api

    therapist = TherapistEmulator("mb1-del-th", "deep-password")
    await therapist.register(client)
    stale_user = await _stale_auth_user(app, therapist.user_id)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as raised:
            await therapist_api.delete_therapist_account(
                request=_request(app),
                user=stale_user,
                session=session,
                x_account_verifier=therapist.auth_key_b64,
            )
    assert raised.value.status_code == 401


async def test_mb1_stale_epoch_cannot_change_totp(client, app, monkeypatch):
    """All three TOTP routes fence on the epoch: a retired session must
    not arm, enable, or strip the second factor."""
    from app.api import account as account_api
    from app.schemas import TotpConfirmRequest, TotpSetupRequest
    from app.security import totp as totp_crypto

    therapist = TherapistEmulator("mb1-totp-th", "deep-password")
    await therapist.register(client)
    # Deterministic code verification: matched counter 5.
    monkeypatch.setattr(account_api, "verify_code", lambda secret, code: 5)

    stale = await _stale_auth_user(app, therapist.user_id)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as setup_denied:
            await account_api.totp_setup(
                body=TotpSetupRequest(verifier=therapist.auth_key_b64),
                request=_request(app),
                user=stale,
                session=session,
            )
        assert setup_denied.value.status_code == 401

    # Enable: a PENDING secret exists, then the session is retired. (The
    # re-login first: the bump retired the test's own bearer.)
    await therapist.login(client)
    setup = await client.post(
        "/api/account/totp/setup",
        headers=therapist.headers,
        json={"verifier": therapist.auth_key_b64},
    )
    assert setup.status_code == 200, setup.text
    stale = await _stale_auth_user(app, therapist.user_id)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as enable_denied:
            await account_api.totp_enable(
                body=TotpConfirmRequest(verifier=therapist.auth_key_b64, code="123456"),
                request=_request(app),
                user=stale,
                session=session,
            )
        assert enable_denied.value.status_code == 401

    # Disable: enrollment armed, then the session is retired.
    async with app.state.sessionmaker() as session:
        from app.models import User

        await session.execute(
            update(User)
            .where(User.id == therapist.user_id)
            .values(totp_enabled=True, totp_last_counter=1)
        )
        await session.commit()
    stale = await _stale_auth_user(app, therapist.user_id)
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as disable_denied:
            await account_api.totp_disable(
                body=TotpConfirmRequest(verifier=therapist.auth_key_b64, code="123456"),
                request=_request(app),
                user=stale,
                session=session,
            )
        assert disable_denied.value.status_code == 401


async def test_mb1_rotated_verifier_fails_the_fresh_row_comparison(client, app):
    """M-B1's other half: after a full credential rotation the OLD
    verifier must fail inside _require_verifier itself — the comparison
    runs against the re-read row, not the auth-time snapshot whose
    scrypt_salt still holds the pre-rotation bytes."""
    from app.api import account as account_api
    from app.models import User
    from app.schemas import LlmConsentRequest

    patient = ClientEmulator("mb1-rot-p", "deep-password")
    await patient.register(client)
    old_verifier = patient.auth_key_b64

    # Rotate the credential through the real endpoint while the current
    # bearer + verifier are both valid: new salt, new verifier, epoch bump.
    patient.derive_new_generation("rotated-deep-password")
    rotated = await client.put(
        "/api/account/credential",
        headers=patient.headers,
        json={
            "verifier": old_verifier,
            "new_salt": patient.salt_b64,
            "new_verifier": patient.auth_key_b64,
        },
    )
    assert rotated.status_code == 204, rotated.text

    fresh_login = await client.post(
        "/api/auth/login",
        json={"username": patient.username, "verifier": patient.auth_key_b64},
    )
    assert fresh_login.status_code == 200, fresh_login.text
    async with app.state.sessionmaker() as session:
        fresh_user_row = await session.get(User, patient.user_id)
        assert fresh_user_row is not None
        body = LlmConsentRequest(enabled=True, verifier=old_verifier)
        with pytest.raises(ApiError) as raised:
            await account_api.set_llm_consent(
                body=body, request=_request(app), user=fresh_user_row, session=session
            )
    assert raised.value.status_code == 403
    assert raised.value.code == "verification_failed"


async def test_mb1_local_recompute_fences_on_epoch(client, app):
    """LOW batch item c: local_recompute enforces the in-fence epoch
    re-authorization its recompute sibling has had since M-2."""
    from app.api import insights as insights_api
    from app.schemas import LocalRecomputeRequest
    from app.security import crypto

    patient = ClientEmulator("mb1-lr-p", "deep-password")
    await patient.register(client)
    stale_user = await _stale_auth_user(app, patient.user_id)
    blob = base64.b64encode(
        crypto.encrypt(
            patient.data_key,
            b"{}",
            crypto.build_aad("insights", patient.user_id, "brain"),
        )
    ).decode("ascii")
    async with app.state.sessionmaker() as session:
        with pytest.raises(ApiError) as raised:
            await insights_api.local_recompute(
                body=LocalRecomputeRequest(
                    base_state_seq=0,
                    state_blob=blob,
                    patterns_blob=blob,
                    analysis_dates=[date.today().isoformat()],
                ),
                request=_request(app),
                user=stale_user,
                session=session,
            )
    assert raised.value.status_code == 401


# =========================================================================
# M-B2 — caseload summaries are disclosure-gated (write AND serve)
# =========================================================================


async def _mature_shared_pair(client, label: str):
    """A therapist/patient pair whose patient is INSIGHT-phase."""
    from tests.helpers import daterange

    therapist = TherapistEmulator(f"mb2-th-{label}", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator(f"mb2-p-{label}", "deep-password")
    await patient.register(client)
    await patient.backdate_account(client, 34)
    for day in daterange(31, date.today() - timedelta(days=1)):
        await patient.create_entry(
            client, "felt calm and grateful today", day, client_entry_id=f"mb2-{day}"
        )
    return therapist, patient


async def _grant_direct(app, patient_id: str, therapist_id: str, disclosure: str) -> str:
    from app.models import Consent, new_id

    async with app.state.sessionmaker() as session:
        consent_id = new_id()
        session.add(
            Consent(
                id=consent_id,
                user_id=patient_id,
                therapist_id=therapist_id,
                status="active",
                disclosure=disclosure,
            )
        )
        await session.commit()
        return consent_id


async def test_mb2_v1_disclosure_gets_no_summary_written_or_served(client, app):
    """M-B2: a v1-disclosure consent is skipped at the summary WRITE and
    treated as no-summary at the SERVE path — the same gate the measures
    read has enforced since H-14."""
    from app.models import Consent

    therapist, patient = await _mature_shared_pair(client, "v1")
    await _grant_direct(app, patient.user_id, therapist.user_id, disclosure="v1")
    await patient.recompute(client)

    async with app.state.sessionmaker() as session:
        consent = (
            (
                await session.execute(
                    select(Consent).where(
                        Consent.user_id == patient.user_id,
                        Consent.therapist_id == therapist.user_id,
                    )
                )
            )
            .scalars()
            .one()
        )
        # WRITE gate: nothing was persisted for the legacy grant.
        assert consent.summary_blob is None
        assert consent.summary_eph_pub is None

    listed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert listed.status_code == 200, listed.text
    row = listed.json()[0]
    # SERVE gate: even a leftover summary would read as no-summary.
    assert row["summary_blob"] is None
    assert row["summary_eph_pub"] is None
    assert row["summary_updated_at"] is None


async def test_mb2_v2_disclosure_summary_written_and_served(client, app):
    therapist, patient = await _mature_shared_pair(client, "v2")
    await _grant_direct(app, patient.user_id, therapist.user_id, disclosure="v2")
    await patient.recompute(client)

    listed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert listed.status_code == 200, listed.text
    row = listed.json()[0]
    assert row["summary_blob"], "the current-disclosure grant receives its summary"
    assert row["summary_eph_pub"]
    assert row["summary_updated_at"] is not None


async def test_mb2_stale_v1_summary_is_not_served_after_the_gate(client, app):
    """The serve gate must treat pre-existing (pre-fix) v1 summaries as
    no-summary — legacy rows written while the recompute persisted every
    active consent's summary are not resurrected by the list."""
    from app.models import Consent

    therapist, patient = await _mature_shared_pair(client, "legacy")
    await _grant_direct(app, patient.user_id, therapist.user_id, disclosure="v1")
    # A pre-fix world wrote a summary for this consent anyway.
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(Consent)
            .where(
                Consent.user_id == patient.user_id,
                Consent.therapist_id == therapist.user_id,
            )
            .values(summary_blob=b"stale-legacy-summary", summary_eph_pub="k")
        )
        await session.commit()

    listed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert listed.status_code == 200, listed.text
    row = listed.json()[0]
    assert row["summary_blob"] is None


# =========================================================================
# M-B3 — post-threshold questions in the detected language
# =========================================================================

WORK_ES = "me siento ansioso por el trabajo y la reunion con el jefe"
CALM_ES = "me siento tranquilo y agradecido, paseo y leo con calma"


def test_mb3_es_pool_renders_spanish_questions():
    """Unit: language="es" renders the ES templates and ES generics; EN is
    byte-identical to the pre-localization behavior (pinned separately by
    test_contract_pins)."""
    from app.services import questions
    from app.services.patterns import Pattern

    temporal = Pattern("temporal", "trabajo", 12, 0.9, {"day": "Sunday"})
    es = questions.render_pattern_questions(temporal, "es")
    assert es and all(q.endswith("?") for q in es)
    assert any("trabajo" in q and "domingo" in q for q in es), es

    steady = Pattern("topic", "guitarra", 12, 0.9, {"trend": "steady"})
    es_steady = questions.render_pattern_questions(steady, "es")
    assert any("presencia constante" in q for q in es_steady), es_steady

    direction = questions.render_pattern_questions(
        Pattern("mood_correlation", "trabajo", 8, 0.6, {"direction": "lower"}), "es"
    )
    assert any("ánimo más bajo" in q for q in direction), direction

    # Generic fallback pool is Spanish and the default remains English
    # (ASCII — the ES pool's inverted-question marks are non-ASCII).
    assert questions.GENERIC_QUESTIONS_ES[0] == "¿Qué ocupó la mayor parte de su mente hoy?"
    es_question = questions.question_for_today("mb3-user", [], date(2026, 9, 3), language="es")
    assert "¿" in es_question, es_question  # Spanish inverted-question punctuation
    assert questions.question_for_today("mb3-user", [], date(2026, 9, 3)).isascii()


def test_mb3_es_generic_pool_pinned_to_shared_contract():
    """The ES pool is byte-for-byte shared/generic_questions_es.json and
    positionally parallel to the EN pool (the mobile day-1 contract)."""
    import json
    from pathlib import Path

    from app.services import questions

    shared = Path(__file__).resolve().parents[2] / "shared" / "generic_questions_es.json"
    payload = json.loads(shared.read_text(encoding="utf-8"))
    assert payload["v"] == 1
    assert tuple(payload["questions"]) == tuple(questions.GENERIC_QUESTIONS_ES)
    assert len(questions.GENERIC_QUESTIONS_ES) == len(questions.GENERIC_QUESTIONS)


def test_mb3_es_template_invariants():
    """The philosophy invariants hold for the ES set too: every question
    ends with "?", and no advice language appears (English or Spanish)."""
    from app.services import questions

    candidates = list(questions.GENERIC_QUESTIONS_ES)
    for templates in questions.TEMPLATE_BY_KIND_ES.values():
        candidates.extend(templates)
    candidates.extend(questions.TOPIC_TEMPLATES_STEADY_ES)
    assert len(questions.TEMPLATE_BY_KIND_ES) == len(questions.TEMPLATE_BY_KIND)
    for question in candidates:
        assert question.rstrip().endswith("?"), f"not a question: {question!r}"
        lowered = question.lower()
        assert "should" not in lowered, f"advice language detected: {question!r}"
        assert "debería" not in lowered, f"advice language detected: {question!r}"
        assert "deberia" not in lowered, f"advice language detected: {question!r}"
        assert "you must" not in lowered


async def test_mb3_es_corpus_stores_a_spanish_daily_question(client):
    """Integration: an insight-phase SPANISH corpus stores the daily
    question rendered in Spanish — English templates no longer leak past
    the threshold for ES users."""
    from tests.helpers import daterange

    patient = ClientEmulator("mb3-es-p", "deep-password")
    await patient.register(client)
    await patient.backdate_account(client, 75)
    # 70 days of Spanish prose ending yesterday (Sundays carry the work
    # text so a temporal pattern can qualify; every text is function-word
    # and ES-sentiment dense so language detection reads "es").
    for day in daterange(70, date.today()):
        text = WORK_ES if day.weekday() == 6 else CALM_ES
        await patient.create_entry(client, text, day, client_entry_id=f"es-{day.isoformat()}")
    await patient.recompute(client)  # run 1: qualification + state
    # A fresh evidence day beyond run 1's window satisfies the
    # replication gate for the statistical kinds (the two-run discipline
    # the engine pins elsewhere).
    await patient.create_entry(client, WORK_ES, date.today(), client_entry_id="es-fresh")
    await patient.recompute(client)  # run 2: the temporal card surfaces

    question = await patient.decrypt_question(client, date.today())
    text = question["question"]
    # Spanish rendering: inverted-question punctuation or the formal
    # "usted" register — and never the English template around a Spanish
    # label ("shows up mostly on ...s — what do those days have in
    # common?").
    assert "¿" in text or "usted" in text, f"expected a Spanish question, got {text!r}"
    assert "shows up mostly" not in text
    assert "What " not in text


# =========================================================================
# M-B4 — ES lexicon fold-invariance
# =========================================================================


def _fold_key(key: str) -> str:
    """The engine's per-token fold (brain._fold_sentiment_text), applied
    to a lexicon key: NFKC compose, then reduce Latin base + combining
    marks to the base letter."""
    import unicodedata

    out = []
    for ch in unicodedata.normalize("NFKC", key):
        decomposed = unicodedata.normalize("NFKD", ch)
        base = decomposed[0]
        if (
            len(decomposed) > 1
            and ord(base) < 0x0250
            and all("\u0300" <= c <= "\u036f" for c in decomposed[1:])
        ):
            out.append(base)
        else:
            out.append(ch)
    return "".join(out)


def test_mb4_every_es_lexicon_key_is_fold_invariant():
    """M-B4: tokenization folds diacritics BEFORE every lookup, so each
    ES lexicon key must fold to itself or to another key carrying the
    SAME value — otherwise the accented spelling is dead weight (never
    matched) or, worse, documents a valence scoring can contradict."""
    from app.services import sentiment_lexicon_es as es

    sets: dict[str, object] = {
        "VADER_BASE_ES": es.VADER_BASE_ES,
        "INTENSIFIERS_ES": es.INTENSIFIERS_ES,
        "NEGATORS_ES": es.NEGATORS_ES,
        "ABSOLUTIST_WORDS_ES": es.ABSOLUTIST_WORDS_ES,
        "SENSE_WORDS_ES": es.SENSE_WORDS_ES,
        "BUT_WORDS_ES": es.BUT_WORDS_ES,
        "LANGUAGE_FUNCTION_WORDS_ES": es.LANGUAGE_FUNCTION_WORDS_ES,
    }
    for name, member in sets.items():
        for key in member:
            folded = _fold_key(key)
            if folded == key:
                continue
            assert folded in member, (
                f"{name}: accented key {key!r} is dead — its folded form "
                f"{folded!r} is absent, so post-fold tokens never match it"
            )
            if isinstance(member, dict):
                assert member[key] == member[folded], (
                    f"{name}: {key!r}={member[key]!r} contradicts its folded "
                    f"twin {folded!r}={member[folded]!r} (the folded spelling "
                    "is what lookups hit)"
                )


def test_mb4_the_cited_dead_keys_and_twins_are_gone():
    from app.services import sentiment_lexicon_es as es

    # Dead accented keys replaced by their folded spellings.
    assert "razon" in es.SENSE_WORDS_ES and "razón" not in es.SENSE_WORDS_ES
    assert "memorice" in es.SENSE_WORDS_ES and "memoricé" not in es.SENSE_WORDS_ES
    assert "quienes" in es.LANGUAGE_FUNCTION_WORDS_ES
    assert "quiénes" not in es.LANGUAGE_FUNCTION_WORDS_ES
    assert "quées" not in es.LANGUAGE_FUNCTION_WORDS_ES
    # "medía" dropped, not renamed: the folded "media" is not a key (the
    # noun/verb readings must not score as an intensifier) and "medio"
    # already carries the entry.
    assert "medía" not in es.INTENSIFIERS_ES
    assert "media" not in es.INTENSIFIERS_ES
    assert es.INTENSIFIERS_ES["medio"] == 0.8
    # Divergent folded twins aligned.
    assert es.VADER_BASE_ES["hartó"] == es.VADER_BASE_ES["harto"] == -2.6
    assert es.VADER_BASE_ES["pérdida"] == es.VADER_BASE_ES["perdida"] == -2.0


# =========================================================================
# L-1 — deterministic temporal time-of-day tie-break
# =========================================================================


def test_l1_tod_tie_breaks_lexicographically():
    """L-1: a tied dominant bucket resolves to the lexicographically
    first candidate on every platform (set iteration order for strings is
    hash-randomization dependent — the pre-fix code was
    process-order-dependent)."""
    from app.services import brain

    tie = brain._dominant_tod(["morning", "evening", "morning", "evening", "night"])
    assert tie == ("evening", 2)  # evening < morning lexicographically
    clear = brain._dominant_tod(["night", "night", "morning", "evening"])
    assert clear == ("night", 2)


def test_l1_tied_tod_corpus_stays_deterministic_and_unnarrowed():
    """A tie can never pass the 70% dominance bar, so a tied corpus pins
    to NO time-of-day refinement — deterministically, on every hash
    seed (the corpus ties evening/morning 4:4 across the theme Sundays)."""
    from app.services import brain
    from app.services.patterns import JournalEntry

    t0 = date(2026, 8, 2)  # a Sunday
    corpus: list[JournalEntry] = []
    for i in range(8):  # 4 evening + 4 morning — an exact tie
        corpus.append(
            JournalEntry(
                "busy day at work again",
                t0 + timedelta(weeks=i),
                tod="evening" if i % 2 == 0 else "morning",
            )
        )
    filler = t0 + timedelta(days=2)
    for i in range(14):
        corpus.append(JournalEntry("quiet day, some reading", filler + timedelta(days=i)))

    today = t0 + timedelta(weeks=8)
    first = brain.update(brain.load_state(None), corpus, today)
    grown = corpus + [
        JournalEntry("another busy work day", today + timedelta(weeks=1), tod="evening")
    ]
    second = brain.update(
        brain.load_state(brain.dump_state(first.new_state)), grown, today + timedelta(weeks=1)
    )
    cards = [p for p in second.surfaced if p.kind == "temporal" and p.label == "work"]
    assert cards, "the tie corpus must still surface the temporal card"
    assert "time_of_day" not in cards[0].detail


# =========================================================================
# L-2 — exotic homoglyphs fold to ASCII
# =========================================================================


def test_l2_exotic_s_homoglyphs_fire_the_dialog_tier():
    """L-2: U+0282 (ʂ) and U+1D74 (ᵴ) have no NFKC decomposition, so the
    homoglyph map — not the normalize step — must fold them: "ʂuicide"
    and "ᵴuicide" now read as plain "suicide"."""
    from app.services import crisis

    assert crisis.matches_dialog("ʂuicide")
    assert crisis.matches_dialog("ᵴuicide")
    # The map deliberately excludes codepoints NFKC already folds.
    assert "\u1d62" not in crisis._HOMOGLYPHS  # ᵢ → i via NFKC
    assert "\u1d69" not in crisis._HOMOGLYPHS  # ᵩ → φ via NFKC (Greek, not Latin)
    # …and those still detect through the NFKC path.
    assert crisis.matches_dialog("suᵢcᵢde")


def test_l2_every_homoglyph_entry_has_no_nfkc_decomposition():
    """The map's stated contract (keys are forms NFKC does not already
    fold) is pinned — a future entry that NFKC-folds would be redundant
    and mislead readers about which layer catches it. (The translate
    table maps integer codepoints to strings; U+03F2 lunate sigma is the
    one DOCUMENTED exception — NFKC maps it to final sigma ς, i.e. the
    WRONG lookalike family, which is exactly why the map pre-empts it.)"""
    import unicodedata

    from app.services import crisis

    for src_code in crisis._HOMOGLYPHS:
        src = chr(src_code)
        folded = unicodedata.normalize("NFKC", src)
        if src_code == 0x03F2:
            assert folded == "\u03c2"  # the documented lunate-sigma case
            continue
        assert folded == src, (
            f"_HOMOGLYPHS key {src!r} (U+{src_code:04X}) NFKC-folds to "
            f"{folded!r}; the map is only for lookalikes the normalize "
            "step cannot reduce"
        )


# =========================================================================
# L-3 — ES corpora score against the ES-winning merge, EN negators scoped
# =========================================================================


def test_l3_es_scoring_uses_the_es_winning_merge():
    """L-3: the 13 shared words score their SPANISH weights under
    language="es" ("perfecto" 2.8, not the muted English 1.3), while the
    default (vector/TS callers) keeps the pinned EN-winning merge."""
    from app.services import brain

    tokens = ["perfecto"]
    default = brain.sentiment_score(tokens)
    spanish = brain.sentiment_score(tokens, "es")
    assert spanish > default, (
        f"ES scoring must un-mute the shared word: es={spanish} default={default}"
    )
    # Exactly the lexicon values: 2.8 (ES) vs 1.3 (EN) on SENTIMENT_SCALE.
    assert spanish == pytest.approx(2.8 / brain.SENTIMENT_SCALE)
    assert default == pytest.approx(1.3 / brain.SENTIMENT_SCALE)


def test_l3_sin_ni_negation_is_es_scoped():
    """L-3: "ni" is a Spanish negator AND a bare English letter pair —
    under "en" it must not negate ("ni feliz" stays positive); under "es"
    it flips with VADER damping; the default keeps the historical union.
    ("sin" carries its own graded valence in the merged lexicon, so "ni"
    is the clean probe; "sin" is additionally pinned OUT of the English
    negator set.)"""
    from app.services import brain

    en = brain.sentiment_score(["ni", "feliz"], "en")
    es = brain.sentiment_score(["ni", "feliz"], "es")
    default = brain.sentiment_score(["ni", "feliz"])
    assert en == pytest.approx(2.8 / brain.SENTIMENT_SCALE)  # unnegated
    assert es == pytest.approx(2.8 * brain.NEGATION_SCALAR / brain.SENTIMENT_SCALE)
    assert default == es  # the pinned default keeps the union behavior
    # The EN set genuinely excludes both ES-only negators.
    assert "ni" not in brain.NEGATORS_EN
    assert "sin" not in brain.NEGATORS_EN
    assert "ni" in brain.NEGATORS_ES and "sin" in brain.NEGATORS_ES


def test_l3_es_merge_contains_every_es_key_with_es_priority():
    from app.services import brain

    for word, valence in brain.VADER_BASE_ES.items():
        assert brain.SENTIMENT_LEXICON_ES[word] == valence
    # The pinned artifact dict is untouched by L-3 (EN-winning merge).
    assert brain.SENTIMENT_LEXICON["perfecto"] == brain.SENTIMENT_LEXICON_EN["perfecto"]


# =========================================================================
# LOW batch — small hardening items
# =========================================================================


def test_low_cors_exposes_the_measures_marker_and_access_log_cursor(app):
    """LOW item a: browser clients can read X-Measures-Revision and
    X-Next-Cursor — both were missing from the CORS expose list while
    the headers were already being set by their routes."""
    cors = None
    for middleware in app.user_middleware:
        if middleware.cls.__name__ == "CORSMiddleware":
            cors = middleware
    assert cors is not None
    exposed = cors.kwargs["expose_headers"]
    assert "X-Measures-Revision" in exposed
    assert "X-Next-Cursor" in exposed
    assert "X-Next-Offset" in exposed
    assert "X-Entries-Revision" in exposed
    assert "X-Notes-Revision" in exposed


async def test_low_meta_joins_the_ops_rate_bucket(client, app):
    """LOW item d: /meta is throttled by the shared ops bucket — the
    free unauthenticated flood surface is gone."""
    app.state.settings.ops_rate_limit = 3
    app.state.settings.ops_rate_window = 60
    statuses = [
        (await client.get("/api/meta")).status_code for _ in range(5)
    ]
    assert statuses[:3] == [200, 200, 200]
    assert 429 in statuses[3:], statuses


def test_low_max_body_bytes_has_an_explicit_ceiling():
    """LOW item f: the A-8-style fail-fast bound — a unit mistake above
    the 64 MiB ceiling refuses to boot."""
    from app.config import MAX_BODY_BYTES, Settings

    assert Settings(environment="development").max_body_bytes <= MAX_BODY_BYTES
    with pytest.raises(RuntimeError, match="max_body_bytes"):
        Settings(environment="development", max_body_bytes=MAX_BODY_BYTES + 1)


def test_low_local_recompute_request_schema_hardening():
    """LOW item g: blob envelopes and the ISO-date pattern are enforced
    at the schema, mirroring EntryCreate/MeasureCreate."""
    import pydantic

    from app.schemas import LocalRecomputeRequest

    ok = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob="a" * 100,
        patterns_blob="b" * 100,
        analysis_dates=["2026-09-26"],
    )
    assert ok.analysis_dates == ["2026-09-26"]
    with pytest.raises(pydantic.ValidationError):
        LocalRecomputeRequest(
            base_state_seq=0,
            state_blob="a" * 2_000_000,  # over the MAX_BLOB_B64 envelope
            patterns_blob="b" * 100,
            analysis_dates=["2026-09-26"],
        )
    with pytest.raises(pydantic.ValidationError):
        LocalRecomputeRequest(
            base_state_seq=0,
            state_blob="a" * 100,
            patterns_blob="b" * 100,
            analysis_dates=["26/09/2026"],  # not ISO
        )


async def test_low_create_note_releases_its_read_txn_before_the_chart_lock(
    client, app, monkeypatch
):
    """LOW item b: create_note closes the pre-lock read transaction
    before queueing on the chart lock (the list_notes/update_note
    pooling discipline) — verified by observing, at lock-acquisition
    time, that the request's session holds no open transaction."""
    import contextlib

    from app.api import therapist as therapist_api
    from app.deps import get_session

    captured: list[tuple[str, bool]] = []
    active: list = [None]
    original_hold = therapist_api._note_locks.hold

    class _RecordingLocks:
        def hold(self, key):
            captured.append((key, active[0] is not None and active[0].in_transaction()))

            @contextlib.asynccontextmanager
            async def _ctx():
                async with original_hold(key):
                    yield

            return _ctx()

    async def recording_session(request: Request):
        async with request.app.state.sessionmaker() as session:
            active[0] = session
            try:
                yield session
            finally:
                active[0] = None

    monkeypatch.setattr(therapist_api, "_note_locks", _RecordingLocks())
    app.dependency_overrides[get_session] = recording_session

    therapist = TherapistEmulator("lowb-th", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator("lowb-p", "deep-password")
    await patient.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted

    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={
            "client_note_id": "low-b",
            "blob": therapist.encrypt_note(patient, "low-b", "note text"),
        },
    )
    assert created.status_code == 201, created.text
    assert captured, "the recording lock must have been acquired"
    for key, in_transaction in captured:
        assert not in_transaction, (
            f"create_note held an open read transaction while queued on {key}"
        )


def test_low_pyproject_pins_match_requirements_in():
    """LOW item h: the direct-dependency pins pyproject hands to uv stay
    aligned with requirements.in — the drift this audit found (alembic
    1.20.0/asyncpg 0.31.0 locked against 1.19.2/0.30.0) cannot silently
    return."""
    import re
    from pathlib import Path

    backend = Path(__file__).resolve().parents[1]
    req = (backend / "requirements.in").read_text()
    pyproject = (backend / "pyproject.toml").read_text()
    for package in ("alembic", "asyncpg"):
        m = re.search(rf"^{package}==(\S+)", req, re.MULTILINE)
        assert m, f"{package} missing from requirements.in"
        pin = re.search(rf'"{package}==([^"]+)"', pyproject)
        assert pin, f"{package} missing (or not exact-pinned) in pyproject.toml"
        assert pin.group(1) == m.group(1), (
            f"{package} drift: requirements.in pins {m.group(1)} but "
            f"pyproject pins {pin.group(1)}"
        )
