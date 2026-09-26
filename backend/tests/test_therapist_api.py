"""The therapist sharing feature at the API level.

The claims under test, in order of consequence:

  * ROLE SEPARATION — a therapist token has no journal path, a patient
    token has no therapist path. Read-only-for-the-therapist is enforced
    by the absence of endpoints, not by UI convention.
  * PAIRING — codes are short-lived, single-use, and every dead variant
    (unknown / expired / consumed) answers the same 404.
  * CONSENT — granting requires the password verifier; revoking clears
    the wrapped key; the grant burns the code.
  * ISOLATION — therapist B cannot read therapist A's patient, and a
    revoked patient is indistinguishable from an unknown one.
  * ZERO-KNOWLEDGE READS — the blobs the therapist endpoint serves are
    exactly the blobs the patient's app serves, and decrypt under the
    therapist's unwrapped key (the full E2E path).
  * AUDIT — every grant/revoke and patient-data read/write leaves an
    access_log row; the log outlives account deletion.
"""

from __future__ import annotations

import base64
import asyncio
import json
from datetime import date, timedelta

import pytest
from sqlalchemy import select, update

from app.api.therapist import THERAPIST_ENTRY_PAGE_SIZE, THERAPIST_ENTRY_RESPONSE_BLOB_BYTES
from app.models import (
    ROLE_THERAPIST,
    AccessLog,
    Consent,
    Entry,
    PairingCode,
    TherapistNote,
    User,
    new_id,
    utcnow,
)
from app.security import crypto
from tests.helpers import ClientEmulator, TherapistEmulator, daterange

TODAY = date.today()
WORK_ANXIOUS = (
    "Deadline at work monday, the boss piled on another project and a "
    "late meeting. Anxious, stressed, dreading the presentation."
)
CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


async def _seed(client, emu: ClientEmulator, days: int = 70) -> None:
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        text = WORK_ANXIOUS if day.weekday() == 6 else CALM
        await emu.create_entry(client, text, day, client_entry_id=f"e-{day.isoformat()}")


async def _grant(client, patient: ClientEmulator, therapist: TherapistEmulator) -> dict:
    """The full happy-path grant; returns the consent body."""
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    assert lookup["status"] == 200, lookup
    return await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )


async def _audit(client) -> list[AccessLog]:
    app = client._transport.app  # noqa: SLF001 — test reachability into state
    async with app.state.sessionmaker() as session:
        return list(
            (await session.execute(select(AccessLog).order_by(AccessLog.at, AccessLog.id)))
            .scalars()
            .all()
        )


async def _expire_all_pairing_codes(client) -> None:
    from app.models import utcnow

    app = client._transport.app  # noqa: SLF001
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(PairingCode).values(expires_at=utcnow() - timedelta(minutes=1))
        )
        await session.commit()


# --- registration & roles ------------------------------------------------------


async def test_therapist_register_login_me(client):
    th = TherapistEmulator("dromega", "pw-therapist", "Dr. Omega")
    body = await th.register(client)
    assert body["role"] == "therapist"

    login = await th.login(client)
    assert login["role"] == "therapist"

    me = await client.get("/api/therapist/me", headers=th.headers)
    assert me.status_code == 200
    me_body = me.json()
    assert me_body["display_name"] == "Dr. Omega"
    assert me_body["username"] == "dromega"
    assert me_body["wrap_pub_key"] == th.wrap_pub_key
    # The stored blob must be the (encrypted) private key, decryptable by
    # the therapist's own password-derived KEK — the portal unlock path.
    private = th.unlock_private_key()
    assert private.curve.name == "secp256r1"


async def test_patient_login_reports_user_role(client):
    emu = ClientEmulator("roleuser", "pw-user")
    body = await emu.register(client)
    assert body["role"] == "user"
    assert (await emu.login(client))["role"] == "user"


async def test_therapist_register_validation(client):
    th = TherapistEmulator("drvalidate", "pw", "Dr. Validate")
    bad_bodies = [
        # salt not 16 bytes
        {"salt": base64.b64encode(b"x" * 15).decode()},
        # verifier not 32 bytes
        {"verifier": base64.b64encode(b"x" * 31).decode()},
        # wrap_pub_key not a P-256 SPKI key
        {"wrap_pub_key": base64.b64encode(b"garbage-key").decode()},
        # wrap_key_blob too short to be an envelope
        {"wrap_key_blob": base64.b64encode(b"xx").decode()},
        # display_name with control characters
        {"display_name": "Dr.\nValidate"},
    ]
    for patch in bad_bodies:
        payload = {
            "username": th.username,
            "salt": th.salt_b64,
            "verifier": th.auth_key_b64,
            "display_name": th.display_name,
            "wrap_pub_key": th.wrap_pub_key,
            "wrap_key_blob": th.wrap_key_blob_b64(),
        }
        payload.update(patch)
        response = await client.post("/api/therapist/register", json=payload)
        assert response.status_code == 422, (patch, response.text)
        assert response.json()["code"] == "validation_error"


async def test_therapist_username_namespace_shared_with_patients(client):
    patient = ClientEmulator("samename", "pw")
    await patient.register(client)
    th = TherapistEmulator("samename", "pw-therapist")
    payload = {
        "username": th.username,
        "salt": th.salt_b64,
        "verifier": th.auth_key_b64,
        "display_name": th.display_name,
        "wrap_pub_key": th.wrap_pub_key,
        "wrap_key_blob": th.wrap_key_blob_b64(),
    }
    response = await client.post("/api/therapist/register", json=payload)
    assert response.status_code == 409
    assert response.json()["code"] == "conflict"


async def test_therapist_register_conflict_counts_against_name_bucket(client):
    th = TherapistEmulator("dupname", "pw")
    await th.register(client)
    response = await client.post(
        "/api/therapist/register",
        json={
            "username": "dupname",
            "salt": th.salt_b64,
            "verifier": th.auth_key_b64,
            "display_name": "Impostor",
            "wrap_pub_key": th.wrap_pub_key,
            "wrap_key_blob": th.wrap_key_blob_b64(),
        },
    )
    assert response.status_code == 409


class TestRoleSeparation:
    async def test_therapist_cannot_use_journal_endpoints(self, client):
        th = TherapistEmulator("drx", "pw")
        await th.register(client)
        checks = [
            client.post(
                "/api/entries",
                headers=th.headers,
                json={
                    "client_entry_id": "e1",
                    "blob": base64.b64encode(b"x" * 40).decode(),
                    "entry_date": TODAY.isoformat(),
                },
            ),
            client.get("/api/entries", headers=th.headers),
            client.get("/api/insights", headers=th.headers),
            client.post(
                "/api/processing/sessions",
                headers=th.headers,
                json={"data_key": base64.b64encode(b"k" * 32).decode()},
            ),
            client.get("/api/account/export", headers=th.headers),
            client.post("/api/insights/recompute", headers=th.headers),
        ]
        for coro in checks:
            response = await coro
            assert response.status_code == 403, response.text
            assert response.json()["code"] == "forbidden"

    async def test_patient_cannot_use_therapist_endpoints(self, client):
        emu = ClientEmulator("plainuser", "pw")
        await emu.register(client)
        checks = [
            client.get("/api/therapist/patients", headers=emu.headers),
            client.post("/api/therapist/pairing-codes", headers=emu.headers),
            client.get("/api/therapist/me", headers=emu.headers),
            client.get("/api/therapist/patients/xyz/insights", headers=emu.headers),
            client.post(
                "/api/therapist/patients/xyz/notes",
                headers=emu.headers,
                json={"client_note_id": "n1", "blob": base64.b64encode(b"x" * 40).decode()},
            ),
        ]
        for coro in checks:
            response = await coro
            assert response.status_code == 403, response.text
            assert response.json()["code"] == "forbidden"

    async def test_anonymous_cannot_use_either(self, client):
        for coro in (
            client.get("/api/therapist/patients"),
            client.get("/api/consents"),
            client.post("/api/consents/pairing/lookup", json={"code": "AB2C4D6F"}),
        ):
            response = await coro
            assert response.status_code == 401


# --- pairing ------------------------------------------------------------------


class TestPairing:
    async def test_create_and_lookup(self, client):
        th = TherapistEmulator("drpair", "pw")
        await th.register(client)
        patient = ClientEmulator("pairpatient", "pw")
        await patient.register(client)

        code = await th.create_pairing_code(client)
        assert len(code) == 8

        result = await patient.pairing_lookup(client, code.lower())  # case-insensitive
        assert result["status"] == 200
        assert result["body"]["therapist_id"] == th.user_id
        assert result["body"]["display_name"] == th.display_name
        assert result["body"]["wrap_pub_key"] == th.wrap_pub_key

    async def test_lookup_does_not_burn(self, client):
        th = TherapistEmulator("drburn", "pw")
        await th.register(client)
        patient = ClientEmulator("burnpatient", "pw")
        await patient.register(client)
        code = await th.create_pairing_code(client)
        for _ in range(2):
            assert (await patient.pairing_lookup(client, code))["status"] == 200
        grant = await patient.grant_consent(client, code, th.wrap_pub_key, th.user_id)
        assert grant["status"] == 201

    async def test_unknown_code_404(self, client):
        patient = ClientEmulator("unknowncode", "pw")
        await patient.register(client)
        result = await patient.pairing_lookup(client, "ZZZZZZZZ")
        assert result["status"] == 404
        assert result["body"]["code"] == "not_found"

    async def test_non_ascii_pairing_code_is_flat_404(self, client):
        th = TherapistEmulator("drunicode", "pw")
        await th.register(client)
        patient = ClientEmulator("unicodepatient", "pw")
        await patient.register(client)

        # The server must not leak a UnicodeEncodeError as a 500 while
        # calculating the digest for either public code path.
        bad_code = "\u00e9" * 8
        lookup = await patient.pairing_lookup(client, bad_code)
        assert lookup["status"] == 404
        assert lookup["body"]["code"] == "not_found"
        grant = await patient.grant_consent(client, bad_code, th.wrap_pub_key, th.user_id)
        assert grant["status"] == 404
        assert grant["body"]["code"] == "not_found"

    async def test_expired_code_404(self, client):
        th = TherapistEmulator("drexpire", "pw")
        await th.register(client)
        patient = ClientEmulator("expirepatient", "pw")
        await patient.register(client)
        code = await th.create_pairing_code(client)
        await _expire_all_pairing_codes(client)
        assert (await patient.pairing_lookup(client, code))["status"] == 404
        grant = await patient.grant_consent(client, code, th.wrap_pub_key, th.user_id)
        assert grant["status"] == 404

    async def test_grant_burns_code(self, client):
        th = TherapistEmulator("drburn2", "pw")
        await th.register(client)
        patient = ClientEmulator("burnpatient2", "pw")
        await patient.register(client)
        code = await th.create_pairing_code(client)
        grant = await patient.grant_consent(client, code, th.wrap_pub_key, th.user_id)
        assert grant["status"] == 201
        # The same code cannot be looked up (or granted) again — not even
        # by another patient.
        other = ClientEmulator("burnpatient3", "pw")
        await other.register(client)
        assert (await other.pairing_lookup(client, code))["status"] == 404
        assert (await other.grant_consent(client, code, th.wrap_pub_key, th.user_id))[
            "status"
        ] == 404

    async def test_pairing_code_ttl_reported(self, client):
        th = TherapistEmulator("drttl", "pw")
        await th.register(client)
        response = await client.post("/api/therapist/pairing-codes", headers=th.headers)
        assert response.status_code == 201
        assert response.json()["expires_in"] == 900


# --- consent grant / revoke -----------------------------------------------------


class TestConsentGrant:
    async def test_happy_path_grant_lists(self, client):
        patient = ClientEmulator("grantme", "pw")
        await patient.register(client)
        th = TherapistEmulator("drgrant", "pw")
        await th.register(client)
        grant = await _grant(client, patient, th)
        assert grant["status"] == 201
        body = grant["body"]
        assert body["status"] == "active"
        assert body["display_name"] == th.display_name
        assert body["username"] == th.username
        assert body["therapist_id"] == th.user_id

        consents = await patient.list_consents(client)
        assert len(consents) == 1
        assert consents[0]["id"] == body["id"]

    async def test_grant_requires_verifier_header(self, client):
        from app.api.consents import SHARING_DISCLOSURE_VERSION

        patient = ClientEmulator("noverify", "pw")
        await patient.register(client)
        th = TherapistEmulator("drnv", "pw")
        await th.register(client)
        code = await th.create_pairing_code(client)
        wrap = {
            "ephemeral_pub": th.wrap_pub_key,
            "wrapped_key": base64.b64encode(b"x" * 60).decode(),
        }
        response = await client.post(
            "/api/consents",
            headers=patient.headers,
            json={"code": code, **wrap, "disclosure": SHARING_DISCLOSURE_VERSION},
        )
        assert response.status_code == 422

    async def test_grant_rejects_wrong_verifier(self, client):
        patient = ClientEmulator("wrongverify", "pw")
        await patient.register(client)
        th = TherapistEmulator("drwv", "pw")
        await th.register(client)
        code = await th.create_pairing_code(client)
        grant = await patient.grant_consent(
            client, code, th.wrap_pub_key, th.user_id, verifier=base64.b64encode(b"b" * 32).decode()
        )
        assert grant["status"] == 403
        assert grant["body"]["code"] == "verification_failed"
        # The code is NOT burned by a failed grant.
        retry = await patient.grant_consent(client, code, th.wrap_pub_key, th.user_id)
        assert retry["status"] == 201

    async def test_grant_validation(self, client):
        from app.api.consents import SHARING_DISCLOSURE_VERSION

        patient = ClientEmulator("grantvalid", "pw")
        await patient.register(client)
        th = TherapistEmulator("drgv", "pw")
        await th.register(client)
        code = await th.create_pairing_code(client)
        cases = [
            {"ephemeral_pub": base64.b64encode(b"not-a-key").decode()},  # invalid SPKI
            {"wrapped_key": base64.b64encode(b"short").decode()},  # under MIN_BLOB_SIZE
            {"wrapped_key": base64.b64encode(b"x" * 300).decode()},  # over cap
            {"wrapped_key": "!!not-b64!!"},
            {"disclosure": None},  # required field absent
        ]
        for patch in cases:
            payload = {
                "code": code,
                "ephemeral_pub": th.wrap_pub_key,
                "wrapped_key": base64.b64encode(b"x" * 60).decode(),
                "disclosure": SHARING_DISCLOSURE_VERSION,
            }
            payload.update(patch)
            response = await client.post(
                "/api/consents",
                headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
                json=payload,
            )
            assert response.status_code == 422, (patch, response.text)

    async def test_grant_with_unknown_code_404(self, client):
        patient = ClientEmulator("grant404", "pw")
        await patient.register(client)
        th = TherapistEmulator("dr404", "pw")
        await th.register(client)
        grant = await patient.grant_consent(client, "ZZZZ9999", th.wrap_pub_key, th.user_id)
        assert grant["status"] == 404

    async def test_regrant_reactivates_same_row(self, client):
        patient = ClientEmulator("regrant", "pw")
        await patient.register(client)
        th = TherapistEmulator("drre", "pw")
        await th.register(client)
        first = await _grant(client, patient, th)
        consent_id = first["body"]["id"]
        assert (await patient.revoke_consent(client, consent_id)) == 204

        second = await _grant(client, patient, th)
        assert second["status"] == 201
        assert second["body"]["id"] == consent_id  # same pair, same row
        consents = await patient.list_consents(client)
        assert len(consents) == 1
        assert consents[0]["status"] == "active"
        assert consents[0]["revoked_at"] is None

    async def test_consent_list_cap_is_explicit_and_does_not_burn_pairing_code(
        self, client, monkeypatch
    ):
        """Preserve the mobile complete-list contract at a bounded size."""
        from app.api import consents as consents_api

        monkeypatch.setattr(consents_api, "MAX_CONSENTS_PER_PATIENT", 1)
        patient = ClientEmulator("sharecap", "pw")
        await patient.register(client)
        target = TherapistEmulator("drcap", "pw")
        await target.register(client)

        async def add_prior_share(label: str) -> None:
            app = client._transport.app  # noqa: SLF001 — compact test fixture setup
            async with app.state.sessionmaker() as session:
                therapist_id = new_id()
                session.add(
                    User(
                        id=therapist_id,
                        username=f"prior-{label}",
                        salt="c2FsdA==",
                        verifier=b"v",
                        scrypt_salt=b"s",
                        role=ROLE_THERAPIST,
                        display_name="Prior therapist",
                        wrap_pub_key="not-used-by-this-test",
                    )
                )
                await session.flush()
                session.add(
                    Consent(
                        user_id=patient.user_id,
                        therapist_id=therapist_id,
                        status="active",
                    )
                )
                await session.commit()

        await add_prior_share("one")
        assert len(await patient.list_consents(client)) == 1

        code = await target.create_pairing_code(client)
        denied = await patient.grant_consent(client, code, target.wrap_pub_key, target.user_id)
        assert denied["status"] == 413
        assert denied["body"]["code"] == "payload_too_large"
        # The quota preflight runs before the conditional code-consumption
        # update, so a later revoke lets this same code be retried.
        assert (await patient.pairing_lookup(client, code))["status"] == 200

        await add_prior_share("two")
        oversized = await client.get("/api/consents", headers=patient.headers)
        assert oversized.status_code == 413
        assert oversized.json()["code"] == "payload_too_large"


class TestConsentRevoke:
    async def _granted(self, client):
        patient = ClientEmulator("revokeme", "pw")
        await patient.register(client)
        th = TherapistEmulator("drrev", "pw")
        await th.register(client)
        grant = await _grant(client, patient, th)
        return patient, th, grant["body"]["id"]

    async def test_revoke_clears_key_material(self, client):
        patient, th, consent_id = await self._granted(client)
        assert (await patient.revoke_consent(client, consent_id)) == 204
        consents = await patient.list_consents(client)
        assert consents[0]["status"] == "revoked"
        assert consents[0]["revoked_at"] is not None

        # The therapist's patient list must not carry key material anymore.
        patients = (await client.get("/api/therapist/patients", headers=th.headers)).json()
        assert patients[0]["status"] == "revoked"
        assert patients[0]["wrapped_key"] is None
        assert patients[0]["ephemeral_pub"] is None

    async def test_revoke_idempotent(self, client):
        patient, _, consent_id = await self._granted(client)
        assert (await patient.revoke_consent(client, consent_id)) == 204
        assert (await patient.revoke_consent(client, consent_id)) == 204

    async def test_revoke_requires_verifier(self, client):
        patient, _, consent_id = await self._granted(client)
        response = await client.request(
            "DELETE", f"/api/consents/{consent_id}", headers=patient.headers
        )
        assert response.status_code == 422
        wrong = await client.request(
            "DELETE",
            f"/api/consents/{consent_id}",
            headers={**patient.headers, "X-Account-Verifier": base64.b64encode(b"z" * 32).decode()},
        )
        assert wrong.status_code == 403

    async def test_revoke_unknown_consent_404(self, client):
        patient, _, _ = await self._granted(client)
        assert (await patient.revoke_consent(client, "nosuchid")) == 404

    async def test_cannot_revoke_another_patients_consent(self, client):
        patient, _, consent_id = await self._granted(client)
        other = ClientEmulator("otherrevoke", "pw")
        await other.register(client)
        assert (await other.revoke_consent(client, consent_id)) == 404


# --- therapist reads -------------------------------------------------------------


class TestTherapistReads:
    async def _shared_patient(self, client, days: int = 40):
        patient = ClientEmulator("sharedp", "pw")
        await patient.register(client)
        await _seed(client, patient, days=days)
        th = TherapistEmulator("drread", "pw")
        await th.register(client)
        grant = await _grant(client, patient, th)
        assert grant["status"] == 201
        return patient, th

    async def test_patients_list_shape(self, client):
        patient, th = await self._shared_patient(client)
        response = await client.get("/api/therapist/patients", headers=th.headers)
        assert response.status_code == 200
        body = response.json()
        assert len(body) == 1
        assert body[0]["user_id"] == patient.user_id
        assert body[0]["username"] == "sharedp"
        assert body[0]["status"] == "active"
        assert body[0]["ephemeral_pub"]
        assert base64.b64decode(body[0]["wrapped_key"])

    async def test_patient_list_cap_is_explicit_and_grant_preserves_code(self, client, monkeypatch):
        from app.api import consents as consents_api
        from app.api import therapist as therapist_api

        # Small test seam; production keeps a 100-record total cap.  Patch
        # both modules because therapist.py imports the shared constant for
        # its legacy-data list guard.
        monkeypatch.setattr(consents_api, "MAX_PATIENTS_PER_THERAPIST", 1)
        monkeypatch.setattr(therapist_api, "MAX_PATIENTS_PER_THERAPIST", 1)
        th = TherapistEmulator("drcaseload", "pw")
        await th.register(client)
        patient = ClientEmulator("caseloadtarget", "pw")
        await patient.register(client)

        async def add_prior_patient(label: str) -> None:
            app = client._transport.app  # noqa: SLF001 — compact test fixture setup
            async with app.state.sessionmaker() as session:
                prior_id = new_id()
                session.add(
                    User(
                        id=prior_id,
                        username=f"prior-patient-{label}",
                        salt="c2FsdA==",
                        verifier=b"v",
                        scrypt_salt=b"s",
                    )
                )
                await session.flush()
                session.add(
                    Consent(
                        user_id=prior_id,
                        therapist_id=th.user_id,
                        status="active",
                    )
                )
                await session.commit()

        await add_prior_patient("one")
        first = await client.get("/api/therapist/patients", headers=th.headers)
        assert first.status_code == 200
        assert len(first.json()) == 1

        code = await th.create_pairing_code(client)
        denied = await patient.grant_consent(client, code, th.wrap_pub_key, th.user_id)
        assert denied["status"] == 413
        assert denied["body"]["code"] == "payload_too_large"
        assert (await patient.pairing_lookup(client, code))["status"] == 200

        await add_prior_patient("two")
        oversized = await client.get("/api/therapist/patients", headers=th.headers)
        assert oversized.status_code == 413
        assert oversized.json()["code"] == "payload_too_large"

    async def test_insights_blob_identical_to_patient_view(self, client):
        patient, th = await self._shared_patient(client)
        await patient.recompute(client)
        own = await client.get("/api/insights", headers=patient.headers)
        via_therapist = await client.get(
            f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers
        )
        assert via_therapist.status_code == 200
        assert via_therapist.json()["blob"] == own.json()["blob"]
        assert via_therapist.json()["phase"] == own.json()["phase"]

    async def test_entries_served_and_decryptable_by_therapist(self, client):
        # The full zero-knowledge path: the therapist unwraps the data key
        # and decrypts an entry blob the patient's app encrypted.
        patient, th = await self._shared_patient(client, days=5)
        patients = (await client.get("/api/therapist/patients", headers=th.headers)).json()
        data_key = th.unwrap_patient_data_key(
            patient, patients[0]["ephemeral_pub"], patients[0]["wrapped_key"]
        )
        assert data_key == patient.data_key

        entries = (
            await client.get(
                f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers
            )
        ).json()
        assert len(entries) == 5
        # Date-ascending, and each blob decrypts with the entry AAD binding.
        dates = [e["entry_date"] for e in entries]
        assert dates == sorted(dates)
        payload = json.loads(
            crypto.decrypt(
                data_key,
                base64.b64decode(entries[0]["blob"]),
                crypto.build_aad("entry", patient.user_id, entries[0]["client_entry_id"]),
            )
        )
        assert payload["text"]

    async def test_entries_since_until_window(self, client):
        patient, th = await self._shared_patient(client, days=10)
        window_start, window_end = TODAY - timedelta(days=5), TODAY - timedelta(days=3)
        response = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"since": window_start.isoformat(), "until": window_end.isoformat()},
        )
        dates = [e["entry_date"] for e in response.json()]
        assert dates and all(window_start.isoformat() <= d <= window_end.isoformat() for d in dates)

    async def test_entries_pagination(self, client):
        patient, th = await self._shared_patient(client, days=10)
        first = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"limit": 4, "page_bytes": THERAPIST_ENTRY_RESPONSE_BLOB_BYTES},
        )
        second = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"limit": 4, "offset": 4, "page_bytes": THERAPIST_ENTRY_RESPONSE_BLOB_BYTES},
        )
        page1 = first.json()
        page2 = second.json()
        assert len(page1) == 4 and len(page2) == 4
        assert page1[-1]["id"] != page2[0]["id"]
        ids = [e["id"] for e in page1 + page2]
        assert len(set(ids)) == 8
        assert first.headers["X-Next-Offset"] == "4"
        assert second.headers["X-Next-Offset"] == "8"

    async def test_entries_default_page_is_25_and_exposes_an_exact_continuation(self, client):
        patient, th = await self._shared_patient(client, days=THERAPIST_ENTRY_PAGE_SIZE + 1)
        first = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
        )
        assert first.status_code == 200
        assert len(first.json()) == THERAPIST_ENTRY_PAGE_SIZE
        assert first.headers["X-Next-Offset"] == str(THERAPIST_ENTRY_PAGE_SIZE)

        second = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"offset": THERAPIST_ENTRY_PAGE_SIZE},
        )
        assert second.status_code == 200
        assert len(second.json()) == 1
        assert "X-Next-Offset" not in second.headers

        too_many = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"limit": THERAPIST_ENTRY_PAGE_SIZE + 1},
        )
        assert too_many.status_code == 422

    async def test_entries_byte_budget_requires_opt_in_and_returns_a_continuation(self, client):
        # Two individually valid-size ciphertext blobs exceed the cumulative
        # response budget. Seed directly so the test exercises response
        # selection rather than request-body handling.
        patient, th = await self._shared_patient(client, days=0)
        raw_blob = b"x" * (THERAPIST_ENTRY_RESPONSE_BLOB_BYTES // 2 + 1)
        app = client._transport.app  # noqa: SLF001 - fixture application state
        async with app.state.sessionmaker() as session:
            session.add_all(
                [
                    Entry(
                        user_id=patient.user_id,
                        client_entry_id="large-a",
                        blob=raw_blob,
                        entry_date=TODAY,
                    ),
                    Entry(
                        user_id=patient.user_id,
                        client_entry_id="large-b",
                        blob=raw_blob,
                        entry_date=TODAY,
                    ),
                ]
            )
            await session.commit()

        legacy = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers
        )
        assert legacy.status_code == 413
        assert legacy.json()["code"] == "payload_too_large"

        first = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"page_bytes": THERAPIST_ENTRY_RESPONSE_BLOB_BYTES},
        )
        assert first.status_code == 200
        first_rows = first.json()
        assert len(first_rows) == 1
        assert first.headers["X-Next-Offset"] == "1"
        assert (
            sum(len(base64.b64decode(row["blob"])) for row in first_rows)
            <= THERAPIST_ENTRY_RESPONSE_BLOB_BYTES
        )

        second = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries",
            headers=th.headers,
            params={"offset": 1, "page_bytes": THERAPIST_ENTRY_RESPONSE_BLOB_BYTES},
        )
        assert second.status_code == 200
        assert len(second.json()) == 1
        assert "X-Next-Offset" not in second.headers

    async def test_baseline_phase_patient_gets_no_blob(self, client):
        patient, th = await self._shared_patient(client, days=5)
        response = await client.get(
            f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers
        )
        assert response.status_code == 200
        body = response.json()
        assert body["phase"] == "baseline"
        assert body["blob"] is None

    async def test_revoked_consent_reads_404(self, client):
        patient, th = await self._shared_patient(client)
        consents = await patient.list_consents(client)
        assert (await patient.revoke_consent(client, consents[0]["id"])) == 204
        for path in ("insights", "entries"):
            response = await client.get(
                f"/api/therapist/patients/{patient.user_id}/{path}", headers=th.headers
            )
            assert response.status_code == 404
            assert response.json()["code"] == "not_found"

    async def test_revoke_serializes_with_an_inflight_content_read(self, client, monkeypatch):
        """A read that won the fence linearizes before revoke; the next read
        must see the committed revoke. Without the shared patient lock, the
        DELETE can commit while the paused read still returns journal rows."""
        from app.api import therapist as therapist_api
        from app.locks import sharing_locks, sharing_patient_lock_key

        patient, th = await self._shared_patient(client, days=1)
        consent_id = (await patient.list_consents(client))[0]["id"]
        real_active_consent = therapist_api._active_consent
        entered = asyncio.Event()
        release = asyncio.Event()
        paused = False

        async def paused_active_consent(*args, **kwargs):
            nonlocal paused
            consent = await real_active_consent(*args, **kwargs)
            if not paused:
                paused = True
                entered.set()
                await release.wait()
            return consent

        monkeypatch.setattr(therapist_api, "_active_consent", paused_active_consent)
        read = asyncio.create_task(
            client.get(f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers)
        )
        await asyncio.wait_for(entered.wait(), timeout=2)
        revoke = asyncio.create_task(patient.revoke_consent(client, consent_id))
        key = sharing_patient_lock_key(patient.user_id or "")
        for _ in range(200):
            entry = sharing_locks._locks.get(key)  # noqa: SLF001 - lock-order regression
            if entry is not None and entry.refs >= 2:
                break
            await asyncio.sleep(0.005)
        else:
            release.set()
            await asyncio.gather(read, revoke)
            raise AssertionError("revoke never queued behind the content-read sharing fence")
        assert revoke.done() is False

        release.set()
        read_response, revoke_status = await asyncio.gather(read, revoke)
        assert read_response.status_code == 200
        assert revoke_status == 204
        after = await client.get(
            f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers
        )
        assert after.status_code == 404

    async def test_cross_therapist_isolation(self, client):
        patient, th_a = await self._shared_patient(client)
        th_b = TherapistEmulator("drb", "pw")
        await th_b.register(client)
        # Therapist B has their OWN patient and consent; asking for A's
        # patient must 404 exactly like an unknown id.
        for target in (patient.user_id, "0" * 32):
            response = await client.get(
                f"/api/therapist/patients/{target}/insights", headers=th_b.headers
            )
            assert response.status_code == 404

    async def test_oversized_user_id_404(self, client):
        _, th = await self._shared_patient(client)
        response = await client.get(
            f"/api/therapist/patients/{'x' * 64}/insights", headers=th.headers
        )
        assert response.status_code == 404


# --- notes -----------------------------------------------------------------------


class TestNotes:
    async def _shared(self, client):
        patient = ClientEmulator("notep", "pw")
        await patient.register(client)
        th = TherapistEmulator("drnote", "pw")
        await th.register(client)
        grant = await _grant(client, patient, th)
        assert grant["status"] == 201
        return patient, th

    async def test_create_list_update_delete(self, client):
        patient, th = await self._shared(client)
        blob = th.encrypt_note(patient, "note-1", "Session 1: patient reports better sleep.")
        created = await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "note-1", "pattern_pid": "temporal:work", "blob": blob},
        )
        assert created.status_code == 201
        note = created.json()
        assert note["pattern_pid"] == "temporal:work"
        assert th.decrypt_note(patient, "note-1", note["blob"])["text"].startswith("Session 1")

        listed = (
            await client.get(f"/api/therapist/patients/{patient.user_id}/notes", headers=th.headers)
        ).json()
        assert len(listed) == 1

        updated = await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=th.headers,
            json={"blob": th.encrypt_note(patient, "note-1", "Updated impression.")},
        )
        assert updated.status_code == 200
        assert updated.json()["updated_at"] >= note["updated_at"]
        # Same client_note_id AAD still decrypts the updated blob.
        assert (
            th.decrypt_note(patient, "note-1", updated.json()["blob"])["text"]
            == "Updated impression."
        )

        assert (
            await client.delete(f"/api/therapist/notes/{note['id']}", headers=th.headers)
        ).status_code == 204
        assert (
            await client.get(f"/api/therapist/patients/{patient.user_id}/notes", headers=th.headers)
        ).json() == []
        actions = [row.action for row in await _audit(client)]
        assert "write_note" in actions
        assert "update_note" in actions
        assert "delete_note" in actions

    async def test_update_delete_race_is_serialized_and_never_500(self, client):
        patient, th = await self._shared(client)
        created = await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={
                "client_note_id": "race-note",
                "blob": th.encrypt_note(patient, "race-note", "before race"),
            },
        )
        assert created.status_code == 201
        note_id = created.json()["id"]
        update, removal = await asyncio.gather(
            client.patch(
                f"/api/therapist/notes/{note_id}",
                headers=th.headers,
                json={"blob": th.encrypt_note(patient, "race-note", "concurrent update")},
            ),
            client.delete(f"/api/therapist/notes/{note_id}", headers=th.headers),
        )
        # Depending on which request acquires the chart lock first, update
        # succeeds before delete (200/204) or delete wins (404/204). Neither
        # valid ordering can surface a stale-row 500.
        assert update.status_code in {200, 404}
        assert removal.status_code in {204, 404}
        assert 500 not in {update.status_code, removal.status_code}

    async def test_note_write_response_is_constructed_under_chart_fence(self, client, monkeypatch):
        """A delete cannot interleave after the write commit but before its response."""
        from app.api import therapist as therapist_api

        patient, th = await self._shared(client)
        original_note_out = therapist_api._note_out
        observed_locked: list[bool] = []
        chart_key = f"notes:{th.user_id}:{patient.user_id}"

        def observe_note_out(row):
            entry = therapist_api._note_locks._locks.get(chart_key)  # noqa: SLF001 - fence seam
            observed_locked.append(entry is not None and entry.lock.locked())
            return original_note_out(row)

        monkeypatch.setattr(therapist_api, "_note_out", observe_note_out)
        created = await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={
                "client_note_id": "response-fence",
                "blob": th.encrypt_note(patient, "response-fence", "first"),
            },
        )
        assert created.status_code == 201
        updated = await client.patch(
            f"/api/therapist/notes/{created.json()['id']}",
            headers=th.headers,
            json={"blob": th.encrypt_note(patient, "response-fence", "second")},
        )
        assert updated.status_code == 200
        assert observed_locked == [True, True]

    async def test_general_note_without_pattern(self, client):
        patient, th = await self._shared(client)
        created = await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={
                "client_note_id": "general-1",
                "blob": th.encrypt_note(patient, "general-1", "Overall: steady."),
            },
        )
        assert created.status_code == 201
        assert created.json()["pattern_pid"] is None

    async def test_create_is_idempotent_on_client_note_id(self, client):
        patient, th = await self._shared(client)

        async def make(text: str):
            return await client.post(
                f"/api/therapist/patients/{patient.user_id}/notes",
                headers=th.headers,
                json={
                    "client_note_id": "same-id",
                    "blob": th.encrypt_note(patient, "same-id", text),
                },
            )

        first = await make("one")
        second = await make("two")
        assert first.status_code == 201 and second.status_code == 201
        assert first.json()["id"] == second.json()["id"]
        listed = (
            await client.get(f"/api/therapist/patients/{patient.user_id}/notes", headers=th.headers)
        ).json()
        assert len(listed) == 1
        assert th.decrypt_note(patient, "same-id", listed[0]["blob"])["text"] == "two"

    async def test_list_byte_budget_requires_opt_in_and_returns_continuation(self, client):
        """A count-bounded page must not serialize a chart-sized response.

        Two individually valid, near-half-budget notes fit within the
        per-note input ceiling but not in the same 2 MiB response page.  The
        A legacy portal's count-only request fails loudly instead of receiving
        a short page it would mistake for complete history.  An opted-in
        portal gets an advancing continuation and can retrieve both.
        """
        from app.api.therapist import NOTES_PAGE_BLOB_BYTES

        patient, th = await self._shared(client)
        raw_blob = b"x" * (NOTES_PAGE_BLOB_BYTES // 2 + 1)
        created = utcnow()
        app = client._transport.app  # noqa: SLF001 — test DB setup
        async with app.state.sessionmaker() as session:
            for index in range(2):
                stamp = created + timedelta(microseconds=index)
                session.add(
                    TherapistNote(
                        therapist_id=th.user_id,
                        user_id=patient.user_id,
                        client_note_id=f"large-{index}",
                        blob=raw_blob,
                        created_at=stamp,
                        updated_at=stamp,
                    )
                )
            await session.commit()

        legacy = await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes?limit=100",
            headers=th.headers,
        )
        assert legacy.status_code == 413
        assert legacy.json()["code"] == "payload_too_large"

        first = await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes?limit=100&page_bytes={NOTES_PAGE_BLOB_BYTES}",
            headers=th.headers,
        )
        assert first.status_code == 200, first.text
        assert [row["client_note_id"] for row in first.json()] == ["large-0"]
        assert first.headers["X-Next-Offset"] == "1"
        assert len(base64.b64decode(first.json()[0]["blob"])) == len(raw_blob)

        second = await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes?limit=100&offset=1&page_bytes={NOTES_PAGE_BLOB_BYTES}",
            headers=th.headers,
        )
        assert second.status_code == 200, second.text
        assert [row["client_note_id"] for row in second.json()] == ["large-1"]
        assert "X-Next-Offset" not in second.headers

    async def test_notes_unknown_patient_404(self, client):
        _, th = await self._shared(client)
        response = await client.post(
            f"/api/therapist/patients/{'0' * 32}/notes",
            headers=th.headers,
            json={"client_note_id": "n", "blob": base64.b64encode(b"x" * 40).decode()},
        )
        assert response.status_code == 404

    async def test_notes_survive_revoke_but_die_with_patient(self, client):
        patient, th = await self._shared(client)
        await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "keep", "blob": th.encrypt_note(patient, "keep", "kept note")},
        )
        consents = await patient.list_consents(client)
        assert (await patient.revoke_consent(client, consents[0]["id"])) == 204
        listed = (
            await client.get(f"/api/therapist/patients/{patient.user_id}/notes", headers=th.headers)
        ).json()
        assert len(listed) == 1  # the therapist's own record outlives the revoke

        assert await patient.delete_account(client) == 204
        response = await client.get(
            f"/api/therapist/patients/{patient.user_id}/notes", headers=th.headers
        )
        assert response.status_code == 404  # the row itself died with the patient

    async def test_other_therapist_cannot_touch_notes(self, client):
        patient, th = await self._shared(client)
        created = await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "mine", "blob": th.encrypt_note(patient, "mine", "mine")},
        )
        note_id = created.json()["id"]
        th2 = TherapistEmulator("drnote2", "pw")
        await th2.register(client)
        assert (
            await client.patch(
                f"/api/therapist/notes/{note_id}",
                headers=th2.headers,
                json={"blob": base64.b64encode(b"x" * 40).decode()},
            )
        ).status_code == 404
        assert (
            await client.delete(f"/api/therapist/notes/{note_id}", headers=th2.headers)
        ).status_code == 404


# --- audit log & cascades ---------------------------------------------------------


class TestAuditAndCascades:
    async def test_audit_rows_for_full_flow(self, client):
        patient = ClientEmulator("auditp", "pw")
        await patient.register(client)
        th = TherapistEmulator("draudit", "pw")
        await th.register(client)
        grant = await _grant(client, patient, th)
        consent_id = grant["body"]["id"]

        await client.get(f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers)
        await client.get(f"/api/therapist/patients/{patient.user_id}/entries", headers=th.headers)
        await client.post(
            f"/api/therapist/patients/{patient.user_id}/notes",
            headers=th.headers,
            json={"client_note_id": "a1", "blob": th.encrypt_note(patient, "a1", "x")},
        )
        await patient.revoke_consent(client, consent_id)

        rows = await _audit(client)
        actions = [(r.action, r.actor_role, r.user_id) for r in rows]
        assert ("grant", "user", patient.user_id) in actions
        assert ("read_insights", "therapist", patient.user_id) in actions
        assert ("read_entries", "therapist", patient.user_id) in actions
        assert ("write_note", "therapist", patient.user_id) in actions
        assert ("revoke", "user", patient.user_id) in actions

    async def test_patient_deletion_cascades_but_audit_survives(self, client):
        patient = ClientEmulator("gonep", "pw")
        await patient.register(client)
        th = TherapistEmulator("drgone", "pw")
        await th.register(client)
        await _grant(client, patient, th)
        await client.get(f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers)

        assert await patient.delete_account(client) == 204

        app = client._transport.app  # noqa: SLF001
        async with app.state.sessionmaker() as session:
            consents = (await session.execute(select(Consent))).scalars().all()
            notes = (await session.execute(select(TherapistNote))).scalars().all()
            logs = (await session.execute(select(AccessLog))).scalars().all()
        assert consents == [] and notes == []
        assert any(log.action == "read_insights" for log in logs)  # audit outlives

        patients = (await client.get("/api/therapist/patients", headers=th.headers)).json()
        assert patients == []

    async def test_therapist_deletion_cascades_consents(self, client):
        patient = ClientEmulator("orphanp", "pw")
        await patient.register(client)
        th = TherapistEmulator("drorphan", "pw")
        await th.register(client)
        await _grant(client, patient, th)
        await th.create_pairing_code(client)

        response = await client.request(
            "DELETE",
            "/api/therapist/account",
            headers={**th.headers, "X-Account-Verifier": th.auth_key_b64},
        )
        assert response.status_code == 204

        app = client._transport.app  # noqa: SLF001
        async with app.state.sessionmaker() as session:
            consents = (await session.execute(select(Consent))).scalars().all()
            codes = (await session.execute(select(PairingCode))).scalars().all()
            users = (await session.execute(select(User))).scalars().all()
        assert consents == [] and codes == []
        assert [u.username for u in users] == ["orphanp"]
        assert await patient.list_consents(client) == []

    async def test_therapist_deletion_requires_verifier(self, client):
        th = TherapistEmulator("drv", "pw")
        await th.register(client)
        response = await client.request("DELETE", "/api/therapist/account", headers=th.headers)
        assert response.status_code == 422

    async def test_therapist_account_delete_survives_a_sharing_shutdown(self, client, app):
        """2026-09-26 audit follow-up (deletion-availability reversal):
        self-erasure is NOT a sharing surface. A feature shutdown must
        block sharing (pairing 404s) while the therapist can still delete
        their own account — restoring the 2026-09-21 guarantee that the
        audit's LOW batch item e had inadvertently retired (a gated delete
        during shutdown stranded right-to-erasure behind a feature flag).
        """
        th = TherapistEmulator("drshutdown", "pw")
        await th.register(client)
        app.state.settings.therapist_sharing_enabled = False

        assert (
            await client.post("/api/therapist/pairing-codes", headers=th.headers)
        ).status_code == 404
        erased = await client.request(
            "DELETE",
            "/api/therapist/account",
            headers={**th.headers, "X-Account-Verifier": th.auth_key_b64},
        )
        assert erased.status_code == 204
        # The account is gone. /me is itself feature-gated, so re-enable
        # sharing first — the deleted credential must then 401 (the 404
        # would be the feature gate, not the user lookup).
        app.state.settings.therapist_sharing_enabled = True
        assert (await client.get("/api/therapist/me", headers=th.headers)).status_code == 401

    async def test_export_carries_share_records(self, client):
        patient = ClientEmulator("exportshare", "pw")
        await patient.register(client)
        th = TherapistEmulator("drexport", "pw")
        await th.register(client)
        await _grant(client, patient, th)
        response = await client.get("/api/account/export", headers=patient.headers)
        assert response.status_code == 200
        bundle = response.json()
        assert bundle["shares"] == [
            {
                "therapist_username": "drexport",
                "therapist_display_name": th.display_name,
                "status": "active",
                "granted_at": bundle["shares"][0]["granted_at"],
                "revoked_at": None,
            }
        ]


# --- evidence drill-down data ------------------------------------------------------


class TestEvidenceDates:
    @staticmethod
    def _advance_a_day(monkeypatch):
        """Recompute-day shim: the brain qualifies statistical patterns on a
        second DISTINCT day, so the corpus must be seen 'tomorrow'."""

        class NextDay(date):
            @classmethod
            def today(cls) -> date:
                return date.today() + timedelta(days=1)

        monkeypatch.setattr("app.api.insights.date_type", NextDay)

    async def _seeded_and_qualified(self, client, monkeypatch, username: str) -> ClientEmulator:
        patient = ClientEmulator(username, "pw")
        await patient.register(client)
        await _seed(client, patient, days=70)
        await patient.recompute(client)
        self._advance_a_day(monkeypatch)
        await patient.recompute(client)
        monkeypatch.undo()
        return patient

    async def test_patterns_carry_evidence_dates(self, client, monkeypatch):
        patient = await self._seeded_and_qualified(client, monkeypatch, "evidencep")
        payload = await patient.decrypt_insights(client)
        patterns = payload["stats"]["patterns"]
        assert patterns, "the seeded corpus must surface patterns"
        seeded = {d.isoformat() for d in daterange(70, TODAY)}
        for pattern in patterns:
            detail = pattern["detail"]
            dates = detail["evidence_dates"]
            assert isinstance(dates, list) and dates
            assert len(dates) <= 60  # EVIDENCE_DATES_CAP
            assert all(d in seeded for d in dates), "evidence must be real corpus days"
            # The stable pattern id for note attachment. Pids are
            # "<kind>:..." for theme/statistical patterns; the phrase
            # cluster family uses the kind-agnostic "phrase:<digest>"
            # namespace (2026-09-20: the pid no longer embeds the
            # classification kind, so a cluster whose mean negativity
            # oscillates cannot flip its own pid).
            assert detail["pattern_pid"]
            assert detail["pattern_pid"].startswith(pattern["kind"]) or detail[
                "pattern_pid"
            ].startswith("phrase:")

    async def test_therapist_sees_evidence_dates_after_e2e_decrypt(self, client, monkeypatch):
        # Full loop: patient surfaces patterns, shares; the therapist
        # unwraps the data key and decrypts the SAME payload — drill-down
        # data included.
        patient = await self._seeded_and_qualified(client, monkeypatch, "evidencep2")
        th = TherapistEmulator("drev", "pw")
        await th.register(client)
        await _grant(client, patient, th)
        patients = (await client.get("/api/therapist/patients", headers=th.headers)).json()
        data_key = th.unwrap_patient_data_key(
            patient, patients[0]["ephemeral_pub"], patients[0]["wrapped_key"]
        )
        insights = (
            await client.get(
                f"/api/therapist/patients/{patient.user_id}/insights", headers=th.headers
            )
        ).json()
        plain = json.loads(
            crypto.decrypt(
                data_key,
                base64.b64decode(insights["blob"]),
                crypto.build_aad("insights", patient.user_id, "patterns"),
            )
        )
        with_dates = [p for p in plain["stats"]["patterns"] if p["detail"].get("evidence_dates")]
        assert with_dates, "therapist-decrypted patterns must carry evidence dates"

        # And the drill-down itself: entries for an evidence date decrypt.
        pattern = with_dates[0]
        day = pattern["detail"]["evidence_dates"][-1]
        entries = (
            await client.get(
                f"/api/therapist/patients/{patient.user_id}/entries",
                headers=th.headers,
                params={"since": day, "until": day},
            )
        ).json()
        assert entries, "the pattern's evidence date must have at least one entry"
        entry = entries[0]
        payload = json.loads(
            crypto.decrypt(
                data_key,
                base64.b64decode(entry["blob"]),
                crypto.build_aad("entry", patient.user_id, entry["client_entry_id"]),
            )
        )
        assert payload["text"]


# --- caseload summaries (2026-09-19) ----------------------------------------------


async def test_recompute_wraps_a_summary_the_therapist_can_decrypt(client):
    """The recompute writes a small ECIES-wrapped summary per active
    consent; the therapist's own private key (the portal's unwrap path)
    opens it to the surfaced-pattern metadata."""
    import json as _json

    from app.security import sharing as sharing_crypto

    patient = ClientEmulator("sum-patient", "deep-password")
    await patient.register(client)
    await _seed(client, patient)
    th = TherapistEmulator("sum-dr", "pw-therapist", "Dr. Summary")
    await th.register(client)
    await _grant(client, patient, th)

    # No summary until the first post-grant recompute.
    before = (await client.get("/api/therapist/patients", headers=th.headers)).json()
    assert before[0]["summary_blob"] is None
    assert before[0]["summary_eph_pub"] is None

    await patient.recompute(client)

    after = (await client.get("/api/therapist/patients", headers=th.headers)).json()
    row = after[0]
    assert row["summary_blob"] is not None
    assert row["summary_eph_pub"] is not None
    assert row["summary_updated_at"] is not None
    plain = sharing_crypto.unwrap_summary_payload(
        th.unlock_private_key(),
        row["summary_eph_pub"],
        base64.b64decode(row["summary_blob"]),
        row["user_id"],
        th.user_id,
    )
    summary = _json.loads(plain.decode("utf-8"))
    assert summary["v"] == 1
    assert isinstance(summary["patterns"], int) and summary["patterns"] > 0
    assert summary["sensitive"] is False  # the seeded corpus has no crisis content
    assert isinstance(summary["newest"], str)


async def test_summary_blob_rejects_relocation_between_consents(client):
    """AAD binds (caseload-summary, user, therapist): a summary wrapped for
    one pair must fail authentication when unwrapped as another's."""
    import json as _json

    from app.security import sharing as sharing_crypto

    patient = ClientEmulator("sum-bind", "deep-password")
    await patient.register(client)
    await _seed(client, patient)
    th = TherapistEmulator("sum-bind-dr", "pw-therapist", "Dr. Bind")
    await th.register(client)
    await _grant(client, patient, th)
    await patient.recompute(client)

    row = (await client.get("/api/therapist/patients", headers=th.headers)).json()[0]
    other_id = "not-the-therapist"
    with pytest.raises(Exception):
        sharing_crypto.unwrap_summary_payload(
            th.unlock_private_key(),
            row["summary_eph_pub"],
            base64.b64decode(row["summary_blob"]),
            row["user_id"],
            other_id,
        )


async def test_revoke_clears_the_summary(client):
    patient = ClientEmulator("sum-revoke", "deep-password")
    await patient.register(client)
    await _seed(client, patient)
    th = TherapistEmulator("sum-revoke-dr", "pw-therapist", "Dr. Revoke")
    await th.register(client)
    granted = await _grant(client, patient, th)
    await patient.recompute(client)
    assert (await client.get("/api/therapist/patients", headers=th.headers)).json()[0][
        "summary_blob"
    ] is not None

    await patient.revoke_consent(client, granted["body"]["id"])
    row = (await client.get("/api/therapist/patients", headers=th.headers)).json()[0]
    assert row["status"] == "revoked"
    assert row["summary_blob"] is None
    assert row["summary_eph_pub"] is None
    assert row["summary_updated_at"] is None
