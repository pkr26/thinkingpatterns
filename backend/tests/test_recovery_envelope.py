"""Key-recovery envelope (wave 3, 2026-09-30).

A forgotten password destroys a zero-knowledge journal by design; the
opt-in recovery kit is the honest escape hatch. Server contract under
test: setup (password re-auth, scrypt verifier of the recovery key,
opaque sealed data-key copy), status (no secrets), disable, recovery
LOGIN (decoy burn, epoch bump killing all bearers, therapist refusal),
and the password RESET proven by the recovery key with the same
possession probe as PUT /account/password.
"""

from __future__ import annotations

import base64
import os

import pytest

from app.security import envelope
from tests.helpers import ClientEmulator, EnvelopeClientEmulator

WRAPPED = envelope.WRAPPED_DATA_KEY_BYTES


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def recovery_body(recovery_key: bytes, wrapped: bytes | None = None) -> dict:
    return {
        "password_verifier": None,  # filled per-test (needs the emulator's auth key)
        "verifier": b64(recovery_key),
        "wrapped_key": b64(wrapped or os.urandom(WRAPPED)),
    }


@pytest.fixture
def recovery_key() -> bytes:
    return os.urandom(32)


async def _setup_kit(client, emu: ClientEmulator, key: bytes, wrapped: bytes | None = None) -> None:
    body = recovery_body(key, wrapped)
    body["password_verifier"] = emu.auth_key_b64
    response = await client.put("/api/account/recovery", headers=emu.headers, json=body)
    assert response.status_code == 204, response.text


@pytest.mark.asyncio
class TestRecoveryKitLifecycle:
    async def test_setup_requires_the_password_verifier(self, client, recovery_key):
        emu = ClientEmulator("rec-nopw", "correct horse battery staple")
        await emu.register(client)
        body = recovery_body(recovery_key)
        body["password_verifier"] = base64.b64encode(b"\x00" * 32).decode("ascii")
        response = await client.put("/api/account/recovery", headers=emu.headers, json=body)
        assert response.status_code == 403, response.text

    async def test_status_roundtrip_and_disable(self, client, recovery_key):
        emu = ClientEmulator("rec-life", "correct horse battery staple")
        await emu.register(client)
        before = await client.get("/api/account/recovery", headers=emu.headers)
        assert before.status_code == 200 and before.json()["enabled"] is False

        await _setup_kit(client, emu, recovery_key)
        after = await client.get("/api/account/recovery", headers=emu.headers)
        assert after.json()["enabled"] is True
        assert after.json()["set_at"] is not None
        # No secret material ever rides the status endpoint.
        assert "verifier" not in after.json()
        assert "wrapped" not in after.json()

        gone = await client.delete(
            "/api/account/recovery",
            headers={**emu.headers, "verifier": emu.auth_key_b64},
        )
        assert gone.status_code == 204, gone.text
        final = await client.get("/api/account/recovery", headers=emu.headers)
        assert final.json()["enabled"] is False

    async def test_replacement_rotates_the_old_key_off(self, client, recovery_key):
        emu = ClientEmulator("rec-replace", "correct horse battery staple")
        await emu.register(client)
        await _setup_kit(client, emu, recovery_key)
        newer = os.urandom(32)
        await _setup_kit(client, emu, newer)
        # The OLD key no longer authenticates.
        old = await client.post(
            "/api/auth/recover",
            json={"username": "rec-replace", "verifier": b64(recovery_key)},
        )
        assert old.status_code == 401, old.text


@pytest.mark.asyncio
class TestRecoveryLogin:
    async def test_success_returns_a_session_and_the_sealed_key_and_kills_old_bearers(
        self, client, recovery_key
    ):
        emu = ClientEmulator("rec-login", "correct horse battery staple")
        await emu.register(client)
        sealed = os.urandom(WRAPPED)
        await _setup_kit(client, emu, recovery_key, sealed)

        response = await client.post(
            "/api/auth/recover",
            json={"username": "rec-login", "verifier": b64(recovery_key)},
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["recovery_wrapped_data_key"] == b64(sealed)
        assert body["user_id"] == emu.user_id

        # The epoch bumped: every pre-recovery bearer is dead.
        stale = await client.get("/api/entries", headers=emu.headers)
        assert stale.status_code == 401, stale.text

    async def test_wrong_key_and_unknown_account_both_answer_401(self, client, recovery_key):
        emu = ClientEmulator("rec-wrong", "correct horse battery staple")
        await emu.register(client)
        await _setup_kit(client, emu, recovery_key)
        wrong = await client.post(
            "/api/auth/recover",
            json={"username": "rec-wrong", "verifier": b64(os.urandom(32))},
        )
        assert wrong.status_code == 401
        unknown = await client.post(
            "/api/auth/recover",
            json={"username": "rec-ghost", "verifier": b64(recovery_key)},
        )
        assert unknown.status_code == 401
        nokit = ClientEmulator("rec-nokit", "correct horse battery staple")
        await nokit.register(client)
        no_kit = await client.post(
            "/api/auth/recover",
            json={"username": "rec-nokit", "verifier": b64(recovery_key)},
        )
        assert no_kit.status_code == 401

    async def test_therapists_cannot_recover_through_a_kit(self, client, recovery_key):
        from tests.helpers import TherapistEmulator

        th = TherapistEmulator("rec-therapist", "correct horse battery staple")
        await th.register(client)
        # Even if a kit somehow existed, the endpoint refuses therapists:
        # their second-factor recovery path is the TOTP backup codes.
        response = await client.post(
            "/api/auth/recover",
            json={"username": "rec-therapist", "verifier": b64(recovery_key)},
        )
        assert response.status_code == 401, response.text


@pytest.mark.asyncio
class TestRecoveryPasswordReset:
    async def test_full_flow_reset_proven_by_the_recovery_key(self, client, recovery_key):
        emu = EnvelopeClientEmulator("rec-reset", "correct horse battery staple")
        await emu.register(client)
        await emu.create_entry(
            client, "words that must survive", __import__("datetime").date.today()
        )
        sealed = os.urandom(WRAPPED)
        await _setup_kit(client, emu, recovery_key, sealed)

        recovered = await client.post(
            "/api/auth/recover",
            json={"username": "rec-reset", "verifier": b64(recovery_key)},
        )
        assert recovered.status_code == 200, recovered.text
        recovery_headers = {"Authorization": f"Bearer {recovered.json()['token']}"}

        # The epoch bump killed the emulator's bearer: re-login with the
        # (still-unchanged) password for the possession probe below.
        await emu.login(client)
        # New password wrap for the SAME random data key (v2 semantics —
        # the data key never changes; only its locker does).
        new_wrap = emu.wrap_for("a brand new passphrase", os.urandom(16))
        emu.password = "a brand new passphrase"

        # Possession probe: a session opened with the REAL (unchanged) data key.
        token = await emu.open_processing_session_for(client, emu.data_key)
        response = await client.put(
            "/api/account/recovery/password",
            headers={**recovery_headers, "X-Processing-Token": token},
            json={
                "proof": b64(recovery_key),
                "new_salt": b64(emu.salt),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": new_wrap,
            },
        )
        assert response.status_code == 204, response.text

        # Login with the NEW password works; the corpus still decrypts.
        await emu.login(client)
        rows = await client.get("/api/entries", headers=emu.headers)
        assert rows.status_code == 200
        assert len(rows.json()) == 1

    async def test_reset_rejects_a_wrong_recovery_key(self, client, recovery_key):
        emu = EnvelopeClientEmulator("rec-badproof", "correct horse battery staple")
        await emu.register(client)
        await _setup_kit(client, emu, recovery_key)
        token = await emu.open_processing_session(client)
        response = await client.put(
            "/api/account/recovery/password",
            headers={**emu.headers, "X-Processing-Token": token},
            json={
                "proof": b64(os.urandom(32)),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(WRAPPED)),
            },
        )
        assert response.status_code == 401, response.text

    async def test_reset_requires_the_processing_possession_probe(self, client, recovery_key):
        emu = EnvelopeClientEmulator("rec-noprobe", "correct horse battery staple")
        await emu.register(client)
        await emu.create_entry(client, "encrypted words", __import__("datetime").date.today())
        await _setup_kit(client, emu, recovery_key)
        response = await client.put(
            "/api/account/recovery/password",
            headers=emu.headers,  # no X-Processing-Token at all
            json={
                "proof": b64(recovery_key),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(WRAPPED)),
            },
        )
        assert response.status_code == 422, response.text
        assert response.json()["code"] == "processing_session_required"

    async def test_reset_refuses_an_envelope_over_the_wrong_key(self, client, recovery_key):
        emu = EnvelopeClientEmulator("rec-wrongkey", "correct horse battery staple")
        await emu.register(client)
        await emu.create_entry(
            client, "the real data key owns these words", __import__("datetime").date.today()
        )
        await _setup_kit(client, emu, recovery_key)
        # A session opened with a WRONG key: the probe must refuse the swap.
        token = await emu.open_processing_session_for(client, os.urandom(32))
        response = await client.put(
            "/api/account/recovery/password",
            headers={**emu.headers, "X-Processing-Token": token},
            json={
                "proof": b64(recovery_key),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": emu.auth_key_b64,
                "wrapped_data_key": b64(os.urandom(WRAPPED)),
            },
        )
        assert response.status_code == 403, response.text
        assert response.json()["code"] == "envelope_key_mismatch"
        # And the account's real envelope survived untouched.
        fresh = await client.get("/api/auth/key-envelope", headers=emu.headers)
        assert fresh.status_code == 200
