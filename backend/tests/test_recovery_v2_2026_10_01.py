"""Recovery-kit domain separation v2 (2026-10-01 deep audit C1).

The v1 kit transmitted the RAW recovery key as the server verifier while
the sealed data key was wrapped under HKDF of exactly that key — a server
(or request-logging layer) that observed one setup or recover request
could open the journal. Scheme v2 splits the derivations:

  verifier (sent) = HKDF(recovery_key, "mindpattern/recovery-verifier/v2")
  seal KEK (never sent) = HKDF(recovery_key, "mindpattern/recovery-seal/v2")

The server stores only which scheme a kit uses and verifies opaquely.
Legacy v1 kits keep working only when the caller explicitly declares v1.
New v1 enrollment is retired, and a scheme mismatch is deliberately
indistinguishable from every other invalid recovery proof.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

import pytest

from app.security import envelope
from tests.helpers import ClientEmulator

WRAPPED = envelope.WRAPPED_DATA_KEY_BYTES
VERIFIER_INFO = b"mindpattern/recovery-verifier/v2"
SEAL_INFO = b"mindpattern/recovery-seal/v2"


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def hkdf_info(key: bytes, info: bytes) -> bytes:
    """RFC 5869 extract-and-expand, SHA-256, zero salt, 32 bytes — the
    client's hkdfSha256(key, info) construction."""
    prk = hmac.new(b"\x00" * 32, key, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


@pytest.fixture
def recovery_key() -> bytes:
    return os.urandom(32)


async def _setup_v2(client, emu: ClientEmulator, key: bytes, wrapped: bytes | None = None) -> None:
    body = {
        "password_verifier": emu.auth_key_b64,
        "verifier": b64(hkdf_info(key, VERIFIER_INFO)),
        "wrapped_key": b64(wrapped or os.urandom(WRAPPED)),
        "scheme": "v2",
    }
    response = await client.put("/api/account/recovery", headers=emu.headers, json=body)
    assert response.status_code == 204, response.text


@pytest.mark.asyncio
class TestRecoveryV2:
    async def test_v2_setup_and_login_never_transmit_the_raw_key(self, client, recovery_key):
        emu = ClientEmulator("rec2-raw", "correct horse battery staple")
        await emu.register(client)
        await _setup_v2(client, emu, recovery_key)

        # The stored verifier is scrypt(HKDF(key)) — NOT scrypt(key): a
        # server replaying the v1 comparison against the transmitted
        # verifier must fail, proving the verifier is derived material.
        response = await client.post(
            "/api/auth/recover",
            json={"username": "rec2-raw", "verifier": b64(recovery_key), "scheme": "v2"},
        )
        assert response.status_code == 401, response.text
        assert response.json()["code"] == "invalid_credentials"

    async def test_v2_login_succeeds_with_the_derived_verifier(self, client, recovery_key):
        emu = ClientEmulator("rec2-ok", "correct horse battery staple")
        await emu.register(client)
        sealed = os.urandom(WRAPPED)
        await _setup_v2(client, emu, recovery_key, sealed)

        response = await client.post(
            "/api/auth/recover",
            json={
                "username": "rec2-ok",
                "verifier": b64(hkdf_info(recovery_key, VERIFIER_INFO)),
                "scheme": "v2",
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["recovery_wrapped_data_key"] == b64(sealed)
        assert body["recovery_scheme"] == "v2"

    async def test_status_reports_the_scheme(self, client, recovery_key):
        emu = ClientEmulator("rec2-status", "correct horse battery staple")
        await emu.register(client)
        before = await client.get("/api/account/recovery", headers=emu.headers)
        assert before.json()["scheme"] == "v1"  # no kit yet — the legacy default
        await _setup_v2(client, emu, recovery_key)
        after = await client.get("/api/account/recovery", headers=emu.headers)
        assert after.json()["enabled"] is True
        assert after.json()["scheme"] == "v2"

    async def test_legacy_v1_requires_explicit_scheme_without_oracle(
        self, client, app, recovery_key
    ):
        emu = ClientEmulator("rec2-mism", "correct horse battery staple")
        await emu.register(client)
        sealed = os.urandom(WRAPPED)
        # A legacy v1 kit...
        response = await client.put(
            "/api/account/recovery",
            headers=emu.headers,
            json={
                "password_verifier": emu.auth_key_b64,
                "verifier": b64(recovery_key),
                "wrapped_key": b64(sealed),
                "scheme": "v1",
            },
        )
        assert response.status_code == 409, response.text
        assert response.json()["code"] == "upgrade_required"

        # Simulate a kit enrolled before v1 retirement.
        from app.api.auth import hash_verifier_off_loop
        from app.models import User, utcnow
        from sqlalchemy import select

        salt = os.urandom(16)
        digest = await hash_verifier_off_loop(recovery_key, salt, n=app.state.settings.scrypt_n)
        async with app.state.sessionmaker() as session:
            row = await session.scalar(select(User).where(User.id == emu.user_id))
            row.recovery_salt = salt
            row.recovery_verifier = digest
            row.recovery_wrapped_data_key = sealed
            row.recovery_set_at = utcnow()
            row.recovery_scheme = 1
            await session.commit()

        # A v2 hint is the same flat credential miss as any bad proof.
        v2_hint = await client.post(
            "/api/auth/recover",
            json={
                "username": "rec2-mism",
                "verifier": b64(hkdf_info(recovery_key, VERIFIER_INFO)),
                "scheme": "v2",
            },
        )
        assert v2_hint.status_code == 401
        assert v2_hint.json()["code"] == "invalid_credentials"

        # ...and the v1 retry (the client's fallback) succeeds.
        retry = await client.post(
            "/api/auth/recover",
            json={"username": "rec2-mism", "verifier": b64(recovery_key), "scheme": "v1"},
        )
        assert retry.status_code == 200, retry.text
        assert retry.json()["recovery_scheme"] == "v1"

    async def test_v2_kit_rejects_a_v1_hint_without_an_oracle(self, client, recovery_key):
        emu = ClientEmulator("rec2-v1hint", "correct horse battery staple")
        await emu.register(client)
        await _setup_v2(client, emu, recovery_key)
        response = await client.post(
            "/api/auth/recover",
            json={"username": "rec2-v1hint", "verifier": b64(recovery_key), "scheme": "v1"},
        )
        assert response.status_code == 401
        assert response.json()["code"] == "invalid_credentials"

    async def test_recovery_scheme_is_required(self, client, recovery_key):
        emu = ClientEmulator("rec2-explicit", "correct horse battery staple")
        await emu.register(client)
        await _setup_v2(client, emu, recovery_key)
        response = await client.post(
            "/api/auth/recover",
            json={"username": emu.username, "verifier": b64(recovery_key)},
        )
        assert response.status_code == 422
        assert response.json()["code"] == "validation_error"

    async def test_failure_budget_is_uniform_and_opaque_for_every_enrollment_state(
        self, client, app, settings, recovery_key
    ):
        """Known-kit, no-kit, unknown and wrong-scheme probes consume the
        same normalized per-identifier budget.  The counter key must not
        retain the supplied username in process memory."""
        settings.auth_rate_limit = 100
        settings.verifier_failure_limit = 2

        wrong_proof = ClientEmulator("rec-budget-proof", "correct horse battery staple")
        await wrong_proof.register(client)
        await _setup_v2(client, wrong_proof, recovery_key)
        wrong_scheme = ClientEmulator("rec-budget-scheme", "correct horse battery staple")
        await wrong_scheme.register(client)
        await _setup_v2(client, wrong_scheme, recovery_key)
        no_kit = ClientEmulator("rec-budget-nokit", "correct horse battery staple")
        await no_kit.register(client)

        cases = [
            (
                wrong_proof.username,
                b64(os.urandom(32)),
                "v2",
            ),
            (
                wrong_scheme.username,
                b64(hkdf_info(recovery_key, VERIFIER_INFO)),
                "v1",
            ),
            (no_kit.username, b64(os.urandom(32)), "v2"),
            ("rec-budget-unknown", b64(os.urandom(32)), "v2"),
        ]
        for username, verifier, scheme in cases:
            observed: list[tuple[int, str]] = []
            for _attempt in range(3):
                response = await client.post(
                    "/api/auth/recover",
                    json={"username": username, "verifier": verifier, "scheme": scheme},
                )
                observed.append((response.status_code, response.json()["code"]))
            assert observed == [
                (401, "invalid_credentials"),
                (401, "invalid_credentials"),
                (429, "rate_limited"),
            ]

        keys = list(app.state.rate_counter._hits)  # noqa: SLF001 -- privacy contract pin
        for username, _verifier, _scheme in cases:
            assert all(username not in key for key in keys)

    async def test_recovery_budget_preserves_exact_case_and_whitespace_lookup_semantics(
        self, client, settings, recovery_key
    ):
        settings.auth_rate_limit = 100
        settings.verifier_failure_limit = 2
        enrolled = ClientEmulator("RecCaseBudget", "correct horse battery staple")
        await enrolled.register(client)
        await _setup_v2(client, enrolled, recovery_key)
        verifier = b64(os.urandom(32))

        async def attempt(username: str) -> int:
            response = await client.post(
                "/api/auth/recover",
                json={"username": username, "verifier": verifier, "scheme": "v2"},
            )
            return response.status_code

        assert [await attempt(enrolled.username) for _ in range(3)] == [401, 401, 429]
        # These inputs do not select the registered row, so neither may
        # inherit its exhausted bucket. Each exact lookup gets its own
        # identical two-failure budget.
        assert [await attempt(enrolled.username.lower()) for _ in range(3)] == [401, 401, 429]
        assert [await attempt(f" {enrolled.username} ") for _ in range(3)] == [401, 401, 429]

    async def test_reset_proven_by_the_v2_verifier(self, client, recovery_key):
        emu = ClientEmulator("rec2-reset", "correct horse battery staple")
        await emu.register(client)
        await _setup_v2(client, emu, recovery_key)
        verifier = b64(hkdf_info(recovery_key, VERIFIER_INFO))

        login = await client.post(
            "/api/auth/recover",
            json={"username": "rec2-reset", "verifier": verifier, "scheme": "v2"},
        )
        assert login.status_code == 200, login.text
        token = login.json()["token"]

        # Possession probe: open a processing session with the REAL data
        # key (the raw /api/processing/sessions contract the emulator uses).
        probe = await client.post(
            "/api/processing/sessions",
            headers={"Authorization": f"Bearer {token}"},
            json={"data_key": emu.data_key_b64},
        )
        assert probe.status_code == 201, probe.text

        new_salt = os.urandom(16)
        response = await client.put(
            "/api/account/recovery/password",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Processing-Token": probe.json()["session_token"],
            },
            json={
                "proof": verifier,
                "new_salt": b64(new_salt),
                "new_verifier": b64(os.urandom(32)),
                "wrapped_data_key": b64(os.urandom(WRAPPED)),
            },
        )
        # 409 processing_session_invalid is acceptable too: single-use
        # probes are consumed by the first reset — what must NEVER happen
        # is 401 invalid_credentials on the CORRECT v2 verifier.
        assert response.status_code in (204, 403, 409), response.text
        if response.status_code != 204:
            assert response.json()["code"] != "invalid_credentials", response.text

        # The raw key is NOT a valid proof for a v2 kit.
        raw_proof = await client.put(
            "/api/account/recovery/password",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Processing-Token": probe.json()["session_token"],
            },
            json={
                "proof": b64(recovery_key),
                "new_salt": b64(os.urandom(16)),
                "new_verifier": b64(os.urandom(32)),
                "wrapped_data_key": b64(os.urandom(WRAPPED)),
            },
        )
        assert raw_proof.status_code in (401, 409), raw_proof.text

    async def test_seal_and_verifier_derivations_are_domain_separated(self, recovery_key):
        # The two v2 labels must produce DIFFERENT keys from the same
        # recovery key — and both must differ from the v1 label.
        v1_info = b"mindpattern/recovery/v1"
        a = hkdf_info(recovery_key, VERIFIER_INFO)
        b_ = hkdf_info(recovery_key, SEAL_INFO)
        c = hkdf_info(recovery_key, v1_info)
        assert len({a, b_, c}) == 3
