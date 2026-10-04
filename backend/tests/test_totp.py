"""Optional therapist TOTP (2026-09-21 audit C-2/F-4, delivered 2026-09-22).

Covers the RFC 6238 helper contract, the at-rest wrap, and the full
endpoint ladder: verifier-gated setup → confirm-with-code enable →
login refuses without/with-wrong/with-replayed code → verifier+code
disable → login works password-only again. Also pins the two properties
the design promises: the stored secret is never plaintext in the
database, and re-running setup retires the previous secret.
"""

from __future__ import annotations

import base64
import time

import pytest
from sqlalchemy import select

from app.models import AccessLog, User
from app.security import totp
from tests.helpers import ClientEmulator, TherapistEmulator, TotpClock, install_totp_clock


def _current_code(secret: bytes, clock: TotpClock) -> str:
    return clock.current_code(secret)


def _b32_decode(secret_b32: str) -> bytes:
    padded = secret_b32 + "=" * (-len(secret_b32) % 8)
    return base64.b32decode(padded)


async def _next_timestep(clock: TotpClock) -> None:
    """Codes are consumed once per 30s timestep; cross a boundary so the
    next presentation is genuinely fresh. The boundary lives on the FAKE
    totp clock (see helpers.TotpClock), so this is a deterministic
    advance — the old real-sleep version cost up to ~30s per call."""
    clock.advance_to_next_timestep()


@pytest.fixture
def totp_clock(monkeypatch):
    """Freeze app.security.totp's wall clock (2026-09-26 test-infrastructure
    audit, item 1): the endpoint ladder reads the clock through the totp
    module's ``time`` attribute when verify_code's injectable ``at`` is
    None, so timestep crossings become instant deterministic advances."""
    return install_totp_clock(monkeypatch)


# --- unit contract -------------------------------------------------------------------


async def test_totp_helper_accepts_current_and_drift_rejects_other():
    raw, b32 = totp.generate_secret()
    assert len(raw) == totp.SECRET_BYTES
    assert _b32_decode(b32) == raw
    now = time.time()
    current = int(now // totp.STEP_SECONDS)
    # 2026-09-26 remediation (LOW e): the drift window is PAST-ONLY
    # (-1..0). The previous and current timestep verify (honest authenticator
    # clock skew); a FUTURE timestep no longer does — the replay fence
    # (totp_last_counter) compensates for the lost forward slack.
    for counter in (current - 1, current):
        assert totp.verify_code(raw, totp._code_for_counter(raw, counter), at=now) == counter
    # a code from outside the drift window does not — future included
    assert totp.verify_code(raw, totp._code_for_counter(raw, current + 1), at=now) is None
    assert totp.verify_code(raw, totp._code_for_counter(raw, current - 5), at=now) is None
    # malformed input never verifies
    for bad in ("", "12345", "1234567", "abcdef", "12345x"):
        assert totp.verify_code(raw, bad, at=now) is None


async def test_totp_secret_is_wrapped_at_rest():
    raw, _b32 = totp.generate_secret()
    wrapped = totp.wrap_secret(raw, "server-secret-material-for-tests")
    assert wrapped.startswith("v1:")
    assert base64.b64encode(raw) not in wrapped.encode("ascii")
    assert totp.unwrap_secret(wrapped, "server-secret-material-for-tests") == raw
    # wrong server key cannot open it (token_secret rotation caveat)
    assert totp.unwrap_secret(wrapped, "a-different-server-secret") is None
    # garbage never explodes
    for bad in (None, "", "v1:", "v1:!!!", "plaintext"):
        assert totp.unwrap_secret(bad, "server-secret-material-for-tests") is None


async def test_totp_default_at_reads_the_real_wall_clock_smoke():
    """The ONE real-clock test left in the suite (2026-09-26 test-infrastructure
    audit, item 1): every other TOTP test drives the module through the
    injectable ``at`` or the faked module clock, so something must pin that
    the production default — ``at=None`` reading ``time.time()`` — still
    works after monkeypatch-based tests restore the attribute. Generous
    bound by construction: the code is minted and verified in adjacent
    statements, and the drift window covers the current AND previous
    timestep, so only a >60s stall between the two statements could flip
    the verdict."""
    raw, _b32 = totp.generate_secret()
    before = int(time.time() // totp.STEP_SECONDS)
    code = totp._code_for_counter(raw, before)
    matched = totp.verify_code(raw, code)  # no ``at``: the real wall clock
    after = int(time.time() // totp.STEP_SECONDS)
    assert matched is not None
    assert after - before <= 1  # the generous real-time ceiling


# --- endpoint ladder ------------------------------------------------------------------


async def _ther_headers(th: TherapistEmulator) -> dict:
    return {"Authorization": f"Bearer {th.token}"}


async def _db_user(app, user_id: str) -> User:
    async with app.state.sessionmaker() as session:
        return (await session.execute(select(User).where(User.id == user_id))).scalars().one()


async def test_totp_full_lifecycle(client, app, totp_clock):
    th = TherapistEmulator("totp-dr", "a-deep-therapist-password", auto_enroll_mfa=False)
    await th.register(client)

    # Setup without the verifier answers 403 — a stolen bearer must not
    # arm a second factor.
    no_verifier = await client.post(
        "/api/account/totp/setup", json={"verifier": "AAAA"}, headers=await _ther_headers(th)
    )
    assert no_verifier.status_code == 403, no_verifier.text

    setup = await client.post(
        "/api/account/totp/setup",
        json={"verifier": th.auth_key_b64},
        headers=await _ther_headers(th),
    )
    assert setup.status_code == 200, setup.text
    body = setup.json()
    secret = _b32_decode(body["secret_base32"])
    assert body["otpauth_uri"].startswith("otpauth://totp/")
    assert body["secret_base32"] in body["otpauth_uri"]

    # At rest: wrapped, never the base32 plaintext.
    row = await _db_user(app, th.user_id)
    assert row.totp_enabled is None  # pending, not armed
    assert body["secret_base32"] not in (row.totp_secret or "")
    assert (row.totp_secret or "").startswith("v1:")

    # Enable with a wrong code answers 403 and leaves login unarmed.
    wrong = await client.post(
        "/api/account/totp/enable",
        json={
            "verifier": th.auth_key_b64,
            "code": "000000" if _current_code(secret, totp_clock) != "000000" else "111111",
        },
        headers=await _ther_headers(th),
    )
    assert wrong.status_code == 403, wrong.text
    assert wrong.json()["code"] == "totp_code_invalid"

    # Enable with the right code arms the login check. Confirming consumes
    # the timestep (the code was presented to the server once), so move to
    # a fresh one before the login attempts.
    await _next_timestep(totp_clock)
    good = await client.post(
        "/api/account/totp/enable",
        json={"verifier": th.auth_key_b64, "code": _current_code(secret, totp_clock)},
        headers=await _ther_headers(th),
    )
    assert good.status_code == 200, good.text
    codes = good.json()["backup_codes"]
    assert len(codes) == 8 and len(set(codes)) == 8
    assert all(len(c) == 10 for c in codes)

    # Login without a code: machine-readable distinct answer.
    missing = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64},
    )
    assert missing.status_code == 401
    assert missing.json()["code"] == "totp_required"

    # Login with a wrong code: password half validated, code half not.
    bad_login = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64, "totp_code": "999991"},
    )
    assert bad_login.status_code == 401
    assert bad_login.json()["code"] == "totp_code_invalid"

    # A wrong PASSWORD never reaches the TOTP check at all.
    bad_password = await client.post(
        "/api/auth/login",
        json={
            "username": th.username,
            "verifier": base64.b64encode(b"\x00" * 32).decode(),
            "totp_code": _current_code(secret, totp_clock),
        },
    )
    assert bad_password.status_code == 401
    assert bad_password.json()["code"] == "invalid_credentials"

    # Login with the right code succeeds (fresh timestep; enable consumed
    # the previous one)…
    await _next_timestep(totp_clock)
    ok_login = await client.post(
        "/api/auth/login",
        json={
            "username": th.username,
            "verifier": th.auth_key_b64,
            "totp_code": _current_code(secret, totp_clock),
        },
    )
    assert ok_login.status_code == 200, ok_login.text

    # …and the SAME code is refused afterwards (replay fence).
    replay = await client.post(
        "/api/auth/login",
        json={
            "username": th.username,
            "verifier": th.auth_key_b64,
            "totp_code": _current_code(secret, totp_clock),
        },
    )
    assert replay.status_code == 401
    assert replay.json()["code"] == "totp_code_invalid"

    # The audit trail carries the lifecycle actions.
    async with app.state.sessionmaker() as session:
        actions = {
            action
            for (action,) in await session.execute(
                select(AccessLog.action).where(AccessLog.actor_id == th.user_id)
            )
        }
    assert {"totp_setup", "totp_enable"} <= actions

    # Disable: verifier alone is not enough (wrong code → 403)…
    bad_disable = await client.post(
        "/api/account/totp/disable",
        json={"verifier": th.auth_key_b64, "code": "314159"},
        headers=await _ther_headers(th),
    )
    assert bad_disable.status_code == 403, bad_disable.text
    # …verifier + a FRESH code (the login consumed this timestep)
    # clears the enrollment.
    await _next_timestep(totp_clock)
    disable = await client.post(
        "/api/account/totp/disable",
        json={"verifier": th.auth_key_b64, "code": _current_code(secret, totp_clock)},
        headers=await _ther_headers(th),
    )
    assert disable.status_code == 204, disable.text

    cleared = await _db_user(app, th.user_id)
    assert cleared.totp_secret is None
    assert cleared.totp_enabled is None

    # Login is password-only again.
    plain = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64},
    )
    assert plain.status_code == 200, plain.text


async def test_totp_setup_refuses_while_enabled_and_replaces_pending(client, totp_clock):
    th = TherapistEmulator("totp-swap-dr", "another-deep-password", auto_enroll_mfa=False)
    await th.register(client)
    first = (
        await client.post(
            "/api/account/totp/setup",
            json={"verifier": th.auth_key_b64},
            headers=await _ther_headers(th),
        )
    ).json()
    secret_a = _b32_decode(first["secret_base32"])
    enable = await client.post(
        "/api/account/totp/enable",
        json={"verifier": th.auth_key_b64, "code": _current_code(secret_a, totp_clock)},
        headers=await _ther_headers(th),
    )
    assert enable.status_code == 200
    assert len(enable.json()["backup_codes"]) == 8

    # While ENABLED, setup refuses (409): an attacker holding only the
    # password half must not be able to strip the factor by re-arming and
    # logging in password-only. Disarming requires a live code.
    refused = await client.post(
        "/api/account/totp/setup",
        json={"verifier": th.auth_key_b64},
        headers=await _ther_headers(th),
    )
    assert refused.status_code == 409, refused.text
    assert refused.json()["code"] == "version_conflict"
    # …and the still-enabled factor keeps gating login.
    missing = await client.post(
        "/api/auth/login",
        json={"username": th.username, "verifier": th.auth_key_b64},
    )
    assert missing.status_code == 401
    assert missing.json()["code"] == "totp_required"

    # From the PENDING state, a re-run simply replaces the not-yet-armed
    # secret: nothing is enforced at login until the new one is confirmed.
    th2 = TherapistEmulator("totp-swap-dr-2", "third-deep-password", auto_enroll_mfa=False)
    await th2.register(client)
    p1 = (
        await client.post(
            "/api/account/totp/setup",
            json={"verifier": th2.auth_key_b64},
            headers=await _ther_headers(th2),
        )
    ).json()
    p2 = (
        await client.post(
            "/api/account/totp/setup",
            json={"verifier": th2.auth_key_b64},
            headers=await _ther_headers(th2),
        )
    ).json()
    assert p1["secret_base32"] != p2["secret_base32"]
    # The FIRST pending secret's code cannot enable enrollment…
    stale_enable = await client.post(
        "/api/account/totp/enable",
        json={
            "verifier": th2.auth_key_b64,
            "code": _current_code(_b32_decode(p1["secret_base32"]), totp_clock),
        },
        headers=await _ther_headers(th2),
    )
    assert stale_enable.status_code == 403, stale_enable.text
    # …but the newest one can.
    confirm = await client.post(
        "/api/account/totp/enable",
        json={
            "verifier": th2.auth_key_b64,
            "code": _current_code(_b32_decode(p2["secret_base32"]), totp_clock),
        },
        headers=await _ther_headers(th2),
    )
    assert confirm.status_code == 200, confirm.text
    assert len(confirm.json()["backup_codes"]) == 8


async def test_totp_is_therapist_only(client):
    patient = ClientEmulator("totp-patient", "patient-deep-password")
    await patient.register(client)
    denied = await client.post(
        "/api/account/totp/setup",
        json={"verifier": patient.auth_key_b64},
        headers={"Authorization": f"Bearer {patient.token}"},
    )
    assert denied.status_code == 403, denied.text
    # A patient account never grows a TOTP prompt.
    login = await client.post(
        "/api/auth/login",
        json={"username": patient.username, "verifier": patient.auth_key_b64},
    )
    assert login.status_code == 200, login.text
