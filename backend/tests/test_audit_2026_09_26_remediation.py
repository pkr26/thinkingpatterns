"""2026-09-26 audit remediation pins (the items this round introduced).

Covers the NEW branches end to end: the /metrics limiter, the sliding
window's no-2x-burst contract at the HTTP layer (already unit-pinned in
test_hardening — here via the live middleware path), socketless-identity
refusal, the live middleware settings accessor, Vary: Origin on mirrored
responses, the body-buffer memory budget, sharded overflow locks, the
TOTP atomic fence under concurrency, note optimistic concurrency
(version_required / version_conflict / version advance), the access-log
hash chain (tamper detection, pruned prefix, survival past account
deletion), hard-deletion terminal audit rows, access-log cursor
validation, revoked-history audit durability, the deactivated-patient
gate, the verifier-gated measure correction delete, and the DELETE
revision-echo headers.
"""

from __future__ import annotations

import asyncio
import base64
import zlib
from datetime import date, datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app.api._audit import (
    append_access_log,
    compute_entry_hash,
    verify_access_log_chain,
)
from app.config import Settings
from app.main import create_app
from app.models import AccessLog, User, utcnow
from tests.helpers import ClientEmulator, TherapistEmulator

TODAY = date.today()


# --- helpers ---------------------------------------------------------------------------


async def _measure(client, emu: ClientEmulator, mid: str) -> dict:
    from app.security import crypto

    blob = base64.b64encode(
        crypto.encrypt(
            emu.data_key,
            b'{"v":1,"measure":"phq9","score":6}',
            crypto.build_aad("measure", emu.user_id, mid),
        )
    ).decode("ascii")
    response = await client.post(
        "/api/measures",
        headers=emu.headers,
        json={"client_measure_id": mid, "blob": blob, "measure_date": TODAY.isoformat()},
    )
    assert response.status_code == 201, response.text
    return response.json()


async def _shared_pair(client, label: str) -> tuple[TherapistEmulator, ClientEmulator]:
    therapist = TherapistEmulator(f"{label}-th", "deep-password")
    await therapist.register(client)
    patient = ClientEmulator(f"{label}-p", "deep-password")
    await patient.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await patient.pairing_lookup(client, code)
    granted = await patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted
    return therapist, patient


# --- item 1: /metrics joins the ops limiter --------------------------------------------


async def test_metrics_endpoint_is_rate_limited(client, settings):
    settings.ops_rate_limit = 3
    settings.environment = "development"  # /metrics exists without a token
    statuses = [r.status_code for r in [await client.get("/metrics") for _ in range(5)]]
    # Development exposes the endpoint but the shared ops bucket still
    # bounds a flood: the first three pass, everything after 429s.
    assert statuses[:3] == [200, 200, 200]
    assert statuses[3:] == [429, 429]


# --- item 4: garbage bool env values refuse to boot (both parsers) ---------------------


def test_optional_bool_env_rejects_garbage(monkeypatch):
    from app.config import _optional_bool_env

    monkeypatch.delenv("MINDPATTERN_REM_OPT_BOOL", raising=False)
    assert _optional_bool_env("MINDPATTERN_REM_OPT_BOOL") is None
    monkeypatch.setenv("MINDPATTERN_REM_OPT_BOOL", "yes")
    assert _optional_bool_env("MINDPATTERN_REM_OPT_BOOL") is True
    monkeypatch.setenv("MINDPATTERN_REM_OPT_BOOL", "0")
    assert _optional_bool_env("MINDPATTERN_REM_OPT_BOOL") is False
    monkeypatch.setenv("MINDPATTERN_REM_OPT_BOOL", "ture")
    with pytest.raises(ValueError, match="is not a boolean"):
        _optional_bool_env("MINDPATTERN_REM_OPT_BOOL")


# --- infra wave (2026-09-26): secrets resolve from mounted files -----------------------


def test_secret_env_prefers_the_env_var_then_the_file(monkeypatch, tmp_path):
    from app.config import _secret_env

    secret_file = tmp_path / "token_secret.txt"
    secret_file.write_text("file-secret-0123456789abcdef0123456789\n")
    monkeypatch.delenv("MINDPATTERN_REM_SECRET", raising=False)
    monkeypatch.delenv("MINDPATTERN_REM_SECRET_FILE", raising=False)
    # Neither source: the default flows through untouched.
    assert _secret_env("MINDPATTERN_REM_SECRET", "fallback") == "fallback"
    # File only: content with the trailing newline stripped.
    monkeypatch.setenv("MINDPATTERN_REM_SECRET_FILE", str(secret_file))
    assert _secret_env("MINDPATTERN_REM_SECRET", "fallback") == (
        "file-secret-0123456789abcdef0123456789"
    )
    # Env var wins over the file (the dev-overlay path stays env-based).
    monkeypatch.setenv("MINDPATTERN_REM_SECRET", "env-secret-0123456789abcdef01234")
    assert _secret_env("MINDPATTERN_REM_SECRET", "fallback") == "env-secret-0123456789abcdef01234"


def test_secret_env_fail_closed_on_unreadable_file(monkeypatch, tmp_path):
    from app.config import _secret_env

    monkeypatch.delenv("MINDPATTERN_REM_SECRET", raising=False)
    monkeypatch.setenv("MINDPATTERN_REM_SECRET_FILE", str(tmp_path / "missing.txt"))
    with pytest.raises(RuntimeError, match="could not be read"):
        _secret_env("MINDPATTERN_REM_SECRET", "fallback")


def test_secret_env_blank_file_resolves_as_unset(monkeypatch, tmp_path):
    from app.config import _secret_env

    blank = tmp_path / "blank.txt"
    blank.write_text("   \n")
    monkeypatch.delenv("MINDPATTERN_REM_SECRET", raising=False)
    monkeypatch.setenv("MINDPATTERN_REM_SECRET_FILE", str(blank))
    assert _secret_env("MINDPATTERN_REM_SECRET", "fallback") == "fallback"


def test_settings_token_secret_reads_the_file_form(monkeypatch, tmp_path):
    from app.config import Settings

    secret_file = tmp_path / "token_secret.txt"
    secret_file.write_text("x" * 48 + "\n")
    monkeypatch.delenv("MINDPATTERN_TOKEN_SECRET", raising=False)
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET_FILE", str(secret_file))
    settings = Settings.from_env()
    assert settings.token_secret == "x" * 48


# --- item 5: a peer-less transport is refused, never bucketed together -----------------


async def test_rate_limit_check_refuses_requests_without_a_client_identity(settings):
    from types import SimpleNamespace

    from app.cache import RateLimitCheck, SlidingWindowCounter
    from app.deps import ApiError

    check = RateLimitCheck("probe-bucket", "auth_rate_limit", "auth_rate_window")
    counter = SlidingWindowCounter()
    request = SimpleNamespace(
        state=SimpleNamespace(),
        client=None,  # the socketless transport: no peer identity at all
        app=SimpleNamespace(state=SimpleNamespace(settings=settings, rate_counter=counter)),
    )
    # The double has NO .client: client_key reports the identity as
    # unavailable and the dependency refuses (fail closed) — one socketless
    # client can no longer spend, or exhaust, anyone else's bucket.
    with pytest.raises(ApiError) as excinfo:
        await check(request)
    assert excinfo.value.status_code == 429
    assert excinfo.value.detail == "no client identity available for rate limiting"
    # The counter never even saw the request: no bucket was created.
    assert list(counter._hits) == []  # noqa: SLF001


async def test_scope_without_peer_has_no_identity():
    from app.cache import client_key_from_scope

    assert client_key_from_scope({"type": "http", "path": "/"}) is None
    assert client_key_from_scope({"type": "http", "path": "/", "client": None}) is None
    assert client_key_from_scope({"type": "http", "path": "/", "client": ("10.0.0.9", 1)}) == (
        "10.0.0.9"
    )


# --- item 6: the middleware's limits follow live settings swaps ------------------------


async def test_middleware_body_cap_follows_a_runtime_settings_swap(settings):
    settings.max_body_bytes = 64 * 1024
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            patient = ClientEmulator("swap-cap", "deep-password")
            await patient.register(c)
            body = {"blob": base64.b64encode(b"x" * 40).decode(), "entry_date": TODAY.isoformat()}
            small = await c.post(
                "/api/entries", headers=patient.headers, json=body | {"client_entry_id": "ok-1"}
            )
            assert small.status_code == 201, small.text
            # Runtime swap: the dependencies read app.state.settings at
            # request time, and since item 6 so does the edge body cap.
            application.state.settings = Settings(
                environment="development",
                token_secret="test-secret-not-for-production",
                max_body_bytes=1024,
            )
            refused = await c.post(
                "/api/entries",
                headers=patient.headers,
                json=body
                | {"client_entry_id": "over-1", "blob": base64.b64encode(b"y" * 2048).decode()},
            )
            assert refused.status_code == 413
            assert refused.json()["code"] == "payload_too_large"


async def test_middleware_rate_limits_follow_a_runtime_settings_swap(settings):
    settings.auth_rate_limit = 100
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            first = await c.post("/api/auth/salt", json={"username": "swap-rl"})
            assert first.status_code == 200
            swapped = Settings(
                environment="development",
                token_secret="test-secret-not-for-production",
                auth_rate_limit=1,
            )
            application.state.settings = swapped
            second = await c.post("/api/auth/salt", json={"username": "swap-rl"})
            assert second.status_code == 429, "the edge gate must read the live limits"
            assert second.json()["code"] == "rate_limited"


# --- item 8: Vary: Origin on the mirrored short-circuit responses ----------------------


async def test_mirrored_cors_responses_carry_vary_origin(settings):
    settings.cors_origins = ["https://portal.example"]
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        transport = ASGITransport(app=application)
        async with AsyncClient(transport=transport, base_url="http://t") as c:
            oversized = {"content-length": "999999999"}
            allowed = await c.post(
                "/api/auth/salt",
                headers={"Origin": "https://portal.example", **oversized},
                json={"username": "vary-ok"},
            )
            assert allowed.status_code == 413
            assert allowed.headers["access-control-allow-origin"] == "https://portal.example"
            # Defense in depth (no-store already mitigates): the response
            # varied by Origin, so a shared cache can never serve an
            # allow-listed client a non-CORS copy or vice versa.
            assert "Origin" in allowed.headers.get("vary", "")

            foreign = await c.post(
                "/api/auth/salt",
                headers={"Origin": "https://evil.example", **oversized},
                json={"username": "vary-bad"},
            )
            assert foreign.status_code == 413
            assert "access-control-allow-origin" not in foreign.headers
            assert "Origin" in foreign.headers.get("vary", "")


# --- item 9: the edge body-buffer memory budget is validated at boot --------------------


def test_body_buffer_budget_refuses_oversized_combinations():
    # 64 MiB x 100 concurrent = 6.4 GiB of edge buffers — far past the
    # documented 512 MiB budget; boot must refuse with the arithmetic.
    # VOICE_PLAN (2026-09-29): the budget is judged on the LARGER of the
    # ordinary and audio route caps, so the message names the max().
    with pytest.raises(
        RuntimeError,
        match=r"max\(max_body_bytes, audio_max_body_bytes\) \* body_buffer_concurrency",
    ):
        Settings(
            environment="development",
            token_secret="test-secret-not-for-production",
            max_body_bytes=64 * 1024 * 1024,
            analysis_blob_budget=64 * 1024 * 1024,  # satisfy the A-8 floor first
            body_buffer_concurrency=100,
        )
    with pytest.raises(RuntimeError, match="body_buffer_concurrency must be"):
        Settings(
            environment="development",
            token_secret="test-secret-not-for-production",
            body_buffer_concurrency=0,
        )
    # The deployment default (2 MiB x 100, the entrypoint's concurrency
    # cap) fits the documented budget with headroom.
    ok = Settings(environment="development", token_secret="test-secret-not-for-production")
    assert ok.body_buffer_concurrency == 100
    assert ok.max_body_bytes * ok.body_buffer_concurrency <= 512 * 1024 * 1024


# --- item 7: overflow shards remove the global serialization cliff ---------------------


async def test_overflow_keys_in_different_shards_do_not_serialize():
    from app.locks import OVERFLOW_SHARDS, UserLocks

    locks = UserLocks(max_keys=1)
    # Two keys deliberately mapped to DIFFERENT shards by the stable crc32.
    shards: dict[int, str] = {}
    n = 0
    while len(shards) < 2 and n < 10_000:
        key = f"shard-probe-{n}"
        shards.setdefault(zlib.crc32(key.encode()) % OVERFLOW_SHARDS, key)
        n += 1
    (k1, k2) = list(shards.values())[0], list(shards.values())[1]

    dedicated_held = asyncio.Event()
    first_in = asyncio.Event()
    second_in = asyncio.Event()
    release = asyncio.Event()

    async def hold_dedicated():
        async with locks.hold("dedicated"):
            dedicated_held.set()
            await release.wait()

    async def overflow(key: str, entered: asyncio.Event):
        async with locks.hold(key):
            entered.set()
            await release.wait()

    d = asyncio.create_task(hold_dedicated())
    await dedicated_held.wait()
    o1 = asyncio.create_task(overflow(k1, first_in))
    await first_in.wait()  # k1 is on ITS shard's fallback lock
    # k2 hashes to a different shard: it must enter WITHOUT waiting for
    # k1 — the old single global overflow lock serialized them.
    o2 = asyncio.create_task(overflow(k2, second_in))
    try:
        await asyncio.wait_for(second_in.wait(), timeout=2.0)
    finally:
        release.set()
        await asyncio.gather(d, o1, o2)
    assert locks.total_overflow_refs() == 0


# --- item 10: the atomic TOTP fence under concurrent same-code logins -------------------


async def test_concurrent_totp_logins_resolve_to_exactly_one_winner(client, monkeypatch):
    from app.security import totp as totp_mod
    from tests.helpers import install_totp_clock
    from tests.test_totp import _b32_decode

    # Fake totp clock (2026-09-26 test-infrastructure audit, item 1): the
    # endpoint ladder reads time through app.security.totp's module-global
    # ``time``, so timestep crossings are deterministic advances — the old
    # cross-module helper slept a real ~30s boundary.
    clock = install_totp_clock(monkeypatch)
    therapist = TherapistEmulator("fence-th", "deep-password")
    await therapist.register(client)
    setup = await client.post(
        "/api/account/totp/setup",
        headers=therapist.headers,
        json={"verifier": therapist.auth_key_b64},
    )
    assert setup.status_code == 200, setup.text
    secret = _b32_decode(setup.json()["secret_base32"])
    code = clock.current_code(secret)
    enabled = await client.post(
        "/api/account/totp/enable",
        headers=therapist.headers,
        json={"verifier": therapist.auth_key_b64, "code": code},
    )
    assert enabled.status_code == 200, enabled.text
    # Burn the enable timestep so the login code below is genuinely fresh.
    clock.advance_to_next_timestep()
    fresh = clock.current_code(secret)

    login = dict(
        username=therapist.username,
        verifier=therapist.auth_key_b64,
        totp_code=fresh,
    )
    first, second = await asyncio.gather(
        client.post("/api/auth/login", json=login),
        client.post("/api/auth/login", json=login),
    )
    outcomes = sorted([first.status_code, second.status_code])
    # The conditional UPDATE is the sole replay authority (item 10): two
    # logins racing the SAME code serialize on the row; exactly one token
    # is issued and the loser gets the flat totp failure — never two
    # successes (replay) and never two failures (fresh-code 401 bug).
    assert outcomes == [200, 401]
    loser = second if second.status_code == 401 else first
    assert loser.json()["code"] in ("totp_code_invalid", "rate_limited")


# --- item 15: note optimistic concurrency ----------------------------------------------


async def test_note_patch_without_base_version_is_rejected(client):
    therapist, patient = await _shared_pair(client, "nv")
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={"client_note_id": "nv-1", "blob": therapist.encrypt_note(patient, "nv-1", "v1")},
    )
    assert created.status_code == 201
    note = created.json()
    assert note["version"] == 1

    missing = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={"blob": therapist.encrypt_note(patient, "nv-1", "v2")},  # no base_version
    )
    assert missing.status_code == 400
    assert missing.json()["code"] == "version_required"


async def test_note_patch_stale_base_version_conflicts_and_refetch_retries(client):
    therapist, patient = await _shared_pair(client, "nv2")
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={"client_note_id": "nv2-1", "blob": therapist.encrypt_note(patient, "nv2-1", "v1")},
    )
    note = created.json()

    # A second device's edit lands first (version -> 2).
    won = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={
            "blob": therapist.encrypt_note(patient, "nv2-1", "won the race"),
            "base_version": 1,
        },
    )
    assert won.status_code == 200
    assert won.json()["version"] == 2

    # The first device still believes version 1: last-write-wins is GONE —
    # the stale edit is a 409, and the clinical record of the winner stays.
    stale = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={
            "blob": therapist.encrypt_note(patient, "nv2-1", "stale silent overwrite"),
            "base_version": 1,
        },
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "version_conflict"

    # Refetch + retry on the CURRENT version succeeds (the recovery flow).
    listed = await client.get(
        f"/api/therapist/patients/{patient.user_id}/notes", headers=therapist.headers
    )
    retried = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={
            "blob": therapist.encrypt_note(patient, "nv2-1", "rebased edit"),
            "base_version": listed.json()[0]["version"],
        },
    )
    assert retried.status_code == 200
    assert retried.json()["version"] == 3


async def test_note_patch_re_fetch_under_the_chart_lock_sees_the_committed_version(
    client, app, monkeypatch
):
    """The 409 verdict is decided against the row re-fetched UNDER the chart
    lock, not the pre-lock snapshot: an edit that commits while this request
    is queued on the lock must be caught. Pinned deterministically by
    pausing the first request inside its lock until the second has committed
    (the in-memory test topology shares one connection, so true gather
    interleaving is not observable there — db.py documents this)."""
    from app.api import therapist as therapist_api

    therapist, patient = await _shared_pair(client, "nv3")
    created = await client.post(
        f"/api/therapist/patients/{patient.user_id}/notes",
        headers=therapist.headers,
        json={"client_note_id": "nv3-1", "blob": therapist.encrypt_note(patient, "nv3-1", "v1")},
    )
    note = created.json()

    original_increment = therapist_api._increment_notes_revision
    first_committed = asyncio.Event()
    waiting_first = asyncio.Event()

    async def increment_pausing_first(session, therapist_user):
        if not first_committed.is_set():
            # The FIRST editor sits inside the chart lock (pre-commit) while
            # a second editor runs its whole request and commits.
            waiting_first.set()
            await first_committed.wait()
        return await original_increment(session, therapist_user)

    monkeypatch.setattr(therapist_api, "_increment_notes_revision", increment_pausing_first)

    async def first_edit():
        return await client.patch(
            f"/api/therapist/notes/{note['id']}",
            headers=therapist.headers,
            json={
                "blob": therapist.encrypt_note(patient, "nv3-1", "first editor"),
                "base_version": 1,
            },
        )

    first_task = asyncio.create_task(first_edit())
    await waiting_first.wait()
    # The second editor's request blocks on the same chart lock the first
    # holds, so run it through the endpoint AFTER releasing: emulate by
    # letting the first commit, then sending the stale-base second edit —
    # the under-lock re-fetch must see version 2 and refuse.
    first_committed.set()
    first = await first_task
    assert first.status_code == 200
    assert first.json()["version"] == 2

    stale = await client.patch(
        f"/api/therapist/notes/{note['id']}",
        headers=therapist.headers,
        json={
            "blob": therapist.encrypt_note(patient, "nv3-1", "second editor, stale base"),
            "base_version": 1,
        },
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "version_conflict"


# --- item 16: the access-log forward hash chain -----------------------------------------


async def test_access_log_chain_verifies_and_detects_tampering(client, app):
    therapist, patient = await _shared_pair(client, "chain")
    # A handful of chained rows for ONE patient, written by the therapist.
    async with app.state.sessionmaker() as session:
        for i in range(4):
            await append_access_log(
                session,
                actor_id=therapist.user_id,
                actor_role="therapist",
                user_id=patient.user_id,
                action="read_insights",
                at=utcnow() + timedelta(seconds=i),
            )
        await session.commit()
        verification = await verify_access_log_chain(session, patient.user_id)
    # 4 seeded rows + the grant flow's own chained audit row = 5, linked.
    assert verification.ok and verification.rows_checked == 5

    # Tamper: rewrite one row's action. The seal no longer matches.
    async with app.state.sessionmaker() as session:
        victim = (
            (
                await session.execute(
                    select(AccessLog).where(AccessLog.user_id == patient.user_id).limit(1)
                )
            )
            .scalars()
            .one()
        )
        victim.action = "read_notes"
        await session.commit()
        broken = await verify_access_log_chain(session, patient.user_id)
    assert not broken.ok
    assert broken.broken_at_seq == victim.chain_seq
    assert broken.reason == "entry_hash does not match the row's contents"


async def test_access_log_chain_detects_mid_trail_deletion(client, app):
    patient = ClientEmulator("chain-gap", "deep-password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        for i in range(4):
            await append_access_log(
                session,
                actor_id=patient.user_id,
                actor_role="user",
                user_id=patient.user_id,
                action="grant",
                at=utcnow() + timedelta(seconds=i),
            )
        await session.commit()
        middle = (
            (
                await session.execute(
                    select(AccessLog).where(
                        AccessLog.user_id == patient.user_id, AccessLog.chain_seq == 2
                    )
                )
            )
            .scalars()
            .one()
        )
        await session.delete(middle)
        await session.commit()
        broken = await verify_access_log_chain(session, patient.user_id)
    assert not broken.ok
    assert "gap" in (broken.reason or "")


async def test_access_log_chain_accepts_a_pruned_prefix(client, app):
    """Retention sweeps delete the OLDEST rows; the surviving head anchors
    the chain and every later link must still hold."""
    patient = ClientEmulator("chain-prune", "deep-password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        for i in range(4):
            await append_access_log(
                session,
                actor_id=patient.user_id,
                actor_role="user",
                user_id=patient.user_id,
                action="grant",
                at=utcnow() + timedelta(seconds=i),
            )
        await session.commit()
        oldest = (
            (
                await session.execute(
                    select(AccessLog).where(
                        AccessLog.user_id == patient.user_id, AccessLog.chain_seq == 1
                    )
                )
            )
            .scalars()
            .one()
        )
        await session.delete(oldest)
        await session.commit()
        verification = await verify_access_log_chain(session, patient.user_id)
    assert verification.ok and verification.rows_checked == 3


def test_compute_entry_hash_is_deterministic_and_binds_every_field():
    a = compute_entry_hash(
        None, "actor", "user", "grant", datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    )
    b = compute_entry_hash(
        None, "actor", "user", "grant", datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    )
    assert a == b and len(a) == 64
    # Every input participates: any single-field change breaks the seal.
    assert a != compute_entry_hash(
        "prev", "actor", "user", "grant", datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    )
    assert a != compute_entry_hash(
        None, "actor2", "user", "grant", datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    )
    assert a != compute_entry_hash(
        None, "actor", "user2", "grant", datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    )
    assert a != compute_entry_hash(
        None, "actor", "user", "revoke", datetime(2026, 9, 26, 12, tzinfo=timezone.utc)
    )
    assert a != compute_entry_hash(
        None, "actor", "user", "grant", datetime(2026, 9, 26, 13, tzinfo=timezone.utc)
    )


async def _shared_pair_therapist_only(
    client, label: str
) -> tuple[TherapistEmulator, ClientEmulator]:
    return await _shared_pair(client, label)


# --- item 17: terminal account_deleted audit rows survive the cascade --------------------


async def test_patient_hard_deletion_writes_a_surviving_terminal_audit_row(client, app):
    patient = ClientEmulator("del-audit", "deep-password")
    await patient.register(client)
    deleted = await client.delete(
        "/api/account",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert deleted.status_code == 204, deleted.text
    async with app.state.sessionmaker() as session:
        rows = (
            (await session.execute(select(AccessLog).where(AccessLog.user_id == patient.user_id)))
            .scalars()
            .all()
        )
        assert [row.action for row in rows] == ["account_deleted"]
        # The row is chained (item 16 integration): it is its chain's head.
        assert rows[0].entry_hash is not None
        verification = await verify_access_log_chain(session, patient.user_id)
    assert verification.ok and verification.rows_checked == 1


async def test_therapist_deletion_writes_the_same_terminal_row(client, app):
    therapist = TherapistEmulator("del-audit-th", "deep-password")
    await therapist.register(client)
    deleted = await client.delete(
        "/api/therapist/account",
        headers={**therapist.headers, "X-Account-Verifier": therapist.auth_key_b64},
    )
    assert deleted.status_code == 204, deleted.text
    async with app.state.sessionmaker() as session:
        actions = (
            (
                await session.execute(
                    select(AccessLog.action).where(AccessLog.actor_id == therapist.user_id)
                )
            )
            .scalars()
            .all()
        )
    assert "account_deleted" in actions


# --- item 18: access-log cursors must be tz-aware ISO + 32-hex ---------------------------


@pytest.mark.parametrize(
    "bad_cursor",
    [
        "2026-09-22T12:00:00|abcdef",  # naive instant
        "2026-09-22|abcdefabcdefabcdefabcdefabcdef12",  # date-only
        "not-a-timestamp|abcdefabcdefabcdefabcdefabcdef12",
        "2026-09-22T12:00:00+00:00",  # missing separator/id
        "2026-09-22T12:00:00+00:00|not-hex!",  # junk id
    ],
)
async def test_patient_access_log_rejects_malformed_cursors(client, bad_cursor):
    patient = ClientEmulator("cursor-p", "deep-password")
    await patient.register(client)
    response = await client.get(
        "/api/account/access-log", headers=patient.headers, params={"cursor": bad_cursor}
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


async def test_therapist_access_log_rejects_a_naive_cursor(client):
    therapist = TherapistEmulator("cursor-th", "deep-password")
    await therapist.register(client)
    response = await client.get(
        "/api/therapist/access-log",
        headers=therapist.headers,
        params={"cursor": "2026-09-22T12:00:00|abcdefabcdefabcdefabcdefabcdef12"},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


# --- item 19: revoked-history audit rows survive a failure in the active pass -------------


async def test_revoked_history_audit_rows_survive_a_later_exception(client, app, monkeypatch):
    from app.api import therapist as therapist_api
    from app.services import threshold as threshold_mod

    therapist, revoked_patient = await _shared_pair(client, "revflush")
    revoke = await client.delete(
        f"/api/consents/{await _consent_id(client, therapist, revoked_patient)}",
        headers={**revoked_patient.headers, "X-Account-Verifier": revoked_patient.auth_key_b64},
    )
    assert revoke.status_code == 204, revoke.text
    # A second, ACTIVE patient on the SAME caseload makes the active pass
    # actually run (and hit the patched threshold evaluation) AFTER the
    # revoked pass committed.
    active_patient = ClientEmulator("revflush2-p", "deep-password")
    await active_patient.register(client)
    code = await therapist.create_pairing_code(client)
    lookup = await active_patient.pairing_lookup(client, code)
    granted = await active_patient.grant_consent(
        client, code, lookup["body"]["wrap_pub_key"], lookup["body"]["therapist_id"]
    )
    assert granted["status"] == 201, granted

    def explode(*args, **kwargs):
        raise RuntimeError("simulated failure in the active pass")

    # The ACTIVE pass evaluates the threshold per patient; blowing it up
    # after the revoked pass models any later exception in the endpoint.
    monkeypatch.setattr(threshold_mod, "evaluate", explode)
    failed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert failed.status_code == 500
    monkeypatch.undo()

    async with app.state.sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(AccessLog).where(
                        AccessLog.actor_id == therapist.user_id,
                        AccessLog.action == "list_patients",
                    )
                )
            )
            .scalars()
            .all()
        )
    # Item 19: the revoked history's audit rows were committed right after
    # the FIRST pass — the later 500 cannot erase them. (The ACTIVE
    # patient's row is absent: its pass never reached its audit commit.)
    revoked_rows = [row for row in rows if row.user_id == revoked_patient.user_id]
    assert revoked_rows, "the revoked-history audit rows must survive a later exception"
    async with app.state.sessionmaker() as session:
        verification = await verify_access_log_chain(session, revoked_patient.user_id)
    assert verification.ok


async def _consent_id(client, therapist: TherapistEmulator, patient: ClientEmulator) -> str:
    listed = await client.get("/api/consents", headers=patient.headers)
    for row in listed.json():
        if row["therapist_id"] == therapist.user_id:
            return row["id"]
    raise AssertionError("consent row not found")


# --- item 20: a deactivated patient account loses therapist access -----------------------


async def test_deactivated_patient_is_invisible_to_therapist_reads(client, app):
    therapist, patient = await _shared_pair(client, "inactive")
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(User).where(User.id == patient.user_id).values(is_active=False)
        )
        await session.commit()

    for path in (
        f"/api/therapist/patients/{patient.user_id}/insights",
        f"/api/therapist/patients/{patient.user_id}/entries",
        f"/api/therapist/patients/{patient.user_id}/measures",
    ):
        response = await client.get(path, headers=therapist.headers)
        assert response.status_code == 404, path
    # The list omits the deactivated patient entirely.
    listed = await client.get("/api/therapist/patients", headers=therapist.headers)
    assert listed.status_code == 200
    assert all(row["user_id"] != patient.user_id for row in listed.json())


# --- item 21: the verifier-gated measure correction delete ------------------------------


async def test_measure_delete_full_ladder(client, app):
    patient = ClientEmulator("mdel", "deep-password")
    await patient.register(client)
    await _measure(client, patient, "m-del-1")
    base_revision = int(
        (await client.get("/api/measures", headers=patient.headers)).headers["X-Measures-Revision"]
    )

    # No verifier -> the destructive path refuses before anything happens.
    bare = await client.delete("/api/measures/m-del-1", headers=patient.headers)
    assert bare.status_code == 422
    assert bare.json()["code"] == "validation_error"

    # Wrong verifier -> 403, row intact.
    wrong = await client.delete(
        "/api/measures/m-del-1",
        headers={**patient.headers, "X-Account-Verifier": base64.b64encode(b"n" * 32).decode()},
    )
    assert wrong.status_code == 403
    assert wrong.json()["code"] == "verification_failed"

    # Correct verifier: hard delete + advanced revision + chained audit row.
    gone = await client.delete(
        "/api/measures/m-del-1",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert gone.status_code == 200, gone.text
    assert gone.json()["measures_revision"] == base_revision + 1
    assert int(gone.headers["X-Measures-Revision"]) == base_revision + 1

    remaining = await client.get("/api/measures", headers=patient.headers)
    assert remaining.json() == []

    # Idempotent retry of the same correction is the flat 404.
    again = await client.delete(
        "/api/measures/m-del-1",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert again.status_code == 404

    # Someone else's measure id is also the flat 404 (never a leak).
    stranger = ClientEmulator("mdel-2", "deep-password")
    await stranger.register(client)
    await _measure(client, stranger, "m-del-1")
    denied = await client.delete(
        "/api/measures/m-del-1",
        headers={**patient.headers, "X-Account-Verifier": patient.auth_key_b64},
    )
    assert denied.status_code == 404

    async with app.state.sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(AccessLog).where(
                        AccessLog.user_id == patient.user_id, AccessLog.action == "delete_measure"
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(rows) == 1
    assert rows[0].entry_hash is not None


# --- item 23: DELETE echoes the collection revision --------------------------------------


async def test_entry_delete_echoes_the_new_entries_revision(client):
    patient = ClientEmulator("edel", "deep-password")
    await patient.register(client)
    await patient.create_entry(client, "delete me", TODAY, "edel-1")
    before = int(
        (await client.get("/api/entries", headers=patient.headers)).headers["X-Entries-Revision"]
    )
    gone = await client.delete("/api/entries/edel-1", headers=patient.headers)
    assert gone.status_code == 204
    # The 204 carries the post-delete snapshot marker: a paged-sync client
    # resumes from this response alone, without an extra GET.
    assert int(gone.headers["X-Entries-Revision"]) == before + 1


# --- item 13: local-recompute reports the threshold honestly -----------------------------


async def test_local_recompute_reports_the_real_phase_and_counts(client):
    patient = ClientEmulator("lr-honest", "deep-password")
    await patient.register(client)
    # A below-threshold account (3 distinct days, threshold 30).
    from datetime import timedelta as _td

    from app.security import crypto

    await patient.backdate_account(client, days=4)
    for offset in (2, 1, 0):
        day = TODAY - _td(days=offset)
        await patient.create_entry(client, "quiet day", day, f"lrh-{offset}")
    state_blob = crypto.encrypt(
        patient.data_key, b'{"v":1}', crypto.build_aad("insights", patient.user_id, "brain")
    )
    patterns_blob = crypto.encrypt(
        patient.data_key, b'{"v":1}', crypto.build_aad("insights", patient.user_id, "patterns")
    )
    response = await client.post(
        "/api/insights/local-recompute",
        headers=patient.headers,
        json={
            "base_state_seq": 0,
            "state_blob": base64.b64encode(state_blob).decode(),
            "patterns_blob": base64.b64encode(patterns_blob).decode(),
            "analysis_dates": [TODAY.isoformat()],
            "patterns_count": 7,
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    # Honest threshold: a baseline account is REPORTED as baseline with
    # real streak/days_remaining (previously hardcoded phase="insight",
    # streak=0, days_remaining=0), and the pattern count is the client's
    # declared count (the server cannot read the opaque payload) — never
    # the old len(analysis_dates).
    assert body["phase"] != "insight"
    assert body["active_days"] == 3
    assert body["days_remaining"] >= 1
    assert body["patterns_stored"] == 7

    no_claim = await client.post(
        "/api/insights/local-recompute",
        headers=patient.headers,
        json={
            "base_state_seq": 1,
            "state_blob": base64.b64encode(state_blob).decode(),
            "patterns_blob": base64.b64encode(patterns_blob).decode(),
            "analysis_dates": [TODAY.isoformat()],
        },
    )
    assert no_claim.status_code == 200, no_claim.text
    assert no_claim.json()["patterns_stored"] == 0
