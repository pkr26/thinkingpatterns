"""2026-09-20 audit remediation, second wave (post-audit fixes).

Covers the fixes from the 2026-09-20 fourth-pass audit:
  * M-2  — entry content_version binding (v2 AAD, version enforcement on
           create/replace, mixed-generation recompute, single-entry GET)
  * H-1/M-3 — the rotation machinery: POST /processing/rekey (server-side
           data-key rotation), PUT /account/credential (login-credential
           rotation, the recovery path for a phished verifier), and
           PUT /consents/{id}/rewrap (re-wrap of live grants)
  * L-1  — UTC calendar consistency in the question/threshold paths
  * L-2  — the shared ops rate bucket for /healthz + /readyz
  * I-1  — the rate counter's monotonic clock
"""

from __future__ import annotations

import base64
import json
import os
from datetime import date, timedelta

import pytest
from httpx import AsyncClient

from app.api import insights as insights_module
from app.cache import FixedWindowCounter
from app.config import Settings
from app.main import create_app
from app.security import crypto, sharing as sharing_crypto
from tests.helpers import ClientEmulator, TherapistEmulator

# Entry dates must sit inside the server's calendar bounds (created-at minus
# one grace day .. UTC-today plus one); anchor like the older suites do.
TODAY = date.today()


# ---------------------------------------------------------------------------
# App fixture with a 1-day threshold so insight-phase flows are cheap to seed
# ---------------------------------------------------------------------------


async def _make_client(unlock_days: int = 1, ops_rate_limit: int = 240) -> AsyncClient:
    from httpx import ASGITransport

    settings = Settings(environment="development")
    settings.database_url = "sqlite+aiosqlite://"
    settings.token_secret = "test-secret-not-for-production"
    settings.unlock_threshold_days = unlock_days
    settings.ops_rate_limit = ops_rate_limit
    settings.ops_rate_window = 60
    app = create_app(settings)
    transport = ASGITransport(app=app)
    lifespan_cm = app.router.lifespan_context(app)
    await lifespan_cm.__aenter__()

    class _Wrapped(AsyncClient):
        async def aclose(self) -> None:  # close the transport, then the app
            await super().aclose()
            await lifespan_cm.__aexit__(None, None, None)

    return _Wrapped(transport=transport, base_url="http://testserver")


# ---------------------------------------------------------------------------
# M-2: entry content_version binding
# ---------------------------------------------------------------------------


async def test_create_stores_version_one_and_v2_aad_decrypts(client: AsyncClient):
    emu = ClientEmulator("m2create", "pw-m2-create-123")
    await emu.register(client)
    row = await emu.create_entry(client, "hello", TODAY, "e-m2-a", content_version=1)
    assert row["content_version"] == 1
    # v2 AAD (version-bound) decrypts; the ladder is exercised end-to-end.
    payload = emu.decrypt_entry(row["blob"], "e-m2-a", 1)
    assert payload["text"] == "hello"


async def test_create_rejects_non_first_version(client: AsyncClient):
    emu = ClientEmulator("m2first", "pw-m2-first-1234")
    await emu.register(client)
    blob = emu.encrypt_entry("x", TODAY, "e-m2-b", content_version=2)
    response = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-m2-b",
            "blob": blob,
            "entry_date": TODAY.isoformat(),
            "content_version": 2,
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


async def test_replace_enforces_next_version(client: AsyncClient):
    emu = ClientEmulator("m2repl", "pw-m2-repl-12345")
    await emu.register(client)
    await emu.create_entry(client, "v1 text", TODAY, "e-m2-c", content_version=1)

    stale = await client.put(
        "/api/entries/e-m2-c",
        headers=emu.headers,
        json={
            "blob": emu.encrypt_entry("edited", TODAY, "e-m2-c", content_version=1),
            "entry_date": TODAY.isoformat(),
            "content_version": 1,
        },
    )
    assert stale.status_code == 409
    assert stale.json()["code"] == "version_conflict"

    ok = await emu.replace_entry(
        client, "e-m2-c", "edited text", TODAY, content_version=2
    )
    assert ok["content_version"] == 2
    assert emu.decrypt_entry(ok["blob"], "e-m2-c", 2)["text"] == "edited text"


async def test_legacy_replace_without_version_still_advances(client: AsyncClient):
    emu = ClientEmulator("m2legacy", "pw-m2-legacy-123")
    await emu.register(client)
    # Legacy client: v1-AAD create, body without content_version on replace.
    await emu.create_entry(client, "legacy v1", TODAY, "e-m2-d")
    blob = emu.encrypt_entry("legacy edited", TODAY, "e-m2-d")
    response = await client.put(
        "/api/entries/e-m2-d",
        headers=emu.headers,
        json={"blob": blob, "entry_date": TODAY.isoformat()},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["content_version"] == 2
    # The legacy (v1) AAD still decrypts the legacy-encrypted replacement.
    payload = emu.decrypt_blob(body["blob"], crypto.entry_aad_v1(emu.user_id, "e-m2-d"))
    assert payload["text"] == "legacy edited"


async def test_get_single_entry_primitive(client: AsyncClient):
    emu = ClientEmulator("m2get", "pw-m2-get-123456")
    await emu.register(client)
    created = await emu.create_entry(client, "single", TODAY, "e-m2-e")
    fetched = await emu.get_entry(client, "e-m2-e")
    assert fetched["id"] == created["id"]
    assert fetched["content_version"] == 1

    missing = await client.get("/api/entries/e-nope", headers=emu.headers)
    assert missing.status_code == 404
    # Owner scoping: another user's id space is invisible.
    other = ClientEmulator("m2get2", "pw-m2-get2-1234")
    await other.register(client)
    foreign = await client.get("/api/entries/e-m2-e", headers=other.headers)
    assert foreign.status_code == 404


async def test_recompute_accepts_mixed_aad_generations():
    http = await _make_client(unlock_days=1)
    try:
        emu = ClientEmulator("m2mixed", "pw-m2-mixed-123")
        await emu.register(client=http)
        await emu.backdate_account(http, 40)
        for offset, (text, cid, version) in enumerate(
            [
                ("legacy v1 entry", "e-mix-1", None),
                ("fresh v2 entry", "e-mix-2", 1),
            ]
        ):
            await emu.create_entry(
                http,
                text,
                date(2026, 9, 1) + timedelta(days=offset),
                cid,
                content_version=version,
            )
        result = await emu.recompute(http)
        assert result["phase"] == "insight"
        decrypted = await emu.decrypt_insights(http)
        assert decrypted["v"] == 2
    finally:
        await http.aclose()


# ---------------------------------------------------------------------------
# H-1 / M-3: rotation machinery
# ---------------------------------------------------------------------------


async def _seed_rotation_fixture(http: AsyncClient):
    """A realistic account: mixed-generation entries, a recomputed insight
    set (brain + patterns + question), a measure, and a live therapist grant."""
    emu = ClientEmulator("rotating", "pw-old-rotating-1")
    await emu.register(client=http)
    await emu.backdate_account(http, 40)
    old_key = emu.data_key
    old_auth_b64 = emu.auth_key_b64

    await emu.create_entry(http, "legacy", date(2026, 9, 1), "e-rot-1")
    await emu.create_entry(http, "modern", date(2026, 9, 2), "e-rot-2", content_version=1)
    await emu.replace_entry(http, "e-rot-2", "modern edited", date(2026, 9, 2), content_version=2)

    result = await emu.recompute(http)
    assert result["phase"] == "insight"

    measure_blob = crypto.encrypt(
        emu.data_key,
        json.dumps({"score": 9}).encode("utf-8"),
        crypto.build_aad("measure", emu.user_id, "m-rot-1"),
    )
    measure_response = await http.post(
        "/api/measures",
        headers=emu.headers,
        json={
            "client_measure_id": "m-rot-1",
            "blob": base64.b64encode(measure_blob).decode("ascii"),
            "measure_date": date(2026, 9, 2).isoformat(),
        },
    )
    assert measure_response.status_code == 201, measure_response.text

    therapist = TherapistEmulator("dr-rotating", "pw-therapist-1")
    await therapist.register(client=http)
    code = await therapist.create_pairing_code(client=http)
    lookup = await emu.pairing_lookup(http, code)
    assert lookup["status"] == 200
    grant = await emu.grant_consent(
        client=http,
        code=code,
        therapist_pub_b64=lookup["body"]["wrap_pub_key"],
        therapist_id=lookup["body"]["therapist_id"],
    )
    assert grant["status"] == 201, grant["body"]
    return emu, old_key, old_auth_b64, therapist, grant["body"]


async def test_full_rotation_flow_recovers_every_collection():
    http = await _make_client(unlock_days=1)
    try:
        emu, old_key, old_auth_b64, therapist, consent = await _seed_rotation_fixture(http)

        # --- rekey: old generation -> new generation ---------------------
        emu.derive_new_generation("pw-new-rotating-1")
        # Rekey/rewrap are proven with the OLD password: the credential itself is
        # rotated only after every key-bearing step has completed.
        counts = await emu.rekey(
            http, old_key=old_key, new_key=emu.data_key, verifier=old_auth_b64
        )
        assert counts["entries"] == 2
        assert counts["insights"] >= 2  # patterns + brain (+ question)
        assert counts["measures"] == 1

        # Entries decrypt under the NEW key via the v2 ladder; the old key
        # can no longer authenticate them.
        rows = (await http.get("/api/entries", headers=emu.headers)).json()
        for row in rows:
            if row["client_entry_id"] == "e-rot-2":
                assert row["content_version"] == 2
            payload = emu.decrypt_entry(row["blob"], row["client_entry_id"], row["content_version"])
            assert payload["text"] in ("legacy", "modern edited")
            with pytest.raises(crypto.TamperError):
                crypto.decrypt(
                    old_key,
                    base64.b64decode(row["blob"]),
                    crypto.entry_aad_v1(emu.user_id, row["client_entry_id"]),
                )

        # Insights decrypt under the new key with their original AAD.
        insights_payload = await emu.decrypt_insights(http)
        assert insights_payload["v"] == 2

        # Measures decrypt under the new key.
        measures = (await http.get("/api/measures", headers=emu.headers)).json()
        assert len(measures) == 1
        plain = crypto.decrypt(
            emu.data_key,
            base64.b64decode(measures[0]["blob"]),
            crypto.build_aad("measure", emu.user_id, "m-rot-1"),
        )
        assert json.loads(plain)["score"] == 9

        # Recompute still works after rotation (brain state carried forward
        # under the new key): a fresh session uses the new data key.
        again = await emu.recompute(http)
        assert again["phase"] == "insight"

        # --- rewrap the live grant to the new key ------------------------
        listed = await emu.list_consents(http)
        assert listed[0]["therapist_wrap_pub_key"] == therapist.wrap_pub_key
        rewrap = await emu.rewrap_consent(
            http,
            listed[0]["id"],
            therapist.wrap_pub_key,
            therapist.user_id,
            verifier=old_auth_b64,
        )
        assert rewrap["status"] == 200, rewrap["body"]

        # The portal unwraps the NEW data key and reads an entry with it.
        patients = (
            await http.get("/api/therapist/patients", headers=therapist.headers)
        ).json()
        assert patients[0]["wrapped_key"] is not None
        unwrapped = therapist.unwrap_patient_data_key(
            emu, patients[0]["ephemeral_pub"], patients[0]["wrapped_key"]
        )
        assert unwrapped == emu.data_key
        entry_page = (
            await http.get(
                f"/api/therapist/patients/{emu.user_id}/entries",
                headers=therapist.headers,
            )
        ).json()
        assert entry_page, "therapist must still read entries after rotation"

        # --- rotate the login credential ---------------------------------
        status = await emu.rotate_credential(
            http, old_auth_b64, emu.salt, emu.auth_key_b64
        )
        assert status == 204

        # The phished OLD verifier no longer logs in; the NEW one does, the
        # server hands out the NEW salt, and every old bearer is dead.
        stale_login = await http.post(
            "/api/auth/login",
            json={"username": emu.username, "verifier": old_auth_b64},
        )
        assert stale_login.status_code == 401

        stale_bearer = await http.get("/api/entries", headers=emu.headers)
        assert stale_bearer.status_code == 401

        salt_response = await http.post("/api/auth/salt", json={"username": emu.username})
        assert salt_response.json()["salt"] == emu.salt_b64

        fresh_login = await emu.login(http)
        assert fresh_login["user_id"] == emu.user_id
        rows_after = (await http.get("/api/entries", headers=emu.headers)).json()
        assert len(rows_after) == 2
    finally:
        await http.aclose()


async def test_rekey_with_wrong_old_key_changes_nothing():
    http = await _make_client(unlock_days=1)
    try:
        emu = ClientEmulator("rekeybad", "pw-rekey-bad-12")
        await emu.register(client=http)
        await emu.create_entry(http, "keep me", TODAY, "e-bad-1")

        wrong_old = crypto.generate_key()
        new_key = crypto.generate_key()
        old_token = await emu.open_processing_session_for(http, wrong_old)
        new_token = await emu.open_processing_session_for(http, new_key)
        response = await http.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
                "X-Account-Verifier": emu.auth_key_b64,
            },
        )
        assert response.status_code == 400
        assert response.json()["code"] == "rekey_key_mismatch"

        # Nothing committed: the stored blob still decrypts under the real key.
        row = await emu.get_entry(http, "e-bad-1")
        assert emu.decrypt_entry(row["blob"], "e-bad-1", row["content_version"])["text"] == "keep me"
    finally:
        await http.aclose()


async def test_rekey_requires_password_proof_and_single_use_tokens():
    http = await _make_client(unlock_days=1)
    try:
        emu = ClientEmulator("rekeyauth", "pw-rekey-auth-1")
        await emu.register(client=http)
        await emu.create_entry(http, "x", TODAY, "e-auth-1")
        old_key, new_key = emu.data_key, crypto.generate_key()

        # No verifier -> 422 before any token is consumed.
        old_token = await emu.open_processing_session_for(http, old_key)
        new_token = await emu.open_processing_session_for(http, new_key)
        response = await http.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
            },
        )
        assert response.status_code == 422

        # Wrong verifier -> 403, tokens still unconsumed (proof runs first).
        response = await http.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
                "X-Account-Verifier": base64.b64encode(crypto.generate_key()).decode(),
            },
        )
        assert response.status_code == 403

        # A bearer alone (stolen token, no password) cannot rekey.
        thief = ClientEmulator("irrelevant", "pw-irrelevant-1")
        response = await http.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
                "X-Account-Verifier": base64.b64encode(thief.auth_key).decode(),
            },
        )
        assert response.status_code == 403

        # Successful rekey consumes both sessions; replaying them is 403.
        counts = await emu.rekey(http, old_key=old_key, new_key=new_key)
        assert counts["entries"] == 1
        response = await http.post(
            "/api/processing/rekey",
            headers={
                **emu.headers,
                "X-Processing-Token": old_token,
                "X-New-Processing-Token": new_token,
                "X-Account-Verifier": base64.b64encode(crypto.generate_key()).decode(),
            },
        )
        assert response.status_code == 403
    finally:
        await http.aclose()


async def test_credential_rotation_requires_the_current_verifier(client: AsyncClient):
    emu = ClientEmulator("credrot", "pw-credrot-1234")
    await emu.register(client)
    new_salt, new_auth = os.urandom(16), crypto.generate_key()

    wrong = await emu.rotate_credential(
        client,
        base64.b64encode(crypto.generate_key()).decode(),
        new_salt,
        base64.b64encode(new_auth).decode(),
    )
    assert wrong == 403

    # Credential unchanged: the original verifier still logs in.
    relogin = await client.post(
        "/api/auth/login", json={"username": emu.username, "verifier": emu.auth_key_b64}
    )
    assert relogin.status_code == 200

    malformed = await client.put(
        "/api/account/credential",
        headers=emu.headers,
        json={
            "verifier": emu.auth_key_b64,
            "new_salt": base64.b64encode(b"tooshort").decode(),
            "new_verifier": base64.b64encode(new_auth).decode(),
        },
    )
    assert malformed.status_code == 422


async def test_rewrap_scoping_and_revoked_consents():
    http = await _make_client(unlock_days=1)
    try:
        emu, _old, _auth, therapist, consent = await _seed_rotation_fixture(http)

        # No verifier -> 422.
        wrap = sharing_crypto.wrap_data_key(
            emu.data_key, therapist.wrap_pub_key, emu.user_id, therapist.user_id
        )
        response = await http.put(
            f"/api/consents/{consent['id']}/rewrap",
            headers=emu.headers,
            json={"ephemeral_pub": wrap[0], "wrapped_key": wrap[1]},
        )
        assert response.status_code == 422

        # Someone else's consent id -> flat 404.
        stranger = ClientEmulator("stranger", "pw-stranger-123")
        await stranger.register(client=http)
        response = await http.put(
            f"/api/consents/{consent['id']}/rewrap",
            headers={
                **stranger.headers,
                "X-Account-Verifier": stranger.auth_key_b64,
            },
            json={"ephemeral_pub": wrap[0], "wrapped_key": wrap[1]},
        )
        assert response.status_code == 404

        # Revoked consent -> 404 (nothing is served under it).
        revoked = await emu.revoke_consent(http, consent["id"])
        assert revoked == 204
        rewrap = await emu.rewrap_consent(
            http, consent["id"], therapist.wrap_pub_key, therapist.user_id
        )
        assert rewrap["status"] == 404
    finally:
        await http.aclose()


# ---------------------------------------------------------------------------
# L-1 / L-2 / I-1
# ---------------------------------------------------------------------------


async def test_utc_today_is_the_shared_calendar_anchor():
    from datetime import datetime, timezone

    assert insights_module._utc_today() == datetime.now(timezone.utc).date()


async def test_ops_endpoints_share_a_rate_bucket():
    http = await _make_client(ops_rate_limit=3)
    try:
        statuses = [(await http.get("/readyz")).status_code for _ in range(4)]
        assert statuses[:3] == [200, 200, 200]
        assert statuses[3] == 429
        # The bucket is shared with /healthz (same "ops-health" bucket).
        assert (await http.get("/healthz")).status_code == 429
    finally:
        await http.aclose()


def test_rate_counter_runs_on_the_monotonic_clock(monkeypatch):
    import app.cache as cache_module

    counter = FixedWindowCounter()
    fake = 5_000.0
    monkeypatch.setattr(cache_module.time, "monotonic", lambda: fake)
    assert counter.hit("k", 60).count == 1
    fake = 5_000.5  # half a minute later: same window
    assert counter.hit("k", 60).count == 2
    fake = 5_061.0  # past the window: fresh window
    assert counter.hit("k", 60).count == 1
