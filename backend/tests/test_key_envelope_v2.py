"""v2 key-scheme surfaces (2026-09-26 crypto-architecture remediation wave).

Covers, per remediation item:
  1. the random data-key ENVELOPE — v2 register/login/unwrap-fetch, the O(1)
     password re-wrap, the v1 self-upgrade, v1 flows unchanged;
  2. the VERSIONED kdf_params blob — structure/bounds validation and the
     canonical-JSON rule that feeds the envelope AAD;
  3. SAS out-of-band pairing verification — both sides derive the same SAS,
     key substitution changes it, code rotation invalidates it;
  4. per-token revocation (jti) + purpose-split secrets — single-token
     logout vs a live sibling token, ksv rotation, secret resolution,
     TOTP wrap under the dedicated secret across the legacy derivation;
  5. the LOW items that landed as code: rekey plaintext scrubbing, envelope
     vectors in shared/vectors.json, the drift-window change (pinned in
     test_totp.py), and the scrypt work factor (pinned in test_mutation_pins
     .py / test_security_fixes.py).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import date, datetime, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import AsyncClient

from app.security import crypto, envelope, kdf, sharing
from tests.helpers import FAST_ITERATIONS, ClientEmulator, EnvelopeClientEmulator, TherapistEmulator

# Clock-anchored (independent audit 2026-09-27): the entry API validates
# entry_date against the SERVER's UTC today minus a 1-day backdate grace,
# so a fixed date ages out the night the UTC clock passes it — the suite
# went red at 2026-09-28T00:00Z with zero code changes. Anchor on the
# server clock instead; the engine math below is date-agnostic.
TODAY = datetime.now(timezone.utc).date()


# ===========================================================================
# 1 + 2. Envelope module + kdf_params blob (unit contract)
# ===========================================================================


def _default_params() -> dict[str, int | str]:
    return dict(kdf.KDF_PARAMS_DEFAULT)


def test_envelope_kek_is_deterministic_and_salt_bound():
    master = bytes(range(32))
    salt_a, salt_b = bytes(range(16)), bytes(range(16, 32))
    kek = envelope.envelope_kek(master, salt_a)
    assert len(kek) == 32
    assert kek == envelope.envelope_kek(master, salt_a)
    assert kek != envelope.envelope_kek(master, salt_b)
    # Domain separation from the auth/data HKDF labels over the same inputs.
    assert kek != kdf.derive_auth_key(master)
    assert kek != kdf.derive_data_key(master)
    with pytest.raises(ValueError, match="at least 16 bytes"):
        envelope.envelope_kek(b"short", salt_a)


def test_envelope_aad_is_canonical_and_binding():
    params = _default_params()
    aad = envelope.envelope_aad("alice", params)
    assert aad.startswith(b'{"context":"envelope"')
    assert b'"username":"alice"' in aad
    # The embedded kdf_params are the canonical JSON blob.
    assert kdf.canonical_kdf_params_json(params).encode() in aad
    # Different account or params -> different AAD bytes.
    assert aad != envelope.envelope_aad("bob", params)
    other = dict(params, iterations=600_001)
    assert aad != envelope.envelope_aad("alice", other)


def test_envelope_wrap_unwrap_roundtrip_and_tamper():
    params = _default_params()
    master = bytes(range(32))
    salt = bytes(range(16, 32))
    kek = envelope.envelope_kek(master, salt)
    data_key = os.urandom(32)
    nonce = bytes(range(40, 52))
    wrapped = envelope.wrap_data_key(
        data_key, kek=kek, username="alice", kdf_params=params, nonce=nonce
    )
    assert len(wrapped) == envelope.WRAPPED_DATA_KEY_BYTES == 60
    assert wrapped.startswith(nonce)
    got = envelope.unwrap_data_key(wrapped, kek=kek, username="alice", kdf_params=params)
    assert got == data_key
    # Wrong password (different KEK) is TamperError, not plaintext.
    with pytest.raises(crypto.TamperError):
        envelope.unwrap_data_key(
            wrapped,
            kek=envelope.envelope_kek(bytes(range(1, 33)), salt),
            username="alice",
            kdf_params=params,
        )
    # Relocation (wrong account) and params mismatch both fail authentication.
    with pytest.raises(crypto.TamperError):
        envelope.unwrap_data_key(wrapped, kek=kek, username="mallory", kdf_params=params)
    with pytest.raises(crypto.TamperError):
        envelope.unwrap_data_key(
            wrapped,
            kek=kek,
            username="alice",
            kdf_params=dict(params, iterations=600_001),
        )
    # Argument-shape failures (vector-generation callers only, but the
    # reference implementation refuses wrong sizes loudly).
    with pytest.raises(ValueError, match="data_key must be 32 bytes"):
        envelope.wrap_data_key(b"short", kek=kek, username="alice", kdf_params=params, nonce=nonce)
    with pytest.raises(ValueError, match="kek must be 32 bytes"):
        envelope.wrap_data_key(
            data_key, kek=b"short", username="alice", kdf_params=params, nonce=nonce
        )
    with pytest.raises(ValueError, match="kek must be 32 bytes"):
        envelope.unwrap_data_key(wrapped, kek=b"short", username="alice", kdf_params=params)
    # Tampered bytes fail; a structurally wrong SIZE is ValueError.
    bad = bytearray(wrapped)
    bad[30] ^= 0x01
    with pytest.raises(crypto.TamperError):
        envelope.unwrap_data_key(bytes(bad), kek=kek, username="alice", kdf_params=params)
    with pytest.raises(ValueError, match="exactly 60"):
        envelope.unwrap_data_key(b"x" * 59, kek=kek, username="alice", kdf_params=params)


def test_kdf_params_validation_matrix():
    # The shipped default and a full argon2id blob are the two valid shapes.
    assert kdf.validate_kdf_params(_default_params()) == _default_params()
    argon = {
        "algorithm": "argon2id",
        "memory_kib": 65536,
        "parallelism": 1,
        "iterations": 3,
        "version": 1,
    }
    assert kdf.validate_kdf_params(argon) == argon
    # Bounds: iterations, memory, parallelism, version, unknown fields.
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), iterations=99_999))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), iterations=10_000_001))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), algorithm="argon2id"))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(argon, memory_kib=19 * 1024 - 1))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(argon, memory_kib=256 * 1024 + 1))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(argon, iterations=1))
    # Symmetric ceiling (re-audit 2026-09-27): argon2id passes cap at 10M
    # exactly like PBKDF2 — a missing ceiling let a buggy client persist a
    # t value every future re-validation and argon2 consumer must honor.
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(argon, iterations=10_000_001))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(argon, parallelism=5))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(argon, parallelism=0))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), version=2))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), extra="field"))
    # pbkdf2 must not carry argon fields; bools are not costs; not a dict.
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), memory_kib=65536))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(dict(_default_params(), iterations=True))
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params([_default_params()])
    # Canonical JSON round-trip + fail-closed parse of stored garbage.
    canonical = kdf.canonical_kdf_params_json(argon)
    assert kdf.parse_kdf_params_json(canonical) == argon
    assert kdf.parse_kdf_params_json(None) is None
    assert kdf.parse_kdf_params_json("not json") is None
    assert kdf.parse_kdf_params_json('{"algorithm":"nope"}') is None


# ===========================================================================
# 1. v2 registration / envelope fetch / unlock (API)
# ===========================================================================


async def test_v2_register_login_and_envelope_roundtrip(client: AsyncClient):
    emu = EnvelopeClientEmulator("v2round", "correct-horse-v2")
    body = await emu.register(client)
    assert body["key_scheme"] == "v2"

    env = await emu.fetch_envelope(client)
    assert env["key_scheme"] == "v2"
    assert env["salt"] == emu.salt_b64
    assert env["kdf_params"] == emu.kdf_params
    unwrapped = emu.unwrap(env["wrapped_data_key"], emu.password, emu.salt)
    assert unwrapped == emu.data_key  # the random key, not a derivation

    # The envelope surface requires a bearer.
    anonymous = await client.get("/api/auth/key-envelope")
    assert anonymous.status_code == 401


async def test_v1_registration_unchanged_and_envelope_answers_v1(client: AsyncClient):
    emu = ClientEmulator("v1unchanged", "pw-v1-unchanged")
    body = await emu.register(client)
    assert body["key_scheme"] == "v1"
    env = await emu.fetch_envelope(client)
    assert env == {
        "key_scheme": "v1",
        "salt": emu.salt_b64,
        "kdf_params": None,
        "wrapped_data_key": None,
    }
    # The v1 key schedule still decrypts what the v1 client stores.
    await emu.create_entry(client, "v1 entry text", TODAY, client_entry_id="v1-e1")
    got = await emu.get_entry(client, "v1-e1")
    assert emu.decrypt_entry(got["blob"], "v1-e1", 1)["text"] == "v1 entry text"


async def test_v2_registration_field_pairing_and_validation(client: AsyncClient):
    emu = EnvelopeClientEmulator("v2bad", "pw-v2-bad")
    good_wrap = emu.wrap_for(emu.password, emu.salt)
    # kdf_params without wrapped_data_key (and vice versa) -> 422.
    for partial in (
        {"kdf_params": emu.kdf_params},
        {"wrapped_data_key": good_wrap},
        # Out-of-bounds iterations.
        {"kdf_params": dict(emu.kdf_params, iterations=10), "wrapped_data_key": good_wrap},
        # Wrong-size envelope (server pins the 60-byte wire shape).
        {
            "kdf_params": emu.kdf_params,
            "wrapped_data_key": base64.b64encode(b"x" * 32).decode(),
        },
    ):
        response = await client.post(
            "/api/auth/register",
            json={
                "username": emu.username,
                "salt": emu.salt_b64,
                "verifier": emu.auth_key_b64,
                **partial,
            },
        )
        assert response.status_code == 422, partial
        assert response.json()["code"] == "validation_error"
    # An argon2id blob is accepted (validate-and-store only — the server
    # never computes the KDF; the verifier path is KDF-blind).
    emu.kdf_params = {
        "algorithm": "argon2id",
        "memory_kib": 65536,
        "parallelism": 2,
        "iterations": 3,
        "version": 1,
    }
    argon_wrap = emu.wrap_for(emu.password, emu.salt)
    response = await client.post(
        "/api/auth/register",
        json={
            "username": emu.username,
            "salt": emu.salt_b64,
            "verifier": emu.auth_key_b64,
            "kdf_params": emu.kdf_params,
            "wrapped_data_key": argon_wrap,
        },
    )
    assert response.status_code == 201, response.text
    login = await client.post(
        "/api/auth/login", json={"username": emu.username, "verifier": emu.auth_key_b64}
    )
    assert login.status_code == 200
    env = await client.get(
        "/api/auth/key-envelope", headers={"Authorization": f"Bearer {login.json()['token']}"}
    )
    assert env.json()["kdf_params"]["algorithm"] == "argon2id"


# ===========================================================================
# 1. The O(1) v2 password change (and the v1 guards around it)
# ===========================================================================


async def test_v2_password_change_needs_no_rekey(client: AsyncClient):
    emu = EnvelopeClientEmulator("v2pw", "old-password-v2")
    await emu.register(client)
    await emu.create_entry(client, "written under the random key", TODAY, client_entry_id="v2-e1")
    old_data_key = emu.data_key

    assert (await emu.change_password(client, "new-password-v2")) == 204

    # Old bearer died (epoch bump) — re-login with the NEW credential.
    stale = await client.get("/api/entries", headers=emu.headers)
    assert stale.status_code == 401
    await emu.login(client)
    # The SAME random data key: the stored entry decrypts unchanged, and
    # the fetched envelope unwraps under the NEW password to the SAME key.
    got = await emu.get_entry(client, "v2-e1")
    assert emu.decrypt_entry(got["blob"], "v2-e1", 1)["text"] == "written under the random key"
    env = await emu.fetch_envelope(client)
    assert env["salt"] == emu.salt_b64  # the new salt was swapped atomically
    assert emu.unwrap(env["wrapped_data_key"], "new-password-v2", emu.salt) == old_data_key
    with pytest.raises(crypto.TamperError):
        emu.unwrap(env["wrapped_data_key"], "old-password-v2", emu.salt)


async def test_v2_password_change_requires_old_verifier_and_shapes(client: AsyncClient):
    emu = EnvelopeClientEmulator("v2pwbad", "pw-v2-pw-bad")
    await emu.register(client)
    # Wrong old-password proof -> 403, nothing changes.
    wrong = dict(
        verifier=base64.b64encode(b"\x00" * 32).decode(),
        new_salt=base64.b64encode(os.urandom(16)).decode(),
        new_verifier=emu.auth_key_b64,
        wrapped_data_key=emu.wrap_for("next", os.urandom(16)),
    )
    response = await client.put("/api/account/password", headers=emu.headers, json=wrong)
    assert response.status_code == 403
    assert response.json()["code"] == "verification_failed"
    # Verifier required; malformed blobs -> 422.
    ok_verifier = emu.auth_key_b64
    no_verifier = dict(wrong, verifier=None)  # type: ignore[arg-type]
    response = await client.put(
        "/api/account/password",
        headers={**emu.headers, "X-Account-Verifier": emu.auth_key_b64},
        json={
            "verifier": ok_verifier,
            "new_salt": "!!",
            "new_verifier": ok_verifier,
            "wrapped_data_key": emu.wrap_for("next", os.urandom(16)),
        },
    )
    assert response.status_code == 422
    response = await client.put(
        "/api/account/password",
        headers=emu.headers,
        json={
            "verifier": ok_verifier,
            "new_salt": base64.b64encode(os.urandom(16)).decode(),
            "new_verifier": base64.b64encode(b"\x00" * 31).decode(),
            "wrapped_data_key": emu.wrap_for("next", os.urandom(16)),
        },
    )
    assert response.status_code == 422
    del no_verifier


async def test_v2_password_change_requires_the_possession_probe(client: AsyncClient):
    """2026-09-28 audit M-1: the v2→v2 exemption let a stolen bearer +
    phished verifier overwrite wrapped_data_key with arbitrary bytes —
    permanent destruction of the only data-key locker. The probe is now
    required from EVERY caller, exactly like /key-envelope/upgrade."""
    emu = EnvelopeClientEmulator("v2probe", "pw-v2-probe-1")
    await emu.register(client)
    await emu.create_entry(client, "probe corpus", TODAY, client_entry_id="v2-p1")
    env_before = await emu.fetch_envelope(client)

    # The attacker's payload: valid shapes, verifier honest (phished), and
    # an envelope over 60 random bytes they will never be able to open.
    garbage = base64.b64encode(os.urandom(60)).decode("ascii")

    # No processing session at all -> 422 before anything is consumed.
    response = await client.put(
        "/api/account/password",
        headers=emu.headers,
        json={
            "verifier": emu.auth_key_b64,
            "new_salt": base64.b64encode(os.urandom(16)).decode(),
            "new_verifier": emu.auth_key_b64,
            "wrapped_data_key": garbage,
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "processing_session_required"

    # A session over the WRONG key fails the stored-ciphertext probe and
    # the envelope survives untouched.
    wrong_token = await emu.open_processing_session_for(client, crypto.generate_key())
    response = await client.put(
        "/api/account/password",
        headers={**emu.headers, "X-Processing-Token": wrong_token},
        json={
            "verifier": emu.auth_key_b64,
            "new_salt": base64.b64encode(os.urandom(16)).decode(),
            "new_verifier": emu.auth_key_b64,
            "wrapped_data_key": garbage,
        },
    )
    assert response.status_code == 403
    assert response.json()["code"] == "envelope_key_mismatch"
    env_after = await emu.fetch_envelope(client)
    assert env_after["wrapped_data_key"] == env_before["wrapped_data_key"]
    # The account still unlocks with the original password + envelope.
    assert await emu.unlock(client) == emu.data_key


async def test_credential_rotation_endpoint_refuses_v2_accounts(client: AsyncClient):
    """PUT /account/credential swaps the salt WITHOUT the envelope; for a
    v2 account that is unrecoverable data loss, so it answers 409 and the
    v1 path keeps working for v1 accounts."""
    v2 = EnvelopeClientEmulator("v2cred", "pw-v2-cred")
    await v2.register(client)
    new_salt = os.urandom(16)
    response = await client.put(
        "/api/account/credential",
        headers=v2.headers,
        json={
            "verifier": v2.auth_key_b64,
            "new_salt": base64.b64encode(new_salt).decode(),
            "new_verifier": v2.auth_key_b64,
        },
    )
    assert response.status_code == 409
    assert response.json()["code"] == "key_scheme_conflict"
    # v1 accounts keep the full legacy flow: rekey -> credential rotation.
    v1 = ClientEmulator("v1cred", "pw-v1-cred")
    await v1.register(client)
    await v1.create_entry(client, "before rotation", TODAY, client_entry_id="v1-c1")
    old_key, old_auth_b64 = v1.data_key, v1.auth_key_b64
    v1.derive_new_generation("pw-v1-cred-next")
    await v1.rekey(client, old_key, v1.data_key, verifier=old_auth_b64)
    assert (await v1.rotate_credential(client, old_auth_b64, v1.salt, v1.auth_key_b64)) == 204
    await v1.login(client)
    got = await v1.get_entry(client, "v1-c1")
    assert v1.decrypt_entry(got["blob"], "v1-c1", 1)["text"] == "before rotation"


# ===========================================================================
# 1. The v1 -> v2 self-upgrade (verifier-gated, possession-proved)
# ===========================================================================


async def test_v1_password_change_migration_requires_possession(client: AsyncClient):
    """Re-audit (2026-09-27): PUT /account/password on a v1 account swaps the
    ENVELOPE, so the uploaded wrap must be proven to cover the account's
    CURRENT data key — a buggy client could otherwise brick its whole corpus
    behind an unopenable locker. The v1 account must present a processing
    session whose key authenticates stored ciphertext (the
    /key-envelope/upgrade possession probe): wrong key -> 403
    envelope_key_mismatch with the account still v1; right key -> 204, the
    scheme flips, and the corpus keeps decrypting. v2→v2 changes stay
    exempt (covered by test_v2_password_change_needs_no_rekey, which sends
    no token)."""
    v1 = ClientEmulator("pw-migrate", "pw-migrate")
    await v1.register(client)
    await v1.create_entry(client, "pre-migration entry", TODAY, client_entry_id="pm-1")
    v2 = EnvelopeClientEmulator.__new__(EnvelopeClientEmulator)
    v2.__dict__.update(v1.__dict__)  # same account, v2 wrap helpers
    v2.kdf_params = dict(kdf.KDF_PARAMS_DEFAULT)

    # The migrating client's payload: verifier = OLD password proof; the
    # envelope wraps the CURRENT password-derived data key under the NEW
    # password's KEK (the real client wraps before sending).
    old_auth_b64 = v1.auth_key_b64
    new_password = "pw-migrate-next"
    new_salt = os.urandom(16)
    new_master = hashlib.pbkdf2_hmac("sha256", new_password.encode(), new_salt, FAST_ITERATIONS)
    new_auth_b64 = base64.b64encode(kdf.derive_auth_key(new_master)).decode("ascii")
    body = {
        "verifier": old_auth_b64,
        "new_salt": base64.b64encode(new_salt).decode("ascii"),
        "new_verifier": new_auth_b64,
        "wrapped_data_key": v2.wrap_for(new_password, new_salt),
    }

    # No processing token -> 422, nothing consumed, still v1.
    response = await client.put("/api/account/password", headers=v1.headers, json=body)
    assert response.status_code == 422
    assert response.json()["code"] == "processing_session_required"
    assert (await v1.fetch_envelope(client))["key_scheme"] == "v1"

    # Wrong-key token (32 bytes of garbage, not the derived data key): the
    # possession probe fails -> 403 envelope_key_mismatch, still v1, and
    # the pre-existing corpus is untouched.
    wrong_token = await v1.open_processing_session_for(client, os.urandom(32))
    response = await client.put(
        "/api/account/password",
        headers={**v1.headers, "X-Processing-Token": wrong_token},
        json=body,
    )
    assert response.status_code == 403
    assert response.json()["code"] == "envelope_key_mismatch"
    assert (await v1.fetch_envelope(client))["key_scheme"] == "v1"
    got = await v1.get_entry(client, "pm-1")
    assert v1.decrypt_entry(got["blob"], "pm-1", 1)["text"] == "pre-migration entry"

    # Right key — the CURRENT password-derived data key: 204, scheme flips,
    # the envelope opens to the SAME key under the NEW password, and the
    # corpus (never re-keyed) still decrypts.
    right_token = await v1.open_processing_session_for(client, v1.data_key)
    response = await client.put(
        "/api/account/password",
        headers={**v1.headers, "X-Processing-Token": right_token},
        json=body,
    )
    assert response.status_code == 204
    # The epoch bumped (every bearer died): re-login under the NEW password.
    v1.salt = new_salt
    v1.master_key = new_master
    v1.auth_key = kdf.derive_auth_key(new_master)  # data_key deliberately untouched
    await v1.login(client)
    env = await v1.fetch_envelope(client)
    assert env["key_scheme"] == "v2"
    assert v2.unwrap(env["wrapped_data_key"], new_password, v1.salt) == v1.data_key
    got = await v1.get_entry(client, "pm-1")
    assert v1.decrypt_entry(got["blob"], "pm-1", 1)["text"] == "pre-migration entry"


async def test_v1_upgrade_to_v2_with_possession_proof(client: AsyncClient):
    v1 = ClientEmulator("upgrademe", "pw-upgrade")
    await v1.register(client)
    await v1.create_entry(client, "pre-upgrade entry", TODAY, client_entry_id="up-1")
    v2 = EnvelopeClientEmulator.__new__(EnvelopeClientEmulator)
    v2.__dict__.update(v1.__dict__)  # same account, v2 wrap helpers
    v2.kdf_params = dict(kdf.KDF_PARAMS_DEFAULT)

    # Wrong-key possession proof: a session opened with garbage 32 bytes
    # does not authenticate the stored ciphertext -> 403, scheme unchanged.
    assert await v2.upgrade_to_v2(client, key=os.urandom(32)) == 403
    env = await v1.fetch_envelope(client)
    assert env["key_scheme"] == "v1"
    # Missing processing token / missing verifier -> 422 both.
    response = await client.post(
        "/api/account/key-envelope/upgrade",
        headers={**v1.headers, "X-Account-Verifier": v1.auth_key_b64},
        json={"wrapped_data_key": v2.wrap_for(v1.password, v1.salt)},
    )
    assert response.status_code == 422
    assert response.json()["code"] == "processing_session_required"
    response = await client.post(
        "/api/account/key-envelope/upgrade",
        headers={**v1.headers, "X-Processing-Token": "nope"},
        json={"wrapped_data_key": v2.wrap_for(v1.password, v1.salt)},
    )
    assert response.status_code == 422

    # Right key (the v1 password-DERIVED data key): 204, scheme flips, and
    # the stored corpus still decrypts under the same key via the envelope.
    assert await v2.upgrade_to_v2(client, key=v1.data_key) == 204
    env = await v1.fetch_envelope(client)
    assert env["key_scheme"] == "v2"
    assert v2.unwrap(env["wrapped_data_key"], v1.password, v1.salt) == v1.data_key
    got = await v1.get_entry(client, "up-1")
    assert v1.decrypt_entry(got["blob"], "up-1", 1)["text"] == "pre-upgrade entry"

    # Post-upgrade: the password change is O(1) and nothing re-keys.
    old_data_key = v1.data_key
    assert (await v2.change_password(client, "pw-upgrade-next")) == 204
    await v2.login(client)
    env = await v2.fetch_envelope(client)
    assert v2.unwrap(env["wrapped_data_key"], "pw-upgrade-next", v2.salt) == old_data_key
    got = await v2.get_entry(client, "up-1")
    assert v2.decrypt_entry(got["blob"], "up-1", 1)["text"] == "pre-upgrade entry"


async def test_upgrade_with_empty_corpus_and_bad_verifier(client: AsyncClient):
    v1 = ClientEmulator("upgrade-empty", "pw-upgrade-empty")
    await v1.register(client)  # no entries/insights/measures yet
    v2 = EnvelopeClientEmulator.__new__(EnvelopeClientEmulator)
    v2.__dict__.update(v1.__dict__)
    v2.kdf_params = dict(kdf.KDF_PARAMS_DEFAULT)
    # Empty corpus: possession is vacuous (nothing to authenticate) — the
    # documented migration-before-first-write path.
    assert await v2.upgrade_to_v2(client) == 204
    assert (await v1.fetch_envelope(client))["key_scheme"] == "v2"
    # A wrong verifier never consumes the processing session.
    fresh = ClientEmulator("upgrade-bad-verifier", "pw-upgrade-bv")
    await fresh.register(client)
    v2b = EnvelopeClientEmulator.__new__(EnvelopeClientEmulator)
    v2b.__dict__.update(fresh.__dict__)
    v2b.kdf_params = dict(kdf.KDF_PARAMS_DEFAULT)
    token = await fresh.open_processing_session(client)
    response = await client.post(
        "/api/account/key-envelope/upgrade",
        headers={
            **fresh.headers,
            "X-Processing-Token": token,
            "X-Account-Verifier": base64.b64encode(b"\x00" * 32).decode(),
        },
        json={"wrapped_data_key": v2b.wrap_for(fresh.password, fresh.salt)},
    )
    assert response.status_code == 403
    # The failed proof did NOT burn the uploaded key: the session still
    # pops (and is scrubbed here — the test is now its only owner).
    from app.security.enclave import zeroize

    app = client._transport.app  # noqa: SLF001 — test reachability into state
    held = app.state.key_store.pop(token, owner=fresh.user_id)
    assert len(held) == 32
    zeroize(held)


async def test_export_bundle_carries_the_v2_envelope(client: AsyncClient):
    emu = EnvelopeClientEmulator("v2export", "pw-v2-export")
    await emu.register(client)
    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200
    # The streamed bundle: '{' + head + ',"shares":[],' + ',"entries":[...'
    prefix = response.text.split(',"entries":[', 1)[0]
    head = json.loads(prefix.rstrip(",") + "}")
    assert head["key_scheme"] == "v2"
    assert head["kdf_params"] == emu.kdf_params
    assert emu.unwrap(head["wrapped_data_key"], emu.password, emu.salt) == emu.data_key


# ===========================================================================
# 3. SAS out-of-band pairing verification
# ===========================================================================


async def _setup_pairing(client: AsyncClient):
    patient = ClientEmulator("saspatient", "pw-sas")
    await patient.register(client)
    therapist = TherapistEmulator("sasdr", "pw")
    await therapist.register(client)
    code = await therapist.create_pairing_code(client)
    return patient, therapist, code


async def test_sas_matches_on_both_sides_and_binds_the_key(client: AsyncClient):
    patient, therapist, code = await _setup_pairing(client)
    lookup = await patient.pairing_lookup(client, code)
    assert lookup["status"] == 200
    patient_sas = lookup["body"]["sas"]
    fingerprint = lookup["body"]["wrap_key_fingerprint"]
    assert len(patient_sas) == 7 and patient_sas[3] == " "
    assert patient_sas.replace(" ", "").isdigit()
    assert len(fingerprint) == 16

    # The therapist side derives the IDENTICAL pair for the same session.
    therapist_sas = await client.get(
        "/api/therapist/pairing/sas",
        params={"patient_user_id": patient.user_id},
        headers={"X-Pairing-Code": code, **therapist.headers},
    )
    assert therapist_sas.status_code == 200, therapist_sas.text
    body = therapist_sas.json()
    assert body["sas"] == patient_sas
    assert body["wrap_key_fingerprint"] == fingerprint
    assert 0 < body["expires_in"] <= sharing.PAIRING_TTL_SECONDS

    # Independent construction check: the exact HMAC over (der + user id).
    der = base64.b64decode(therapist.wrap_pub_key)
    assert patient_sas == sharing.pairing_sas(code, der, patient.user_id)
    assert fingerprint == sharing.wrap_key_fingerprint(der)


async def test_sas_changes_with_key_and_code(client: AsyncClient, app):
    patient, therapist, code = await _setup_pairing(client)
    lookup = (await patient.pairing_lookup(client, code))["body"]

    # A DIFFERENT therapist key derives a different SAS for the same code
    # and patient — the malicious-server substitution the SAS exists to
    # catch. Computed directly (the server would never serve a foreign
    # key's SAS for its own therapist row).
    other_key = ec.generate_private_key(ec.SECP256R1())
    other_der = other_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    assert sharing.pairing_sas(code, other_der, patient.user_id) != lookup["sas"]
    # A different patient id also changes the SAS (binds the grant target).
    assert sharing.pairing_sas(code, other_der, "user-someone-else") != lookup["sas"]
    # A different CODE (fresh pairing session) changes the SAS: rotation
    # inherently invalidates the previous comparison string.
    second_code = await therapist.create_pairing_code(client)
    assert second_code != code
    assert (
        sharing.pairing_sas(second_code, base64.b64decode(therapist.wrap_pub_key), patient.user_id)
        != lookup["sas"]
    )

    # Burning the code (a grant consumes it) kills the therapist SAS read.
    grant = await patient.grant_consent(client, code, therapist.wrap_pub_key, therapist.user_id)
    assert grant["status"] == 201
    gone = await client.get(
        "/api/therapist/pairing/sas",
        params={"patient_user_id": patient.user_id},
        headers={"X-Pairing-Code": code, **therapist.headers},
    )
    assert gone.status_code == 404
    # The new code's SAS endpoint works but differs from the burned one's.
    fresh = await client.get(
        "/api/therapist/pairing/sas",
        params={"patient_user_id": patient.user_id},
        headers={"X-Pairing-Code": second_code, **therapist.headers},
    )
    assert fresh.status_code == 200
    assert fresh.json()["sas"] != lookup["sas"]


async def test_sas_endpoint_walls(client: AsyncClient):
    patient, therapist, code = await _setup_pairing(client)
    # Therapist-authenticated only.
    anon = await client.get("/api/therapist/pairing/sas", params={"patient_user_id": "x" * 32})
    # Exact pin (2026-09-28): anonymous → 401 (the flat wall).
    assert anon.status_code == 401
    as_patient = await client.get(
        "/api/therapist/pairing/sas",
        params={"patient_user_id": patient.user_id},
        headers={"X-Pairing-Code": code, **patient.headers},
    )
    assert as_patient.status_code == 403
    # Someone ELSE's code must not answer (flat 404, no oracle).
    other = TherapistEmulator("sasother", "pw")
    await other.register(client)
    foreign = await client.get(
        "/api/therapist/pairing/sas",
        params={"patient_user_id": patient.user_id},
        headers={"X-Pairing-Code": code, **other.headers},
    )
    assert foreign.status_code == 404
    # No live session at all -> 404.
    no_code = await client.get(
        "/api/therapist/pairing/sas",
        params={"patient_user_id": patient.user_id},
        headers=therapist.headers,
    )
    assert no_code.status_code == 404


# ===========================================================================
# 4. Per-token revocation + purpose-split secrets
# ===========================================================================


async def test_logout_kills_only_the_revoked_token(client: AsyncClient, app):
    emu = ClientEmulator("jtitest", "pw-jti")
    await emu.register(client)
    first = emu.token
    second_body = await emu.login(client)
    assert second_body["token"] != first

    assert (await client.post("/api/auth/logout", headers=emu.headers)).status_code == 204
    dead = await client.get("/api/entries", headers=emu.headers)
    assert dead.status_code == 401
    alive = await client.get("/api/entries", headers={"Authorization": f"Bearer {first}"})
    assert alive.status_code == 200
    # Credential rotation remains the GLOBAL revocation: epoch bump kills
    # the still-live sibling token too.
    await client.post("/api/auth/logout", headers={"Authorization": f"Bearer {first}"})
    last = (await emu.login(client))["token"]
    new_salt = os.urandom(16)
    emu2 = ClientEmulator("jtitest", "pw-jti")
    emu2.__dict__.update(emu.__dict__)
    emu2.derive_new_generation("pw-jti-next", new_salt)
    status = await emu2.rotate_credential(client, emu.auth_key_b64, new_salt, emu2.auth_key_b64)
    assert status == 204
    after_rotate = await client.get("/api/entries", headers={"Authorization": f"Bearer {last}"})
    assert after_rotate.status_code == 401


async def test_token_claims_carry_jti_purpose_and_ksv(client: AsyncClient, app):
    from app.security import tokens as tokens_module

    emu = ClientEmulator("claimsuser", "pw-claims")
    body = await emu.register(client)
    payload = tokens_module.verify_token(body["token"], app.state.settings.auth_token_secret)
    assert payload["purpose"] == "patient"
    assert payload["ksv"] == 1
    assert len(payload["jti"]) == 32

    th = TherapistEmulator("claimsdr", "pw")
    th_body = await th.register(client)
    th_payload = tokens_module.verify_token(th_body["token"], app.state.settings.auth_token_secret)
    assert th_payload["purpose"] == "therapist"
    # Two tokens for one account never share a jti.
    again = await emu.login(client)
    second = tokens_module.verify_token(again["token"], app.state.settings.auth_token_secret)
    assert second["jti"] != payload["jti"]


async def test_ksv_rotation_invalidates_cleanly(client: AsyncClient, app):
    """Setting the dedicated auth secret (ksv 1 -> 2) kills outstanding
    bearers EVEN when the operator copies the same bytes."""
    emu = ClientEmulator("ksvuser", "pw-ksv")
    await emu.register(client)
    ok = await client.get("/api/entries", headers=emu.headers)
    assert ok.status_code == 200

    settings = app.state.settings
    assert settings.auth_secret_version == 1
    settings.auth_token_secret_explicit = settings.token_secret  # same BYTES
    assert settings.auth_token_secret == settings.token_secret
    assert settings.auth_secret_version == 2

    rotated = await client.get("/api/entries", headers=emu.headers)
    assert rotated.status_code == 401
    settings.auth_token_secret_explicit = ""  # restore for other fixtures


def test_token_claim_shapes_are_hardened():
    """jti/purpose/ksv shape policing: a well-SIGNED token carrying a
    hostile claim shape is malformed, never a 500 or a silent accept."""
    import base64
    import hashlib
    import hmac as hmac_mod
    import json

    from app.security import tokens as tokens_module

    def signed(payload_dict: dict) -> str:
        body = tokens_module._b64url_encode(
            json.dumps(payload_dict, separators=(",", ":")).encode()
        )
        sig = tokens_module._b64url_encode(
            hmac_mod.new(b"s", body.encode(), hashlib.sha256).digest()
        )
        return f"{body}.{sig}"

    base = {"uid": "u", "exp": 9_999_999_999}
    # Bad jtis: wrong length, non-hex, non-string, bool-ish.
    for bad_jti in ("abc", "z" * 32, "A" * 32, 42, True, {"jti": 1}, None):
        with pytest.raises(tokens_module.TokenError):
            tokens_module.verify_token(signed({**base, "jti": bad_jti}), "s")
    # A well-formed jti parses; unknown purpose and bad ksv fail closed.
    assert tokens_module.verify_token(signed({**base, "jti": "a" * 32}), "s")["jti"] == "a" * 32
    for bad_purpose in ("refresh", "admin", "", 1, None):
        with pytest.raises(tokens_module.TokenError):
            tokens_module.verify_token(signed({**base, "purpose": bad_purpose}), "s")
    for bad_ksv in (0, -1, True, "1", 1.5):
        with pytest.raises(tokens_module.TokenError):
            tokens_module.verify_token(signed({**base, "ksv": bad_ksv}), "s")
    assert tokens_module.verify_token(signed({**base, "ksv": 2}), "s")["ksv"] == 2
    # The issuer refuses an unknown purpose and non-positive ttl up front.
    with pytest.raises(ValueError, match="purpose"):
        tokens_module.issue_token("u", "s", 60, purpose="refresh")
    with pytest.raises(ValueError, match="ttl_seconds"):
        tokens_module.issue_token("u", "s", 0)
    # Injected deterministic jti (vector/test-only parameter) round-trips.
    pinned = tokens_module.issue_token("u", "s", 60, jti="b" * 32)
    assert tokens_module.verify_token(pinned, "s")["jti"] == "b" * 32


def test_revocation_store_ttl_and_prune():
    from app.cache import TokenRevocationStore

    store = TokenRevocationStore()
    assert not store.is_revoked("a" * 32)
    store.revoke("a" * 32, expires_at_epoch=200.0, now=100.0)
    assert store.is_revoked("a" * 32, now=150.0)
    assert not store.is_revoked("b" * 32, now=150.0)
    # At expiry the entry frees itself (and stops answering revoked).
    assert not store.is_revoked("a" * 32, now=200.0)
    assert len(store) == 0
    # Legacy jti-less tokens are never members.
    assert not store.is_revoked(None)
    # Size cap evicts the OLDEST expiry first.
    capped = TokenRevocationStore(max_entries=2)
    capped.revoke("1" * 32, 300.0, now=0.0)
    capped.revoke("2" * 32, 200.0, now=0.0)
    capped.revoke("3" * 32, 400.0, now=0.0)
    assert not capped.is_revoked("2" * 32, now=1.0)  # evicted (earliest expiry)
    assert capped.is_revoked("1" * 32, now=1.0)
    assert capped.is_revoked("3" * 32, now=1.0)
    with pytest.raises(ValueError):
        capped.revoke("", 1.0)


def test_purpose_split_secret_resolution_and_validation(monkeypatch):
    from app.config import Settings

    # Legacy-only: every purpose resolves to the legacy secret (identity
    # derivation), live even after token_secret is mutated post-init.
    s = Settings(environment="development")
    s.token_secret = "late-mutation-secret"
    assert s.auth_token_secret == "late-mutation-secret"
    assert s.totp_wrap_secret == "late-mutation-secret"
    assert s.pairing_secret == "late-mutation-secret"
    assert s.auth_secret_version == 1
    # Explicit vars win per-purpose and bump the ksv for the auth secret.
    s2 = Settings(
        environment="development",
        token_secret="x" * 40,
        auth_token_secret_explicit="a" * 40,
        totp_wrap_secret_explicit="t" * 40,
        pairing_secret_explicit="p" * 40,
    )
    assert s2.auth_token_secret == "a" * 40
    assert s2.totp_wrap_secret == "t" * 40
    assert s2.pairing_secret == "p" * 40
    assert s2.auth_secret_version == 2
    # Production rejects short explicit secrets, and bad scrypt_n values.
    with pytest.raises(RuntimeError, match="MINDPATTERN_AUTH_TOKEN_SECRET"):
        Settings(
            environment="production", token_secret="y" * 40, auth_token_secret_explicit="short"
        )
    with pytest.raises(RuntimeError, match="MINDPATTERN_TOTP_WRAP_SECRET"):
        Settings(environment="production", token_secret="y" * 40, totp_wrap_secret_explicit="short")
    with pytest.raises(RuntimeError, match="MINDPATTERN_PAIRING_SECRET"):
        Settings(environment="production", token_secret="y" * 40, pairing_secret_explicit="short")
    for bad_n in (2**14, 3 * 2**15, 2**21, 0):
        with pytest.raises(RuntimeError, match="scrypt_n"):
            Settings(environment="development", scrypt_n=bad_n)
    # from_env wires the dedicated vars.
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "z" * 45)
    monkeypatch.setenv("MINDPATTERN_AUTH_TOKEN_SECRET", "auth" * 11)
    monkeypatch.setenv("MINDPATTERN_TOTP_WRAP_SECRET", "totp" * 11)
    monkeypatch.setenv("MINDPATTERN_PAIRING_SECRET", "pair" * 11)
    monkeypatch.setenv("MINDPATTERN_SCRYPT_N", "65536")
    wired = Settings.from_env()
    assert wired.auth_token_secret == "auth" * 11
    assert wired.totp_wrap_secret == "totp" * 11
    assert wired.pairing_secret == "pair" * 11
    assert wired.auth_secret_version == 2
    assert wired.scrypt_n == 65536


def test_totp_wrap_survives_legacy_derivation_and_splits_clean():
    """Wrapped TOTP secrets stay valid across the legacy-derivation path
    (wrap and unwrap both resolve to the same secret), and an explicit
    dedicated secret re-keys the wrap (old blobs stop opening)."""
    from app.config import Settings
    from app.security import totp

    legacy = Settings(environment="development", token_secret="legacy" * 8)
    assert legacy.totp_wrap_secret == legacy.token_secret
    raw, _ = totp.generate_secret()
    wrapped = totp.wrap_secret(raw, legacy.totp_wrap_secret)
    assert totp.unwrap_secret(wrapped, legacy.totp_wrap_secret) == raw
    assert totp.unwrap_secret(wrapped, legacy.token_secret) == raw  # identity path

    split = Settings(
        environment="development",
        token_secret="legacy" * 8,
        totp_wrap_secret_explicit="dedicated" * 8,
    )
    assert split.totp_wrap_secret != split.token_secret
    assert totp.unwrap_secret(wrapped, split.totp_wrap_secret) is None  # one-way rotation


# ===========================================================================
# 5. Rekey plaintext scrubbing + envelope vectors in shared/vectors.json
# ===========================================================================


def test_rekey_batches_scrub_plaintext_buffers(monkeypatch):
    """Every plaintext the rekey batch touches lands in a SecureBuffer that
    is zeroized before the batch returns (2026-09-26 LOW a)."""
    from app.api import insights as insights_api
    from app.security.enclave import SecureBuffer

    created: list[SecureBuffer] = []

    class RecordingBuffer(SecureBuffer):
        def __init__(self, data):
            super().__init__(data)
            created.append(self)

    monkeypatch.setattr(insights_api, "SecureBuffer", RecordingBuffer)

    key_old = crypto.generate_key()
    key_new = crypto.generate_key()
    user_id = "scrub-user"
    rows = []
    for i in range(3):
        cid = f"scrub-{i}"
        version = 1
        blob = crypto.encrypt(
            bytearray(key_old),
            b"secret text " + str(i).encode(),
            crypto.entry_aad_v1(user_id, cid),
        )
        rows.append((f"row-{i}", cid, version, blob))
    # One row already under the NEW key exercises the authentication-only
    # probe path, whose plaintext must be discarded too.
    rows.append(
        (
            "row-new",
            "scrub-new",
            1,
            crypto.encrypt(
                bytearray(key_new),
                b"already rotated",
                crypto.entry_aad_v2(user_id, "scrub-new", 1),
            ),
        )
    )

    reencrypted, already = insights_api._rekey_entry_batch(
        bytearray(key_old), bytearray(key_new), rows, user_id
    )
    assert already == 1 and len(reencrypted) == 3
    assert all(buf.is_zeroized() for buf in created), [
        bytes(buf.data) for buf in created if not buf.is_zeroized()
    ]
    # The ciphertexts are honestly under the new key with the v2 AAD.
    for row_id, blob in reencrypted:
        cid = dict((r[0], r[1]) for r in rows)[row_id]
        assert (
            crypto.decrypt(key_new, blob, crypto.entry_aad_v2(user_id, cid, 1)).startswith(
                b"secret text "
            )
            or row_id == "row-new"
        )
    # The blob-batch (insights/measures) scrubs identically.
    created.clear()
    insight_rows = [
        (
            "i-1",
            crypto.encrypt(
                bytearray(key_old),
                b"pattern payload",
                crypto.build_aad("insights", user_id, "patterns"),
            ),
        ),
    ]
    out, already = insights_api._rekey_blob_batch(
        bytearray(key_old),
        bytearray(key_new),
        insight_rows,
        lambda row_id: crypto.build_aad("insights", user_id, "patterns"),
    )
    assert len(out) == 1 and already == 0
    assert all(buf.is_zeroized() for buf in created)


def test_shared_vectors_carry_the_envelope_section():
    """shared/vectors.json: every pre-existing section untouched, the new
    envelope_vectors section present, positives round-trip through the real
    modules and negatives refuse to authenticate (LOW d)."""
    from pathlib import Path

    vectors = json.loads(
        (Path(__file__).resolve().parents[2] / "shared" / "vectors.json").read_text()
    )
    assert {"vectors", "encrypt_vectors", "wrap_vectors", "aad_edge_cases"} <= set(vectors)
    section = vectors["envelope_vectors"]
    kinds = [v["kind"] for v in section]
    assert kinds == [
        "entry-aad-v2",
        "entry-aad-v2-tampered",
        "key-envelope-wrap",
        "key-envelope-wrap-tampered",
    ]
    for item in section:
        if item["kind"] == "entry-aad-v2":
            plain = crypto.decrypt(
                base64.b64decode(item["data_key"]),
                base64.b64decode(item["blob"]),
                crypto.build_aad(*item["aad_parts"]),
            )
            assert plain == base64.b64decode(item["plaintext"])
        elif item["kind"] == "entry-aad-v2-tampered":
            with pytest.raises(crypto.TamperError):
                crypto.decrypt(
                    base64.b64decode(item["data_key"]),
                    base64.b64decode(item["blob"]),
                    crypto.build_aad(*item["aad_parts"]),
                )
        elif item["kind"] == "key-envelope-wrap":
            kek = envelope.envelope_kek(
                base64.b64decode(item["master_key"]), base64.b64decode(item["salt"])
            )
            assert kek == base64.b64decode(item["kek"])
            assert envelope.unwrap_data_key(
                base64.b64decode(item["wrapped"]),
                kek=kek,
                username=item["username"],
                kdf_params=item["kdf_params"],
            ) == base64.b64decode(item["data_key"])
        else:  # key-envelope-wrap-tampered
            kek = envelope.envelope_kek(
                base64.b64decode(item["master_key"]), base64.b64decode(item["salt"])
            )
            with pytest.raises(crypto.TamperError):
                envelope.unwrap_data_key(
                    base64.b64decode(item["wrapped"]),
                    kek=kek,
                    username=item["username"],
                    kdf_params=item["kdf_params"],
                )


# ===========================================================================
# Sharing still wraps the SAME data key for v2 accounts (unchanged flow)
# ===========================================================================


async def test_v2_sharing_wraps_the_same_random_key(client: AsyncClient):
    emu = EnvelopeClientEmulator("v2share", "pw-v2-share")
    await emu.register(client)
    th = TherapistEmulator("v2sharedr", "pw")
    await th.register(client)
    code = await th.create_pairing_code(client)
    grant = await emu.grant_consent(client, code, th.wrap_pub_key, th.user_id)
    assert grant["status"] == 201, grant["body"]
    # The stored wrap (ephemeral pub + wrapped key) is visible on the
    # therapist's patient list — the portal's own view of the grant.
    patients = await client.get("/api/therapist/patients", headers=th.headers)
    assert patients.status_code == 200, patients.text
    row = next(p for p in patients.json() if p["user_id"] == emu.user_id)
    assert row["status"] == "active"
    # End-to-end: the portal unwraps the account's RANDOM data key and
    # decrypts the patient's entry with it.
    await emu.create_entry(client, "shared under v2", TODAY, client_entry_id="v2-s1")
    patient_view = await emu.get_entry(client, "v2-s1")
    unwrapped = th.unwrap_patient_data_key(emu, row["ephemeral_pub"], row["wrapped_key"])
    assert unwrapped == emu.data_key
    plain = crypto.decrypt(
        unwrapped,
        base64.b64decode(patient_view["blob"]),
        crypto.entry_aad_v1(emu.user_id or "", "v2-s1"),
    )
    assert json.loads(plain)["text"] == "shared under v2"
    # And after a v2 password change the SAME consent wrap keeps working —
    # the data key never moved, so no re-wrap is needed.
    assert (await emu.change_password(client, "pw-v2-share-next")) == 204
    await emu.login(client)
    patients2 = await client.get("/api/therapist/patients", headers=th.headers)
    row2 = next(p for p in patients2.json() if p["user_id"] == emu.user_id)
    assert row2["wrapped_key"] == row["wrapped_key"]  # untouched
    assert (
        th.unwrap_patient_data_key(emu, row2["ephemeral_pub"], row2["wrapped_key"]) == emu.data_key
    )
