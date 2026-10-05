"""Independent behavioral oracles for the ten security mutation campaigns.

Expected authenticated bytes are built with hashlib/hmac/AESGCM rather than
the application's matching encrypt/decrypt helpers. Clock edges, owned buffer
references and live credential-withdrawal races exercise externally observable
contracts; a source digest is never a behavioral oracle here.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, update

from app.api import auth
from app.models import User
from app.security import crypto, enclave, envelope, kdf, step_up, tokens
from tests.helpers import ClientEmulator, EnvelopeClientEmulator, TherapistEmulator
from tests.test_recovery_envelope import _setup_kit, b64, recovery_verifier


def _hkdf(ikm: bytes, *, salt: bytes = b"", info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or b"\0" * 32, ikm, hashlib.sha256).digest()
    blocks, block, counter = b"", b"", 1
    while len(blocks) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        blocks += block
        counter += 1
    return blocks[:length]


def _signed_payload(payload: dict, secret: str) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
    signature = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), body, hashlib.sha256).digest()
    ).rstrip(b"=")
    return body.decode() + "." + signature.decode()


def test_decoy_salt_binds_exact_username_and_domain():
    secret = "independent-decoy-key"
    subkey = _hkdf(secret.encode(), info=b"mindpattern/decoy-salt/v1")
    values = []
    for username in ("Alice", "alice", " alice ", "Mañana"):
        expected = hmac.new(subkey, b"decoy:" + username.encode(), hashlib.sha256).digest()[:16]
        actual = auth.decoy_salt(username, secret)
        assert base64.b64decode(actual) == expected
        values.append(actual)
    assert len(set(values)) == len(values)


async def test_inactive_account_salt_is_decoy(client, app, settings):
    patient = ClientEmulator("deep-inactive-salt", "correct horse battery staple")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(User).where(User.id == patient.user_id).values(is_active=False)
        )
        await session.commit()
    response = await client.post("/api/auth/salt", json={"username": patient.username})
    assert response.status_code == 200
    expected = auth.decoy_salt(
        patient.username, settings.decoy_secret.strip() or settings.token_secret
    )
    assert response.json()["salt"] == expected
    assert response.json()["salt"] != base64.b64encode(patient.salt).decode()


async def test_registration_issue_failure_does_not_commit_account(client, app, monkeypatch):
    patient = ClientEmulator("deep-registration-failure", "correct horse battery staple")
    real_issue = auth._issue

    def fail_issue(*args):
        raise RuntimeError("controlled issuance failure")

    monkeypatch.setattr(auth, "_issue", fail_issue)
    failed = await client.post(
        "/api/auth/register",
        json={
            "username": patient.username,
            "salt": patient.salt_b64,
            "verifier": patient.auth_key_b64,
            "age_attestation": "minimum_age_confirmed_v1",
        },
    )
    assert failed.status_code == 500
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(select(User.id).where(User.username == patient.username)) is None
        )
    monkeypatch.setattr(auth, "_issue", real_issue)
    await patient.register(client)


@pytest.mark.parametrize("size", [31, 33])
async def test_registration_verifier_encoded_shape_does_not_replace_byte_bound(client, size):
    patient = ClientEmulator("deep-verifier-size", "correct horse battery staple")
    response = await client.post(
        "/api/auth/register",
        json={
            "username": patient.username,
            "salt": patient.salt_b64,
            "verifier": base64.b64encode(bytes(range(size))).decode(),
            "age_attestation": "minimum_age_confirmed_v1",
        },
    )
    assert response.status_code == 422
    assert response.json()["code"] == "validation_error"


def test_token_expiry_at_exact_boundary_and_nonfinite_claims():
    secret = "independent-token-key"
    token = tokens.issue_token("patient", secret, ttl_seconds=10, now=100)
    assert tokens.verify_token(token, secret, now=109.999)["uid"] == "patient"
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(token, secret, now=110)
    for value in (True, None, "tomorrow", float("nan"), float("inf"), 10**400):
        forged = _signed_payload({"uid": "patient", "exp": value}, secret)
        with pytest.raises(tokens.TokenError):
            tokens.verify_token(forged, secret, now=100)


@pytest.mark.parametrize(
    "claim,value",
    [
        ("ep", True),
        ("ksv", True),
        ("jti", "f" * 31),
        ("purpose", []),
        ("purpose", {}),
        ("purpose", ["patient"]),
    ],
)
def test_signed_token_bad_claims_fail_as_token_errors(claim, value):
    payload = {"uid": "patient", "exp": 200, claim: value}
    with pytest.raises(tokens.TokenError):
        tokens.verify_token(_signed_payload(payload, "shape-key"), "shape-key", now=100)


async def test_token_purpose_matches_live_account_role(client, settings):
    patient = ClientEmulator("deep-purpose-wall", "correct horse battery staple")
    await patient.register(client)
    payload = tokens.verify_token(patient.token, settings.auth_token_secret)
    payload["purpose"] = "therapist"
    wrong = _signed_payload(payload, settings.auth_token_secret)
    response = await client.get("/api/entries", headers={"Authorization": "Bearer " + wrong})
    assert response.status_code == 401


async def test_totp_backup_code_is_one_use_sequentially_and_concurrently(client):
    therapist = TherapistEmulator("deep-backup-custody", "correct horse battery staple")
    await therapist.register(client)
    body = {
        "username": therapist.username,
        "verifier": therapist.auth_key_b64,
        "totp_code": therapist.totp_backup_codes[0],
    }
    accepted = await client.post("/api/auth/login", json=body)
    assert accepted.status_code == 200, accepted.text
    replay = await client.post("/api/auth/login", json=body)
    assert replay.status_code == 401 and replay.json()["code"] == "totp_code_invalid"
    concurrent = {**body, "totp_code": therapist.totp_backup_codes[1]}
    results = await asyncio.gather(
        client.post("/api/auth/login", json=concurrent),
        client.post("/api/auth/login", json=concurrent),
    )
    assert sorted(response.status_code for response in results) == [200, 401]


@pytest.mark.parametrize("changed", ["user_id", "action", "token_jti", "token_epoch"])
async def test_step_up_binds_every_authority_and_burns_wrong_attempt(changed):
    store = step_up.StepUpProofStore()
    binding = {
        "user_id": "patient",
        "action": "account_delete",
        "token_jti": "jti-a",
        "token_epoch": 4,
    }
    proof, _ = await store.issue(**binding)
    wrong = {**binding, changed: 5 if changed == "token_epoch" else "wrong"}
    assert await store.consume(proof, **wrong) is False
    assert await store.consume(proof, **binding) is False
    fresh, _ = await store.issue(**binding)
    assert await store.consume(fresh, **binding) is True
    assert await store.consume(fresh, **binding) is False


async def test_step_up_exact_monotonic_expiry_and_bounded_eviction(monkeypatch):
    clock = SimpleNamespace(value=100.0)
    monkeypatch.setattr(step_up.time, "monotonic", lambda: clock.value)
    monkeypatch.setattr(step_up, "STEP_UP_MAX_PER_USER", 2)
    monkeypatch.setattr(step_up, "STEP_UP_MAX_PROOFS", 3)
    store = step_up.StepUpProofStore()
    binding = {
        "user_id": "patient",
        "action": "account_delete",
        "token_jti": None,
        "token_epoch": 1,
    }
    first, _ = await store.issue(**binding)
    second, _ = await store.issue(**binding)
    third, _ = await store.issue(**binding)
    assert await store.consume(first, **binding) is False
    assert await store.consume(second, **binding) is True
    clock.value += 120
    assert await store.consume(third, **binding) is False
    assert await store.consume("\u0661invalid", **binding) is False


def test_kdf_cost_shapes_and_write_read_floor_separation():
    historical = {"algorithm": "pbkdf2-sha256", "version": 1, "iterations": 100_000}
    assert kdf.validate_kdf_params(historical)["iterations"] == 100_000
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(historical, min_pbkdf2_iterations=600_000)
    for field in ("iterations", "version"):
        with pytest.raises(kdf.KdfParamsError):
            kdf.validate_kdf_params({**historical, field: True})
    valid = {
        "algorithm": "argon2id",
        "version": 1,
        "iterations": 2,
        "memory_kib": 19 * 1024,
        "parallelism": 1,
    }
    assert kdf.validate_kdf_params(valid)["iterations"] == 2
    for field, value in (
        ("memory_kib", 19 * 1024 - 1),
        ("memory_kib", 256 * 1024 + 1),
        ("iterations", 1),
        ("iterations", 10_000_001),
        ("parallelism", 0),
        ("parallelism", 5),
        ("parallelism", True),
    ):
        with pytest.raises(kdf.KdfParamsError):
            kdf.validate_kdf_params({**valid, field: value})
    assert kdf.parse_kdf_params_json(" " * 257) is None
    assert (
        kdf.parse_kdf_params_json(
            '{"algorithm":"pbkdf2-sha256","version":true,"iterations":600000}'
        )
        is None
    )


def test_kdf_key_labels_and_storage_canonicalization_are_independent():
    master = bytes(range(32))
    assert kdf.derive_auth_key(master) == _hkdf(master, info=b"mindpattern/auth/v1")
    assert kdf.derive_data_key(master) == _hkdf(master, info=b"mindpattern/data/v1")
    params = kdf.validate_kdf_params(
        {"version": 1, "iterations": 600_000, "algorithm": "pbkdf2-sha256"}
    )
    assert (
        kdf.canonical_kdf_params_json(params)
        == '{"algorithm":"pbkdf2-sha256","iterations":600000,"version":1}'
    )
    assert kdf.parse_kdf_params_json(kdf.canonical_kdf_params_json(params)) == params


def test_aes_envelope_aad_and_version_match_independent_aead():
    key, nonce = bytes(range(32)), bytes(range(12))
    expected_aad = b'["entry","user-\\u00f1","entry-7","2"]'
    assert crypto.entry_aad_v2("user-ñ", "entry-7", 2) == expected_aad
    external = nonce + AESGCM(key).encrypt(nonce, b"independent payload", expected_aad)
    assert crypto.decrypt(key, external, expected_aad) == b"independent payload"
    with pytest.raises(crypto.TamperError):
        crypto.decrypt(key, external, b'["entry","other-user","entry-7","2"]')
    encrypted = crypto.encrypt_with_nonce(key, b"independent payload", expected_aad, nonce)
    assert (
        AESGCM(key).decrypt(encrypted[:12], encrypted[12:], expected_aad) == b"independent payload"
    )
    short_key = bytes(range(16))
    valid_aes128 = nonce + AESGCM(short_key).encrypt(nonce, b"must still be rejected", expected_aad)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt(short_key, valid_aes128, expected_aad)


def test_key_envelope_independent_aad_and_kek():
    params = kdf.validate_kdf_params(
        {"algorithm": "pbkdf2-sha256", "version": 1, "iterations": 600_000}
    )
    master, salt = bytes(range(32)), bytes(range(16))
    expected_kek = _hkdf(master, salt=salt, info=b"mindpattern/envelope/v2")
    expected_aad = b'{"context":"envelope","kdf_params":{"algorithm":"pbkdf2-sha256","version":1,"iterations":600000},"username":"M\\u00f1"}'
    assert envelope.envelope_kek(master, salt) == expected_kek
    assert envelope.envelope_aad("Mñ", params) == expected_aad
    data_key, nonce = bytes(range(32, 64)), bytes(range(12))
    external = nonce + AESGCM(expected_kek).encrypt(nonce, data_key, expected_aad)
    assert (
        envelope.unwrap_data_key(external, kek=expected_kek, username="Mñ", kdf_params=params)
        == data_key
    )


async def test_recovery_withdrawal_while_proof_hashes_retires_the_proof(client, app, monkeypatch):
    patient = ClientEmulator("deep-recovery-race", "correct horse battery staple")
    await patient.register(client)
    recovery_key = bytes(range(32))
    await _setup_kit(client, patient, recovery_key)
    proof = recovery_verifier(recovery_key)
    hashing, resume = asyncio.Event(), asyncio.Event()
    real_hash = auth.hash_verifier_off_loop

    async def pause_recovery(value, salt, **kwargs):
        result = await real_hash(value, salt, **kwargs)
        if value == proof:
            hashing.set()
            await resume.wait()
        return result

    monkeypatch.setattr(auth, "hash_verifier_off_loop", pause_recovery)
    attempt = asyncio.create_task(
        client.post(
            "/api/auth/recover",
            json={
                "username": patient.username,
                "verifier": b64(proof),
                "scheme": "v2",
            },
        )
    )
    try:
        await asyncio.wait_for(hashing.wait(), timeout=10)
        withdrawn = await client.delete(
            "/api/account/recovery", headers={**patient.headers, "verifier": patient.auth_key_b64}
        )
        assert withdrawn.status_code == 204, withdrawn.text
    finally:
        resume.set()
    response = await asyncio.wait_for(attempt, timeout=10)
    assert response.status_code == 401, response.text
    unchanged = await client.get("/api/account/recovery", headers=patient.headers)
    assert unchanged.status_code == 200 and unchanged.json()["enabled"] is False


async def test_recovery_correct_verifier_with_wrong_scheme_still_fails(client):
    patient = ClientEmulator("deep-recovery-scheme", "correct horse battery staple")
    await patient.register(client)
    key = bytes(range(32))
    await _setup_kit(client, patient, key)
    body = {"username": patient.username, "verifier": b64(recovery_verifier(key)), "scheme": "v1"}
    rejected = await client.post("/api/auth/recover", json=body)
    assert rejected.status_code == 401
    assert rejected.json()["code"] == "invalid_credentials"
    accepted = await client.post("/api/auth/recover", json={**body, "scheme": "v2"})
    assert accepted.status_code == 200, accepted.text


async def test_password_change_zeroizes_other_resident_processing_keys(client, app):
    patient = EnvelopeClientEmulator("deep-password-purge", "correct horse battery staple")
    await patient.register(client)
    first = await patient.open_processing_session(client)
    second = await patient.open_processing_session(client)
    first_key = app.state.key_store._keys[first][0]
    second_key = app.state.key_store._keys[second][0]
    assert (await patient.change_password(client, "another correct password")) == 204
    assert first_key == bytearray(32) and second_key == bytearray(32)
    for token in (first, second):
        with pytest.raises(enclave.KeyNotFound):
            app.state.key_store.pop(token, owner=patient.user_id)


def test_keystore_required_owner_global_capacity_and_single_use():
    store = enclave.InMemoryKeyStore(max_sessions=2, max_sessions_per_owner=1)
    key = bytes(range(32))
    for owner in (None, "", 5):
        with pytest.raises(ValueError):
            store.create(key, 60, now=100, owner=owner)
    first = store.create(key, 60, now=100, owner="a")
    with pytest.raises(enclave.KeyStoreFull):
        store.create(key, 60, now=100, owner="a")
    second = store.create(key, 60, now=100, owner="b")
    with pytest.raises(enclave.KeyStoreFull):
        store.create(key, 60, now=100, owner="c")
    owned = store.pop(first, now=101, owner="a")
    assert isinstance(owned, bytearray) and owned == key
    with pytest.raises(enclave.KeyNotFound):
        store.pop(first, now=101, owner="a")
    enclave.zeroize(owned)
    store.destroy(second, owner="b")


def test_keystore_exact_expiry_zeroizes_owned_buffer():
    store = enclave.InMemoryKeyStore()
    token = store.create(bytes(range(32)), 10, now=100, owner="patient")
    held = store._keys[token][0]
    with pytest.raises(enclave.KeyNotFound):
        store.pop(token, now=110, owner="patient")
    assert held == bytearray(32)
    with pytest.raises(enclave.KeyNotFound):
        store.pop(token, now=100, owner="patient")


@pytest.mark.parametrize("fail", [False, True])
def test_processing_scrubs_all_owned_key_and_plaintext_references(monkeypatch, fail):
    key = bytes(range(32))
    aad = b"context"
    ciphertext = crypto.encrypt(key, b"private journal", aad)
    context = enclave.SecureProcessingContext(key)
    keys, plains = [], []
    real_decrypt = enclave.decrypt

    def observe_decrypt(k, blob, binding):
        keys.append(k)
        return real_decrypt(k, blob, binding)

    monkeypatch.setattr(enclave, "decrypt", observe_decrypt)

    def analyze(buffers):
        plains.extend(buffers)
        assert enclave.plaintext_windows() == 1
        if fail:
            raise RuntimeError("controlled analysis failure")
        return "done"

    if fail:
        with pytest.raises(RuntimeError, match="controlled analysis failure"):
            context.run([(aad, ciphertext), (aad, ciphertext)], analyze)
    else:
        assert context.run([(aad, ciphertext), (aad, ciphertext)], analyze) == "done"
    assert enclave.plaintext_windows() == 0
    assert context._key == bytearray(32)
    assert keys and all(k is keys[0] for k in keys)
    assert isinstance(keys[0], bytearray) and keys[0] == bytearray(32)
    assert plains and all(p == bytearray(len(p)) for p in plains)


def test_processing_partial_decrypt_failure_scrubs_earlier_plaintext(monkeypatch):
    captured = []
    original = crypto.SecureBuffer

    class ObserveBuffer(original):
        def __init__(self, data):
            super().__init__(data)
            captured.append(self.data)

    monkeypatch.setattr(enclave, "SecureBuffer", ObserveBuffer)
    key, aad = bytes(range(32)), b"context"
    valid = crypto.encrypt(key, b"prior decrypted text", aad)
    context = enclave.SecureProcessingContext(key)
    with pytest.raises(crypto.TamperError):
        context.run(
            [(aad, valid), (aad, valid[:-1])], lambda buffers: pytest.fail("analysis must not run")
        )
    assert captured and captured[0] == bytearray(len(captured[0]))
    assert context._key == bytearray(32)
    assert enclave.plaintext_windows() == 0
