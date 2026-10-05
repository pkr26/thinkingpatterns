"""Actual ciphertext, owned-memory and processing-session lifetime contracts."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import math
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
KEY = bytes(range(32))


def _modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    return (
        importlib.import_module("app.security.crypto"),
        importlib.import_module("app.security.enclave"),
    )


def test_zeroization_updates_borrowed_memory_and_preserves_buffer_length(monkeypatch):
    crypto, enclave = _modules(monkeypatch)
    owned = bytearray(b"sensitive-key-material")
    borrowed = memoryview(owned)
    enclave.zeroize(owned)
    assert borrowed.tobytes() == b"\0" * 22
    secure = crypto.SecureBuffer(b"private plaintext")
    assert len(secure) == 17 and secure.is_zeroized() is False
    view = memoryview(secure.data)
    secure.zeroize()
    assert len(secure) == 17 and secure.is_zeroized() is True
    assert view.tobytes() == b"\0" * 17


def test_crypto_envelope_interoperability_and_unambiguous_aad(monkeypatch):
    crypto, _ = _modules(monkeypatch)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = bytes(range(12))
    aad = b'["entry","patient","item","7"]'
    plain = b"private journal"
    expected = nonce + AESGCM(KEY).encrypt(nonce, plain, aad)
    assert crypto.encrypt_with_nonce(KEY, plain, aad, nonce) == expected
    assert crypto.decrypt(bytearray(KEY), expected, aad) == plain
    assert crypto.build_aad("a,b", "c", "雪") == rb'["a,b","c","\u96ea"]'
    assert crypto.entry_aad_v1("patient", "item") == b'["entry","patient","item"]'
    assert crypto.entry_aad_v2("patient", "item", 7) == aad
    assert crypto.entry_aad_candidates("patient", "item", 7) == (
        aad,
        b'["entry","patient","item"]',
    )
    for changed in (b'["entry","other","item","7"]', b'["entry","patient","item","8"]'):
        with pytest.raises(crypto.TamperError, match="^authentication failed$"):
            crypto.decrypt(KEY, expected, changed)
    altered = expected[:-1] + bytes([expected[-1] ^ 1])
    with pytest.raises(crypto.TamperError, match="^authentication failed$"):
        crypto.decrypt(KEY, altered, aad)


def test_crypto_entropy_calls_and_invalid_lengths(monkeypatch):
    crypto, _ = _modules(monkeypatch)
    calls = []

    def entropy(size):
        calls.append(size)
        return bytes([len(calls)]) * size

    monkeypatch.setattr(crypto.os, "urandom", entropy)
    assert crypto.generate_key() == b"\1" * 32
    first = crypto.encrypt(KEY, b"p", None)
    second = crypto.encrypt(KEY, b"p", None)
    assert calls == [32, 12, 12]
    assert first[:12] == b"\2" * 12 and second[:12] == b"\3" * 12
    assert first != second and len(first) == len(second) == 29
    for length in (0, 16, 31, 33):
        key = bytes(length)
        for operation in (
            lambda key=key: crypto.encrypt_with_nonce(key, b"p", None, bytes(12)),
            lambda key=key: crypto.decrypt(key, bytes(28), None),
        ):
            with pytest.raises(
                crypto.CryptoError, match=f"^key must be 32 bytes, got {length}$"
            ):
                operation()
    for length in (0, 11, 13):
        with pytest.raises(
            crypto.CryptoError, match=f"^nonce must be 12 bytes, got {length}$"
        ):
            crypto.encrypt_with_nonce(KEY, b"p", None, bytes(length))
    for length in (0, 27):
        with pytest.raises(
            crypto.TamperError, match=f"^blob too short: {length} bytes$"
        ):
            crypto.decrypt(KEY, bytes(length))
    empty = crypto.encrypt_with_nonce(KEY, b"", None, bytes(12))
    assert len(empty) == 28 and crypto.decrypt(KEY, empty) == b""


def test_session_defaults_admit_four_per_owner_and_1024_total(monkeypatch):
    _, enclave = _modules(monkeypatch)
    store = enclave.InMemoryKeyStore()
    assert len(store) == 0
    for owner in range(256):
        for _ in range(4):
            store.create(KEY, 1, now=0, owner=f"patient-{owner}")
        if owner < 255:
            with pytest.raises(
                enclave.KeyStoreFull,
                match="^processing session capacity reached for account$",
            ):
                store.create(KEY, 1, now=0, owner=f"patient-{owner}")
    assert len(store) == 1024
    with pytest.raises(
        enclave.KeyStoreFull, match="^processing session capacity reached$"
    ):
        store.create(KEY, 1, now=0, owner="next-patient")
    assert store.purge_expired(now=1) == 1024 and len(store) == 0


def test_session_validation_and_token_entropy(monkeypatch):
    _, enclave = _modules(monkeypatch)
    for total, per_owner in ((0, 1), (1, 0), (-1, 1)):
        with pytest.raises(
            ValueError, match="^processing-session limits must be positive$"
        ):
            enclave.InMemoryKeyStore(
                max_sessions=total, max_sessions_per_owner=per_owner
            )
    store = enclave.InMemoryKeyStore(max_sessions=1, max_sessions_per_owner=1)
    for owner in ("", None, 42):
        with pytest.raises(
            ValueError, match="^owner is required .*explicit test sentinel.*$"
        ):
            store.create(KEY, 1, now=0, owner=owner)
    for key in (b"", bytes(31), bytes(33)):
        with pytest.raises(ValueError, match="^key must be 32 bytes$"):
            store.create(key, 1, now=0, owner="patient")
    for ttl in (0, -1):
        with pytest.raises(ValueError, match="^ttl must be positive$"):
            store.create(KEY, ttl, now=0, owner="patient")
    first = store.create(KEY, 1, now=0, owner="patient")
    owned = store.pop(first, now=0, owner="patient")
    assert bytes(owned) == KEY
    enclave.zeroize(owned)
    with pytest.raises(enclave.KeyNotFound):
        store.get(first, now=0, owner="patient")
    second = store.create(KEY, 1, now=0, owner="patient")
    assert first != second, "new sessions need fresh unpredictable bearer capabilities"
    for token in (first, second):
        # The capability is opaque. Its private entropy width may increase;
        # it must remain URL-safe and carry at least 256 random bits.
        assert token and set(token) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
        assert len(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))) >= 32
        assert KEY.hex() not in token and base64.b64encode(KEY).decode() not in token
    assert bytes(store.get(second, now=0, owner="patient")) == KEY
    assert store.purge_expired(now=1) == 1 and len(store) == 0


def test_session_owner_checks_do_not_consume_and_pop_transfers_owned_key(monkeypatch):
    _, enclave = _modules(monkeypatch)
    store = enclave.InMemoryKeyStore()
    token = store.create(KEY, 10, now=0, owner="patient")
    for operation in (store.get, store.pop):
        with pytest.raises(
            enclave.KeyNotFound, match="^processing session belongs to another user$"
        ):
            operation(token, now=1, owner="intruder")
        assert len(store) == 1
    assert store.destroy(token, owner="intruder") is False and len(store) == 1
    copy = store.get(token, now=1, owner="patient")
    assert type(copy) is bytearray and copy == KEY
    copy[0] = 255
    assert store.get(token, now=1, owner="patient") == KEY
    owned = store.pop(token, now=1, owner="patient")
    assert type(owned) is bytearray and owned == KEY and len(store) == 0
    with pytest.raises(enclave.KeyNotFound, match="^unknown processing session$"):
        store.pop(token, now=1, owner="patient")
    assert store.destroy(token) is False


@pytest.mark.parametrize("operation", ["get", "pop"])
def test_session_expiry_is_inclusive_and_uses_monotonic_time(monkeypatch, operation):
    _, enclave = _modules(monkeypatch)
    clock = [100.0]
    monkeypatch.setattr(enclave.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(enclave.time, "time", lambda: -1_000_000)
    store = enclave.InMemoryKeyStore()
    token = store.create(KEY, 10, owner="patient")
    clock[0] = 109.999
    assert store.get(token, owner="patient") == KEY
    # Inspect the owned memory through a borrowed reference, rather than a
    # get() clone; an expiry must scrub the memory it actually retained.
    resident = store._keys[token][0]
    clock[0] = 110.0
    with pytest.raises(enclave.KeyNotFound, match="^processing session expired$"):
        getattr(store, operation)(token, owner="patient")
    assert resident == bytes(32) and len(store) == 0


def test_session_purge_destroy_and_admission_zeroize_exact_owned_buffers(monkeypatch):
    _, enclave = _modules(monkeypatch)
    store = enclave.InMemoryKeyStore(max_sessions=3, max_sessions_per_owner=2)
    a = store.create(KEY, 1, now=0, owner="a")
    b = store.create(KEY, 10, now=0, owner="b")
    old_a = store._keys[a][0]
    old_b = store._keys[b][0]
    assert store.purge_expired(now=0.999) == 0
    assert store.purge_expired(now=1) == 1
    assert old_a == bytes(32) and old_b == KEY
    a = store.create(KEY, 10, now=1, owner="a")
    a2 = store.create(KEY, 10, now=1, owner="a")
    resident = [store._keys[t][0] for t in (a, a2)]
    assert store.destroy_all_for_owner("missing") == 0
    assert store.destroy_all_for_owner("a") == 2
    assert all(item == bytes(32) for item in resident)
    assert len(store) == 1 and store.get(b, now=1, owner="b") == KEY
    assert store.destroy_all() == 1 and old_b == bytes(32) and len(store) == 0
    assert store.destroy_all() == 0
    token = store.create(KEY, 1, now=0, owner="a")
    expired = store._keys[token][0]
    store.create(KEY, 1, now=1, owner="a")
    assert expired == bytes(32) and len(store) == 1
    remaining = next(iter(store._keys.values()))[0]
    token = next(iter(store._keys))
    assert store.destroy(token, owner="a") is True
    assert remaining == bytes(32) and len(store) == 0


@pytest.mark.parametrize("failure", [None, "analyzer", "ciphertext"])
def test_enclave_aad_fallback_and_all_exit_paths_scrub_keys_and_plaintext(
    monkeypatch, failure
):
    crypto, enclave = _modules(monkeypatch)
    first = (b"wrong", b"legacy")
    encrypted = [
        (first, crypto.encrypt(KEY, b"first private entry", b"legacy")),
        (None, crypto.encrypt(KEY, b"second private entry", None)),
    ]
    if failure == "ciphertext":
        blob = encrypted[1][1]
        encrypted[1] = (None, blob[:-1] + bytes([blob[-1] ^ 1]))
    context = enclave.SecureProcessingContext(KEY)
    borrowed_key = context._key
    working_keys = []
    borrowed_plain = []
    actual_decrypt = enclave.decrypt

    def decrypt(key, blob, aad):
        working_keys.append(key)
        assert type(key) is bytearray
        assert enclave.plaintext_windows() == 1
        return actual_decrypt(key, blob, aad)

    monkeypatch.setattr(enclave, "decrypt", decrypt)
    actual_buffer = enclave.SecureBuffer

    class ObservedBuffer(actual_buffer):
        def __init__(self, data):
            super().__init__(data)
            borrowed_plain.append(self.data)

    monkeypatch.setattr(enclave, "SecureBuffer", ObservedBuffer)

    def analyze(plains):
        assert enclave.plaintext_windows() == 1
        assert plains == [b"first private entry", b"second private entry"]
        assert all(type(item) is bytearray for item in plains)
        if failure == "analyzer":
            raise LookupError("analyzer refused")
        return {"processed": len(plains)}

    if failure == "ciphertext":
        with pytest.raises(crypto.TamperError):
            context.run(encrypted, analyze)
    elif failure == "analyzer":
        with pytest.raises(LookupError, match="^analyzer refused$"):
            context.run(encrypted, analyze)
    else:
        assert context.run(encrypted, analyze) == {"processed": 2}
    assert len(working_keys) == 3
    assert all(key is working_keys[0] for key in working_keys)
    assert working_keys[0] == bytes(32) and borrowed_key == bytes(32)
    assert borrowed_plain and all(not any(item) for item in borrowed_plain)
    assert enclave.plaintext_windows() == 0
    assert context.authenticated_aads == (
        [b"legacy"] if failure == "ciphertext" else [b"legacy", None]
    )


def test_enclave_singleton_aad_candidates_and_isolated_result(monkeypatch):
    crypto, enclave = _modules(monkeypatch)
    blob = crypto.encrypt(KEY, b"private", b"aad")
    observed = []
    assert (
        enclave._decrypt_with_candidates(bytearray(KEY), blob, (b"aad",), observed)
        == b"private"
    )
    assert observed == [b"aad"]
    observed = []
    assert (
        enclave._decrypt_with_candidates(
            bytearray(KEY), blob, bytearray(b"aad"), observed
        )
        == b"private"
    )
    assert observed == [bytearray(b"aad")]
    with pytest.raises(crypto.TamperError, match="^authentication failed$"):
        enclave._decrypt_with_candidates(bytearray(KEY), blob, (b"wrong", b"other"), [])
    assert (
        enclave.run_isolated(KEY, [(b"aad", blob)], lambda items: bytes(items[0]))
        == b"private"
    )
    assert enclave.plaintext_windows() == 0
    with pytest.raises(ValueError, match="^key must be 32 bytes$"):
        enclave.SecureProcessingContext(bytes(31))


def test_nested_enclaves_count_each_live_plaintext_window(monkeypatch):
    crypto, enclave = _modules(monkeypatch)
    blob = crypto.encrypt(KEY, b"private", None)
    outer = enclave.SecureProcessingContext(KEY)

    def outer_analysis(_):
        assert enclave.plaintext_windows() == 1
        inner = enclave.SecureProcessingContext(KEY)

        def inner_analysis(_):
            assert enclave.plaintext_windows() == 2
            return "inner finished"

        assert inner.run([(None, blob)], inner_analysis) == "inner finished"
        assert enclave.plaintext_windows() == 1
        return "outer finished"

    assert outer.run([(None, blob)], outer_analysis) == "outer finished"
    assert enclave.plaintext_windows() == 0


def _token_modules(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    return importlib.import_module("app.security.tokens")


def _signed_payload(payload, secret="signing-secret"):
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).rstrip(b"=")
    mac = base64.urlsafe_b64encode(
        hmac.digest(secret.encode(), encoded, "sha256")
    ).rstrip(b"=")
    return encoded.decode() + "." + mac.decode()


def test_token_wire_claims_signature_and_precise_expiry(monkeypatch):
    tokens = _token_modules(monkeypatch)
    payload = {
        "uid": "patient雪",
        "iat": 0,
        "exp": 1,
        "ep": 7,
        "jti": "0123456789abcdef" * 2,
        "purpose": "therapist",
        "ksv": 2,
    }
    expected = _signed_payload(payload)
    actual = tokens.issue_token(
        "patient雪",
        "signing-secret",
        1,
        now=0,
        epoch=7,
        purpose="therapist",
        ksv=2,
        jti=payload["jti"],
    )
    assert actual == expected
    assert tokens.verify_token(actual, "signing-secret", now=0) == payload
    assert tokens.verify_token(actual, "signing-secret", now=0.999) == payload
    with pytest.raises(tokens.TokenError, match="^token expired$"):
        tokens.verify_token(actual, "signing-secret", now=1)
    calls = []
    monkeypatch.setattr(
        tokens.secrets, "token_hex", lambda count: calls.append(count) or "a" * 32
    )
    monkeypatch.setattr(tokens.time, "time", lambda: 100.9)
    defaults = tokens.verify_token(tokens.issue_token("p", "s", 2), "s", now=100)
    assert defaults == {
        "uid": "p",
        "iat": 100,
        "exp": 102,
        "ep": 1,
        "jti": "a" * 32,
        "purpose": "patient",
        "ksv": 1,
    }
    assert calls == [16]
    for ttl in (0, -1):
        with pytest.raises(ValueError, match="^ttl_seconds must be positive$"):
            tokens.issue_token("p", "s", ttl)
    with pytest.raises(
        ValueError, match="^purpose must be one of \\['patient', 'therapist'\\]$"
    ):
        tokens.issue_token("p", "s", 1, purpose="refresh")


def test_tokens_signed_hostile_claims_refuse_every_shape_without_native_errors(
    monkeypatch,
):
    tokens = _token_modules(monkeypatch)
    pristine = {
        "uid": "patient",
        "exp": 500,
        "ep": 1,
        "ksv": 1,
        "jti": "a" * 32,
        "purpose": "patient",
    }
    fields = {
        "uid": ["", None, True, 7, [], {}],
        "exp": [
            None,
            "500",
            True,
            [],
            math.nan,
            math.inf,
            -math.inf,
            10**400,
            -(10**400),
            32_503_680_001,
        ],
        "ep": [True, False, "1", 1.1, [], {}],
        "jti": [None, True, 32, "a" * 31, "a" * 33, "A" * 32, "X" * 32, "g" * 32],
        "purpose": [None, True, 1, [], "refresh", "Patient"],
        "ksv": [None, True, False, 0, -1, "1", 1.1, []],
    }
    for field, invalids in fields.items():
        for invalid in invalids:
            with pytest.raises(tokens.TokenError, match="^malformed payload$"):
                tokens.verify_token(
                    _signed_payload({**pristine, field: invalid}),
                    "signing-secret",
                    now=0,
                )
    for invalid in (None, [], 1, {}, {"exp": 500}, {"uid": "p"}):
        with pytest.raises(tokens.TokenError, match="^malformed payload$"):
            tokens.verify_token(_signed_payload(invalid), "signing-secret", now=0)
    for payload in (
        {"uid": "p", "exp": 1},
        {"uid": "p", "exp": 1, "ep": None},
        {**pristine, "exp": 32_503_680_000},
        {**pristine, "exp": 1.5},
        {**pristine, "ksv": 2},
        {**pristine, "ep": -1},
    ):
        assert (
            tokens.verify_token(_signed_payload(payload), "signing-secret", now=0)
            == payload
        )


def test_token_encoded_transport_validation_and_constant_time_mac_comparison(
    monkeypatch,
):
    tokens = _token_modules(monkeypatch)
    for blob in [bytes(range(length)) for length in range(257)] + [b"\0\0\x17"]:
        encoded = base64.urlsafe_b64encode(blob).rstrip(b"=").decode()
        assert tokens._b64url_encode(blob) == encoded
        assert tokens._b64url_decode(encoded) == blob
    for malformed in (None, 1, [], "", "onepart", "雪.signature", "body.雪"):
        with pytest.raises(tokens.TokenError, match="^malformed token$"):
            tokens.verify_token(malformed, "s", now=0)
    with pytest.raises(tokens.TokenError, match="^bad signature$"):
        tokens.verify_token("body.extra.signature", "s", now=0)
    original = tokens.hmac.compare_digest
    compared = []

    def compare(first, second):
        assert type(first) is bytes and type(second) is bytes
        compared.append((first, second))
        return original(first, second)

    monkeypatch.setattr(tokens.hmac, "compare_digest", compare)
    good = _signed_payload({"uid": "p", "exp": 100})
    assert tokens.verify_token(good, "signing-secret", now=0) == {
        "uid": "p",
        "exp": 100,
    }
    with pytest.raises(tokens.TokenError, match="^bad signature$"):
        tokens.verify_token(good, "wrong-secret", now=0)
    assert len(compared) == 2
    for raw in (b"not-json", b"{", b"\xff", b""):
        body = base64.urlsafe_b64encode(raw).rstrip(b"=")
        signature = base64.urlsafe_b64encode(hmac.digest(b"s", body, "sha256")).rstrip(
            b"="
        )
        with pytest.raises(tokens.TokenError, match="^malformed payload$"):
            tokens.verify_token(body.decode() + "." + signature.decode(), "s", now=0)


def test_hkdf_matches_independent_rfc5869_implementation_and_cost_contract(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    kdf = importlib.import_module("app.security.kdf")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    for salt in (None, b"", b"nonempty salt"):
        for length in (1, 31, 32, 33, 65, 8159, 8160):
            expected = HKDF(
                algorithm=hashes.SHA256(), length=length, salt=salt, info=b"purpose"
            ).derive(KEY)
            assert kdf.hkdf_sha256(KEY, salt, b"purpose", length) == expected
    for length in (0, -1, 8161):
        with pytest.raises(ValueError, match="^invalid HKDF output length$"):
            kdf.hkdf_sha256(KEY, None, b"purpose", length)
    for operation, info in (
        (kdf.derive_auth_key, b"mindpattern/auth/v1"),
        (kdf.derive_data_key, b"mindpattern/data/v1"),
    ):
        expected = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=None, info=info
        ).derive(KEY)
        assert operation(KEY) == expected
    calls = []
    monkeypatch.setattr(
        kdf.hashlib, "pbkdf2_hmac", lambda *args: calls.append(args) or b"key"
    )
    assert kdf.derive_master_key("雪", b"salt1234") == b"key"
    assert kdf.derive_master_key(b"password", b"salt1234", 100_000) == b"key"
    assert calls == [
        ("sha256", "雪".encode(), b"salt1234", 600_000),
        ("sha256", b"password", b"salt1234", 100_000),
    ]
    with pytest.raises(ValueError, match="^salt must be at least 8 bytes$"):
        kdf.derive_master_key("p", bytes(7))
    with pytest.raises(
        ValueError,
        match=r"^iterations must be at least 100000 \(got 99999; the cross-platform contract is 600000\)$",
    ):
        kdf.derive_master_key("p", bytes(8), 99_999)


def test_kdf_params_native_cost_bounds_canonical_storage_and_legacy_read_floor(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    kdf = importlib.import_module("app.security.kdf")
    pb = {"algorithm": "pbkdf2-sha256", "version": 1, "iterations": 600_000}
    argon = {
        "algorithm": "argon2id",
        "version": 1,
        "iterations": 2,
        "memory_kib": 19_456,
        "parallelism": 1,
    }
    assert kdf.KDF_PARAMS_DEFAULT == pb
    for params in (pb, argon):
        canonical = kdf.validate_kdf_params(params)
        expected = json.dumps(
            params, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        assert (
            canonical == params and kdf.canonical_kdf_params_json(canonical) == expected
        )
        assert kdf.parse_kdf_params_json(expected) == params
        for key in params:
            for bad in (None, True, [], {}, 1.1):
                with pytest.raises(kdf.KdfParamsError):
                    kdf.validate_kdf_params({**params, key: bad})
        with pytest.raises(
            kdf.KdfParamsError, match="^kdf_params has unknown fields: \\['extra'\\]$"
        ):
            kdf.validate_kdf_params({**params, "extra": 1})
    limits = [
        (pb, "iterations", 100_000, 10_000_000),
        (argon, "iterations", 2, 10_000_000),
        (argon, "memory_kib", 19_456, 262_144),
        (argon, "parallelism", 1, 4),
    ]
    for params, field, lower, upper in limits:
        for boundary in (lower, upper):
            assert (
                kdf.validate_kdf_params({**params, field: boundary})[field] == boundary
            )
        for rejected in (lower - 1, upper + 1):
            with pytest.raises(kdf.KdfParamsError):
                kdf.validate_kdf_params({**params, field: rejected})
    historical = {**pb, "iterations": 100_000}
    assert kdf.parse_kdf_params_json(json.dumps(historical)) == historical
    with pytest.raises(kdf.KdfParamsError):
        kdf.validate_kdf_params(historical, min_pbkdf2_iterations=600_000)
    stored = json.dumps(pb)
    boundary = stored + " " * (256 - len(stored))
    assert kdf.parse_kdf_params_json(boundary) == pb
    assert kdf.parse_kdf_params_json(boundary + " ") is None
    for bad in ("", None, "not-json", "[]", "null", "{}"):
        assert kdf.parse_kdf_params_json(bad) is None


def test_kdf_refusals_explain_public_cost_and_structure_errors(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    kdf = importlib.import_module("app.security.kdf")
    pb = {"algorithm": "pbkdf2-sha256", "version": 1, "iterations": 600_000}
    argon = {
        "algorithm": "argon2id",
        "version": 1,
        "iterations": 2,
        "memory_kib": 19_456,
        "parallelism": 1,
    }
    refusals = [
        ([], "kdf_params must be a JSON object"),
        (
            {**pb, "algorithm": "unknown"},
            "kdf_params.algorithm must be 'pbkdf2-sha256' or 'argon2id'",
        ),
        ({**pb, "version": 2}, "kdf_params.version must be 1"),
        (
            {**pb, "memory_kib": 19_456},
            "pbkdf2-sha256 kdf_params carry iterations only",
        ),
        ({**pb, "parallelism": 1}, "pbkdf2-sha256 kdf_params carry iterations only"),
        (
            {**pb, "iterations": 99_999},
            "kdf_params.iterations must be 100000-10000000 for pbkdf2-sha256",
        ),
        (
            {**argon, "iterations": 1},
            "kdf_params.iterations must be 2-10000000 for argon2id",
        ),
        (
            {**argon, "memory_kib": 19_455},
            "kdf_params.memory_kib must be 19456-262144 (19-256 MiB)",
        ),
        ({**argon, "parallelism": 0}, "kdf_params.parallelism must be 1-4"),
        ({**pb, "iterations": True}, "kdf_params.iterations must be an integer"),
        ({**argon, "memory_kib": False}, "kdf_params.memory_kib must be an integer"),
        ({**argon, "parallelism": None}, "kdf_params.parallelism must be an integer"),
    ]
    for field in ("iterations", "memory_kib", "parallelism"):
        missing = {name: value for name, value in argon.items() if name != field}
        refusals.append((missing, f"argon2id kdf_params require {[field]}"))
    for value, diagnostic in refusals:
        with pytest.raises(kdf.KdfParamsError) as observed:
            kdf.validate_kdf_params(value)
        assert str(observed.value) == diagnostic


def test_sticky_entry_guard_mac_is_bound_to_every_ciphertext_metadata_field(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    guard = importlib.import_module("app.security.entry_guard")
    models = importlib.import_module("app.models")
    crypto = importlib.import_module("app.security.crypto")
    settings = SimpleNamespace(
        audit_mac_key_version=2, audit_mac_keyring={2: KEY, 1: b"o" * 32}
    )
    row = models.Entry(
        id="entry雪",
        user_id="patient雪",
        client_entry_id="client雪",
        entry_date=date(2026, 1, 1),
        blob=b"opaque ciphertext",
        content_version=7,
    )
    guard.seal_entry_guard(row, settings, v2_bound=True)
    canonical = [
        "entry-aad-guard/v1",
        "entry雪",
        "patient雪",
        "client雪",
        7,
        2,
        2,
        hashlib.sha256(b"opaque ciphertext").hexdigest(),
    ]
    purpose = hmac.digest(KEY, b"mindpattern/entry-aad-guard/v1", "sha256")
    expected = hmac.digest(
        purpose,
        json.dumps(canonical, separators=(",", ":"), ensure_ascii=True).encode("ascii"),
        "sha256",
    ).hex()
    assert row.aad_guard_mac == expected
    assert guard.validate_entry_guard(row, settings) is True
    assert guard.guarded_entry_aads(row, settings) == (
        b'["entry","patient\\u96ea","client\\u96ea","7"]',
    )
    assert guard.guard_values(row) == {
        "aad_guard_version": 2,
        "aad_guard_key_version": 2,
        "aad_guard_mac": expected,
    }
    for field, bad in [
        ("id", "other"),
        ("user_id", "other"),
        ("client_entry_id", "other"),
        ("content_version", 8),
        ("aad_guard_version", 0),
        ("aad_guard_key_version", 1),
        ("blob", b"altered ciphertext"),
        ("aad_guard_mac", "0" * 64),
    ]:
        original = getattr(row, field)
        setattr(row, field, bad)
        with pytest.raises(
            crypto.TamperError, match="^entry AAD guard is absent or invalid$"
        ):
            guard.validate_entry_guard(row, settings)
        setattr(row, field, original)
    for field, bad in [
        ("content_version", True),
        ("content_version", 0),
        ("content_version", 2**63),
        ("aad_guard_version", True),
        ("aad_guard_version", 1),
        ("aad_guard_key_version", True),
        ("aad_guard_key_version", 999),
        ("blob", bytearray(b"cipher")),
        ("id", ""),
        ("user_id", None),
        ("client_entry_id", 7),
        ("aad_guard_mac", "雪"),
        ("aad_guard_mac", None),
    ]:
        original = getattr(row, field)
        setattr(row, field, bad)
        with pytest.raises(
            crypto.TamperError, match="^entry AAD guard is absent or invalid$"
        ):
            guard.validate_entry_guard(row, settings)
        setattr(row, field, original)
    for version in (1, 2**63 - 1):
        row.content_version = version
        guard.seal_entry_guard(row, settings, v2_bound=False)
        assert guard.validate_entry_guard(row, settings) is False
        assert guard.guarded_entry_aads(row, settings) == crypto.entry_aad_candidates(
            row.user_id, row.client_entry_id, version
        )
    row.id = None
    row.content_version = None
    monkeypatch.setattr(guard, "new_id", lambda: "generated-entry-id")
    guard.seal_entry_guard(row, settings, v2_bound=True)
    assert row.id == "generated-entry-id" and row.content_version == 1
    assert guard.validate_entry_guard(row, settings) is True


def test_password_envelope_independent_kdf_aad_and_length_refusals(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    envelope = importlib.import_module("app.security.envelope")
    crypto = importlib.import_module("app.security.crypto")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    params = {"algorithm": "pbkdf2-sha256", "version": 1, "iterations": 600_000}
    salt = b"account salt"
    kek = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"mindpattern/envelope/v2"
    ).derive(KEY)
    assert envelope.envelope_kek(KEY, salt) == kek
    assert len(envelope.envelope_kek(bytes(16), salt)) == 32
    with pytest.raises(
        ValueError, match="^password-derived key material must be at least 16 bytes$"
    ):
        envelope.envelope_kek(bytes(15), salt)
    aad = json.dumps(
        {"context": "envelope", "kdf_params": params, "username": "patient雪"},
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    assert envelope.envelope_aad("patient雪", params) == aad
    nonce = bytes(range(12))
    wrapped = nonce + AESGCM(kek).encrypt(nonce, KEY, aad)
    assert (
        envelope.wrap_data_key(
            KEY, kek=kek, username="patient雪", kdf_params=params, nonce=nonce
        )
        == wrapped
    )
    assert (
        envelope.unwrap_data_key(
            wrapped, kek=kek, username="patient雪", kdf_params=params
        )
        == KEY
    )
    with pytest.raises(crypto.TamperError):
        envelope.unwrap_data_key(wrapped, kek=kek, username="other", kdf_params=params)
    with pytest.raises(ValueError, match="^data_key must be 32 bytes$"):
        envelope.wrap_data_key(
            bytes(31), kek=kek, username="p", kdf_params=params, nonce=nonce
        )
    for operation in (
        lambda: envelope.wrap_data_key(
            KEY, kek=bytes(31), username="p", kdf_params=params, nonce=nonce
        ),
        lambda: envelope.unwrap_data_key(
            wrapped, kek=bytes(31), username="p", kdf_params=params
        ),
    ):
        with pytest.raises(ValueError, match="^kek must be 32 bytes$"):
            operation()
    for length in (0, 59, 61):
        with pytest.raises(
            ValueError, match="^wrapped data key must be exactly 60 bytes$"
        ):
            envelope.unwrap_data_key(
                bytes(length), kek=kek, username="p", kdf_params=params
            )


def test_authenticated_guard_shape_validation_rejects_even_correctly_signed_bad_metadata(
    monkeypatch,
):
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    guard = importlib.import_module("app.security.entry_guard")
    crypto = importlib.import_module("app.security.crypto")
    settings = SimpleNamespace(audit_mac_key_version=2, audit_mac_keyring={2: KEY})
    pristine = {
        "id": "entry",
        "user_id": "patient",
        "client_entry_id": "client",
        "blob": b"opaque",
        "content_version": 1,
        "aad_guard_version": 0,
        "aad_guard_key_version": 2,
    }
    for field, bad in [
        ("content_version", 2**63),
        ("content_version", True),
        ("content_version", 0),
        ("aad_guard_version", 1),
        ("aad_guard_version", False),
        ("id", ""),
        ("user_id", ""),
        ("client_entry_id", ""),
        ("id", 7),
        ("user_id", None),
        ("client_entry_id", False),
    ]:
        row = SimpleNamespace(**{**pristine, field: bad})
        row.aad_guard_mac = guard._mac(row, KEY)
        with pytest.raises(
            crypto.TamperError, match="^entry AAD guard is absent or invalid$"
        ):
            guard.validate_entry_guard(row, settings)


def test_trusted_bootstrap_uses_native_eight_row_pages_and_preserves_existing_signed_ciphertext(
    monkeypatch,
):
    import asyncio
    from datetime import datetime, timezone

    from sqlalchemy import event, select
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    guard = importlib.import_module("app.security.entry_guard")
    models = importlib.import_module("app.models")
    settings = SimpleNamespace(audit_mac_key_version=2, audit_mac_keyring={2: KEY})
    queries = []

    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(models.Base.metadata.create_all)
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            async with sessions() as session:
                with pytest.raises(
                    RuntimeError,
                    match="^trusted entry bootstrap is unavailable or already complete$",
                ):
                    await guard.bootstrap_trusted_entries(sessions, settings)
                session.add(models.EntryGuardBootstrap(id=1))
                session.add(
                    models.User(
                        id="patient",
                        username="patient",
                        salt="salt",
                        verifier=b"v",
                        scrypt_salt=b"s",
                    )
                )
                for n in range(17):
                    row = models.Entry(
                        id=f"{n:02d}",
                        user_id="patient",
                        client_entry_id=f"client-{n}",
                        blob=("opaque-" + str(n)).encode(),
                        entry_date=date(2026, 10, 5),
                        content_version=1,
                    )
                    if n == 0:
                        guard.seal_entry_guard(row, settings, v2_bound=True)
                    session.add(row)
                await session.commit()

            @event.listens_for(engine.sync_engine, "before_cursor_execute")
            def record(connection, cursor, statement, parameters, context, many):
                if (
                    "FROM entries ORDER BY" in statement
                    or "FROM entries \nWHERE entries.id >" in statement
                ):
                    queries.append(parameters)

            before = datetime.now(timezone.utc)
            assert await guard.bootstrap_trusted_entries(sessions, settings) == 17
            assert len(queries) == 4 and all(
                parameters[-2] == 8 for parameters in queries
            )
            async with sessions() as session:
                marker = await session.get(models.EntryGuardBootstrap, 1)
                assert before <= marker.completed_at <= datetime.now(timezone.utc)
                rows = list(
                    (
                        await session.scalars(
                            select(models.Entry).order_by(models.Entry.id)
                        )
                    ).all()
                )
                for n, row in enumerate(rows):
                    assert row.blob == ("opaque-" + str(n)).encode()
                    assert guard.validate_entry_guard(row, settings) is (n == 0)
                with pytest.raises(
                    RuntimeError,
                    match="^trusted entry bootstrap is unavailable or already complete$",
                ):
                    await guard.bootstrap_trusted_entries(sessions, settings)
        finally:
            await engine.dispose()

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "fault", ["partial_seal", "completed_marker", "missing_marker"]
)
def test_trusted_bootstrap_refuses_partial_seals_and_changed_completion_marker(
    monkeypatch, fault
):
    import asyncio
    from datetime import datetime, timezone

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    guard = importlib.import_module("app.security.entry_guard")
    crypto = importlib.import_module("app.security.crypto")
    models = importlib.import_module("app.models")
    settings = SimpleNamespace(audit_mac_key_version=2, audit_mac_keyring={2: KEY})

    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(models.Base.metadata.create_all)
            sessions = async_sessionmaker(engine, expire_on_commit=False)
            async with sessions() as session:
                session.add(models.EntryGuardBootstrap(id=1))
                if fault == "partial_seal":
                    session.add(
                        models.Entry(
                            id="entry",
                            user_id="patient",
                            client_entry_id="client",
                            blob=b"opaque",
                            entry_date=date(2026, 10, 5),
                            content_version=1,
                            aad_guard_version=0,
                            aad_guard_key_version=None,
                            aad_guard_mac="invalid",
                        )
                    )
                await session.commit()
            if fault == "partial_seal":
                with pytest.raises(
                    crypto.TamperError, match="^entry AAD guard is absent or invalid$"
                ):
                    await guard.bootstrap_trusted_entries(sessions, settings)
            else:
                calls = 0

                class ConcurrentOperatorSession:
                    def __init__(self):
                        self.session = sessions()

                    async def __aenter__(self):
                        nonlocal calls
                        calls += 1
                        await self.session.__aenter__()
                        if calls == 3:
                            marker = await self.session.get(
                                models.EntryGuardBootstrap, 1
                            )
                            if fault == "missing_marker":
                                await self.session.delete(marker)
                            else:
                                marker.completed_at = datetime.now(timezone.utc)
                            await self.session.commit()
                        return self.session

                    async def __aexit__(self, *args):
                        return await self.session.__aexit__(*args)

                with pytest.raises(
                    RuntimeError, match="^trusted entry bootstrap marker changed$"
                ):
                    await guard.bootstrap_trusted_entries(
                        ConcurrentOperatorSession, settings
                    )
        finally:
            await engine.dispose()

    asyncio.run(exercise())


def test_signed_body_with_invalid_base64_character_is_a_malformed_payload(monkeypatch):
    _modules(monkeypatch)
    tokens = importlib.import_module("app.security.tokens")
    import base64
    import hashlib
    import hmac

    payload = {"uid": "patient", "exp": 1001}
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=")
    while len(encoded) % 4 != 2:
        payload["uid"] += "x"
        encoded = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=")
    body = encoded + b"!"
    signature = base64.urlsafe_b64encode(
        hmac.digest(b"secret", body, hashlib.sha256)
    ).rstrip(b"=")
    with pytest.raises(tokens.TokenError, match="^malformed payload$"):
        tokens.verify_token((body + b"." + signature).decode(), "secret", now=1000)


def test_trusted_bootstrap_cannot_skip_a_tampered_empty_identifier(monkeypatch):
    import asyncio

    from sqlalchemy import update
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    _modules(monkeypatch)
    guard = importlib.import_module("app.security.entry_guard")
    models = importlib.import_module("app.models")
    settings = SimpleNamespace(audit_mac_key_version=2, audit_mac_keyring={2: KEY})

    async def exercise():
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(models.Base.metadata.create_all)
            maker = async_sessionmaker(engine, expire_on_commit=False)
            async with maker() as session:
                row = models.Entry(
                    id="entry",
                    user_id="patient",
                    client_entry_id="client",
                    blob=b"opaque",
                    entry_date=date(2026, 10, 5),
                    content_version=1,
                )
                guard.seal_entry_guard(row, settings, v2_bound=True)
                session.add(row)
                session.add(models.EntryGuardBootstrap(id=1))
                await session.commit()
                await session.execute(
                    update(models.Entry).where(models.Entry.id == "entry").values(id="")
                )
                await session.commit()
            crypto = importlib.import_module("app.security.crypto")
            with pytest.raises(
                crypto.TamperError, match="^entry AAD guard is absent or invalid$"
            ):
                await guard.bootstrap_trusted_entries(maker, settings)
            async with maker() as session:
                assert (
                    await session.get(models.EntryGuardBootstrap, 1)
                ).completed_at is None
        finally:
            await engine.dispose()

    asyncio.run(exercise())
