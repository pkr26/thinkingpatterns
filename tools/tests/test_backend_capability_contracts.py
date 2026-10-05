"""Interoperable authenticators and native capability retention boundaries."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import importlib
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _module(monkeypatch, name):
    monkeypatch.setenv("MINDPATTERN_ENV", "development")
    monkeypatch.syspath_prepend(str(ROOT / "backend"))
    return importlib.import_module("app.security." + name)


def _hkdf(material, label, salt=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=label).derive(
        material
    )


def test_authenticator_matches_rfc4226_and_accepts_only_past_and_current(monkeypatch):
    totp = _module(monkeypatch, "totp")
    secret = b"12345678901234567890"
    codes = [
        "755224",
        "287082",
        "359152",
        "969429",
        "338314",
        "254676",
        "287922",
        "162583",
        "399871",
        "520489",
    ]
    assert [totp._code_for_counter(secret, n) for n in range(10)] == codes
    for n in range(2, 9):
        at = n * 30 + 29.9
        assert totp.verify_code(secret, codes[n], at=at) == n
        assert totp.verify_code(secret, " " + codes[n - 1] + " ", at=at) == n - 1
        assert totp.verify_code(secret, codes[n + 1], at=at) is None
        assert totp.verify_code(secret, codes[n - 2], at=at) is None
    monkeypatch.setattr(totp.time, "time", lambda: 90.0)
    assert totp.verify_code(secret, codes[3]) == 3
    for code in ("", "12345", "1234567", "abcdef", "١٢٣٤٥٦", "²34567"):
        assert totp.verify_code(secret, code, at=90) is None
    # verify_code exposes an explicit clock input. Keep the counter inside
    # the RFC's unsigned 64-bit range and derive floor using exact integer
    # arithmetic, even when binary64 division rounds up at a boundary.
    import struct

    at = 2.457722474143434e17
    numerator, denominator = at.as_integer_ratio()
    counter = numerator // (denominator * 30)
    digest = hmac.digest(secret, struct.pack(">Q", counter), "sha1")
    offset = digest[-1] & 15
    expected = f"{(int.from_bytes(digest[offset : offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"
    assert totp.verify_code(secret, expected, at=at, drift=0) == counter


def test_authenticator_enrollment_and_wrapped_secrets_interoperate(monkeypatch):
    totp = _module(monkeypatch, "totp")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    calls = []
    native_entropy = totp.secrets.token_bytes

    def entropy(size=None):
        calls.append(size)
        requested = size if size is not None else len(native_entropy())
        # Honor the CSPRNG's integer and default-length contracts. Complete
        # Base32 groups end in X, preserving the padding/strip regression.
        return (
            bytes(range(requested))
            if requested == 12
            else bytes(requested - 1) + b"\x17"
        )

    monkeypatch.setattr(totp.secrets, "token_bytes", entropy)
    raw, encoded = totp.generate_secret()
    assert len(raw) >= 20 and len(calls) == 1
    assert raw == bytes(len(raw) - 1) + b"\x17"
    assert encoded == base64.b32encode(raw).decode().rstrip("=")
    assert base64.b32decode(encoded + "=" * ((-len(encoded)) % 8)) == raw
    if len(raw) % 5 == 0:
        assert encoded.endswith("X")
    from urllib.parse import parse_qs, urlsplit

    assert parse_qs(urlsplit(totp.otpauth_uri(encoded, "therapist")).query)[
        "secret"
    ] == [encoded]
    digest = hmac.digest(raw, (1).to_bytes(8, "big"), "sha1")
    offset = digest[-1] & 15
    expected_code = f"{(int.from_bytes(digest[offset : offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"
    assert totp.verify_code(raw, expected_code, at=59) == 1
    assert totp.otpauth_uri("ABC", "a/b 雪") == (
        "otpauth://totp/Fathom:a%2Fb%20%E9%9B%AA?secret=ABC&issuer=Fathom"
        "&algorithm=SHA1&digits=6&period=30"
    )
    assert totp.otpauth_uri("DEF", "user", "issuer:/") == (
        "otpauth://totp/issuer%3A%2F:user?secret=DEF&issuer=issuer%3A%2F"
        "&algorithm=SHA1&digits=6&period=30"
    )
    key = _hkdf("wrap-secret雪".encode(), b"mindpattern/totp-at-rest/v1")
    nonce = bytes(range(12))
    for secret in (b"", raw):
        expected = (
            "v1:"
            + base64.b64encode(
                nonce + AESGCM(key).encrypt(nonce, secret, b"totp")
            ).decode()
        )
        assert totp.wrap_secret(secret, "wrap-secret雪") == expected
        assert totp.unwrap_secret(expected, "wrap-secret雪") == secret
        assert totp.unwrap_secret(expected, "other-secret") is None
        assert (
            totp.unwrap_secret(expected[:4] + "!" + expected[4:], "wrap-secret雪")
            is None
        )
    for blob in (
        None,
        "",
        "v2:garbage",
        "v1:???",
        "v1:" + base64.b64encode(bytes(27)).decode(),
    ):
        assert totp.unwrap_secret(blob, "wrap-secret雪") is None

    # Also exercise the real producer: default-length entropy is a supported
    # secrets API, and a longer key must enroll, verify and wrap normally.
    monkeypatch.setattr(totp.secrets, "token_bytes", native_entropy)
    native_raw, native_encoded = totp.generate_secret()
    assert len(native_raw) >= 20
    assert (
        base64.b32decode(native_encoded + "=" * ((-len(native_encoded)) % 8))
        == native_raw
    )
    assert parse_qs(urlsplit(totp.otpauth_uri(native_encoded, "therapist")).query)[
        "secret"
    ] == [native_encoded]
    native_digest = hmac.digest(native_raw, (1).to_bytes(8, "big"), "sha1")
    native_offset = native_digest[-1] & 15
    native_code = f"{(int.from_bytes(native_digest[native_offset : native_offset + 4], 'big') & 0x7FFFFFFF) % 1_000_000:06d}"
    assert totp.verify_code(native_raw, native_code, at=59) == 1
    assert (
        totp.unwrap_secret(
            totp.wrap_secret(native_raw, "wrap-secret雪"), "wrap-secret雪"
        )
        == native_raw
    )


def test_human_codes_reject_biased_entropy_and_keep_exact_native_lengths(monkeypatch):
    sharing = _module(monkeypatch, "sharing")
    totp = _module(monkeypatch, "totp")
    alphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ"
    # Bytes 240..255 cannot be mapped uniformly into the released 30-symbol
    # alphabet. Include the exact boundary then enough accepted symbols.
    entropy = bytes([240, 255]) + bytes(range(30))
    monkeypatch.setattr(sharing.os, "urandom", lambda n: entropy[:n])
    assert sharing.generate_pairing_code() == alphabet[:8]
    assert totp.generate_backup_code() == alphabet[:10]
    for invalid in ("ß", "雪", "O1234567", "2345-678", "23456789\u00a0"):
        assert sharing.normalize_pairing_code(invalid) == ""
    assert sharing.normalize_pairing_code(" \t2345abcd\r\n") == "2345ABCD"
    for operation, label in (
        (sharing.pairing_code_digest, b"mindpattern/pairing-digest/v1"),
        (sharing.backup_code_digest, b"mindpattern/totp-backup-digest/v1"),
    ):
        key = _hkdf("server雪".encode(), label)
        assert (
            operation(" 2345abcd ", "server雪")
            == hmac.digest(key, b"2345ABCD", "sha256").hex()
        )
        assert operation("雪", "server雪") == hmac.digest(key, b"", "sha256").hex()
    der = b"independent public key"
    digest = hmac.digest(b"2345ABCD", der + "patient雪".encode(), "sha256")
    digits = f"{int.from_bytes(digest, 'big') % 1_000_000:06d}"
    assert (
        sharing.pairing_sas("2345ABCD", der, "patient雪")
        == digits[:3] + " " + digits[3:]
    )
    assert sharing.wrap_key_fingerprint(der) == hashlib.sha256(der).hexdigest()[:16]


def test_ecies_keys_summary_limits_and_independent_ciphertext_interoperation(
    monkeypatch,
):
    sharing = _module(monkeypatch, "sharing")
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
        load_der_public_key,
    )

    therapist = ec.derive_private_key(5, ec.SECP256R1())
    ephemeral = ec.derive_private_key(7, ec.SECP256R1())
    der = therapist.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    b64 = base64.b64encode(der).decode()
    for payload, operation, context in (
        (bytes(range(32)), sharing.wrap_data_key, b"consent-wrap"),
        (b"x" * 512, sharing.wrap_summary_payload, b"caseload-summary"),
    ):
        if operation is sharing.wrap_data_key:
            eph_b64, wrapped_b64 = operation(
                payload, b64, "patient", "therapist", ephemeral
            )
        else:
            eph_b64, wrapped_b64 = operation(payload, b64, "patient", "therapist")
        eph_der = base64.b64decode(eph_b64)
        shared = therapist.exchange(ec.ECDH(), load_der_public_key(eph_der))
        key = _hkdf(shared, b"mindpattern/wrap/v1", eph_der + der)
        wrapped = base64.b64decode(wrapped_b64)
        aad = b'["' + context + b'","patient","therapist"]'
        assert AESGCM(key).decrypt(wrapped[:12], wrapped[12:], aad) == payload
        if operation is sharing.wrap_data_key:
            assert (
                sharing.unwrap_data_key(
                    therapist, eph_b64, wrapped, "patient", "therapist"
                )
                == payload
            )
            assert (
                sharing.unwrap_data_key(
                    therapist, eph_b64, wrapped, "patient", "therapist", der
                )
                == payload
            )
        else:
            assert (
                sharing.unwrap_summary_payload(
                    therapist, eph_b64, wrapped, "patient", "therapist"
                )
                == payload
            )
    with pytest.raises(sharing.SharingError, match="^summary payload too large$"):
        sharing.wrap_summary_payload(bytes(513), b64, "patient", "therapist")
    with pytest.raises(sharing.SharingError, match="^data_key must be 32 bytes$"):
        sharing.wrap_data_key(bytes(31), b64, "patient", "therapist")


def test_key_registration_refuses_each_malformed_key_with_named_diagnostics(
    monkeypatch,
):
    sharing = _module(monkeypatch, "sharing")
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    other_curve = ec.derive_private_key(3, ec.SECP384R1())
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    for material, diagnostic in (
        (b"not DER", "not a valid SPKI public key"),
        (
            rsa_key.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            "public key must be elliptic-curve",
        ),
        (
            other_curve.public_key().public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            "public key must be P-256 (prime256v1)",
        ),
    ):
        with pytest.raises(sharing.SharingError) as observed:
            sharing.validate_public_key_b64(base64.b64encode(material).decode())
        assert str(observed.value) == diagnostic
    valid = ec.derive_private_key(1, ec.SECP256R1())
    public = valid.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    with pytest.raises(sharing.SharingError, match="^public key must be base64$"):
        sharing.validate_public_key_b64("!" + base64.b64encode(public).decode())
    pkcs8 = valid.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    assert (
        sharing.load_private_key_pkcs8(pkcs8).private_numbers()
        == valid.private_numbers()
    )
    for material, diagnostic in (
        (b"not DER", "not a valid PKCS8 private key"),
        (
            rsa_key.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption()),
            "private key must be P-256 (prime256v1)",
        ),
        (
            other_curve.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            ),
            "private key must be P-256 (prime256v1)",
        ),
    ):
        with pytest.raises(sharing.SharingError) as observed:
            sharing.load_private_key_pkcs8(material)
        assert str(observed.value) == diagnostic


def test_export_capabilities_have_native_capacity_and_immutable_digest_only_grants(
    monkeypatch,
):
    module = _module(monkeypatch, "export_ticket")
    monkeypatch.setattr(module.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(module.time, "time", lambda: 1000.0)
    store = module.ExportTicketStore()
    arguments = {
        "token_epoch": 4,
        "token_jti": "jti",
        "token_expires": 2000.0,
        "secret_fingerprint": "fingerprint",
    }
    tokens = [store.issue(user_id=f"user-{n}", **arguments) for n in range(1024)]
    assert len(store._tickets) == 1024 and set(tokens).isdisjoint(store._tickets)
    with pytest.raises(RuntimeError, match="^export ticket capacity reached$"):
        store.issue(user_id="next-user", **arguments)
    grant = store.consume(tokens[0])
    assert grant.user_id == "user-0" and grant.expires_at == 160.0
    assert grant.token_epoch == 4 and grant.token_jti == "jti"
    assert grant.token_expires == 2000.0 and grant.secret_fingerprint == "fingerprint"
    with pytest.raises(FrozenInstanceError):
        grant.user_id = "other-user"
    assert store.consume(tokens[0]) is None
    assert (
        module.secret_fingerprint("secret雪", 7)
        == hashlib.sha256("7:secret雪".encode()).hexdigest()
    )
    store.clear()
    assert store._tickets == {}


def test_export_replacement_and_both_expiry_clocks_are_inclusive(monkeypatch):
    module = _module(monkeypatch, "export_ticket")
    mono, wall = [100.0], [1000.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: mono[0])
    monkeypatch.setattr(module.time, "time", lambda: wall[0])
    arguments = {
        "user_id": "user",
        "token_epoch": 1,
        "token_jti": None,
        "token_expires": 2000.0,
        "secret_fingerprint": "f",
    }
    store = module.ExportTicketStore()
    first, second, third = [store.issue(**arguments) for _ in range(3)]
    assert store.consume(first) is None
    assert store.consume(second) is not None and store.consume(third) is not None
    token = store.issue(**arguments)
    mono[0] = 160.0
    assert store.consume(token) is None
    mono[0] = 200.0
    token = store.issue(**{**arguments, "token_expires": 1001.0})
    wall[0] = 1001.0
    assert store.consume(token) is None
    # Admission must discard a token at either exact expiry boundary.
    wall[0] = 1000.0
    expired_mono = store.issue(**arguments)
    expired_wall = store.issue(
        **{**arguments, "user_id": "other", "token_expires": 1001.0}
    )
    # Exercise each expiry independently; expiring both at once can hide
    # an inclusive-boundary defect in either predicate.
    mono[0], wall[0] = 259.0, 1001.0
    store.issue(**{**arguments, "user_id": "new"})
    assert module.ExportTicketStore._digest(expired_wall) not in store._tickets
    mono[0] = 260.0
    store.issue(**{**arguments, "user_id": "next"})
    assert module.ExportTicketStore._digest(expired_mono) not in store._tickets


def test_step_up_retention_capacity_frozen_bindings_and_single_use(monkeypatch):
    module = _module(monkeypatch, "step_up")
    clock = [100.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])

    async def exercise():
        store = module.StepUpProofStore()
        args = {
            "user_id": "user",
            "action": "delete",
            "token_jti": "jti",
            "token_epoch": 2,
        }
        tokens = []
        for n in range(9):
            clock[0] = 100.0 + n
            token, ttl = await store.issue(**args)
            assert ttl == 120
            tokens.append(token)
        assert len(set(tokens)) == 9, (
            "each one-use proof needs a fresh unpredictable capability"
        )
        for token in tokens:
            assert token and set(token) <= set(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            )
            assert len(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))) >= 32
        assert len(store._proofs) == 8
        assert set(tokens).isdisjoint(store._proofs)
        proof = next(iter(store._proofs.values()))
        with pytest.raises(FrozenInstanceError):
            proof.action = "other"
        assert await store.consume(tokens[0], **args) is False
        assert await store.consume(tokens[1], **{**args, "action": "other"}) is False
        assert await store.consume(tokens[1], **args) is False
        assert await store.consume(tokens[2], **args) is True
        assert await store.consume(tokens[2], **args) is False
        assert await store.consume("雪", **args) is False
        token, _ = await store.issue(**args)
        clock[0] += 120
        assert await store.consume(token, **args) is False
        # Materialize the real native 10,000-cardinality store with valid
        # proof records; no production capacity or branch is lowered.
        clock[0] = 100.0
        store._proofs = {
            hashlib.sha256(f"proof-{n}".encode()).hexdigest(): replace(
                proof, user_id=f"user-{n}", expires_at=220.0
            )
            for n in range(10_000)
        }
        with pytest.raises(RuntimeError, match="^step-up proof capacity exhausted$"):
            await store.issue(**{**args, "user_id": "new-user"})
        clock[0] = 220.0
        await store.issue(**{**args, "user_id": "new-user"})
        assert len(store._proofs) == 1

    asyncio.run(exercise())


def test_deletion_evidence_authenticates_utc_seconds_and_exact_expiry(monkeypatch):
    module = _module(monkeypatch, "deletion_tombstone")
    models = importlib.import_module("app.models")
    now = datetime(2026, 10, 5, 12, 0, 0, 987654, tzinfo=timezone.utc)
    user = models.User(id="patient雪", role="patient", token_epoch=9)
    row = module.new_deletion_tombstone(
        user, secret="server雪", auth_secret_version=7, now=now
    )
    assert row.deleted_at == now.replace(microsecond=0)
    assert row.expires_at == row.deleted_at + timedelta(days=30)
    values = [
        "1",
        "patient雪",
        "patient",
        "9",
        "7",
        str(int(row.deleted_at.timestamp())),
        str(int(row.expires_at.timestamp())),
    ]
    assert (
        row.record_mac
        == hmac.digest("server雪".encode(), "\n".join(values).encode(), "sha256").hex()
    )
    assert module.verifies_deletion_tombstone(
        row,
        secret="server雪",
        auth_secret_version=7,
        now=row.expires_at - timedelta(microseconds=1),
    )
    assert not module.verifies_deletion_tombstone(
        row, secret="server雪", auth_secret_version=7, now=row.expires_at
    )
    shifted = now.astimezone(timezone(timedelta(hours=-7)))
    assert module._canonical_timestamp(now) == module._canonical_timestamp(shifted)
    assert module._canonical_timestamp(now.replace(tzinfo=None)) == str(
        int(now.timestamp())
    )
