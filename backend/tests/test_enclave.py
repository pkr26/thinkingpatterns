"""Secure processing enclave: key store TTLs, zeroization, plaintext windows."""

from __future__ import annotations

import pytest

from app.security import crypto
from app.security.enclave import (
    InMemoryKeyStore,
    KeyNotFound,
    SecureProcessingContext,
    plaintext_windows,
    run_isolated,
)


def make_blobs(key, count=3):
    aads_and_plaintexts = [
        (crypto.build_aad("entry", "u1", f"e{i}"), f"secret plaintext {i}".encode())
        for i in range(count)
    ]
    return aads_and_plaintexts, [
        (aad, crypto.encrypt(key, pt, aad)) for aad, pt in aads_and_plaintexts
    ]


class TestInMemoryKeyStore:
    def test_create_get_roundtrip(self):
        store = InMemoryKeyStore()
        key = crypto.generate_key()
        token = store.create(key, ttl_seconds=60, owner="unbound-test")
        assert store.get(token) == key

    def test_unknown_token(self):
        store = InMemoryKeyStore()
        with pytest.raises(KeyNotFound):
            store.get("nope")

    def test_expiry(self):
        store = InMemoryKeyStore()
        token = store.create(crypto.generate_key(), ttl_seconds=10, now=100.0, owner="unbound-test")
        store.get(token, now=105.0)
        with pytest.raises(KeyNotFound):
            store.get(token, now=110.0)  # at/after expiry
        with pytest.raises(KeyNotFound):  # and it was purged, not just refused
            store.get(token, now=100.0)

    def test_destroy(self):
        store = InMemoryKeyStore()
        token = store.create(crypto.generate_key(), 60, owner="unbound-test")
        assert store.destroy(token) is True
        assert store.destroy(token) is False  # idempotent second destroy
        with pytest.raises(KeyNotFound):
            store.get(token)

    def test_foreign_owner_cannot_consume_or_destroy_a_session(self):
        store = InMemoryKeyStore()
        key = crypto.generate_key()
        token = store.create(key, 60, owner="owner")

        with pytest.raises(KeyNotFound):
            store.pop(token, owner="other")
        assert store.destroy(token, owner="other") is False

        # The real owner can still consume the exact store-owned key.  This
        # guards against a rejected cross-account request becoming a DoS.
        consumed = store.pop(token, owner="owner")
        assert consumed == key
        for index in range(len(consumed)):
            consumed[index] = 0

    def test_purge_expired(self):
        store = InMemoryKeyStore()
        store.create(crypto.generate_key(), 10, now=0.0, owner="unbound-test")
        store.create(crypto.generate_key(), 10, now=0.0, owner="unbound-test")
        keep = store.create(crypto.generate_key(), 100, now=0.0, owner="unbound-test")
        assert len(store) == 3
        purged = store.purge_expired(now=50.0)
        assert purged == 2
        assert len(store) == 1
        store.get(keep, now=50.0)  # survivor still works

    def test_rejects_bad_key_and_ttl(self):
        store = InMemoryKeyStore()
        with pytest.raises(ValueError):
            store.create(b"too-short", 60, owner="unbound-test")
        with pytest.raises(ValueError):
            store.create(crypto.generate_key(), 0, owner="unbound-test")

    def test_tokens_are_unique_and_long(self):
        # Owner binding is mandatory now, so minting 20 sessions for one
        # owner needs that owner's cap raised (default 4): this test is
        # about token entropy, not per-owner capacity.
        store = InMemoryKeyStore(max_sessions_per_owner=20)
        key = crypto.generate_key()
        tokens = {store.create(key, 60, owner="unbound-test") for _ in range(20)}
        assert len(tokens) == 20
        assert all(len(t) >= 32 for t in tokens)


class TestSecureProcessingContext:
    def test_analyze_sees_plaintext(self):
        key = crypto.generate_key()
        _, blobs = make_blobs(key)
        # Copy inside the analysis window: buffers themselves are zeroized after.
        result = SecureProcessingContext(key).run(blobs, lambda plains: [bytes(p) for p in plains])
        assert result == [b"secret plaintext 0", b"secret plaintext 1", b"secret plaintext 2"]

    def test_plaintext_zeroized_after_run(self):
        key = crypto.generate_key()
        _, blobs = make_blobs(key, count=4)
        captured = []

        def analyze(plains):
            captured.extend(plains)
            return "done"

        assert SecureProcessingContext(key).run(blobs, analyze) == "done"
        for buf in captured:
            assert all(b == 0 for b in buf), "buffer survived the processing window"

    def test_zeroized_even_when_analysis_raises(self):
        key = crypto.generate_key()
        _, blobs = make_blobs(key)
        captured = []

        def exploding(plains):
            captured.extend(plains)
            raise RuntimeError("analyzer blew up")

        with pytest.raises(RuntimeError):
            SecureProcessingContext(key).run(blobs, exploding)
        for buf in captured:
            assert all(b == 0 for b in buf)

    def test_zeroized_even_when_decryption_fails_midway(self):
        key = crypto.generate_key()
        _, blobs = make_blobs(key, count=3)
        tampered = [(aad, bytes(blob[:-1]) + bytes([blob[-1] ^ 1])) for aad, blob in blobs]
        with pytest.raises(crypto.TamperError):
            SecureProcessingContext(key).run(tampered, lambda plains: plains)
        assert plaintext_windows() == 0

    def test_plaintext_window_counter_balanced(self):
        key = crypto.generate_key()
        _, blobs = make_blobs(key, count=2)
        before = plaintext_windows()
        observed = []

        def analyze(plains):
            observed.append(plaintext_windows())
            return None

        SecureProcessingContext(key).run(blobs, analyze)
        assert observed == [before + 1]
        assert plaintext_windows() == before

    def test_wrong_key_fails_all(self):
        key = crypto.generate_key()
        _, blobs = make_blobs(key)
        with pytest.raises(crypto.TamperError):
            SecureProcessingContext(crypto.generate_key()).run(blobs, lambda p: p)

    def test_bad_key_size_rejected(self):
        with pytest.raises(ValueError):
            SecureProcessingContext(b"short").run([], lambda p: p)

    def test_run_isolated_helper(self):
        key = crypto.generate_key()
        aad = crypto.build_aad("entry", "u", "e")
        blob = crypto.encrypt(key, b"one shot", aad)
        result = run_isolated(key, [(aad, blob)], lambda plains: bytes(plains[0]))
        assert result == b"one shot"

    def test_one_key_buffer_drives_every_decryption_and_is_zeroized(self, monkeypatch):
        # Per-item bytes(self._key) minted N immutable key copies that
        # lingered unzeroized until GC; the context now mints ONE bytearray
        # working copy per run, feeds it to every decrypt call, and scrubs
        # it with the rest of the run's buffers.
        key = crypto.generate_key()
        _, blobs = make_blobs(key, count=4)
        from app.security import enclave

        seen_keys = []
        real_decrypt = enclave.decrypt

        def spy(k, blob, aad=None):
            seen_keys.append(k)
            return real_decrypt(k, blob, aad)

        monkeypatch.setattr("app.security.enclave.decrypt", spy)
        result = SecureProcessingContext(key).run(blobs, lambda plains: len(plains))
        assert result == 4
        assert len(seen_keys) == 4
        assert all(k is seen_keys[0] for k in seen_keys), (
            "every item must decrypt with the same working buffer"
        )
        assert isinstance(seen_keys[0], bytearray)
        assert all(b == 0 for b in seen_keys[0]), "working key copy survived the window"

    def test_key_buffer_zeroized_even_when_decryption_fails(self, monkeypatch):
        key = crypto.generate_key()
        _, blobs = make_blobs(key, count=3)
        tampered = [(aad, bytes(blob[:-1]) + bytes([blob[-1] ^ 1])) for aad, blob in blobs]
        from app.security import enclave

        seen_keys = []
        real_decrypt = enclave.decrypt

        def spy(k, blob, aad=None):
            seen_keys.append(k)
            return real_decrypt(k, blob, aad)

        monkeypatch.setattr("app.security.enclave.decrypt", spy)
        with pytest.raises(crypto.TamperError):
            SecureProcessingContext(key).run(tampered, lambda plains: plains)
        assert seen_keys and all(b == 0 for b in seen_keys[0])
