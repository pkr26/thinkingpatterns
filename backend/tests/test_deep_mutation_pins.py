"""Pins for every true survivor of the 2026-09-15 deep mutation campaign.

Each test here kills one or more mutants that survived the FULL suite during
the campaign (see reports/mutation_report_2026-09-15.md). The structurally
unkillable survivors — postgres-only branches exercised via duck-typed fakes
where possible, typing-only mutations, opaque lock keys, `limit(1)`+`.first()`
pairs, dead pydantic defaults — are enumerated in the report's equivalents
section and deliberately not chased here.

Error-path tests assert the machine-readable ``code`` (and the exact
``detail`` where the campaign showed the string drifting unpunished): both
are client contract, per app/deps.py's envelope docstring.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac as hmac_mod
import inspect
import json
import logging
import math
import os
from dataclasses import replace
from datetime import date, timedelta
from types import SimpleNamespace

import pytest
from fastapi.exceptions import RequestValidationError
from sqlalchemy import delete as sa_delete
from sqlalchemy.exc import IntegrityError

from app.api import account, auth, entries, insights
from app.cache import EVICTION_BATCH, MAX_TRACKED_KEYS, FixedWindowCounter
from app.config import (
    MAX_PROCESSING_SESSION_TTL,
    MAX_RATE_LIMIT,
    MAX_RATE_WINDOW_SECONDS,
    MAX_TOKEN_TTL_SECONDS,
    Settings,
)
from app.deps import DEFAULT_ERROR_CODES, ApiError, require_user
from app.locks import UserLocks
from app.main import _error_envelope, logger as main_logger
from app.middleware import HardeningMiddleware
from app.models import Entry, Insight, User, new_id
from app.schemas import (
    MAX_BLOB_B64,
    MAX_DATA_KEY_B64,
    MAX_SALT_B64,
    MAX_VERIFIER_B64,
    USERNAME_PATTERN,
)
from app.security import crypto, enclave, tokens
from tests.helpers import ClientEmulator, daterange

T0 = date.today()


# ===========================================================================
# app/api/account.py — cross-user isolation, export shape, verifier paths
# ===========================================================================


async def test_account_delete_never_touches_other_users_rows(client, app):
    """The campaign's worst survivor: `delete(Insight).where(user_id == id)`
    mutated to `!=` (wipe every OTHER user's insights) passed the suite."""
    alice = ClientEmulator("delalice", "pw-alice-is-long")
    bob = ClientEmulator("delbob", "pw-bob-is-long-too")
    await alice.register(client)
    await bob.register(client)
    await alice.backdate_account(client, days=10)
    await bob.backdate_account(client, days=10)
    await alice.create_entry(client, "alice day", T0 - timedelta(days=3))
    await bob.create_entry(client, "bob day", T0 - timedelta(days=3))
    async with app.state.sessionmaker() as session:
        session.add(
            Insight(
                id=new_id(),
                user_id=bob.user_id,
                kind="patterns",
                for_date=None,
                blob=b"bob-insight",
            )
        )
        session.add(
            Insight(
                id=new_id(),
                user_id=alice.user_id,
                kind="patterns",
                for_date=None,
                blob=b"alice-insight",
            )
        )
        await session.commit()

    assert await alice.delete_account(client) == 204

    from sqlalchemy import select

    async with app.state.sessionmaker() as session:
        bob_e = (
            (await session.execute(select(Entry).where(Entry.user_id == bob.user_id)))
            .scalars()
            .all()
        )
        bob_i = (
            (await session.execute(select(Insight).where(Insight.user_id == bob.user_id)))
            .scalars()
            .all()
        )
        alice_e = (
            (await session.execute(select(Entry).where(Entry.user_id == alice.user_id)))
            .scalars()
            .all()
        )
    assert len(bob_e) == 1, "another user's entries were destroyed by account deletion"
    assert len(bob_i) == 1, "another user's insights were destroyed by account deletion"
    assert alice_e == [], "deleted user's entries must be gone"


async def test_account_delete_missing_verifier_detail(client):
    emu = ClientEmulator("delnever", "pw-del-never-x")
    await emu.register(client)
    response = await client.request("DELETE", "/api/account", headers=emu.headers)
    assert response.status_code == 422
    assert response.json() == {
        "detail": "account verifier required (X-Account-Verifier header)",
        "code": "validation_error",
    }


async def test_export_stream_has_no_duplicate_collection_keys(client):
    emu = ClientEmulator("exportok", "pw-export-ok-x")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    await emu.create_entry(client, "exported day", T0 - timedelta(days=2))
    response = await client.get("/api/account/export", headers=emu.headers)
    assert response.status_code == 200
    text = response.text
    # The streamed head must exclude the collections: duplicates would mean a
    # client could parse a different shape than the streamed one.
    assert text.count('"entries":') == 1
    assert text.count('"insights":') == 1
    parsed = json.loads(text)
    assert parsed["entries"] and parsed["entries"][0]["client_entry_id"]


# ===========================================================================
# app/api/auth.py — decoy determinism, timing-equalization, contract codes
# ===========================================================================


def test_decoy_salt_is_deterministic_across_versions():
    # Cross-version stability: registered decoys must not change silently
    # (the HKDF label is part of the derived key). Golden value pinned.
    assert auth.decoy_salt("mutation-pin-user", "test-secret-not-for-production") == (
        "u23+g0gY9TbU3fxMOfXWXg=="
    )


def test_default_error_codes_map_is_pinned_exactly():
    assert DEFAULT_ERROR_CODES == {
        400: "bad_request",
        401: "unauthorized",
        403: "forbidden",
        404: "not_found",
        405: "method_not_allowed",
        408: "request_timeout",
        409: "conflict",
        410: "gone",
        413: "payload_too_large",
        422: "validation_error",
        429: "rate_limited",
        500: "internal_error",
        503: "service_unavailable",
    }


async def test_register_contract_codes_and_details(client):
    bad = ClientEmulator("regcontract", "pw-reg-contract")
    # non-base64 salt
    r = await client.post(
        "/api/auth/register",
        json={"username": bad.username, "salt": "!!not-b64!!", "verifier": bad.auth_key_b64},
    )
    assert r.status_code == 422
    assert r.json() == {"detail": "salt and verifier must be base64", "code": "validation_error"}
    # salt of the wrong byte length (valid b64)
    r = await client.post(
        "/api/auth/register",
        json={
            "username": bad.username,
            "salt": base64.b64encode(b"x" * 17).decode(),
            "verifier": bad.auth_key_b64,
        },
    )
    assert r.status_code == 422
    assert r.json() == {"detail": "salt must be exactly 16 bytes", "code": "validation_error"}
    # verifier of the wrong byte length
    r = await client.post(
        "/api/auth/register",
        json={
            "username": bad.username,
            "salt": bad.salt_b64,
            "verifier": base64.b64encode(b"y" * 33).decode(),
        },
    )
    assert r.status_code == 422
    assert r.json() == {"detail": "verifier must be 32 bytes", "code": "validation_error"}


async def test_register_conflict_code(client):
    emu = ClientEmulator("regdup", "pw-reg-dup-x")
    await emu.register(client)
    again = ClientEmulator("regdup", "pw-other-longer")
    r = await client.post(
        "/api/auth/register",
        json={"username": again.username, "salt": again.salt_b64, "verifier": again.auth_key_b64},
    )
    assert r.status_code == 409
    assert r.json() == {"detail": "username already taken", "code": "conflict"}


async def test_register_integrity_race_returns_409_contract(monkeypatch, settings):
    """The unique-index race path (pre-check missed, INSERT collided)."""

    class UserResult:
        def scalar_one_or_none(self):
            return None

    class RacingSession:
        bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))

        async def execute(self, stmt):
            return UserResult()

        def add(self, row):
            pass

        async def flush(self):
            raise IntegrityError(
                "INSERT", {}, Exception("UNIQUE constraint failed: users.username")
            )

        async def commit(self):
            raise AssertionError("rollback must precede any retry of commit")

        async def rollback(self):
            pass

    from app.cache import FixedWindowCounter

    request = SimpleNamespace(
        app=SimpleNamespace(
            state=SimpleNamespace(settings=settings, rate_counter=FixedWindowCounter())
        )
    )
    body = auth.RegisterRequest(
        username="race-user",
        salt=base64.b64encode(b"s" * 16).decode(),
        verifier=base64.b64encode(b"v" * 32).decode(),
    )
    with pytest.raises(ApiError) as exc_info:
        await auth.register(body=body, request=request, session=RacingSession())
    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "username already taken"
    assert exc_info.value.code == "conflict"


async def test_login_unknown_user_burns_exact_dummy_inputs(client, monkeypatch):
    """The existence-hiding scrypt burn must hash the same shapes as a real
    login: a 32-byte key over a 16-byte salt, both zero-filled."""
    calls: list[tuple] = []

    async def recorder(key, salt, limiter=None):
        calls.append((bytes(key), bytes(salt)))
        return b"\x00" * 64

    monkeypatch.setattr(auth, "hash_verifier_off_loop", recorder)
    r = await client.post(
        "/api/auth/login",
        json={
            "username": "ghost-user-never-registered",
            "verifier": base64.b64encode(b"z" * 32).decode(),
        },
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "invalid credentials", "code": "invalid_credentials"}
    assert calls == [(b"\x00" * auth.AUTH_KEY_SIZE, b"\x00" * 16)]


async def test_login_known_user_bad_b64_verifier_uses_empty_bytes(client, monkeypatch):
    emu = ClientEmulator("regbadb64", "pw-login-badb64-x")
    await emu.register(client)
    calls: list[tuple] = []

    async def recorder(key, salt, limiter=None):
        calls.append((bytes(key), bytes(salt)))
        return b"\x00" * 64

    monkeypatch.setattr(auth, "hash_verifier_off_loop", recorder)
    r = await client.post(
        "/api/auth/login", json={"username": emu.username, "verifier": "!!not-b64!!"}
    )
    assert r.status_code == 401
    assert r.json() == {"detail": "invalid credentials", "code": "invalid_credentials"}
    # The undecodable verifier collapses to empty bytes before hashing.
    assert calls and calls[0][0] == b""


# ===========================================================================
# app/api/entries.py — unique-violation classifier, dialect branch, details
# ===========================================================================


class _Orig(SimpleNamespace):
    """Duck-typed driver error: pgcode (psycopg) / sqlstate (asyncpg)."""


def test_is_unique_violation_classifier_matrix():
    import app.api.entries as e

    no_orig = IntegrityError("s", {}, Exception("boom"))
    assert e._is_unique_violation(no_orig) is False  # orig is None -> False

    pg = IntegrityError("s", {}, _Orig(pgcode="23505"))
    assert e._is_unique_violation(pg) is True
    ap = IntegrityError("s", {}, _Orig(sqlstate="23505"))
    assert e._is_unique_violation(ap) is True
    both = IntegrityError("s", {}, _Orig(pgcode="23505", sqlstate="23505"))
    assert e._is_unique_violation(both) is True
    other = IntegrityError("s", {}, _Orig(pgcode="23503", sqlstate="23503"))
    assert e._is_unique_violation(other) is False
    sqlite_unique = IntegrityError("s", {}, Exception("UNIQUE constraint failed: entries"))
    assert e._is_unique_violation(sqlite_unique) is True
    sqlite_other = IntegrityError("s", {}, Exception("NOT NULL constraint failed: entries"))
    assert e._is_unique_violation(sqlite_other) is False


def test_blob_length_follows_session_dialect():
    import app.api.entries as e

    pg_session = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))
    lite_session = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")))
    assert e._blob_length(pg_session).name == "octet_length"
    assert e._blob_length(lite_session).name == "length"


async def test_entry_integrity_error_path_returns_409_contract(monkeypatch, settings):
    """The INSERT-then-IntegrityError race path (behind the per-user lock):
    a unique violation must surface as the exact 409 contract."""
    import app.api.entries as e

    class QuotaResult:
        def one(self):
            return (0, 0)

    class PreCheckResult:
        def scalar_one_or_none(self):
            return None

    class RevisionResult:
        # The production path advances the owner marker in the same
        # transaction as the INSERT.  Model a successful DML update so this
        # fixture reaches the intended insert-IntegrityError race path.
        rowcount = 1

    class RacingSession:
        def __init__(self):
            self.executions = 0

        async def get(self, model, user_id, *, populate_existing=False):
            return user

        async def execute(self, stmt):
            self.executions += 1
            if self.executions == 1:
                return QuotaResult()
            if self.executions == 2:
                return PreCheckResult()
            return RevisionResult()

        def add(self, row):
            pass

        async def commit(self):
            raise IntegrityError(
                "INSERT", {}, Exception("UNIQUE constraint failed: entries.client_entry_id")
            )

        async def rollback(self):
            pass

        async def refresh(self, row, *, attribute_names=None):
            pass

    user = User(id="u-race", is_active=True, token_epoch=1)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings)))
    RacingSession.bind = SimpleNamespace(dialect=SimpleNamespace(name="sqlite"))
    body = e.EntryCreate(
        client_entry_id="e-race", blob=base64.b64encode(b"x" * 64).decode(), entry_date=T0
    )
    with pytest.raises(ApiError) as exc_info:
        await e.create_entry(body=body, request=request, user=user, session=RacingSession())
    assert exc_info.value.status_code == 409
    assert exc_info.value.detail == "entry already exists"
    assert exc_info.value.code == "conflict"


async def test_entry_blob_too_small_detail(client):
    emu = ClientEmulator("smolblob", "pw-smol-blob-x")
    await emu.register(client)
    r = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-smol",
            "blob": base64.b64encode(os.urandom(8)).decode(),  # < nonce+tag
            "entry_date": T0.isoformat(),
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "detail": f"blob must be at least {crypto.MIN_BLOB_SIZE} bytes",
        "code": "validation_error",
    }


async def test_entry_before_account_detail(client):
    emu = ClientEmulator("toosoon", "pw-too-soon-x")
    await emu.register(client)
    r = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-early",
            "blob": emu.encrypt_entry("early", T0 - timedelta(days=5), "e-early"),
            "entry_date": (T0 - timedelta(days=5)).isoformat(),
        },
    )
    assert r.status_code == 422
    assert r.json() == {
        "detail": "entry_date is before this account existed",
        "code": "validation_error",
    }


# ===========================================================================
# app/api/insights.py — parse budget/clamp/tolerance, classifiers, contracts
# ===========================================================================


def _payload(text="x", sentiment=None, created_at=None):
    return json.dumps(
        {
            "v": 1,
            "text": text,
            "sentiment": sentiment,
            "created_at": (created_at or T0).isoformat(),
        }
    ).encode()


def _budget_payloads(count, per_entry_chars):
    """count payloads, one per day, each with a matching inner created_at."""
    days = [T0 - timedelta(days=count - 1 - i) for i in range(count)]
    return [bytearray(_payload(text="c" * per_entry_chars, created_at=d)) for d in days], days


def test_parse_entries_per_entry_text_cap():
    parsed = insights._parse_entries([bytearray(_payload(text="a" * 20_001))], [T0])
    assert len(parsed[0].text) == insights.MAX_ANALYSIS_TEXT_CHARS
    # exactly-at-cap text is kept verbatim (timezone-honest entries unaffected)
    parsed = insights._parse_entries([bytearray(_payload(text="b" * 20_000))], [T0])
    assert len(parsed[0].text) == 20_000


def test_parse_entries_total_budget_truncates_oldest_only():
    n = (insights.MAX_ANALYSIS_TOTAL_CHARS // insights.MAX_ANALYSIS_TEXT_CHARS) + 2
    plains, dates = _budget_payloads(n, insights.MAX_ANALYSIS_TEXT_CHARS)
    parsed = insights._parse_entries(plains, dates)
    assert parsed[0].text == "", "oldest entry must be truncated beyond the budget"
    assert parsed[-1].text != "" and parsed[-2].text != ""
    total = sum(len(e.text) for e in parsed)
    assert total <= insights.MAX_ANALYSIS_TOTAL_CHARS


def test_parse_entries_total_exactly_at_budget_truncates_nothing():
    # exactly 2_000_000 chars: nothing is dropped (the `<=` boundary)
    cap = insights.MAX_ANALYSIS_TEXT_CHARS
    n = insights.MAX_ANALYSIS_TOTAL_CHARS // cap  # 100 entries x 20_000
    plains, dates = _budget_payloads(n, cap)
    parsed = insights._parse_entries(plains, dates)
    assert all(e.text == "c" * cap for e in parsed)
    # 101 x cap is 20_000 over: only the oldest is emptied, landing exactly
    # back on the budget
    plains, dates = _budget_payloads(n + 1, cap)
    parsed = insights._parse_entries(plains, dates)
    assert parsed[0].text == ""
    assert parsed[1].text == "c" * cap
    assert sum(len(e.text) for e in parsed) == insights.MAX_ANALYSIS_TOTAL_CHARS


def test_parse_entries_sentiment_clamp_both_ends():
    parsed = insights._parse_entries([bytearray(_payload(sentiment=5.0))], [T0])
    assert parsed[0].sentiment == 1.0
    parsed = insights._parse_entries([bytearray(_payload(sentiment=-5.0))], [T0])
    assert parsed[0].sentiment == -1.0
    parsed = insights._parse_entries([bytearray(_payload(sentiment=0.25))], [T0])
    assert parsed[0].sentiment == 0.25


def test_parse_entries_inner_date_tolerance_edges():
    # one day of skew is honest (timezone) and must parse
    parsed = insights._parse_entries([bytearray(_payload(created_at=T0 - timedelta(days=1)))], [T0])
    assert parsed[0].entry_date == T0
    # two days is not
    with pytest.raises(ValueError, match=r"^created_at does not match entry_date$"):
        insights._parse_entries([bytearray(_payload(created_at=T0 - timedelta(days=2)))], [T0])


def test_parse_entries_type_and_sentiment_error_messages():
    with pytest.raises(ValueError, match=r"^text must be a string$"):
        insights._parse_entries(
            [bytearray(b'{"text": 5, "created_at": "' + T0.isoformat().encode() + b'"}')], [T0]
        )
    with pytest.raises(ValueError, match=r"^sentiment must be a finite number$"):
        insights._parse_entries([bytearray(_payload(sentiment=True))], [T0])


def test_insights_fk_violation_classifier_matrix():
    fk = IntegrityError("s", {}, _Orig(pgcode="23503"))
    assert insights._is_fk_violation(fk) is True
    fk = IntegrityError("s", {}, _Orig(sqlstate="23503"))
    assert insights._is_fk_violation(fk) is True
    other = IntegrityError("s", {}, _Orig(pgcode="23505"))
    assert insights._is_fk_violation(other) is False
    no_orig = IntegrityError("s", {}, Exception("x"))
    assert insights._is_fk_violation(no_orig) is False
    lite = IntegrityError("s", {}, Exception("FOREIGN KEY constraint failed"))
    assert insights._is_fk_violation(lite) is True
    null = IntegrityError("s", {}, Exception("NOT NULL constraint failed"))
    assert insights._is_fk_violation(null) is False


def test_dialect_insert_follows_session():
    from sqlalchemy.dialects import postgresql, sqlite as sqlite_dialect

    pg = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name="postgresql")))
    lite = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name="sqlite")))
    assert insights._dialect_insert(pg) is postgresql.insert
    assert insights._dialect_insert(lite) is sqlite_dialect.insert


def test_decode_b64_rejects_invalid_chars_before_length():
    with pytest.raises(ApiError) as exc_info:
        insights._decode_b64("ab!c", "data_key")
    assert exc_info.value.status_code == 422
    assert exc_info.value.detail == "data_key must be base64"
    assert exc_info.value.code == "validation_error"


async def _insight_user(client, app):
    """31+ clean days: a user whose /insights/recompute reaches the write path."""
    emu = ClientEmulator("pin" + os.urandom(3).hex(), "pw-insight-pin-x")
    await emu.register(client)
    await emu.backdate_account(client, days=45)
    for d in daterange(33, T0):
        await emu.create_entry(client, "an ordinary day with work and sleep", d)
    return emu


async def test_recompute_empty_account_contract(client):
    emu = ClientEmulator("emptypin", "pw-empty-pin-x")
    await emu.register(client)
    r = await client.post("/api/insights/recompute", headers=emu.headers)
    assert r.status_code == 400
    assert r.json() == {"detail": "no entries to analyze", "code": "bad_request"}


async def test_baseline_recompute_reports_zero_lifecycle_counters(client):
    emu = ClientEmulator("baselinepin", "pw-baseline-pin")
    await emu.register(client)
    await emu.backdate_account(client, days=10)
    await emu.create_entry(client, "one ordinary day", T0 - timedelta(days=2))
    r = await client.post("/api/insights/recompute", headers=emu.headers)
    assert r.status_code == 200
    body = r.json()
    assert body["phase"] == "baseline"
    assert body["analyzer"] == "none"
    assert body["patterns_new"] == 0
    assert body["patterns_fading"] == 0


async def test_recompute_token_and_session_contracts(client):
    emu = await _insight_user(client, None)
    r = await client.post("/api/insights/recompute", headers=emu.headers)
    assert r.status_code == 401
    assert r.json() == {
        "detail": "missing processing session token",
        "code": "processing_session_required",
    }

    r = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": "not-a-token"}
    )
    assert r.status_code == 403
    assert r.json() == {
        "detail": "processing session missing or expired",
        "code": "processing_session_invalid",
    }


async def test_recompute_tampered_entry_contract(client, app):
    emu = await _insight_user(client, app)
    async with app.state.sessionmaker() as session:
        from sqlalchemy import select, update

        row = (
            (
                await session.execute(
                    select(Entry)
                    .where(Entry.user_id == emu.user_id)
                    .order_by(Entry.entry_date.asc())
                )
            )
            .scalars()
            .first()
        )
        await session.execute(
            update(Entry)
            .where(Entry.id == row.id)
            .values(blob=bytes(row.blob)[:-1] + bytes([row.blob[-1] ^ 1]))
        )
        await session.commit()

    token = await emu.open_processing_session(client)
    r = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert r.status_code == 400
    assert r.json() == {"detail": "entry blob failed authentication", "code": "entry_blob_invalid"}


async def test_recompute_malformed_payload_contract(client, app):
    emu = await _insight_user(client, app)
    aad = crypto.build_aad("entry", emu.user_id, "e-malformed")
    blob = crypto.encrypt(emu.data_key, b"this is not json at all", aad)
    async with app.state.sessionmaker() as session:
        session.add(
            Entry(
                id=new_id(),
                user_id=emu.user_id,
                client_entry_id="e-malformed",
                blob=blob,
                entry_date=T0 - timedelta(days=1),
            )
        )
        await session.commit()

    token = await emu.open_processing_session(client)
    r = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert r.status_code == 400
    assert r.json() == {"detail": "entry payload malformed", "code": "entry_payload_malformed"}


async def test_recompute_fk_violation_maps_to_410_contract(client, app, monkeypatch):
    emu = await _insight_user(client, app)

    async def fk_bomb(session, user_id, kind, for_date, blob, state_seq=0):
        raise IntegrityError("INSERT", {}, Exception("FOREIGN KEY constraint failed"))

    monkeypatch.setattr(insights, "_replace_insight", fk_bomb)
    token = await emu.open_processing_session(client)
    r = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert r.status_code == 410
    assert r.json() == {"detail": "account no longer exists", "code": "account_deleted"}


async def _tamper_state(app, emu):
    """Flip one byte of the persisted brain-state blob."""
    from sqlalchemy import select, update

    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(Insight).where(Insight.user_id == emu.user_id, Insight.kind == "brain")
                )
            )
            .scalars()
            .first()
        )
        await session.execute(
            update(Insight)
            .where(Insight.id == row.id)
            .values(blob=bytes(row.blob)[:-1] + bytes([row.blob[-1] ^ 1]))
        )
        await session.commit()


async def test_recompute_retry_path_tampered_entry_contract(client, app):
    """Tampered brain state + tampered entry: the amnesia retry must surface
    the ENTRY error (the retry-path 400s, not the primary-path ones)."""
    emu = await _insight_user(client, app)
    await emu.recompute(client)  # persists a brain-state row
    await _tamper_state(app, emu)
    from sqlalchemy import select, update

    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(Entry)
                    .where(Entry.user_id == emu.user_id)
                    .order_by(Entry.entry_date.asc())
                )
            )
            .scalars()
            .first()
        )
        await session.execute(
            update(Entry)
            .where(Entry.id == row.id)
            .values(blob=bytes(row.blob)[:-1] + bytes([row.blob[-1] ^ 1]))
        )
        await session.commit()

    token = await emu.open_processing_session(client)
    r = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert r.status_code == 400
    assert r.json() == {"detail": "entry blob failed authentication", "code": "entry_blob_invalid"}


async def test_recompute_retry_path_malformed_entry_contract(client, app):
    """Tampered brain state + AEAD-valid garbage entry: the amnesia retry
    surfaces the malformed-payload 400 from the retry path."""
    emu = await _insight_user(client, app)
    await emu.recompute(client)
    await _tamper_state(app, emu)
    aad = crypto.build_aad("entry", emu.user_id, "e-retry-malformed")
    blob = crypto.encrypt(emu.data_key, b"still not json", aad)
    async with app.state.sessionmaker() as session:
        session.add(
            Entry(
                id=new_id(),
                user_id=emu.user_id,
                client_entry_id="e-retry-malformed",
                blob=blob,
                entry_date=T0 - timedelta(days=1),
            )
        )
        await session.commit()

    token = await emu.open_processing_session(client)
    r = await client.post(
        "/api/insights/recompute", headers={**emu.headers, "X-Processing-Token": token}
    )
    assert r.status_code == 400
    assert r.json() == {"detail": "entry payload malformed", "code": "entry_payload_malformed"}


async def test_question_retention_window_edges(client, app):
    emu = await _insight_user(client, app)
    today = date.today()
    async with app.state.sessionmaker() as session:
        # 91 days old: outside retention (deleted); 90 days old: kept
        session.add(
            Insight(
                id=new_id(),
                user_id=emu.user_id,
                kind="question",
                for_date=today - timedelta(days=91),
                blob=b"old",
            )
        )
        session.add(
            Insight(
                id=new_id(),
                user_id=emu.user_id,
                kind="question",
                for_date=today - timedelta(days=90),
                blob=b"edge",
            )
        )
        await session.commit()

    await emu.recompute(client)

    from sqlalchemy import select

    async with app.state.sessionmaker() as session:
        remaining = {
            row.for_date
            for row in (
                await session.execute(
                    select(Insight).where(
                        Insight.user_id == emu.user_id, Insight.kind == "question"
                    )
                )
            ).scalars()
        }
    assert today - timedelta(days=91) not in remaining, "91-day-old question must be purged"
    assert today - timedelta(days=90) in remaining, "90-day-old question must be retained"


async def test_question_not_found_contract(client):
    emu = ClientEmulator("noqpin", "pw-no-question-x")
    await emu.register(client)
    r = await client.get("/api/questions/today", headers=emu.headers)
    assert r.status_code == 404
    body = r.json()
    assert body["code"] == "not_found"
    assert body["detail"] == (
        "no question for today; open a processing session and run /insights/recompute"
    )


async def test_recompute_runs_on_the_wired_analyze_limiter(client, app):
    """If the recompute path stops borrowing the wired limiter (detached or
    renamed), analysis silently floods the shared thread pool — the exact
    resource-exhaustion the limiter exists to prevent."""
    import anyio

    emu = await _insight_user(client, app)
    real_limiter = app.state.analyze_limiter
    gate = anyio.CapacityLimiter(1)
    await gate.acquire()  # the test task holds the only slot

    app.state.analyze_limiter = gate
    try:
        # Correctly wired: analysis blocks on the exhausted gate -> the
        # wait_for cancellation (or the 500 it produces) raises. Detached
        # (mutant): the default pool runs it and recompute SUCCEEDS, so no
        # exception fires and this raises a failure.
        with pytest.raises((asyncio.TimeoutError, AssertionError)):
            await asyncio.wait_for(emu.recompute(client), timeout=10.0)
    finally:
        app.state.analyze_limiter = real_limiter
        gate.release()


# ===========================================================================
# app/schemas.py — DoS ceilings as observable 422 boundaries
# ===========================================================================


async def test_request_size_ceilings_are_enforced_at_the_edge(client):
    emu = ClientEmulator("ceilings", "pw-ceilings-x")
    await emu.register(client)
    # salt: 129 chars is one over the ceiling and must fail SCHEMA validation
    r = await client.post(
        "/api/auth/register",
        json={
            "username": "ceilings2",
            "salt": "A" * (MAX_SALT_B64 + 1),
            "verifier": emu.auth_key_b64,
        },
    )
    assert r.status_code == 422
    assert "String should have at most 128 characters" in r.json()["detail"]
    # data_key: 45 chars (one over 44)
    r = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": "A" * (MAX_DATA_KEY_B64 + 1)},
    )
    assert r.status_code == 422
    assert "String should have at most 44 characters" in r.json()["detail"]
    # blob: 1_500_001 chars (one over)
    r = await client.post(
        "/api/entries",
        headers=emu.headers,
        json={
            "client_entry_id": "e-huge",
            "blob": "A" * (MAX_BLOB_B64 + 1),
            "entry_date": T0.isoformat(),
        },
    )
    assert r.status_code == 422
    assert "String should have at most 1500000 characters" in r.json()["detail"]
    # at exactly the ceilings the schema passes and validation moves downstream
    r = await client.post(
        "/api/processing/sessions", headers=emu.headers, json={"data_key": "A" * MAX_DATA_KEY_B64}
    )
    assert r.status_code == 422 and r.json()["detail"] == "data_key must be 32 bytes"


async def test_processing_session_length_contract(client):
    emu = ClientEmulator("dkeylen", "pw-d-key-len-x")
    await emu.register(client)
    r = await client.post(
        "/api/processing/sessions",
        headers=emu.headers,
        json={"data_key": base64.b64encode(b"k" * 33).decode()},
    )
    assert r.status_code == 422
    assert r.json() == {
        "detail": f"data_key must be {crypto.KEY_SIZE} bytes",
        "code": "validation_error",
    }


async def test_processing_session_requires_data_key(client):
    emu = ClientEmulator("dkeyreq", "pw-d-key-req-x")
    await emu.register(client)
    r = await client.post("/api/processing/sessions", headers=emu.headers, json={})
    assert r.status_code == 422
    assert "Field required" in r.json()["detail"]


# ===========================================================================
# app/deps.py — rollback recovery keeps a usable user
# ===========================================================================


async def test_require_user_commit_failure_recovers_user(monkeypatch):
    user = User(id="u-flaky", is_active=True, token_epoch=1)

    class FlakySession:
        def __init__(self):
            self._gets = [user, None]  # the re-fetch after rollback misses

        async def get(self, model, pk):
            return self._gets.pop(0)

        async def commit(self):
            raise RuntimeError("pool hiccup")

        async def rollback(self):
            pass

    secret = "flaky-session-secret"
    token = tokens.issue_token(user.id, secret, 60, epoch=1)
    request = SimpleNamespace(
        app=SimpleNamespace(state=SimpleNamespace(settings=SimpleNamespace(token_secret=secret)))
    )
    result = await require_user(request, f"Bearer {token}", FlakySession())
    assert result is user, "a failed commit must keep the authenticated user usable"


# ===========================================================================
# app/main.py — envelope fallbacks, limits, validation detail, ops endpoints
# ===========================================================================


def test_main_logger_channel_name():
    assert main_logger.name == "mindpattern"


def test_error_envelope_detail_is_always_a_string():
    assert _error_envelope(400, ["not", "a", "string"]) == {
        "detail": "request failed",
        "code": "bad_request",
    }
    assert _error_envelope(400, "") == {"detail": "request failed", "code": "bad_request"}
    assert _error_envelope(400, "real problem") == {"detail": "real problem", "code": "bad_request"}


def test_error_envelope_unknown_status_default_code():
    assert _error_envelope(599, "boom", None) == {"detail": "boom", "code": "error"}
    assert _error_envelope(429, "slow down") == {"detail": "slow down", "code": "rate_limited"}


async def test_app_wires_the_documented_concurrency_limiters(app):
    import anyio

    assert isinstance(app.state.analyze_limiter, anyio.CapacityLimiter)
    assert app.state.analyze_limiter.total_tokens == 4
    assert isinstance(app.state.auth_limiter, anyio.CapacityLimiter)
    assert app.state.auth_limiter.total_tokens == 4


async def test_validation_detail_shape(client, app, monkeypatch):
    from app.deps import require_user

    async def explode():
        raise RequestValidationError(
            [
                {"loc": ("body", "entries", 0), "msg": "not a valid entry", "type": "weird"},
                {"loc": ("body", "salt"), "msg": "too short", "type": "string_too_short"},
            ]
        )

    app.dependency_overrides[require_user] = explode
    try:
        r = await client.get("/api/entries")
    finally:
        app.dependency_overrides.clear()
    assert r.status_code == 422
    assert r.json()["detail"] == ("entries.0: not a valid entry; salt: too short")
    assert r.json()["code"] == "validation_error"


async def test_validation_detail_defaults_and_truncation(client, app, monkeypatch):
    from app.deps import require_user

    async def no_msg():
        raise RequestValidationError([{"loc": (), "type": "weird"}])

    async def many():
        raise RequestValidationError(
            [{"loc": ("body", f"f{i}"), "msg": "m" * 30, "type": "x"} for i in range(40)]
        )

    async def none_at_all():
        raise RequestValidationError([])

    async def override(fn):
        app.dependency_overrides[require_user] = fn
        try:
            return await client.get("/api/entries")
        finally:
            app.dependency_overrides.clear()

    r = await override(no_msg)
    assert r.json()["detail"] == "invalid value"
    r = await override(many)
    assert len(r.json()["detail"]) == 500, "validation detail must cap at 500 chars"
    r = await override(none_at_all)
    assert r.json()["detail"] == "request validation failed"


async def test_readyz_contract_and_openapi_tags(client, app):
    r = await client.get("/readyz")
    assert r.status_code == 200
    assert set(r.json()) == {"status", "version"}
    from app.main import APP_VERSION

    assert r.json()["version"] == APP_VERSION
    assert app.openapi()["paths"]["/readyz"]["get"]["tags"] == ["ops"]


async def test_readyz_reports_database_unavailable(client, app, caplog):
    import contextlib

    @contextlib.asynccontextmanager
    async def broken_sessionmaker():
        class Broken:
            async def execute(self, *a, **k):
                raise RuntimeError("connection refused")

        yield Broken()

    real = app.state.sessionmaker
    app.state.sessionmaker = broken_sessionmaker
    try:
        with caplog.at_level(logging.ERROR, logger="mindpattern"):
            r = await client.get("/readyz")
    finally:
        app.state.sessionmaker = real
    assert r.status_code == 503
    assert r.json() == {"detail": "database unavailable", "code": "service_unavailable"}
    assert any(
        r.getMessage() == "readiness check failed: database or schema unavailable"
        for r in caplog.records
    )


# ===========================================================================
# app/middleware.py — exact envelope bodies on every hardening path
# ===========================================================================


_OVERSIZE = b'{"detail": "request body too large", "code": "payload_too_large"}'
_NESTED = b'{"detail": "request body too deeply nested", "code": "bad_request"}'
_BAD_LENGTH = b'{"detail": "invalid content-length", "code": "bad_request"}'
_INTERNAL = b'{"detail": "internal server error", "code": "internal_error"}'


async def _run_middleware(handler, headers=(), bodies=(b"",), max_body=16):
    sent = []

    async def receive():
        return {"type": "http.request", "body": bodies[0]}

    async def send(message):
        sent.append(message)

    mw = HardeningMiddleware(handler, max_body_bytes=max_body)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/",
        "headers": [(b"content-length", str(len(bodies[0])).encode()), *headers],
    }
    await mw(scope, receive, send)
    return sent


async def _body_of(sent):
    return b"".join(m.get("body", b"") for m in sent)


async def test_middleware_500_body_is_the_exact_envelope():
    async def boom(scope, receive, send):
        raise RuntimeError("unhandled")

    sent = await _run_middleware(boom)
    assert sent[0]["status"] == 500
    assert await _body_of(sent) == _INTERNAL


async def test_middleware_recursion_body_is_the_exact_envelope():
    async def nested(scope, receive, send):
        raise RecursionError("too deep")

    sent = await _run_middleware(nested)
    assert sent[0]["status"] == 400
    assert await _body_of(sent) == _NESTED


async def test_middleware_bad_content_length_body():
    async def unreachable(scope, receive, send):  # pragma: no cover
        raise AssertionError("must not reach the app")

    async def receive():
        return {"type": "http.request", "body": b""}

    sent = []

    async def send(m):
        sent.append(m)

    await HardeningMiddleware(unreachable, max_body_bytes=16)(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"content-length", b"not-a-number")],
        },
        receive,
        send,
    )
    assert sent[0]["status"] == 400
    assert await _body_of(sent) == _BAD_LENGTH


async def test_middleware_oversize_content_length_body():
    async def unreachable(scope, receive, send):  # pragma: no cover
        raise AssertionError("must not reach the app")

    async def receive():
        return {"type": "http.request", "body": b""}

    sent = []

    async def send(m):
        sent.append(m)

    await HardeningMiddleware(unreachable, max_body_bytes=16)(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [(b"content-length", b"999999")],
        },
        receive,
        send,
    )
    assert sent[0]["status"] == 413
    assert await _body_of(sent) == _OVERSIZE


async def test_middleware_streamed_overflow_is_413():
    async def reader(scope, receive, send):
        while True:
            message = await receive()
            if message["type"] != "http.request":
                break

    sent = await _run_middleware(reader, bodies=(b"x" * 32,), max_body=16)
    assert sent[0]["status"] == 413
    assert await _body_of(sent) == _OVERSIZE


async def test_middleware_xff_warns_once_with_exact_message(caplog):
    async def ok(scope, receive, send):
        send_ok = {"type": "http.response.start", "status": 200, "headers": []}
        await send(send_ok)
        await send({"type": "http.response.body", "body": b""})

    async def send(m):
        pass

    async def receive():
        return {"type": "http.request", "body": b""}

    mw = HardeningMiddleware(ok, max_body_bytes=16)
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-forwarded-for", b"1.2.3.4")],
    }
    with caplog.at_level(logging.WARNING, logger="mindpattern"):
        await mw(scope, receive, send)
        await mw(scope, receive, send)
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].getMessage() == (
        "X-Forwarded-For ignored: MINDPATTERN_TRUST_PROXY_HEADERS is off "
        "or the direct peer is outside MINDPATTERN_TRUSTED_PROXY_IPS; "
        "rate limiting keys on the direct peer"
    )


# ===========================================================================
# app/cache.py — window arithmetic and eviction batching
# ===========================================================================


def test_eviction_batch_is_a_tenth_of_the_cap():
    assert EVICTION_BATCH == MAX_TRACKED_KEYS // 10 == 1_000


def test_counter_window_must_be_positive():
    counter = FixedWindowCounter()
    with pytest.raises(ValueError, match=r"^window_seconds must be positive$"):
        counter.hit("k", 0, now=1.0)
    with pytest.raises(ValueError, match=r"^window_seconds must be positive$"):
        counter.check("k", 0, now=1.0)
    # window of exactly 1 second is legal
    assert counter.hit("k2", 1, now=1.0).count == 1


def test_counter_window_reset_and_retry_after_math():
    counter = FixedWindowCounter()
    first = counter.hit("k", 60, now=100.0)
    assert (first.count, first.retry_after) == (1, 61)
    # one second before expiry: still inside the window
    inside = counter.hit("k", 60, now=159.0)
    assert inside.count == 2
    assert inside.retry_after == 2
    # exactly at the boundary the window resets: count is 1, not 3
    reset = counter.hit("k", 60, now=160.0)
    assert reset.count == 1
    assert reset.retry_after == 61
    # check() mirrors the same boundary without counting
    assert counter.check("k", 60, now=220.0).count == 0


def test_counter_check_does_not_count():
    counter = FixedWindowCounter()
    counter.hit("k", 60, now=100.0)
    assert counter.check("k", 60, now=101.0).count == 1
    assert counter.check("k", 60, now=102.0).count == 1  # unchanged
    # a 1-second window is legal for check() too
    assert counter.check("k1s", 1, now=1.0).count == 0


def test_counter_check_retry_after_math():
    counter = FixedWindowCounter()
    counter.hit("k", 60, now=100.0)
    assert counter.check("k", 60, now=101.0).retry_after == 60
    assert counter.check("k", 60, now=159.5).retry_after == 1
    assert counter.check("k", 60, now=159.0).retry_after == 2


def test_counter_eviction_overflow_edges():
    counter = FixedWindowCounter()
    # exactly at (cap - batch): no eviction may fire (overflow == 0)
    for i in range(MAX_TRACKED_KEYS - EVICTION_BATCH):
        counter.hit(f"fill-{i}", 3600, now=1000.0 + i)
    assert len(counter._hits) == MAX_TRACKED_KEYS - EVICTION_BATCH
    # crossing the cap evicts down past the cap (batch headroom), never above it
    counter.hit("over-1", 3600, now=9_000.0)
    assert len(counter._hits) <= MAX_TRACKED_KEYS


# ===========================================================================
# app/locks.py — lock-table growth bound
# ===========================================================================


def test_user_locks_default_cap_is_ten_thousand():
    default = inspect.signature(UserLocks.__init__).parameters["max_keys"].default
    assert default == 10_000


async def test_user_locks_evict_down_to_cap():
    # Sequential acquires clean up mid-sequence, so the eviction batch only
    # matters after CONCURRENT holders pile up idle entries at once.
    locks = UserLocks(max_keys=2)
    gate = asyncio.Event()

    async def hold_until_released(key):
        async with locks.hold(key):
            await gate.wait()

    tasks = [asyncio.create_task(hold_until_released(k)) for k in ("a", "b", "c")]
    for _ in range(200):  # two dedicated holders + one shared overflow holder
        if len(locks._locks) == 2 and locks._overflow_refs == 1:
            break
        await asyncio.sleep(0.01)
    assert len(locks._locks) == 2
    assert locks._overflow_refs == 1
    gate.set()
    await asyncio.gather(*tasks)

    async with locks.hold("e"):  # four idle entries at the crossing
        assert len(locks._locks) == 2, "eviction must clear down to the cap"
    assert len(locks._locks) == 2


# ===========================================================================
# app/config.py — fail-closed defaults and validation boundaries
# ===========================================================================


def _prod_settings(**overrides) -> Settings:
    base = dict(
        environment="staging", token_secret="x" * 40, database_url="postgresql+asyncpg://u:p@h/db"
    )
    base.update(overrides)
    return Settings(**base)


def _dev_settings(**overrides) -> Settings:
    base = dict(
        environment="development", token_secret="x" * 40, database_url="sqlite+aiosqlite://"
    )
    base.update(overrides)
    return Settings(**base)


def test_settings_default_environment_is_production(monkeypatch):
    monkeypatch.delenv("MINDPATTERN_ENV", raising=False)
    monkeypatch.setenv("MINDPATTERN_DB_URL", "postgresql+asyncpg://u:p@h/db")
    monkeypatch.setenv("MINDPATTERN_TOKEN_SECRET", "s" * 40)
    assert Settings.from_env().environment == "production"
    assert Settings.__dataclass_fields__["environment"].default == "production"


def test_settings_secret_length_message():
    # the 32-char floor applies to every non-development environment
    with pytest.raises(RuntimeError) as exc_info:
        _prod_settings(token_secret="short")
    assert str(exc_info.value) == (
        "MINDPATTERN_TOKEN_SECRET must be at least 32 characters in environment 'staging'"
    )


def test_settings_lower_bound_messages():
    with pytest.raises(RuntimeError, match=r"^db_pool_size must be >= 1$"):
        _dev_settings(db_pool_size=0)
    with pytest.raises(RuntimeError, match=r"^db_max_overflow must be >= 0$"):
        _dev_settings(db_max_overflow=-1)


def test_settings_upper_bound_messages():
    with pytest.raises(
        RuntimeError, match=rf"^token_ttl_seconds must be <= {MAX_TOKEN_TTL_SECONDS}$"
    ):
        _dev_settings(token_ttl_seconds=MAX_TOKEN_TTL_SECONDS + 1)
    with pytest.raises(
        RuntimeError, match=rf"^processing_session_ttl must be <= {MAX_PROCESSING_SESSION_TTL}$"
    ):
        _dev_settings(processing_session_ttl=MAX_PROCESSING_SESSION_TTL + 1)
    with pytest.raises(
        RuntimeError, match=rf"^auth_rate_window must be <= {MAX_RATE_WINDOW_SECONDS}$"
    ):
        _dev_settings(auth_rate_window=MAX_RATE_WINDOW_SECONDS + 1)
    with pytest.raises(RuntimeError, match=rf"^auth_rate_limit must be <= {MAX_RATE_LIMIT}$"):
        _dev_settings(auth_rate_limit=MAX_RATE_LIMIT + 1)


def test_settings_1024_floors_are_inclusive():
    assert _dev_settings(max_body_bytes=1024).max_body_bytes == 1024
    assert _dev_settings(max_user_blob_bytes=1024).max_user_blob_bytes == 1024
    with pytest.raises(RuntimeError, match=r"^max_body_bytes must be >= 1024$"):
        _dev_settings(max_body_bytes=1023)
    with pytest.raises(RuntimeError, match=r"^max_user_blob_bytes must be >= 1024$"):
        _dev_settings(max_user_blob_bytes=1023)


def test_config_logger_channel_name():
    from app.config import logger as config_logger

    assert config_logger.name == "mindpattern"


def test_settings_llm_transport_gates(caplog):
    with pytest.raises(RuntimeError) as exc_info:
        _dev_settings(llm_url="http://llm.example.com/v1")
    assert str(exc_info.value) == (
        "MINDPATTERN_LLM_URL must use https:// — decrypted journal "
        "plaintext is POSTed to it. Plain http:// is only accepted "
        "for exact loopback hosts with "
        "MINDPATTERN_ENV=development exactly."
    )
    import logging as _logging

    with caplog.at_level(_logging.WARNING, logger="mindpattern"):
        _dev_settings(llm_url="https://llm.example.com/v1", llm_api_key="")
    assert any(
        "MINDPATTERN_LLM_URL is set but MINDPATTERN_LLM_API_KEY is "
        "empty — LLM requests will go out without an API key" in r.getMessage()
        for r in caplog.records
    )
    # dev loopback http stays legal
    assert _dev_settings(llm_url="http://127.0.0.1:8080/v1", llm_api_key="k").llm_url.startswith(
        "http://127.0.0.1"
    )


# ===========================================================================
# app/security/* — canonical forms, boundaries, zeroization, error text
# ===========================================================================


def test_b64url_canonical_forms():
    # encode: canonical unpadded wire form
    assert tokens._b64url_encode(b"\x00") == "AA"
    assert tokens._b64url_encode(b"\x00\x00") == "AAA"
    assert "=" not in tokens._b64url_encode(b"\xfb\xef\xbe")
    # an output ending in 'X': only a padding-only strip keeps it intact
    assert tokens._b64url_encode(b"\x00\x00\x17") == "AAAX"
    # decode: every length class round-trips (incl. len % 4 == 3)
    for raw in (b"\x00", b"\x00\x00", b"\x00\x00\x00", b"\x00" * 5):
        assert tokens._b64url_decode(tokens._b64url_encode(raw)) == raw


def test_verify_token_malformed_payload_message():
    body = tokens._b64url_encode(
        json.dumps(
            {"uid": "u", "iat": 1, "exp": "soon", "ep": 1}, separators=(",", ":"), sort_keys=True
        ).encode()
    )
    sig = tokens._b64url_encode(hmac_mod.new(b"secret", body.encode(), hashlib.sha256).digest())
    with pytest.raises(tokens.TokenError, match=r"^malformed payload$"):
        tokens.verify_token(f"{body}.{sig}", "secret", now=2)


def test_encrypt_nonce_size_message():
    key = os.urandom(crypto.KEY_SIZE)
    with pytest.raises(
        crypto.CryptoError, match=rf"^nonce must be {crypto.NONCE_SIZE} bytes, got 5$"
    ):
        crypto.encrypt_with_nonce(key, b"payload", None, b"12345")


async def test_keystore_expiry_boundary_zeroizes_and_messages(monkeypatch):
    store = enclave.InMemoryKeyStore()
    key = bytes(range(32))
    token = store.create(key, ttl_seconds=10, now=100.0, owner="u1")

    zeroized: list = []
    real_zeroize = enclave.zeroize
    monkeypatch.setattr(enclave, "zeroize", lambda k: zeroized.append(k) or real_zeroize(k))

    with pytest.raises(enclave.KeyNotFound, match=r"^processing session expired$"):
        store.pop(token, now=110.0, owner="u1")  # exactly at expiry
    assert zeroized and isinstance(zeroized[0], bytearray)
    assert any(v != 0 for v in zeroized[0]) is False, "expired key must be wiped"

    with pytest.raises(enclave.KeyNotFound, match=r"^unknown processing session$"):
        store.pop("no-such-token", now=100.0)

    token2 = store.create(key, ttl_seconds=10, now=100.0, owner="u1")
    with pytest.raises(enclave.KeyNotFound, match=r"^processing session belongs to another user$"):
        store.pop(token2, now=105.0, owner="someone-else")


# ===========================================================================
# api/meta + envelopes through real HTTP (defaults path)
# ===========================================================================


async def test_unknown_route_uses_default_error_code(client):
    r = await client.get("/api/definitely-not-a-route")
    assert r.status_code == 404
    assert r.json() == {"detail": "Not Found", "code": "not_found"}
