"""Analysis-generation (state_seq) rollback-visibility pins (2026-09-19).

The audit finding: the brain-state/patterns blob's AAD is constant per
account, so GCM proves context but not VERSION — a compromised server could
replay an earlier, cryptographically valid state and the recompute path
accepted it silently (live PoC: rewound state, recompute 200). The server
cannot defend its own storage, but it now makes every rollback
CLIENT-DETECTABLE: each recompute stamps a monotonic ``state_seq`` (row
column + plaintext echo + value embedded inside the encrypted patterns
payload), and a client that pins its high-water mark catches any replay.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import date, timedelta

os.environ.setdefault("MINDPATTERN_ENV", "development")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import select, update  # noqa: E402

from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Insight, User, utcnow  # noqa: E402
from app.security import crypto  # noqa: E402
from tests.helpers import ClientEmulator, daterange  # noqa: E402


@pytest.fixture()
def settings() -> Settings:
    s = Settings(environment="development")
    s.database_url = "sqlite+aiosqlite://"
    s.token_secret = "state-seq-test-secret"
    s.entries_rate_limit = 1000
    s.read_rate_limit = 10_000
    s.processing_rate_limit = 1_000
    return s


@pytest_asyncio.fixture()
async def app(settings):
    application = create_app(settings)
    async with application.router.lifespan_context(application):
        yield application


@pytest_asyncio.fixture()
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as c:
        yield c


async def _mature_recompute_user(client: AsyncClient, app, name: str) -> ClientEmulator:
    """A past-threshold account with one recompute already stored."""
    user = ClientEmulator(name, f"pw-{name}")
    await user.register(client)
    await user.backdate_account(client, 40)
    today = date.today()
    for dt in daterange(35, today):
        await user.create_entry(client, f"{name} entry {dt}", dt)
    await user.recompute(client)
    return user


def _decrypt_patterns(user: ClientEmulator, blob_b64: str) -> dict:
    blob = base64.b64decode(blob_b64)
    plain = crypto.decrypt(user.data_key, blob, crypto.build_aad("insights", user.user_id, "patterns"))
    return json.loads(plain.decode("utf-8"))


async def test_state_seq_monotonic_and_echoed(client, app):
    user = await _mature_recompute_user(client, app, "seqmon")
    first = await client.post(
        "/api/insights/recompute",
        headers={
            **user.headers,
            "X-Processing-Token": await user.open_processing_session(client),
        },
    )
    assert first.status_code == 200
    seq2 = first.json()["state_seq"]
    assert seq2 == 2, "second recompute is generation 2"

    got = await client.get("/api/insights", headers=user.headers)
    body = got.json()
    assert body["state_seq"] == seq2, "GET /insights echoes the stored generation"
    payload = _decrypt_patterns(user, body["blob"])
    assert payload["state_seq"] == seq2, (
        "the encrypted payload's embedded generation equals the plaintext echo"
    )


async def test_rollback_blob_without_column_is_detectable(client, app):
    """The audit's attack, replayed against the fixed contract: swap in an
    OLDER valid-GCM blob while leaving the column — the echo and the payload
    now DISAGREE, which is exactly the client-side rollback signal."""
    user = await _mature_recompute_user(client, app, "seqroll")

    # Generation 1's blob, captured before generation 2 overwrites it.
    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(Insight).where(
                        Insight.user_id == user.user_id, Insight.kind == "patterns"
                    )
                )
            )
            .scalars()
            .one()
        )
        gen1_blob = bytes(row.blob)
        assert row.state_seq == 1

    await user.recompute(client)  # generation 2

    # Compromised-server replay: restore the generation-1 blob, leave the
    # column at 2 (the most favorable case for the attacker — echoing a
    # matching old column is caught by the client's high-water pin).
    async with app.state.sessionmaker() as session:
        await session.execute(
            update(Insight)
            .where(Insight.user_id == user.user_id, Insight.kind == "patterns")
            .values(blob=gen1_blob)
        )
        await session.commit()

    got = await client.get("/api/insights", headers=user.headers)
    body = got.json()
    assert body["state_seq"] == 2, "the column still says generation 2"
    payload = _decrypt_patterns(user, body["blob"])
    assert payload["state_seq"] == 1, "the replayed blob embeds generation 1"
    # THE SIGNAL: echo (2) != payload (1). Pre-fix this rollback was
    # completely silent; now any client doing the documented cross-check
    # detects it, and a pinned high-water mark >= 2 catches column rollback.


async def test_rollback_column_and_blob_caught_by_high_water(client, app):
    """Full both-copies rollback: the echo and payload agree (at 1), but the
    value moved BACKWARDS from the client's previously observed 2 — the
    high-water half of the contract."""
    user = await _mature_recompute_user(client, app, "seqboth")
    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(Insight).where(
                        Insight.user_id == user.user_id, Insight.kind == "patterns"
                    )
                )
            )
            .scalars()
            .one()
        )
        gen1_blob = bytes(row.blob)
    observed_max = (await user.recompute(client))["state_seq"]
    assert observed_max == 2

    async with app.state.sessionmaker() as session:
        await session.execute(
            update(Insight)
            .where(Insight.user_id == user.user_id, Insight.kind == "patterns")
            .values(blob=gen1_blob, state_seq=1)
        )
        await session.commit()

    body = (await client.get("/api/insights", headers=user.headers)).json()
    assert body["state_seq"] == 1 < observed_max, (
        "a both-copies rollback is caught by the client's pinned high-water mark"
    )


async def test_baseline_recompute_carries_generation_zero(client, app):
    """Pre-threshold recomputes store nothing: the response's generation is
    the documented 0, and GET /insights agrees."""
    user = ClientEmulator("seqbase", "pw-seqbase")
    await user.register(client)
    await user.create_entry(client, "one entry only", date.today())
    response = await client.post(
        "/api/insights/recompute",
        headers={
            **user.headers,
            "X-Processing-Token": await user.open_processing_session(client),
        },
    )
    assert response.status_code == 200
    assert response.json()["state_seq"] == 0
    body = (await client.get("/api/insights", headers=user.headers)).json()
    assert body["blob"] is None
    assert body["state_seq"] == 0
