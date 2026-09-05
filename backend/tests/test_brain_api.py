"""The v2 mini-brain at the API level: memory across recomputes.

The product claim under test: the brain STORES patterns and UPDATES them
based on input. That means a recompute is not a stateless batch job —
the encrypted "brain" insight row carries pattern memory forward, and
the surfaced patterns reflect lifecycle, not just today's corpus.
"""

from __future__ import annotations

import json
from datetime import date, timedelta

import pytest

from app.security import crypto
from tests.helpers import ClientEmulator, daterange

TODAY = date.today()
WORK_ANXIOUS = ("Deadline at work monday, the boss piled on another project and a "
                "late meeting. Anxious, stressed, dreading the presentation.")
CALM = "Long walk by the river, felt calm and grateful. Cooked, ate well, slept deeply."


async def seed(client, emu, days: int) -> None:
    await emu.backdate_account(client, days=days + 2)
    for day in daterange(days, TODAY):
        text = WORK_ANXIOUS if day.weekday() == 6 else CALM
        await emu.create_entry(client, text, day, client_entry_id=f"e-{day.isoformat()}")


async def decrypt_brain_state(client, emu) -> dict:
    """Fetch + decrypt the latest kind="brain" insight row directly."""
    from sqlalchemy import select

    from app.models import Insight

    app = client._transport.app  # noqa: SLF001 — test reachability into state
    async with app.state.sessionmaker() as session:
        row = (
            (
                await session.execute(
                    select(Insight)
                    .where(Insight.user_id == emu.user_id, Insight.kind == "brain")
                    .order_by(Insight.created_at.desc(), Insight.id.desc())
                    .limit(1)
                )
            )
            .scalars()
            .first()
        )
    assert row is not None, "recompute must persist the encrypted brain state"
    plain = crypto.decrypt(emu.data_key, bytes(row.blob),
                            crypto.build_aad("insights", emu.user_id, "brain"))
    return json.loads(plain.decode("utf-8"))


async def test_brain_state_row_exists_and_is_encrypted(client):
    emu = ClientEmulator("brainstate", "pw-brain")
    await emu.register(client)
    await seed(client, emu, days=70)

    await emu.recompute(client)
    state = await decrypt_brain_state(client, emu)
    assert state["v"] == 2
    assert state["patterns"], "the store must hold the qualified patterns"
    temporal = state["patterns"]["temporal:work"]
    assert temporal["state"] == "emerging"  # 10 occurrences ≥ STRONG_EVIDENCE
    assert temporal["first_qualified"] == TODAY.isoformat()
    # The blob is real ciphertext, not plaintext JSON in the DB.
    from sqlalchemy import select

    from app.models import Insight

    app = client._transport.app  # noqa: SLF001 — test reachability into state
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
    assert b"temporal" not in bytes(row.blob)


async def test_memory_carries_forward_between_recomputes(client):
    emu = ClientEmulator("carryfwd", "pw-carry")
    await emu.register(client)
    await seed(client, emu, days=70)

    first = await emu.recompute(client)
    assert first["analyzer"] == "brain"
    assert first["patterns_new"] >= 1

    # A fresh entry + a second recompute: the brain folds it in; patterns
    # persist (qualification history grows rather than resetting).
    await emu.create_entry(client, CALM, TODAY, client_entry_id="fresh-1")
    second = await emu.recompute(client)
    assert second["patterns_stored"] >= first["patterns_stored"] - 1  # stable corpus
    state = await decrypt_brain_state(client, emu)
    temporal = state["patterns"]["temporal:work"]
    assert len(temporal["qualification_days"]) == 1  # same calendar day: no double count
    assert state["history"][-1][0] == TODAY.isoformat()


async def test_corrupt_brain_state_degrades_to_amnesia(client):
    emu = ClientEmulator("amnesia", "pw-amnesia")
    await emu.register(client)
    await seed(client, emu, days=70)
    await emu.recompute(client)

    # Replace the stored brain state with VALID ciphertext of garbage JSON.
    from sqlalchemy import select

    from app.models import Insight

    app = client._transport.app  # noqa: SLF001 — test reachability into state
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
        row.blob = crypto.encrypt(
            emu.data_key, b"{definitely not json",
            crypto.build_aad("insights", emu.user_id, "brain"),
        )
        await session.commit()

    body = await emu.recompute(client)  # must not 500: fresh brain, rebuilt
    assert body["analyzer"] == "brain"
    state = await decrypt_brain_state(client, emu)
    assert state["patterns"]


async def test_tampered_brain_state_retries_without_it(client):
    emu = ClientEmulator("tamperstate", "pw-tamper")
    await emu.register(client)
    await seed(client, emu, days=70)
    await emu.recompute(client)

    from sqlalchemy import select

    from app.models import Insight

    app = client._transport.app  # noqa: SLF001 — test reachability into state
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
        corrupted = bytearray(bytes(row.blob))
        corrupted[-1] ^= 1
        row.blob = bytes(corrupted)
        await session.commit()

    body = await emu.recompute(client)  # GCM fails → retry with amnesia
    assert body["analyzer"] == "brain"
    assert body["patterns_stored"] >= 1
    # Regression: the retry must analyze the FULL corpus — an early version
    # closed over the (truthy) state flag and silently treated the newest
    # ENTRY as the brain state, analyzing one entry too few.
    insights = await emu.decrypt_insights(client)
    assert insights["stats"]["total_entries"] == 70


async def test_llm_enrichment_merges_into_surfaced_patterns(client, settings, monkeypatch):
    from app.services.llm import LLMAnalyzer

    settings.llm_url = "https://llm.example/v1"
    settings.llm_api_key = "k"
    posted = []

    def fake_post(self, payload):
        posted.append(payload)
        model_output = {
            "patterns": [
                # A valid phrase the user actually wrote (corpus-anchored).
                {"kind": "recurring_phrase", "label": "slept deeply",
                 "occurrences": 5, "confidence": 0.9, "detail": {}},
                # Model fiction: a phrase nowhere in the corpus — must drop.
                {"kind": "recurring_phrase", "label": "never wrote this at all",
                 "occurrences": 5, "confidence": 0.9, "detail": {}},
            ]
        }
        return {"choices": [{"message": {"content": json.dumps(model_output)}}]}

    monkeypatch.setattr(LLMAnalyzer, "_post", fake_post)

    emu = ClientEmulator("llmenrich", "pw-llm")
    await emu.register(client)
    await emu.backdate_account(client, days=72)
    # Explicit, re-authenticated consent — the LLM path is opt-in.
    await client.put("/api/account/llm-consent", headers=emu.headers,
                     json={"enabled": True, "verifier": emu.auth_key_b64})

    await seed(client, emu, days=70)
    body = await emu.recompute(client)
    assert body["analyzer"] == "llm"
    assert posted, "the consented LLM path must actually run"

    insights = await emu.decrypt_insights(client)
    labels = [p["label"] for p in insights["stats"]["patterns"]]
    assert "slept deeply" in labels
    assert "never wrote this at all" not in labels


async def test_baseline_still_stores_no_brain_state(client):
    emu = ClientEmulator("nofirst", "pw-nofirst")
    await emu.register(client)
    await seed(client, emu, days=29)  # below threshold

    await emu.recompute(client)
    from sqlalchemy import select

    from app.models import Insight

    app = client._transport.app  # noqa: SLF001 — test reachability into state
    async with app.state.sessionmaker() as session:
        rows = (
            (
                await session.execute(
                    select(Insight).where(Insight.user_id == emu.user_id)
                )
            )
            .scalars()
            .all()
        )
    assert rows == []


async def test_recompute_response_carries_lifecycle_counters(client):
    emu = ClientEmulator("counters", "pw-count")
    await emu.register(client)
    await seed(client, emu, days=70)
    body = await emu.recompute(client)
    assert body["patterns_new"] >= 1
    assert body["patterns_fading"] == 0  # nothing can fade on first contact
    # First contact: every surfaced pattern is a first qualification.
    assert body["patterns_stored"] == body["patterns_new"]
