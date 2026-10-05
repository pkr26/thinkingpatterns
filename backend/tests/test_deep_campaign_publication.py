"""Publication invariants observed through fresh HTTP and database reads."""

from __future__ import annotations

import base64
import json
from datetime import date

from sqlalchemy import select

from app.models import Insight
from app.security import crypto
from app.services import brain, questions
from app.services.patterns import Pattern
from tests.helpers import ClientEmulator


async def test_each_server_recompute_advances_all_publication_generation_copies(client, app):
    patient = ClientEmulator("publication-generation", "password")
    await patient.register(client)
    app.state.settings.unlock_threshold_days = 1
    await patient.create_entry(
        client, "A calm and ordinary day", date.today(), client_entry_id="one"
    )
    for expected in (1, 2, 3):
        response = await patient.recompute(client)
        assert response["state_seq"] == expected
        fetched = await client.get("/api/insights", headers=patient.headers)
        assert fetched.status_code == 200, fetched.text
        body = fetched.json()
        assert body["state_seq"] == expected
        plain = crypto.decrypt(
            patient.data_key,
            base64.b64decode(body["blob"]),
            crypto.build_aad("insights", patient.user_id, "patterns"),
        )
        assert json.loads(plain)["state_seq"] == expected
        async with app.state.sessionmaker() as session:
            rows = list(
                (
                    await session.scalars(
                        select(Insight).where(
                            Insight.user_id == patient.user_id,
                            Insight.kind.in_(("patterns", "brain")),
                        )
                    )
                ).all()
            )
            assert {row.kind: row.state_seq for row in rows} == {
                "patterns": expected,
                "brain": expected,
            }


async def test_persisted_daily_question_survives_restart_and_new_analysis_candidates(
    client, app, monkeypatch
):
    patient = ClientEmulator("publication-question", "password")
    await patient.register(client)
    app.state.settings.unlock_threshold_days = 1
    today = date.today()
    await patient.create_entry(client, "A calm and ordinary day", today, client_entry_id="morning")
    update = brain.update
    analyses = []
    generated = []

    def changing_candidates(*args, **kwargs):
        result = update(*args, **kwargs)
        label = "the morning meeting" if not analyses else "the evening conversation"
        analyses.append(label)
        result.surfaced = [Pattern("rumination", label, 4, 0.9, {"pid": label})]
        return result

    def new_question(user_id, patterns, for_date, *, language):
        generated.append(patterns[0].label)
        return f"What did you notice about {patterns[0].label}?"

    monkeypatch.setattr(brain, "update", changing_candidates)
    monkeypatch.setattr(questions, "question_for_today", new_question)
    await patient.recompute(client)
    first = await patient.decrypt_question(client, today)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(
            select(Insight).where(
                Insight.user_id == patient.user_id,
                Insight.kind == "question",
                Insight.for_date == today,
            )
        )
        first_bytes, first_generation = bytes(row.blob), row.state_seq
    # Remove the process-local pin as a restart would. The database question
    # must stay stable even when the analyzer proposes a different candidate.
    monkeypatch.setattr(questions, "_DAY_PINNED_QUESTIONS", {})
    await patient.create_entry(client, "An evening conversation", today, client_entry_id="evening")
    await patient.recompute(client)
    assert analyses == ["the morning meeting", "the evening conversation"]
    assert generated == ["the morning meeting"]
    assert await patient.decrypt_question(client, today) == first
    async with app.state.sessionmaker() as session:
        row = await session.scalar(
            select(Insight).where(
                Insight.user_id == patient.user_id,
                Insight.kind == "question",
                Insight.for_date == today,
            )
        )
        assert bytes(row.blob) == first_bytes
        assert row.state_seq == first_generation
