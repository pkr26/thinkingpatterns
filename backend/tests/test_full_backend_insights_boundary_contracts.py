"""Native SQL, ciphertext resume, calendar and bounded parsing contracts."""

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from sqlalchemy import select
from sqlalchemy.dialects import postgresql, sqlite
from starlette.requests import Request

from app.api import insights
from app.cache import RateLimitCheck, SlidingWindowCounter
from app.config import Settings
from app.deps import ApiError
from app.models import Insight, RekeyJournal
from app.schemas import LocalRecomputeRequest, RekeyRequest
from app.security import crypto
from app.security.enclave import SecureBuffer
from tests.test_full_backend_collection_mutation import (
    BLOB,
    NOW,
    OWNER,
    b64,
    collection_db,  # noqa: F401
    envelope,
)

# Fixture imports are requested as parameters.
# ruff: noqa: F811
OLD = bytearray(b"o" * 32)
NEW = bytearray(b"n" * 32)
OPERATION = "12345678-1234-1234-1234-123456789abc"


def plaintext(text="entry", **fields):
    return bytearray(
        json.dumps({"text": text, "created_at": NOW.date().isoformat(), **fields}).encode()
    )


@pytest.mark.parametrize("dialect", ["postgresql", "sqlite"])
def test_native_upsert_uses_the_actual_supported_sql_dialect(dialect):
    session = SimpleNamespace(bind=SimpleNamespace(dialect=SimpleNamespace(name=dialect)))
    statement = (
        insights._dialect_insert(session)(Insight)
        .values(user_id=OWNER, kind="patterns", blob=BLOB)
        .on_conflict_do_update(index_elements=["user_id", "kind", "for_date"], set_={"blob": BLOB})
    )
    compiled = statement.compile(
        dialect=postgresql.dialect() if dialect == "postgresql" else sqlite.dialect()
    )
    assert str(compiled).startswith("INSERT INTO insights")
    assert "ON CONFLICT (user_id, kind, for_date) DO UPDATE SET blob" in str(compiled)
    assert compiled.dialect.name == dialect
    # PostgreSQL and SQLite build distinct executable Insert classes.
    assert statement.__class__.__module__.split(".")[2] == dialect


@pytest.mark.parametrize("kind", ["entry", "measure", "insight"])
def test_resume_scans_continue_after_two_already_rotated_rows_and_scrub_all_plaintext(
    monkeypatch, kind
):
    buffers = []

    class ObservedBuffer(SecureBuffer):
        def __init__(self, value):
            super().__init__(value)
            buffers.append(self)

    monkeypatch.setattr(insights, "SecureBuffer", ObservedBuffer)
    identifiers = ["already-1", "pending-1", "already-2", "pending-2"]

    def modern(rid):
        return crypto.entry_aad_v2(OWNER, rid, 1)

    def measure(rid):
        return crypto.build_aad("measure", OWNER, rid)

    insight = crypto.build_aad("insights", OWNER, "custom")
    if kind == "entry":
        rows = [
            (rid, rid, 1, crypto.encrypt(NEW if i % 2 == 0 else OLD, rid.encode(), modern(rid)))
            for i, rid in enumerate(identifiers)
        ]
        out, already = insights._rekey_entry_batch(OLD, NEW, rows, OWNER)
        decoded = [(rid, crypto.decrypt(NEW, blob, modern(rid))) for rid, blob in out]
    elif kind == "measure":
        rows = [
            (rid, crypto.encrypt(NEW if i % 2 == 0 else OLD, rid.encode(), measure(rid)))
            for i, rid in enumerate(identifiers)
        ]
        out, already = insights._rekey_blob_batch(OLD, NEW, rows, measure)
        decoded = [(rid, crypto.decrypt(NEW, blob, measure(rid))) for rid, blob in out]
    else:
        rows = [
            (
                rid,
                "custom",
                None,
                crypto.encrypt(NEW if i % 2 == 0 else OLD, rid.encode(), insight),
                5,
            )
            for i, rid in enumerate(identifiers)
        ]
        out, already = insights._rekey_insight_batch(OLD, NEW, rows, OWNER)
        decoded = [(row["id"], crypto.decrypt(NEW, row["blob"], insight)) for row in out]
        assert [r["state_seq"] for r in out] == [5, 5]
    assert already == 2
    assert decoded == [("pending-1", b"pending-1"), ("pending-2", b"pending-2")]
    assert buffers and all(buffer.data == bytearray(len(buffer.data)) for buffer in buffers)


def test_rekey_nullable_question_date_uses_its_actual_insight_aad():
    aad = crypto.build_aad("insights", OWNER, "question")
    blob = crypto.encrypt(OLD, b"legacy undated question", aad)
    out, already = insights._rekey_insight_batch(
        OLD, NEW, [("legacy", "question", None, blob, 4)], OWNER
    )
    assert already == 0 and len(out) == 1
    assert crypto.decrypt(NEW, out[0]["blob"], aad) == b"legacy undated question"
    assert out[0]["state_seq"] == 4


@pytest.mark.asyncio
async def test_fresh_rekey_journal_reports_initial_entry_stage(collection_db):
    db = collection_db
    body = RekeyRequest(
        operation_id=OPERATION, new_salt=b64(b"s" * 16), new_verifier=b64(b"v" * 32)
    )
    first = await insights._load_or_create_rekey_journal(
        db.session,
        OWNER,
        body=body,
        digest="request",
        old_key=OLD,
        new_key=NEW,
        settings=db.settings,
    )
    assert first.stage == "entries"
    assert first.entries_done == first.measures_done == first.insights_done == 0
    assert first.operation_id == OPERATION
    assert (await db.session.get(RekeyJournal, first.id)).stage == "entries"


@pytest.mark.parametrize("value,expected", [(-2.0, -1.0), (0.0, 0.0), (2.0, 1.0)])
def test_parser_clamps_hostile_finite_sentiment_and_preserves_empty_tags(value, expected):
    entries = insights._parse_entries([plaintext(sentiment=value)], [NOW.date()])
    assert entries[0].sentiment == expected
    assert entries[0].tags == ()


@pytest.mark.parametrize("bucket", ["morning", "afternoon", "evening", "night"])
def test_parser_preserves_supported_writing_windows_and_native_voice_translation(bucket):
    row = insights._parse_entries(
        [
            plaintext(
                text="Bonjour",
                tod=bucket,
                input_mode="voice",
                transcript_lang="fr",
                english_text="Hello translated",
            )
        ],
        [NOW.date()],
    )[0]
    assert row.text == "Hello translated" and row.tod == bucket
    for lang in ["en", "es"]:
        row = insights._parse_entries(
            [plaintext(text="native", transcript_lang=lang, english_text="translation")],
            [NOW.date()],
        )[0]
        assert row.text == "native"


@pytest.mark.parametrize(
    "offset,accepted", [(-2, False), (-1, True), (0, True), (1, True), (2, False)]
)
def test_parser_inner_calendar_tolerance_has_both_exact_edges(offset, accepted):
    plain = plaintext(created_at=(NOW.date() + timedelta(days=offset)).isoformat())
    if accepted:
        assert insights._parse_entries([plain], [NOW.date()])[0].entry_date == NOW.date()
    else:
        with pytest.raises(ValueError, match="created_at does not match entry_date"):
            insights._parse_entries([plain], [NOW.date()])


def test_parser_enforces_actual_per_entry_and_total_text_cost_boundaries():
    # Exercise real 20,000 / 2,000,000-character ceilings with actual JSON,
    # rather than reducing them to a synthetic branch condition.
    assert len(insights._parse_entries([plaintext("x" * 20001)], [NOW.date()])[0].text) == 20000
    unit = plaintext("x" * 20000)
    rows = insights._parse_entries([unit] * 102, [NOW.date()] * 102)
    assert [len(e.text) for e in rows] == [0, 0] + [20000] * 100
    assert sum(len(e.text) for e in rows) == 2000000
    rows = insights._parse_entries([plaintext("x")] + [unit] * 100, [NOW.date()] * 101)
    assert [len(e.text) for e in rows] == [0] + [20000] * 100


@pytest.mark.asyncio
@pytest.mark.parametrize("count", [1, 366])
async def test_local_analysis_scope_cardinality_uses_exact_inclusive_calendar_limit(
    collection_db, monkeypatch, count
):
    db = collection_db
    monkeypatch.setattr(insights, "_utc_today", lambda: NOW.date())
    body = LocalRecomputeRequest(
        base_state_seq=0,
        state_blob=b64(BLOB),
        patterns_blob=b64(BLOB),
        analysis_dates=[NOW.date().isoformat()] * count,
        patterns_count=0,
    )
    result = await insights.local_recompute(body, db.request, db.owner, db.session)
    assert result.active_days == 0 and result.patterns_stored == 0
    stored = list((await db.session.scalars(select(Insight))).all())
    assert sorted((r.kind, bytes(r.blob), r.state_seq) for r in stored) == [
        ("brain", BLOB, 1),
        ("patterns", BLOB, 1),
    ]


@pytest.mark.parametrize("count", [0, 367])
def test_public_local_model_rejects_scope_outside_handler_input_domain(count):
    from pydantic import ValidationError

    with pytest.raises(ValidationError) as failure:
        LocalRecomputeRequest(
            base_state_seq=0,
            state_blob=b64(BLOB),
            patterns_blob=b64(BLOB),
            analysis_dates=[NOW.date().isoformat()] * count,
            patterns_count=0,
        )
    assert failure.value.errors()[0]["loc"] == ("analysis_dates",)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "path,limit_attr,window_attr",
    [
        ("/processing/sessions", "processing_rate_limit", "processing_rate_window"),
        ("/processing/rekey", "processing_rate_limit", "processing_rate_window"),
        ("/insights/recompute", "processing_rate_limit", "processing_rate_window"),
        ("/insights/local-recompute", "processing_rate_limit", "processing_rate_window"),
        ("/insights", "read_rate_limit", "read_rate_window"),
        ("/questions/today", "read_rate_limit", "read_rate_window"),
    ],
)
async def test_public_route_rate_gates_consume_the_configured_identity_window(
    path, limit_attr, window_attr
):
    application = FastAPI()
    settings = Settings(environment="development")
    setattr(settings, limit_attr, 1)
    setattr(settings, window_attr, 600)
    application.state.settings = settings
    application.state.rate_counter = SlidingWindowCounter()
    route = next(r for r in insights.router.routes if r.path == path)
    check = next(
        d.dependency for d in route.dependencies if isinstance(d.dependency, RateLimitCheck)
    )
    request = Request(
        {
            "type": "http",
            "app": application,
            "client": ("203.0.113.18", 443),
            "headers": [],
            "state": {},
        }
    )
    await check(request)
    with pytest.raises(ApiError) as failure:
        await check(request)
    assert failure.value.status_code == 429 and failure.value.code == "rate_limited"
    assert int(failure.value.headers["Retry-After"]) > 0


@pytest.mark.asyncio
async def test_dated_question_retention_keeps_exact_ninety_day_edge_and_other_kinds(
    collection_db, monkeypatch
):
    from app import main, models
    from app.db import build_sessionmaker

    db = collection_db
    monkeypatch.setattr(models, "utcnow", lambda: NOW)
    db.request.app.state.sessionmaker = build_sessionmaker(db.engine)
    observed = []
    db.request.app.state.metrics = SimpleNamespace(
        observe_retention=lambda **values: observed.append(values)
    )
    dates = [
        NOW.date() - timedelta(days=91),
        NOW.date() - timedelta(days=90),
        NOW.date() - timedelta(days=89),
        None,
    ]
    db.session.add_all(
        [
            Insight(
                id=f"{i + 100:032x}",
                user_id=OWNER,
                kind="question",
                for_date=day,
                blob=BLOB,
                state_seq=1,
                created_at=NOW,
            )
            for i, day in enumerate(dates)
        ]
    )
    db.session.add(
        Insight(
            id="e" * 32,
            user_id=OWNER,
            kind="patterns",
            for_date=dates[0],
            blob=BLOB,
            state_seq=1,
            created_at=NOW,
        )
    )
    await db.session.commit()
    assert await main._prune_expired_questions_once(db.request.app) is False
    async with db.request.app.state.sessionmaker() as session:
        remaining = list((await session.scalars(select(Insight))).all())
    assert {r.id for r in remaining} == {f"{i + 100:032x}" for i in range(1, 4)} | {"e" * 32}
    assert observed == [dict(question_insights=1, question_backlog=False)]
