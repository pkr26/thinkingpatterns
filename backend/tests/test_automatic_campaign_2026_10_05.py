"""Finite account exports must advance pages and complete every section."""

from __future__ import annotations

import asyncio
import base64
from contextvars import ContextVar
from datetime import date, datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import account as account_api, insights as insights_api
from app.models import Consent, Entry, Insight, User
from tests.test_account_api import test_delete_account_hard_cascades as _check_account_erasure
from tests.test_api_pins import _measure_blob
from tests.test_audit_2026_09_21_backend import (
    test_rekey_advances_entries_and_measures_revision as _check_rekey_revisions,
)
from tests.test_audit_remediation_2026_09_28 import (
    test_rekey_resume_rekeys_rows_written_after_the_interrupted_run as _check_rekey_resume,
)
from tests.test_independent_remediation_2026_10_04_backend import (
    test_one_time_explicit_bootstrap_preserves_ciphertext_and_never_repair_missing_guard as _check_trusted_entry_bootstrap,
)
from tests.test_remediation_2026_10_03 import (
    test_v1_rekey_includes_audio_and_invalidates_obsolete_recovery as _check_rekey_audio,
)
from tests.test_voice_remediation_2026_09_29 import _voice_ready


@pytest.fixture(autouse=True)
def _export_audio_context(settings, tmp_path):
    settings.audio_enabled = True
    settings.stt_url = "https://stt.example.com/v1"
    settings.stt_api_key = "synthetic-key"
    settings.audio_local_dir = str(tmp_path / "audio")


async def test_finite_export_advances_every_page_and_finishes(client, app, settings, monkeypatch):
    """No repeat page or repeated EOF query; small streams have finite work."""
    emu = await _voice_ready(client, settings, "automatic-finite-export")
    today = date.today()
    for index in range(2):
        entry_id = f"finite-entry-{index}"
        await emu.create_entry(client, "a recorded quiet day", today, client_entry_id=entry_id)
        response = await client.post(
            "/api/v1/audio/attachments",
            headers=emu.headers,
            json={
                "client_entry_id": entry_id,
                "blob": base64.b64encode(b"RIFF-synthetic-audio" * (index + 8)).decode(),
                "mime": "audio/webm",
                "duration_seconds": 10 + index,
            },
        )
        assert response.status_code == 201, response.text
        measure_id = f"finite-measure-{index}"
        response = await client.post(
            "/api/measures",
            headers=emu.headers,
            json={
                "client_measure_id": measure_id,
                "blob": _measure_blob(emu, measure_id, index),
                "measure_date": today.isoformat(),
            },
        )
        assert response.status_code == 201, response.text
    async with app.state.sessionmaker() as session:
        # Both cursor keys are needed when independent entries share one
        # timestamp (bulk imports and coarse database clocks can do this).
        await session.execute(
            update(Entry)
            .where(Entry.user_id == emu.user_id)
            .values(received_at=datetime.now(timezone.utc) - timedelta(minutes=1))
        )
        for index in range(2):
            therapist_id = f"finite-therapist-{index}"
            session.add(
                User(
                    id=therapist_id,
                    username=therapist_id,
                    salt="synthetic",
                    verifier=b"synthetic",
                    scrypt_salt=b"synthetic",
                    role="therapist",
                )
            )
            await session.flush()
            session.add(
                Consent(
                    id=f"finite-consent-{index}",
                    user_id=emu.user_id,
                    therapist_id=therapist_id,
                    status="active",
                )
            )
            session.add(
                Insight(
                    user_id=emu.user_id,
                    kind=f"finite-insight-{index}",
                    for_date=None,
                    blob=b"x" * (60 + index),
                )
            )
        await session.commit()
    monkeypatch.setattr(account_api, "EXPORT_METADATA_PAGE_SIZE", 1)
    execute = AsyncSession.execute
    reads = 0
    seen = set()
    # Audit verification intentionally reads its evidence before serialization;
    # the four ordinary pagers have no reason to revisit a completed page.
    ordinary = {
        "entries",
        "measures",
        "audio_attachments",
        "consent_events",
        "insights",
        "consents",
    }
    export_tables = ordinary | {"access_logs"}

    def table_names(table):
        if hasattr(table, "left") and hasattr(table, "right"):
            return table_names(table.left) | table_names(table.right)
        return {getattr(table, "name", "")}

    async def checked_execute(session, statement, *args, **kwargs):
        nonlocal reads
        result = await execute(session, statement, *args, **kwargs)
        tables = set().union(*(table_names(table) for table in statement.get_final_froms()))
        if not tables.intersection(export_tables):
            return result
        if getattr(statement, "_limit_clause", None) is None and "insights" not in tables:
            return result
        reads += 1
        assert reads <= 64, "finite two-row export exceeded its page-query work budget"
        frozen = result.freeze()
        if tables.intersection(ordinary):
            compiled = statement.compile()
            query = (
                str(compiled),
                tuple(sorted((key, repr(value)) for key, value in compiled.params.items())),
            )
            row_ids = tuple(
                str(getattr(row, "id", row[0] if isinstance(row, (tuple, list)) else row))
                for row in frozen.data
            )
            page = query, row_ids
            assert page not in seen, "export revisited the same page or queried again after EOF"
            seen.add(page)
        return frozen()

    monkeypatch.setattr(AsyncSession, "execute", checked_execute)
    response = await asyncio.wait_for(client.get("/api/account/export", headers=emu.headers), 5)
    assert response.status_code == 200, response.text
    bundle = response.json()
    assert bundle["version"] == 3 and bundle["user_id"] == emu.user_id
    assert {row["client_entry_id"] for row in bundle["entries"]} == {
        "finite-entry-0",
        "finite-entry-1",
    }
    assert {row["client_measure_id"] for row in bundle["measures"]} == {
        "finite-measure-0",
        "finite-measure-1",
    }
    assert {row["kind"] for row in bundle["insights"]} == {"finite-insight-0", "finite-insight-1"}
    assert {row["client_entry_id"] for row in bundle["audio"]} == {
        "finite-entry-0",
        "finite-entry-1",
    }
    assert {row["id"] for row in bundle["shares"]} == {"finite-consent-0", "finite-consent-1"}
    assert bundle["consent_events"], "voice consent evidence must survive export"
    assert (
        len(bundle["entries"])
        == len(bundle["measures"])
        == len(bundle["insights"])
        == len(bundle["audio"])
        == 2
    )
    assert reads > 0


@pytest.fixture
def finite_rekey_pages(monkeypatch):
    """Small rotations must advance each SQL page and stop at exhaustion."""
    active = ContextVar("finite_rekey_page_work", default=None)
    stage = ContextVar("finite_rekey_stage", default="rotation")
    send = httpx.AsyncClient.send
    execute = AsyncSession.execute
    preflight = insights_api._preflight_legacy_rotation

    async def checked_preflight(*args, **kwargs):
        token = stage.set("preflight")
        try:
            return await preflight(*args, **kwargs)
        finally:
            stage.reset(token)

    async def checked_send(client, request, *args, **kwargs):
        if request.url.path != "/api/processing/rekey":
            return await send(client, request, *args, **kwargs)
        work = {"queries": 0, "seen": set(), "failure": None}
        token = active.set(work)
        try:
            response = await asyncio.wait_for(send(client, request, *args, **kwargs), 10)
            assert work["failure"] is None, work["failure"]
            return response
        finally:
            active.reset(token)

    async def checked_execute(session, statement, *args, **kwargs):
        result = await execute(session, statement, *args, **kwargs)
        work = active.get()
        if work is None or getattr(statement, "_limit_clause", None) is None:
            return result
        tables = {getattr(table, "name", "") for table in statement.get_final_froms()}
        if not tables.intersection({"entries", "insights", "measures", "audio_attachments"}):
            return result
        work["queries"] += 1
        if work["queries"] > 64:
            work["failure"] = "finite rekey exceeded its bounded page-query work"
            raise AssertionError(work["failure"])
        compiled = statement.compile()
        query = (
            str(compiled),
            tuple(sorted((key, repr(value)) for key, value in compiled.params.items())),
        )
        frozen = result.freeze()
        ids = tuple(str(row.id if hasattr(row, "id") else row[0]) for row in frozen.data)
        # Authentication preflight and the actual rewrite independently walk
        # the same corpus. Exhaustion is unique within each of those stages.
        page = stage.get(), query, ids
        if page in work["seen"]:
            work["failure"] = f"rekey repeated a page or queried again after EOF: {page!r}"
            raise AssertionError(work["failure"])
        work["seen"].add(page)
        return frozen()

    monkeypatch.setattr(httpx.AsyncClient, "send", checked_send)
    monkeypatch.setattr(AsyncSession, "execute", checked_execute)
    monkeypatch.setattr(insights_api, "_preflight_legacy_rotation", checked_preflight)


async def test_finite_rekey_entries_and_measures_finishes(client, finite_rekey_pages):
    await _check_rekey_revisions(client)


async def test_finite_rekey_legacy_preflight_finishes(finite_rekey_pages):
    await _check_rekey_resume()


async def test_finite_rekey_audio_finishes(client, app, settings, tmp_path, finite_rekey_pages):
    await _check_rekey_audio(client, app, settings, tmp_path)


@pytest.mark.parametrize("unexpected", [False, True, "disconnect"])
async def test_body_channel_replays_each_message_once_and_stops_draining(unexpected):
    from app.middleware import HardeningMiddleware

    source = (
        [{"type": "http.disconnect"}]
        if unexpected == "disconnect"
        else (
            (
                [{"type": "synthetic.control"}]
                if unexpected
                else [
                    {"type": "http.request", "body": b"first", "more_body": True},
                    {"type": "http.request", "body": b"second", "more_body": False},
                ]
            )
            + [{"type": "http.disconnect"}]
        )
    )
    received, sent = [], []
    reads = 0

    async def receive():
        nonlocal reads
        assert reads < len(source), "request channel was read again after its terminal message"
        message = source[reads]
        reads += 1
        return message

    async def application(scope, downstream_receive, send):
        assert reads == (1 if unexpected else 2), (
            "draining must hand off at the first terminal or unexpected event"
        )
        for expected in source:
            message = await downstream_receive()
            assert message == expected, (
                "buffered request messages must replay once in channel order"
            )
            received.append(message)
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"complete", "more_body": False})

    async def send(message):
        sent.append(message)

    middleware = HardeningMiddleware(application, max_body_bytes=1024, body_read_timeout_seconds=1)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/meta/status",
        "headers": [],
        "client": ("127.0.0.1", 1234),
    }
    await asyncio.wait_for(middleware(scope, receive, send), 2)
    assert received == source and reads == len(source)
    assert [message["status"] for message in sent if message["type"] == "http.response.start"] == [
        200
    ]
    assert sent[-1]["body"] == b"complete"


async def test_trusted_entry_bootstrap_advances_pages_and_stops_after_exhaustion(
    client, app, settings, monkeypatch
):
    from app.security import entry_guard

    active = ContextVar("finite_trusted_entry_bootstrap", default=None)
    bootstrap = entry_guard.bootstrap_trusted_entries
    scalars = AsyncSession.scalars

    async def checked_bootstrap(*args, **kwargs):
        token = active.set({"seen": set(), "reads": 0})
        try:
            return await asyncio.wait_for(bootstrap(*args, **kwargs), 5)
        finally:
            active.reset(token)

    async def checked_scalars(session, statement, *args, **kwargs):
        result = await scalars(session, statement, *args, **kwargs)
        work = active.get()
        if work is None:
            return result
        work["reads"] += 1
        assert work["reads"] <= 4, "one-row trusted bootstrap exceeded its finite query work"
        rows = result.all()
        page = tuple(row.id for row in rows)
        assert page not in work["seen"], (
            "trusted bootstrap revisited a page or queried after exhaustion"
        )
        work["seen"].add(page)
        return SimpleNamespace(all=lambda: rows)

    monkeypatch.setattr(entry_guard, "bootstrap_trusted_entries", checked_bootstrap)
    monkeypatch.setattr(AsyncSession, "scalars", checked_scalars)
    await _check_trusted_entry_bootstrap(client, app, settings)


async def test_account_erasure_crosses_empty_phases_and_finishes(client, app, monkeypatch):
    from app.services import account_deletion

    active = ContextVar("finite_account_purge_work", default=None)
    purge = account_deletion.purge_one_account_page
    execute = AsyncSession.execute
    calls = 0

    async def checked_purge(*args, **kwargs):
        nonlocal calls
        calls += 1
        token = active.set({"reads": 0, "seen_empty": set()})
        try:
            return await asyncio.wait_for(purge(*args, **kwargs), 5)
        finally:
            active.reset(token)

    async def checked_execute(session, statement, *args, **kwargs):
        work = active.get()
        if work is not None:
            work["reads"] += 1
            assert work["reads"] <= 128, "small-account purge exceeded its finite statement budget"
        result = await execute(session, statement, *args, **kwargs)
        if work is None or not getattr(statement, "is_select", False):
            return result
        frozen = result.freeze()
        if not frozen.data:
            compiled = statement.compile()
            query = (
                str(compiled),
                tuple(sorted((key, repr(value)) for key, value in compiled.params.items())),
            )
            assert query not in work["seen_empty"], "purge queried the same exhausted phase again"
            work["seen_empty"].add(query)
        return frozen()

    monkeypatch.setattr(account_deletion, "purge_one_account_page", checked_purge)
    monkeypatch.setattr(AsyncSession, "execute", checked_execute)
    await _check_account_erasure(client, app)
    assert calls > 0, "account erasure must actually complete a purge turn"
