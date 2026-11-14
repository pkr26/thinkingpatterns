"""Owned external SQLite writes cannot silently omit an export record."""

import base64
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event

from app.config import Settings
from app.models import Entry, Insight, Measure
from app.security import crypto
from tests.helpers import ClientEmulator


@pytest.fixture
def settings(tmp_path):
    return Settings(
        environment="development",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'owned-export.sqlite'}",
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["entries", "insights", "measures"])
async def test_native_external_resize_preserves_every_returned_ciphertext(
    client, app, settings, kind
):
    owner = ClientEmulator("external-export-" + kind, "native external export password")
    await owner.register(client)
    at = datetime.now(timezone.utc) - timedelta(days=4)
    rows = []
    blobs = []
    for index in range(3):
        day = (at + timedelta(days=index)).date()
        rid = f"external-export-{index}"
        aad = (
            crypto.entry_aad_v2(owner.user_id, rid, 1)
            if kind == "entries"
            else crypto.build_aad("question", owner.user_id, day.isoformat())
            if kind == "insights"
            else crypto.build_aad("measure", owner.user_id, rid)
        )
        blob = crypto.encrypt(owner.data_key, b"{}", aad)
        blobs.append(blob)
        if kind == "entries":
            row = Entry(
                user_id=owner.user_id,
                client_entry_id=rid,
                entry_date=day,
                received_at=at + timedelta(days=index),
                blob=blob,
            )
        elif kind == "insights":
            row = Insight(
                user_id=owner.user_id,
                kind="question",
                for_date=day,
                created_at=at + timedelta(days=index),
                blob=blob,
            )
        else:
            row = Measure(
                user_id=owner.user_id,
                client_measure_id=rid,
                measure_date=day,
                received_at=at + timedelta(days=index),
                blob=blob,
            )
        rows.append(row)
    async with app.state.sessionmaker() as session:
        session.add_all(rows)
        await session.commit()
    # This is an explicitly owned external-database interference domain.
    # It has zero currentAPI-write origin: normal API writers share the
    # export lifecycle fence and cannot grow a selected page this way.
    grown = crypto.encrypt(owner.data_key, b"x" * (2 * 1024 * 1024), b"owned external resize")
    changed = []

    def resize_before_blob_fetch(connection, cursor, statement, parameters, context, executemany):
        if (
            not changed
            and f"FROM {kind}" in statement
            and f"{kind}.id IN" in statement
            and f"{kind}.blob," in statement
        ):
            path = settings.database_url.removeprefix("sqlite+aiosqlite:///")
            with sqlite3.connect(path) as writer:
                writer.execute(f"UPDATE {kind} SET blob=? WHERE id=?", (grown, rows[1].id))
                writer.commit()
            changed.append(rows[1].id)

    event.listen(app.state.engine.sync_engine, "before_cursor_execute", resize_before_blob_fetch)
    try:
        response = await client.get("/api/v1/account/export", headers=owner.headers)
    finally:
        event.remove(
            app.state.engine.sync_engine, "before_cursor_execute", resize_before_blob_fetch
        )
    assert response.status_code == 200, response.text[:500]
    assert changed == [rows[1].id]
    assert [base64.b64decode(item["blob"]) for item in response.json()[kind]] == [
        blobs[0],
        grown,
        blobs[2],
    ]
