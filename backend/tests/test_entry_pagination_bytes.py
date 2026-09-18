"""Response-byte paging regressions for encrypted journal history."""

from __future__ import annotations

import base64
from datetime import date

from app.api.entries import ENTRY_PAGE_BLOB_BYTES
from app.models import Entry
from tests.helpers import ClientEmulator


async def test_entries_byte_paginate_without_legacy_silent_truncation(client, app):
    """Only the modern opt-in may receive a short page with a continuation.

    The metadata-first route must not load/emit all three large blobs at
    once.  An older client gets a clear 413 rather than treating a short page
    as end-of-history; the opt-in caller receives two bounded rows, then the
    final one on the advertised offset.
    """

    emu = ClientEmulator("pagebytes", "pw-page-bytes")
    await emu.register(client)
    raw_size = ENTRY_PAGE_BLOB_BYTES // 2
    seeded_ids = ["page-byte-1", "page-byte-2", "page-byte-3"]
    async with app.state.sessionmaker() as session:
        session.add_all(
            [
                Entry(
                    user_id=emu.user_id,
                    client_entry_id=entry_id,
                    blob=bytes([index + 1]) * raw_size,
                    entry_date=date.today(),
                )
                for index, entry_id in enumerate(seeded_ids)
            ]
        )
        await session.commit()

    legacy = await client.get("/api/entries", headers=emu.headers, params={"limit": 25})
    assert legacy.status_code == 413
    assert legacy.json()["code"] == "payload_too_large"

    first = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 25, "page_bytes": ENTRY_PAGE_BLOB_BYTES},
    )
    assert first.status_code == 200, first.text
    first_rows = first.json()
    assert len(first_rows) == 2
    assert first.headers["X-Next-Offset"] == "2"
    assert sum(len(base64.b64decode(row["blob"])) for row in first_rows) == ENTRY_PAGE_BLOB_BYTES

    second = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 25, "offset": 2, "page_bytes": ENTRY_PAGE_BLOB_BYTES},
    )
    assert second.status_code == 200, second.text
    assert len(second.json()) == 1
    assert "X-Next-Offset" not in second.headers
    assert {row["client_entry_id"] for row in first_rows + second.json()} == set(seeded_ids)


async def test_entries_reject_page_byte_budget_smaller_than_first_blob(client, app):
    emu = ClientEmulator("smallpage", "pw-small-page")
    await emu.register(client)
    async with app.state.sessionmaker() as session:
        session.add(
            Entry(
                user_id=emu.user_id,
                client_entry_id="too-large-for-request",
                blob=b"x" * 2_048,
                entry_date=date.today(),
            )
        )
        await session.commit()

    response = await client.get(
        "/api/entries",
        headers=emu.headers,
        params={"limit": 25, "page_bytes": 1_024},
    )
    assert response.status_code == 413
    assert response.json()["code"] == "payload_too_large"
