"""A byte-bounded export page must preserve its unconsumed ordered tail."""

from __future__ import annotations

import asyncio
import base64
import json

import pytest
from test_backend_export_contracts import NOW, _fixture, _unique_json_object


@pytest.mark.parametrize("table", ["entries", "insights"])
def test_an_over_budget_middle_record_cannot_be_skipped(monkeypatch, tmp_path, table):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, count=3) as db:
            from app.schemas import EntryCreate, LocalRecomputeRequest
            from sqlalchemy import update

            # Both large entry envelopes fit the real 1,500,000-character
            # request schema. Together they exceed the native 2 MiB page.
            payloads = [b"a" * (1024 * 1024), b"b" * 1_100_000, b"c" * 28]
            encoded = [base64.b64encode(blob).decode() for blob in payloads]
            model = db.models.Entry if table == "entries" else db.models.Insight
            prefix = "entry" if table == "entries" else "insight"
            if table == "entries":
                for n, blob in enumerate(encoded):
                    EntryCreate(
                        client_entry_id=f"client{n:04d}",
                        entry_date=NOW.date(),
                        blob=blob,
                    )
            else:
                # A supported 4 MiB request setting accommodates these two
                # opaque local-analysis uploads; the export page remains at
                # its unmodified native 2 MiB limit.
                db.settings.max_body_bytes = 4 * 1024 * 1024
                LocalRecomputeRequest(
                    base_state_seq=0,
                    state_blob=encoded[0],
                    patterns_blob=encoded[1],
                    analysis_dates=[NOW.date().isoformat()],
                )
            async with db.maker() as session:
                for n, payload in enumerate(payloads):
                    identity = prefix + f"{n:04d}"
                    values = {"blob": payload}
                    if table == "insights" and n < 2:
                        values.update(
                            kind="brain" if n == 0 else "patterns", for_date=None
                        )
                    await session.execute(
                        update(model).where(model.id == identity).values(**values)
                    )
                    db.blobs[identity] = len(payload)
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            expected = db.expected[table]
            for n, blob in enumerate(encoded):
                expected[n]["blob"] = blob
                if table == "insights" and n < 2:
                    expected[n].update(
                        kind="brain" if n == 0 else "patterns", for_date=None
                    )
            assert result[table] == expected
            assert db.request.app.state.export_limiter.borrowed_tokens == 0

    asyncio.run(asyncio.wait_for(exercise(), 10))


def test_exact_byte_prefix_and_full_tail_need_only_two_ciphertext_fetches(
    monkeypatch, tmp_path
):
    async def exercise():
        async with _fixture(monkeypatch, tmp_path, count=102) as db:
            from app.schemas import EntryCreate
            from sqlalchemy import update

            payload = b"b" * (1024 * 1024)
            encoded = base64.b64encode(payload).decode()
            EntryCreate(
                client_entry_id="client0001", entry_date=NOW.date(), blob=encoded
            )
            async with db.maker() as session:
                await session.execute(
                    update(db.models.Entry)
                    .where(db.models.Entry.id == "entry0001")
                    .values(blob=payload)
                )
                db.blobs["entry0001"] = len(payload)
                await session.commit()
                response = await db.account.export_account(
                    db.request, await session.get(db.models.User, "patient"), session
                )
            result = json.loads(
                "".join([chunk async for chunk in response.body_iterator]),
                object_pairs_hook=_unique_json_object,
            )
            expected = db.expected["entries"]
            expected[1]["blob"] = encoded
            assert result["entries"] == expected
            reads = [
                sql
                for sql, _params in db.queries
                if "FROM entries" in sql
                and "entries.id IN" in sql
                and "entries.blob," in sql
            ]
            # The first two supported envelopes exactly fit a native byte
            # page; the remaining100 small envelopes fit one metadata page.
            # A premature boundary would introduce a third data round trip.
            assert len(reads) == 2

    asyncio.run(asyncio.wait_for(exercise(), 10))
