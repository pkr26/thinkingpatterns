"""External verification checklist 2026-09-23, round 2: threshold, timezone
day-boundaries, backdating inflation, fabricated client claims, exact body cap.

Closes the mapped gaps:

* the #1 real-world bug source — 23:59 vs 00:01 local writes in UTC−12 and
  UTC+14 landing on the correct active day for the 30-day gate;
* "distinct days, not entries" and grace-window inflation at the API level
  (the main suite had the pure-function pins; the bulk-import scenario
  existed only in the red-team harness);
* a tampered client claiming ``phase``/``active_days`` it never earned;
* the EXACT 2 MiB body boundary (accepted) vs 2 MiB + 1 byte (413) — the
  suite had only far-over-cap probes.
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, datetime, time, timedelta, timezone

import pytest

from app.middleware import HardeningMiddleware
from tests.helpers import ClientEmulator, daterange

TODAY = date.today()
UTC = timezone.utc


# --- 3a: timezone day-boundary ---------------------------------------------------


def _local_dates_across_midnight(offset_hours: int, base: date) -> tuple[date, date]:
    """The LOCAL calendar dates an extreme-zone user's client would send for
    a 23:59 write and a 00:01 write two minutes later (local wall time)."""
    zone = timezone(timedelta(hours=offset_hours))
    late_evening = datetime.combine(base, time(23, 59), tzinfo=zone)
    early_morning = late_evening + timedelta(minutes=2)  # 00:01 next local day
    return late_evening.date(), early_morning.date()


class TestTimezoneDayBoundary:
    @pytest.mark.parametrize("offset_hours", [-12, 14], ids=["utc-minus-12", "utc-plus-14"])
    def test_extreme_zone_midnight_pair_lands_on_two_distinct_local_dates(self, offset_hours):
        # The client dates entries by LOCAL calendar day; two writes two
        # minutes apart across local midnight must be two distinct days no
        # matter how far east or west of UTC the writer sits.
        late, early = _local_dates_across_midnight(offset_hours, TODAY)
        assert late != early

    @pytest.mark.parametrize("offset_hours", [-12, 14], ids=["utc-minus-12", "utc-plus-14"])
    def test_extreme_zone_dates_stay_inside_the_server_grace_window(self, offset_hours):
        # Whatever local date an extreme-zone client sends, it is at most
        # one day away from the server's UTC calendar — which is exactly
        # what the ±1-day validation grace accepts. A zone outside
        # [-12, +14] would break this invariant.
        zone = timezone(timedelta(hours=offset_hours))
        for wall in (time(0, 1), time(6, 0), time(12, 0), time(18, 0), time(23, 59)):
            local = datetime.combine(TODAY, wall, tzinfo=zone)
            utc_day = datetime.now(UTC).date()
            assert abs((local.date() - utc_day).days) <= 1, (wall, local.date(), utc_day)

    async def test_utc_plus_14_morning_entry_counts_as_its_own_active_day(self, client):
        # 00:01 local in UTC+14 is still the PREVIOUS UTC day server-side;
        # the client sends its local date (= server today + 1) and the
        # grace accepts it. That entry must advance the gate by exactly
        # one distinct day.
        emu = ClientEmulator("tz-east", "pw")
        await emu.register(client)
        await emu.backdate_account(client, days=60)
        for day in daterange(28, TODAY - timedelta(days=1)):  # 28 distinct days
            await emu.create_entry(client, f"day {day}", day)
        summary = await client.get("/api/insights", headers=emu.headers)
        assert summary.json()["days_remaining"] == 2

        tomorrow_local = TODAY + timedelta(days=1)  # the UTC+14 00:01-local date
        await emu.create_entry(client, "00:01 my time", tomorrow_local, "tz-e-1")
        summary = await client.get("/api/insights", headers=emu.headers)
        assert summary.json()["days_remaining"] == 1

    async def test_two_minutes_across_local_midnight_count_as_two_active_days(self, client):
        # 23:59 on day X and 00:01 on day X+1 (any zone): two entries, two
        # distinct active days — never collapsed into one "wrote twice".
        emu = ClientEmulator("tz-pair", "pw")
        await emu.register(client)
        await emu.backdate_account(client, days=60)
        for day in daterange(28, TODAY - timedelta(days=2)):
            await emu.create_entry(client, f"day {day}", day)
        summary = await client.get("/api/insights", headers=emu.headers)
        assert summary.json()["days_remaining"] == 2

        await emu.create_entry(client, "23:59 local", TODAY - timedelta(days=1), "tz-p-1")
        await emu.create_entry(client, "00:01 local", TODAY, "tz-p-2")
        summary = await client.get("/api/insights", headers=emu.headers)
        assert summary.json()["days_remaining"] == 0

    async def test_same_instant_seen_from_both_extremes_never_double_counts(self, client):
        # One UTC instant is 06:00 "today" in UTC−12's evening... in local
        # terms the SAME moment is early-next-day in UTC+14. One write is
        # one write: the date the client sends is what counts, exactly once.
        emu = ClientEmulator("tz-one", "pw")
        await emu.register(client)
        await emu.backdate_account(client, days=60)
        await emu.create_entry(client, "single write", TODAY, "tz-s-1")
        await emu.create_entry(client, "same day rewrite", TODAY, "tz-s-2")
        summary = await client.get("/api/insights", headers=emu.headers)
        assert summary.json()["days_remaining"] == 29  # one active day, not two


# --- 4b: distinct days, not entries -----------------------------------------------


class TestDistinctDaysNotEntries:
    async def test_thirty_entries_in_one_afternoon_are_one_active_day(self, client):
        emu = ClientEmulator("burst-day", "pw")
        await emu.register(client)
        for i in range(30):
            await emu.create_entry(client, f"entry {i} same day", TODAY, f"burst-{i}")
        summary = await client.get("/api/insights", headers=emu.headers)
        body = summary.json()
        assert body["phase"] == "baseline"
        assert body["days_remaining"] == 29

    async def test_forty_entries_spread_over_the_grace_window_are_two_days(self, client):
        # The most an attacker can span with a fresh account is
        # [today, today+1]; 40 entries there must never look like 40 days.
        emu = ClientEmulator("burst-window", "pw")
        await emu.register(client)
        for i in range(40):
            day = TODAY if i % 2 == 0 else TODAY + timedelta(days=1)
            await emu.create_entry(client, f"entry {i}", day, f"grace-{i}")
        summary = await client.get("/api/insights", headers=emu.headers)
        body = summary.json()
        assert body["phase"] == "baseline"
        assert body["days_remaining"] == 28


# --- 4c: server-side enforcement against a fabricated client claim ------------------


class TestFabricatedPhaseClaim:
    async def test_recompute_ignores_a_fabricated_phase_and_stays_baseline(self, client):
        emu = ClientEmulator("liar-client", "pw")
        await emu.register(client)
        await emu.backdate_account(client, days=60)
        for day in daterange(5, TODAY):  # 5 active days — far below the gate
            await emu.create_entry(client, "ordinary day", day)

        token = await emu.open_processing_session(client)
        response = await client.post(
            "/api/insights/recompute",
            headers={**emu.headers, "X-Processing-Token": token},
            json={
                "phase": "insight",
                "active_days": 99,
                "unlock_days": 0,
                "force": True,
            },
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["phase"] == "baseline", "the server computes the phase from its own rows"
        assert body["days_remaining"] == 25

        stored = await client.get("/api/insights", headers=emu.headers)
        assert stored.json()["blob"] is None, "nothing may be stored below the gate"
        questions = await client.get("/api/questions/today", headers=emu.headers)
        assert questions.status_code == 404


# --- 9b: the exact body-cap boundary ------------------------------------------------


class TestExactBodyCapBoundary:
    async def test_middleware_accepts_exactly_the_cap_and_rejects_one_byte_more(self):
        async def echo_app(scope, receive, send):
            body = b""
            while True:
                message = await receive()
                if message["type"] == "http.request":
                    body += message.get("body", b"")
                    if not message.get("more_body"):
                        break
                else:
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        wrapped = HardeningMiddleware(echo_app, max_body_bytes=100)

        async def run(body: bytes) -> int:
            sent: list[dict] = []

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            async def send(message):
                sent.append(message)

            scope = {
                "type": "http",
                "asgi": {"version": "2.3"},
                "http_version": "1.1",
                "method": "POST",
                "path": "/x",
                "headers": [(b"content-length", str(len(body)).encode())],
            }
            await wrapped(scope, receive, send)
            return sent[0]["status"]

        assert await run(b"x" * 100) == 200, "exactly the cap is accepted"
        assert await run(b"x" * 101) == 413, "one byte over the cap is rejected"

    async def test_streamed_chunked_body_on_the_exact_boundary(self):
        async def echo_app(scope, receive, send):
            while True:
                message = await receive()
                if message["type"] != "http.request":
                    break
                if not message.get("more_body"):
                    break
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        wrapped = HardeningMiddleware(echo_app, max_body_bytes=100)

        async def run(chunks: list[bytes]) -> int:
            sent: list[dict] = []
            queue = [
                {"type": "http.request", "body": chunk, "more_body": i < len(chunks) - 1}
                for i, chunk in enumerate(chunks)
            ]

            async def receive():
                return queue.pop(0) if queue else {"type": "http.disconnect"}

            async def send(message):
                sent.append(message)

            scope = {
                "type": "http",
                "asgi": {"version": "2.3"},
                "http_version": "1.1",
                "method": "POST",
                "path": "/x",
                "headers": [],  # chunked: no content-length
            }
            await wrapped(scope, receive, send)
            return sent[0]["status"]

        assert await run([b"x" * 60, b"x" * 40]) == 200, "chunks summing to the cap pass"
        assert await run([b"x" * 60, b"x" * 41]) == 413, "chunks summing to cap+1 are cut"

    async def test_default_settings_boundary_is_exactly_two_mebibytes(self, client):
        # The production default: 2 MiB accepted (fails LATER validation,
        # never as 413), 2 MiB + 1 byte refused by the cap itself.
        cap = 2 * 1024 * 1024
        at_cap = b'{"x": "' + b"a" * (cap - 8) + b'"'
        assert len(at_cap) == cap
        response = await client.post(
            "/api/v1/auth/salt",
            content=at_cap,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 422, "exactly at the cap the body is parsed, then validated"

        over_cap = at_cap + b"~"
        response = await client.post(
            "/api/v1/auth/salt",
            content=over_cap,
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 413
        assert response.json()["code"] == "payload_too_large"
