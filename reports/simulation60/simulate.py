#!/usr/bin/env python3
"""60-day, 5-user MindPattern simulation.

Two coordinated tracks over the SAME corpora:

  LIVE  — every entry is synced through the real API (encrypted with the
          real client crypto), then a real recompute + insight read. This
          is what the server actually stores and surfaces.

  REPLAY — a clock-accurate offline replay through the SAME brain code
          (app.services.brain.update) with `today` advancing one
          simulated day at a time and the 30-active-day threshold
          mirrored, so pattern lifecycles (candidate -> emerging ->
          confirmed) become visible per day — something the live server
          cannot show, because its wall clock only ever says "today".

Determinism cross-check: the replay's final day (today, full corpus)
must surface exactly what the live API's recompute surfaced.

Outputs: results.json (everything), timeline_*.csv (per-user daily
timeline), stdout summary.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import json
import os
import random
import sys
from datetime import date, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))
REPO = BACKEND.parent

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import create_async_engine

from app.security import crypto, kdf
from app.db import build_sessionmaker
from app.models import Entry, Insight, User
from app.services import brain, questions
from app.services.patterns import JournalEntry

BASE_URL = os.environ.get("E2E_BASE", "http://127.0.0.1:8907")
DB_URL = os.environ.get("E2E_DB", f"sqlite+aiosqlite:///{BACKEND / 'sim60.db'}")
DAYS = 60
TODAY = date.today()

# ------------------------------------------------------------------ corpus ----

FILLERS = [
    "morning coffee on the balcony before anything else",
    "the commute was uneventful today",
    "cooked something simple for dinner",
    "watered the plants and swept the kitchen",
    "listened to half a podcast episode on the way home",
    "answered a few lingering messages at lunch",
    "took the stairs instead of the elevator",
    "read ten pages of the novel before bed",
    "tidied the desk and cleared the inbox",
    "walked the long way to the pharmacy",
    "made the bed properly for once",
    "brewed tea and watched the rain start",
    "stretched for five minutes in the evening",
    "reorganized one shelf of the bookcase",
    "called the pharmacy about the prescription refill",
    "fixed the wobbly chair leg at last",
    "picked up groceries on the way back",
    "watched an episode of the documentary series",
    "did a load of laundry and folded it",
    "sketched a little in the notebook",
    "practiced a few chords quietly",
    "took photos of the cloudy sky at noon",
    "sorted the recycling and took it down",
    "paid a bill online and filed the receipt",
    "sat outside for a while doing nothing",
    "tried the new bakery around the corner",
    "cleaned the bathroom quickly",
    "backed up the laptop while making dinner",
    "mended the tear in the old jacket",
    "wrote a postcard to my aunt",
    "changed the sheets and opened the windows",
    "finished the crossword with help",
    "met the neighbor briefly at the door",
    "booked the dentist appointment",
    "renewed the library books online",
    "tried a stretching video before bed",
    "cooked soup for two meals",
    "organized the photos on my phone",
    "watered the neighbor's plants too",
    "ironed the shirts for the week",
    "looked up a recipe for the weekend",
    "cleaned the keyboard and the screen",
    "donated a bag of old clothes",
    "replaced the lightbulb in the hallway",
    "sat with the window open listening to birds",
    "did the dishes right after eating",
    "took a short walk after lunch",
    "journalled a quick list of things done",
    "called mom for ten minutes",
    "prepared tomorrow's lunch in advance",
    "rested on the couch without screens",
]

SLEEP_WORRY = [
    "i can't sleep, my mind won't stop",
    "i can't sleep, my mind just won't stop tonight",
    "can't sleep, my mind won't stop racing",
]

GUITAR = [
    "spent the evening with the guitar, learning fingerpicking",
    "practiced guitar scales after dinner",
    "wrote a riff on the guitar tonight",
    "guitar practice again, the chords are getting cleaner",
    "jammed on the guitar for a while",
    "watched a guitar lesson and played along badly",
    "changed the guitar strings, it sounds brighter now",
    "played guitar until my fingers ached",
]

SCROLL = [
    "wasted the whole evening scrolling, eyes tired",
    "doomscrolling again until midnight, feel foggy",
    "screens all evening, head buzzing afterwards",
    "fell down the feed again, regret it every time",
]


class Persona:
    def __init__(self, name, password, seed, blurb):
        self.name, self.password, self.blurb = name, password, blurb
        self.rng = random.Random(seed)
        self.entries: list[dict] = []  # {text, sentiment, date, cid}
        self.expected: list[str] = []

    def filler(self, used):
        """Round-robin the pool, max 3 uses each — no constant fallback
        sentence that would itself become the strongest 'pattern'."""
        best = min(range(len(FILLERS)), key=lambda i: used.get(i, 0))
        used[best] = used.get(best, 0) + 1
        return FILLERS[best]

    def add(self, d, text, sentiment):
        self.entries.append({
            "text": text, "sentiment": round(max(-1, min(1, sentiment)), 3),
            "date": d, "cid": f"{self.name}-{len(self.entries):04d}",
        })


def gen_maya(p: Persona):
    """Work dread on Sundays + recurring sleep worry with next-day dips."""
    p.expected = ["temporal (work -> Sundays)", "mood_correlation (work days lower)",
                  "link (day after sleep worry reads lower)",
                  "rumination / recurring_phrase (the worry)"]
    used: dict[int, int] = {}
    low_dates: set[date] = set()
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        base = p.rng.uniform(-0.15, 0.15)
        p.add(d, p.filler(used), base)  # morning filler
        evening, sent = p.filler(used), base
        if d.weekday() == 6:  # Sunday: work dread
            evening = "the week is looming, big deadline pressure at work again"
            sent = p.rng.uniform(-0.75, -0.55)
        elif d.weekday() in (0, 2, 4) and p.rng.random() < 0.85:  # M/W/F nights
            evening = "went to bed late. " + p.rng.choice(SLEEP_WORRY)
            sent = p.rng.uniform(-0.5, -0.3)
            low_dates.add(d + timedelta(days=1))
        else:
            evening = evening + ". quiet night"
        p.add(d, evening, sent)
    for e in p.entries:  # the day after a worry night reads low
        if e["date"] in low_dates:
            e["sentiment"] = round(min(e["sentiment"], p.rng.uniform(-0.75, -0.55)), 3)


def gen_omar(p: Persona):
    """Stable mood; a hobby topic that RISES over the last three weeks."""
    p.expected = ["topic (guitar rising)", "(little else — stable baseline)"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = p.rng.uniform(0.0, 0.25)
        p.add(d, p.filler(used), s)
        text = p.filler(used)
        if i in (6, 20, 33):  # sparse early base
            text += ". messed around on the guitar for a bit"
        elif i >= 40 and i % 2 == 0:  # dense late window, varied phrasing
            text += ". " + p.rng.choice(GUITAR)
        p.add(d, text, s + p.rng.uniform(-0.05, 0.05))


def gen_priya(p: Persona):
    """Scrolling nights read low that day; late decline + carryover + swings."""
    p.expected = ["mood_correlation (scrolling nights <-> lower days)",
                  "mood_shift (late decline)", "inertia (day-to-day carryover)"]
    used: dict[int, int] = {}
    carry = 0.0
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        late = i >= DAYS - 25
        phi, amp = (0.72, 0.85) if late else (0.1, 0.12)
        carry = phi * carry + (1 - phi) * p.rng.uniform(-amp, amp)
        s = 0.05 + carry - (0.75 if late else 0.0)
        scroll_day = late is False and p.rng.random() < 0.42
        if scroll_day:
            s = p.rng.uniform(-0.7, -0.45)
        p.add(d, p.filler(used), s)
        evening = p.filler(used)
        if scroll_day:
            evening += ". " + p.rng.choice(SCROLL)
        p.add(d, evening, s + p.rng.uniform(-0.05, 0.05))
        if p.rng.random() < 0.12:  # some days a third short entry
            p.add(d, "short note: drank enough water today", s)


def gen_lena(p: Persona):
    """Family visits every ~week with next-day dips; Sunday grandma calls."""
    p.expected = ["link (day after family visits reads lower)",
                  "temporal (family mentions / Sundays)"]
    used: dict[int, int] = {}
    family_days = set()
    i = 3
    while i < DAYS - 3:
        family_days.add(i)
        i += 7 + p.rng.randrange(2)
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = p.rng.uniform(-0.05, 0.25)
        if i and (i - 1) in family_days:  # day after a visit
            s = p.rng.uniform(-0.8, -0.6)
        p.add(d, p.filler(used), s)
        evening = p.filler(used)
        if i in family_days:
            evening += ". visited the family, mom and dad were there"
        if d.weekday() == 6:
            evening += ". called grandma like every sunday"
            p.add(d, evening, s)
            p.add(d, "long slow dinner afterwards", s - 0.05)
            continue
        p.add(d, evening, s + p.rng.uniform(-0.05, 0.05))


def gen_tom(p: Persona):
    """Control: pure noise, no planted structure. Should surface nothing."""
    p.expected = ["NOTHING (false-positive control)"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        if p.rng.random() < 0.12:
            continue  # tom skips some days, like a real user
        s = p.rng.uniform(-0.35, 0.35)
        p.add(d, p.filler(used), s)
        if p.rng.random() < 0.5:
            p.add(d, p.filler(used), s + p.rng.uniform(-0.1, 0.1))


# ------------------------------------------------------------------ client ----


class Client:
    def __init__(self, username, password):
        self.username = username
        self.salt = os.urandom(16)
        master = kdf.derive_master_key(password, self.salt)
        self.auth_key = kdf.derive_auth_key(master)
        self.data_key = kdf.derive_data_key(master)
        self.user_id = None
        self.token = None

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def encrypt(self, e: dict) -> str:
        payload = {"v": 1, "text": e["text"], "sentiment": e["sentiment"],
                   "created_at": e["date"].isoformat()}
        blob = crypto.encrypt(self.data_key, json.dumps(payload).encode(),
                              crypto.build_aad("entry", self.user_id, e["cid"]))
        return base64.b64encode(blob).decode()


async def req(c, method, path, **kw):
    for attempt in range(8):
        r = await c.request(method, path, **kw)
        if r.status_code == 429 and attempt < 7:
            await asyncio.sleep(float(r.headers.get("retry-after", "20")) + 1)
            continue
        return r
    return r


async def age_account(user_id, days):
    engine = create_async_engine(DB_URL)
    async with build_sessionmaker(engine)() as s:
        from app.models import utcnow
        await s.execute(
            __import__("sqlalchemy").update(User).where(User.id == user_id)
            .values(created_at=utcnow() - timedelta(days=days)))
        await s.commit()
    await engine.dispose()


# ------------------------------------------------------------------- replay ----


def replay(persona: Persona, single_shot: bool = False):
    """Clock-accurate per-day replay.

    single_shot=False: recompute every day past the 30-active-day threshold,
    exactly like the real app syncing daily — the full 60-day story.
    single_shot=True: ONE recompute on the final day — the "fresh account
    with imported history" view, comparable to a single live API recompute.

    Returns (final_patterns, timeline, first_day_map).
    """
    entries = [JournalEntry(text=e["text"], entry_date=e["date"],
                            sentiment=e["sentiment"]) for e in persona.entries]
    state = None
    seen_pids: dict[str, dict] = {}   # pid -> {kind,label,first_day,state}
    timeline: list[dict] = []
    final_patterns: list[dict] = []
    distinct_dates: set[date] = set()
    idx = 0
    for day_offset in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - day_offset)
        while idx < len(entries) and entries[idx].entry_date <= d:
            distinct_dates.add(entries[idx].entry_date)
            idx += 1
        row = {"day": day_offset + 1, "date": d.isoformat(),
               "active_days": len(distinct_dates), "recomputed": False,
               "surfaced": 0, "new": [], "transitions": []}
        last_day = day_offset == DAYS - 1
        if len(distinct_dates) >= 30 and (not single_shot or last_day):
            row["recomputed"] = True
            result = brain.update(state, entries[:idx], d)
            state = result.new_state
            pats = []
            for p in result.surfaced:
                pid = p.detail.get("pattern_pid", "?")
                pats.append({"pid": pid, "kind": p.kind, "label": p.label,
                             "state": p.detail.get("pattern_state", "?"),
                             "occurrences": p.occurrences})
                prev = seen_pids.get(pid)
                if prev is None:
                    seen_pids[pid] = {"kind": p.kind, "label": p.label,
                                      "first_day": day_offset + 1,
                                      "state": p.detail.get("pattern_state", "?")}
                    row["new"].append(f"{p.kind}: {p.label[:48]}")
                elif prev["state"] != p.detail.get("pattern_state"):
                    row["transitions"].append(
                        f"{p.kind} '{p.label[:32]}' {prev['state']} -> "
                        f"{p.detail.get('pattern_state')}")
                    prev["state"] = p.detail.get("pattern_state")
            row["surfaced"] = len(pats)
            if last_day:
                final_patterns = pats
        timeline.append(row)
    return final_patterns, timeline, seen_pids


# --------------------------------------------------------------------- main ----


async def run():
    print(f"target {BASE_URL} | db {DB_URL} | {DAYS} days, 5 users\n")
    personas = [
        Persona("maya", "maya-sim-pass-1", 21, "work-dread Sundays + sleep worry with next-day dips"),
        Persona("omar", "omar-sim-pass-2", 22, "stable; guitar topic rising in the last 3 weeks"),
        Persona("priya", "priya-sim-pass-3", 23, "scrolling nights read low; late decline + inertia + swings"),
        Persona("lena", "lena-sim-pass-4", 24, "family visits with next-day dips; Sunday grandma calls"),
        Persona("tom", "tom-sim-pass-5", 25, "CONTROL: pure noise, no planted structure"),
    ]
    generators = {"maya": gen_maya, "omar": gen_omar, "priya": gen_priya,
                  "lena": gen_lena, "tom": gen_tom}
    for p in personas:
        generators[p.name](p)

    report: dict = {"days": DAYS, "users": []}
    async with httpx.AsyncClient(base_url=BASE_URL, timeout=120) as c:
        for p in personas:
            print(f"=== {p.name}: {p.blurb}")
            print(f"    {len(p.entries)} entries over "
                  f"{len({e['date'] for e in p.entries})} active days, "
                  f"{max(1, len(p.entries) // max(1, DAYS))}+/day")
            cl = Client(p.name, p.password)
            r = await req(c, "POST", "/api/auth/register", json={
                "username": p.name, "salt": base64.b64encode(cl.salt).decode(),
                "verifier": base64.b64encode(cl.auth_key).decode()})
            assert r.status_code == 201, r.text
            cl.user_id, cl.token = r.json()["user_id"], r.json()["token"]
            await age_account(cl.user_id, DAYS + 2)

            t0 = asyncio.get_event_loop().time()
            ok = fail = 0
            for e in p.entries:
                r = await req(c, "POST", "/api/entries", headers=cl.headers, json={
                    "client_entry_id": e["cid"], "blob": cl.encrypt(e),
                    "entry_date": e["date"].isoformat()})
                ok += r.status_code == 201
                fail += r.status_code != 201
            sync_secs = asyncio.get_event_loop().time() - t0

            ps = await req(c, "POST", "/api/processing/sessions", headers=cl.headers,
                           json={"data_key": base64.b64encode(cl.data_key).decode()})
            r = await req(c, "POST", "/api/insights/recompute",
                          headers={**cl.headers,
                                   "X-Processing-Token": ps.json()["session_token"]})
            live = r.json()
            r = await req(c, "GET", "/api/insights", headers=cl.headers)
            blob = r.json()["blob"]
            payload = json.loads(crypto.decrypt(
                cl.data_key, base64.b64decode(blob),
                crypto.build_aad("insights", cl.user_id, "patterns")))
            live_patterns = payload["stats"]["patterns"]
            live_set = {(x["kind"], x["label"]) for x in live_patterns}

            final_patterns, timeline, first_days = replay(p)
            single_shot_patterns, _, _ = replay(p, single_shot=True)
            replay_set = {(x["kind"], x["label"]) for x in final_patterns}
            single_set = {(x["kind"], x["label"]) for x in single_shot_patterns}
            match = live_set == single_set

            q = questions.question_for_today(cl.user_id, [
                Pattern_shim(x) for x in live_patterns], TODAY) if live_patterns else None

            print(f"    live recompute: phase={live['phase']} "
                  f"active_days={live['active_days']} patterns={live['patterns_stored']} "
                  f"(sync {ok}/{ok + fail} entries in {sync_secs:.0f}s)")
            print(f"    determinism (live == single-shot replay): {match}")
            print(f"    --- what a REAL daily user sees by day 60 "
                  f"(30 daily recomputes): {len(final_patterns)} patterns ---")
            for x in final_patterns:
                fd = next((v["first_day"] for v in first_days.values()
                           if v["kind"] == x["kind"] and v["label"] == x["label"]), "?")
                st = x["state"]
                print(f"      day {str(fd):>3} [{st:9}] {x['kind']:17} "
                      f"{x['label'][:56]} (n={x['occurrences']})")
            if not final_patterns:
                print("      (nothing surfaced)")
            print(f"    --- fresh-account single recompute view: "
                  f"{len(live_patterns)} patterns (direct-measurement kinds only) ---")

            report["users"].append({
                "name": p.name, "blurb": p.blurb, "expected": p.expected,
                "entries": len(p.entries),
                "active_days": live["active_days"],
                "patterns_live": live_patterns,
                "patterns_replay_daily": final_patterns,
                "patterns_replay_singleshot": single_shot_patterns,
                "pattern_first_day": {f"{v['kind']}|{v['label']}": v["first_day"]
                                      for v in first_days.values()},
                "determinism_live_eq_singleshot": match,
                "question_today": q,
                "timeline": timeline,
                "user_id": cl.user_id,
            })

    # ---- storage metrics straight from the database ----
    engine = create_async_engine(DB_URL)
    async with build_sessionmaker(engine)() as s:
        rows = (await s.execute(
            select(Entry.user_id, func.count(Entry.id), func.sum(func.length(Entry.blob)))
            .group_by(Entry.user_id))).all()
        entry_stats = {r[0]: (r[1], int(r[2] or 0)) for r in rows}
        ins_rows = (await s.execute(
            select(Insight.user_id, Insight.kind, func.count(Insight.id),
                   func.sum(func.length(Insight.blob)))
            .group_by(Insight.user_id, Insight.kind))).all()
        insight_stats = {}
        for uid, kind, n, b in ins_rows:
            insight_stats.setdefault(uid, {})[kind] = (n, int(b or 0))
        sample = (await s.execute(select(Entry).limit(1))).scalar_one()
        sample_row = {
            "client_entry_id": sample.client_entry_id,
            "entry_date": sample.entry_date.isoformat(),
            "blob_prefix_hex": bytes(sample.blob)[:24].hex(),
            "blob_len": len(bytes(sample.blob)),
        }
        tables = (await s.execute(
            __import__("sqlalchemy").text(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"))
        ).scalars().all()
    await engine.dispose()
    report["tables_in_db"] = list(tables)

    for u in report["users"]:
        n, b = entry_stats.get(u["user_id"], (0, 0))
        u["storage"] = {
            "entry_rows": n, "entry_ciphertext_bytes": b,
            "insights": {k: {"rows": v[0], "bytes": v[1]}
                         for k, v in insight_stats.get(u["user_id"], {}).items()},
        }
    report["sample_entry_row_at_rest"] = sample_row

    out = Path(__file__).parent / "results.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f"\nwrote {out}")
    return report


class Pattern_shim:
    """questions.question_for_today expects Pattern objects; minimal shim."""
    def __init__(self, d):
        self.kind = d["kind"]
        self.label = d["label"]
        self.occurrences = d.get("occurrences", 0)
        self.confidence = d.get("confidence", 0.0)
        self.detail = d.get("detail", {})


if __name__ == "__main__":
    asyncio.run(run())
