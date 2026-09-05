"""Seed a demo account with a realistic journal + computed insights.

Purpose: the 30-day threshold is honest product design, but it makes the
mini-brain unjudgeable in a demo — so this script creates an account whose
journal already has 70 days of history with planted, realistic structure
(Sunday work dread, a returning worry, family visits with next-day dips, a
late rough patch), runs a real recompute through the real API, and prints
what the brain surfaced. Judges can then sign into the app with the
printed credentials and see the same insights the script verified.

The crypto is the real client-side stack (app.security.kdf/crypto — the
same code the mobile app mirrors, pinned by shared/vectors.json): the
server only ever receives opaque blobs and one single-use data key.

Usage (backend running on localhost:8000):
    ../.venv/bin/python scripts/seed_demo.py --username demo --password 'correct horse battery staple'
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import random
import sys
import time
from datetime import date, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx

from app.security import crypto
from app.security import kdf as keyderive

FILLERS = [
    "read a few pages of the novel before lights out",
    "rearranged the kitchen shelves and found old receipts",
    "listened to a podcast on the commute home",
    "watered all the plants on the balcony",
    "tried a new recipe with lentils and rice",
    "fixed the squeaky door hinge at last",
    "walked past the old bookshop after lunch",
    "wrote a letter to my cousin overseas",
    "sorted through the photo box from the move",
    "repaired the bike tire in the garage",
    "watched the rain from the window with tea",
    "organized the desk drawers and old cables",
    "cooked soup for tomorrow and froze half",
    "stretched out on the couch for a while",
    "sketched the view from the kitchen window",
    "practiced chords until my fingers hurt",
    "paid the utilities and filed the receipt",
    "cleaned the bathroom and changed the sheets",
    "backed up the laptop and cleared the desktop",
    "called the pharmacy about the prescription",
    "took the long way home through the park",
    "mended the seam on my winter coat",
    "bought oranges and bread from the corner shop",
    "renewed the library books online",
    "moved the compost and planted basil",
    "ironed shirts while the race was on",
    "tidied the hallway and the shoe rack",
    "brewed proper coffee instead of instant",
    "changed the burnt bulb in the hallway",
    "drafted the card for my neighbor's birthday",
    "sewed the loose button back on my jacket",
    "took the recycling down and swept the stairs",
    "looked up train times for the weekend trip",
    "replaced the filter in the kitchen extractor",
    "archived last year's paperwork into the box",
    "set the alarm and laid out clothes for tomorrow",
    "answered the group chat and caught up on messages",
    "trimmed the hedge before the rain came in",
    "measured the hallway for the new shelf",
]
SLEEP_WORRY = [
    "i can't sleep, my mind won't stop",
    "i can't sleep, my mind just won't stop tonight",
    "can't sleep, my mind won't stop racing",
]
POSITIVE = [
    "felt genuinely good today, calm and rested",
    "great day, laughed a lot with friends, grateful",
    "peaceful morning, productive afternoon, feeling hopeful",
]
# A non-lexicon topic, phrased differently every time, RISING in the late
# window — the demo of emergent topic discovery (audit finding #2).
GUITAR_VARIANTS = [
    "spent the evening with the guitar, learning fingerpicking",
    "practiced guitar scales after dinner",
    "wrote a riff on the guitar tonight",
    "guitar practice again, the chords are getting cleaner",
    "jammed on the guitar for a while",
]

NEGATIVE = [
    "felt low and drained, hard to focus",
    "anxious all day, overwhelmed and tense",
    "sad and empty tonight, nothing helped",
    "worn out and irritable by the afternoon",
    "a heavy, grey feeling settled in early",
    "kept putting things off and felt worse for it",
    "tense shoulders and a racing heart all evening",
    "numb and disconnected most of the day",
    "quietly down, like the volume was turned too low",
    "snapped at someone small and regretted it",
]


def build_corpus(end: date, days: int, seed: int) -> list[dict]:
    """A deterministic journal with realistic planted structure."""
    rng = random.Random(seed)
    start = end - timedelta(days=days - 1)

    # Mood stream: gentle noise; the final ~3 weeks carry a decline,
    # stronger day-to-day carryover and wider swings.
    mood: dict[date, float] = {}
    carry = 0.0
    day = start
    while day <= end:
        if day >= end - timedelta(days=27):
            phi, amplitude = 0.60, 0.70
        else:
            phi, amplitude = 0.05, 0.15
        carry = phi * carry + (1 - phi) * rng.uniform(-amplitude, amplitude)
        value = 0.05 + carry
        if day >= end - timedelta(days=20):
            value -= 0.55
        mood[day] = max(-1.0, min(1.0, value))
        day += timedelta(days=1)

    # Family visits: ~9 days spread out; the day after each reads low.
    family_days = set()
    day = start + timedelta(days=6)
    while day <= end - timedelta(days=6):
        family_days.add(day)
        day += timedelta(days=7 + rng.randrange(3))
    for d in family_days:
        for k in (1, 2):
            if d + timedelta(days=k) in mood:
                mood[d + timedelta(days=k)] = min(mood[d + timedelta(days=k)], -0.55)
    for d in mood:
        if d.weekday() == 6:  # Sundays: the work dread
            mood[d] = min(mood[d], -0.45)

    worry_days = set()
    day = start + timedelta(days=5)
    while day <= end - timedelta(days=2):
        worry_days.add(day)
        day += timedelta(days=6 + rng.randrange(2))

    # Rising topic schedule: a tiny early base, ~11 mentions in the last
    # six weeks (every other day, skipping Wednesdays).
    guitar_days = set()
    day = end - timedelta(days=40)
    while len(guitar_days) < 11 and day <= end:
        if day.weekday() != 2:
            guitar_days.add(day)
        day += timedelta(days=2)
    guitar_early = {start + timedelta(days=9), start + timedelta(days=24)}
    guitar_idx = 0

    entries: list[dict] = []
    filler_uses: dict[int, int] = {}
    day = start
    while day <= end:
        wd = day.weekday()
        planted = (wd == 6 or day in family_days or day in worry_days
                   or day in guitar_days or day in guitar_early)
        # Planted days always write (the demo's structure must not be
        # gambled away by the skip draw); filler days skip like a real user.
        if planted or (wd != 2 and rng.random() < 0.85):
            available = [i for i in range(len(FILLERS)) if filler_uses.get(i, 0) < 2]
            if available:
                choice = rng.choice(available)
                filler_uses[choice] = filler_uses.get(choice, 0) + 1
                text = FILLERS[choice]
            else:
                # Capacity exhausted (large --days): the day carries only its
                # planted sentence — never an IndexError, never a synthetic
                # near-duplicate filler.
                text = ""
            if wd == 6:
                text = "big deadline pressure at work again, boss emailed twice about monday"
            if day in family_days:
                text += ". visited the family, mom and dad were there"
            if day in worry_days:
                text += ". " + rng.choice(SLEEP_WORRY)
            if day in guitar_early:
                text += ". messed around on the guitar for a bit"
            if day in guitar_days:
                text += ". " + GUITAR_VARIANTS[guitar_idx % len(GUITAR_VARIANTS)]
                guitar_idx += 1
            m = mood[day]
            if m > 0.35:
                text += ". " + rng.choice(POSITIVE)
            elif m < -0.35:
                text += ". " + rng.choice(NEGATIVE)
            entries.append({"text": text, "date": day.isoformat(), "sentiment": round(m, 3)})
        day += timedelta(days=1)
    return entries


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="http://127.0.0.1:8000")
    parser.add_argument("--username", default="demo")
    parser.add_argument("--password", default="demo-patterns-2026")
    parser.add_argument("--days", type=int, default=84)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--db-url", default=None,
                        help="SQLAlchemy URL of the API database — needed once to backdate the demo account's created_at (see below)")
    args = parser.parse_args()

    client = httpx.Client(base_url=args.base_url, timeout=30)

    salt = os.urandom(16)
    master = keyderive.derive_master_key(args.password, salt)
    auth_key = keyderive.derive_auth_key(master)
    data_key = keyderive.derive_data_key(master)
    verifier_b64 = base64.b64encode(auth_key).decode()

    # Register (login if the name is taken, e.g. on a re-run).
    register = client.post("/api/auth/register", json={
        "username": args.username,
        "salt": base64.b64encode(salt).decode(),
        "verifier": verifier_b64,
    })
    if register.status_code == 409:
        login = client.post("/api/auth/login", json={
            "username": args.username, "verifier": verifier_b64,
        })
        login.raise_for_status()
        session = login.json()
    else:
        register.raise_for_status()
        session = register.json()
    token = session["token"]
    user_id = session["user_id"]
    headers = {"Authorization": f"Bearer {token}"}
    print(f"account: {args.username} (user {user_id[:8]}…)")

    # Threshold honesty blocks entries predating the account — by design.
    # A demo account must therefore have actually started {days} days ago:
    # when given the DB URL, backdate THIS user's created_at (the demo
    # story is an account with history; no API invariant is weakened).
    if args.db_url:
        import asyncio
        from datetime import datetime, timezone as tz

        from sqlalchemy import update
        from app.db import build_sessionmaker
        from app.models import User

        async def backdate() -> None:
            from sqlalchemy.ext.asyncio import create_async_engine
            engine = create_async_engine(args.db_url)
            Session = build_sessionmaker(engine)
            async with Session() as db:
                await db.execute(
                    update(User)
                    .where(User.id == user_id)
                    .values(created_at=datetime.now(tz.utc) - timedelta(days=args.days + 2))
                )
                await db.commit()
            await engine.dispose()

        asyncio.run(backdate())
        print(f"account history backdated {args.days + 2} days (demo story)")

    corpus = build_corpus(date.today(), args.days, args.seed)
    print(f"seeding {len(corpus)} encrypted entries over {args.days} days…")
    for item in corpus:
        payload = json.dumps({
            "v": 1,
            "text": item["text"],
            "sentiment": item["sentiment"],
            "created_at": item["date"],
        }).encode()
        blob = crypto.encrypt(
            data_key, payload,
            crypto.build_aad("entry", user_id, f"e-{item['date']}-{item['date'][5:]}"),
        )
        body = {
            "client_entry_id": f"e-{item['date']}-{item['date'][5:]}",
            "blob": base64.b64encode(blob).decode(),
            "entry_date": item["date"],
        }
        for attempt in range(3):
            created = client.post("/api/entries", headers=headers, json=body)
            if created.status_code == 429 and attempt < 2:
                time.sleep(20)  # entry rate limit (default 120/min)
                continue
            break
        if created.status_code == 409:  # re-run: same entry id already synced
            continue
        created.raise_for_status()

    # One single-use processing session, then the recompute.
    ps = client.post("/api/processing/sessions", headers=headers,
                     json={"data_key": base64.b64encode(data_key).decode()})
    ps.raise_for_status()
    recompute = client.post("/api/insights/recompute", headers={
        **headers, "x-processing-token": ps.json()["session_token"],
    })
    recompute.raise_for_status()
    result = recompute.json()
    print(f"recompute: phase={result['phase']} active_days={result['active_days']} "
          f"analyzer={result['analyzer']} patterns={result['patterns_stored']} "
          f"question_stored={result['question_stored']}")

    insights = client.get("/api/insights", headers=headers)
    insights.raise_for_status()
    blob_b64 = insights.json().get("blob")
    if not blob_b64:
        print("no insight blob stored")
        return 1
    plain = crypto.decrypt(
        data_key, base64.b64decode(blob_b64),
        crypto.build_aad("insights", user_id, "patterns"),
    )
    payload = json.loads(plain.decode())
    print(f"\n=== surfaced patterns ({len(payload['stats']['patterns'])}) ===")
    for p in payload["stats"]["patterns"]:
        state = p["detail"].get("pattern_state", "?")
        print(f"  [{state:9}] {p['kind']:18} {p['label'][:60]}")
    print(f"\nSign into the app →  username: {args.username}   password: {args.password}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
