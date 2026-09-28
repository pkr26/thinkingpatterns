#!/usr/bin/env python3
"""365-day, 10-user MindPattern end-to-end simulation + full-API campaign.

Successor of reports/simulation60 (60 days, 5 users, 5 endpoints): the
same live-API philosophy — every entry synced through the real server
with the real client crypto — extended to a full year, ten personas,
and EVERY route the backend mounts (52 endpoints), plus every
functionality that only a year of data exercises:

  * pattern lifecycles over 12 months (candidate -> emerging ->
    confirmed, fade + re-qualification), replayed clock-accurately per
    simulated day through the SAME brain code the server runs;
  * determinism cross-check: the LIVE API recompute must surface
    exactly what a single-shot offline replay surfaces;
  * a pure-noise CONTROL user for 365 days: no statistical kind may
    ever surface for them (the FDR gates under a year of pressure);
  * crisis-language persona: sensitive-flagging, non-quoting questions;
  * structured channels (payload v2: energy/sleep/tags/tod);
  * PHQ-9-style encrypted measures over the whole year, patient side
    AND therapist side;
  * the zero-knowledge sharing lifecycle: pairing + SAS verification on
    both ends, grant, therapist reads (insights/entries/measures),
    notes with versions + revisions + idempotent retries, revoke,
    re-grant, therapist wrap-key rotation + patient rewrap, caseload
    summaries;
  * key lifecycle: full data-key rekey (old->new processing sessions),
    v1->v2 envelope upgrade, O(1) v2 password change (consents must
    survive it — same data key);
  * TOTP 2FA (therapist role): setup/enable/login/backup codes/replay/
    disable;
  * export bundles decrypted locally; access logs (patient + therapist)
    with cursor pagination; credential rotation; logout; hard account
    deletion (decoy salt, username recycling);
  * negative paths: wrong verifiers, dead tokens, stale revisions,
    duplicate ids, out-of-range dates, oversize bodies, role
    boundaries, cross-therapist isolation;
  * at-rest zero-knowledge: every stored blob column is ciphertext and
    the raw database file contains none of the journal plaintext;
  * rate limiting verified against the default ops bucket.

Every check prints [PASS]/[FAIL]; the process exits non-zero if any
check failed. Outputs: results.json, timeline_<user>.csv, stdout log.
"""

from __future__ import annotations

import asyncio
import base64
import csv
import json
import os
import random
import re
import sys
import time as walltime
from datetime import date, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))
REPO = BACKEND.parent

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import create_async_engine

from app.db import build_sessionmaker
from app.models import User, utcnow
from app.security import crypto, envelope as envelope_crypto, kdf
from app.security import sharing as sharing_crypto
from app.security import totp as totp_mod
from app.services import brain, questions
from app.services.brain import STATISTICAL_KINDS
from app.services.patterns import JournalEntry

BASE_URL = os.environ.get("E2E_BASE", "http://127.0.0.1:8908")
DB_URL = os.environ.get("E2E_DB", f"sqlite+aiosqlite:///{BACKEND / 'sim1y.db'}")
DAYS = 365
TODAY = date.today()

# ------------------------------------------------------------------ checks ----

CHECKS: list[dict] = []
_PHASE = ["0 · boot"]


def phase(title: str) -> None:
    _PHASE[0] = title
    print(f"\n--- {title} ---")


def check(name: str, ok: bool, extra: str = "") -> bool:
    tag = "PASS" if ok else "FAIL"
    print(f"[{tag}] {name}" + (f" ({extra})" if extra else ""))
    CHECKS.append({"phase": _PHASE[0], "name": name, "ok": bool(ok),
                   "extra": extra})
    return bool(ok)


async def req(c, method, path, **kw):
    """Request with 429 honouring (raised buckets make this rare)."""
    for attempt in range(10):
        r = await c.request(method, path, **kw)
        if r.status_code == 429 and attempt < 9:
            await asyncio.sleep(float(r.headers.get("retry-after", "5")) + 0.5)
            continue
        return r
    return r


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
SCROLL = [
    "wasted the whole evening scrolling, eyes tired",
    "doomscrolling again until midnight, feel foggy",
    "screens all evening, head buzzing afterwards",
    "fell down the feed again, regret it every time",
]
GUITAR_VERBS = [
    "played", "practiced", "picked up", "strummed", "tuned", "sat with",
    "noodled on", "rehearsed on", "warmed up on", "improvised on",
]
GUITAR_TAILS = [
    "for a while", "after dinner", "before bed", "for twenty minutes",
    "with the new picks", "along to a record", "by the window",
    "until my hands got tired", "working through the lesson book",
    "trying a new riff",
]


def _guitar_sentence(rng: random.Random) -> str:
    # combinatorial: the WORD guitar recurs across near-unique sentences,
    # so the topic rises without any single sentence clustering
    return f"{rng.choice(GUITAR_VERBS)} the guitar {rng.choice(GUITAR_TAILS)}"


GUITAR_EARLY = [
    "messed around on the guitar for a bit",
    "picked up the guitar briefly before bed",
    "strummed the guitar for a few minutes",
    "tuned the guitar and played quietly",
]
CRISIS = [
    "i want to disappear, i can't take this anymore",   # canonical
    "i want to disappear, i can't take this anymore",
    "i want to disappear, i can't take this anymore",
    "i want to disappear, this is too much for me",     # near-dup variant
]
RUN = [
    "went for a run by the river",
    "running intervals at the track",
    "an easy run around the park",
    "ran the hilly loop, legs like jelly",
]
DEADLINE = [
    "buried under deadline pressure again",
    "the project deadline is eating me alive",
    "another late night grinding on the deadline",
]


class Persona:
    def __init__(self, name, password, seed, blurb):
        self.name, self.password, self.blurb = name, password, blurb
        self.rng = random.Random(seed)
        self.entries: list[dict] = []
        self.expected: list[str] = []
        self.edits: list[tuple[str, str, float]] = []   # cid, new_text, sent
        self.deletes: list[str] = []

    def filler(self, used):
        best = min(range(len(FILLERS)), key=lambda i: used.get(i, 0))
        used[best] = used.get(best, 0) + 1
        return FILLERS[best]

    def add(self, d, text, sentiment, **extra):
        row = {"text": text, "sentiment": round(max(-1, min(1, sentiment)), 3),
               "date": d, "cid": f"{self.name}-{len(self.entries):04d}"}
        row.update(extra)
        self.entries.append(row)


def gen_maya(p: Persona):
    """Work dread on Sundays + recurring sleep worry with next-day dips."""
    p.expected = ["temporal (work -> Sundays)", "link (day after sleep worry)",
                  "rumination / recurring_phrase (the worry)"]
    used: dict[int, int] = {}
    low_dates: set[date] = set()
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        base = p.rng.uniform(-0.15, 0.15)
        p.add(d, p.filler(used), base)
        evening, sent = p.filler(used), base
        if d.weekday() == 6:
            evening = "the week is looming, big deadline pressure at work again"
            sent = p.rng.uniform(-0.75, -0.55)
        elif d.weekday() in (0, 2, 4) and p.rng.random() < 0.8:
            evening = "went to bed late. " + p.rng.choice(SLEEP_WORRY)
            sent = p.rng.uniform(-0.5, -0.3)
            low_dates.add(d + timedelta(days=1))
        else:
            evening += ". quiet night"
        p.add(d, evening, sent)
    for e in p.entries:
        if e["date"] in low_dates:
            e["sentiment"] = round(min(e["sentiment"], p.rng.uniform(-0.75, -0.55)), 3)


def gen_omar(p: Persona):
    """Stable mood; a hobby topic that RISES over the last three months
    (varied phrasings throughout, so the TOPIC rises rather than any one
    sentence clustering into a recurring-phrase card)."""
    p.expected = ["topic (guitar rising)", "(little else — stable baseline)"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = p.rng.uniform(0.0, 0.25)
        p.add(d, p.filler(used), s)
        text = p.filler(used)
        if i % 9 == 4:                       # sparse, VARIED early base
            text += ". " + p.rng.choice(GUITAR_EARLY)
        elif i >= DAYS - 90 and i % 2 == 0:  # dense late window, unique-ish
            text += ". " + _guitar_sentence(p.rng)
        p.add(d, text, s + p.rng.uniform(-0.05, 0.05))


def gen_priya(p: Persona):
    """Scrolling nights read low; late-year decline + carryover + swings."""
    p.expected = ["mood_correlation (scrolling nights <-> lower days)",
                  "mood_shift (late decline)", "inertia (day-to-day carryover)"]
    used: dict[int, int] = {}
    carry = 0.0
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        late = i >= DAYS - 90
        phi, amp = (0.72, 0.85) if late else (0.1, 0.12)
        carry = phi * carry + (1 - phi) * p.rng.uniform(-amp, amp)
        s = 0.05 + carry - (0.75 if late else 0.0)
        scroll_day = (not late) and p.rng.random() < 0.4
        if scroll_day:
            s = p.rng.uniform(-0.7, -0.45)
        p.add(d, p.filler(used), s)
        evening = p.filler(used)
        if scroll_day:
            evening += ". " + p.rng.choice(SCROLL)
        p.add(d, evening, s + p.rng.uniform(-0.05, 0.05))
        if p.rng.random() < 0.12:
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
        if i and (i - 1) in family_days:
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
    """CONTROL: pure noise for a full year. No statistical kind may surface."""
    p.expected = ["NO statistical kinds (false-positive control, 365 days)"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        if p.rng.random() < 0.12:
            continue
        s = p.rng.uniform(-0.35, 0.35)
        p.add(d, p.filler(used), s)
        if p.rng.random() < 0.5:
            p.add(d, p.filler(used), s + p.rng.uniform(-0.1, 0.1))


def gen_ava(p: Persona):
    """Slow year arc: decline through the middle months, recovery at the end;
    running days consistently read higher."""
    p.expected = ["mood_shift (decline then recovery)", "mood_correlation (run days higher)"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        frac = i / DAYS
        if frac < 0.3:
            trend = 0.15
        elif frac < 0.75:
            trend = 0.15 - 0.95 * (frac - 0.3) / 0.45
        else:
            trend = -0.8 + 0.9 * (frac - 0.75) / 0.25
        run_day = p.rng.random() < 0.35 and d.weekday() in (1, 3, 5)
        s = trend + p.rng.uniform(-0.12, 0.12) + (0.35 if run_day else 0.0)
        p.add(d, p.filler(used), s)
        text = p.filler(used)
        if frac >= 0.3 and frac < 0.75 and p.rng.random() < 0.3:
            text += ". " + p.rng.choice(DEADLINE)
        if run_day:
            text += ". " + p.rng.choice(RUN)
        p.add(d, text, s + p.rng.uniform(-0.05, 0.05))


def gen_ben(p: Persona):
    """Structured channels (v2 payload): rated sleep + energy + tags + tod;
    PHQ-9 measures every 2 weeks with slowly improving scores."""
    p.expected = ["link (rough rated nights -> next day lower)",
                  "cadence (daily)", "measures trend improving all year"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        poor = p.rng.random() < 0.3
        sleep_rating = p.rng.choice([1, 2] if poor else [3, 4, 5])
        s = p.rng.uniform(-0.05, 0.2) - (0.25 if poor else 0.0)
        p.add(d, p.filler(used), s,
              payload_v=2, energy=round(max(-1, min(1, s)), 3),
              sleep=sleep_rating, tags=["work", "routine"], tod="morning")
        evening = p.filler(used)
        if poor:
            evening += ". rough night, kept waking up"
        p.add(d, evening, s + p.rng.uniform(-0.05, 0.05),
              payload_v=2, energy=round(max(-1, min(1, s - 0.1)), 3),
              sleep=sleep_rating, tags=["work"], tod="evening")
    # measures: PHQ-9 every 14 days, score easing 14 -> 4
    n = DAYS // 14
    for k in range(n):
        d = TODAY - timedelta(days=DAYS - 1 - 14 * k)
        score = round(14 - 10 * (k / max(1, n - 1)) + p.rng.uniform(-1, 1))
        p.measures.append({"date": d, "score": max(2, min(16, score)),
                           "cid": f"{p.name}-phq9-{k:02d}"})
    p.expected_tools = ["measures: " + str(n) + " PHQ-9 completions"]


def gen_chloe(p: Persona):
    """Crisis episodes every ~10 days: flagged sensitive, never quoted."""
    p.expected = ["rumination/sensitive (crisis phrase cluster)",
                  "question must never quote crisis language"]
    used: dict[int, int] = {}
    episode_days = set()
    i = 8
    while i < DAYS - 5:
        episode_days.add(i)
        i += 9 + p.rng.randrange(3)
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = p.rng.uniform(-0.3, 0.1)
        p.add(d, p.filler(used), s)
        if i in episode_days:
            p.add(d, p.rng.choice(CRISIS), p.rng.uniform(-0.92, -0.8))
            p.add(d, "everything felt heavy again tonight", p.rng.uniform(-0.7, -0.55))
        else:
            p.add(d, p.filler(used) + ". okay day overall", s + p.rng.uniform(-0.05, 0.05))


def gen_dev(p: Persona):
    """Editor: weekly work stress + revises ~8% of entries, deletes ~12."""
    p.expected = ["temporal (weekly work stress)",
                  "edit/delete lifecycle keeps analysis consistent"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        base = p.rng.uniform(-0.1, 0.2)
        p.add(d, p.filler(used), base)
        evening, sent = p.filler(used), base
        if d.weekday() == 0 and p.rng.random() < 0.85:   # Mondays
            evening = "back to work, the backlog is crushing"
            sent = p.rng.uniform(-0.7, -0.5)
        p.add(d, evening, sent)
    editable = [e for e in p.entries[40:] if p.rng.random() < 0.08]
    if not editable:                       # guard: the PUT path must run
        editable = [p.entries[60]]
    for e in editable:
        p.edits.append((e["cid"], e["text"] + " (edited to add context)", e["sentiment"]))
    deletable = [e for e in p.entries[60:] if p.rng.random() < 0.02][:12]
    if not deletable:                      # guard: the DELETE path must run
        deletable = [p.entries[61]]
    p.deletes = [e["cid"] for e in deletable]


def gen_elena(p: Persona):
    """Stable journaler; the sharing + key-lifecycle persona."""
    p.expected = ["(stable — cadence at most; the interesting part is sharing)"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = p.rng.uniform(0.0, 0.3)
        p.add(d, p.filler(used), s)
        if p.rng.random() < 0.7:
            p.add(d, p.filler(used) + ". calm evening", s + p.rng.uniform(-0.05, 0.05))


def build_personas() -> list[Persona]:
    personas = [
        Persona("maya", "maya-sim-pass-1", 21, "work-dread Sundays + sleep worry + next-day dips"),
        Persona("omar", "omar-sim-pass-2", 22, "stable; guitar topic rising in the last 2 months"),
        Persona("priya", "priya-sim-pass-3", 23, "scrolling nights; late-year decline + inertia"),
        Persona("lena", "lena-sim-pass-4", 24, "family visits w/ next-day dips; Sunday calls"),
        Persona("tom", "tom-sim-pass-5", 25, "CONTROL: pure noise, 365 days"),
        Persona("ava", "ava-sim-pass-6", 26, "year arc: mid-year decline, late recovery; run days higher"),
        Persona("ben", "ben-sim-pass-7", 27, "structured channels v2 + biweekly PHQ-9 measures"),
        Persona("chloe", "chloe-sim-pass-8", 28, "crisis episodes ~3-weekly (sensitive, non-quoting)"),
        Persona("dev", "dev-sim-pass-9", 29, "editor: revises 8%, deletes a few, weekly stress"),
        Persona("elena", "elena-sim-pass-10", 30, "stable; sharing + envelope v2 + password lifecycle"),
    ]
    gens = {"maya": gen_maya, "omar": gen_omar, "priya": gen_priya,
            "lena": gen_lena, "tom": gen_tom, "ava": gen_ava, "ben": gen_ben,
            "chloe": gen_chloe, "dev": gen_dev, "elena": gen_elena}
    for p in personas:
        p.measures: list[dict] = []
        gens[p.name](p)
    return personas


# ------------------------------------------------------------------ client ----


class Client:
    """Full-fidelity patient client: the real KDF library, real AES-GCM,
    the exact AAD contracts of the mobile app."""

    def __init__(self, username, password):
        self.username, self.password = username, password
        self.salt = os.urandom(16)
        self.master = kdf.derive_master_key(password, self.salt)
        self.auth_key = kdf.derive_auth_key(self.master)
        self.data_key = kdf.derive_data_key(self.master)
        self.kdf_params: dict | None = None
        self.user_id: str | None = None
        self.token: str | None = None

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def auth_b64(self):
        return base64.b64encode(self.auth_key).decode()

    @property
    def data_key_b64(self):
        return base64.b64encode(self.data_key).decode()

    def register_body(self) -> dict:
        return {"username": self.username,
                "salt": base64.b64encode(self.salt).decode(),
                "verifier": self.auth_b64}

    def encrypt(self, e: dict, content_version: int = 1) -> str:
        payload = {"v": e.get("payload_v", 1), "text": e["text"],
                   "sentiment": e["sentiment"], "created_at": e["date"].isoformat()}
        if e.get("payload_v", 1) >= 2:
            payload["energy"] = e.get("energy")
            payload["sleep"] = e.get("sleep")
            payload["tags"] = e.get("tags")
            payload["tod"] = e.get("tod")
        aad = crypto.entry_aad_v2(self.user_id, e["cid"], content_version)
        blob = crypto.encrypt(self.data_key, json.dumps(payload).encode(), aad)
        return base64.b64encode(blob).decode()

    def decrypt_entry(self, blob_b64: str, cid: str, version: int) -> dict:
        blob = base64.b64decode(blob_b64)
        failure = None
        for aad in crypto.entry_aad_candidates(self.user_id, cid, version):
            try:
                return json.loads(crypto.decrypt(self.data_key, blob, aad).decode())
            except crypto.TamperError as exc:
                failure = exc
        raise failure

    def decrypt_blob(self, blob_b64: str, aad: bytes):
        return crypto.decrypt(self.data_key, base64.b64decode(blob_b64), aad)


class Therapist:
    """Portal-fidelity therapist client (P-256 wrap key + notes key)."""

    def __init__(self, username, password, display_name):
        self.username, self.password = username, password
        self.display_name = display_name
        self.salt = os.urandom(16)
        self.master = kdf.derive_master_key(password, self.salt)
        self.auth_key = kdf.derive_auth_key(self.master)
        self.wrap_kek = kdf.hkdf_sha256(self.master, None, sharing_crypto.PORTAL_WRAP_INFO)
        self.notes_key = kdf.hkdf_sha256(self.master, None, sharing_crypto.PORTAL_NOTES_INFO)
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.user_id = None
        self.token = None

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    @property
    def auth_b64(self):
        return base64.b64encode(self.auth_key).decode()

    def _pkcs8(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    def _pub_b64(self) -> str:
        return base64.b64encode(
            self.private_key.public_key().public_bytes(
                serialization.Encoding.DER,
                PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()

    def _key_blob_b64(self) -> str:
        blob = crypto.encrypt(
            self.wrap_kek, self._pkcs8(),
            crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, self.username))
        return base64.b64encode(blob).decode()

    def register_body(self) -> dict:
        return {"username": self.username,
                "salt": base64.b64encode(self.salt).decode(),
                "verifier": self.auth_b64,
                "display_name": self.display_name,
                "wrap_pub_key": self._pub_b64(),
                "wrap_key_blob": self._key_blob_b64()}

    def register_body_with(self, pub_b64: str, blob_b64: str) -> dict:
        body = self.register_body()
        body["wrap_pub_key"], body["wrap_key_blob"] = pub_b64, blob_b64
        return body

    def unlock_private(self, stored_blob_b64: str):
        plain = crypto.decrypt(
            self.wrap_kek, base64.b64decode(stored_blob_b64),
            crypto.build_aad(sharing_crypto.THERAPIST_KEY_CONTEXT, self.username))
        return sharing_crypto.load_private_key_pkcs8(plain)

    def unwrap_patient_key(self, patient: Client, eph_b64: str, wrapped_b64: str) -> bytes:
        return sharing_crypto.unwrap_data_key(
            self.unlock_private(self.stored_key_blob), eph_b64,
            base64.b64decode(wrapped_b64), patient.user_id, self.user_id,
            therapist_pub_der=base64.b64decode(self._pub_b64()))

    def encrypt_note(self, patient_uid: str, cid: str, text: str) -> str:
        payload = {"v": 1, "text": text}
        aad = crypto.build_aad(sharing_crypto.NOTE_CONTEXT, self.user_id,
                               patient_uid, cid)
        return base64.b64encode(
            crypto.encrypt(self.notes_key, json.dumps(payload).encode(), aad)).decode()

    def decrypt_note(self, patient_uid: str, cid: str, blob_b64: str) -> dict:
        aad = crypto.build_aad(sharing_crypto.NOTE_CONTEXT, self.user_id,
                               patient_uid, cid)
        return json.loads(crypto.decrypt(
            self.notes_key, base64.b64decode(blob_b64), aad).decode())

    def rotate_wrap_key(self):
        self.private_key = ec.generate_private_key(ec.SECP256R1())


async def age_account(engine, user_id, days):
    async with build_sessionmaker(engine)() as s:
        await s.execute(update(User).where(User.id == user_id)
                        .values(created_at=utcnow() - timedelta(days=days)))
        await s.commit()


# ------------------------------------------------------------------- replay ----


def persona_journal(p: Persona) -> list[JournalEntry]:
    out = []
    for e in p.entries:
        out.append(JournalEntry(
            text=e["text"], entry_date=e["date"], sentiment=e["sentiment"],
            energy=e.get("energy"), sleep_quality=e.get("sleep"),
            tags=tuple(e.get("tags") or ()), tod=e.get("tod")))
    return out


def replay(persona: Persona, single_shot: bool = False):
    """Clock-accurate replay: one recompute per simulated day once the
    30-active-day threshold is crossed (single_shot: one final recompute)."""
    entries = persona_journal(persona)
    state = None
    seen: dict[str, dict] = {}
    timeline: list[dict] = []
    final_patterns: list[dict] = []
    distinct: set[date] = set()
    idx = 0
    for off in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - off)
        while idx < len(entries) and entries[idx].entry_date <= d:
            distinct.add(entries[idx].entry_date)
            idx += 1
        row = {"day": off + 1, "date": d.isoformat(), "active_days": len(distinct),
               "recomputed": False, "surfaced": 0, "new": [], "transitions": []}
        last_day = off == DAYS - 1
        if len(distinct) >= 30 and (not single_shot or last_day):
            row["recomputed"] = True
            result = brain.update(state, entries[:idx], d)
            state = result.new_state
            pats = []
            for pat in result.surfaced:
                pid = pat.detail.get("pattern_pid", "?")
                pats.append({"pid": pid, "kind": pat.kind, "label": pat.label,
                             "state": pat.detail.get("pattern_state", "?"),
                             "occurrences": pat.occurrences,
                             "sensitive": bool(pat.detail.get("sensitive"))})
                prev = seen.get(pid)
                if prev is None:
                    seen[pid] = {"kind": pat.kind, "label": pat.label,
                                 "first_day": off + 1,
                                 "state": pat.detail.get("pattern_state", "?")}
                    row["new"].append(f"{pat.kind}: {pat.label[:48]}")
                elif prev["state"] != pat.detail.get("pattern_state"):
                    row["transitions"].append(
                        f"{pat.kind} '{pat.label[:32]}' {prev['state']} -> "
                        f"{pat.detail.get('pattern_state')}")
                    prev["state"] = pat.detail.get("pattern_state")
            row["surfaced"] = len(pats)
            if last_day:
                final_patterns = pats
        timeline.append(row)
    return final_patterns, timeline, seen


# --------------------------------------------------------------------- main ----


async def run():
    t_start = walltime.time()
    print(f"target {BASE_URL}\ndb      {DB_URL}\nplan    {DAYS} days, 10 personas, every endpoint\n")
    personas = build_personas()
    for p in personas:
        print(f"  {p.name:7} {len(p.entries):4} entries / "
              f"{len({e['date'] for e in p.entries}):3} active days"
              + (f" / {len(p.measures)} measures" if p.measures else ""))

    engine = create_async_engine(DB_URL)
    report: dict = {"days": DAYS, "users": [], "phases": []}

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=180) as c:

        # ---------------------------------------------------------------- 0
        phase("0 · boot: health, meta, canonical mount")
        r = await req(c, "GET", "/healthz")
        check("GET /healthz -> 200", r.status_code == 200)
        r = await req(c, "GET", "/readyz")
        check("GET /readyz -> 200 (db reachable)", r.status_code == 200)
        r = await req(c, "GET", "/api/meta")
        meta = r.json()
        check("GET /api/meta -> 200", r.status_code == 200)
        check("meta: unlock_days == 30", meta["unlock_days"] == 30,
              f"got {meta['unlock_days']}")
        check("meta: sharing available, disclosure v2",
              meta["sharing_available"] is True
              and meta["sharing_disclosure_version"] == "v2")
        llm_flag = meta["llm_available"]
        r2 = await req(c, "GET", "/api/v1/meta")
        check("GET /api/v1/meta (canonical mount) mirrors /api/meta",
              r2.status_code == 200 and r2.json() == meta)

        # ---------------------------------------------------------------- 1
        phase("1 · registration: 10 patients + therapist (+ negatives)")
        clients: dict[str, Client] = {}
        for p in personas:
            cl = Client(p.name, p.password)
            r = await req(c, "POST", "/api/auth/register", json=cl.register_body())
            if r.status_code != 201:
                check(f"register {p.name} -> 201", False, r.text[:200])
                continue
            body = r.json()
            cl.user_id, cl.token = body["user_id"], body["token"]
            clients[p.name] = cl
            await age_account(engine, cl.user_id, DAYS + 2)
            ok = (body["role"] == "user" and body["key_scheme"] == "v1"
                  and body["token"] and body["expires_in"] > 0)
            check(f"register {p.name} -> 201 (role=user, v1)", ok)
        check("all 10 patient registrations succeeded", len(clients) == 10)

        dr_sharma = Therapist("dr_sharma", "sharma-portal-pass-1", "Dr. Ananya Sharma")
        r = await req(c, "POST", "/api/therapist/register", json=dr_sharma.register_body())
        body = r.json()
        dr_sharma.user_id, dr_sharma.token = body.get("user_id"), body.get("token")
        check("therapist register dr_sharma -> 201 role=therapist",
              r.status_code == 201 and body.get("role") == "therapist")

        dr_evil = Therapist("dr_evil", "evil-portal-pass-2", "Dr. Mallory Evil")
        r = await req(c, "POST", "/api/therapist/register", json=dr_evil.register_body())
        body = r.json()
        dr_evil.user_id, dr_evil.token = body.get("user_id"), body.get("token")
        check("therapist register dr_evil -> 201", r.status_code == 201)

        # negatives
        maya = clients["maya"]
        r = await req(c, "POST", "/api/auth/register", json=maya.register_body())
        check("duplicate username -> 409 conflict", r.status_code == 409)
        bad = {"username": "has space!", "salt": maya.register_body()["salt"],
               "verifier": maya.register_body()["verifier"]}
        r = await req(c, "POST", "/api/auth/register", json=bad)
        check("invalid username charset -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/auth/register",
                      json={**maya.register_body(), "username": "shortsalt",
                            "salt": base64.b64encode(b"x").decode()})
        check("salt wrong size -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/auth/register",
                      json={**maya.register_body(), "username": "extrafield",
                            "surprise": 1})
        check("unknown field (extra=forbid) -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/therapist/register",
                      json={"username": "notatherapist",
                            "salt": maya.register_body()["salt"],
                            "verifier": maya.register_body()["verifier"],
                            "display_name": "X", "wrap_pub_key": "garbage",
                            "wrap_key_blob": "garbage"})
        check("therapist register garbage wrap key -> 422", r.status_code == 422)

        r = await req(c, "POST", "/api/auth/salt", json={"username": "maya"})
        check("POST /auth/salt returns the registered salt",
              r.status_code == 200 and base64.b64decode(r.json()["salt"]) == maya.salt)
        r = await req(c, "POST", "/api/auth/salt", json={"username": "nobody-here"})
        decoy = r.json().get("salt")
        r2 = await req(c, "POST", "/api/auth/salt", json={"username": "nobody-here"})
        check("salt for unknown user: deterministic decoy, same shape",
              r.status_code == 200 and decoy and r2.json()["salt"] == decoy
              and len(base64.b64decode(decoy)) == 16)

        # ---------------------------------------------------------------- 2
        phase("2 · the year of entries: 10 users x 365 days, real client crypto")
        sync_stats = {}
        for p in personas:
            cl = clients[p.name]
            t0 = walltime.time()
            ok = fail = 0
            for e in p.entries:
                r = await req(c, "POST", "/api/entries", headers=cl.headers, json={
                    "client_entry_id": e["cid"], "blob": cl.encrypt(e),
                    "entry_date": e["date"].isoformat(), "content_version": 1})
                ok += r.status_code == 201
                fail += r.status_code != 201
                if r.status_code != 201:
                    print(f"      !! {p.name} {e['cid']}: {r.status_code} {r.text[:120]}")
            secs = walltime.time() - t0
            sync_stats[p.name] = (ok, fail, secs)
            check(f"{p.name}: {ok}/{ok + fail} entries synced ({secs:.0f}s)",
                  fail == 0)

        e0 = personas[0].entries[0]
        r = await req(c, "POST", "/api/entries", headers=maya.headers, json={
            "client_entry_id": e0["cid"], "blob": maya.encrypt(e0),
            "entry_date": e0["date"].isoformat()})
        check("duplicate client_entry_id -> 409", r.status_code == 409)
        r = await req(c, "POST", "/api/entries", headers=maya.headers, json={
            "client_entry_id": "future-entry", "blob": maya.encrypt(e0),
            "entry_date": (TODAY + timedelta(days=5)).isoformat()})
        check("entry_date beyond today+1 -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/entries", headers=maya.headers, json={
            "client_entry_id": "ancient-entry", "blob": maya.encrypt(
                {**e0, "date": TODAY - timedelta(days=400)}),
            "entry_date": (TODAY - timedelta(days=400)).isoformat()})
        check("entry_date before account creation -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/entries", headers=maya.headers, json={
            "client_entry_id": "x1", "blob": "not-base64!!",
            "entry_date": TODAY.isoformat()})
        check("blob not base64 -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/entries", headers=maya.headers, json={
            "client_entry_id": "x2", "blob": base64.b64encode(os.urandom(3 * 1024 * 1024)).decode(),
            "entry_date": TODAY.isoformat()})
        check("3 MiB body -> 413 before parsing", r.status_code == 413)
        r = await req(c, "POST", "/api/entries",
                      json={"client_entry_id": "x3", "blob": "AAAA", "entry_date": "2026-01-01"})
        check("POST /entries without token -> 401", r.status_code == 401)
        r = await req(c, "POST", "/api/entries", headers={
            "Authorization": "Bearer bogus-token"}, json={
            "client_entry_id": "x4", "blob": "AAAA", "entry_date": "2026-01-01"})
        check("bogus bearer -> 401", r.status_code == 401)

        # ---------------------------------------------------------------- 3
        phase("3 · editing lifecycle (dev) + list pagination (dev, maya)")
        dev, devp = clients["dev"], next(p for p in personas if p.name == "dev")
        edited_ok = conflicts = 0
        for cid, new_text, sent in devp.edits:
            e = next(x for x in devp.entries if x["cid"] == cid)
            r = await req(c, "GET", f"/api/entries/{cid}", headers=dev.headers)
            stored = r.json()
            version = stored["content_version"]
            r = await req(c, "PUT", f"/api/entries/{cid}", headers=dev.headers, json={
                "blob": dev.encrypt({**e, "text": new_text, "sentiment": sent},
                                    content_version=version + 1),
                "entry_date": stored["entry_date"], "content_version": version + 1})
            edited_ok += r.status_code == 200
            # stale version retry must conflict exactly once in a while
            if conflicts < 1:
                r2 = await req(c, "PUT", f"/api/entries/{cid}", headers=dev.headers, json={
                    "blob": dev.encrypt({**e, "text": new_text}, content_version=version + 1),
                    "entry_date": stored["entry_date"], "content_version": version + 1})
                conflicts = 1 if r2.status_code == 409 else -1
                check("PUT with stale content_version -> 409 version_conflict",
                      r2.status_code == 409)
        check(f"dev edited {len(devp.edits)} entries via PUT (version bump)",
              edited_ok == len(devp.edits) and edited_ok > 0)

        deleted_ok = 0
        for cid in devp.deletes:
            r = await req(c, "DELETE", f"/api/entries/{cid}", headers=dev.headers)
            deleted_ok += r.status_code == 204
            if "X-Entries-Revision" not in r.headers and deleted_ok == 1:
                check("DELETE returns X-Entries-Revision header", False)
        check(f"dev deleted {len(devp.deletes)} entries -> 204 + revision header",
              deleted_ok == len(devp.deletes) and deleted_ok > 0
              and all("X-Entries-Revision" in r.headers for _ in [0]))
        r = await req(c, "GET", f"/api/entries/{devp.deletes[0]}", headers=dev.headers)
        check("deleted entry GET -> 404", r.status_code == 404)

        r = await req(c, "GET", f"/api/entries/{devp.edits[0][0]}", headers=dev.headers)
        dec = dev.decrypt_entry(r.json()["blob"], devp.edits[0][0],
                                r.json()["content_version"])
        check("edited entry decrypts to the new text (v2 AAD ladder)",
              "(edited to add context)" in dec["text"])

        # pagination walk (dev): offset/limit until exhausted
        total, offset = 0, 0
        expected_total = len(devp.entries) - len(devp.deletes)
        while True:
            r = await req(c, "GET", f"/api/entries?limit=200&offset={offset}",
                          headers=dev.headers)
            page = r.json()
            total += len(page)
            nxt = r.headers.get("X-Next-Offset")
            if nxt is None:
                break
            offset = int(nxt)
        check(f"dev pagination walk sees exactly {expected_total} entries",
              total == expected_total, f"walked {total}")

        r = await req(c, "GET", "/api/entries?limit=200", headers=dev.headers)
        rev = r.headers.get("X-Entries-Revision")
        check("GET /entries carries X-Entries-Revision", rev is not None)
        r = await req(c, "GET",
                      f"/api/entries?limit=10&expected_revision={int(rev) - 1}",
                      headers=dev.headers)
        check("stale expected_revision -> 409 collection_changed",
              r.status_code == 409)
        r = await req(c, "GET",
                      f"/api/entries?limit=10&expected_revision={rev}",
                      headers=dev.headers)
        check("current expected_revision -> 200", r.status_code == 200)
        r = await req(c, "GET", "/api/entries?limit=500&page_bytes=4096",
                      headers=dev.headers)
        page_rows = r.json()
        blob_sum = sum(len(base64.b64decode(x["blob"])) for x in page_rows)
        check("page_bytes opt-in respected (ciphertext budget + more pages)",
              r.status_code == 200 and 0 < len(page_rows) < 500
              and blob_sum <= 4096
              and r.headers.get("X-Next-Offset") is not None,
              f"{len(page_rows)} rows / {blob_sum} ciphertext bytes")
        r = await req(c, "GET", "/api/entries?limit=500", headers=dev.headers)
        all_rows = r.json()
        first_date = all_rows[0]["entry_date"]
        mid_date = all_rows[len(all_rows) // 2]["entry_date"]
        r = await req(c, "GET", f"/api/entries?since={mid_date}&limit=500",
                      headers=dev.headers)
        later = r.json()
        check("since= filter bounds the window (only later rows, boundary kept)",
              r.status_code == 200 and later
              and all(x["entry_date"] >= mid_date for x in later)
              and later[0]["entry_date"] == mid_date
              and len(later) < len(all_rows))

        # ---------------------------------------------------------------- 4
        phase("4 · measures: a year of encrypted PHQ-9 (ben, chloe)")
        ben, benp = clients["ben"], next(p for p in personas if p.name == "ben")
        posted = 0
        for m in benp.measures:
            payload = {"v": 1, "instrument": "phq9", "score": m["score"]}
            blob = crypto.encrypt(
                ben.data_key, json.dumps(payload).encode(),
                crypto.build_aad("measure", ben.user_id, m["cid"]))
            r = await req(c, "POST", "/api/measures", headers=ben.headers, json={
                "client_measure_id": m["cid"],
                "blob": base64.b64encode(blob).decode(),
                "measure_date": m["date"].isoformat()})
            posted += r.status_code == 201
        check(f"ben posted {len(benp.measures)} PHQ-9 measures -> 201",
              posted == len(benp.measures) and posted > 0)

        r = await req(c, "GET", "/api/measures?limit=500", headers=ben.headers)
        rows = r.json()
        check("GET /measures returns all rows, newest first",
              r.status_code == 200 and len(rows) == len(benp.measures)
              and rows[0]["measure_date"] >= rows[-1]["measure_date"])
        dec = json.loads(crypto.decrypt(
            ben.data_key, base64.b64decode(rows[-1]["blob"]),
            crypto.build_aad("measure", ben.user_id, rows[-1]["client_measure_id"])))
        check("oldest measure decrypts (score 14-ish start of year)",
              dec["instrument"] == "phq9" and dec["score"] >= 12)
        dec = json.loads(crypto.decrypt(
            ben.data_key, base64.b64decode(rows[0]["blob"]),
            crypto.build_aad("measure", ben.user_id, rows[0]["client_measure_id"])))
        check("newest measure decrypts (score ~4, the year's improvement)",
              dec["score"] <= 8, f"score={dec['score']}")
        check("X-Measures-Revision header present",
              "X-Measures-Revision" in r.headers)
        r = await req(c, "DELETE", f"/api/measures/{rows[0]['client_measure_id']}",
                      headers={**ben.headers, "X-Account-Verifier": "AAAA"})
        check("measure DELETE wrong verifier -> 403", r.status_code == 403)
        r = await req(c, "DELETE", f"/api/measures/{rows[0]['client_measure_id']}",
                      headers={**ben.headers, "X-Account-Verifier": ben.auth_b64})
        check("measure DELETE with verifier -> 200 + revision",
              r.status_code == 200 and "measures_revision" in r.json())

        # ---------------------------------------------------------------- 5
        phase("5 · recompute, insights, questions, determinism (10 users)")
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=maya.headers, json={"data_key": "AAAA"})
        check("processing session with non-32B key -> 422", r.status_code == 422)

        insights_per_user: dict[str, dict] = {}
        replay_final: dict[str, list] = {}
        for p in personas:
            cl = clients[p.name]
            t0 = walltime.time()
            r = await req(c, "POST", "/api/processing/sessions",
                          headers=cl.headers, json={"data_key": cl.data_key_b64})
            tok = r.json()["session_token"]
            body = {}
            if p.name == "chloe":
                body = {"feedback_blob": base64.b64encode(crypto.encrypt(
                    cl.data_key, json.dumps({"feedback": [], "muted": []}).encode(),
                    crypto.build_aad("feedback", cl.user_id, TODAY.isoformat()))).decode()}
            r = await req(c, "POST", "/api/insights/recompute",
                          headers={**cl.headers, "X-Processing-Token": tok},
                          json=body if body else None)
            live = r.json()
            recompute_secs = walltime.time() - t0
            if not check(f"{p.name}: recompute -> insight phase",
                         r.status_code == 200 and live["phase"] == "insight"
                         and live["analyzer"] == "brain", str(live)[:160]):
                continue
            r = await req(c, "POST", "/api/insights/recompute",
                          headers={**cl.headers, "X-Processing-Token": tok})
            check(f"{p.name}: reused processing token -> 403", r.status_code == 403)
            r = await req(c, "POST", "/api/insights/recompute", headers=cl.headers)
            check(f"{p.name}: recompute without token -> 401", r.status_code == 401)

            r = await req(c, "GET", "/api/insights", headers=cl.headers)
            ins = r.json()
            payload = json.loads(cl.decrypt_blob(
                ins["blob"], crypto.build_aad("insights", cl.user_id, "patterns")))
            live_patterns = payload["stats"]["patterns"]
            insights_per_user[p.name] = {"response": live, "payload": payload,
                                         "patterns": live_patterns}

            r = await req(c, "GET", "/api/questions/today", headers=cl.headers)
            if live["patterns_stored"] == 0:
                # no surfaced patterns -> no question generated today; the
                # 404 IS the honest answer (the control user lands here)
                check(f"{p.name}: zero patterns -> no question today (404)",
                      r.status_code == 404)
                q = None
            else:
                q = json.loads(cl.decrypt_blob(
                    r.json()["blob"],
                    crypto.build_aad("question", cl.user_id, r.json()["for_date"])))
                check(f"{p.name}: GET /questions/today decrypts "
                      f"(for_date={q['for_date']})",
                      r.status_code == 200 and bool(q.get("question")))

            fp, timeline, seen = replay(p)
            replay_final[p.name] = fp
            sp, _, _ = replay(p, single_shot=True)
            live_set = {(x["kind"], x["label"]) for x in live_patterns}
            single_set = {(x["kind"], x["label"]) for x in sp}
            check(f"{p.name}: determinism live == single-shot replay "
                  f"({len(live_set)} patterns)",
                  live_set == single_set)

            print(f"      {p.name}: active_days={live['active_days']} "
                  f"streak={live['streak']} stored={live['patterns_stored']} "
                  f"new={live['patterns_new']} fading={live['patterns_fading']} "
                  f"({recompute_secs:.1f}s)")
            for x in fp[:12]:
                fd = next((v["first_day"] for v in seen.values()
                           if v["kind"] == x["kind"] and v["label"] == x["label"]), "?")
                print(f"        day {str(fd):>3} [{x['state']:9}] {x['kind']:18} "
                      f"{x['label'][:56]} (n={x['occurrences']})"
                      + (" [SENSITIVE]" if x["sensitive"] else ""))
            if len(fp) > 12:
                print(f"        ... +{len(fp) - 12} more")

            report["users"].append({
                "name": p.name, "blurb": p.blurb, "expected": p.expected,
                "entries": len(p.entries),
                "active_days": live["active_days"], "streak": live["streak"],
                "patterns_live": live_patterns,
                "patterns_replay_daily": fp,
                "pattern_first_day": {f"{v['kind']}|{v['label']}": v["first_day"]
                                      for v in seen.values()},
                "determinism_live_eq_singleshot": live_set == single_set,
                "timeline": timeline, "user_id": cl.user_id,
                "sync": sync_stats[p.name],
                "recompute_seconds": round(recompute_secs, 1),
            })

        # control + persona-specific assertions on decrypted data
        tom_pat = insights_per_user["tom"]["patterns"]
        stat_kinds = [x["kind"] for x in tom_pat if x["kind"] in STATISTICAL_KINDS]
        check("CONTROL tom (365d noise): zero statistical patterns surfaced",
              not stat_kinds, f"surfaced kinds: {[x['kind'] for x in tom_pat]}")
        # 2026-09-28 lexicon remediation proof: tom's noise year must not
        # produce ANY rumination card — his only one pre-fix was the
        # "took it down" chore cluster the directional "down" misread.
        check("CONTROL tom: no rumination cards after the polysemy fix",
              not any(x["kind"] == "rumination" for x in tom_pat))

        chloe_pat = insights_per_user["chloe"]["patterns"]
        crisis_pat = [x for x in chloe_pat if "disappear" in x["label"].lower()
                      or "take this" in x["label"].lower()]
        sens = [x for x in crisis_pat
                if x.get("sensitive") or x.get("detail", {}).get("sensitive")]
        check("chloe: crisis-phrase patterns exist and are flagged sensitive",
              len(crisis_pat) > 0 and len(sens) == len(crisis_pat),
              f"{len(crisis_pat)} crisis patterns, {len(sens)} sensitive")
        r = await req(c, "GET", "/api/questions/today",
                      headers=clients["chloe"].headers)
        if r.status_code == 200:
            qd = json.loads(clients["chloe"].decrypt_blob(
                r.json()["blob"], crypto.build_aad(
                    "question", clients["chloe"].user_id, r.json()["for_date"])))
            qtext = qd["question"].lower()
            check("chloe: today's question never quotes crisis language",
                  "disappear" not in qtext and "take this" not in qtext
                  and "can't take" not in qtext, qtext[:90])
        else:
            check("chloe: today's question never quotes crisis language "
                  "(no question served)", r.status_code == 404)

        omar_topic = [x for x in replay_final["omar"]
                      if x["kind"] == "topic" and "guitar" in x["label"].lower()]
        check("omar: rising guitar topic surfaced (daily-user view; the "
              "replication gate correctly holds it out of a single-shot "
              "fresh-account view)",
              bool(omar_topic)
              and omar_topic[0]["state"] in ("emerging", "confirmed"),
              f"n={omar_topic[0]['occurrences']}, state={omar_topic[0]['state']}"
              if omar_topic else "absent")
        maya_pat = insights_per_user["maya"]["patterns"]
        # 2026-09-28 lexicon remediation proof: the perseverative phrase
        # ("can't sleep, my mind won't stop") must now carry the
        # RUMINATION kind (pre-fix it read +0.222 — positive — and stayed
        # a neutral recurring_phrase).
        check("maya: sleep-worry surfaces as RUMINATION (polysemy fix)",
              any(x["kind"] == "rumination"
                  and ("sleep" in x["label"].lower() or "mind" in x["label"].lower())
                  for x in maya_pat),
              "; ".join(sorted({f"{x['kind']}:{x['label'][:24]}"
                                for x in maya_pat}))[:120])

        # feedback loop, real taps (maya): a tap on one of her patterns
        pid = next((x["detail"].get("pattern_pid") for x in maya_pat
                    if x.get("detail", {}).get("pattern_pid")), None)
        if pid:
            fb = {"feedback": [{"pid": pid, "resonated": True}], "muted": []}
            r = await req(c, "POST", "/api/processing/sessions",
                          headers=maya.headers, json={"data_key": maya.data_key_b64})
            tok = r.json()["session_token"]
            blob = base64.b64encode(crypto.encrypt(
                maya.data_key, json.dumps(fb).encode(),
                crypto.build_aad("feedback", maya.user_id, TODAY.isoformat()))).decode()
            r = await req(c, "POST", "/api/insights/recompute",
                          headers={**maya.headers, "X-Processing-Token": tok},
                          json={"feedback_blob": blob})
            check("recompute with feedback taps (muted/unmuted queue) -> 200",
                  r.status_code == 200 and r.json()["phase"] == "insight")
            garbage = base64.b64encode(crypto.encrypt(
                maya.data_key, b'{"feedback": "not-a-list"}',
                crypto.build_aad("feedback", maya.user_id, TODAY.isoformat()))).decode()
            r = await req(c, "POST", "/api/processing/sessions",
                          headers=maya.headers, json={"data_key": maya.data_key_b64})
            tok = r.json()["session_token"]
            r = await req(c, "POST", "/api/insights/recompute",
                          headers={**maya.headers, "X-Processing-Token": tok},
                          json={"feedback_blob": garbage})
            check("malformed feedback payload -> 400 entry_payload_malformed",
                  r.status_code == 400)
        else:
            check("maya has a pattern pid to tap feedback on", False)

        # ---------------------------------------------------------------- 6
        phase("6 · local-recompute: on-device brain, escrow upload (chloe)")
        chloe = clients["chloe"]
        chloe_p = next(p for p in personas if p.name == "chloe")
        r = await req(c, "GET", "/api/insights", headers=chloe.headers)
        base_seq = r.json()["state_seq"]
        result = brain.update(None, persona_journal(chloe_p), TODAY)
        up_payload = {"v": 2, "phase": "insight", "state_seq": base_seq + 1,
                      "stats": {**result.stats,
                                "patterns": [p.to_dict() for p in result.surfaced]}}
        pats_blob = base64.b64encode(crypto.encrypt(
            chloe.data_key, json.dumps(up_payload).encode(),
            crypto.build_aad("insights", chloe.user_id, "patterns"))).decode()
        state_blob = base64.b64encode(crypto.encrypt(
            chloe.data_key, brain.dump_state(result.new_state),
            crypto.build_aad("insights", chloe.user_id, "brain"))).decode()
        dates = sorted({e["date"].isoformat() for e in chloe_p.entries})[-40:]
        r = await req(c, "POST", "/api/insights/local-recompute",
                      headers=chloe.headers,
                      json={"base_state_seq": base_seq, "state_blob": state_blob,
                            "patterns_blob": pats_blob, "analysis_dates": dates,
                            "patterns_count": len(result.surfaced)})
        check("local-recompute upload -> 200, analyzer=local, seq+1",
              r.status_code == 200 and r.json()["analyzer"] == "local"
              and r.json()["state_seq"] == base_seq + 1, str(r.json())[:120])
        r = await req(c, "POST", "/api/insights/local-recompute",
                      headers=chloe.headers,
                      json={"base_state_seq": base_seq, "state_blob": state_blob,
                            "patterns_blob": pats_blob, "analysis_dates": dates})
        check("local-recompute stale base_state_seq -> 409", r.status_code == 409)
        r = await req(c, "GET", "/api/insights", headers=chloe.headers)
        served = json.loads(chloe.decrypt_blob(
            r.json()["blob"], crypto.build_aad("insights", chloe.user_id, "patterns")))
        check("GET /insights now serves exactly the uploaded payload",
              served == up_payload)
        # restore server-brain state with a fresh recompute for later phases
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=chloe.headers, json={"data_key": chloe.data_key_b64})
        tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/insights/recompute",
                      headers={**chloe.headers, "X-Processing-Token": tok})
        check("server recompute re-asserts state after local experiment",
              r.status_code == 200 and r.json()["analyzer"] == "brain")

        # ---------------------------------------------------------------- 7
        phase("7 · zero-knowledge sharing lifecycle (elena+ben -> dr_sharma)")
        elena, elena_p = clients["elena"], next(
            p for p in personas if p.name == "elena")
        ben_p = benp
        r = await req(c, "POST", "/api/therapist/pairing-codes",
                      headers=dr_sharma.headers)
        code = r.json()["code"]
        check("therapist issues pairing code (TTL 900s)",
              r.status_code == 201 and r.json()["expires_in"] == 900)

        r = await req(c, "POST", "/api/consents/pairing/lookup",
                      headers=elena.headers, json={"code": "WRONGCOD"})
        check("wrong pairing code -> 404 (same as expired)", r.status_code == 404)
        r = await req(c, "POST", "/api/consents/pairing/lookup",
                      headers=elena.headers, json={"code": code})
        lookup = r.json()
        check("patient pairing lookup -> therapist identity + SAS + fingerprint",
              r.status_code == 200 and lookup["therapist_id"] == dr_sharma.user_id
              and re.fullmatch(r"\d{3} \d{3}", lookup["sas"])
              and len(lookup["wrap_key_fingerprint"]) == 16)
        local_sas = sharing_crypto.pairing_sas(
            code, base64.b64decode(dr_sharma._pub_b64()), elena.user_id)
        check("patient-side SAS equals locally computed SAS (MITM check)",
              lookup["sas"] == local_sas)
        r = await req(c, "GET",
                      f"/api/therapist/pairing/sas?patient_user_id={elena.user_id}",
                      headers={**dr_sharma.headers, "X-Pairing-Code": code})
        check("therapist-side SAS equals the same value (both ends verify)",
              r.status_code == 200 and r.json()["sas"] == local_sas)

        wrap = sharing_crypto.wrap_data_key(
            elena.data_key, dr_sharma._pub_b64(), elena.user_id, dr_sharma.user_id)
        r = await req(c, "POST", "/api/consents", headers=elena.headers,
                      json={"code": code, "ephemeral_pub": wrap[0],
                            "wrapped_key": wrap[1], "disclosure": "v1"})
        check("grant with outdated disclosure -> 409", r.status_code == 409)
        r = await req(c, "POST", "/api/consents", headers=elena.headers,
                      json={"code": code, "ephemeral_pub": wrap[0],
                            "wrapped_key": wrap[1], "disclosure": "v2"})
        check("grant WITHOUT verifier -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/consents",
                      headers={**elena.headers, "X-Account-Verifier": "AAAA"},
                      json={"code": code, "ephemeral_pub": wrap[0],
                            "wrapped_key": wrap[1], "disclosure": "v2"})
        check("grant with WRONG verifier -> 403", r.status_code == 403)
        r = await req(c, "POST", "/api/consents",
                      headers={**elena.headers, "X-Account-Verifier": elena.auth_b64},
                      json={"code": code, "ephemeral_pub": wrap[0],
                            "wrapped_key": wrap[1], "disclosure": "v2"})
        consent = r.json()
        check("grant with verifier -> 201 active consent",
              r.status_code == 201 and consent["status"] == "active")
        consent_id = consent["id"]

        r = await req(c, "POST", "/api/consents/pairing/lookup",
                      headers=elena.headers, json={"code": code})
        check("pairing code burned after grant -> 404", r.status_code == 404)

        r = await req(c, "GET", "/api/consents", headers=maya.headers)
        check("maya's consent list is []", r.status_code == 200 and r.json() == [])
        r = await req(c, "GET", "/api/consents", headers=elena.headers)
        check("elena sees her consent", r.status_code == 200
              and len(r.json()) == 1 and r.json()[0]["id"] == consent_id)

        r = await req(c, "GET", "/api/therapist/me", headers=dr_sharma.headers)
        me = r.json()
        dr_sharma.stored_key_blob = me["wrap_key_blob"]
        check("GET /therapist/me returns identity + wrap key + totp flag",
              r.status_code == 200 and me["username"] == "dr_sharma"
              and me["totp_enabled"] is False)

        # elena recomputes while consent is active -> caseload summary written
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=elena.headers, json={"data_key": elena.data_key_b64})
        tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/insights/recompute",
                      headers={**elena.headers, "X-Processing-Token": tok})
        check("elena recompute with active grant -> 200", r.status_code == 200)

        r = await req(c, "GET", "/api/therapist/patients", headers=dr_sharma.headers)
        rows = r.json()
        erow = next((x for x in rows if x["user_id"] == elena.user_id), None)
        check("therapist patient list shows elena with wrapped key + summary",
              erow is not None and erow["wrapped_key"] and erow["ephemeral_pub"]
              and erow["summary_blob"] and erow["summary_eph_pub"])

        unwrapped = dr_sharma.unwrap_patient_key(
            elena, erow["ephemeral_pub"], erow["wrapped_key"])
        check("portal unwraps patient data key (ECDH->HKDF->GCM)",
              unwrapped == elena.data_key)

        summary = json.loads(sharing_crypto.unwrap_summary_payload(
            dr_sharma.unlock_private(dr_sharma.stored_key_blob),
            erow["summary_eph_pub"], base64.b64decode(erow["summary_blob"]),
            elena.user_id, dr_sharma.user_id))
        n_elena = len(insights_per_user["elena"]["patterns"])
        check("caseload summary decrypts and matches surfaced count",
              summary["v"] == 1 and summary["patterns"] == n_elena,
              f"summary={summary['patterns']} live={n_elena}")

        r = await req(c, "GET", "/api/insights", headers=elena.headers)
        patient_blob = r.json()["blob"]
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/insights",
                      headers=dr_sharma.headers)
        check("therapist insight read is consent-gated + byte-identical",
              r.status_code == 200 and r.json()["blob"] == patient_blob
              and patient_blob is not None)
        served = json.loads(crypto.decrypt(
            unwrapped, base64.b64decode(r.json()["blob"]),
            crypto.build_aad("insights", elena.user_id, "patterns")))
        check("portal decrypts elena's patterns with the unwrapped key",
              served["stats"]["patterns"] == insights_per_user["elena"]["patterns"])

        d_since = (TODAY - timedelta(days=120)).isoformat()
        d_until = (TODAY - timedelta(days=60)).isoformat()
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/entries"
                      f"?since={d_since}&until={d_until}&limit=25",
                      headers=dr_sharma.headers)
        window = r.json()
        in_range = all(d_since <= x["entry_date"] <= d_until for x in window)
        check("therapist entry window (since/until) honored",
              r.status_code == 200 and in_range and len(window) <= 25)
        if window:
            dec = json.loads(crypto.decrypt(
                unwrapped, base64.b64decode(window[0]["blob"]),
                crypto.entry_aad_v2(elena.user_id, window[0]["client_entry_id"],
                                    window[0]["content_version"])))
            check("portal decrypts the entry evidence window",
                  isinstance(dec.get("text"), str))

        # ben grants too -> multi-patient caseload + measures read
        r = await req(c, "POST", "/api/therapist/pairing-codes",
                      headers=dr_sharma.headers)
        code2 = r.json()["code"]
        wrap2 = sharing_crypto.wrap_data_key(
            ben.data_key, dr_sharma._pub_b64(), ben.user_id, dr_sharma.user_id)
        r = await req(c, "POST", "/api/consents",
                      headers={**ben.headers, "X-Account-Verifier": ben.auth_b64},
                      json={"code": code2, "ephemeral_pub": wrap2[0],
                            "wrapped_key": wrap2[1], "disclosure": "v2"})
        check("ben grants dr_sharma -> 201", r.status_code == 201)
        r = await req(c, "GET",
                      f"/api/therapist/patients/{ben.user_id}/measures?limit=500",
                      headers=dr_sharma.headers)
        brows = r.json()
        check("therapist reads ben's measures (v2 disclosure)",
              r.status_code == 200 and len(brows) == len(ben_p.measures) - 1)
        r = await req(c, "GET", "/api/therapist/patients", headers=dr_sharma.headers)
        brow = next(x for x in r.json() if x["user_id"] == ben.user_id)
        ben_unwrapped = dr_sharma.unwrap_patient_key(
            ben, brow["ephemeral_pub"], brow["wrapped_key"])
        dec = json.loads(crypto.decrypt(
            ben_unwrapped, base64.b64decode(brows[0]["blob"]),
            crypto.build_aad("measure", ben.user_id,
                             brows[0]["client_measure_id"])))
        check("portal decrypts ben's newest measure (the improving trend)",
              dec["instrument"] == "phq9" and dec["score"] <= 8)

        # notes lifecycle
        note_cid = "note-elena-0001"
        blob1 = dr_sharma.encrypt_note(elena.user_id, note_cid,
                                       "Session 1: adjusting the plan together")
        r = await req(c, "POST",
                      f"/api/therapist/patients/{elena.user_id}/notes",
                      headers=dr_sharma.headers,
                      json={"client_note_id": note_cid, "pattern_pid": None,
                            "blob": blob1})
        note = r.json()
        check("therapist writes encrypted note -> 201", r.status_code == 201)
        r = await req(c, "POST",
                      f"/api/therapist/patients/{elena.user_id}/notes",
                      headers=dr_sharma.headers,
                      json={"client_note_id": note_cid, "pattern_pid": None,
                            "blob": blob1})
        check("same-content note retry is idempotent (same id)",
              r.status_code == 201 and r.json()["id"] == note["id"])
        blob_conflict = dr_sharma.encrypt_note(elena.user_id, note_cid, "different")
        r = await req(c, "POST",
                      f"/api/therapist/patients/{elena.user_id}/notes",
                      headers=dr_sharma.headers,
                      json={"client_note_id": note_cid, "pattern_pid": None,
                            "blob": blob_conflict})
        check("same id, different content -> 409 version_conflict",
              r.status_code == 409)

        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/notes",
                      headers=dr_sharma.headers)
        check("notes list + local decryption under the notes key",
              r.status_code == 200 and len(r.json()) == 1
              and dr_sharma.decrypt_note(elena.user_id, note_cid,
                                         r.json()[0]["blob"])["text"]
              .startswith("Session 1"))

        blob2 = dr_sharma.encrypt_note(elena.user_id, note_cid,
                                       "Session 2: plan is working")
        r = await req(c, "PATCH", f"/api/therapist/notes/{note['id']}",
                      headers=dr_sharma.headers,
                      json={"blob": blob2, "base_version": note["version"]})
        patched = r.json()
        check("note PATCH -> 200, version bumped", r.status_code == 200
              and patched["version"] == note["version"] + 1)
        r = await req(c, "PATCH", f"/api/therapist/notes/{note['id']}",
                      headers=dr_sharma.headers,
                      json={"blob": blob2, "base_version": note["version"]})
        check("note PATCH with stale base_version -> 409", r.status_code == 409)
        r = await req(c, "PATCH", f"/api/therapist/notes/{note['id']}",
                      headers=dr_sharma.headers, json={"blob": blob2})
        check("note PATCH without base_version -> 400", r.status_code == 400)
        r = await req(c, "GET", f"/api/therapist/notes/{note['id']}/revisions",
                      headers=dr_sharma.headers)
        revs = r.json()
        check("note revisions list keeps superseded blobs",
              r.status_code == 200 and len(revs) >= 1
              and dr_sharma.decrypt_note(elena.user_id, note_cid,
                                         revs[0]["blob"])["text"]
              .startswith("Session 1"))

        # revoke -> 404s, key material cleared, notes survive
        r = await req(c, "DELETE", f"/api/consents/{consent_id}",
                      headers={**elena.headers, "X-Account-Verifier": "AAAA"})
        check("revoke with wrong verifier -> 403", r.status_code == 403)
        r = await req(c, "DELETE", f"/api/consents/{consent_id}",
                      headers={**elena.headers, "X-Account-Verifier": elena.auth_b64})
        check("revoke with verifier -> 204", r.status_code == 204)
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/insights",
                      headers=dr_sharma.headers)
        check("therapist insight read after revoke -> 404", r.status_code == 404)
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/entries",
                      headers=dr_sharma.headers)
        check("therapist entry read after revoke -> 404", r.status_code == 404)
        r = await req(c, "GET", "/api/therapist/patients", headers=dr_sharma.headers)
        erow2 = next(x for x in r.json() if x["user_id"] == elena.user_id)
        check("revoked row kept (status=revoked), key material cleared",
              erow2["status"] == "revoked" and erow2["wrapped_key"] is None
              and erow2["summary_blob"] is None)
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/notes",
                      headers=dr_sharma.headers)
        check("therapist notes SURVIVE the revoke (own record)",
              r.status_code == 200 and len(r.json()) == 1)

        # re-grant reactivates the same consent row; then wrap-key rotation
        r = await req(c, "POST", "/api/therapist/pairing-codes",
                      headers=dr_sharma.headers)
        code3 = r.json()["code"]
        wrap3 = sharing_crypto.wrap_data_key(
            elena.data_key, dr_sharma._pub_b64(), elena.user_id, dr_sharma.user_id)
        r = await req(c, "POST", "/api/consents",
                      headers={**elena.headers, "X-Account-Verifier": elena.auth_b64},
                      json={"code": code3, "ephemeral_pub": wrap3[0],
                            "wrapped_key": wrap3[1], "disclosure": "v2"})
        check("re-grant reactivates the SAME consent row (id continuity)",
              r.status_code == 201 and r.json()["id"] == consent_id)
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/insights",
                      headers=dr_sharma.headers)
        check("therapist reads resume after re-grant", r.status_code == 200)

        dr_sharma.rotate_wrap_key()
        new_pub = dr_sharma._pub_b64()
        new_blob = dr_sharma._key_blob_b64()
        r = await req(c, "PUT", "/api/therapist/wrap-key",
                      headers={**dr_sharma.headers,
                               "X-Account-Verifier": dr_sharma.auth_b64},
                      json={"wrap_pub_key": new_pub, "wrap_key_blob": new_blob})
        check("therapist rotates wrap key -> 204", r.status_code == 204)
        r = await req(c, "GET", "/api/therapist/me", headers=dr_sharma.headers)
        dr_sharma.stored_key_blob = r.json()["wrap_key_blob"]
        check("GET /therapist/me now serves the new public key",
              r.json()["wrap_pub_key"] == new_pub)
        wrap4 = sharing_crypto.wrap_data_key(
            elena.data_key, new_pub, elena.user_id, dr_sharma.user_id)
        r = await req(c, "PUT", f"/api/consents/{consent_id}/rewrap",
                      headers={**elena.headers,
                               "X-Account-Verifier": elena.auth_b64},
                      json={"ephemeral_pub": wrap4[0], "wrapped_key": wrap4[1]})
        check("patient rewraps data key to the rotated key -> 200",
              r.status_code == 200)
        r = await req(c, "GET", "/api/therapist/patients", headers=dr_sharma.headers)
        erow3 = next(x for x in r.json() if x["user_id"] == elena.user_id)
        got = dr_sharma.unwrap_patient_key(elena, erow3["ephemeral_pub"],
                                           erow3["wrapped_key"])
        check("portal unwraps with the ROTATED key == real data key",
              got == elena.data_key)

        # ---------------------------------------------------------------- 8
        phase("8 · key lifecycle: rekey (priya), envelope v2 + O(1) password (elena)")
        priya = clients["priya"]
        old_key = priya.data_key
        # capture a plaintext for comparison across the rotation
        r = await req(c, "GET", "/api/entries?limit=1", headers=priya.headers)
        first_row = r.json()[0]
        before = priya.decrypt_entry(first_row["blob"], first_row["client_entry_id"],
                                     first_row["content_version"])
        # pure DATA-KEY rotation (the compromise-hygiene path): a fresh
        # random 32B key; the login credential stays exactly as it was.
        priya.data_key = os.urandom(32)
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=priya.headers, json={
                          "data_key": base64.b64encode(old_key).decode()})
        old_tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=priya.headers, json={"data_key": priya.data_key_b64})
        new_tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/processing/rekey",
                      headers={**priya.headers, "X-Processing-Token": old_tok,
                               "X-New-Processing-Token": new_tok,
                               "X-Account-Verifier": priya.auth_b64})
        counts = r.json() if r.status_code == 200 else {}
        priya_entries_n = len(next(p for p in personas if p.name == "priya").entries)
        check("rekey old->new -> 200 with row counts",
              r.status_code == 200
              and counts.get("entries") == priya_entries_n
              and counts.get("insights", 0) >= 1
              and counts.get("measures") == 0,
              str(counts))
        r = await req(c, "GET", "/api/entries?limit=1", headers=priya.headers)
        row = r.json()[0]
        after = priya.decrypt_entry(row["blob"], row["client_entry_id"],
                                    row["content_version"])
        check("after rekey, entries decrypt with the NEW key, same plaintext",
              row["id"] == first_row["id"] and after == before)
        try:
            crypto.decrypt(old_key, base64.b64decode(row["blob"]),
                           crypto.entry_aad_v2(priya.user_id,
                                               row["client_entry_id"],
                                               row["content_version"]))
            old_fails = False
        except crypto.TamperError:
            old_fails = True
        check("old key can no longer decrypt anything", old_fails)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "priya", "verifier": priya.auth_b64})
        check("priya logs in with her UNchanged credential (rekey never "
              "touched it)",
              r.status_code == 200)
        priya.token = r.json()["token"]
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=priya.headers, json={"data_key": priya.data_key_b64})
        tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/insights/recompute",
                      headers={**priya.headers, "X-Processing-Token": tok})
        check("recompute works under the new key", r.status_code == 200)

        # elena: v1 -> v2 envelope upgrade, then O(1) password change
        r = await req(c, "GET", "/api/auth/key-envelope", headers=elena.headers)
        check("elena envelope is v1 (nulls)", r.status_code == 200
              and r.json()["key_scheme"] == "v1"
              and r.json()["wrapped_data_key"] is None)
        elena.kdf_params = dict(kdf.KDF_PARAMS_DEFAULT)
        elena_master = kdf.derive_master_key(elena.password, elena.salt)
        kek = envelope_crypto.envelope_kek(elena_master, elena.salt)
        wrapped = envelope_crypto.wrap_data_key(
            elena.data_key, kek=kek, username=elena.username,
            kdf_params=elena.kdf_params, nonce=os.urandom(12))
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=elena.headers, json={"data_key": elena.data_key_b64})
        tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/account/key-envelope/upgrade",
                      headers={**elena.headers, "X-Processing-Token": tok,
                               "X-Account-Verifier": elena.auth_b64},
                      json={"kdf_params": elena.kdf_params,
                            "wrapped_data_key": base64.b64encode(wrapped).decode()})
        check("v1->v2 envelope upgrade -> 204", r.status_code == 204)
        r = await req(c, "GET", "/api/auth/key-envelope", headers=elena.headers)
        env = r.json()
        check("envelope now v2 with wrapped key",
              env["key_scheme"] == "v2" and env["wrapped_data_key"])
        got_key = envelope_crypto.unwrap_data_key(
            base64.b64decode(env["wrapped_data_key"]), kek=kek,
            username=elena.username, kdf_params=elena.kdf_params)
        check("envelope unwraps to the SAME data key (no rekey happened)",
              got_key == elena.data_key)
        r = await req(c, "GET", "/api/entries?limit=1", headers=elena.headers)
        check("entries still decrypt after upgrade (key unchanged)",
              r.status_code == 200)

        old_elena_token = elena.token
        new_salt2 = os.urandom(16)
        new_master2 = kdf.derive_master_key("elena-sim-pass-10-new", new_salt2)
        old_auth_b64 = elena.auth_b64
        elena.auth_key = kdf.derive_auth_key(new_master2)
        elena.salt = new_salt2
        elena.password = "elena-sim-pass-10-new"
        kek2 = envelope_crypto.envelope_kek(new_master2, new_salt2)
        wrapped2 = envelope_crypto.wrap_data_key(
            elena.data_key, kek=kek2, username=elena.username,
            kdf_params=elena.kdf_params, nonce=os.urandom(12))
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=elena.headers, json={"data_key": elena.data_key_b64})
        tok = r.json()["session_token"]
        r = await req(c, "PUT", "/api/account/password",
                      headers={**elena.headers, "X-Processing-Token": tok},
                      json={"verifier": old_auth_b64,
                            "new_salt": base64.b64encode(new_salt2).decode(),
                            "new_verifier": elena.auth_b64,
                            "wrapped_data_key": base64.b64encode(wrapped2).decode(),
                            "new_kdf_params": elena.kdf_params})
        check("v2 password change (possession probe) -> 204", r.status_code == 204)
        r = await req(c, "GET", "/api/insights",
                      headers={"Authorization": f"Bearer {old_elena_token}"})
        check("old bearer died with the epoch bump", r.status_code == 401)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "elena", "verifier": elena.auth_b64})
        check("elena logs in with the NEW password", r.status_code == 200)
        elena.token = r.json()["token"]
        r = await req(c, "GET", "/api/auth/key-envelope", headers=elena.headers)
        env2 = r.json()
        got2 = envelope_crypto.unwrap_data_key(
            base64.b64decode(env2["wrapped_data_key"]), kek=kek2,
            username=elena.username, kdf_params=elena.kdf_params)
        check("new envelope unwraps (client-side) to the same data key",
              got2 == elena.data_key)
        r = await req(c, "GET",
                      f"/api/therapist/patients/{elena.user_id}/insights",
                      headers=dr_sharma.headers)
        check("therapist consent SURVIVES the O(1) password change "
              "(data key never moved)",
              r.status_code == 200)

        # credential-only rotation (ava): the documented v1 ordering —
        # rekey the blobs to the NEW password's key FIRST, then retire the
        # old credential (both keys still derivable inside that window).
        ava = clients["ava"]
        ava_old_auth = ava.auth_b64
        ava_old_key = ava.data_key
        ava_salt2 = os.urandom(16)
        ava_master2 = kdf.derive_master_key("ava-sim-pass-6-b", ava_salt2)
        ava.auth_key = kdf.derive_auth_key(ava_master2)
        ava.data_key = kdf.derive_data_key(ava_master2)
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=ava.headers,
                      json={"data_key": base64.b64encode(ava_old_key).decode()})
        ava_old_tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=ava.headers, json={"data_key": ava.data_key_b64})
        ava_new_tok = r.json()["session_token"]
        r = await req(c, "POST", "/api/processing/rekey",
                      headers={**ava.headers, "X-Processing-Token": ava_old_tok,
                               "X-New-Processing-Token": ava_new_tok,
                               "X-Account-Verifier": ava_old_auth})
        check("ava rekeys blobs to the new password's key first",
              r.status_code == 200 and r.json()["entries"] > 0)
        r = await req(c, "PUT", "/api/account/credential", headers=ava.headers, json={
            "verifier": ava_old_auth,
            "new_salt": base64.b64encode(ava_salt2).decode(),
            "new_verifier": base64.b64encode(ava.auth_key).decode()})
        check("credential rotation -> 204 (tokens die, re-login)", r.status_code == 204)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "ava", "verifier": base64.b64encode(ava.auth_key).decode()})
        check("ava re-logins with new credential", r.status_code == 200)
        ava.token = r.json()["token"]
        r = await req(c, "GET", "/api/entries?limit=1", headers=ava.headers)
        row = r.json()[0]
        dec = ava.decrypt_entry(row["blob"], row["client_entry_id"],
                                row["content_version"])
        check("ava's year decrypts under the new password's key",
              r.status_code == 200 and isinstance(dec["text"], str))
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "ava", "verifier": ava_old_auth})
        check("old credential is dead (401)", r.status_code == 401)

        # ---------------------------------------------------------------- 9
        phase("9 · TOTP 2FA (therapist role): full lifecycle")
        r = await req(c, "POST", "/api/account/totp/setup",
                      headers=dr_sharma.headers,
                      json={"verifier": dr_sharma.auth_b64})
        setup = r.json()
        check("totp setup -> secret + otpauth uri",
              r.status_code == 200 and setup["secret_base32"]
              and setup["otpauth_uri"].startswith("otpauth://totp/"))
        r = await req(c, "POST", "/api/account/totp/enable",
                      headers=dr_sharma.headers,
                      json={"verifier": dr_sharma.auth_b64, "code": "000000"})
        check("enable with wrong code -> 403 totp_code_invalid",
              r.status_code == 403 and r.json().get("code") == "totp_code_invalid")
        secret_b32 = setup["secret_base32"]
        secret = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))

        # A code is single-use per timestep: mint one per 30s window,
        # sleeping to the next boundary only when the window was consumed.
        used_ctr = [-1]

        async def fresh_code() -> str:
            ctr = int(walltime.time() // 30)
            if ctr == used_ctr[0]:
                await asyncio.sleep(30 - (walltime.time() % 30) + 0.4)
                ctr = int(walltime.time() // 30)
            used_ctr[0] = ctr
            return totp_mod._code_for_counter(secret, ctr)

        enable_code = await fresh_code()
        r = await req(c, "POST", "/api/account/totp/enable",
                      headers=dr_sharma.headers,
                      json={"verifier": dr_sharma.auth_b64, "code": enable_code})
        enable = r.json()
        check("enable with current code -> 200 + 8 backup codes",
              r.status_code == 200 and len(enable["backup_codes"]) == 8)

        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_sharma", "verifier": dr_sharma.auth_b64})
        check("login without code -> 401 totp_required",
              r.status_code == 401 and r.json().get("code") == "totp_required")
        login_code = await fresh_code()
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_sharma", "verifier": dr_sharma.auth_b64,
            "totp_code": login_code})
        check("login with fresh code -> 200", r.status_code == 200)
        dr_sharma.token = r.json()["token"]
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_sharma", "verifier": dr_sharma.auth_b64,
            "totp_code": login_code})
        check("login with REPLAYED code -> 401 totp_code_invalid",
              r.status_code == 401 and r.json().get("code") == "totp_code_invalid",
              "replay protection")
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_sharma", "verifier": dr_sharma.auth_b64,
            "totp_code": enable["backup_codes"][0]})
        check("login with a backup code -> 200 (then it burns)", r.status_code == 200)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_sharma", "verifier": dr_sharma.auth_b64,
            "totp_code": enable["backup_codes"][0]})
        check("same backup code reused -> 401", r.status_code == 401)
        r = await req(c, "GET", "/api/therapist/me", headers=dr_sharma.headers)
        check("GET /therapist/me reports totp_enabled", r.json()["totp_enabled"] is True)
        r = await req(c, "POST", "/api/account/totp/setup",
                      headers=maya.headers, json={"verifier": maya.auth_b64})
        check("patient token on totp/setup -> 403 (therapist-only)",
              r.status_code == 403)
        disable_code = await fresh_code()
        r = await req(c, "POST", "/api/account/totp/disable",
                      headers=dr_sharma.headers,
                      json={"verifier": dr_sharma.auth_b64, "code": disable_code})
        check("totp disable with code -> 204", r.status_code == 204)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_sharma", "verifier": dr_sharma.auth_b64})
        check("login works without code after disable", r.status_code == 200)
        dr_sharma.token = r.json()["token"]

        # --------------------------------------------------------------- 10
        phase("10 · LLM consent: honest refusal when no provider is configured")
        r = await req(c, "GET", "/api/account/llm-consent", headers=maya.headers)
        check("llm-consent defaults disabled",
              r.status_code == 200 and r.json()["enabled"] is False)
        r = await req(c, "PUT", "/api/account/llm-consent",
                      headers={**maya.headers, "X-Account-Verifier": maya.auth_b64},
                      json={"enabled": True, "verifier": maya.auth_b64})
        expected = 409 if not llm_flag else 200
        ok = (r.status_code == expected
              and (expected == 409 and r.json().get("code") == "llm_unavailable"))
        check("PUT enable with no provider configured -> 409 llm_unavailable",
              ok, f"meta.llm_available={llm_flag}")
        r = await req(c, "PUT", "/api/account/llm-consent",
                      headers={**maya.headers, "X-Account-Verifier": maya.auth_b64},
                      json={"enabled": False, "verifier": maya.auth_b64})
        check("PUT disable -> 200 (idempotent)", r.status_code == 200
              and r.json()["enabled"] is False)

        # --------------------------------------------------------------- 11
        phase("11 · logout kills exactly one token")
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "maya", "verifier": maya.auth_b64})
        second_token = r.json()["token"]
        r = await req(c, "POST", "/api/auth/logout",
                      headers={"Authorization": f"Bearer {second_token}"})
        check("logout -> 204", r.status_code == 204)
        r = await req(c, "GET", "/api/entries?limit=1",
                      headers={"Authorization": f"Bearer {second_token}"})
        check("logged-out token is dead (401)", r.status_code == 401)
        r = await req(c, "GET", "/api/entries?limit=1", headers=maya.headers)
        check("maya's main token still alive (jti-scoped revoke)",
              r.status_code == 200)

        # --------------------------------------------------------------- 12
        phase("12 · export: zero-knowledge bundle, decrypted locally")
        for p in personas:
            cl = clients[p.name]
            r = await req(c, "GET", "/api/account/export", headers=cl.headers)
            if r.status_code != 200:
                check(f"export {p.name} -> 200", False, r.text[:150])
                continue
            bundle = r.json()
            n_expected = len(p.entries) - (
                len(next(x for x in personas if x.name == "dev").deletes)
                if p.name == "dev" else 0)
            ok = (bundle["version"] == 1 and len(bundle["entries"]) == n_expected
                  and bundle["salt"])
            sample = bundle["entries"][0]
            dec = cl.decrypt_entry(sample["blob"], sample["client_entry_id"],
                                   sample["content_version"])
            ok = ok and isinstance(dec["text"], str)
            if p.name == "ben":
                ok = ok and len(bundle["measures"]) == len(p.measures) - 1
            if p.name == "elena":
                shares = bundle["shares"]
                ok = ok and len(shares) == 1 and shares[0]["status"] == "active"
            check(f"export {p.name}: full bundle, entries decrypt locally", ok,
                  f"{len(bundle['entries'])} entries")
        r = await req(c, "GET", "/api/account/export",
                      headers=clients["chloe"].headers)
        blob_raw = r.json()["entries"][0]["blob"]
        check("exported entry blobs are opaque ciphertext (no plaintext leak)",
              "disappear" not in blob_raw and base64.b64decode(blob_raw)[:1] != b"{")

        # --------------------------------------------------------------- 13
        phase("13 · access logs (patient + therapist) with cursor pagination")
        rows: list[dict] = []
        cursor = None
        for _ in range(100):   # safety cap; the log is far shorter
            params = {"limit": 7}
            if cursor:
                params["cursor"] = cursor   # httpx percent-encodes (+ | :)
            r = await req(c, "GET", "/api/account/access-log",
                          headers=elena.headers, params=params)
            page = r.json()
            if not isinstance(page, list):
                break
            rows.extend(page)
            cursor = r.headers.get("X-Next-Cursor")
            if cursor is None:
                break
        therapist_reads = [x for x in rows if x.get("actor") == "therapist"]
        check("elena's access log paginates fully and records therapist reads",
              r.status_code == 200 and len(rows) >= 8 and len(therapist_reads) >= 2,
              f"{len(rows)} rows, {len(therapist_reads)} therapist reads")
        r = await req(c, "GET", "/api/account/access-log?cursor=garbage",
                      headers=elena.headers)
        check("malformed cursor -> 422", r.status_code == 422)
        r = await req(c, "GET", "/api/therapist/access-log?limit=50",
                      headers=dr_sharma.headers)
        trows = r.json()
        check("therapist access log names the patient",
              r.status_code == 200 and any(
                  x.get("patient_name") == "elena" for x in trows))

        # --------------------------------------------------------------- 14
        phase("14 · boundaries, roles, deletion (dr_evil + fred)")
        r = await req(c, "GET", f"/api/therapist/patients/{elena.user_id}/insights",
                      headers=dr_evil.headers)
        check("therapist B reading therapist A's patient -> 404",
              r.status_code == 404)
        r = await req(c, "POST",
                      f"/api/therapist/patients/{maya.user_id}/notes",
                      headers=dr_evil.headers,
                      json={"client_note_id": "n1", "pattern_pid": None,
                            "blob": dr_evil.encrypt_note(maya.user_id, "n1", "x")})
        check("note on unpaired patient -> 404", r.status_code == 404)
        r = await req(c, "GET", "/api/therapist/patients/not-a-uuid/insights",
                      headers=dr_sharma.headers)
        check("random patient id -> flat 404", r.status_code == 404)
        patient_routes = ["GET /api/entries?limit=1", "GET /api/insights",
                          "GET /api/consents", "GET /api/questions/today",
                          "GET /api/account/export", "GET /api/measures?limit=1"]
        ok403 = True
        for route in patient_routes:
            method, path = route.split(" ", 1)
            r = await req(c, method, path, headers=dr_sharma.headers)
            ok403 = ok403 and r.status_code == 403
        check("therapist token on all patient reads -> 403", ok403)
        r = await req(c, "POST", "/api/processing/sessions",
                      headers=dr_sharma.headers, json={"data_key": maya.data_key_b64})
        check("therapist token on processing/sessions -> 403", r.status_code == 403)
        r = await req(c, "POST", "/api/entries", headers=dr_sharma.headers,
                      json={"client_entry_id": "t1", "blob": "AAAA",
                            "entry_date": TODAY.isoformat()})
        check("therapist token on POST /entries -> 403", r.status_code == 403)
        therapist_routes = ["GET /api/therapist/me", "GET /api/therapist/patients",
                            "POST /api/therapist/pairing-codes"]
        ok403 = True
        for route in therapist_routes:
            method, path = route.split(" ", 1)
            r = await req(c, method, path, headers=maya.headers)
            ok403 = ok403 and r.status_code == 403
        check("patient token on therapist routes -> 403", ok403)

        r = await req(c, "DELETE", "/api/therapist/account",
                      headers={**dr_evil.headers, "X-Account-Verifier": "AAAA"})
        check("therapist delete with wrong verifier -> 403", r.status_code == 403)
        r = await req(c, "DELETE", "/api/therapist/account",
                      headers={**dr_evil.headers,
                               "X-Account-Verifier": dr_evil.auth_b64})
        check("therapist account delete -> 204", r.status_code == 204)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "dr_evil", "verifier": dr_evil.auth_b64})
        check("deleted therapist cannot log in (401)", r.status_code == 401)

        fred = Client("fred", "fred-sim-pass-0")
        r = await req(c, "POST", "/api/auth/register", json=fred.register_body())
        fred.user_id, fred.token = r.json()["user_id"], r.json()["token"]
        fred_real_salt = fred.salt
        r = await req(c, "POST", "/api/entries", headers=fred.headers, json={
            "client_entry_id": "fred-1", "blob": fred.encrypt(
                {"text": "first day", "sentiment": 0.0, "date": TODAY,
                 "cid": "fred-1"}),
            "entry_date": TODAY.isoformat()})
        check("fred (baseline) writes an entry", r.status_code == 201)
        r = await req(c, "POST", "/api/insights/recompute", headers=fred.headers)
        check("baseline recompute: no token required, phase=baseline",
              r.status_code == 200 and r.json()["phase"] == "baseline"
              and r.json()["analyzer"] == "none")
        r = await req(c, "GET", "/api/questions/today", headers=fred.headers)
        check("baseline user has no question yet -> 404", r.status_code == 404)

        r = await req(c, "DELETE", "/api/account", headers=fred.headers)
        check("account delete without verifier -> 422", r.status_code == 422)
        r = await req(c, "DELETE", "/api/account",
                      headers={**fred.headers, "X-Account-Verifier": "AAAA"})
        check("account delete with wrong verifier -> 403", r.status_code == 403)
        r = await req(c, "DELETE", "/api/account",
                      headers={**fred.headers, "X-Account-Verifier": fred.auth_b64})
        check("account delete with verifier -> 204", r.status_code == 204)
        r = await req(c, "GET", "/api/entries?limit=1", headers=fred.headers)
        check("token dies with the account", r.status_code == 401)
        r = await req(c, "POST", "/api/auth/login", json={
            "username": "fred", "verifier": fred.auth_b64})
        check("deleted account login -> 401 (same as unknown)", r.status_code == 401)
        r = await req(c, "POST", "/api/auth/salt", json={"username": "fred"})
        decoy2 = r.json()["salt"]
        r = await req(c, "POST", "/api/auth/salt", json={"username": "fred"})
        check("salt after deletion: decoy, deterministic, never the real one",
              decoy2 == r.json()["salt"]
              and base64.b64decode(decoy2) != fred_real_salt
              and len(base64.b64decode(decoy2)) == 16)
        fred2 = Client("fred", "fred-sim-pass-reborn")
        r = await req(c, "POST", "/api/auth/register", json=fred2.register_body())
        fred2.user_id, fred2.token = r.json()["user_id"], r.json()["token"]
        check("username becomes available again (fresh account)",
              r.status_code == 201)
        r = await req(c, "GET", "/api/entries?limit=1", headers={
            "Authorization": f"Bearer {fred2.token}"})
        check("re-registered account starts empty", r.status_code == 200
              and r.json() == [])

        # --------------------------------------------------------------- 15
        phase("15 · storage at rest: zero-knowledge database inspection")
        async with build_sessionmaker(engine)() as s:
            tables = (await s.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "ORDER BY name"))).scalars().all()
            counts = {}
            for t in ["users", "entries", "insights", "measures", "consents",
                      "therapist_notes", "therapist_note_revisions",
                      "access_log", "token_revocation", "rekey_journal",
                      "pairing_codes", "totp_backup_codes"]:
                if t in tables:
                    counts[t] = (await s.execute(
                        text(f"SELECT COUNT(*) FROM {t}"))).scalar_one()
            blobs = (await s.execute(text(
                "SELECT blob FROM entries LIMIT 200"))).scalars().all()
            ins_blobs = (await s.execute(text(
                "SELECT blob FROM insights LIMIT 100"))).scalars().all()
            meas_blobs = (await s.execute(text(
                "SELECT blob FROM measures LIMIT 100"))).scalars().all()
        report["table_counts"] = counts
        print(f"      tables: {counts}")

        def looks_cipher(b) -> bool:
            """Structural ciphertext test: a stored plaintext payload would
            be valid UTF-8 AND parse as JSON. Random AES-GCM output meets
            the first condition once in a blue moon and the second never
            (even when a blob's first byte happens to be '{' or '[')."""
            raw = bytes(b)
            if len(raw) < 28:
                return False
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError:
                return True
            if decoded.lstrip()[:1] in ("{", "["):
                try:
                    json.loads(decoded)
                except json.JSONDecodeError:
                    return True
                return False   # a parseable JSON payload at rest = leak
            return '"text"' not in decoded

        check("entry blobs at rest are ciphertext (entropy profile)",
              len(blobs) == 200 and all(looks_cipher(b) for b in blobs))
        check("insight + measure blobs at rest are ciphertext",
              ins_blobs and all(looks_cipher(b) for b in ins_blobs)
              and meas_blobs and all(looks_cipher(b) for b in meas_blobs))

        db_bytes = (BACKEND / "sim1y.db").read_bytes()
        probes = [b"fingerpicking", b"doomscrolling", b"grandma", b"want to disappear",
                  b"deadline pressure", b"Session 1: adjusting"]
        leaks = [p for p in probes if p in db_bytes]
        check("raw DB file contains none of the journal/note plaintext",
              not leaks, f"leaked: {leaks}" if leaks else "6 probes clean")
        wal = BACKEND / "sim1y.db-wal"
        if wal.exists():
            wal_bytes = wal.read_bytes()
            leaks_wal = [p for p in probes if p in wal_bytes]
            check("DB write-ahead log is equally clean", not leaks_wal)

        # --------------------------------------------------------------- 16
        phase("16 · rate limiting: default ops bucket burst (429 + Retry-After)")
        hit_429 = None
        t0 = walltime.time()
        for i in range(241):
            # raw request: the 429 IS the expected answer here, no retry
            r = await c.get("/api/meta")
            if r.status_code == 429:
                hit_429 = r
                break
        check("ops bucket trips under burst -> 429 + Retry-After",
              hit_429 is not None
              and "retry-after" in {k.lower() for k in hit_429.headers},
              f"tripped at request {i + 1} / {walltime.time() - t0:.1f}s")

    await engine.dispose()

    # ------------------------------------------------------------------ out ----
    failed = [x for x in CHECKS if not x["ok"]]
    passed_n = len(CHECKS) - len(failed)
    print(f"\n{'=' * 70}")
    print(f"1-YEAR E2E CAMPAIGN: {passed_n}/{len(CHECKS)} checks passed")
    if failed:
        print("\nFAILED:")
        for x in failed:
            print(f"  [{x['phase']}] {x['name']} {x['extra']}")
    print(f"\ntotal wall time: {(walltime.time() - t_start) / 60:.1f} min")

    report["checks"] = CHECKS
    report["summary"] = {"passed": passed_n, "failed": len(failed),
                         "total": len(CHECKS)}
    out = Path(__file__).parent / "results.json"
    out.write_text(json.dumps(report, indent=2, default=str))
    print(f"full results: {out}")

    for u in report["users"]:
        csv_path = out.parent / f"timeline_{u['name']}.csv"
        with csv_path.open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=[
                "day", "date", "active_days", "recomputed", "surfaced",
                "new", "transitions"])
            writer.writeheader()
            for row in u["timeline"]:
                writer.writerow({"day": row["day"], "date": row["date"],
                                 "active_days": row["active_days"],
                                 "recomputed": row["recomputed"],
                                 "surfaced": row["surfaced"],
                                 "new": "; ".join(row["new"]),
                                 "transitions": "; ".join(row["transitions"])})
    print(f"wrote {len(report['users'])} timeline CSVs")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(run()))
