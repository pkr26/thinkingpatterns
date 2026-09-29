#!/usr/bin/env python3
"""365-day, 13-user MindPattern end-to-end simulation + full-API campaign.

Successor of reports/simulation60 (60 days, 5 users, 5 endpoints): the
same live-API philosophy — every entry synced through the real server
with the real client crypto — extended to a full year, thirteen
personas, and EVERY route the backend mounts, plus every functionality
that only a year of data exercises.

2026-09-29 VOICE EXTENSION: the campaign now exercises the whole voice
journaling surface as three additional real users who MIX voice and
typed entries, against two in-process fake providers the script itself
serves (an OpenAI-compatible STT endpoint and an OpenAI-compatible
chat-completions endpoint — the server cannot tell them from the real
things, which is the point):

  * rosa  — Spanish-speaking voice journaler: recordings transcribed
    through the STT round-trip, translated by the LLM path, saved as
    payload-v3 entries (input_mode=voice, transcript_lang=es,
    english_text), native-Spanish analysis (D-7 en/es routing);
  * amara — French-speaking voice journaler: the French transcripts
    are analyzed THROUGH their English translations (D-7 routing for
    languages without lexicons) — a pattern must surface from the
    translated text, and no pattern label may contain French;
  * kwame — English voice journaler + kept recordings: the full
    attachment lifecycle (encrypt-under-data-key upload, owner fetch
    byte-identical, replace, delete, lazy expiry 410, quota 413), the
    share-voice grant (therapist playback decrypts with the unwrapped
    key; off → 403; revoked consent → 404), and the H4 privacy gate
    (voice consent alone NEVER dispatches journal text to the LLM —
    english_text is null and the fake provider log stays empty until
    the account's CURRENT llm consent exists).

The voice pipeline is driven end to end: synthetic takes are POSTed as
base64 audio to /audio/transcriptions, the transcript + language +
translation come back from the fake providers, and the entry is
encrypted exactly the way the web client does (v3 payload). STT retry
(429 once → success) and hard upstream failure (500 ×2 → 502
stt_upstream) are proven through the same seam.

Everything below is the standing year-long campaign:

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
from app.db import build_sessionmaker
from app.models import User, utcnow
from app.security import crypto, kdf
from app.security import envelope as envelope_crypto
from app.security import sharing as sharing_crypto
from app.security import totp as totp_mod
from app.services import brain
from app.services.brain import STATISTICAL_KINDS
from app.services.patterns import JournalEntry
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import PublicFormat
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text, update
from sqlalchemy.ext.asyncio import create_async_engine

BASE_URL = os.environ.get("E2E_BASE", "http://127.0.0.1:8908")
DB_URL = os.environ.get("E2E_DB", f"sqlite+aiosqlite:///{BACKEND / 'sim1y.db'}")
# The fake provider endpoints this script serves, and the URLs the SERVER
# must have been booted with (MINDPATTERN_STT_URL / MINDPATTERN_LLM_URL).
STT_FAKE_URL = os.environ.get("E2E_STT", "http://127.0.0.1:8912/v1")
LLM_FAKE_URL = os.environ.get("E2E_LLM", "http://127.0.0.1:8913/v1")
STT_FAKE_KEY = "sim-stt-key"
LLM_FAKE_KEY = "sim-llm-key"
STT_PROVIDER_NAME = "SimWhisper"
# The server's audio local-dir store (MINDPATTERN_AUDIO_LOCAL_DIR for the
# sim boot; phase 17 inspects it, the erasure phase proves objects die).
AUDIO_DIR = Path(os.environ.get("E2E_AUDIO_DIR", str(BACKEND / "data" / "audio-sim1y")))
DAYS = 365
# Local calendar date on purpose: the personas' year is anchored to the
# operator's wall clock, same as the clients' entry_date picker.
TODAY = date.today()  # noqa: DTZ011

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


# ------------------------------------------------------- fake providers ----
#
# The voice pipeline's two third-party surfaces, served in-process so the
# REAL server code paths (services/stt.py SpeechToText, services/llm.py
# LLMAnalyzer) make genuine HTTP round-trips with genuine auth headers,
# multipart shapes, and response contracts. The STT fake decodes the
# campaign's deterministic synthetic takes; the LLM fake answers the
# translation prompt from a fixed phrasebook and the enrichment prompt
# with an empty narration set (the brain's findings stand unchanged).

SIM_MAGIC = b"SIMAUD1"


def synth_take(utterance: str, lang: str, marker: str = "", pad: int = 0) -> bytes:
    """Deterministic 'recording': magic | lang | marker | text | NUL pad."""
    return b"\x00".join(
        [SIM_MAGIC, lang.encode(), marker.encode(), utterance.encode()]
    ) + b"\x00" * pad


def parse_take(audio: bytes) -> tuple[str, str, str]:
    """(lang, marker, utterance) — raises ValueError on foreign audio."""
    parts = audio.split(b"\x00", 3)
    if len(parts) != 4 or parts[0] != SIM_MAGIC:
        raise ValueError("not a synthetic take")
    return parts[1].decode(), parts[2].decode(), parts[3].rstrip(b"\x00").decode()


# The phrasebook the LLM fake translates from. rosa/amara speak fixed
# sentences so every transcript's English is exact and assertable.
ES_BOOK: dict[str, str] = {
    "no puedo dormir, mi mente no para":
        "can't sleep, my mind won't stop",
    "me cuesta dormir, los pensamientos no paran":
        "struggling to sleep, the thoughts won't stop",
    "no puedo dormir, mi mente no para hoy":
        "can't sleep, my mind won't stop today",
    "se acerca la semana, mucha presión en el trabajo otra vez":
        "the week is looming, big deadline pressure at work again",
    "café en el balcón antes de empezar el día":
        "coffee on the balcony before starting the day",
    "el trayecto estuvo tranquilo hoy": "the commute was quiet today",
    "cociné algo sencillo para cenar": "cooked something simple for dinner",
    "regué las plantas y barrí la cocina":
        "watered the plants and swept the kitchen",
    "escuché media hora de podcast al volver":
        "listened to half a podcast on the way home",
    "compré pan en la panadería de la esquina":
        "bought bread at the corner bakery",
    "ordené un estante de la librería": "tidied one shelf of the bookcase",
    "caminé hasta la farmacia por el camino largo":
        "walked the long way to the pharmacy",
    "vi un capítulo de la serie documental":
        "watched an episode of the documentary series",
    "llamé a mi tía un rato": "called my aunt for a while",
    "estiré cinco minutos por la noche":
        "stretched for five minutes in the evening",
    "saqué al perro al parque": "took the dog to the park",
}

FR_BOOK: dict[str, str] = {
    "ma poitrine se serre avant la réunion hebdomadaire":
        "my chest tightens before the weekly review",
    "la poitrine serrée encore avant la réunion":
        "chest tight again before the review",
    "café sur le balcon avant de commencer":
        "coffee on the balcony before starting",
    "le trajet était calme aujourd'hui": "the commute was calm today",
    "j'ai cuisiné quelque chose de simple": "i cooked something simple",
    "j'ai arrosé les plantes et balayé la cuisine":
        "watered the plants and swept the kitchen",
    "j'ai écouté la moitié d'un podcast": "listened to half a podcast",
    "j'ai acheté du pain à la boulangerie": "bought bread at the bakery",
    "j'ai rangé une étagère de la bibliothèque":
        "tidied a shelf of the bookcase",
    "j'ai marché jusqu'à la pharmacie par le grand chemin":
        "walked to the pharmacy the long way",
    "j'ai regardé un épisode du documentaire":
        "watched an episode of the documentary",
    "j'ai appelé ma tante un moment": "called my aunt for a while",
    "j'ai étiré cinq minutes le soir": "stretched five minutes in the evening",
    "j'ai sorti le chien au parc": "took the dog to the park",
}

# whisper-1 asks for verbose_json, whose language field carries the
# provider's full NAME — exactly the shape normalize_language maps.
STT_LANG_NAMES = {"es": "spanish", "fr": "french", "en": "english"}


def _split_multipart(body: bytes, content_type: str) -> dict[str, tuple[str, bytes]]:
    """Dependency-free multipart/form-data parse: name -> (filename, data)."""
    match = re.search(r'boundary="?([^";]+)"?', content_type)
    if not match:
        raise ValueError("no boundary")
    boundary = b"--" + match.group(1).encode()
    out: dict[str, tuple[str, bytes]] = {}
    for chunk in body.split(boundary)[1:]:
        chunk = chunk.strip(b"\r\n")
        if chunk in (b"", b"--"):
            continue
        head, _, data = chunk.partition(b"\r\n\r\n")
        name_m = re.search(rb'name="([^"]+)"(?:;\s*filename="([^"]*)")?', head)
        if name_m is None:
            continue
        name = name_m.group(1).decode()
        filename = (name_m.group(2) or b"").decode()
        out[name] = (filename, data.rstrip(b"\r\n"))
    return out


STT_LOG: list[dict] = []
LLM_LOG: list[dict] = []


def build_fakes():
    stt_app = FastAPI()
    llm_app = FastAPI()

    @stt_app.get("/healthz")
    async def _stt_health():
        return {"ok": True}

    @stt_app.post("/v1/audio/transcriptions")
    async def _transcribe(request: Request):
        body = await request.body()
        parts = _split_multipart(body, request.headers.get("content-type", ""))
        if "file" not in parts or "model" not in parts:
            return JSONResponse({"error": "bad multipart"}, status_code=400)
        filename, audio = parts["file"]
        model = parts["model"][1].decode()
        response_format = parts.get("response_format", (b"", b"json"))[1].decode()
        STT_LOG.append({
            "size": len(audio), "filename": filename, "model": model,
            "format": response_format,
            "auth": request.headers.get("authorization", ""),
            "content": audio,
        })
        try:
            lang, marker, utterance = parse_take(audio)
        except ValueError:
            return JSONResponse({"error": "unparseable audio"}, status_code=400)
        if marker == "ALWAYSFAIL":
            return JSONResponse({"error": "upstream on fire"}, status_code=500)
        if marker == "RETRYONCE":
            seen = sum(1 for x in STT_LOG[:-1] if x["content"] == audio)
            if seen == 0:
                # one cold-queue refusal with a Retry-After the server
                # must honour (M8: one bounded retry)
                return JSONResponse(
                    {"error": "queue cold"}, status_code=429,
                    headers={"retry-after": "0"})
        return {"text": utterance, "language": STT_LANG_NAMES.get(lang, lang),
                "duration": round(len(audio) / 1024, 1)}

    @llm_app.get("/healthz")
    async def _llm_health():
        return {"ok": True}

    @llm_app.post("/v1/chat/completions")
    async def _chat(request: Request):
        payload = await request.json()
        system = payload["messages"][0]["content"]
        user = payload["messages"][-1]["content"]
        if "translation engine" in system:
            LLM_LOG.append({"kind": "translate", "text": user,
                            "auth": request.headers.get("authorization", "")})
            spec = json.loads(user)
            text, src = spec.get("text", ""), spec.get("source_language", "auto")
            if src in ("es",) or text in ES_BOOK:
                english = ES_BOOK.get(text, "ES:: " + text)
            elif src in ("fr",) or text in FR_BOOK:
                english = FR_BOOK.get(text, "FR:: " + text)
            else:
                english = text          # an English transcript echoes back
            return {"choices": [{"message": {"content": english}}]}
        LLM_LOG.append({"kind": "enrich", "text": user,
                        "auth": request.headers.get("authorization", "")})
        # the model may only NARRATE brain findings — none offered
        return {"choices": [{"message": {"content": '{"patterns": []}'}}]}

    return stt_app, llm_app


async def start_fakes() -> list:
    """Serve both fakes on loopback ports inside this event loop."""
    from urllib.parse import urlparse

    import uvicorn

    servers = []
    for app, url in ((build_fakes()[0], STT_FAKE_URL), (build_fakes()[1], LLM_FAKE_URL)):
        parsed = urlparse(url)
        cfg = uvicorn.Config(app, host="127.0.0.1", port=parsed.port,
                             log_level="error")
        server = uvicorn.Server(cfg)
        servers.append(server)
        asyncio.create_task(server.serve())
    async with httpx.AsyncClient(timeout=10) as probe:
        for server, url in zip(servers, (STT_FAKE_URL, LLM_FAKE_URL)):
            origin = f"http://{urlparse(url).netloc}"
            for _ in range(100):
                try:
                    if (await probe.get(origin + "/healthz")).status_code == 200:
                        break
                except httpx.HTTPError:
                    await asyncio.sleep(0.1)
            else:
                raise RuntimeError(f"fake provider at {url} did not come up")
    return servers


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


def gen_rosa(p: Persona):
    """Spanish VOICE journaler (payload v3, transcript_lang=es): typed
    Spanish notes in the morning, spoken evenings. M/W/F sleep worry in
    Spanish, Sunday work dread — the es twin of maya's story, spoken."""
    p.expected = ["voice year in Spanish (v3 entries, es analysis)",
                  "cluster on the Spanish sleep worry (recurring_phrase or rumination)"]
    typed_es = [k for k in ES_BOOK if k not in (
        "no puedo dormir, mi mente no para",
        "me cuesta dormir, los pensamientos no paran",
        "no puedo dormir, mi mente no para hoy",
        "se acerca la semana, mucha presión en el trabajo otra vez")]
    worry = ["no puedo dormir, mi mente no para",
             "me cuesta dormir, los pensamientos no paran"]
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        base = p.rng.uniform(-0.1, 0.2)
        if p.rng.random() < 0.55:                       # typed Spanish note
            p.add(d, p.rng.choice(typed_es), base)
        evening, sent = p.rng.choice(typed_es), base    # spoken take
        if d.weekday() == 6:
            evening = "se acerca la semana, mucha presión en el trabajo otra vez"
            sent = p.rng.uniform(-0.75, -0.55)
        elif d.weekday() in (0, 2, 4) and p.rng.random() < 0.8:
            evening = p.rng.choice(worry)
            sent = p.rng.uniform(-0.5, -0.3)
        p.add(d, evening, sent,
              voice={"lang": "es", "english": ES_BOOK[evening]})


def gen_amara(p: Persona):
    """French VOICE journaler: the D-7 routing persona — her transcripts
    are French, but the brain must analyze the ENGLISH translations (fr
    has no lexicon), so her patterns surface from translated text. The
    review worry is mostly ONE canonical sentence (maya's sleep-worry
    shape) so the cluster earns its support."""
    p.expected = ["voice year in French -> english_text analysis (D-7)",
                  "cluster on the translated chest-tightness worry",
                  "no French may ever appear in a pattern label"]
    typed_fr = [k for k in FR_BOOK if k not in (
        "ma poitrine se serre avant la réunion hebdomadaire",
        "la poitrine serrée encore avant la réunion")]
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        base = p.rng.uniform(-0.1, 0.2)
        if p.rng.random() < 0.4:                       # typed French note
            p.add(d, p.rng.choice(typed_fr), base)
        spoken, sent = p.rng.choice(typed_fr), base    # spoken take, daily
        if d.weekday() in (3, 6) and p.rng.random() < 0.9:
            spoken = ("la poitrine serrée encore avant la réunion"
                      if p.rng.random() < 0.2 else
                      "ma poitrine se serre avant la réunion hebdomadaire")
            sent = p.rng.uniform(-0.55, -0.35)
        p.add(d, spoken, sent,
              voice={"lang": "fr", "english": FR_BOOK[spoken]})


def gen_kwame(p: Persona):
    """English VOICE journaler + kept recordings: typed mornings, spoken
    evenings, every ~5th take KEPT (encrypted attachment). CONTROL voice
    user — varied mundane takes, no statistical kind may surface."""
    p.expected = ["voice CONTROL: mundane spoken year, zero statistical kinds",
                  "kept-recording lifecycle: upload/fetch/replace/delete/"]
    used: dict[int, int] = {}
    for i in range(DAYS):
        d = TODAY - timedelta(days=DAYS - 1 - i)
        s = p.rng.uniform(-0.3, 0.3)
        if p.rng.random() < 0.55:                      # typed morning
            p.add(d, p.filler(used), s)
        if p.rng.random() >= 0.75:
            continue                                   # speaks most days
        take = p.filler(used)
        keep = len([e for e in p.entries if e.get("voice")]) % 5 == 0
        p.add(d, take, s + p.rng.uniform(-0.05, 0.05),
              voice={"lang": "en", "english": take, "keep": keep})


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
        Persona("rosa", "rosa-sim-pass-11", 31, "VOICE es: spoken Spanish year, translated v3 entries"),
        Persona("amara", "amara-sim-pass-12", 32, "VOICE fr: spoken French year, english_text analysis"),
        Persona("kwame", "kwame-sim-pass-13", 33, "VOICE en + kept recordings + share-voice control"),
    ]
    gens = {"maya": gen_maya, "omar": gen_omar, "priya": gen_priya,
            "lena": gen_lena, "tom": gen_tom, "ava": gen_ava, "ben": gen_ben,
            "chloe": gen_chloe, "dev": gen_dev, "elena": gen_elena,
            "rosa": gen_rosa, "amara": gen_amara, "kwame": gen_kwame}
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
        voice = e.get("voice")
        if voice:
            # v3 exactly as the web client emits it (crypto/patient.ts):
            # the voice channels upgrade the payload; english_text rides
            # even when null, transcript_lang only when known.
            payload["v"] = 3
            payload["input_mode"] = "voice"
            if voice.get("lang"):
                payload["transcript_lang"] = voice["lang"]
            payload["english_text"] = voice.get("english")
        aad = crypto.entry_aad_v2(self.user_id, e["cid"], content_version)
        blob = crypto.encrypt(self.data_key, json.dumps(payload).encode(), aad)
        return base64.b64encode(blob).decode()

    def encrypt_audio(self, cid: str, audio: bytes) -> str:
        """Kept-recording envelope: same data key, AAD ("audio", uid, cid, 1)."""
        aad = crypto.build_aad("audio", self.user_id, cid, "1")
        return base64.b64encode(crypto.encrypt(self.data_key, audio, aad)).decode()

    def decrypt_audio(self, cid: str, blob_b64: str) -> bytes:
        aad = crypto.build_aad("audio", self.user_id, cid, "1")
        return crypto.decrypt(self.data_key, base64.b64decode(blob_b64), aad)

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
        # D-7 routing mirror (api/insights.py): en/es analyze the native
        # transcript; every other language analyzes english_text when one
        # was stored — the offline replay must feed the brain EXACTLY the
        # text the server's recompute fed it.
        text = e["text"]
        voice = e.get("voice")
        if (voice and voice.get("lang") not in ("en", "es", None)
                and isinstance(voice.get("english"), str) and voice["english"].strip()):
            text = voice["english"]
        out.append(JournalEntry(
            text=text, entry_date=e["date"], sentiment=e["sentiment"],
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
    print(f"target {BASE_URL}\ndb      {DB_URL}")
    print(f"plan    {DAYS} days, 13 personas (10 typed + 3 voice), every endpoint")
    print(f"fakes   stt {STT_FAKE_URL} / llm {LLM_FAKE_URL}\n")
    personas = build_personas()
    for p in personas:
        voice_n = len([e for e in p.entries if e.get("voice")])
        print(f"  {p.name:7} {len(p.entries):4} entries / "
              f"{len({e['date'] for e in p.entries}):3} active days"
              + (f" / {voice_n} VOICE" if voice_n else "")
              + (f" / {len(p.measures)} measures" if p.measures else ""))

    engine = create_async_engine(DB_URL)
    report: dict = {"days": DAYS, "users": [], "phases": []}
    fakes = await start_fakes()

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
        check("meta: llm_available True (fake provider configured)",
              llm_flag is True and meta["llm_provider_name"])
        check("meta: audio_available True with stt policy fingerprint",
              meta.get("audio_available") is True
              and meta.get("stt_provider_name") == STT_PROVIDER_NAME
              and bool(meta.get("stt_policy_fingerprint")),
              f"audio={meta.get('audio_available')}")
        r2 = await req(c, "GET", "/api/v1/meta")
        check("GET /api/v1/meta (canonical mount) mirrors /api/meta",
              r2.status_code == 200 and r2.json() == meta)

        # ---------------------------------------------------------------- 1
        phase("1 · registration: 13 patients + therapist (+ negatives)")
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
        check("all 13 patient registrations succeeded", len(clients) == 13)

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
        phase("2 · the year of entries: 10 typed users + typed notes of "
              "the voice users, real client crypto")
        sync_stats = {}
        for p in personas:
            cl = clients[p.name]
            typed = [e for e in p.entries if not e.get("voice")]
            t0 = walltime.time()
            ok = fail = 0
            for e in typed:
                r = await req(c, "POST", "/api/entries", headers=cl.headers, json={
                    "client_entry_id": e["cid"], "blob": cl.encrypt(e),
                    "entry_date": e["date"].isoformat(), "content_version": 1})
                ok += r.status_code == 201
                fail += r.status_code != 201
                if r.status_code != 201:
                    print(f"      !! {p.name} {e['cid']}: {r.status_code} {r.text[:120]}")
            secs = walltime.time() - t0
            sync_stats[p.name] = (ok, fail, secs)
            check(f"{p.name}: {ok}/{ok + fail} typed entries synced ({secs:.0f}s)",
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
        phase("3 · voice year: consent -> record -> transcribe -> translate "
              "-> save (rosa es, amara fr, kwame en)")
        rosa_p = next(p for p in personas if p.name == "rosa")
        amara_p = next(p for p in personas if p.name == "amara")
        kwame_p = next(p for p in personas if p.name == "kwame")
        rosa, amara, kwame = clients["rosa"], clients["amara"], clients["kwame"]
        ES_WORRY = "no puedo dormir, mi mente no para"
        ES_WORRY_EDIT = "no puedo dormir, mi mente no para hoy"
        FR_WORRY = "ma poitrine se serre avant la réunion hebdomadaire"

        def take_b64(utterance, lang, marker="", pad=0):
            return base64.b64encode(
                synth_take(utterance, lang, marker, pad)).decode()

        async def transcribe(cl, utterance, lang, marker="", pad=0,
                             mime="audio/webm", duration=47):
            return await req(c, "POST", "/api/audio/transcriptions",
                             headers=cl.headers, json={
                                 "audio_b64": take_b64(utterance, lang, marker, pad),
                                 "mime": mime, "duration_seconds": duration})

        # --- the consent wall: nothing voice-shaped works before opt-in
        r = await req(c, "GET", "/api/account/voice-consent", headers=rosa.headers)
        check("voice-consent defaults disabled",
              r.status_code == 200 and r.json()["enabled"] is False)
        r = await transcribe(rosa, ES_WORRY, "es")
        check("transcribe without voice consent -> 403 voice_consent_required",
              r.status_code == 403
              and r.json().get("code") == "voice_consent_required")
        r = await req(c, "POST", "/api/audio/attachments", headers=rosa.headers,
                      json={"client_entry_id": rosa_p.entries[0]["cid"],
                            "blob": rosa.encrypt_audio(rosa_p.entries[0]["cid"],
                                                       b"x" * 64),
                            "mime": "audio/webm", "duration_seconds": 30})
        check("attachment upload without voice consent -> 403", r.status_code == 403)
        r = await req(c, "POST", "/api/audio/transcriptions",
                      headers=dr_sharma.headers, json={
                          "audio_b64": take_b64("hello", "en"),
                          "mime": "audio/webm", "duration_seconds": 10})
        check("therapist token on /audio/transcriptions -> 403",
              r.status_code == 403)
        r = await req(c, "POST", "/api/audio/transcriptions", json={
            "audio_b64": take_b64("hello", "en"),
            "mime": "audio/webm", "duration_seconds": 10})
        check("anonymous transcribe -> 401", r.status_code == 401)

        # --- verifier discipline + opt-in for the three voice users
        r = await req(c, "PUT", "/api/account/voice-consent",
                      headers=rosa.headers,
                      json={"enabled": True})
        check("voice-consent enable WITHOUT verifier -> 422", r.status_code == 422)
        r = await req(c, "PUT", "/api/account/voice-consent",
                      headers={**rosa.headers, "X-Account-Verifier": rosa.auth_b64},
                      json={"enabled": True, "verifier": "AAAA"})
        check("voice-consent enable with WRONG verifier -> 403",
              r.status_code == 403)
        stt_policy = meta["stt_policy_fingerprint"]
        for cl in (rosa, amara, kwame):
            r = await req(c, "PUT", "/api/account/voice-consent",
                          headers={**cl.headers, "X-Account-Verifier": cl.auth_b64},
                          json={"enabled": True, "verifier": cl.auth_b64})
            body = r.json()
            check(f"{cl.username}: voice consent enabled against current policy",
                  r.status_code == 200 and body["enabled"] is True
                  and body["active_for_current_policy"] is True
                  and body["voice_consent_policy"] == stt_policy
                  and body["voice_consent_at"], str(body)[:140])
        # rosa and amara want their transcripts translated: the LLM consent
        # is a SEPARATE surface (H4) and must be granted explicitly. kwame
        # stays llm-consent-less for now — his H4 probe below depends on it.
        for cl in (rosa, amara):
            r = await req(c, "PUT", "/api/account/llm-consent",
                          headers={**cl.headers, "X-Account-Verifier": cl.auth_b64},
                          json={"enabled": True, "verifier": cl.auth_b64})
            check(f"{cl.username}: llm consent enabled (translation surface)",
                  r.status_code == 200 and r.json()["enabled"] is True
                  and r.json()["active_for_current_policy"] is True)

        # --- H4 gate: voice consent alone must NEVER dispatch text to the LLM
        llm_translates = lambda: [x for x in LLM_LOG if x["kind"] == "translate"]
        before = len(llm_translates())
        r = await transcribe(kwame, "walked the long way to the pharmacy", "en")
        body = r.json()
        check("kwame (voice consent, NO llm consent): transcript ok, "
              "english_text NULL (H4)",
              r.status_code == 200
              and body.get("original_text")
              == "walked the long way to the pharmacy"
              and body.get("language") == "en"
              and body.get("language_raw") == "english"
              and body.get("english_text") is None, str(body)[:160])
        check("H4: zero LLM translation dispatches for the non-consented account",
              len(llm_translates()) == before,
              f"{before} -> {len(llm_translates())}")
        r = await req(c, "POST", "/api/audio/translations", headers=kwame.headers,
                      json={"text": "walked the long way to the pharmacy",
                            "source_lang": "en"})
        check("re-translate while llm consent off -> null, still no dispatch",
              r.status_code == 200 and r.json()["english_text"] is None
              and len(llm_translates()) == before)
        r = await req(c, "PUT", "/api/account/llm-consent",
                      headers={**kwame.headers, "X-Account-Verifier": kwame.auth_b64},
                      json={"enabled": True, "verifier": kwame.auth_b64})
        check("kwame enables llm consent (provider configured) -> 200",
              r.status_code == 200 and r.json()["enabled"] is True)
        r = await req(c, "POST", "/api/audio/translations", headers=kwame.headers,
                      json={"text": "walked the long way to the pharmacy",
                            "source_lang": "en"})
        check("re-translate after llm consent -> english echo, exactly 1 dispatch",
              r.status_code == 200
              and r.json()["english_text"] == "walked the long way to the pharmacy"
              and len(llm_translates()) == before + 1)

        # --- rosa's first spoken entry: the full patient journey incl. edit
        rosa_first = next(e for e in rosa_p.entries
                          if e.get("voice") and e["text"] == ES_WORRY)
        r = await transcribe(rosa, ES_WORRY, "es")
        body = r.json()
        check("rosa take 1: spanish detected, phrasebook translation returned",
              r.status_code == 200 and body.get("original_text") == ES_WORRY
              and body.get("language") == "es"
              and body.get("language_raw") == "spanish"
              and body.get("english_text") == ES_BOOK[ES_WORRY]
              and body.get("provider_name") == STT_PROVIDER_NAME,
              str(body)[:170])
        if body.get("language"):
            saved = {**rosa_first,
                     "voice": {"lang": body["language"],
                               "english": body["english_text"]}}
        else:
            saved = {**rosa_first, "voice": {"lang": "es", "english": None}}
        r = await req(c, "POST", "/api/entries", headers=rosa.headers, json={
            "client_entry_id": saved["cid"], "blob": rosa.encrypt(saved),
            "entry_date": saved["date"].isoformat(), "content_version": 1})
        check("rosa saves her spoken entry (payload v3) -> 201",
              r.status_code == 201)
        r = await req(c, "POST", "/api/audio/translations", headers=rosa.headers,
                      json={"text": ES_WORRY_EDIT, "source_lang": "es"})
        check("rosa edits the transcript: re-translate before saving",
              r.status_code == 200
              and r.json()["english_text"] == ES_BOOK[ES_WORRY_EDIT])
        r = await req(c, "GET", f"/api/entries/{saved['cid']}", headers=rosa.headers)
        version = r.json()["content_version"]
        edited = {**saved, "text": ES_WORRY_EDIT,
                  "voice": {"lang": "es", "english": ES_BOOK[ES_WORRY_EDIT]}}
        r = await req(c, "PUT", f"/api/entries/{saved['cid']}",
                      headers=rosa.headers, json={
                          "blob": rosa.encrypt(edited, content_version=version + 1),
                          "entry_date": saved["date"].isoformat(),
                          "content_version": version + 1})
        check("edited voice entry PUT (v3 preserved) -> 200", r.status_code == 200)
        r = await req(c, "GET", f"/api/entries/{saved['cid']}", headers=rosa.headers)
        dec = rosa.decrypt_entry(r.json()["blob"], saved["cid"],
                                 r.json()["content_version"])
        check("edited entry decrypts with v3 channels intact",
              dec["v"] == 3 and dec["input_mode"] == "voice"
              and dec["text"] == ES_WORRY_EDIT
              and dec["transcript_lang"] == "es"
              and dec["english_text"] == ES_BOOK[ES_WORRY_EDIT])

        # --- amara's first French take: language routing sanity
        r = await transcribe(amara, FR_WORRY, "fr")
        body = r.json()
        check("amara take 1: french detected, english translation returned",
              r.status_code == 200 and body.get("original_text") == FR_WORRY
              and body.get("language") == "fr"
              and body.get("language_raw") == "french"
              and body.get("english_text") == FR_BOOK[FR_WORRY],
              str(body)[:170])

        # --- the bulk voice year: every take through the real pipeline
        voice_personas = {"rosa": rosa_p, "amara": amara_p, "kwame": kwame_p}
        attachments: dict[str, dict] = {}
        for pname, p in voice_personas.items():
            cl = clients[pname]
            vlist = [e for e in p.entries
                     if e.get("voice") and e["cid"] != saved["cid"]]
            t0, ok, fail = walltime.time(), 0, 0
            for e in vlist:
                r = await transcribe(cl, e["text"], e["voice"]["lang"])
                body = r.json()
                good = (r.status_code == 200
                        and body.get("original_text") == e["text"]
                        and body.get("language") == e["voice"]["lang"])
                expected_en = (e["text"] if e["voice"]["lang"] == "en"
                               else e["voice"]["english"])
                good = good and body.get("english_text") == expected_en
                ok += good
                fail += not good
                if not good:
                    print(f"      !! {pname} {e['cid']}: {r.status_code} "
                          f"{str(body)[:120]}")
                    continue
                entry = {**e, "voice": {"lang": body["language"],
                                        "english": body["english_text"]}}
                r = await req(c, "POST", "/api/entries", headers=cl.headers, json={
                    "client_entry_id": e["cid"], "blob": cl.encrypt(entry),
                    "entry_date": e["date"].isoformat(), "content_version": 1})
                ok += r.status_code == 201
                fail += r.status_code != 201
                if e["voice"].get("keep"):
                    take = synth_take(e["text"], e["voice"]["lang"])
                    r = await req(c, "POST", "/api/audio/attachments",
                                  headers=cl.headers, json={
                                      "client_entry_id": e["cid"],
                                      "blob": cl.encrypt_audio(e["cid"], take),
                                      "mime": "audio/webm",
                                      "duration_seconds": 47})
                    if r.status_code == 201:
                        attachments[e["cid"]] = {
                            "id": r.json()["attachment_id"],
                            "expires_at": r.json()["expires_at"],
                            "take": take}
                    else:
                        fail += 1
                        print(f"      !! {pname} attachment {e['cid']}: "
                              f"{r.status_code} {r.text[:120]}")
            secs = walltime.time() - t0
            check(f"{pname}: {len(vlist)} spoken takes transcribed+translated "
                  f"+ saved as v3 entries ({secs:.0f}s)", fail == 0)
        kept_n = len(attachments)
        check(f"kwame kept {kept_n} recordings (encrypted uploads -> 201)",
              kept_n >= 20)
        exp_days = {(date.fromisoformat(a["expires_at"][:10]) - TODAY).days
                    for a in attachments.values()}
        check("retention: every kept recording expires in ~30 days",
              bool(exp_days) and exp_days <= {29, 30, 31, 32},
              f"day deltas {sorted(exp_days)}")

        # --- the providers saw exactly the traffic the server should send
        check("every STT call carried the bearer key, whisper-1 + verbose_json",
              STT_LOG and all(x["auth"] == f"Bearer {STT_FAKE_KEY}"
                              and x["model"] == "whisper-1"
                              and x["format"] == "verbose_json"
                              for x in STT_LOG),
              f"{len(STT_LOG)} calls")
        ext_ok = all(x["filename"] == "recording.webm" for x in STT_LOG)
        check("STT filename derives from the mime table (recording.webm)", ext_ok)

        # --- STT retry (M8): one 429, honoured, retried, succeeds
        retry_take = synth_take("sorted the recycling and took it down",
                                "en", marker="RETRYONCE")
        r = await req(c, "POST", "/api/audio/transcriptions",
                      headers=kwame.headers, json={
                          "audio_b64": base64.b64encode(retry_take).decode(),
                          "mime": "audio/webm", "duration_seconds": 30})
        sends = sum(1 for x in STT_LOG if x["content"] == retry_take)
        check("STT 429-with-Retry-After retried exactly once -> transcript ok",
              r.status_code == 200
              and r.json().get("original_text")
              == "sorted the recycling and took it down"
              and sends == 2, f"{sends} upstream sends")
        fail_take = synth_take("this take never lands", "en", marker="ALWAYSFAIL")
        r = await req(c, "POST", "/api/audio/transcriptions",
                      headers=kwame.headers, json={
                          "audio_b64": base64.b64encode(fail_take).decode(),
                          "mime": "audio/webm", "duration_seconds": 30})
        check("STT hard upstream failure -> 502 stt_upstream (one retry, then up)",
              r.status_code == 502 and r.json().get("code") == "stt_upstream"
              and sum(1 for x in STT_LOG if x["content"] == fail_take) == 2)

        # --- route validation probes (consented user, hostile inputs)
        r = await transcribe(rosa, ES_WORRY, "es", mime="audio/flac")
        check("unsupported mime -> 422", r.status_code == 422)
        r = await transcribe(rosa, ES_WORRY, "es", duration=400)
        check("duration over the cap -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/audio/transcriptions",
                      headers=rosa.headers, json={
                          "audio_b64": "", "mime": "audio/webm",
                          "duration_seconds": 30})
        check("empty audio_b64 -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/audio/transcriptions",
                      headers=rosa.headers, json={
                          "audio_b64": "not-base64!!", "mime": "audio/webm",
                          "duration_seconds": 30})
        check("audio_b64 not base64 -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/audio/transcriptions",
                      headers=rosa.headers, json={
                          "audio_b64": base64.b64encode(os.urandom(5 * 1024 * 1024)).decode(),
                          "mime": "audio/webm", "duration_seconds": 30})
        check("5 MiB take -> 413 at the audio body cap", r.status_code == 413)

        # --- owner listing shows unexpired kept-audio metadata only
        r = await req(c, "GET", "/api/entries?limit=500", headers=kwame.headers)
        rows = {x["client_entry_id"]: x for x in r.json()}
        kept_cids = set(attachments)
        with_audio = {cid for cid, x in rows.items() if x.get("audio")}
        check("kwame's entry listing carries audio meta exactly on kept takes",
              with_audio == kept_cids,
              f"{len(with_audio)} meta / {len(kept_cids)} kept")
        sample_cid = next(iter(kept_cids))
        check("audio meta names the attachment + expiry",
              rows[sample_cid]["audio"]["attachment_id"]
              == attachments[sample_cid]["id"]
              and rows[sample_cid]["audio"]["expires_at"])

        # ---------------------------------------------------------------- 4
        phase("4 · editing lifecycle (dev) + list pagination (dev, maya)")
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
        mid_date = all_rows[len(all_rows) // 2]["entry_date"]
        r = await req(c, "GET", f"/api/entries?since={mid_date}&limit=500",
                      headers=dev.headers)
        later = r.json()
        check("since= filter bounds the window (only later rows, boundary kept)",
              r.status_code == 200 and later
              and all(x["entry_date"] >= mid_date for x in later)
              and later[0]["entry_date"] == mid_date
              and len(later) < len(all_rows))

        # ---------------------------------------------------------------- 5
        phase("5 · measures: a year of encrypted PHQ-9 (ben, chloe)")
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

        # ---------------------------------------------------------------- 6
        phase("6 · recompute, insights, questions, determinism (13 users)")
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
            # The three voice users hold CURRENT llm consent on a configured
            # endpoint, so their recompute legitimately runs brain-first with
            # the (no-op narration) enricher: analyzer "llm". Everyone else
            # must stay on the deterministic brain alone.
            expected_analyzer = ({"brain", "llm"} if p.name
                                 in ("rosa", "amara", "kwame") else {"brain"})
            if not check(f"{p.name}: recompute -> insight phase",
                         r.status_code == 200 and live["phase"] == "insight"
                         and live["analyzer"] in expected_analyzer,
                         str(live)[:160]):
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
                print(f"        day {fd!s:>3} [{x['state']:9}] {x['kind']:18} "
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

        # --- voice-persona assertions (the spoken years) -------------------
        rosa_pat = insights_per_user["rosa"]["patterns"]
        rosa_worry = [x for x in rosa_pat
                      if "dormir" in x["label"].lower() or "mente" in x["label"].lower()]
        check("rosa: the SPANISH sleep-worry take clusters (spoken year, es)",
              bool(rosa_worry)
              and rosa_worry[0]["kind"] in ("recurring_phrase", "rumination")
              and rosa_worry[0]["occurrences"] >= 20,
              f"{[(x['kind'], x['occurrences']) for x in rosa_worry]}")
        amara_pat = insights_per_user["amara"]["patterns"]
        amara_worry = [x for x in amara_pat
                       if "chest" in x["label"].lower() or "review" in x["label"].lower()]
        check("amara: worry surfaces from the ENGLISH translation (fr -> en D-7)",
              bool(amara_worry)
              and amara_worry[0]["kind"] in ("recurring_phrase", "rumination")
              and amara_worry[0]["occurrences"] >= 15,
              f"{[(x['kind'], x['occurrences']) for x in amara_worry]}")
        check("amara: no French ever reaches a pattern label (analysis ran en)",
              not any("poitrine" in x["label"].lower()
                      or "réunion" in x["label"].lower() for x in amara_pat))
        kwame_pat = insights_per_user["kwame"]["patterns"]
        kwame_stat = [x for x in kwame_pat if x["kind"] in STATISTICAL_KINDS]
        check("VOICE CONTROL kwame: zero statistical kinds (spoken noise year)",
              not kwame_stat, f"surfaced: {[x['kind'] for x in kwame_pat]}")
        enrich_calls = [x for x in LLM_LOG if x["kind"] == "enrich"]
        check("llm enricher observed on consented recomputes (narration-only "
              "contract; kwame holds no findings to narrate)",
              len(enrich_calls) >= 2
              and all('"findings"' in x["text"] for x in enrich_calls),
              f"{len(enrich_calls)} enrichment calls")

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

        # ---------------------------------------------------------------- 7
        phase("7 · local-recompute: on-device brain, escrow upload (chloe)")
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

        # ---------------------------------------------------------------- 8
        phase("8 · zero-knowledge sharing lifecycle (elena+ben -> dr_sharma)")
        elena = clients["elena"]
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

        # --- kwame's voice-sharing grant: playback behind share_voice -----
        r = await req(c, "POST", "/api/therapist/pairing-codes",
                      headers=dr_sharma.headers)
        code_k = r.json()["code"]
        wrap_k = sharing_crypto.wrap_data_key(
            kwame.data_key, dr_sharma._pub_b64(), kwame.user_id, dr_sharma.user_id)
        r = await req(c, "POST", "/api/consents",
                      headers={**kwame.headers, "X-Account-Verifier": kwame.auth_b64},
                      json={"code": code_k, "ephemeral_pub": wrap_k[0],
                            "wrapped_key": wrap_k[1], "disclosure": "v2"})
        kwame_consent = r.json()
        check("kwame grants dr_sharma -> 201", r.status_code == 201)
        r = await req(c, "PUT", f"/api/consents/{kwame_consent['id']}/share-voice",
                      headers=kwame.headers, json={"enabled": True})
        check("share-voice without verifier -> 422", r.status_code == 422)
        r = await req(c, "PUT", f"/api/consents/{kwame_consent['id']}/share-voice",
                      headers={**kwame.headers, "X-Account-Verifier": "AAAA"},
                      json={"enabled": True})
        check("share-voice with wrong verifier -> 403", r.status_code == 403)
        r = await req(c, "PUT", f"/api/consents/{kwame_consent['id']}/share-voice",
                      headers={**kwame.headers,
                               "X-Account-Verifier": kwame.auth_b64},
                      json={"enabled": True})
        check("share-voice ON -> 200, grant widened",
              r.status_code == 200 and r.json()["share_voice"] is True)
        r = await req(c, "GET", "/api/consents", headers=kwame.headers)
        check("kwame's own consent list shows share_voice=True",
              r.status_code == 200 and r.json()[0]["share_voice"] is True)
        r = await req(c, "GET", "/api/therapist/patients", headers=dr_sharma.headers)
        krow = next(x for x in r.json() if x["user_id"] == kwame.user_id)
        check("portal roster serves the live share_voice grant (P5)",
              krow.get("share_voice") is True)
        kwame_unwrapped = dr_sharma.unwrap_patient_key(
            kwame, krow["ephemeral_pub"], krow["wrapped_key"])
        check("portal unwraps kwame's data key", kwame_unwrapped == kwame.data_key)

        # walk kwame's entries through the therapist window (page size 25)
        # until a kept-recording row shows up
        voice_row, offset = None, 0
        for _ in range(30):
            r = await req(
                c, "GET",
                f"/api/therapist/patients/{kwame.user_id}/entries"
                f"?limit=25&offset={offset}",
                headers=dr_sharma.headers)
            page = r.json()
            if not isinstance(page, list):
                break
            voice_row = next(
                (x for x in page if x["client_entry_id"] in attachments), None)
            nxt = r.headers.get("X-Next-Offset")
            if voice_row is not None or nxt is None:
                break
            offset = int(nxt)
        check("therapist entry listing carries audio meta for kept takes",
              voice_row is not None
              and (voice_row.get("audio") or {}).get("attachment_id")
              == attachments[voice_row["client_entry_id"]]["id"])
        dec = json.loads(crypto.decrypt(
            kwame_unwrapped, base64.b64decode(voice_row["blob"]),
            crypto.entry_aad_v2(kwame.user_id, voice_row["client_entry_id"],
                                voice_row["content_version"])))
        check("portal decrypts a v3 voice entry (mode + lang + translation)",
              dec["v"] == 3 and dec["input_mode"] == "voice"
              and dec.get("transcript_lang") == "en"
              and dec.get("english_text") == dec["text"])

        att = attachments[voice_row["client_entry_id"]]
        audio_path = (f"/api/therapist/patients/{kwame.user_id}"
                      f"/audio/{att['id']}")
        r = await req(c, "GET", audio_path, headers=dr_evil.headers)
        check("OTHER therapist's audio fetch -> flat 404", r.status_code == 404)
        r = await req(c, "GET", audio_path, headers=dr_sharma.headers)
        played = r.json()
        plain = crypto.decrypt(
            kwame_unwrapped, base64.b64decode(played["blob"]),
            crypto.build_aad("audio", kwame.user_id,
                             voice_row["client_entry_id"], "1"))
        check("therapist plays the kept recording: decrypts to the take bytes",
              r.status_code == 200
              and played["client_entry_id"] == voice_row["client_entry_id"]
              and plain == att["take"])
        check("playback metadata honest (mime/duration/size/expiry)",
              played["mime_type"] == "audio/webm"
              and played["duration_seconds"] == 47
              and played["size_bytes"] == len(att["take"]) + 28
              and played["expires_at"])

        r = await req(c, "PUT", f"/api/consents/{kwame_consent['id']}/share-voice",
                      headers={**kwame.headers,
                               "X-Account-Verifier": kwame.auth_b64},
                      json={"enabled": False})
        check("share-voice OFF -> 200, grant narrowed",
              r.status_code == 200 and r.json()["share_voice"] is False)
        r = await req(c, "GET", audio_path, headers=dr_sharma.headers)
        check("audio fetch with share-voice off -> 403", r.status_code == 403)
        r = await req(c, "PUT", f"/api/consents/{kwame_consent['id']}/share-voice",
                      headers={**kwame.headers,
                               "X-Account-Verifier": kwame.auth_b64},
                      json={"enabled": True})
        check("share-voice back ON -> 200", r.status_code == 200)
        r = await req(c, "GET", audio_path, headers=dr_sharma.headers)
        check("playback resumes after re-enable (2nd audited access)",
              r.status_code == 200)

        # revoking the consent kills the audio path with it
        r = await req(c, "DELETE", f"/api/consents/{kwame_consent['id']}",
                      headers={**kwame.headers,
                               "X-Account-Verifier": kwame.auth_b64})
        check("kwame revokes the grant -> 204", r.status_code == 204)
        r = await req(c, "GET", audio_path, headers=dr_sharma.headers)
        check("audio fetch after revoke -> 404 (consent-gated)", r.status_code == 404)

        # ---------------------------------------------------------------- 9
        phase("9 · kept-recording lifecycle: fetch/replace/delete/expiry/"
              "quota (kwame)")
        def dir_objects() -> set:
            return {p.relative_to(AUDIO_DIR).as_posix()
                    for p in AUDIO_DIR.rglob("*.enc")} if AUDIO_DIR.exists() else set()

        cid_a = next(iter(attachments))
        att_a = attachments[cid_a]
        r = await req(c, "GET", f"/api/audio/attachments/{att_a['id']}",
                      headers=kwame.headers)
        check("owner fetch: blob decrypts to the original take",
              r.status_code == 200
              and kwame.decrypt_audio(cid_a, r.json()["blob"]) == att_a["take"])
        r = await req(c, "GET", f"/api/audio/attachments/{att_a['id']}",
                      headers=rosa.headers)
        check("another patient's attachment id -> flat 404", r.status_code == 404)

        # replace: same entry re-recorded — the old object must die
        before_objs = dir_objects()
        new_take = synth_take("sorted the recycling and took it down", "en")
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": cid_a,
                            "blob": kwame.encrypt_audio(cid_a, new_take),
                            "mime": "audio/webm", "duration_seconds": 52})
        replaced = r.json()
        check("re-upload replaces (same attachment row, refreshed expiry)",
              r.status_code == 201
              and replaced["attachment_id"] == att_a["id"]
              and replaced["expires_at"] > att_a["expires_at"],
              f"{att_a['expires_at']} -> {replaced['expires_at']}")
        r = await req(c, "GET", f"/api/audio/attachments/{att_a['id']}",
                      headers=kwame.headers)
        check("replaced recording decrypts to the NEW take",
              r.status_code == 200
              and kwame.decrypt_audio(cid_a, r.json()["blob"]) == new_take)
        check("replace deleted the old object (no orphans on disk)",
              len(dir_objects()) == len(before_objs),
              f"{len(before_objs)} -> {len(dir_objects())} objects")
        attachments[cid_a]["take"] = new_take

        # delete: the ENTRY survives, the audio is gone
        cid_b = next(cid for cid in attachments if cid != cid_a)
        r = await req(c, "DELETE",
                      f"/api/audio/attachments/{attachments[cid_b]['id']}",
                      headers=kwame.headers)
        check("attachment DELETE -> 204", r.status_code == 204)
        r = await req(c, "GET",
                      f"/api/audio/attachments/{attachments[cid_b]['id']}",
                      headers=kwame.headers)
        check("deleted attachment GET -> 404", r.status_code == 404)
        r = await req(c, "GET", f"/api/entries/{cid_b}", headers=kwame.headers)
        check("the entry itself survives the audio delete",
              r.status_code == 200 and r.json().get("audio") is None)
        del attachments[cid_b]

        # lazy expiry: a row aged past retention answers 410 and dies
        cid_c = next(cid for cid in attachments if cid != cid_a)
        att_c = attachments[cid_c]
        async with build_sessionmaker(engine)() as s:
            await s.execute(text(
                "UPDATE audio_attachments SET expires_at = :past WHERE id = :id"),
                {"past": utcnow() - timedelta(seconds=5), "id": att_c["id"]})
            await s.commit()
        r = await req(c, "GET", f"/api/audio/attachments/{att_c['id']}",
                      headers=kwame.headers)
        check("expired recording GET -> 410 audio_expired (lazy sweep)",
              r.status_code == 410 and r.json().get("code") == "audio_expired")
        r = await req(c, "GET", f"/api/audio/attachments/{att_c['id']}",
                      headers=kwame.headers)
        check("expired row is GONE after the lazy delete", r.status_code == 404)
        r = await req(c, "GET", "/api/entries?limit=500", headers=kwame.headers)
        row_c = next(x for x in r.json() if x["client_entry_id"] == cid_c)
        check("entry listing drops audio meta once expired",
              row_c.get("audio") is None)
        del attachments[cid_c]

        # quota: padded takes until the account cap refuses
        quota_cid = cid_a
        pad_take = synth_take("quota probe take", "en", pad=150 * 1024)
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": quota_cid,
                            "blob": kwame.encrypt_audio(quota_cid, pad_take),
                            "mime": "audio/webm", "duration_seconds": 240})
        check("large re-upload within quota -> 201 (replace accounting)",
              r.status_code == 201, r.text[:120])
        quota_cid2 = next(cid for cid in attachments
                          if cid not in (cid_a, quota_cid))
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": quota_cid2,
                            "blob": kwame.encrypt_audio(
                                quota_cid2, synth_take("over quota", "en",
                                                       pad=150 * 1024)),
                            "mime": "audio/webm", "duration_seconds": 240})
        check("quota exceeded -> 413 audio_quota_exceeded",
              r.status_code == 413
              and r.json().get("code") == "audio_quota_exceeded")

        # validation probes on the attachment route
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": "no-such-entry",
                            "blob": kwame.encrypt_audio("no-such-entry", b"x" * 64),
                            "mime": "audio/webm", "duration_seconds": 30})
        check("attachment for unknown entry -> 404 unknown_entry",
              r.status_code == 404 and r.json().get("code") == "unknown_entry")
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": cid_a,
                            "blob": base64.b64encode(b"toosmall").decode(),
                            "mime": "audio/webm", "duration_seconds": 30})
        check("blob under MIN_BLOB_SIZE -> 422", r.status_code == 422)
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": cid_a,
                            "blob": kwame.encrypt_audio(cid_a, b"y" * 64),
                            "mime": "audio/flac", "duration_seconds": 30})
        check("attachment with unsupported mime -> 422", r.status_code == 422)

        # consent OFF again: transcription and uploads stop, kept audio
        # stays playable (no provider is involved in playback)
        r = await req(c, "PUT", "/api/account/voice-consent",
                      headers={**kwame.headers,
                               "X-Account-Verifier": kwame.auth_b64},
                      json={"enabled": False, "verifier": kwame.auth_b64})
        check("kwame disables voice consent -> 200 (record wiped)",
              r.status_code == 200 and r.json()["enabled"] is False
              and r.json()["voice_consent_at"] is None)
        r = await transcribe(kwame, "walked the long way to the pharmacy", "en")
        check("transcribe after consent off -> 403", r.status_code == 403)
        r = await req(c, "POST", "/api/audio/attachments", headers=kwame.headers,
                      json={"client_entry_id": cid_a,
                            "blob": kwame.encrypt_audio(cid_a, b"z" * 64),
                            "mime": "audio/webm", "duration_seconds": 30})
        check("attachment upload after consent off -> 403", r.status_code == 403)
        r = await req(c, "GET", f"/api/audio/attachments/{att_a['id']}",
                      headers=kwame.headers)
        check("kept recordings remain PLAYABLE with consent off",
              r.status_code == 200)
        r = await req(c, "PUT", "/api/account/voice-consent",
                      headers={**kwame.headers,
                               "X-Account-Verifier": kwame.auth_b64},
                      json={"enabled": True, "verifier": kwame.auth_b64})
        check("kwame re-enables voice consent -> 200", r.status_code == 200)

        # --------------------------------------------------------------- 10
        phase("10 · key lifecycle: rekey (priya), envelope v2 + O(1) password (elena)")
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

        # --------------------------------------------------------------- 11
        phase("11 · TOTP 2FA (therapist role): full lifecycle")
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
        # --------------------------------------------------------------- 12
        phase("12 · LLM consent lifecycle (fake provider configured by this "
              "campaign)")
        r = await req(c, "GET", "/api/account/llm-consent", headers=maya.headers)
        check("llm-consent defaults disabled",
              r.status_code == 200 and r.json()["enabled"] is False)
        r = await req(c, "PUT", "/api/account/llm-consent",
                      headers={**maya.headers, "X-Account-Verifier": maya.auth_b64},
                      json={"enabled": True, "verifier": maya.auth_b64})
        body = r.json()
        expected = 200 if llm_flag else 409
        ok = r.status_code == expected and (
            (expected == 200 and body["enabled"] is True
             and body["active_for_current_policy"] is True
             and body["llm_consent_policy"] == meta.get("llm_policy_fingerprint")
             and body["llm_consent_at"])
            or (expected == 409 and body.get("code") == "llm_unavailable"))
        check("PUT enable -> 200 against the current policy fingerprint "
              "(409 llm_unavailable when unconfigured)", ok,
              f"meta.llm_available={llm_flag}")
        r = await req(c, "PUT", "/api/account/llm-consent",
                      headers={**maya.headers, "X-Account-Verifier": maya.auth_b64},
                      json={"enabled": True, "verifier": maya.auth_b64})
        check("double-enable idempotent", r.status_code == 200
              and r.json()["enabled"] is True)
        r = await req(c, "PUT", "/api/account/llm-consent",
                      headers={**maya.headers, "X-Account-Verifier": maya.auth_b64},
                      json={"enabled": False, "verifier": maya.auth_b64})
        check("PUT disable -> 200 (record wiped)", r.status_code == 200
              and r.json()["enabled"] is False
              and r.json()["llm_consent_at"] is None)

        # --------------------------------------------------------------- 13
        phase("13 · logout kills exactly one token")
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

        # --------------------------------------------------------------- 14
        phase("14 · export: zero-knowledge bundle, decrypted locally")
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
            if p.name in ("rosa", "amara", "kwame"):
                # the voice channels ride the export: find one spoken entry
                spoken = next(x for x in bundle["entries"]
                              if x["client_entry_id"].startswith(p.name)
                              and not x["client_entry_id"].endswith("phq9")
                              and cl.decrypt_entry(
                                  x["blob"], x["client_entry_id"],
                                  x["content_version"]).get("v") == 3)
                vdec = cl.decrypt_entry(spoken["blob"], spoken["client_entry_id"],
                                        spoken["content_version"])
                ok = ok and vdec["input_mode"] == "voice"
                ok = ok and vdec.get("transcript_lang") in ("es", "fr", "en")
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

        # --------------------------------------------------------------- 15
        phase("15 · access logs (patient + therapist) with cursor pagination")
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
        # kwame's voice-sharing actions + the therapist's audio playback
        r = await req(c, "GET", "/api/account/access-log?limit=200",
                      headers=kwame.headers)
        klog = r.json()
        audio_access = [x for x in klog if x.get("action") == "audio_access"]
        share_toggles = {x.get("action") for x in klog
                         if x.get("action", "").startswith("share_voice")}
        check("kwame's log records every audited therapist playback",
              r.status_code == 200 and len(audio_access) >= 2
              and all(x.get("actor") == "therapist" for x in audio_access),
              f"{len(audio_access)} audio_access rows")
        check("share-voice on/off toggles are audit-logged as patient actions",
              share_toggles >= {"share_voice_on", "share_voice_off"},
              str(sorted(share_toggles)))

        # --------------------------------------------------------------- 16
        phase("16 · boundaries, roles, deletion (dr_evil + fred + gina)")
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
                          "GET /api/account/export", "GET /api/measures?limit=1",
                          "GET /api/audio/attachments/whatever-id",
                          "POST /api/audio/transcriptions"]
        ok403 = True
        for route in patient_routes:
            method, path = route.split(" ", 1)
            if method == "POST":
                r = await req(c, method, path, headers=dr_sharma.headers, json={
                    "audio_b64": "AAAA", "mime": "audio/webm",
                    "duration_seconds": 10})
            else:
                r = await req(c, method, path, headers=dr_sharma.headers)
            ok403 = ok403 and r.status_code == 403
        check("therapist token on all patient reads (+audio) -> 403", ok403)
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

        # gina: voice user erased with kept recordings (M2 — objects die too)
        gina = Client("gina", "gina-sim-pass-1")
        r = await req(c, "POST", "/api/auth/register", json=gina.register_body())
        gina.user_id, gina.token = r.json()["user_id"], r.json()["token"]
        r = await req(c, "PUT", "/api/account/voice-consent",
                      headers={**gina.headers, "X-Account-Verifier": gina.auth_b64},
                      json={"enabled": True, "verifier": gina.auth_b64})
        check("gina enables voice consent", r.status_code == 200)
        gina_entry = {"text": "spoke my first note", "sentiment": 0.1,
                      "date": TODAY, "cid": "gina-1"}
        r = await req(c, "POST", "/api/entries", headers=gina.headers, json={
            "client_entry_id": "gina-1", "blob": gina.encrypt(gina_entry),
            "entry_date": TODAY.isoformat()})
        check("gina writes an entry", r.status_code == 201)
        gina_take = synth_take("spoke my first note", "en")
        r = await req(c, "POST", "/api/audio/attachments", headers=gina.headers,
                      json={"client_entry_id": "gina-1",
                            "blob": gina.encrypt_audio("gina-1", gina_take),
                            "mime": "audio/webm", "duration_seconds": 21})
        check("gina keeps one recording", r.status_code == 201)
        gina_dir = AUDIO_DIR / "audio" / gina.user_id
        check("gina's object exists in the local store before erasure",
              gina_dir.exists()
              and any(p.is_file() for p in gina_dir.rglob("*")))
        r = await req(c, "DELETE", "/api/account",
                      headers={**gina.headers, "X-Account-Verifier": gina.auth_b64})
        check("gina account delete (kept audio present) -> 204",
              r.status_code == 204)
        # M2: the erasure path best-effort-deletes the OBJECTS before the
        # row cascade — and the store prunes the account's now-empty
        # directory, so the erased identity leaves nothing on disk
        check("account erasure removed her audio OBJECTS, not just rows (M2)",
              not gina_dir.exists(),
              f"leftovers: {[p.name for p in gina_dir.rglob('*')]}"
              if gina_dir.exists() else "user dir gone")

        # --------------------------------------------------------------- 17
        phase("17 · storage at rest: zero-knowledge database inspection")
        async with build_sessionmaker(engine)() as s:
            tables = (await s.execute(text(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "ORDER BY name"))).scalars().all()
            counts = {}
            for t in ["users", "entries", "insights", "measures", "consents",
                      "therapist_notes", "therapist_note_revisions",
                      "access_log", "token_revocation", "rekey_journal",
                      "pairing_codes", "totp_backup_codes", "audio_attachments"]:
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
        check("audio_attachments table holds kwame's kept recordings",
              counts.get("audio_attachments", 0) >= 20,
              f"{counts.get('audio_attachments')} rows")

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
                  b"deadline pressure", b"Session 1: adjusting",
                  b"no puedo dormir", b"ma poitrine", b"SIMAUD1"]
        leaks = [p for p in probes if p in db_bytes]
        check("raw DB file contains none of the journal/note/voice plaintext",
              not leaks, f"leaked: {leaks}" if leaks else "9 probes clean")
        wal = BACKEND / "sim1y.db-wal"
        if wal.exists():
            wal_bytes = wal.read_bytes()
            leaks_wal = [p for p in probes if p in wal_bytes]
            check("DB write-ahead log is equally clean", not leaks_wal)

        # the local audio store: objects must be CLIENT CIPHERTEXT — the
        # synthetic take marker can never appear on disk in the clear
        audio_files = list(AUDIO_DIR.rglob("*.enc")) if AUDIO_DIR.exists() else []
        plain_objs = [p for p in audio_files
                      if SIM_MAGIC in p.read_bytes()[:4096]]
        check("audio store objects are opaque ciphertext (no take plaintext)",
              len(audio_files) >= 20 and not plain_objs,
              f"{len(audio_files)} objects, {len(plain_objs)} leaking")

        # --------------------------------------------------------------- 18
        phase("18 · rate limiting: default ops bucket burst (429 + Retry-After)")
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

    for server in fakes:
        server.should_exit = True
    await engine.dispose()

    # ------------------------------------------------------------------ out ----
    failed = [x for x in CHECKS if not x["ok"]]
    passed_n = len(CHECKS) - len(failed)
    print(f"\n{'=' * 70}")
    print(f"VOICE+TEXT 1-YEAR E2E CAMPAIGN: {passed_n}/{len(CHECKS)} checks passed")
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
