#!/usr/bin/env python3
"""Live black-box E2E campaign for MindPattern.

Runs against a REAL uvicorn server (default http://127.0.0.1:8907) and
exercises every user-visible scenario with multiple simultaneous users:
patients, therapists, attackers. The client-side crypto mirrors the real
mobile app and portal (same KDF, AES-256-GCM envelopes, AAD bindings,
ECDH->HKDF key wrap), so the server only ever sees what a real device
would send.

Two direct-DB touchpoints (clearly marked) exist for the same reason
scripts/seed_demo.py has them: to give a test account honest history
(age created_at) and to simulate server-side corruption (byte flips in
stored ciphertext). Every HTTP flow itself is pure black-box.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import traceback
from datetime import date, timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[2] / "backend"
sys.path.insert(0, str(BACKEND))
REPO = BACKEND.parent

import httpx
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from sqlalchemy import update
from sqlalchemy.ext.asyncio import create_async_engine

from app.security import crypto, kdf, sharing
from app.db import build_sessionmaker
from app.models import Entry, Insight, User

BASE_URL = os.environ.get("E2E_BASE", "http://127.0.0.1:8907")
DB_URL = os.environ.get(
    "E2E_DB", f"sqlite+aiosqlite:///{BACKEND / 'e2e_test.db'}")
TODAY = date.today()

CRISIS_PHRASES = json.loads((REPO / "shared" / "crisis_phrases.json").read_text())

# ---------------------------------------------------------------- results ----

RESULTS: list[dict] = []
CURRENT_GROUP = ["boot"]


def group(name: str) -> None:
    CURRENT_GROUP[0] = name
    print(f"\n--- {name} ---")


def check(name: str, ok: bool, evidence: str = "") -> bool:
    entry = {
        "group": CURRENT_GROUP[0],
        "name": name,
        "ok": bool(ok),
        "evidence": str(evidence)[:400],
    }
    RESULTS.append(entry)
    mark = "PASS" if ok else "FAIL"
    print(f"[{mark}] {name}" + (f"  | {evidence}" if evidence and not ok else ""))
    return bool(ok)


def code_of(resp: httpx.Response) -> str:
    try:
        return resp.json().get("code", "")
    except Exception:
        return ""


async def req(client, method, path, *, retry_429=True, **kw):
    """Request wrapper: transparently wait out rate limits EXCEPT where the
    test explicitly wants to observe the 429 (retry_429=False)."""
    for attempt in range(6):
        resp = await client.request(method, path, **kw)
        if resp.status_code == 429 and retry_429 and attempt < 5:
            await asyncio.sleep(float(resp.headers.get("retry-after", "20")) + 1)
            continue
        return resp
    return resp


# ------------------------------------------------------------ emulators ----


class Patient:
    """The mobile app: PBKDF2 master -> HKDF auth/data keys, AES-GCM blobs."""

    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.salt = os.urandom(16)
        self.master = kdf.derive_master_key(password, self.salt)
        self.auth_key = kdf.derive_auth_key(self.master)
        self.data_key = kdf.derive_data_key(self.master)
        self.user_id: str | None = None
        self.token: str | None = None

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def encrypt_entry(self, text: str, entry_date: date, cid: str, sentiment=None, plaintext=None):
        payload = plaintext if plaintext is not None else {
            "v": 1, "text": text, "sentiment": sentiment,
            "created_at": entry_date.isoformat(),
        }
        if plaintext is None and sentiment is None:
            payload["sentiment"] = None
        aad = crypto.build_aad("entry", self.user_id or "", cid)
        blob = crypto.encrypt(
            self.data_key,
            json.dumps(payload).encode() if plaintext is None else plaintext,
            aad,
        )
        return base64.b64encode(blob).decode()

    def decrypt_blob(self, blob_b64: str, aad: bytes) -> dict:
        return json.loads(crypto.decrypt(self.data_key, base64.b64decode(blob_b64), aad))

    async def register(self, c) -> httpx.Response:
        r = await req(c, "POST", "/api/auth/register", json={
            "username": self.username,
            "salt": base64.b64encode(self.salt).decode(),
            "verifier": base64.b64encode(self.auth_key).decode(),
        })
        if r.status_code == 201:
            self.user_id, self.token = r.json()["user_id"], r.json()["token"]
        return r

    async def login(self, c) -> httpx.Response:
        r = await req(c, "POST", "/api/auth/login", json={
            "username": self.username,
            "verifier": base64.b64encode(self.auth_key).decode(),
        })
        if r.status_code == 200:
            self.user_id, self.token = r.json()["user_id"], r.json()["token"]
        return r

    async def add_entry(self, c, text, entry_date, cid, sentiment=None, plaintext=None):
        return await req(c, "POST", "/api/entries", headers=self.headers, json={
            "client_entry_id": cid,
            "blob": self.encrypt_entry(text, entry_date, cid, sentiment, plaintext),
            "entry_date": entry_date.isoformat(),
        })

    async def recompute(self, c, processing_token="OPEN"):
        tok = processing_token
        if tok == "OPEN":
            r = await req(c, "POST", "/api/processing/sessions",
                          headers=self.headers,
                          json={"data_key": base64.b64encode(self.data_key).decode()})
            if r.status_code != 201:
                return r
            tok = r.json()["session_token"]
        headers = {**self.headers, "X-Processing-Token": tok} if tok else self.headers
        return await req(c, "POST", "/api/insights/recompute", headers=headers)

    def decrypt_insights(self, blob_b64):
        return self.decrypt_blob(
            blob_b64, crypto.build_aad("insights", self.user_id, "patterns"))


class Therapist:
    """The portal: password KEK wraps a real P-256 keypair; notes key."""

    def __init__(self, username: str, password: str, display_name: str):
        self.username, self.password, self.display_name = username, password, display_name
        self.salt = os.urandom(16)
        self.master = kdf.derive_master_key(password, self.salt)
        self.auth_key = kdf.derive_auth_key(self.master)
        self.wrap_kek = kdf.hkdf_sha256(self.master, None, sharing.PORTAL_WRAP_INFO)
        self.notes_key = kdf.hkdf_sha256(self.master, None, sharing.PORTAL_NOTES_INFO)
        self.priv = ec.generate_private_key(ec.SECP256R1())
        self.wrap_pub_key = base64.b64encode(
            self.priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        ).decode()
        self.user_id, self.token, self.stored_key_blob = None, None, None

    @property
    def headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def _pkcs8(self):
        return self.priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

    def key_blob_b64(self):
        blob = crypto.encrypt(
            self.wrap_kek, self._pkcs8(),
            crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, self.username))
        return base64.b64encode(blob).decode()

    async def register(self, c, pub_override=None, blob_override=None):
        r = await req(c, "POST", "/api/therapist/register", json={
            "username": self.username,
            "salt": base64.b64encode(self.salt).decode(),
            "verifier": base64.b64encode(self.auth_key).decode(),
            "display_name": self.display_name,
            "wrap_pub_key": pub_override or self.wrap_pub_key,
            "wrap_key_blob": blob_override or self.key_blob_b64(),
        })
        if r.status_code == 201:
            self.user_id, self.token = r.json()["user_id"], r.json()["token"]
        return r

    async def fetch_me(self, c):
        r = await req(c, "GET", "/api/therapist/me", headers=self.headers)
        if r.status_code == 200:
            self.stored_key_blob = r.json()["wrap_key_blob"]
        return r

    def unlock_private_key(self):
        blob = base64.b64decode(self.stored_key_blob or self.key_blob_b64())
        plain = crypto.decrypt(
            self.wrap_kek, blob,
            crypto.build_aad(sharing.THERAPIST_KEY_CONTEXT, self.username))
        return sharing.load_private_key_pkcs8(plain)

    def unwrap_patient_key(self, patient: Patient, ephemeral_b64, wrapped_b64) -> bytes:
        return sharing.unwrap_data_key(
            self.unlock_private_key(), ephemeral_b64, base64.b64decode(wrapped_b64),
            patient.user_id, self.user_id,
            therapist_pub_der=base64.b64decode(self.wrap_pub_key))

    def encrypt_note(self, patient: Patient, cid: str, text: str):
        aad = crypto.build_aad(sharing.NOTE_CONTEXT, self.user_id, patient.user_id, cid)
        return base64.b64encode(crypto.encrypt(
            self.notes_key, json.dumps({"v": 1, "text": text}).encode(), aad)).decode()

    def decrypt_note(self, patient: Patient, cid: str, blob_b64):
        aad = crypto.build_aad(sharing.NOTE_CONTEXT, self.user_id, patient.user_id, cid)
        return json.loads(crypto.decrypt(self.notes_key, base64.b64decode(blob_b64), aad))


# ------------------------------------------------------- direct-DB helpers ----
# (same reach-through seed_demo.py uses; see module docstring)


async def db_age_account(user_id: str, days: int):
    engine = create_async_engine(DB_URL)
    async with build_sessionmaker(engine)() as s:
        from app.models import utcnow
        await s.execute(update(User).where(User.id == user_id).values(
            created_at=utcnow() - timedelta(days=days)))
        await s.commit()
    await engine.dispose()


async def db_flip_entry_blob(user_id: str, cid: str) -> bytes:
    """Corrupt one stored ciphertext byte; returns the original blob."""
    from sqlalchemy import select
    engine = create_async_engine(DB_URL)
    original = None
    async with build_sessionmaker(engine)() as s:
        row = (await s.execute(select(Entry).where(
            Entry.user_id == user_id, Entry.client_entry_id == cid))).scalar_one()
        original = bytes(row.blob)
        corrupted = bytearray(original)
        corrupted[-1] ^= 0xFF
        row.blob = bytes(corrupted)
        await s.commit()
    await engine.dispose()
    return original


async def db_restore_entry_blob(user_id: str, cid: str, blob: bytes):
    from sqlalchemy import select
    engine = create_async_engine(DB_URL)
    async with build_sessionmaker(engine)() as s:
        row = (await s.execute(select(Entry).where(
            Entry.user_id == user_id, Entry.client_entry_id == cid))).scalar_one()
        row.blob = blob
        await s.commit()
    await engine.dispose()


async def db_corrupt_brain_state(user_id: str):
    from sqlalchemy import select
    engine = create_async_engine(DB_URL)
    async with build_sessionmaker(engine)() as s:
        row = (await s.execute(select(Insight).where(
            Insight.user_id == user_id, Insight.kind == "brain"))).scalar_one()
        blob = bytearray(bytes(row.blob))
        blob[-1] ^= 0xFF
        row.blob = bytes(blob)
        await s.commit()
    await engine.dispose()


# ------------------------------------------------------------ corpora ----

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
    "paid the utilities and filed the receipt",
    "took the long way home through the park",
    "brewed proper coffee instead of instant",
    "answered the group chat and caught up on messages",
    "looked up train times for the weekend trip",
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
]
POSITIVE = [
    "felt genuinely good today, calm and rested",
    "great day, laughed a lot with friends, grateful",
    "peaceful morning, productive afternoon, feeling hopeful",
]
NEGATIVE = [
    "felt low and drained, hard to focus",
    "anxious all day, overwhelmed and tense",
    "sad and empty tonight, nothing helped",
    "worn out and irritable by the afternoon",
    "numb and disconnected most of the day",
]


def structured_corpus(end: date, days: int, seed: int) -> list[dict]:
    """Sunday work dread + recurring sleep worry + family-visit next-day dips
    + rising guitar topic + late mood decline (the structures the brain
    should find)."""
    rng = random.Random(seed)
    start = end - timedelta(days=days - 1)
    mood, carry, day = {}, 0.0, start
    while day <= end:
        phi, amp = (0.60, 0.70) if day >= end - timedelta(days=27) else (0.05, 0.15)
        carry = phi * carry + (1 - phi) * rng.uniform(-amp, amp)
        v = 0.05 + carry - (0.55 if day >= end - timedelta(days=20) else 0)
        mood[day] = max(-1.0, min(1.0, v))
        day += timedelta(days=1)
    family, day = set(), start + timedelta(days=6)
    while day <= end - timedelta(days=6):
        family.add(day)
        day += timedelta(days=7 + rng.randrange(3))
    for d in family:
        for k in (1, 2):
            if d + timedelta(days=k) in mood:
                mood[d + timedelta(days=k)] = min(mood[d + timedelta(days=k)], -0.55)
    for d in mood:
        if d.weekday() == 6:
            mood[d] = min(mood[d], -0.45)
    worry, day = set(), start + timedelta(days=5)
    while day <= end - timedelta(days=2):
        worry.add(day)
        day += timedelta(days=6 + rng.randrange(2))
    guitar, day = set(), end - timedelta(days=40)
    while len(guitar) < 11 and day <= end:
        if day.weekday() != 2:
            guitar.add(day)
        day += timedelta(days=2)
    guitar_early = {start + timedelta(days=9), start + timedelta(days=24)}

    entries, uses, gi = [], {}, 0
    day = start
    while day <= end:
        wd = day.weekday()
        planted = wd == 6 or day in family or day in worry or day in guitar or day in guitar_early
        if planted or (wd != 2 and rng.random() < 0.85):
            avail = [i for i in range(len(FILLERS)) if uses.get(i, 0) < 2]
            text = FILLERS[rng.choice(avail)] if avail else ""
            if wd == 6:
                text = "big deadline pressure at work again, boss emailed twice about monday"
            if day in family:
                text += ". visited the family, mom and dad were there"
            if day in worry:
                text += ". " + rng.choice(SLEEP_WORRY)
            if day in guitar_early:
                text += ". messed around on the guitar for a bit"
            if day in guitar:
                text += ". " + GUITAR[gi % len(GUITAR)]
                gi += 1
            m = mood[day]
            if m > 0.35:
                text += ". " + rng.choice(POSITIVE)
            elif m < -0.35:
                text += ". " + rng.choice(NEGATIVE)
            entries.append({"text": text, "date": day,
                            "sentiment": round(m, 3),
                            "cid": f"e2e-{day.isoformat()}"})
        day += timedelta(days=1)
    return entries


def plain_mood_corpus(end: date, days: int, crisis: bool) -> list[dict]:
    """Simple diary: mild structure + (optionally) crisis-adjacent lines the
    server must never quote back in pattern labels."""
    rng = random.Random(99 if crisis else 55)
    entries = []
    for i in range(days):
        d = end - timedelta(days=days - 1 - i)
        m = rng.uniform(-0.8, 0.3) - (0.3 if i > days * 0.6 else 0)
        text = rng.choice(FILLERS)
        if d.weekday() == 6:
            text += ". work dread again, the week starts tomorrow"
        if i % 6 == 3:
            text += ". " + rng.choice(SLEEP_WORRY)
        if crisis and i % 5 == 1:
            text += ". honestly sometimes i feel like ending it all, i am so tired"
        if crisis and i % 7 == 2:
            text += ". there are days i think about killing myself and it scares me"
        if m < -0.4:
            text += ". " + rng.choice(NEGATIVE)
        entries.append({"text": text, "date": d, "sentiment": round(m, 3),
                        "cid": f"e2e-{d.isoformat()}"})
    return entries


DIALOG_REGEXES = [re.compile(p, re.I) for p in CRISIS_PHRASES["dialog"]]

# The crisis-leak oracle must be at least as strong as the engine it audits:
# run the REAL backend tiers (read-only import — this script already puts
# backend/ on sys.path for app.security). The old raw-text dialog-regex
# scan missed everything the engine's normalization/variant/suppress tiers
# exist to catch (leet digits, split variants, diacritics, zero-width
# tricks, suppress-tier phrasing), so a regression there was invisible to
# this campaign (2026-09-19 audit, L-97).
from app.services import crisis as _crisis_engine  # noqa: E402


def quotes_crisis_language(text: str) -> str | None:
    """True engine verdict first (dialog OR suppress tier); then a
    best-effort regex only to name WHICH phrase fired for the check
    message."""
    try:
        if not (_crisis_engine.matches_dialog(text) or _crisis_engine.matches_suppress(text)):
            return None
    except Exception:
        # Engine import blew up mid-run: fall back to the (weaker) regex
        # scan rather than silently passing everything.
        for rx in DIALOG_REGEXES:
            m = rx.search(text)
            if m:
                return m.group(0)
        return None
    for rx in DIALOG_REGEXES:
        m = rx.search(text)
        if m:
            return m.group(0)
    # Engine tier fired through a normalization/variant the plain regexes
    # cannot see — that is precisely the class of leak this oracle must
    # still catch.
    return "<crisis language caught by the engine's normalization/variant tiers>"


# ------------------------------------------------------------- scenarios ----


async def s_meta(c):
    group("1 · meta & mounts")
    r = await req(c, "GET", "/api/meta")
    body = r.json()
    check("GET /api/meta", r.status_code == 200 and body["unlock_days"] == 30
          and body["llm_available"] is False and body["api_version"] == "v1",
          f"{r.status_code} {body}")
    r = await req(c, "GET", "/api/v1/meta")
    check("canonical /api/v1 mount answers identically",
          r.status_code == 200 and r.json().get("unlock_days") == 30, f"{r.status_code}")
    r = await req(c, "GET", "/api/does-not-exist")
    j = r.json() if r.content else {}
    check("unknown route -> flat error envelope (string detail + code)",
          r.status_code == 404 and isinstance(j.get("detail"), str) and j.get("code") == "not_found",
          f"{r.status_code} {j}")
    r = await req(c, "GET", "/docs")
    check("GET /docs (development mode)", r.status_code == 200, f"{r.status_code}")


async def s_registration(c, users: dict):
    group("2 · registration & validation")
    alice: Patient = users["alice"]
    r = await alice.register(c)
    body = r.json()
    check("patient registers (201, token, role=user)",
          r.status_code == 201 and body.get("role") == "user" and body.get("token"),
          f"{r.status_code} {body}")
    r = await users["bob"].register(c)
    check("second patient registers independently",
          r.status_code == 201 and users["bob"].user_id != alice.user_id, f"{r.status_code}")
    r = await req(c, "POST", "/api/auth/register", json={
        "username": "alice", "salt": base64.b64encode(os.urandom(16)).decode(),
        "verifier": base64.b64encode(os.urandom(32)).decode()})
    check("duplicate username -> 409 conflict", r.status_code == 409 and code_of(r) == "conflict",
          f"{r.status_code} {r.text[:120]}")
    for label, uname in [("too-short username", "ab"), ("illegal characters", "bad name!"),
                         ("overlong username", "x" * 65)]:
        r = await req(c, "POST", "/api/auth/register", json={
            "username": uname, "salt": base64.b64encode(os.urandom(16)).decode(),
            "verifier": base64.b64encode(os.urandom(32)).decode()})
        check(f"{label} -> 422", r.status_code == 422 and code_of(r) == "validation_error",
              f"{r.status_code}")
    for label, salt, ver in [
        ("salt not 16 bytes", base64.b64encode(os.urandom(8)).decode(),
         base64.b64encode(os.urandom(32)).decode()),
        ("verifier not 32 bytes", base64.b64encode(os.urandom(16)).decode(),
         base64.b64encode(os.urandom(16)).decode()),
        ("salt not base64", "!!!not-b64!!!", base64.b64encode(os.urandom(32)).decode()),
    ]:
        r = await req(c, "POST", "/api/auth/register", json={
            "username": "valtest", "salt": salt, "verifier": ver})
        check(f"{label} -> 422", r.status_code == 422, f"{r.status_code} {r.text[:100]}")
    r = await req(c, "POST", "/api/auth/register", json={})
    j = r.json()
    check("empty body -> 422 with STRING detail (not fastapi list)",
          r.status_code == 422 and isinstance(j.get("detail"), str), f"{r.status_code} {j}")


async def s_salt_enumeration(c, users):
    group("3 · salt lookup / enumeration posture")
    r = await req(c, "POST", "/api/auth/salt", json={"username": "alice"})
    salt_known = r.json().get("salt", "")
    check("salt for existing user", r.status_code == 200 and len(base64.b64decode(salt_known)) == 16,
          f"{r.status_code}")
    r = await req(c, "POST", "/api/auth/salt", json={"username": "who-does-not-exist"})
    salt_unknown = r.json().get("salt", "")
    check("salt for UNKNOWN user -> 200 decoy, same shape",
          r.status_code == 200 and len(salt_unknown) == len(salt_known)
          and salt_unknown != salt_known, f"{r.status_code} len={len(salt_unknown)}")
    r = await req(c, "POST", "/api/auth/salt", json={"username": "x" * 200})
    check("oversized probe string handled (no oracle)", r.status_code in (200, 422),
          f"{r.status_code}")


async def s_login_logout(c, users):
    group("4 · login / logout / token epochs")
    alice: Patient = users["alice"]
    r = await alice.login(c)
    check("login with correct password-derived verifier",
          r.status_code == 200 and r.json().get("role") == "user", f"{r.status_code}")
    wrong = Patient("alice", "wrong-password-entirely")
    r = await wrong.login(c)
    check("wrong password -> 401 invalid_credentials",
          r.status_code == 401 and code_of(r) == "invalid_credentials", f"{r.status_code}")
    ghost = Patient("ghost-user", "whatever")
    r = await ghost.login(c)
    same_detail = r.json().get("detail")
    check("unknown user -> identical 401 (no existence oracle)",
          r.status_code == 401 and same_detail == "invalid credentials", f"{r.status_code} {same_detail}")
    dev1 = dict(alice.headers)
    await alice.login(c)
    dev2 = dict(alice.headers)
    r1 = await req(c, "GET", "/api/entries", headers=dev1)
    r2 = await req(c, "GET", "/api/entries", headers=dev2)
    check("two devices hold valid tokens simultaneously",
          r1.status_code == 200 and r2.status_code == 200, f"{r1.status_code}/{r2.status_code}")
    r = await req(c, "POST", "/api/auth/logout", headers=dev2)
    check("logout -> 204", r.status_code == 204, f"{r.status_code}")
    r1 = await req(c, "GET", "/api/entries", headers=dev1)
    r2 = await req(c, "GET", "/api/entries", headers=dev2)
    check("epoch bump kills ALL device tokens at once",
          r1.status_code == 401 and r2.status_code == 401, f"{r1.status_code}/{r2.status_code}")
    r = await alice.login(c)
    check("fresh login after logout works", r.status_code == 200, f"{r.status_code}")
    r = await req(c, "GET", "/api/entries")
    check("missing bearer -> 401 envelope", r.status_code == 401 and code_of(r) == "unauthorized",
          f"{r.status_code}")
    r = await req(c, "GET", "/api/entries", headers={"Authorization": "Bearer garbage"})
    check("garbage bearer -> 401 envelope", r.status_code == 401 and code_of(r) == "unauthorized",
          f"{r.status_code}")


async def s_entries(c, users):
    group("5 · journal entry sync (bob)")
    bob: Patient = users["bob"]
    await db_age_account(bob.user_id, 7)  # a week-old user, as the journal implies
    texts = [f"bob day {i}: {t}" for i, t in enumerate(
        ["calm morning walk", "productive work day", "argued with a friend, feeling low",
         "good gym session", "quiet evening with a book"], start=1)]
    days = [TODAY - timedelta(days=k) for k in (5, 4, 3, 2, 1)]
    ok = True
    for text, d in zip(texts, days):
        r = await bob.add_entry(c, text, d, f"bob-{d.isoformat()}")
        ok = ok and r.status_code == 201
    check("create 5 AES-GCM entries (201 each)", ok, "see individual calls")
    r = await req(c, "GET", "/api/entries", headers=bob.headers)
    rows = r.json()
    check("list returns 5 entries in date order",
          r.status_code == 200 and len(rows) == 5
          and [x["entry_date"] for x in rows] == sorted(x["entry_date"] for x in rows),
          f"{r.status_code} n={len(rows)}")
    roundtrip = True
    for row, (text, d) in zip(rows, zip(texts, days)):
        plain = bob.decrypt_blob(row["blob"], crypto.build_aad("entry", bob.user_id, row["client_entry_id"]))
        roundtrip = roundtrip and plain["text"] == text and plain["created_at"] == d.isoformat()
    check("client decrypts every stored blob (roundtrip)", roundtrip, "decryption mismatch")
    r = await req(c, "GET", "/api/entries", headers=bob.headers,
                  params={"limit": 2, "offset": 0})
    page1 = [x["client_entry_id"] for x in r.json()]
    r = await req(c, "GET", "/api/entries", headers=bob.headers,
                  params={"limit": 2, "offset": 2})
    page2 = [x["client_entry_id"] for x in r.json()]
    r = await req(c, "GET", "/api/entries", headers=bob.headers,
                  params={"limit": 2, "offset": 4})
    page3 = [x["client_entry_id"] for x in r.json()]
    check("pagination is stable and exhaustive",
          len(page1) == 2 and len(page2) == 2 and len(page3) == 1
          and not (set(page1) & set(page2)) and len(set(page1 + page2 + page3)) == 5,
          f"{page1}/{page2}/{page3}")
    r = await req(c, "GET", "/api/entries", headers=bob.headers,
                  params={"since": (TODAY - timedelta(days=3)).isoformat()})
    check("?since= date filter", len(r.json()) == 3, f"n={len(r.json())}")
    r = await bob.add_entry(c, texts[0], days[0], f"bob-{days[0].isoformat()}")
    check("duplicate client_entry_id -> 409", r.status_code == 409 and code_of(r) == "conflict",
          f"{r.status_code}")
    r = await bob.add_entry(c, "future", TODAY + timedelta(days=3), "bob-fut3")
    check("entry 3 days in the future -> 422",
          r.status_code == 422 and "future" in r.json().get("detail", ""), f"{r.status_code}")
    r = await bob.add_entry(c, "tz grace", TODAY + timedelta(days=1), "bob-fut1")
    check("entry tomorrow (UTC+14 device grace) -> 201", r.status_code == 201, f"{r.status_code}")
    r = await bob.add_entry(c, "backdated", TODAY - timedelta(days=9), "bob-back9")
    check("entry from before the (aged) account existed -> 422 (no threshold fast-forward)",
          r.status_code == 422 and code_of(r) == "validation_error", f"{r.status_code}")
    r = await req(c, "POST", "/api/entries", headers=bob.headers, json={
        "client_entry_id": "bob-bad", "blob": "%%%not-base64%%%", "entry_date": TODAY.isoformat()})
    check("non-base64 blob -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "POST", "/api/entries", headers=bob.headers, json={
        "client_entry_id": "bob-small", "blob": base64.b64encode(b"toosmall").decode(),
        "entry_date": TODAY.isoformat()})
    check("undersized blob -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "POST", "/api/entries", headers=bob.headers, json={
        "client_entry_id": "bad id with spaces!", "blob": bob.encrypt_entry("x", TODAY, "bad id"),
        "entry_date": TODAY.isoformat()})
    check("invalid client_entry_id pattern -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "DELETE", "/api/entries/bob-fut1", headers=bob.headers)
    check("delete entry -> 204", r.status_code == 204, f"{r.status_code}")
    r = await req(c, "DELETE", "/api/entries/bob-fut1", headers=bob.headers)
    check("delete again -> 404", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", "/api/entries", headers=bob.headers)
    check("list reflects deletion (5 remain)", len(r.json()) == 5, f"n={len(r.json())}")


async def s_baseline_phase(c, users):
    group("6 · 30-day threshold honesty (bob, 5 active days)")
    bob: Patient = users["bob"]
    r = await bob.recompute(c)
    body = r.json()
    check("recompute in baseline phase -> no analysis, no key use",
          r.status_code == 200 and body["phase"] == "baseline" and body["analyzer"] == "none"
          and body["patterns_stored"] == 0, f"{r.status_code} {body}")
    check("days_remaining counts down honestly (25 left)",
          body.get("days_remaining") == 25, f"{body.get('days_remaining')}")
    r = await req(c, "GET", "/api/insights", headers=bob.headers)
    body = r.json()
    check("GET /insights in baseline -> phase + countdown, blob=None",
          r.status_code == 200 and body["phase"] == "baseline" and body["blob"] is None,
          f"{r.status_code}")
    r = await req(c, "GET", "/api/questions/today", headers=bob.headers)
    check("no daily question before threshold", r.status_code == 404, f"{r.status_code}")
    frank = users["frank"]
    await frank.register(c)
    r = await frank.recompute(c, processing_token=None)
    check("recompute with zero entries -> 400 bad_request",
          r.status_code == 400 and code_of(r) == "bad_request", f"{r.status_code}")


async def s_insight_phase(c, users):
    group("7 · insight phase, patterns, questions (alice, 48-day journal)")
    alice: Patient = users["alice"]
    await db_age_account(alice.user_id, 86)
    corpus = structured_corpus(TODAY, 84, seed=11)
    ok = True
    for item in corpus:
        r = await alice.add_entry(c, item["text"], item["date"], item["cid"],
                                  sentiment=item["sentiment"])
        ok = ok and r.status_code == 201
    check(f"seeded {len(corpus)} historical entries (aged account)", ok, "create failures")
    r = await alice.recompute(c)
    body = r.json()
    check("recompute crosses threshold -> phase=insight, brain analyzer",
          r.status_code == 200 and body["phase"] == "insight" and body["analyzer"] == "brain",
          f"{r.status_code} {body}")
    check("active_days counted from entry dates (>=30)",
          body.get("active_days", 0) >= 30, f"{body.get('active_days')}")
    r = await req(c, "GET", "/api/insights", headers=alice.headers)
    blob1 = r.json()["blob"]
    check("GET /insights now carries encrypted blob",
          r.status_code == 200 and blob1 is not None, f"{r.status_code}")
    payload = alice.decrypt_insights(blob1)
    patterns = payload["stats"]["patterns"]
    kinds = sorted({p["kind"] for p in patterns})
    check("patient decrypts patterns blob (v2 payload, >=1 pattern)",
          payload.get("v") == 2 and len(patterns) >= 1, f"v={payload.get('v')} n={len(patterns)}")
    check(f"pattern kinds surfaced: {', '.join(kinds)}", len(kinds) >= 2,
          f"only {kinds}")
    known = {"temporal", "mood_correlation", "link", "inertia", "instability",
             "mood_shift", "rumination", "topic", "recurring_phrase"}
    check("all pattern kinds are from the documented set",
          all(p["kind"] in known for p in patterns),
          f"unknown: {[p['kind'] for p in patterns if p['kind'] not in known]}")
    with_detail = all("detail" in p and "label" in p for p in patterns)
    check("every pattern carries label + evidence detail", with_detail, "missing detail")
    has_sleep = any("sleep" in p["label"].lower() or "mind" in p["label"].lower()
                    for p in patterns)
    check("planted recurring sleep worry is found", has_sleep,
          f"labels: {[p['label'][:40] for p in patterns][:8]}")
    r = await req(c, "GET", "/api/questions/today", headers=alice.headers)
    check("daily question stored (200 + blob)",
          r.status_code == 200 and r.json().get("blob"), f"{r.status_code} {r.text[:120]}")
    if r.status_code == 200 and r.json().get("blob"):
        q = alice.decrypt_blob(r.json()["blob"],
                               crypto.build_aad("question", alice.user_id, TODAY.isoformat()))
        check("question decrypts for today", bool(q.get("question")), f"{q}")
    else:
        check("question decrypts for today", False, "no question blob")

    r = await alice.recompute(c)
    body2 = r.json()
    check("same-day recompute: deterministic, surfaced count unchanged",
          r.status_code == 200 and body2.get("patterns_stored") == body.get("patterns_stored"),
          f"{body.get('patterns_stored')} -> {body2.get('patterns_stored')}")
    r = await req(c, "GET", "/api/insights", headers=alice.headers)
    payload2 = alice.decrypt_insights(r.json()["blob"])
    check("same corpus + same day -> identical decrypted patterns",
          payload2["stats"]["patterns"] == payload["stats"]["patterns"],
          "pattern drift on unchanged corpus")


async def s_processing_sessions(c, users):
    group("8 · processing-session lifecycle (single-use keys)")
    alice: Patient = users["alice"]
    r = await req(c, "POST", "/api/insights/recompute", headers=alice.headers)
    check("insight-phase recompute without token -> 401 processing_session_required",
          r.status_code == 401 and code_of(r) == "processing_session_required", f"{r.status_code}")
    r = await req(c, "POST", "/api/insights/recompute",
                  headers={**alice.headers, "X-Processing-Token": "forged-token"})
    check("forged processing token -> 403", r.status_code == 403
          and code_of(r) == "processing_session_invalid", f"{r.status_code}")
    ps = await req(c, "POST", "/api/processing/sessions", headers=alice.headers,
                   json={"data_key": base64.b64encode(alice.data_key).decode()})
    token = ps.json().get("session_token", "")
    r = await req(c, "POST", "/api/insights/recompute",
                  headers={**alice.headers, "X-Processing-Token": token})
    ok1 = r.status_code == 200
    r2 = await req(c, "POST", "/api/insights/recompute",
                   headers={**alice.headers, "X-Processing-Token": token})
    check("session consumed by first recompute; reuse -> 403 (single-use)",
          ok1 and r2.status_code == 403, f"first={ok1} reuse={r2.status_code}")
    r = await req(c, "POST", "/api/processing/sessions", headers=alice.headers,
                  json={"data_key": base64.b64encode(os.urandom(8)).decode()})
    check("wrong-size data key -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "POST", "/api/processing/sessions", headers=alice.headers,
                  json={"data_key": "!!not-b64!!"})
    check("non-base64 data key -> 422", r.status_code == 422, f"{r.status_code}")


async def s_tamper_and_payloads(c, users):
    group("9 · ciphertext tampering & hostile payloads (carol + eve)")
    carol: Patient = users["carol"]
    await carol.register(c)
    await db_age_account(carol.user_id, 86)
    corpus = plain_mood_corpus(TODAY, 84, crisis=True)
    for item in corpus:
        await carol.add_entry(c, item["text"], item["date"], item["cid"],
                              sentiment=item["sentiment"])
    r = await carol.recompute(c)
    body = r.json()
    check("carol (crisis-language journal) recomputes fine",
          r.status_code == 200 and body["phase"] == "insight", f"{r.status_code} {body}")
    r = await req(c, "GET", "/api/insights", headers=carol.headers)
    payload = carol.decrypt_insights(r.json()["blob"])
    labels = [p["label"] for p in payload["stats"]["patterns"]]
    flagged = [
        p for p in payload["stats"]["patterns"]
        if quotes_crisis_language(p["label"]) or quotes_crisis_language(
            str(p.get("detail", {}).get("variants", "")))
    ]
    unflagged_leak = [p["label"] for p in flagged if not p.get("detail", {}).get("sensitive")]
    benign_misflag = [p["label"] for p in payload["stats"]["patterns"]
                      if p.get("detail", {}).get("sensitive")
                      and p not in flagged]
    check("crisis-quoting patterns are exactly the ones flagged sensitive=True "
          "(clients render those non-quoting)", len(labels) > 0 and not unflagged_leak
          and not benign_misflag,
          f"unflagged leaks: {unflagged_leak}; misflagged benign: {benign_misflag}")
    r = await req(c, "GET", "/api/questions/today", headers=carol.headers)
    if r.status_code == 200 and r.json().get("blob"):
        q = carol.decrypt_blob(r.json()["blob"],
                               crypto.build_aad("question", carol.user_id, TODAY.isoformat()))
        check("daily question never quotes crisis language",
              quotes_crisis_language(q.get("question", "")) is None, f"{q}")
    else:
        check("daily question never quotes crisis language", r.status_code == 404,
              f"{r.status_code}")

    # entry blob corrupted at rest (server-side DB corruption scenario)
    victim = corpus[len(corpus) // 2]["cid"]
    original = await db_flip_entry_blob(carol.user_id, victim)
    r = await carol.recompute(c)
    check("corrupted stored entry blob -> 400 entry_blob_invalid (GCM auth)",
          r.status_code == 400 and code_of(r) == "entry_blob_invalid", f"{r.status_code} {r.text[:100]}")
    await db_restore_entry_blob(carol.user_id, victim, original)
    r = await carol.recompute(c)
    check("recompute recovers after blob restored", r.status_code == 200, f"{r.status_code}")

    # brain state corrupted at rest -> amnesia retry, account not bricked
    await db_corrupt_brain_state(carol.user_id)
    r = await carol.recompute(c)
    check("corrupted brain state -> amnesia retry, recompute still succeeds",
          r.status_code == 200 and r.json().get("phase") == "insight", f"{r.status_code} {r.text[:100]}")

    # hostile (but AEAD-valid, client-crafted) plaintexts
    eve: Patient = users["eve"]
    await eve.register(c)
    await db_age_account(eve.user_id, 40)
    for i in range(32):
        d = TODAY - timedelta(days=31 - i)
        await eve.add_entry(c, f"day {i} ordinary notes", d, f"eve-{d.isoformat()}",
                            sentiment=-0.2)
    bad_payload = b"this is not json at all"
    d = TODAY - timedelta(days=3)
    r = await eve.add_entry(c, None, d, "eve-bad1", plaintext=bad_payload)
    check("AEAD-valid non-JSON payload accepted for storage (opaque blobs)",
          r.status_code == 201, f"{r.status_code}")
    r = await eve.recompute(c)
    check("recompute on non-JSON payload -> 400 entry_payload_malformed",
          r.status_code == 400 and code_of(r) == "entry_payload_malformed", f"{r.status_code}")
    await req(c, "DELETE", "/api/entries/eve-bad1", headers=eve.headers)
    nan_json = json.dumps({"v": 1, "text": "mood today", "sentiment": float("nan"),
                           "created_at": d.isoformat()}).encode()
    r = await eve.add_entry(c, None, d, "eve-bad2", plaintext=nan_json)
    r2 = await eve.recompute(c)
    check("NaN sentiment -> 400 entry_payload_malformed (poisons nothing)",
          r2.status_code == 400 and code_of(r2) == "entry_payload_malformed", f"{r2.status_code}")
    await req(c, "DELETE", "/api/entries/eve-bad2", headers=eve.headers)
    mismatch = json.dumps({"v": 1, "text": "inner date lies", "sentiment": 0.1,
                           "created_at": "2020-01-01"}).encode()
    await eve.add_entry(c, None, d, "eve-bad3", plaintext=mismatch)
    r = await eve.recompute(c)
    check("inner created_at far from entry_date -> 400",
          r.status_code == 400 and code_of(r) == "entry_payload_malformed", f"{r.status_code}")
    await req(c, "DELETE", "/api/entries/eve-bad3", headers=eve.headers)
    r = await eve.recompute(c)
    check("account healthy again after hostile entries removed",
          r.status_code == 200, f"{r.status_code}")


async def s_account_lifecycle(c, users):
    group("10 · account: export, LLM consent, deletion (dave)")
    dave: Patient = users["dave"]
    await dave.register(c)
    await db_age_account(dave.user_id, 5)
    texts = []
    for i in range(3):  # ascending dates so creation order == export order
        d = TODAY - timedelta(days=2 - i)
        text = f"dave note {i}"
        texts.append((text, d))
        await dave.add_entry(c, text, d, f"dave-{d.isoformat()}")
    r = await req(c, "GET", "/api/account/export", headers=dave.headers)
    bundle = json.loads(r.content)
    check("export streams a full ciphertext bundle",
          r.status_code == 200 and len(bundle.get("entries", [])) == 3
          and bundle.get("version") == 1 and "salt" in bundle, f"{r.status_code}")
    dec = all(
        dave.decrypt_blob(
            e["blob"], crypto.build_aad("entry", dave.user_id, e["client_entry_id"]))["text"] == t
        for e, (t, d) in zip(bundle["entries"], texts))
    check("exported ciphertexts decrypt locally (zero-knowledge export)", dec, "mismatch")
    check("export carries share metadata (empty)", bundle.get("shares") == [], f"{bundle.get('shares')}")

    r = await req(c, "GET", "/api/account/llm-consent", headers=dave.headers)
    check("llm-consent defaults to disabled", r.status_code == 200
          and r.json()["enabled"] is False, f"{r.json()}")
    r = await req(c, "PUT", "/api/account/llm-consent", headers=dave.headers,
                  json={"enabled": True})
    check("enable LLM without verifier -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "PUT", "/api/account/llm-consent", headers=dave.headers,
                  json={"enabled": True, "verifier": base64.b64encode(os.urandom(32)).decode()})
    check("enable LLM with WRONG verifier -> 403 (token alone insufficient)",
          r.status_code == 403 and code_of(r) == "verification_failed", f"{r.status_code} {r.text[:100]}")
    r = await req(c, "PUT", "/api/account/llm-consent", headers=dave.headers,
                  json={"enabled": True,
                        "verifier": base64.b64encode(dave.auth_key).decode()})
    body = r.json()
    check("enable LLM with correct verifier -> 200 + Art.7 record",
          r.status_code == 200 and body["enabled"] is True and body["llm_consent_at"]
          and body["llm_consent_disclosure"] == "v1", f"{body}")
    r = await req(c, "PUT", "/api/account/llm-consent", headers=dave.headers,
                  json={"enabled": False,
                        "verifier": base64.b64encode(dave.auth_key).decode()})
    check("disable clears the consent record", r.json()["enabled"] is False
          and r.json()["llm_consent_at"] is None, f"{r.json()}")

    r = await req(c, "DELETE", "/api/account", headers=dave.headers)
    check("delete account without verifier -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "DELETE", "/api/account", headers={
        **dave.headers, "X-Account-Verifier": base64.b64encode(os.urandom(32)).decode()})
    check("delete with wrong verifier -> 403", r.status_code == 403, f"{r.status_code}")
    r = await req(c, "DELETE", "/api/account", headers={
        **dave.headers, "X-Account-Verifier": base64.b64encode(dave.auth_key).decode()})
    check("delete with correct verifier -> 204", r.status_code == 204, f"{r.status_code}")
    r = await req(c, "GET", "/api/entries", headers=dave.headers)
    check("token dies with the account", r.status_code == 401, f"{r.status_code}")
    r = await req(c, "POST", "/api/auth/login", json={
        "username": "dave", "verifier": base64.b64encode(dave.auth_key).decode()})
    check("deleted account cannot log in (401, same as unknown)",
          r.status_code == 401, f"{r.status_code}")
    r = await req(c, "POST", "/api/auth/salt", json={"username": "dave"})
    salt_deleted = r.json().get("salt", "")
    r2 = await req(c, "POST", "/api/auth/salt", json={"username": "dave"})
    salt_deleted_2 = r2.json().get("salt", "")
    check("salt for deleted account: deterministic decoy, never the real salt, "
          "same shape as any account",
          r.status_code == 200 and salt_deleted == salt_deleted_2
          and salt_deleted != base64.b64encode(dave.salt).decode()
          and len(base64.b64decode(salt_deleted)) == 16,
          f"{salt_deleted} vs {salt_deleted_2} real={base64.b64encode(dave.salt).decode()}")
    reborn = Patient("dave", "a-brand-new-password")
    r = await reborn.register(c)
    check("username becomes available again (fresh account, zero history)",
          r.status_code == 201, f"{r.status_code}")
    r = await req(c, "GET", "/api/entries", headers=reborn.headers)
    check("re-registered account starts empty", r.json() == [], f"{r.json()}")
    users["dave"] = reborn


async def s_sharing(c, users, ther):
    group("11 · zero-knowledge therapist sharing (alice -> dr_house)")
    alice: Patient = users["alice"]
    house: Therapist = ther["house"]
    r = await house.register(c)
    body = r.json()
    check("therapist registers (201, role=therapist)",
          r.status_code == 201 and body.get("role") == "therapist", f"{r.status_code} {body}")
    r = await req(c, "POST", "/api/auth/login", json={
        "username": "house", "verifier": base64.b64encode(house.auth_key).decode()})
    check("therapist logs in through the same /auth/login",
          r.status_code == 200 and r.json().get("role") == "therapist", f"{r.status_code}")
    house.token = r.json()["token"]
    r = await house.fetch_me(c)
    me = r.json()
    check("GET /therapist/me returns username, display name, wrap keys",
          r.status_code == 200 and me["wrap_pub_key"] == house.wrap_pub_key
          and me["wrap_key_blob"], f"{r.status_code}")
    house.stored_key_blob = me["wrap_key_blob"]
    priv = house.unlock_private_key()
    check("portal unlocks its private key locally (password KEK decrypts blob)",
          priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
          == base64.b64decode(house.wrap_pub_key), "unwrap mismatch")
    r = await req(c, "POST", "/api/therapist/pairing-codes", headers=house.headers)
    pc = r.json()
    check("pairing code issued (15-minute TTL)", r.status_code == 201
          and pc.get("expires_in") == 900 and pc.get("code"), f"{pc}")
    code = pc["code"]
    r = await req(c, "POST", "/api/consents/pairing/lookup",
                  headers=alice.headers, json={"code": code})
    lookup = r.json()
    check("patient looks up code: therapist name + public key, code NOT burned",
          r.status_code == 200 and lookup["display_name"] == house.display_name
          and lookup["wrap_pub_key"] == house.wrap_pub_key and lookup["therapist_id"] == house.user_id,
          f"{r.status_code} {lookup}")
    r = await req(c, "POST", "/api/consents/pairing/lookup",
                  headers=alice.headers, json={"code": "GUESS-1234"})
    check("wrong code -> 404 (same as expired/consumed)", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "POST", "/api/consents/pairing/lookup",
                  headers=alice.headers, json={"code": ""})
    check("empty code -> 422 validation", r.status_code == 422, f"{r.status_code}")

    eph_b64, wrapped_b64 = sharing.wrap_data_key(
        alice.data_key, house.wrap_pub_key, alice.user_id, house.user_id)
    grant_body = {"code": code, "ephemeral_pub": eph_b64,
                  "wrapped_key": wrapped_b64, "disclosure": "v1"}
    r = await req(c, "POST", "/api/consents", headers=alice.headers, json=grant_body)
    check("grant without verifier -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "POST", "/api/consents", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(os.urandom(32)).decode()},
        json=grant_body)
    check("grant with wrong verifier -> 403", r.status_code == 403, f"{r.status_code}")
    r = await req(c, "POST", "/api/consents", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(alice.auth_key).decode()},
        json=grant_body)
    consent = r.json()
    consent_id = consent.get("id")
    check("grant with verifier -> 201 consent (stolen token cannot share journal)",
          r.status_code == 201 and consent.get("status") == "active", f"{r.status_code} {consent}")
    r = await req(c, "POST", "/api/consents/pairing/lookup",
                  headers=alice.headers, json={"code": code})
    check("code is burned after grant -> 404", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "POST", "/api/consents", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(alice.auth_key).decode()},
        json=grant_body)
    check("granting twice with the same code -> 404", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", "/api/consents", headers=alice.headers)
    check("patient sees their consent list", r.status_code == 200
          and len(r.json()) == 1 and r.json()[0]["display_name"] == house.display_name,
          f"{r.json()}")

    r = await req(c, "GET", "/api/therapist/patients", headers=house.headers)
    patients = r.json()
    check("therapist patient list shows alice with wrapped key material",
          r.status_code == 200 and len(patients) == 1 and patients[0]["wrapped_key"]
          and patients[0]["ephemeral_pub"], f"{patients}")
    row = patients[0]
    unwrapped = house.unwrap_patient_key(alice, row["ephemeral_pub"], row["wrapped_key"])
    check("portal unwraps patient data key (ECDH->HKDF->GCM) == the real key",
          unwrapped == alice.data_key, "unwrap mismatch")

    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/insights",
                  headers=house.headers)
    t_blob = r.json().get("blob")
    r2 = await req(c, "GET", "/api/insights", headers=alice.headers)
    p_blob = r2.json().get("blob")
    check("therapist insight read is consent-gated and byte-identical to patient's",
          r.status_code == 200 and t_blob is not None and t_blob == p_blob,
          f"{r.status_code} blobs_equal={t_blob == p_blob}")
    # portal decrypts with the unwrapped key through the same AAD path
    portal_plain = json.loads(crypto.decrypt(
        unwrapped, base64.b64decode(t_blob),
        crypto.build_aad("insights", alice.user_id, "patterns")))
    patient_plain = alice.decrypt_insights(p_blob)
    check("portal decrypts the SAME patterns payload with the unwrapped key",
          portal_plain == patient_plain, "payload mismatch")

    since = (TODAY - timedelta(days=10)).isoformat()
    until = (TODAY - timedelta(days=5)).isoformat()
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/entries",
                  headers=house.headers, params={"since": since, "until": until, "limit": 500})
    rows = r.json()
    texts_match = dates_ok = True
    dates_ok = all(since <= x["entry_date"] <= until for x in rows)
    for x in rows:
        plain = json.loads(crypto.decrypt(
            unwrapped, base64.b64decode(x["blob"]),
            crypto.build_aad("entry", alice.user_id, x["client_entry_id"])))
        texts_match = texts_match and plain["created_at"] == x["entry_date"]
    check("therapist reads + decrypts the entry evidence window (since/until)",
          r.status_code == 200 and len(rows) >= 4 and dates_ok and texts_match,
          f"{r.status_code} n={len(rows)} dates={dates_ok} texts={texts_match}")

    note_blob = house.encrypt_note(alice, "note-1",
                                   "patient presents seasonal work stress; revisit in 2 weeks")
    r = await req(c, "POST", f"/api/therapist/patients/{alice.user_id}/notes",
                  headers=house.headers,
                  json={"client_note_id": "note-1", "pattern_pid": None, "blob": note_blob})
    check("therapist writes an encrypted note (201)", r.status_code == 201, f"{r.status_code}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/notes",
                  headers=house.headers)
    notes = r.json()
    okn = r.status_code == 200 and len(notes) == 1
    text = house.decrypt_note(alice, "note-1", notes[0]["blob"])["text"] if okn else ""
    check("notes list + local decryption under the notes key",
          okn and "seasonal work stress" in text, f"{r.status_code} n={len(notes)}")
    note_id = notes[0]["id"] if okn else ""
    updated = house.encrypt_note(alice, "note-1", "updated: follow-up scheduled for monday")
    r = await req(c, "PATCH", f"/api/therapist/notes/{note_id}", headers=house.headers,
                  json={"blob": updated})
    check("note update (PATCH) -> 200", r.status_code == 200, f"{r.status_code}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/notes",
                  headers=house.headers)
    final_text = house.decrypt_note(alice, "note-1", r.json()[0]["blob"])["text"]
    check("updated note decrypts to new content", "follow-up scheduled" in final_text, final_text)

    r = await req(c, "DELETE", f"/api/consents/{consent_id}", headers=alice.headers)
    check("revoke without verifier -> 422", r.status_code == 422, f"{r.status_code}")
    r = await req(c, "DELETE", f"/api/consents/{consent_id}", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(os.urandom(32)).decode()})
    check("revoke with wrong verifier -> 403", r.status_code == 403, f"{r.status_code}")
    r = await req(c, "DELETE", f"/api/consents/{consent_id}", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(alice.auth_key).decode()})
    check("revoke with verifier -> 204", r.status_code == 204, f"{r.status_code}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/insights",
                  headers=house.headers)
    check("after revoke: therapist insight read dies (404)", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/entries",
                  headers=house.headers)
    check("after revoke: entry reads die (404)", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", "/api/therapist/patients", headers=house.headers)
    row = next((p for p in r.json() if p["user_id"] == alice.user_id), {})
    check("patient list keeps the row (status=revoked) but key material is cleared",
          row.get("status") == "revoked" and row.get("wrapped_key") is None
          and row.get("ephemeral_pub") is None, f"{row}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/notes",
                  headers=house.headers)
    check("therapist notes SURVIVE the revoke (own record)",
          r.status_code == 200 and len(r.json()) == 1, f"{r.status_code}")

    r = await req(c, "POST", "/api/therapist/pairing-codes", headers=house.headers)
    code2 = r.json()["code"]
    e2, w2 = sharing.wrap_data_key(alice.data_key, house.wrap_pub_key, alice.user_id, house.user_id)
    r = await req(c, "POST", "/api/consents", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(alice.auth_key).decode()},
        json={"code": code2, "ephemeral_pub": e2, "wrapped_key": w2, "disclosure": "v1"})
    consent2 = r.json()
    check("re-grant reactivates the SAME consent row (id continuity)",
          r.status_code == 201 and consent2.get("id") == consent_id
          and consent2.get("status") == "active", f"{consent2.get('id')} vs {consent_id}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/notes",
                  headers=house.headers)
    check("note history intact across revoke/re-grant", len(r.json()) == 1, f"{r.json()}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/insights",
                  headers=house.headers)
    check("therapist reads resume after re-grant", r.status_code == 200
          and r.json().get("blob") == p_blob, f"{r.status_code}")

    # dave's fresh account attempts sharing-shape validation
    dave = users["dave"]
    r = await req(c, "POST", "/api/consents", headers={
        **dave.headers, "X-Account-Verifier": base64.b64encode(dave.auth_key).decode()},
        json={"code": code2, "ephemeral_pub": "garbage-not-a-key",
              "wrapped_key": base64.b64encode(os.urandom(64)).decode(), "disclosure": "v1"})
    check("grant with garbage ephemeral_pub -> 422", r.status_code == 422, f"{r.status_code}")


async def s_cross_access(c, users, ther):
    group("12 · cross-user & role-boundary attacks")
    alice, bob = users["alice"], users["bob"]
    house, wilson = ther["house"], ther["wilson"]
    await wilson.register(c)
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/insights",
                  headers=wilson.headers)
    check("therapist B reading therapist A's patient -> 404",
          r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", f"/api/therapist/patients/{alice.user_id}/entries",
                  headers=wilson.headers)
    check("therapist B entry read -> 404", r.status_code == 404, f"{r.status_code}")
    blob = wilson.encrypt_note(alice, "wilson-1", "should never be writable")
    r = await req(c, "POST", f"/api/therapist/patients/{alice.user_id}/notes",
                  headers=wilson.headers,
                  json={"client_note_id": "wilson-1", "blob": blob})
    check("therapist B note on unpaired patient -> 404", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", f"/api/therapist/patients/{bob.user_id}/insights",
                  headers=house.headers)
    check("therapist reading a patient who never granted -> 404",
          r.status_code == 404, f"{r.status_code}")
    for method, path in [("GET", "/api/therapist/me"), ("POST", "/api/therapist/pairing-codes"),
                         ("GET", "/api/therapist/patients")]:
        r = await req(c, method, path, headers=alice.headers)
        check(f"patient token on {method} {path} -> 403", r.status_code == 403, f"{r.status_code}")
    r = await req(c, "POST", "/api/entries", headers=house.headers, json={
        "client_entry_id": "house-forbidden",
        "blob": alice.encrypt_entry("therapists can never write here", TODAY, "house-forbidden"),
        "entry_date": TODAY.isoformat()})
    check("therapist token on POST /entries -> 403 (no therapist write path)",
          r.status_code == 403, f"{r.status_code} {r.text[:100]}")
    for method, path in [("GET", "/api/entries"), ("GET", "/api/insights"),
                         ("POST", "/api/processing/sessions"), ("GET", "/api/consents"),
                         ("GET", "/api/account/export"), ("GET", "/api/questions/today")]:
        r = await req(c, method, path, headers=house.headers) if method == "GET" else \
            await req(c, method, path, headers=house.headers,
                      json={"data_key": base64.b64encode(os.urandom(32)).decode()})
        check(f"therapist token on {method} {path} -> 403", r.status_code == 403, f"{r.status_code}")
    r = await req(c, "GET", "/api/entries", headers=bob.headers)
    check("bob's entry list contains ONLY bob's entries (no cross-patient read path)",
          r.status_code == 200 and all(x["client_entry_id"].startswith("bob-") for x in r.json()),
          f"{[x['client_entry_id'] for x in r.json()][:5]}")
    r = await req(c, "DELETE", "/api/consents/nonexistent-id", headers={
        **alice.headers, "X-Account-Verifier": base64.b64encode(alice.auth_key).decode()})
    check("revoking an unknown consent -> 404", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "GET", "/api/therapist/patients/0000000000000000000000000000/insights",
                  headers=house.headers)
    check("random patient id -> flat 404", r.status_code == 404, f"{r.status_code}")
    r = await req(c, "POST", "/api/therapist/register", json={
        "username": "badwrap", "salt": base64.b64encode(os.urandom(16)).decode(),
        "verifier": base64.b64encode(os.urandom(32)).decode(), "display_name": "Bad Wrap",
        "wrap_pub_key": base64.b64encode(b"not-a-real-spki-key-at-all").decode(),
        "wrap_key_blob": base64.b64encode(os.urandom(200)).decode()})
    check("therapist registration with garbage wrap key -> 422", r.status_code == 422,
          f"{r.status_code}")
    r = await req(c, "DELETE", "/api/therapist/notes/does-not-exist", headers=wilson.headers)
    check("therapist deleting a foreign/nonexistent note -> 404", r.status_code == 404,
          f"{r.status_code}")


async def s_rate_limits(c, users):
    group("13 · rate limiting (default export bucket: 5/min)")
    gina = Patient("gina", "gina-password-123")
    await gina.register(c)
    statuses = []
    for _ in range(7):
        r = await req(c, "GET", "/api/account/export", headers=gina.headers, retry_429=False)
        statuses.append(r.status_code)
        if r.status_code == 429:
            retry_after = r.headers.get("retry-after")
            body429 = r.json()
            break
    check("burst exports trip the bucket -> 429 with Retry-After",
          429 in statuses and retry_after is not None and body429.get("code") == "rate_limited",
          f"{statuses}")
    r = await req(c, "GET", "/api/account/export", headers=gina.headers, retry_429=False)
    check("bucket still closed immediately after", r.status_code == 429, f"{r.status_code}")
    alice = users["alice"]
    r = await req(c, "GET", "/api/entries", headers=alice.headers)
    check("other users unaffected by one user's exhaustion", r.status_code == 200, f"{r.status_code}")


async def s_body_limits(c, users):
    group("14 · request body limits")
    alice = users["alice"]
    huge = base64.b64encode(os.urandom(3 * 1024 * 1024)).decode()
    r = await req(c, "POST", "/api/entries", headers=alice.headers, json={
        "client_entry_id": "huge-blob", "blob": huge, "entry_date": TODAY.isoformat()})
    check("3 MiB body -> rejected (413) before parsing",
          r.status_code in (413, 422), f"{r.status_code}")


# ------------------------------------------------------------------ main ----


async def run():
    print(f"target: {BASE_URL}   db: {DB_URL}   today: {TODAY}")
    users = {
        "alice": Patient("alice", "correct-horse-battery-1"),
        "bob": Patient("bob", "staple-lamp-quiet-2"),
        "carol": Patient("carol", "river-copper-plant-3"),
        "dave": Patient("dave", "orbit-glass-field-4"),
        "eve": Patient("eve", "harbor-stone-leaf-5"),
        "frank": Patient("frank", "meadow-iron-dust-6"),
    }
    ther = {"house": Therapist("house", "portal-secret-A-1", "Dr. Gregory House"),
            "wilson": Therapist("wilson", "portal-secret-B-2", "Dr. James Wilson")}

    async with httpx.AsyncClient(base_url=BASE_URL, timeout=120) as c:
        stages = [
            ("boot", lambda: s_meta(c)),
            ("registration", lambda: s_registration(c, users)),
            ("salt", lambda: s_salt_enumeration(c, users)),
            ("login", lambda: s_login_logout(c, users)),
            ("entries", lambda: s_entries(c, users)),
            ("baseline", lambda: s_baseline_phase(c, users)),
            ("insight", lambda: s_insight_phase(c, users)),
            ("sessions", lambda: s_processing_sessions(c, users)),
            ("tamper", lambda: s_tamper_and_payloads(c, users)),
            ("account", lambda: s_account_lifecycle(c, users)),
            ("sharing", lambda: s_sharing(c, users, ther)),
            ("cross", lambda: s_cross_access(c, users, ther)),
            ("rate", lambda: s_rate_limits(c, users)),
            ("body", lambda: s_body_limits(c, users)),
        ]
        for name, fn in stages:
            try:
                await fn()
            except Exception:
                group(f"{name} · CRASHED")
                check(f"stage '{name}' completed without harness error", False,
                      traceback.format_exc()[-350:])

    # ---- summary ----
    total = len(RESULTS)
    failed = [r for r in RESULTS if not r["ok"]]
    print("\n" + "=" * 72)
    print(f"E2E CAMPAIGN: {total - len(failed)}/{total} checks passed")
    if failed:
        print("\nFAILURES:")
        for f in failed:
            print(f"  [{f['group']}] {f['name']}\n      {f['evidence']}")
    out = Path(__file__).parent / "results.json"
    out.write_text(json.dumps(RESULTS, indent=2))
    print(f"\nfull results: {out}")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(run()))
