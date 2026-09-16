"""Red-team campaign shared helpers.

Every audit script prints ``AUDIT|<id>|<VERDICT>|<summary>`` lines and dumps
a JSON result file under redteam/results/. Verdicts:

  BLOCKED   — attack repelled by an existing control (good)
  FINDING   — attack succeeded (severity noted in the summary)
  PARTIAL   — control holds only under assumptions that can break
  INFO      — structural observation, no runtime vulnerability
  NOT-RUN   — environment did not permit execution (reason given)

These scripts attack the developers' OWN code, in their own repo, on
localhost, with throwaway data. Nothing here touches third-party systems.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys
import time
import traceback
import uuid
from datetime import date, timedelta
from pathlib import Path
from typing import Any

# The app fails closed outside development; the harness is a development
# context (same opt-in the backend test suite uses).
os.environ.setdefault("MINDPATTERN_ENV", "development")

ROOT = Path(__file__).resolve().parent.parent
BACKEND = ROOT / "backend"
sys.path.insert(0, str(BACKEND))
sys.path.insert(0, str(BACKEND / "app"))

RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)

RESULTS_BUFFER: list[dict[str, str]] = []


def verdict(audit_id: str, status: str, summary: str) -> None:
    line = f"AUDIT|{audit_id}|{status}|{summary}"
    print(line, flush=True)
    RESULTS_BUFFER.append({"id": audit_id, "status": status, "summary": summary})


def dump(script_name: str) -> None:
    (RESULTS / f"{script_name}.json").write_text(json.dumps(RESULTS_BUFFER, indent=2))


def section(title: str) -> None:
    print(f"\n=== {title} " + "=" * max(0, 70 - len(title)), flush=True)


async def guard(audit_id: str, fn, *args, **kwargs) -> Any:
    """Run an attack step (sync or async); an unexpected crash becomes an
    ERROR verdict, not a dead campaign."""
    import inspect

    try:
        result = fn(*args, **kwargs)
        if inspect.iscoroutine(result):
            result = await result
        return result
    except Exception:  # noqa: BLE001 - audit harness reports everything
        verdict(audit_id, "ERROR", f"harness crash: {traceback.format_exc(limit=3)}")
        return None


# ---------------------------------------------------------------------------
# App construction (mirrors backend/tests/conftest.py)
# ---------------------------------------------------------------------------

def make_settings(**overrides: Any):
    from app.config import Settings

    s = Settings(environment="development")
    s.database_url = "sqlite+aiosqlite://"  # in-memory, per-app
    s.token_secret = "redteam-audit-secret-32-chars-min!!"
    s.processing_session_ttl = 300
    s.unlock_threshold_days = 30
    s.auth_rate_limit = 10
    s.entries_rate_limit = 1000
    for k, v in overrides.items():
        setattr(s, k, v)
    return s


async def make_app(settings=None):
    from app.main import create_app

    settings = settings or make_settings()
    application = create_app(settings)
    await application.router.lifespan_context(application).__aenter__()
    return application


def make_client(app):
    import httpx

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


# ---------------------------------------------------------------------------
# Client-side crypto (the REAL modules — same primitives the mobile app runs)
# ---------------------------------------------------------------------------

def derive_keys(password: str, salt: bytes, iterations: int = 600_000):
    """Returns (auth_key, data_key) exactly like the mobile client.

    The master derivation goes through hashlib directly: the shipping
    library floors iterations at kdf.MIN_ITERATIONS (2026-09-16 fix), and
    the harness legitimately wants cheap keys (same stance as the backend
    test suite's ClientEmulator). The HKDF subkeys still use the library."""
    import hashlib

    from app.security import kdf

    master = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return kdf.derive_auth_key(master), kdf.derive_data_key(master)


def encrypt_entry(data_key: bytes, user_id: str, client_entry_id: str, text: str,
                  created_at: str, sentiment: float | None = None) -> str:
    from app.security import crypto

    payload = json.dumps({"v": 1, "text": text, "sentiment": sentiment,
                          "created_at": created_at}).encode()
    aad = crypto.build_aad("entry", user_id, client_entry_id)
    return base64.b64encode(crypto.encrypt(bytes(data_key), payload, aad=aad)).decode()


async def register_user(client, username: str, password: str, iterations: int = 600_000) -> dict:
    """Full client-side key schedule + server registration, like the app."""
    salt = os.urandom(16)
    auth_key, data_key = derive_keys(password, salt, iterations)
    r = await client.post("/api/v1/auth/register", json={
        "username": username,
        "salt": base64.b64encode(salt).decode(),
        "verifier": base64.b64encode(auth_key).decode(),
    })
    r.raise_for_status()
    body = r.json()
    return {
        "username": username, "user_id": body["user_id"], "token": body["token"],
        "auth_key": auth_key, "data_key": data_key, "salt": salt,
    }


async def login_user(client, username: str, auth_key: bytes) -> dict:
    r = await client.post("/api/v1/auth/login", json={
        "username": username,
        "verifier": base64.b64encode(auth_key).decode(),
    })
    r.raise_for_status()
    return r.json()


def auth_headers(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def direct_insert_entry(app, user_id: str, data_key: bytes, text: str,
                              entry_date: date, cid: str | None = None,
                              sentiment: float | None = None) -> str:
    """Insert an Entry row bypassing the API's ±1-day date bound — how a
    long-lived account's history actually looks. Uses the real client crypto."""
    from app.models import Entry

    cid = cid or f"e-{entry_date.isoformat()}-{uuid.uuid4().hex[:12]}"
    blob_b64 = encrypt_entry(data_key, user_id, cid, text,
                             created_at=entry_date.isoformat(), sentiment=sentiment)
    async with app.state.sessionmaker() as session:
        session.add(Entry(user_id=user_id, client_entry_id=cid,
                          blob=base64.b64decode(blob_b64),
                          entry_date=entry_date, received_at=entry_date))
        await session.commit()
    return cid


_MOOD_WORDS = [
    ("great", "calm", "productive"), ("tired", "stressed", "busy"),
    ("happy", "relaxed", "focused"), ("anxious", "worried", "rushed"),
    ("content", "peaceful", "steady"), ("drained", "heavy", "slow"),
]


async def seed_unlocked_user(app, client, username: str, password: str,
                             days: int = 35, text_fn=None) -> dict:
    """A user past the 30-day threshold with real (direct-insert) history.

    The default text VARIES day to day: a constant-sentiment corpus is a
    separate, deliberate attack case (see c_api.py C3.mood-shift-phi-1),
    not something every downstream test should trip over.
    """
    user = await register_user(client, username, password, iterations=1000)  # fast KDF for the harness
    today = date.today()
    for i in range(days, 0, -1):
        d = today - timedelta(days=i)
        if text_fn:
            text = text_fn(d)
        else:
            words = _MOOD_WORDS[i % len(_MOOD_WORDS)]
            text = f"day {i}: felt {words[0]}, somewhat {words[1]}, work was {words[2]}."
        await direct_insert_entry(app, user["user_id"], user["data_key"], text, d)
    return user


def run(coro_factory, script_name: str) -> None:
    async def wrapped():
        await coro_factory()

    try:
        asyncio.run(wrapped())
    finally:
        dump(script_name)
    bad = [r for r in RESULTS_BUFFER if r["status"] == "ERROR"]
    print(f"\n[{script_name}] {len(RESULTS_BUFFER)} verdicts, {len(bad)} harness errors", flush=True)
