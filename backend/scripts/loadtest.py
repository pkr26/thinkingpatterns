#!/usr/bin/env python3
"""Load probe for a running MindPattern API (2026-09-17).

The first load picture anyone could produce was incidental (the red-team
measured scrypt RSS under 8 concurrent registrations). This script is the
deliberate version: it drives the three cost centers — registration +
login (scrypt), entry creation, and the full recompute pipeline (brain
analysis) — against a live server and prints latency percentiles and
throughput. No assertions, no pass/fail: it is a measurement tool for
capacity planning against the single-process deployment contract.

Usage:
    python scripts/loadtest.py --url http://localhost:8000 --users 20 \
        --db-url postgresql+asyncpg://u:p@localhost/mindpattern

The 30-day threshold cannot be fast-forwarded through the API (the
+/-1-day backdating guard is a security property), so measuring the FULL
recompute pipeline needs accounts that old: pass --db-url to backdate the
persistent load handles' created_at (seed_demo's mechanism) before the
entries are seeded. Without it (or before the handles have aged), the
recompute phase stays in the baseline phase — which the script now reports
and counts as a FAILURE for capacity purposes, never as a silent success.

Cost model to keep in mind while reading results:
  * login is scrypt(N=2^16)-bound: ~4/s per process (the auth limiter).
  * recompute is brain-bound: ~1.2s per 2000-entry corpus (development
    core), 4 concurrent analyze slots -> ~3/s ceiling.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import sys
import time
from dataclasses import dataclass, field

import httpx

# The client's REAL key schedule (the emulator from tests, trimmed):
# fast test KDF + the real HKDF auth/data split. The server cannot tell.
sys.path.insert(0, ".")


@dataclass
class Stats:
    label: str
    latencies: list[float] = field(default_factory=list)
    failures: int = 0
    elapsed: float = 0.0  # wall seconds for the whole phase (set by phase())

    def record(self, seconds: float, ok: bool) -> None:
        if ok:
            self.latencies.append(seconds)
        else:
            self.failures += 1

    def summary(self) -> str:
        if not self.latencies:
            return f"{self.label}: ALL FAILED ({self.failures})"
        lat = sorted(self.latencies)
        p = lambda q: lat[min(len(lat) - 1, int(q * len(lat)))]  # noqa: E731
        # Completion rate = successes / WALL time (Little's law under the
        # phase's actual concurrency). The old "throughput" divided by
        # sum(latencies) — that is 1/mean-latency, understating the rate
        # by roughly the concurrency factor (2026-09-19 audit, L-35).
        rate = len(lat) / self.elapsed if self.elapsed > 0 else float("nan")
        return (
            f"{self.label}: n={len(lat)} fail={self.failures} "
            f"p50={p(0.50):.3f}s p95={p(0.95):.3f}s max={lat[-1]:.3f}s "
            f"completion-rate={rate:.2f}/s (wall {self.elapsed:.1f}s)"
        )


def derive(password: str, salt: bytes, user_id: str | None):
    """The client's derivation: PBKDF2 master -> HKDF auth/data keys."""
    from app.security import kdf as k

    master = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 1000)
    return k.derive_auth_key(master), k.derive_data_key(master)


class LoadUser:
    def __init__(self, client: httpx.AsyncClient, n: int, password: str):
        self.client = client
        self.name = f"load{n}"
        self.password = password
        self.salt = hashlib.sha256(f"load-salt-{n}".encode()).digest()[:16]
        self.token: str | None = None
        self.user_id: str | None = None
        self.data_key: bytes | None = None
        # Set in main(): True when the seeded corpus has >= 30 distinct
        # entry days, so recompute MUST cross into the insight phase and
        # run the real analyzer (a 200 that stays baseline/analyzer=none
        # measured a no-op — 2026-09-19 audit, H-20).
        self.expect_analysis = False
        self.last_recompute_state = "not-run"

    async def register(self) -> bool:
        auth_key, data_key = derive(self.password, self.salt, None)
        self.data_key = data_key
        r = await self.client.post(
            "/api/v1/auth/register",
            json={
                "username": self.name,
                "salt": base64.b64encode(self.salt).decode(),
                "verifier": base64.b64encode(auth_key).decode(),
            },
        )
        if r.status_code == 201:
            self.token = r.json()["token"]
            self.user_id = r.json()["user_id"]
            return True
        if r.status_code == 409:
            # Persistent handles re-register on every run: 409 is the
            # expected answer, and without this login fallback every
            # later call would run with `Bearer None` and measure 401
            # latencies instead of entry/recompute work.
            return await self.login()
        return False

    async def login(self) -> bool:
        auth_key, _ = derive(self.password, self.salt, None)
        r = await self.client.post(
            "/api/v1/auth/login",
            json={
                "username": self.name,
                "verifier": base64.b64encode(auth_key).decode(),
            },
        )
        if r.status_code == 200:
            self.token = r.json()["token"]
            self.user_id = r.json()["user_id"]
            return True
        return False

    async def create_entry(self, day: str, text: str) -> bool:
        from app.security import crypto

        entry_id = f"load-{day}"
        payload = json.dumps({"v": 1, "text": text, "sentiment": None, "created_at": day}).encode()
        blob = crypto.encrypt(
            self.data_key, payload, crypto.build_aad("entry", self.user_id or "", entry_id)
        )
        r = await self.client.post(
            "/api/v1/entries",
            headers={"Authorization": f"Bearer {self.token}"},
            json={
                "client_entry_id": entry_id,
                "blob": base64.b64encode(blob).decode(),
                "entry_date": day,
            },
        )
        return r.status_code in (201, 409)

    async def recompute(self) -> bool:
        r = await self.client.post(
            "/api/v1/processing/sessions",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"data_key": base64.b64encode(self.data_key).decode()},
        )
        if r.status_code != 201:
            return False
        token = r.json()["session_token"]
        r = await self.client.post(
            "/api/v1/insights/recompute",
            headers={"Authorization": f"Bearer {self.token}", "X-Processing-Token": token},
        )
        if r.status_code != 200:
            return False
        # Assert on the WORK DONE, not just the status: phase must be
        # "insight" and the analyzer must have actually run ("brain" or
        # "llm") when the seeded corpus crossed the 30-distinct-day
        # threshold. A plain 200 in baseline phase measures a no-op and
        # used to be counted as recompute capacity (2026-09-19 audit, H-20).
        body = r.json()
        self.last_recompute_state = (
            f"phase={body.get('phase')} analyzer={body.get('analyzer')} "
            f"active_days={body.get('active_days')}"
        )
        if self.expect_analysis and (
            body.get("phase") != "insight" or body.get("analyzer") not in ("brain", "llm")
        ):
            return False
        return True


async def phase(client: httpx.AsyncClient, label: str, coros) -> Stats:
    stats = Stats(label)
    started = time.monotonic()

    async def timed(i, coro):
        t0 = time.monotonic()
        try:
            ok = await coro
        except Exception:
            ok = False
        stats.record(time.monotonic() - t0, bool(ok))

    await asyncio.gather(*(timed(i, c) for i, c in enumerate(coros)))
    stats.elapsed = time.monotonic() - started
    print(f"  {stats.summary()}")
    return stats


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument(
        "--entries-per-user",
        type=int,
        default=32,
        help="entries (on distinct days) seeded per user; >= 30 distinct days "
        "is required for recompute to cross into the insight phase and "
        "measure real analyzer work instead of a baseline no-op "
        "(2026-09-19 audit, H-20)",
    )
    parser.add_argument(
        "--days-back",
        type=int,
        default=35,
        help="entries spread over N days (drives the brain's window size; "
        "keep >= entries-per-user so every entry lands on its own day)",
    )
    parser.add_argument(
        "--db-url",
        default=None,
        help="Optional SQLAlchemy URL of the API database. The entry API "
        "only accepts dates within +/-1 day of account creation (the "
        "threshold-inflation guard), so seeding 30+ distinct PAST days "
        "requires backdating the load handles' created_at — exactly what "
        "scripts/seed_demo.py does for the demo account. Without it, a "
        "fresh database rejects the backdated entries (422) and the "
        "recompute phase measures only the baseline no-op.",
    )
    args = parser.parse_args()

    from datetime import date, datetime, timedelta
    from datetime import timezone as tz

    password = "loadtest-password-1"
    async with httpx.AsyncClient(base_url=args.url, timeout=120) as client:
        print(f"==> load probe against {args.url} ({args.users} users)")
        # Two scrypt phases over the SAME handles: a fresh database
        # answers registration (201); an existing one answers 409 and the
        # login fallback takes over — either way every later phase runs
        # with a real bearer token.
        users = [LoadUser(client, i, password) for i in range(args.users)]
        await phase(client, "register", [u.register() for u in users])
        await phase(client, "login", [u.register() for u in users])
        tokenless = sum(1 for u in users if u.token is None)
        if tokenless:
            print(f"  WARNING: {tokenless}/{len(users)} handles have no token")
            print("  (auth rate limits?): their timings below measure 401s,")
            print("  not real work — raise MINDPATTERN_AUTH_RATE_* on the")
            print("  server for the probe.")

        today = date.today()
        if args.days_back < args.entries_per_user:
            print(
                f"  WARNING: --days-back ({args.days_back}) < --entries-per-user "
                f"({args.entries_per_user}): entry days collide, distinct-day "
                f"count drops below the 30-day threshold and recompute measures "
                f"a baseline no-op. Raise --days-back."
            )
        # One entry per DISTINCT day, spread across the window: the day is
        # computed so different entry indices never collide on the same
        # date when days_back >= entries_per_user. Distinct calendar days
        # are what the 30-day threshold counts.
        days = [
            today
            - timedelta(days=(e * args.days_back) // max(args.entries_per_user - 1, 1))
            for e in range(args.entries_per_user)
        ]
        distinct_days = len(set(days))
        if distinct_days >= 30 and not args.db_url:
            print(
                f"  NOTE: {distinct_days} distinct entry days require accounts that "
                f"old — pass --db-url to backdate the load handles' created_at "
                f"(seed_demo's mechanism) or the API's +/-1-day backdating "
                f"guard will 422 every entry older than the account."
            )
        if distinct_days < 30:
            print(
                f"  WARNING: only {distinct_days} distinct entry days seeded — "
                f"below the 30-day insight threshold, so the recompute phase "
                f"will exercise the BASELINE path only (no analyzer work). "
                f"Use --entries-per-user 30 --days-back >= 30."
            )

        if args.db_url and distinct_days >= 30:
            from sqlalchemy import update
            from sqlalchemy.ext.asyncio import create_async_engine

            from app.db import build_sessionmaker
            from app.models import User

            engine = create_async_engine(args.db_url)
            Session = build_sessionmaker(engine)
            async with Session() as db:
                for u in users:
                    await db.execute(
                        update(User)
                        .where(User.id == u.user_id)
                        .values(
                            created_at=datetime.now(tz.utc) - timedelta(days=args.days_back + 2)
                        )
                    )
                await db.commit()
            await engine.dispose()
            print(f"  backdated {len(users)} load handles {args.days_back + 2} days")

        jobs = []
        for u in users:
            u.expect_analysis = distinct_days >= 30
            for day in days:
                jobs.append(
                    u.create_entry(
                        day.isoformat(),
                        "a calm load test day with ordinary words about tea and walking",
                    )
                )
        await phase(client, "create-entry", jobs)

        recompute_stats = await phase(client, "recompute", [u.recompute() for u in users])
        from collections import Counter

        states = Counter(u.last_recompute_state for u in users)
        print(f"  recompute outcomes: {dict(states)}")
        if recompute_stats.failures and any(
            "phase=baseline" in s or "analyzer=none" in s for s in states
        ):
            print("  (baseline/no-analyzer recomputes were counted as FAILURES:")
            print("   a 200 without analyzer work is a no-op, not capacity)")

    print("==> done. Compare p95s against the deployment contract: login is")
    print("    scrypt-bound (~4/s ceiling); recompute is brain-bound (~3/s at")
    print("    4 concurrent analyze slots). Sustained saturation of either")
    print("    means it is time for the Redis keystore/counter work.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
