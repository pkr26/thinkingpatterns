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
    python scripts/loadtest.py --url http://localhost:8000 --users 20

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
        return (
            f"{self.label}: n={len(lat)} fail={self.failures} "
            f"p50={p(0.50):.3f}s p95={p(0.95):.3f}s max={lat[-1]:.3f}s "
            f"throughput={len(lat) / sum(lat):.2f}/s"
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
        blob = crypto.encrypt(self.data_key, payload, crypto.build_aad("entry", self.user_id or "", entry_id))
        r = await self.client.post(
            "/api/v1/entries",
            headers={"Authorization": f"Bearer {self.token}"},
            json={"client_entry_id": entry_id, "blob": base64.b64encode(blob).decode(), "entry_date": day},
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
        return r.status_code == 200


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
    print(f"  {stats.summary()}  (wall {time.monotonic() - started:.1f}s)")
    return stats


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--users", type=int, default=20)
    parser.add_argument("--entries-per-user", type=int, default=5)
    parser.add_argument("--days-back", type=int, default=35,
                        help="entries spread over N days (drives the brain's window size)")
    args = parser.parse_args()

    from datetime import date, timedelta

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
        jobs = []
        for u in users:
            for e in range(args.entries_per_user):
                day = (today - timedelta(days=(e * args.days_back) // max(args.entries_per_user, 1))).isoformat()
                jobs.append(u.create_entry(day, "a calm load test day with ordinary words about tea and walking"))
        await phase(client, "create-entry", jobs)

        await phase(client, "recompute", [u.recompute() for u in users])

    print("==> done. Compare p95s against the deployment contract: login is")
    print("    scrypt-bound (~4/s ceiling); recompute is brain-bound (~3/s at")
    print("    4 concurrent analyze slots). Sustained saturation of either")
    print("    means it is time for the Redis keystore/counter work.")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
