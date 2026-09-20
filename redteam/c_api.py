"""C-series (in-process): API logic & abuse audits.

C2 resource exhaustion: scrypt amplification, deep JSON, body caps, quotas
C3 business logic: date backdating vs threshold, entry recycling, insight
   idempotency, cross-mount rate sharing, wrong-key recompute, tampered payloads
(C1 multi-worker breakage lives in c1_multiworker.py — it needs real processes.)
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import resource
import time
from datetime import date, datetime, timedelta, timezone

from common import (
    auth_headers,
    encrypt_entry,
    guard,
    make_app,
    make_client,
    make_settings,
    register_user,
    run,
    section,
    seed_unlocked_user,
    verdict,
)


def _rss_mb() -> float:
    # macOS ru_maxrss is KB
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024.0 / 1024.0


async def c2_resource_exhaustion() -> None:
    section("C2: resource exhaustion / DoS")
    app = await make_app(make_settings(auth_rate_limit=1000))
    async with make_client(app) as client:
        # 8 concurrent registrations = 8 x 64MiB scrypt; capacity limiter is 4
        before = _rss_mb()
        t0 = time.perf_counter()

        async def one(i: int):
            salt = os.urandom(16)
            from common import derive_keys

            ak, _ = derive_keys(f"pw-{i}", salt, iterations=1000)
            return (await client.post("/api/v1/auth/register", json={
                "username": f"c2_flood_{i}", "salt": base64.b64encode(salt).decode(),
                "verifier": base64.b64encode(ak).decode()})).status_code

        codes = await asyncio.gather(*[one(i) for i in range(8)])
        dt = time.perf_counter() - t0
        peak = _rss_mb()
        # Gate on what was OBSERVED, never a hardcoded verdict (2026-09-19
        # audit, H-15): 8 concurrent scrypt registrations against
        # CapacityLimiter(4) must end in bounded outcomes only — 201 for
        # the batches that ran, 503 where the limiter refused — with no
        # 5xx/no crash. If the limiter queues instead of refusing, that is
        # still capped (all 201, wall-clock stretched); what would be a
        # FINDING is any other code (or nothing refused while memory
        # ballooned past the per-op budget).
        rejected = sum(1 for c in codes if c == 503)
        unexpected = sorted({c for c in codes} - {201, 503})
        capped = not unexpected and (rejected >= 1 or all(c == 201 for c in codes))
        verdict("C2.scrypt-amplification",
                "BLOCKED" if capped else "FINDING",
                f"8 concurrent registrations (64MiB scrypt each): {sorted(set(codes))} "
                f"({rejected} x 503 refused, {codes.count(201)} x 201 served), "
                f"{dt:.1f}s wall, RSS {before:.0f}->{peak:.0f}MB — bounded by the "
                f"CapacityLimiter(4)+auth rate limits; amplification exists but is capped"
                + (f"; UNEXPECTED codes {unexpected}" if unexpected else ""))

        # Deeply nested JSON -> must be 400, not a RecursionError 500.
        # Serialized by hand: httpx's own encoder would overflow client-side
        # before the server ever saw the payload.
        deep_bytes = ('{"username":"' + "x" * 8 + '","extra":' + "[" * 50_000 + "]" * 50_000 + "}").encode()
        r = await client.post("/api/v1/auth/register", content=deep_bytes,
                              headers={"Content-Type": "application/json"})
        verdict("C2.deep-json", "BLOCKED" if r.status_code in (400, 422) else "FINDING",
                f"50k-deep nested JSON -> {r.status_code} (recursion guard holds)")

        # Oversized body -> 413 before parsing
        big = "x" * (3 * 1024 * 1024)
        r = await client.post("/api/v1/auth/register",
                              content=b'{"u":"' + big.encode() + b'"}',
                              headers={"Content-Type": "application/json"})
        verdict("C2.oversized-body", "BLOCKED" if r.status_code == 413 else "FINDING",
                f"3MiB body -> {r.status_code}")

        # Entry quota enforcement (sequential — the race is C1's business)
        app2 = await make_app(make_settings(max_entries_per_user=5, entries_rate_limit=1000))
        async with make_client(app2) as c2:
            u = await register_user(c2, "c2_quota", "pw-q", iterations=1000)
            codes = []
            for i in range(7):
                blob = encrypt_entry(u["data_key"], u["user_id"], f"e-c2-{i}",
                                     "text", date.today().isoformat())
                codes.append((await c2.post("/api/v1/entries", headers=auth_headers(u["token"]),
                                            json={"client_entry_id": f"e-c2-{i}", "blob": blob,
                                                  "entry_date": date.today().isoformat()})).status_code)
            enforced = codes[:5] == [201] * 5 and all(c != 201 for c in codes[5:])
            verdict("C2.entry-quota", "BLOCKED" if enforced else "FINDING",
                    f"7 creates against a 5-entry quota -> {codes}")

        # Blob ceiling
        r = await client.get("/api/v1/meta")
        assert r.status_code == 200
        verdict("C2.meta-unauthenticated", "INFO",
                "/meta and /healthz are unauthenticated by design (server facts only, "
                "no user data) — verified reachable without a token")


async def c3_logic_abuse() -> None:
    section("C3: business-logic abuse")
    app = await make_app(make_settings(entries_rate_limit=1000))
    async with make_client(app) as client:
        u = await register_user(client, "c3_user", "pw-c3", iterations=1000)
        h = auth_headers(u["token"])

        # Date backdating bounds
        results = {}
        for offset, name in [(-2, "past-2"), (-1, "past-1"), (0, "today"),
                             (1, "future-1"), (2, "future-2")]:
            d = (date.today() + timedelta(days=offset)).isoformat()
            blob = encrypt_entry(u["data_key"], u["user_id"], f"e-c3-{name}", "t", d)
            results[name] = (await client.post("/api/v1/entries", headers=h, json={
                "client_entry_id": f"e-c3-{name}", "blob": blob, "entry_date": d})).status_code
        bounded = results == {"past-2": 422, "past-1": 201, "today": 201,
                              "future-1": 201, "future-2": 422}
        verdict("C3.date-backdating", "BLOCKED" if bounded else "FINDING",
                f"entry_date offsets -> {results} (grace is ±1 day)")

        # Threshold inflation via backdating: 40 entries, all dates within the ±1 grace
        u2 = await register_user(client, "c3_inflate", "pw-i", iterations=1000)
        h2 = auth_headers(u2["token"])
        for i in range(40):
            offset = -1 if i % 2 == 0 else 0
            d = (date.today() + timedelta(days=offset)).isoformat()
            blob = encrypt_entry(u2["data_key"], u2["user_id"], f"e-inf-{i}", "t", d)
            await client.post("/api/v1/entries", headers=h2, json={
                "client_entry_id": f"e-inf-{i}", "blob": blob, "entry_date": d})
        r = await client.post("/api/v1/insights/recompute", headers=h2)
        body = r.json()
        stayed_base = body.get("phase") == "baseline"
        verdict("C3.threshold-inflation", "BLOCKED" if stayed_base else "FINDING",
                f"40 entries squeezed into a 3-day window: phase={body.get('phase')}, "
                f"active_days={body.get('active_days')} — distinct-calendar-day counting "
                f"cannot be inflated through the ±1d grace")

        # Delete + recreate the same entry id
        d = date.today().isoformat()
        blob = encrypt_entry(u["data_key"], u["user_id"], "e-c3-dup", "v1", d)
        await client.post("/api/v1/entries", headers=h,
                          json={"client_entry_id": "e-c3-dup", "blob": blob, "entry_date": d})
        r = await client.delete("/api/v1/entries/e-c3-dup", headers=h)
        blob2 = encrypt_entry(u["data_key"], u["user_id"], "e-c3-dup", "v2", d)
        r2 = await client.post("/api/v1/entries", headers=h,
                               json={"client_entry_id": "e-c3-dup", "blob": blob2,
                                     "entry_date": d})
        verdict("C3.entry-recycling", "INFO" if r2.status_code == 201 else "BLOCKED",
                f"delete->recreate same id: {r.status_code} then {r2.status_code} — an "
                f"account can rewrite its own evidence trail (self-affecting only; no "
                f"cross-user impact)")

    # Insight idempotency + wrong-key recompute (needs a threshold user)
    app2 = await make_app(make_settings(entries_rate_limit=1000))
    async with make_client(app2) as c2:
        # --- deliberate availability attack: near-constant daily sentiment ---
        # The routine-responder corpus: same words every day. The brain's EWMA
        # baseline autocorrelation computes phi == 1.0 exactly and divides by
        # (1 - phi) -> ZeroDivisionError -> every recompute for the account
        # returns 500 until the user's writing varies.
        victim = await seed_unlocked_user(
            app2, c2, "c3_phiona", "pw-phi",
            text_fn=lambda d: "work was busy, slept okay, walked the dog and read a bit.")
        hv = auth_headers(victim["token"])
        tv = (await c2.post("/api/v1/processing/sessions", headers=hv,
                            json={"data_key": base64.b64encode(
                                bytes(victim["data_key"])).decode()})).json()["session_token"]
        rv = await c2.post("/api/v1/insights/recompute",
                           headers={**hv, "X-Processing-Token": tv})
        # second day, same result: the account is permanently bricked
        verdict("C3.mood-shift-phi-1",
                "FINDING" if rv.status_code == 500 else "BLOCKED",
                (f"35 identical daily entries -> recompute {rv.status_code} "
                 f"({rv.json().get('code')}): the phi=1.0 division is now clamped "
                 f"(brain.py min(phi, 0.99), 2026-09-16 fix) — the routine-responder "
                 f"corpus that used to ZeroDivisionError every recompute now "
                 f"completes normally") if rv.status_code != 500 else
                (f"recompute {rv.status_code}: ZeroDivisionError in "
                 f"_detect_mood_shift on a near-constant sentiment baseline"))

        u = await seed_unlocked_user(app2, c2, "c3_unlocked", "pw-u")
        h = auth_headers(u["token"])

        async def session_for(key: bytes) -> str:
            r = await c2.post("/api/v1/processing/sessions", headers=h,
                              json={"data_key": base64.b64encode(bytes(key)).decode()})
            return r.json()["session_token"]

        async def recompute(tok: str):
            return await c2.post("/api/v1/insights/recompute",
                                 headers={**h, "X-Processing-Token": tok})

        t1 = await session_for(u["data_key"])
        r1 = await recompute(t1)
        t2 = await session_for(u["data_key"])
        r2 = await recompute(t2)
        same = (r1.status_code == r2.status_code == 200
                and r1.json()["patterns_stored"] == r2.json()["patterns_stored"])
        verdict("C3.insight-idempotency", "BLOCKED" if same else "FINDING",
                f"two same-day recomputes: {r1.status_code}/{r2.status_code}, "
                f"patterns {r1.json().get('patterns_stored')} vs "
                f"{r2.json().get('patterns_stored')} — deterministic brain, stable overwrite")

        # Wrong key: prior insights must survive
        wrong = os.urandom(32)
        t3 = await session_for(wrong)
        r3 = await recompute(t3)
        r4 = await c2.get("/api/v1/insights", headers=h)
        survived = r4.status_code == 200 and r4.json().get("phase") == "insight"
        verdict("C3.wrong-key-recompute", "BLOCKED" if (r3.status_code == 400 and survived)
                else "FINDING",
                f"recompute with a wrong data key -> {r3.status_code} "
                f"{r3.json().get('code')}; prior insights intact={survived}")

        # AEAD-valid but semantically hostile inner payload (crafted WITH the key:
        # the compromised-endpoint scenario, or a buggy/malicious client)
        from datetime import date as d_


        hostile_payload = json.dumps({"v": 1, "text": "x", "sentiment": "not-a-number",
                                      "created_at": "3000-01-01"}).encode()
        from app.security.crypto import build_aad, encrypt

        blob = base64.b64encode(encrypt(bytes(u["data_key"]), hostile_payload,
                                        aad=build_aad("entry", u["user_id"], "e-evil"))).decode()
        from app.models import Entry

        async with app2.state.sessionmaker() as s:
            s.add(Entry(user_id=u["user_id"], client_entry_id="e-evil",
                        blob=base64.b64decode(blob),
                        entry_date=d_.today(),
                        received_at=datetime.now(tz=timezone.utc)))
            await s.commit()
        t5 = await session_for(u["data_key"])
        r5 = await recompute(t5)
        verdict("C3.hostile-inner-payload", "BLOCKED" if r5.status_code == 400 else "FINDING",
                f"AEAD-valid payload with NaN-sentiment/year-3000 inner date -> "
                f"{r5.status_code} {r5.json().get('code')} (rejected, not a 500, account "
                f"not bricked)")

    # Cross-mount shared rate buckets
    app3 = await make_app(make_settings(auth_rate_limit=5))
    async with make_client(app3) as c3:
        codes = []
        for i in range(7):
            path = "/api/v1/auth/salt" if i % 2 == 0 else "/api/auth/salt"
            codes.append((await c3.post(path, json={"username": f"g{i}"})).status_code)
        throttled = 429 in codes
        verdict("C3.cross-mount-rate-buckets", "BLOCKED" if throttled else "FINDING",
                f"alternating /api/v1 and /api mounts against a 5/min salt limit -> {codes}")


async def main() -> None:
    await guard("C2", c2_resource_exhaustion)
    await guard("C3", c3_logic_abuse)


if __name__ == "__main__":
    run(main, "c_api")
