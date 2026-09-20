"""C1: multi-worker deployment breakage (live uvicorn, 2 workers).

The codebase documents single-process as a hard assumption (locks.py,
cache.py, enclave keystore are all in-process). This audit boots the real
server the documented-forbidden way — ``--workers 2`` — and re-runs three
guarantees that are supposed to hold.

Fragmentation only appears across SEPARATE TCP connections: keep-alive
pins a connection to one worker. Every burst below therefore uses one
fresh AsyncClient per request, fired concurrently.
"""

from __future__ import annotations

import asyncio
import base64
import os
import signal
import subprocess
from contextlib import asynccontextmanager
from datetime import date

import httpx
from common import derive_keys, encrypt_entry, run, section, verdict

PORT = 8971
BASE = f"http://127.0.0.1:{PORT}"
DB = "/tmp/redteam_c1.db"


def spawn_server() -> subprocess.Popen:
    env = dict(os.environ)
    env.update({
        "MINDPATTERN_ENV": "development",
        "MINDPATTERN_DB_URL": f"sqlite+aiosqlite:///{DB}",
        "MINDPATTERN_TOKEN_SECRET": "redteam-c1-secret-32-chars-minimum",
        "MINDPATTERN_AUTH_RATE_LIMIT": "40",   # keep registration usable
        "MINDPATTERN_EXPORT_RATE_LIMIT": "5",
        "MINDPATTERN_MAX_ENTRIES_PER_USER": "5",
    })
    if os.path.exists(DB):
        os.remove(DB)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Dev-mode create_all races between workers ( OperationalError "table
    # already exists") — boot ONE worker first to lay the schema down, then
    # boot the two-worker target against the prepared DB. (Production uses
    # the alembic entrypoint with a Postgres advisory lock, so this race is
    # dev-only; noted in the report.)
    pre = subprocess.Popen(
        [os.path.join(root, ".venv", "bin", "python"), "-m", "uvicorn",
         "app.main:app", "--port", str(PORT), "--log-level", "error"],
        cwd=os.path.join(root, "backend"), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True)
    import time as _t

    _t.sleep(4)
    try:
        os.killpg(pre.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    _t.sleep(0.5)
    log = open("/tmp/redteam_c1_server.log", "w")  # noqa: SIM115 - closed in finally
    proc = subprocess.Popen(
        [os.path.join(root, ".venv", "bin", "python"),
         "-m", "uvicorn", "app.main:app", "--workers", "2",
         "--port", str(PORT), "--log-level", "warning"],
        cwd=os.path.join(root, "backend"), env=env,
        stdout=log, stderr=log, start_new_session=True)  # own process group
    proc._redteam_log = log
    return proc


async def wait_healthy(proc) -> bool:
    for _ in range(120):
        if proc.poll() is not None:
            return False
        try:
            async with httpx.AsyncClient() as c:
                if (await c.get(f"{BASE}/healthz", timeout=1.0)).status_code == 200:
                    return True
        except httpx.HTTPError:
            pass
        await asyncio.sleep(0.5)
    return False


@asynccontextmanager
async def one_shot():
    """A single request over its own connection — the only way to be sure
    the kernel load-balances us across both workers."""
    c = httpx.AsyncClient(base_url=BASE, timeout=30.0)
    try:
        yield c
    finally:
        await c.aclose()


async def burst(n: int, fn) -> list:
    """n concurrent one-connection requests; fn receives a fresh client."""
    async def single(i):
        async with one_shot() as c:
            return await fn(c, i)

    return list(await asyncio.gather(*[single(i) for i in range(n)]))


async def register(username: str) -> dict:
    salt = os.urandom(16)
    ak, dk = derive_keys(f"pw-{username}", salt, iterations=1000)
    async with one_shot() as c:
        r = await c.post("/api/v1/auth/register", json={
            "username": username, "salt": base64.b64encode(salt).decode(),
            "verifier": base64.b64encode(ak).decode()})
        r.raise_for_status()
        body = r.json()
        return {"token": body["token"], "user_id": body["user_id"],
                "data_key": dk, "auth_key": ak}


async def main() -> None:
    section("C1: multi-worker breakage (uvicorn --workers 2, documented-forbidden)")
    proc = spawn_server()
    try:
        # 2026-09-16 fix: the single-process guard (app/singleprocess.py)
        # makes the SECOND worker refuse to boot, which fails the whole
        # uvicorn supervisor. A dead 2-worker server within the wait window
        # is now the CORRECT outcome.
        healthy = await wait_healthy(proc)
        # The first worker may answer a probe before the second worker's
        # refusal tears the supervisor down — require the server to STAY up.
        if healthy:
            await asyncio.sleep(4)
            try:
                async with httpx.AsyncClient() as c:
                    healthy = (await c.get(f"{BASE}/healthz", timeout=1.0)).status_code == 200
            except httpx.HTTPError:
                healthy = False
        alive = proc.poll() is None
        if not healthy or not alive:
            # Require the EXPECTED refusal signature before attributing a
            # dead/unhealthy 2-worker boot to the deployment lock: a bad
            # import, a DB error, or a port clash also leaves an unhealthy
            # boot, and calling any of those "lock refused" would print a
            # false BLOCKED (2026-09-19 audit, M-34).
            try:
                proc._redteam_log.flush()
                with open("/tmp/redteam_c1_server.log") as fh:
                    log_text = fh.read()
            except OSError:
                log_text = ""
            refused = "already serving this deployment" in log_text
            if refused:
                verdict("C1.server-boot", "BLOCKED",
                        "2-worker uvicorn is REFUSED: the deployment lock makes the "
                        "second worker exit at startup with 'another worker/process is "
                        "already serving this deployment' (single-process contract is "
                        "now enforced, not just documented)")
            else:
                verdict("C1.server-boot", "ERROR",
                        f"2-worker uvicorn unhealthy/dead WITHOUT the deployment-lock "
                        f"refusal signature (healthy={healthy}, alive={alive}) — cause "
                        f"unidentified, refusing to claim the lock refused it. "
                        f"Server log tail: {log_text[-600:]!r}")
            return
        verdict("C1.server-boot", "FINDING", "2-worker uvicorn booted (guard failed)")

        # --- 1. rate-limit fragmentation: dedicated 5/min export bucket ------
        u = await register("c1_export")
        hdr = {"Authorization": f"Bearer {u['token']}"}
        codes = await burst(12, lambda c, i: c.get("/api/v1/account/export", headers=hdr))
        statuses = [r.status_code for r in codes]
        allowed = statuses.count(200)
        verdict("C1.rate-limit-fragmentation",
                "FINDING" if allowed > 5 else "BLOCKED",
                f"12 concurrent exports (separate connections) against the 5/min "
                f"export bucket: {allowed} allowed, statuses={sorted(set(statuses))} "
                f"— each worker keeps its own counter")

        # --- 2. entry-quota race --------------------------------------------
        u2 = await register("c1_quota")
        hdr2 = {"Authorization": f"Bearer {u2['token']}"}

        async def create(c, i):
            blob = encrypt_entry(u2["data_key"], u2["user_id"], f"e-c1-{i}", "text",
                                 date.today().isoformat())
            return (await c.post("/api/v1/entries", headers=hdr2, json={
                "client_entry_id": f"e-c1-{i}", "blob": blob,
                "entry_date": date.today().isoformat()})).status_code

        statuses = await burst(12, create)
        created = statuses.count(201)
        verdict("C1.quota-race",
                "FINDING" if created > 5 else "PARTIAL",
                f"12 concurrent creates against a 5-entry quota: {created} created "
                f"(races across processes are real but SQLite's single-writer lock "
                f"narrows the window — one run of this same attack observed 6/5; on "
                f"Postgres the window widens)")

        # --- 3. keystore fragmentation --------------------------------------
        u3 = await register("c1_keys")
        hdr3 = {"Authorization": f"Bearer {u3['token']}"}
        for i in range(2):  # baseline phase, but WITH entries so recompute runs
            blob = encrypt_entry(u3["data_key"], u3["user_id"], f"e-k-{i}", "text",
                                 date.today().isoformat())
            async with one_shot() as c:
                (await c.post("/api/v1/entries", headers=hdr3, json={
                    "client_entry_id": f"e-k-{i}", "blob": blob,
                    "entry_date": date.today().isoformat()})).raise_for_status()
        async with one_shot() as c:
            r = await c.post("/api/v1/processing/sessions", headers=hdr3,
                             json={"data_key": base64.b64encode(
                                 bytes(u3["data_key"])).decode()})
            tok = r.json()["session_token"]
        # Baseline-phase recompute must DESTROY the presented token. Fire the
        # same token at both workers: if each worker holds its own store, the
        # destroy only lands where the request happens to land.
        statuses = await burst(6, lambda c, i: c.post(
            "/api/v1/insights/recompute",
            headers={**hdr3, "X-Processing-Token": tok}))
        answered = [s.status_code for s in statuses]
        # Every 200 means a baseline recompute saw (and destroyed) a token —
        # more than one 200 with the SAME single-use token proves split state
        ok_count = answered.count(200)
        verdict("C1.keystore-fragmentation",
                "FINDING" if ok_count > 1 else "BLOCKED",
                f"one session token fed to {len(answered)} recomputes across "
                f"workers: {ok_count} succeeded (statuses {sorted(set(answered))}) — "
                f"single-use/destroy/TTL/logout-purge guarantees are per-process; "
                f"a 2-worker deployment keeps uploaded data keys alive in the "
                f"worker the destroying call never reaches")
    finally:
        import signal as _sig

        try:
            os.killpg(proc.pid, _sig.SIGKILL)  # parent + its workers, nobody else
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc._redteam_log.close()
        except Exception:  # noqa: BLE001
            pass


if __name__ == "__main__":
    run(main, "c1_multiworker")
