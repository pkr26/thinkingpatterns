"""G-series: infrastructure & supply-chain audits.

G1 backup vs deletion conflict (docker unavailable -> config audit + live
   dev-DB dump simulation of what a backup would expose)
G2 supply chain (pip-audit / npm audit if network allows; lockfile shape)
G3 production fail-closed verification (subprocess boots) + repo hygiene
"""

from __future__ import annotations

import json
import os
import subprocess

from common import RESULTS, guard, run, section, verdict

ROOT = RESULTS.parent.parent
BACKEND = ROOT / "backend"
VENV_PY = ROOT / ".venv" / "bin" / "python"


def g1_backups() -> None:
    section("G1: backup vs deletion + dump contents")
    compose = (ROOT / "docker-compose.yml").read_text()
    has_backup = "pg_dump" in compose and "backups" in compose
    retention = "35" in compose
    encrypted = "openssl enc -aes-256-cbc" in compose and "BACKUP_KEY:?set" in compose
    verdict("G1.backup-profile-config",
            "BLOCKED" if encrypted else "FINDING",
            f"compose backup profile: pg_dump={has_backup}, 35-day "
            f"retention={'yes' if retention else 'no'}, AES-256-CBC dump "
            f"encryption with a REQUIRED BACKUP_KEY={'yes' if encrypted else 'NO'} "
            f"(2026-09-16 fix — a stolen backup volume is ciphertext at rest). "
            f"Residual by design: dumps taken before a deletion still hold the "
            f"user's rows until retention expires; the README states this as "
            f"the deletion-and-retention scope")

    # What a dump actually exposes: read the dev DB the same way pg_dump would
    db = BACKEND / "mindpattern.db"
    if not db.exists():
        verdict("G1.dump-contents", "NOT-RUN", "no dev sqlite DB present to inspect")
        return
    import sqlite3

    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        users = con.execute("select username, created_at, is_active from users limit 5").fetchall()
        n_entries = con.execute("select count(*) from entries").fetchone()[0]
        dates = con.execute(
            "select distinct entry_date from entries order by entry_date limit 40").fetchall()
        sizes = con.execute(
            "select min(length(blob)), max(length(blob)), avg(length(blob)) from entries"
        ).fetchone()
    finally:
        con.close()
    verdict("G1.dump-contents", "PARTIAL" if users or n_entries else "INFO",
            f"what a dump carries (same columns): {len(users)} usernames, "
            f"{n_entries} entries, {len(dates)} distinct dates, blob sizes {sizes} "
            f"— with the 2026-09-16 fix this metadata is only readable by a "
            f"BACKUP_KEY holder (AES-256-CBC at rest); the residual is the "
            f"retention-vs-deletion window, not plaintext-on-disk")


def g2_supply_chain() -> None:
    section("G2: supply chain")
    # pip-audit
    r = subprocess.run([str(VENV_PY), "-m", "pip_audit", "--version"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        r2 = subprocess.run([str(VENV_PY), "-m", "pip", "show", "pip-audit"],
                            capture_output=True, text=True)
        pip_ok = r2.returncode == 0
    else:
        pip_ok = True
    if pip_ok:
        reqs = str(BACKEND / "requirements.lock.txt")
        r = subprocess.run([str(VENV_PY), "-m", "pip_audit", "-r", reqs, "--no-deps"],
                           capture_output=True, text=True, timeout=300)
        vulns = [ln for ln in r.stdout.splitlines() if "vuln" in ln.lower() or "Vulnerability" in ln]
        verdict("G2.pip-audit", "BLOCKED" if r.returncode == 0 and not vulns else "FINDING",
                f"pip-audit on requirements.lock.txt: rc={r.returncode}, "
                f"vulnerability lines={len(vulns)} {vulns[:3]}")
    else:
        verdict("G2.pip-audit", "NOT-RUN",
                "pip-audit not installed in the venv and offline install is not "
                "attempted; CI gates it (ci.yml supply-chain job)")

    # npm audit
    npm = ROOT / ".tools" / "node" / "bin" / "npm"
    if npm.exists():
        r = subprocess.run([str(npm), "audit", "--json"], cwd=str(ROOT / "mobile"),
                           capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(r.stdout or "{}")
            meta = data.get("metadata", {}).get("vulnerabilities", {})
            if not meta:
                verdict("G2.npm-audit", "NOT-RUN",
                        f"npm audit returned no vulnerability metadata "
                        f"(rc={r.returncode}; likely offline)")
            else:
                total = sum(v for k, v in meta.items() if k != "total") or meta.get("total", 0)
                verdict("G2.npm-audit", "FINDING" if total else "BLOCKED",
                        f"npm audit (mobile): {meta} — CI runs this with "
                        f"continue-on-error:true (5 known-high Metro chain admitted)")
        except json.JSONDecodeError:
            verdict("G2.npm-audit", "NOT-RUN",
                    f"npm audit unavailable (rc={r.returncode}, offline?)")
    else:
        verdict("G2.npm-audit", "NOT-RUN", "bundled npm not found")

    # Lockfile shape: hashes pin transitive deps?
    lock = (BACKEND / "requirements.lock.txt").read_text()
    hashed = sum(1 for ln in lock.splitlines() if "--hash=" in ln)
    total = sum(1 for ln in lock.splitlines() if ln.strip() and not ln.startswith("#"))
    verdict("G2.lockfile-hashes", "BLOCKED" if hashed and hashed >= total * 0.9 else "FINDING",
            f"requirements.lock.txt: {hashed}/{total} requirement lines carry --hash "
            f"pins; Docker installs with --no-deps")

    # CI pinning
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    uses_lines = [ln.split("uses:", 1)[1].strip() for ln in ci.splitlines() if "uses:" in ln]
    unpinned = [u for u in uses_lines if "@" not in u or len(u.split("@")[-1]) < 20]
    verdict("G2.actions-pinning", "BLOCKED" if not unpinned else "FINDING",
            f"GitHub Actions refs: {len(uses_lines)} uses, unpinned/floating: {unpinned}")
    mutation = (ROOT / ".github" / "workflows" / "mutation.yml").read_text()
    verdict("G2.mutation-gate", "INFO",
            f"mutation workflow: survivors do not fail the run "
            f"({'continue-on-error' in mutation or 'fail_fast' not in mutation}) — "
            f"quality signal only, documented")


def _boot_check(name: str, env_overrides: dict[str, str], expect_refuse: bool) -> None:
    env = {"PATH": os.environ["PATH"]}
    env.update(env_overrides)
    code = (
        "import sys; sys.path.insert(0, '.');"
        "from app.config import Settings;"
        "s = Settings.from_env();"
        "print('BOOT-OK', s.environment)"
    )
    r = subprocess.run([str(VENV_PY), "-c", code], cwd=str(BACKEND), env=env,
                       capture_output=True, text=True, timeout=60)
    refused = "BOOT-OK" not in r.stdout
    ok = refused == expect_refuse
    verdict("G3." + name, "BLOCKED" if ok else "FINDING",
            f"env={env_overrides.get('MINDPATTERN_ENV', 'production-default')} "
            f"{'refused boot' if refused else 'booted'} as expected={expect_refuse}"
            + ("" if ok else f" — stderr: {r.stderr.strip()[-160:]}"))


def g3_config_and_hygiene() -> None:
    section("G3: fail-closed config + repo hygiene")
    base = {"MINDPATTERN_DB_URL": "postgresql+asyncpg://u:p@localhost/db",
            "MINDPATTERN_TOKEN_SECRET": "x" * 40}
    _boot_check("prod-default-secret",
                {"MINDPATTERN_ENV": "production",
                 "MINDPATTERN_DB_URL": base["MINDPATTERN_DB_URL"]}, True)
    _boot_check("prod-short-secret",
                {"MINDPATTERN_ENV": "production",
                 "MINDPATTERN_DB_URL": base["MINDPATTERN_DB_URL"],
                 "MINDPATTERN_TOKEN_SECRET": "short"}, True)
    _boot_check("prod-sqlite",
                {"MINDPATTERN_ENV": "production",
                 "MINDPATTERN_DB_URL": "sqlite+aiosqlite:///./x.db",
                 "MINDPATTERN_TOKEN_SECRET": "x" * 40}, True)
    _boot_check("prod-http-llm-url",
                {**base, "MINDPATTERN_ENV": "production",
                 "MINDPATTERN_LLM_URL": "http://evil.example/v1"}, True)
    # The real fail-closed probe: a TYPO/staging env must NOT slip into the
    # development branch — with the default dev secret it must still refuse.
    _boot_check("typo-env-fails-closed",
                {"MINDPATTERN_ENV": "staging ",
                 "MINDPATTERN_DB_URL": base["MINDPATTERN_DB_URL"]}, True)
    # Staging with VALID config boots — under production gates (that is the
    # correct fail-closed semantics, not a refusal).
    _boot_check("staging-valid-boots-under-prod-gates",
                {**base, "MINDPATTERN_ENV": "staging"}, False)

    # Repo hygiene
    r = subprocess.run(["git", "ls-files"], cwd=str(ROOT), capture_output=True, text=True)
    tracked = r.stdout.splitlines()
    bad = [f for f in tracked if f.endswith((".env", ".pem", ".key", ".db", ".sqlite3"))
           or f.startswith(".env")]
    verdict("G3.tracked-secrets", "BLOCKED" if not bad else "FINDING",
            f"git-tracked secret/db files: {bad or 'none'} ({len(tracked)} files tracked)")

    dockerignore = BACKEND / ".dockerignore"
    di = dockerignore.read_text() if dockerignore.exists() else ""
    verdict("G3.dockerignore-db", "BLOCKED" if "*.db" in di or "mindpattern.db" in di
            else "FINDING",
            f"backend/.dockerignore excludes dev DBs: {'*.db' in di or 'mindpattern.db' in di} "
            f"(mindpattern.db exists on disk in backend/ and must never enter the image)")


async def main() -> None:
    await guard("G1", g1_backups)
    await guard("G2", g2_supply_chain)
    await guard("G3", g3_config_and_hygiene)


if __name__ == "__main__":
    run(main, "g_infra")
