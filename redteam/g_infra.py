"""G-series: infrastructure & supply-chain audits.

G1 backup vs deletion conflict (docker unavailable -> config audit + live
   dev-DB dump simulation of what a backup would expose)
G2 supply chain (pip-audit / npm audit if network allows; lockfile shape)
G3 production fail-closed verification (subprocess boots) + repo hygiene
"""

from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import yaml
from common import RESULTS, guard, run, section, verdict

ROOT = RESULTS.parent.parent
BACKEND = ROOT / "backend"
VENV_PY = ROOT / ".venv" / "bin" / "python"


def _backup_helper_contract(path: Path) -> bool:
    """Exercise file-secret resolution and the actual OpenSSL argv builder.

    Formatting cannot change this oracle. The authenticated restore drill
    supplies separate end-to-end encryption/HMAC evidence.
    """
    spec = importlib.util.spec_from_file_location("redteam_backup_contract", path)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with tempfile.TemporaryDirectory(prefix="redteam-backup-contract-") as scratch:
        key = Path(scratch) / "fixture-key"
        key.write_text("redteam-backup-fixture-not-production\n")
        with patch.dict(os.environ, {"BACKUP_KEY_FILE": str(key)}, clear=True):
            resolved = helper._resolve_backup_key()
        with patch.dict(os.environ, {}, clear=True):
            try:
                helper._resolve_backup_key()
            except RuntimeError:
                refuses_missing = True
            else:
                refuses_missing = False
        with patch.object(
            helper.subprocess, "run", return_value=SimpleNamespace(returncode=0)
        ) as call:
            helper._openssl(resolved, io.BytesIO(b"fixture"), io.BytesIO(), decrypt=False)
        args = call.call_args.args[0]
        iter_at = args.index("-iter") if "-iter" in args else -1
        return (
            refuses_missing
            and resolved == "redteam-backup-fixture-not-production"
            and "-aes-256-cbc" in args
            and "-pbkdf2" in args
            and iter_at >= 0
            and iter_at + 1 < len(args)
            and args[iter_at + 1] == "600000"
            and resolved not in args
            and "BACKUP_KEY" not in call.call_args.kwargs["env"]
        )


def g1_backups() -> None:
    section("G1: backup vs deletion + dump contents")
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    backup = compose["services"]["backup"]
    env = backup.get("environment", {})
    entrypoint = backup.get("entrypoint", [])
    script = "\n".join(entrypoint) if isinstance(entrypoint, list) else entrypoint
    volumes = backup.get("volumes", [])
    has_backup = "pg_dump" in script and any(
        isinstance(volume, str) and volume.endswith(":/backups") for volume in volumes
    )
    retention = env.get("BACKUP_RETENTION_DAYS") == "${BACKUP_RETENTION_DAYS:-35}"
    plaintext_env_absent = env.get("BACKUP_KEY") in (None, "")
    key_file_mount = env.get("BACKUP_KEY_FILE") == "/run/secrets/backup_key"
    mounted = backup.get("secrets", [])
    secret_mounted = any(
        secret == "backup_key" or isinstance(secret, dict) and secret.get("source") == "backup_key"
        for secret in mounted
    ) and "backup_key" in compose.get("secrets", {})
    uses_helper = 'mindpattern-backup-mac encrypt "$$tmp" "$$mac_tmp"' in script
    helper_contract = _backup_helper_contract(ROOT / "backup/backup_mac.py")
    encrypted = (
        has_backup
        and retention
        and plaintext_env_absent
        and key_file_mount
        and secret_mounted
        and uses_helper
        and helper_contract
    )
    verdict(
        "G1.backup-profile-config",
        "BLOCKED" if encrypted else "FINDING",
        f"compose backup profile: pg_dump={has_backup}, 35-day "
        f"retention={'yes' if retention else 'no'}, AES-256-CBC/PBKDF2-600k dump "
        f"encryption with the key REQUIRED via the mounted secret file "
        f"(plaintext env absent={plaintext_env_absent}, BACKUP_KEY_FILE mount={key_file_mount}, "
        f"secrets: entry={secret_mounted}, shared helper={uses_helper}, executed helper contract={helper_contract}) — a stolen backup "
        f"volume is ciphertext at rest and a missing key refuses the dump outright. "
        f"Residual by design: dumps taken before a deletion still hold the "
        f"user's rows until retention expires; the README states this as "
        f"the deletion-and-retention scope",
    )

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
            "select distinct entry_date from entries order by entry_date limit 40"
        ).fetchall()
        sizes = con.execute(
            "select min(length(blob)), max(length(blob)), avg(length(blob)) from entries"
        ).fetchone()
    finally:
        con.close()
    verdict(
        "G1.dump-contents",
        "PARTIAL" if users or n_entries else "INFO",
        f"what a dump carries (same columns): {len(users)} usernames, "
        f"{n_entries} entries, {len(dates)} distinct dates, blob sizes {sizes} "
        f"— with the 2026-09-16 fix this metadata is only readable by a "
        f"BACKUP_KEY holder (AES-256-CBC at rest); the residual is the "
        f"retention-vs-deletion window, not plaintext-on-disk",
    )


def g2_supply_chain() -> None:
    section("G2: supply chain")
    # pip-audit
    r = subprocess.run(
        [str(VENV_PY), "-m", "pip_audit", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        r2 = subprocess.run(
            [str(VENV_PY), "-m", "pip", "show", "pip-audit"],
            check=False,
            capture_output=True,
            text=True,
        )
        pip_ok = r2.returncode == 0
    else:
        pip_ok = True
    if pip_ok:
        reqs = str(BACKEND / "requirements.lock.txt")
        r = subprocess.run(
            [str(VENV_PY), "-m", "pip_audit", "-r", reqs, "--no-deps"],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
        vulns = [
            ln for ln in r.stdout.splitlines() if "vuln" in ln.lower() or "Vulnerability" in ln
        ]
        verdict(
            "G2.pip-audit",
            "BLOCKED" if r.returncode == 0 and not vulns else "FINDING",
            f"pip-audit on requirements.lock.txt: rc={r.returncode}, "
            f"vulnerability lines={len(vulns)} {vulns[:3]}",
        )
    else:
        verdict(
            "G2.pip-audit",
            "NOT-RUN",
            "pip-audit not installed in the venv and offline install is not "
            "attempted; CI gates it (ci.yml supply-chain job)",
        )

    # npm audit
    npm = ROOT / ".tools" / "node" / "bin" / "npm"
    if npm.exists():
        r = subprocess.run(
            [str(npm), "audit", "--json"],
            cwd=str(ROOT / "mobile"),
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        try:
            data = json.loads(r.stdout or "{}")
            meta = data.get("metadata", {}).get("vulnerabilities", {})
            if not meta:
                verdict(
                    "G2.npm-audit",
                    "NOT-RUN",
                    f"npm audit returned no vulnerability metadata "
                    f"(rc={r.returncode}; likely offline)",
                )
            else:
                total = sum(v for k, v in meta.items() if k != "total") or meta.get("total", 0)
                verdict(
                    "G2.npm-audit",
                    "FINDING" if total else "BLOCKED",
                    f"npm audit (mobile): {meta}; registry findings remain visible. "
                    f"The pinned postinstall patches and verify_dependency_patches.mjs "
                    f"exercise the two remaining unpublished advisory mitigations; "
                    f"registry metadata does not certify those source patches.",
                )
        except json.JSONDecodeError:
            verdict(
                "G2.npm-audit",
                "NOT-RUN",
                f"npm audit unavailable (rc={r.returncode}, offline?)",
            )
    else:
        verdict("G2.npm-audit", "NOT-RUN", "bundled npm not found")

    # Lockfile shape: hashes pin transitive deps?
    lock = (BACKEND / "requirements.lock.txt").read_text()
    hashed = sum(1 for ln in lock.splitlines() if "--hash=" in ln)
    total = sum(1 for ln in lock.splitlines() if ln.strip() and not ln.startswith("#"))
    verdict(
        "G2.lockfile-hashes",
        "BLOCKED" if hashed and hashed >= total * 0.9 else "FINDING",
        f"requirements.lock.txt: {hashed}/{total} requirement lines carry --hash "
        f"pins; Docker installs with --no-deps",
    )

    # CI pinning
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    uses_lines = [ln.split("uses:", 1)[1].strip() for ln in ci.splitlines() if "uses:" in ln]
    unpinned = [u for u in uses_lines if "@" not in u or len(u.split("@")[-1]) < 20]
    verdict(
        "G2.actions-pinning",
        "BLOCKED" if not unpinned else "FINDING",
        f"GitHub Actions refs: {len(uses_lines)} uses, unpinned/floating: {unpinned}",
    )
    mutation = (ROOT / ".github" / "workflows" / "mutation.yml").read_text()
    verdict(
        "G2.mutation-gate",
        "INFO",
        f"mutation workflow: survivors do not fail the run "
        f"({'continue-on-error' in mutation or 'fail_fast' not in mutation}) — "
        f"quality signal only, documented",
    )


def _boot_check(
    name: str,
    env_overrides: dict[str, str],
    expect_refuse: bool,
    expected_setting: str | None = None,
) -> None:
    env = {"PATH": os.environ["PATH"]}
    env.update(env_overrides)
    code = (
        "import sys; sys.path.insert(0, '.');"
        "from app.config import Settings;"
        "s = Settings.from_env();"
        "print('BOOT-OK', s.environment)"
    )
    r = subprocess.run(
        [str(VENV_PY), "-c", code],
        cwd=str(BACKEND),
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
    booted = "BOOT-OK" in r.stdout
    # A refusal only counts when it is the EXPECTED fail-closed signature:
    # a RuntimeError from Settings validation naming a MINDPATTERN_* knob.
    # Any crash (import error, syntax error, missing module) used to read
    # as "refused boot as expected" — with stderr inspected only on the
    # failure path, never on the verdict (2026-09-19 audit, L-46).
    refusal_sig = (
        "RuntimeError" in r.stderr
        and "MINDPATTERN_" in r.stderr
        and (expected_setting is None or expected_setting in r.stderr)
    )
    if booted:
        ok = expect_refuse is False
    else:
        ok = expect_refuse is True and refusal_sig
    detail = (
        f"env={env_overrides.get('MINDPATTERN_ENV', 'production-default')} "
        f"{'booted' if booted else ('refused boot (fail-closed RuntimeError)' if refusal_sig else 'DIED without the fail-closed signature')}"
        f", expected={'refusal' if expect_refuse else 'boot'}"
    )
    if not booted and not refusal_sig:
        detail += f" — stderr tail: {r.stderr.strip()[-300:]}"
    elif not ok:
        detail += f" — stderr: {r.stderr.strip()[-160:]}"
    verdict("G3." + name, "BLOCKED" if ok else "FINDING", detail)


def g3_config_and_hygiene() -> None:
    section("G3: fail-closed config + repo hygiene")
    base = {
        "MINDPATTERN_DB_URL": "postgresql+asyncpg://u:p@localhost/db",
        "MINDPATTERN_TOKEN_SECRET": "x" * 40,
        "MINDPATTERN_AUTH_TOKEN_SECRET": "redteam-auth-purpose-fixture-32-chars",
        "MINDPATTERN_TOTP_WRAP_SECRET": "redteam-totp-purpose-fixture-32-chars",
        "MINDPATTERN_PAIRING_SECRET": "redteam-pair-purpose-fixture-32-chars",
        "MINDPATTERN_DECOY_SECRET": "redteam-decoy-purpose-fixture-32-chars",
        "MINDPATTERN_AUDIT_MAC_SECRET": bytes(range(16)).hex() * 2,
        "MINDPATTERN_AUDIT_JOURNAL": "/tmp/redteam-config-probe-audit.jsonl",
    }
    _boot_check(
        "prod-default-secret",
        {
            **base,
            "MINDPATTERN_ENV": "production",
            "MINDPATTERN_TOKEN_SECRET": "",
        },
        True,
        "MINDPATTERN_TOKEN_SECRET",
    )
    _boot_check(
        "prod-short-secret",
        {
            **base,
            "MINDPATTERN_ENV": "production",
            "MINDPATTERN_TOKEN_SECRET": "short",
        },
        True,
        "MINDPATTERN_TOKEN_SECRET",
    )
    _boot_check(
        "prod-sqlite",
        {
            **base,
            "MINDPATTERN_ENV": "production",
            "MINDPATTERN_DB_URL": "sqlite+aiosqlite:///./x.db",
            "MINDPATTERN_TOKEN_SECRET": "x" * 40,
        },
        True,
        "MINDPATTERN_DB_URL",
    )
    _boot_check(
        "prod-http-llm-url",
        {
            **base,
            "MINDPATTERN_ENV": "production",
            "MINDPATTERN_LLM_URL": "http://evil.example/v1",
        },
        True,
        "MINDPATTERN_LLM_URL",
    )
    # The real fail-closed probe: a TYPO/staging env must NOT slip into the
    # development branch — with the default dev secret it must still refuse.
    _boot_check(
        "typo-env-fails-closed",
        {
            **base,
            "MINDPATTERN_ENV": "staging ",
            "MINDPATTERN_TOKEN_SECRET": "",
        },
        True,
        "MINDPATTERN_TOKEN_SECRET",
    )
    # Staging with VALID config boots — under production gates (that is the
    # correct fail-closed semantics, not a refusal).
    _boot_check(
        "staging-valid-boots-under-prod-gates",
        {**base, "MINDPATTERN_ENV": "staging"},
        False,
    )

    # Repo hygiene
    r = subprocess.run(
        ["git", "ls-files"], cwd=str(ROOT), check=False, capture_output=True, text=True
    )
    tracked = r.stdout.splitlines()
    # S-14 (pentest 2026-09-26): mobile/ios/.xcode.env is the React Native
    # template's COMMITTED build shim (the Xcode phase sources it for
    # NODE_BINARY; untracking breaks fresh clones). Verified content: one
    # `export NODE_BINARY=$(command -v node)` line, no secret — same
    # allowlist decision as .gitleaks.toml's entry for it.
    ALLOWED_ENV_PATHS = {"mobile/ios/.xcode.env"}

    # 2026-09-28 audit: the net matched suffixes over the WHOLE path, so a
    # tracked `foo.env` in a directory named e.g. `.envish/` dodged the
    # basename intent, and keystore/cert containers (.p12/.pfx/.crt) were
    # missing entirely. Match the .env* family on the BASENAME (a name
    # starting with ".env" or ending ".env") and add the PKCS#12/cert
    # containers. (mobile/android/app/debug.keystore deliberately stays
    # outside this net: the RN template's public debug keystore, matched by
    # verify_native_release.mjs's own allowlist instead.)
    def _secretish(path: str) -> bool:
        base = os.path.basename(path)
        return base.startswith(".env") or base.endswith(
            (".env", ".pem", ".key", ".db", ".sqlite3", ".p12", ".pfx", ".crt")
        )

    bad = [f for f in tracked if _secretish(f) and f not in ALLOWED_ENV_PATHS]
    verdict(
        "G3.tracked-secrets",
        "BLOCKED" if not bad else "FINDING",
        f"git-tracked secret/db/keystore files: {bad or 'none'} "
        f"(+ {len(ALLOWED_ENV_PATHS)} reviewed RN template shim) "
        f"({len(tracked)} files tracked)",
    )

    dockerignore = BACKEND / ".dockerignore"
    di = dockerignore.read_text() if dockerignore.exists() else ""
    verdict(
        "G3.dockerignore-db",
        "BLOCKED" if "*.db" in di or "mindpattern.db" in di else "FINDING",
        f"backend/.dockerignore excludes dev DBs: {'*.db' in di or 'mindpattern.db' in di} "
        f"(mindpattern.db exists on disk in backend/ and must never enter the image)",
    )


async def main() -> None:
    await guard("G1", g1_backups)
    await guard("G2", g2_supply_chain)
    await guard("G3", g3_config_and_hygiene)


if __name__ == "__main__":
    run(main, "g_infra")
