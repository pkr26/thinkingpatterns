#!/usr/bin/env python3
"""Verify the October 3 upgrade preserves synthetic legacy ciphertext.

Run with backend/.venv/bin/python and REMEDIATION_UPGRADE_DB_URL pointing
to a disposable PostgreSQL database whose name ends in _test. First apply
the previous head a3f7c1d9b5e2. This never wipes or creates a database.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import asyncpg
from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[1]
if not __debug__:
    raise SystemExit(
        "upgrade verification requires assertions; refuse Python optimization"
    )
sys.path.insert(0, str(ROOT / "backend"))
from app.security import crypto  # noqa: E402


async def main():
    url = os.environ["REMEDIATION_UPGRADE_DB_URL"]
    wire = url.replace("postgresql+asyncpg://", "postgresql://", 1)
    if not urlparse(wire).path.endswith("_test"):
        raise SystemExit("refusing a database whose name does not end in _test")
    conn = await asyncpg.connect(wire)
    try:
        head = await conn.fetchval("SELECT version_num FROM alembic_version")
        if head != "a3f7c1d9b5e2":
            raise SystemExit("expected the previous migration head before seeding")
        if await conn.fetchval("SELECT count(*) FROM users"):
            raise SystemExit("refusing to seed a nonempty database")
        await conn.execute("BEGIN")
        now = datetime.now(timezone.utc)
        patient, therapist = "1" * 32, "2" * 32
        data_key, notes_key = bytes(range(32)), bytes(reversed(range(32)))
        for uid, role in ((patient, "user"), (therapist, "therapist")):
            await conn.execute(
                """INSERT INTO users
                (id, username, salt, verifier, scrypt_salt, created_at,
                 is_active, token_epoch, llm_consent, role)
                VALUES ($1,$2,$3,$4,$5,$6,true,0,false,$7)""",
                uid,
                f"upgrade-{role}",
                "synthetic-salt",
                bytes(32),
                bytes(16),
                now,
                role,
            )
        entry_aad = crypto.entry_aad_v1(patient, "legacy-entry")
        entry = crypto.encrypt(
            data_key, b'{"v":1,"text":"synthetic preserved journal"}', entry_aad
        )
        note_aad = crypto.build_aad("note", therapist, patient, "legacy-note")
        note = crypto.encrypt(
            notes_key, b'{"v":1,"text":"synthetic current note"}', note_aad
        )
        revision = crypto.encrypt(
            notes_key, b'{"v":1,"text":"synthetic earlier note"}', note_aad
        )
        await conn.execute(
            "INSERT INTO entries (id,user_id,client_entry_id,blob,entry_date,received_at) VALUES ($1,$2,$3,$4,$5,$6)",
            "3" * 32,
            patient,
            "legacy-entry",
            entry,
            date.today(),
            now,
        )
        await conn.execute(
            "INSERT INTO therapist_notes (id,therapist_id,user_id,client_note_id,blob,created_at,updated_at,version) VALUES ($1,$2,$3,$4,$5,$6,$6,2)",
            "4" * 32,
            therapist,
            patient,
            "legacy-note",
            note,
            now,
        )
        await conn.execute(
            "INSERT INTO therapist_note_revisions (id,note_id,therapist_id,blob,created_at) VALUES ($1,$2,$3,$4,$5)",
            "5" * 32,
            "4" * 32,
            therapist,
            revision,
            now,
        )
        await conn.execute(
            "INSERT INTO audio_attachments (id,user_id,client_entry_id,backend,storage_key,size_bytes,mime_type,duration_seconds,created_at,expires_at) VALUES ($1,$2,$3,'fs','synthetic-legacy.enc',48,'audio/m4a',10,$4,$4)",
            "6" * 32,
            patient,
            "legacy-entry",
            now,
        )
        audio_columns = "id,user_id,client_entry_id,backend,storage_key,size_bytes,mime_type,duration_seconds,created_at,expires_at"
        original_audio = tuple(
            await conn.fetchrow(f"SELECT {audio_columns} FROM audio_attachments")
        )
        await conn.execute("COMMIT")
    finally:
        await conn.close()
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=ROOT / "backend",
        env={**os.environ, "MINDPATTERN_DB_URL": url},
        check=True,
    )
    conn = await asyncpg.connect(wire)
    try:
        config = Config(str(ROOT / "backend/alembic.ini"))
        config.set_main_option("script_location", str(ROOT / "backend/alembic"))
        expected_head = ScriptDirectory.from_config(config).get_current_head()
        assert (
            await conn.fetchval("SELECT version_num FROM alembic_version")
            == expected_head
        )
        for table, expected, key, aad in (
            ("entries", entry, data_key, entry_aad),
            ("therapist_notes", note, notes_key, note_aad),
            ("therapist_note_revisions", revision, notes_key, note_aad),
        ):
            actual = await conn.fetchval(f"SELECT blob FROM {table}")
            assert actual == expected, f"{table}: ciphertext changed"
            assert crypto.decrypt(key, actual, aad).startswith(
                b'{"v":1,"text":"synthetic'
            )
        assert (
            await conn.fetchval(
                "SELECT count(*) FROM users WHERE custody_version=0 AND notes_keyring_blob IS NULL"
            )
            == 2
        )
        assert (
            await conn.fetchval("SELECT storage_locator FROM audio_attachments") is None
        )
        assert (
            tuple(await conn.fetchrow(f"SELECT {audio_columns} FROM audio_attachments"))
            == original_audio
        ), "legacy audio metadata changed"
        assert await conn.fetchval("SELECT count(*) FROM audio_deletions") == 0
        print(
            f"PASS: previous-head upgrade to {expected_head} preserves exact journal, current note, revision and audio metadata; ciphertext authenticates; custody defaults and deletion outbox are correct"
        )
    finally:
        await conn.close()


if __name__ == "__main__":
    asyncio.run(main())
