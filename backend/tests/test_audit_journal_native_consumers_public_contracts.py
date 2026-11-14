"""Native authenticated journal producers and their real maintenance consumers."""

import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app import main
from app.api import _audit
from app.config import Settings
from app.db import build_engine, build_sessionmaker, init_models
from app.models import AccessLog, User
from app.security import crypto
from tests.helpers import ClientEmulator


@pytest.fixture
def settings(tmp_path):
    journal = tmp_path / "owned-audit.journal"
    journal.touch(mode=0o600)
    return Settings(
        environment="development",
        database_url="sqlite+aiosqlite://",
        audit_journal_path=str(journal),
    )


async def owner_and_head(client, app, name):
    owner = ClientEmulator(name, "native-audit-journal-password")
    await owner.register(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(
            select(AccessLog)
            .where(AccessLog.user_id == owner.user_id)
            .order_by(AccessLog.chain_seq.desc())
        )
        expected = (row.chain_seq, row.entry_hash, row.entry_mac)
    return owner, expected


@pytest.mark.asyncio
async def test_authenticated_registration_publishes_its_actual_native_audit_seal(client, app):
    owner, expected = await owner_and_head(client, app, "native-journal-publication")
    journal = Path(app.state.settings.audit_journal_path)
    evidence = _audit.read_journal_evidence(str(journal))
    kept = evidence[owner.user_id]
    assert (kept.seq, kept.entry_hash, kept.entry_mac) == expected
    assert kept.conflict is False
    assert expected[0] == 1 and len(expected[1]) == len(expected[2]) == 64


@pytest.mark.asyncio
async def test_actual_healthy_journal_maintenance_preserves_public_readiness(client, app):
    await owner_and_head(client, app, "native-journal-maintenance")
    await main._prune_access_log_once(app)
    ready = await client.get("/readyz")
    assert ready.status_code == 200, ready.text


@pytest.mark.asyncio
async def test_active_native_index_reads_two_application_commits_without_losing_custody(
    client, app
):
    owner, initial = await owner_and_head(client, app, "native-journal-active-index")
    today = datetime.now(timezone.utc).date()
    measure_ids = ["journal-measure-one", "journal-measure-two"]
    for measure_id in measure_ids:
        plaintext = json.dumps({"v": 1, "measure": "phq9", "score": 4}).encode("utf-8")
        blob = crypto.encrypt(
            owner.data_key, plaintext, crypto.build_aad("measure", owner.user_id, measure_id)
        )
        created = await client.post(
            "/api/measures",
            headers=owner.headers,
            json={
                "client_measure_id": measure_id,
                "blob": base64.b64encode(blob).decode("ascii"),
                "measure_date": today.isoformat(),
            },
        )
        assert created.status_code == 201, created.text
    index = _audit.reusable_journal_evidence_index(app.state.settings.audit_journal_path)
    owned_index_path = Path(index.path)
    try:
        # Measure deletion explicitly appends action=delete_measure to the
        # authenticated chain. Entry creation does not append an audit row.
        # Retain the real maintenance index across two actual audited commits.
        for number, measure_id in enumerate(measure_ids, start=1):
            deleted = await client.delete(
                f"/api/measures/{measure_id}",
                headers={**owner.headers, "X-Account-Verifier": owner.auth_key_b64},
            )
            assert deleted.status_code == 200, deleted.text
            async with app.state.sessionmaker() as session:
                row = await session.scalar(
                    select(AccessLog)
                    .where(AccessLog.user_id == owner.user_id)
                    .order_by(AccessLog.chain_seq.desc())
                )
                expected = (row.chain_seq, row.entry_hash, row.entry_mac)
                assert row.action == "delete_measure"
                assert row.chain_seq == initial[0] + number
                assert len(row.entry_hash) == len(row.entry_mac) == 64
            kept = index.get(owner.user_id)
            assert (kept.seq, kept.entry_hash, kept.entry_mac) == expected
            assert kept.conflict is False
    finally:
        _audit.close_reusable_journal_evidence_index()
        index.close()
        # A broken index implementation may recreate its own unlinked SQLite
        # file while reading. Clean only the exact path returned to this test.
        owned_index_path.unlink(missing_ok=True)


@pytest.mark.asyncio
async def test_real_external_journal_corruption_is_detected_by_maintenance(client, app):
    await owner_and_head(client, app, "native-journal-generation")
    journal = Path(app.state.settings.audit_journal_path)
    _audit.reusable_journal_evidence_index(str(journal))
    with journal.open("a", encoding="utf-8") as stream:
        stream.write("malformed externally appended evidence\n")
    with pytest.raises(RuntimeError, match="audit journal evidence is unavailable or malformed"):
        await main._prune_access_log_once(app)
    refused = await client.get("/readyz")
    assert refused.status_code == 503, refused.text


@pytest.mark.asyncio
async def test_documented_link_only_legacy_append_publishes_its_native_seal(tmp_path):
    # append_access_log explicitly preserves its link-only legacy seeding
    # API with an explicitly empty key ring. Exercise that declared library domain.
    engine = build_engine("sqlite+aiosqlite://")
    journal = tmp_path / "owned-legacy.journal"
    try:
        await init_models(engine)
        sessions = build_sessionmaker(engine)
        async with sessions() as session:
            owner_id = "d" * 32
            session.add(
                User(
                    id=owner_id,
                    username="native-legacy-journal",
                    salt="legacy-fixture-salt",
                    verifier=b"v" * 32,
                    scrypt_salt=b"s" * 16,
                )
            )
            await session.flush()
            row = await _audit.append_access_log(
                session,
                actor_id=owner_id,
                actor_role="user",
                user_id=owner_id,
                action="legacy_import",
                mac_keys={},
                allow_new_chain=True,
            )
            expected_hash = row.entry_hash
            assert row.entry_mac is None
            await session.commit()
            assert await _audit.flush_audit_journal(session, str(journal)) == 1
        kept = _audit.read_journal_evidence(str(journal))[owner_id]
        assert (kept.seq, kept.entry_hash, kept.entry_mac) == (1, expected_hash, "-")
        assert kept.conflict is False
    finally:
        _audit.close_reusable_journal_evidence_index()
        await engine.dispose()
