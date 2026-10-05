"""Real transaction and cryptographic boundaries from the October 4 audit."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.api import _audit
from app.deps import get_session
from app.models import AccessLog, new_id
from tests.helpers import ClientEmulator


@pytest.fixture(autouse=True)
def _authenticate_authorized_entry_fixture_inserts():
    """Exercise production writes without conftest's legacy-seed repair hook.

    Otherwise removing the API's seal call would still pass every guarded
    recompute regression because the ORM fixture silently signs its insert.
    The deliberate unsealed bootstrap rows in this module need no repair.
    """
    yield


@pytest.fixture
def settings(settings, tmp_path):
    settings.audit_journal_path = str(tmp_path / "committed-evidence.jsonl")
    return settings


async def _append(session, owner, action):
    return await _audit.append_access_log(
        session, actor_id=owner, actor_role="user", user_id=owner, action=action
    )


async def test_recovered_real_savepoint_conflict_publishes_committed_audit(
    client, app, settings, monkeypatch
):
    patient = ClientEmulator("audit-savepoint-retry", "synthetic password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        collision_id = await session.scalar(select(AccessLog.id))
    ids = iter((collision_id, new_id()))
    monkeypatch.setattr(_audit, "new_id", lambda: next(ids))
    async for session in get_session(SimpleNamespace(app=app)):
        row = await _append(session, patient.user_id, "after_real_constraint_retry")
        row_hash = row.entry_hash
        await session.commit()
    assert row_hash in Path(settings.audit_journal_path).read_text()
    async with app.state.sessionmaker() as session:
        assert await session.scalar(select(AccessLog.id).where(AccessLog.entry_hash == row_hash))


@pytest.mark.parametrize("rollback_kind", ["outer", "savepoint", "implicit_close"])
async def test_uncommitted_audit_tail_never_reaches_journal(client, app, settings, rollback_kind):
    patient = ClientEmulator("audit-rollback-" + rollback_kind, "synthetic password")
    await patient.register(client)
    before = Path(settings.audit_journal_path).read_text()
    async for session in get_session(SimpleNamespace(app=app)):
        if rollback_kind == "savepoint":
            with pytest.raises(RuntimeError, match="abort only the savepoint"):
                async with session.begin_nested():
                    await _append(session, patient.user_id, "uncommitted_nested")
                    raise RuntimeError("abort only the savepoint")
            await session.commit()
        else:
            await _append(session, patient.user_id, "uncommitted_outer")
            if rollback_kind == "outer":
                await session.rollback()
    assert Path(settings.audit_journal_path).read_text() == before


async def test_later_outer_rollback_preserves_earlier_committed_audit(client, app, settings):
    patient = ClientEmulator("audit-multiple-transactions", "synthetic password")
    await patient.register(client)
    async for session in get_session(SimpleNamespace(app=app)):
        committed = await _append(session, patient.user_id, "committed_prefix")
        committed_hash = committed.entry_hash
        await session.commit()
        abandoned = await _append(session, patient.user_id, "abandoned_suffix")
        abandoned_hash = abandoned.entry_hash
        await session.rollback()
    evidence = Path(settings.audit_journal_path).read_text()
    assert committed_hash in evidence
    assert abandoned_hash not in evidence


async def _recompute_response(client, patient):
    token = await patient.open_processing_session(client)
    return await client.post(
        "/api/insights/recompute", headers={**patient.headers, "X-Processing-Token": token}
    )


async def test_api_entry_write_seals_guard_without_fixture_repair(client, app, settings):
    from datetime import date

    from app.models import Entry
    from app.security.entry_guard import validate_entry_guard

    patient = ClientEmulator("api-entry-guard-seal", "synthetic password")
    await patient.register(client)
    await patient.create_entry(client, "calm home", date.today(), "entry", content_version=1)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        assert row is not None
        assert validate_entry_guard(row, settings) is False


@pytest.mark.parametrize("corrupt_state", [False, True])
async def test_authenticated_v2_observation_rejects_legacy_replay_even_after_amnesia(
    client, app, settings, corrupt_state
):
    import base64
    from datetime import date

    from sqlalchemy import update

    from app.models import Entry, Insight
    from app.security.entry_guard import validate_entry_guard

    settings.unlock_threshold_days = 1
    patient = ClientEmulator("guard-replay-" + str(corrupt_state), "synthetic password")
    await patient.register(client)
    legacy = await patient.create_entry(client, "old anxious work", date.today(), "entry")
    await patient.replace_entry(client, "entry", "new calm home", date.today(), content_version=2)
    first = await patient.recompute(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        assert validate_entry_guard(row, settings)
        row.blob = base64.b64decode(legacy["blob"])
        if corrupt_state:
            await session.execute(
                update(Insight)
                .where(Insight.user_id == patient.user_id, Insight.kind == "brain")
                .values(blob=b"corrupted state")
            )
        await session.commit()
    denied = await _recompute_response(client, patient)
    assert denied.status_code == 400 and denied.json()["code"] == "entry_blob_invalid", denied.text
    async with app.state.sessionmaker() as session:
        assert (
            await session.scalar(
                select(Insight.state_seq).where(
                    Insight.user_id == patient.user_id, Insight.kind == "patterns"
                )
            )
            == first["state_seq"]
        )


@pytest.mark.parametrize(
    "mutation", ["missing", "sticky_bit", "generation", "identity", "mac", "key_version"]
)
async def test_entry_guard_metadata_tamper_fails_closed(client, app, settings, mutation):
    from datetime import date

    from app.models import Entry

    settings.unlock_threshold_days = 1
    patient = ClientEmulator("guard-tamper-" + mutation, "synthetic password")
    await patient.register(client)
    await patient.create_entry(client, "calm home", date.today(), "entry", content_version=1)
    await patient.recompute(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        if mutation == "missing":
            row.aad_guard_mac = None
            row.aad_guard_key_version = None
            row.aad_guard_version = 0
        elif mutation == "sticky_bit":
            row.aad_guard_version = 0
        elif mutation == "generation":
            row.content_version += 1
        elif mutation == "identity":
            row.client_entry_id = "other"
        elif mutation == "mac":
            row.aad_guard_mac = "0" * 64
        else:
            row.aad_guard_key_version += 1
        await session.commit()
    denied = await _recompute_response(client, patient)
    assert denied.status_code == 400 and denied.json()["code"] == "entry_blob_invalid", denied.text


async def test_legacy_edits_remain_compatible_until_positive_v2_and_sticky_survives_edit(
    client, app, settings
):
    from datetime import date

    from app.models import Entry
    from app.security.entry_guard import validate_entry_guard

    settings.unlock_threshold_days = 1
    patient = ClientEmulator("guard-compatibility", "synthetic password")
    await patient.register(client)
    await patient.create_entry(client, "old calm home", date.today(), "entry")
    await patient.replace_entry(client, "entry", "legacy calm home", date.today())
    await patient.recompute(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        assert row.content_version == 2 and not validate_entry_guard(row, settings)
    await patient.replace_entry(
        client, "entry", "modern calm home", date.today(), content_version=3
    )
    await patient.recompute(client)
    await patient.replace_entry(
        client, "entry", "updated calm home", date.today(), content_version=4
    )
    await patient.recompute(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        assert row.content_version == 4 and validate_entry_guard(row, settings)


def test_guard_keyring_rotation_and_purpose_separation(settings):
    from app.models import Entry
    from app.security.crypto import TamperError
    from app.security.entry_guard import seal_entry_guard, validate_entry_guard

    original = SimpleNamespace(audit_mac_keyring={1: b"a" * 32}, audit_mac_key_version=1)
    rotated = SimpleNamespace(
        audit_mac_keyring={1: b"a" * 32, 2: b"b" * 32}, audit_mac_key_version=2
    )
    retired = SimpleNamespace(audit_mac_keyring={2: b"b" * 32}, audit_mac_key_version=2)
    row = Entry(user_id="owner", client_entry_id="entry", content_version=3, blob=b"opaque")
    seal_entry_guard(row, original, v2_bound=True)
    assert validate_entry_guard(row, rotated)
    with pytest.raises(TamperError):
        validate_entry_guard(row, retired)
    seal_entry_guard(row, rotated, v2_bound=True)
    assert row.aad_guard_key_version == 2 and validate_entry_guard(row, retired)
    row.aad_guard_mac = "ñ" * 64
    with pytest.raises(TamperError):
        validate_entry_guard(row, rotated)


async def test_one_time_explicit_bootstrap_preserves_ciphertext_and_never_repair_missing_guard(
    client, app, settings
):
    from datetime import date

    from app.models import Entry, EntryGuardBootstrap
    from app.security.crypto import TamperError
    from app.security.entry_guard import bootstrap_trusted_entries, validate_entry_guard

    patient = ClientEmulator("guard-bootstrap", "synthetic password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        row = Entry(
            user_id=patient.user_id,
            client_entry_id="legacy",
            content_version=7,
            blob=b"preserve exact opaque bytes",
            entry_date=date.today(),
        )
        row._skip_trusted_entry_fixture = True
        session.add(row)
        if await session.get(EntryGuardBootstrap, 1) is None:
            session.add(EntryGuardBootstrap(id=1))
        await session.commit()
        row_id = row.id
    assert await bootstrap_trusted_entries(app.state.sessionmaker, settings, batch_size=1) == 1
    async with app.state.sessionmaker() as session:
        row = await session.get(Entry, row_id)
        assert row.blob == b"preserve exact opaque bytes" and row.content_version == 7
        assert not validate_entry_guard(row, settings)
        row.aad_guard_mac = None
        await session.commit()
    with pytest.raises(RuntimeError, match="already complete"):
        await bootstrap_trusted_entries(app.state.sessionmaker, settings)
    async with app.state.sessionmaker() as session:
        row = await session.get(Entry, row_id)
        with pytest.raises(TamperError):
            validate_entry_guard(row, settings)


def test_rekey_requires_sticky_v2_and_upgrades_interrupted_new_key_legacy():
    from app.api.insights import _rekey_entry_batch, _RekeyMismatch
    from app.security import crypto

    old, new = bytearray(b"o" * 32), bytearray(b"n" * 32)
    legacy = crypto.encrypt(old, b"legacy", crypto.entry_aad_v1("owner", "entry"))
    with pytest.raises(_RekeyMismatch):
        _rekey_entry_batch(old, new, [("row", "entry", 2, legacy)], "owner", {"row": True})
    rewritten, resumed = _rekey_entry_batch(
        old, new, [("row", "entry", 2, legacy)], "owner", {"row": False}
    )
    assert (
        resumed == 0
        and crypto.decrypt(new, rewritten[0][1], crypto.entry_aad_v2("owner", "entry", 2))
        == b"legacy"
    )
    interrupted = crypto.encrypt(new, b"interrupted legacy", crypto.entry_aad_v1("owner", "entry"))
    rewritten, resumed = _rekey_entry_batch(
        old, new, [("row", "entry", 2, interrupted)], "owner", {"row": False}
    )
    assert (
        resumed == 0
        and crypto.decrypt(new, rewritten[0][1], crypto.entry_aad_v2("owner", "entry", 2))
        == b"interrupted legacy"
    )
    unchanged, resumed = _rekey_entry_batch(
        old, new, [("row", "entry", 2, rewritten[0][1])], "owner", {"row": True}
    )
    assert unchanged == [] and resumed == 1


async def test_real_rekey_upgrades_legacy_guard_and_preserves_boundary(client, app, settings):
    import base64
    from datetime import date

    from app.models import Entry
    from app.security import crypto
    from app.security.entry_guard import validate_entry_guard

    settings.unlock_threshold_days = 1
    patient = ClientEmulator("guard-real-rekey", "old synthetic password")
    await patient.register(client)
    legacy = await patient.create_entry(client, "legacy calm home", date.today(), "entry")
    old_key, old_verifier = patient.data_key, patient.auth_key_b64
    patient.derive_new_generation("new synthetic password")
    await patient.rekey(client, old_key, patient.data_key, verifier=old_verifier)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        assert validate_entry_guard(row, settings)
        assert crypto.decrypt(
            patient.data_key, bytes(row.blob), crypto.entry_aad_v2(patient.user_id, "entry", 1)
        )
        row.blob = base64.b64decode(legacy["blob"])
        await session.commit()
    denied = await _recompute_response(client, patient)
    assert denied.status_code == 400 and denied.json()["code"] == "entry_blob_invalid"


async def test_bootstrap_refuses_missing_marker_and_partial_invalid_guard(client, app, settings):
    from datetime import date

    from app.models import Entry, EntryGuardBootstrap
    from app.security.crypto import TamperError
    from app.security.entry_guard import bootstrap_trusted_entries

    async with app.state.sessionmaker() as session:
        marker = await session.get(EntryGuardBootstrap, 1)
        if marker is not None:
            await session.delete(marker)
            await session.commit()
    with pytest.raises(RuntimeError, match="unavailable"):
        await bootstrap_trusted_entries(app.state.sessionmaker, settings)
    patient = ClientEmulator("guard-invalid-bootstrap", "synthetic password")
    await patient.register(client)
    async with app.state.sessionmaker() as session:
        row = Entry(
            user_id=patient.user_id,
            client_entry_id="legacy",
            content_version=1,
            blob=b"opaque",
            entry_date=date.today(),
            aad_guard_mac="0" * 64,
            aad_guard_key_version=1,
        )
        row._skip_trusted_entry_fixture = True
        session.add_all([row, EntryGuardBootstrap(id=1)])
        await session.commit()
    with pytest.raises(TamperError):
        await bootstrap_trusted_entries(app.state.sessionmaker, settings)
    async with app.state.sessionmaker() as session:
        assert (await session.get(EntryGuardBootstrap, 1)).completed_at is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("content_version", None),
        ("content_version", "2"),
        ("content_version", True),
        ("content_version", 0),
        ("content_version", 2**63),
        ("aad_guard_version", None),
        ("aad_guard_version", True),
        ("aad_guard_key_version", []),
        ("blob", None),
        ("id", None),
    ],
)
def test_malformed_guard_metadata_always_fails_with_tamper_error(settings, field, value):
    from app.models import Entry
    from app.security.crypto import TamperError
    from app.security.entry_guard import seal_entry_guard, validate_entry_guard

    row = Entry(user_id="owner", client_entry_id="entry", content_version=1, blob=b"opaque")
    seal_entry_guard(row, settings, v2_bound=False)
    setattr(row, field, value)
    with pytest.raises(TamperError):
        validate_entry_guard(row, settings)


async def test_old_valid_unknown_guard_cannot_mix_with_unassociated_legacy_ciphertext(
    client, app, settings
):
    import base64
    from datetime import date

    from app.models import Entry
    from app.security.entry_guard import guard_values

    settings.unlock_threshold_days = 1
    patient = ClientEmulator("guard-history-mix", "synthetic password")
    await patient.register(client)
    legacy = await patient.create_entry(client, "old legacy calm", date.today(), "entry")
    await patient.replace_entry(
        client, "entry", "modern calm home", date.today(), content_version=2
    )
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        unknown_guard = guard_values(row)
    await patient.recompute(client)
    async with app.state.sessionmaker() as session:
        row = await session.scalar(select(Entry).where(Entry.user_id == patient.user_id))
        row.blob = base64.b64decode(legacy["blob"])
        for field, value in unknown_guard.items():
            setattr(row, field, value)
        await session.commit()
    denied = await _recompute_response(client, patient)
    assert denied.status_code == 400 and denied.json()["code"] == "entry_blob_invalid"


@pytest.mark.parametrize("bootstrap", [False, True])
def test_packaged_entrypoint_requires_explicit_trusted_bootstrap_flag(tmp_path, bootstrap):
    """Exercise shell dispatch: normal boot must never adopt historical rows."""
    import os
    import subprocess

    commands = tmp_path / "commands"
    commands.mkdir()
    log = tmp_path / "dispatch.log"
    for command in ("alembic", "python", "uvicorn"):
        script = commands / command
        script.write_text(f'#!/bin/sh\nprintf "%s\\n" "{command} $*" >> "$BOOTSTRAP_CALL_LOG"\n')
        script.chmod(0o700)
    environment = {
        **os.environ,
        "PATH": str(commands) + os.pathsep + os.environ["PATH"],
        "BOOTSTRAP_CALL_LOG": str(log),
        "MINDPATTERN_DB_URL": "sqlite+aiosqlite://",
    }
    entrypoint = Path(__file__).resolve().parents[1] / "docker-entrypoint.sh"
    command = ["/bin/sh", str(entrypoint)] + (["--trusted-entry-bootstrap"] if bootstrap else [])
    subprocess.run(command, env=environment, check=True, timeout=10)
    calls = log.read_text().splitlines()
    assert calls[0] == "alembic upgrade head"
    assert len(calls) == 2
    if bootstrap:
        assert calls[1] == "python bootstrap_entry_guards.py --trusted-bootstrap"
    else:
        assert calls[1].startswith("uvicorn app.main:app ")
        assert "--no-proxy-headers" in calls[1]
