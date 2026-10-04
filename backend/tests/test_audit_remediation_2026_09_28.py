"""2026-09-28 audit remediation pins (docs/archive/audits/AUDIT_SESSIONS_2026-09-28.md).

Behavioral coverage for the fixes from the deep audit of the last two
sessions:

  * H-1 — rekey resume RE-WALKS every stage: rows written under the old
           key after an interrupted run are rekeyed (the old stage-skip
           silently finalized over them), stale journals cannot short-
           circuit a fresh rotation, and the response counts describe
           the current run only.
  * M-1 — PUT /account/password requires the processing-session
           possession probe on EVERY key scheme (v2→v2 included): a
           bearer + verifier alone can no longer overwrite the envelope.
  * L-1 — token-revocation hydration marks the cache overflowed when the
           durable table exceeds the cap (the point-query fallback must
           engage at boot, not only after a runtime eviction).
  * M-5 — audit-journal single-pass heads + retention-aligned
           compaction.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import date, datetime, timedelta, timezone

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.api import insights as insights_module
from app.config import Settings
from app.main import create_app
from app.models import AuditChainState, Measure, RekeyJournal, new_id, utcnow
from app.security import crypto
from tests.helpers import ClientEmulator

TODAY = datetime.now(timezone.utc).date()


async def _make_client() -> AsyncClient:
    settings = Settings(environment="development")
    settings.database_url = "sqlite+aiosqlite://"
    settings.token_secret = "test-secret-not-for-production"
    settings.unlock_threshold_days = 1
    settings.ops_rate_limit = 240
    settings.ops_rate_window = 60
    app = create_app(settings)
    transport = ASGITransport(app=app)
    lifespan_cm = app.router.lifespan_context(app)
    await lifespan_cm.__aenter__()

    class _Wrapped(AsyncClient):
        async def aclose(self) -> None:
            await super().aclose()
            await lifespan_cm.__aexit__(None, None, None)

    return _Wrapped(transport=transport, base_url="http://test")


def _decrypt_entry_with(
    key: bytes, user_id: str, blob_b64: str, client_entry_id: str, content_version: int
) -> dict:
    blob = base64.b64decode(blob_b64)
    failure: Exception | None = None
    for aad in crypto.entry_aad_candidates(user_id, client_entry_id, content_version):
        try:
            return json.loads(crypto.decrypt(key, blob, aad).decode("utf-8"))
        except crypto.TamperError as exc:
            failure = exc
    assert failure is not None
    raise failure


async def _seed_journal(app, user_id: str, **values) -> None:
    """Insert a RekeyJournal row simulating an interrupted rotation."""
    defaults = {
        "stage": "measures",
        "entry_cursor": None,
        "measure_cursor": None,
        "entries_done": 0,
        "insights_done": 0,
        "measures_done": 0,
    }
    defaults.update(values)
    async with app.state.sessionmaker() as session:
        session.add(RekeyJournal(user_id=user_id, **defaults))
        await session.commit()


# ---------------------------------------------------------------------------
# H-1: rekey resume re-walks every stage
# ---------------------------------------------------------------------------


async def test_rekey_resume_rekeys_rows_written_after_the_interrupted_run():
    """The exact data-loss path from the audit: a journal left at
    stage="measures" by a crashed run, further OLD-key entries written in
    the window, then a retry. The old stage-skip never walked those rows
    and finalized 'successfully' over undecryptable blobs; the retry must
    rekey every one of them."""
    http = await _make_client()
    try:
        emu = ClientEmulator("resume1", "pw-resume-one-1")
        await emu.register(client=http)
        await emu.create_entry(http, "before the crash", TODAY, "e-r1")
        await emu.create_entry(http, "also before", TODAY, "e-r2")

        # The interrupted run's journal: entries "finished", crashed while
        # walking measures (none exist). Cursor names the LAST pre-crash
        # entry id — the post-crash write lands AFTER it in insertion order
        # but at an unpredictable position in the random-hex id sort.
        async with http._transport.app.state.sessionmaker() as session:  # noqa: SLF001
            last_entry_id = (
                await session.execute(
                    select(insights_module.Entry.id)
                    .where(insights_module.Entry.user_id == emu.user_id)
                    .order_by(insights_module.Entry.id.desc())
                    .limit(1)
                )
            ).scalar_one()
        await _seed_journal(
            http._transport.app,  # noqa: SLF001
            emu.user_id,
            stage="measures",
            entry_cursor=last_entry_id,
            entries_done=2,
        )

        # Post-crash write under the OLD key: the rotation never completed,
        # so the client is still journaling under the current data key.
        response = await http.post(
            "/api/entries",
            headers=emu.headers,
            json={
                "client_entry_id": "e-r3",
                "entry_date": TODAY.isoformat(),
                "blob": emu.encrypt_entry("written after the crash", TODAY, "e-r3"),
            },
        )
        assert response.status_code == 409 and response.json()["code"] == "rekey_in_progress"
        # Recreate a genuine historical legacy write directly: upgraded API
        # admission now fences it, but existing installations still need repair.
        async with http._transport.app.state.sessionmaker() as session:
            session.add(
                insights_module.Entry(
                    user_id=emu.user_id,
                    client_entry_id="e-r3",
                    entry_date=TODAY,
                    blob=base64.b64decode(
                        emu.encrypt_entry("written after the crash", TODAY, "e-r3")
                    ),
                )
            )
            await session.commit()

        new_key = crypto.generate_key()
        counts = await emu.rekey(http, old_key=emu.data_key, new_key=new_key)

        # Every entry — including the post-crash one — is under the new key.
        assert counts["entries"] == 3, counts
        for cid in ("e-r1", "e-r2", "e-r3"):
            row = await emu.get_entry(http, cid)
            plain = _decrypt_entry_with(
                new_key, emu.user_id, row["blob"], cid, row["content_version"]
            )
            assert plain["text"]
        # And the journal is retired (finalize ran).
        async with http._transport.app.state.sessionmaker() as session:  # noqa: SLF001
            rows = (
                (
                    await session.execute(
                        select(RekeyJournal).where(RekeyJournal.user_id == emu.user_id)
                    )
                )
                .scalars()
                .all()
            )
        assert rows == []
    finally:
        await http.aclose()


async def test_rekey_stale_journal_cannot_shortcircuit_a_fresh_rotation():
    """A journal abandoned by an old rotation (different new key) must not
    let a fresh rotation skip the corpus. Entries-only account: the fresh
    run re-walks everything and succeeds; the stale counters in the
    journal are ignored, and the response reports THIS run's counts."""
    http = await _make_client()
    try:
        emu = ClientEmulator("stale1", "pw-stale-journal-1")
        await emu.register(client=http)
        await emu.create_entry(http, "stale journal corpus a", TODAY, "e-s1")
        await emu.create_entry(http, "stale journal corpus b", TODAY, "e-s2")

        # An abandoned A→B rotation: claims both earlier stages complete
        # with inflated stale counters.
        await _seed_journal(
            http._transport.app,  # noqa: SLF001
            emu.user_id,
            stage="measures",
            entries_done=99,
            insights_done=99,
            measures_done=99,
        )

        fresh_key = crypto.generate_key()
        counts = await emu.rekey(http, old_key=emu.data_key, new_key=fresh_key)
        assert counts["entries"] == 2, counts
        assert counts["insights"] == 0, counts  # stale 99 NOT echoed back
        assert counts["measures"] == 0, counts
        row = await emu.get_entry(http, "e-s1")
        plain = _decrypt_entry_with(
            fresh_key, emu.user_id, row["blob"], "e-s1", row["content_version"]
        )
        assert plain["text"] == "stale journal corpus a"
    finally:
        await http.aclose()


async def test_rekey_resume_counts_already_new_measures_without_mismatch():
    """A genuinely interrupted run that committed a measures batch under
    the new key: the retry re-walks, authenticates those rows under the
    NEW key (counted, not re-encrypted, no rekey_key_mismatch), and still
    re-walks entries from scratch."""
    http = await _make_client()
    try:
        emu = ClientEmulator("measrs", "pw-measure-resume-1")
        await emu.register(client=http)
        await emu.create_entry(http, "entry before the crash", TODAY, "e-m1")

        app = http._transport.app  # noqa: SLF001
        new_key = crypto.generate_key()
        # The interrupted run committed ONE measure batch under the new key
        # before dying: seed the row exactly as that run left it.
        seeded_aad = crypto.build_aad("measure", emu.user_id, "m-seeded-1")
        seeded_blob = crypto.encrypt(
            new_key, json.dumps({"v": 1, "score": 3}).encode("utf-8"), seeded_aad
        )
        async with app.state.sessionmaker() as session:
            session.add(
                Measure(
                    user_id=emu.user_id,
                    client_measure_id="m-seeded-1",
                    blob=seeded_blob,
                    measure_date=TODAY,
                )
            )
            await session.commit()
            seeded_id = (
                await session.execute(
                    select(Measure.id).where(Measure.user_id == emu.user_id).limit(1)
                )
            ).scalar_one()
        await _seed_journal(
            app, emu.user_id, stage="measures", measure_cursor=seeded_id, measures_done=1
        )

        counts = await emu.rekey(http, old_key=emu.data_key, new_key=new_key)
        assert counts["entries"] == 1, counts
        assert counts["measures"] == 1, counts  # the already-new row counted
    finally:
        await http.aclose()


# ---------------------------------------------------------------------------
# L-1: hydration truncation engages the point-query fallback
# ---------------------------------------------------------------------------


@pytest.fixture
async def chain_sessionmaker():
    """A standalone engine (the app fixture's single shared connection
    races the background sweep; these unit tests need no app)."""
    from app.db import build_engine, build_sessionmaker
    from app.models import Base

    engine = build_engine("sqlite+aiosqlite://")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield build_sessionmaker(engine)
    await engine.dispose()


async def test_hydration_truncation_marks_the_cache_overflowed(chain_sessionmaker):
    """A durable table larger than the cap truncates the boot hydration
    (newest-expiry-first). Without the overflow flag the loaded map is
    treated as a complete mirror and a truncated revocation is honored as
    "not revoked" until its own exp — the exact resurrection the durable
    store exists to prevent."""
    from app.cache import TokenRevocationStore
    from app.models import TokenRevocation as RevocationRow

    store = TokenRevocationStore(max_entries=2)
    async with chain_sessionmaker() as session:
        for i in range(3):
            # Distinct expiries: row 0 (soonest) is the one hydration drops.
            session.add(
                RevocationRow(
                    jti=f"trunc{i:029d}",
                    expires_at=datetime.now(timezone.utc) + timedelta(hours=i + 1),
                )
            )
        await session.commit()
        loaded = await store.hydrate(session)
        assert loaded == 2
        assert store._overflowed is True  # noqa: SLF001 — the pin IS the flag
        # The truncated (oldest-expiry) revocation still answers revoked via
        # the durable point query, not the incomplete memory mirror.
        assert await store.is_revoked_checked(session, "trunc" + "0" * 29)


# ---------------------------------------------------------------------------
# M-5: journal single-pass heads + retention-aligned compaction
# ---------------------------------------------------------------------------


def test_journal_heads_map_matches_the_per_user_read(tmp_path):
    from app.api._audit import read_journal_head, read_journal_heads

    user_a = "1" * 32
    user_b = "2" * 32
    user_c = "3" * 32
    journal = tmp_path / "journal.log"
    journal.write_text(
        f"{user_a} 1 " + "a" * 64 + " - 2026-09-20T00:00:00+00:00\n"
        f"{user_a} 2 " + "b" * 64 + " - 2026-09-21T00:00:00+00:00\n"
        f"{user_b} 7 " + "c" * 64 + " - 2026-09-22T00:00:00+00:00\n"
        "garbage line\n"
        f"{user_a} notanumber " + "d" * 64 + " - 2026-09-23T00:00:00+00:00\n",
        encoding="utf-8",
    )
    heads = read_journal_heads(str(journal))
    assert heads == {
        user_a: (2, "2026-09-21T00:00:00+00:00"),
        user_b: (7, "2026-09-22T00:00:00+00:00"),
    }
    assert read_journal_head(str(journal), user_a) == (2, "2026-09-21T00:00:00+00:00")
    assert read_journal_head(str(journal), user_b) == (7, "2026-09-22T00:00:00+00:00")
    assert read_journal_head(str(journal), user_c) is None


def test_journal_compaction_drops_only_pre_cutoff_lines(tmp_path):
    from app.api._audit import compact_audit_journal

    user_a = "1" * 32
    user_b = "2" * 32
    journal = tmp_path / "journal.log"
    journal.write_text(
        f"{user_a} 1 " + "a" * 64 + " - 2026-08-01T00:00:00+00:00\n"
        f"{user_a} 2 " + "b" * 64 + " - 2026-09-21T00:00:00+00:00\n"
        f"{user_b} 7 " + "c" * 64 + " - 2026-09-22T00:00:00+00:00\n",
        encoding="utf-8",
    )
    kept, dropped = compact_audit_journal(str(journal), "2026-09-01T00:00:00+00:00")
    assert (kept, dropped) == (2, 1)
    assert "2026-08-01" not in journal.read_text(encoding="utf-8")
    # No temp litter: compaction replaced the file atomically.
    assert list(tmp_path.iterdir()) == [journal]
    # Compacting an already-compact journal is a no-op.
    assert compact_audit_journal(str(journal), "2026-09-01T00:00:00+00:00") == (2, 0)


async def test_sweep_verifies_with_the_heads_map_and_compacts(client, app, monkeypatch, tmp_path):
    """The sweep reuses one index and compacts superseded journal lines."""
    from app import main as main_mod
    from app.api import _audit as audit_module

    journal_owner = "f" * 32
    old_line = f"{journal_owner} 1 {'a' * 64} {'b' * 64} 2020-01-01T00:00:00+00:00\n"
    newest_line = f"{journal_owner} 2 {'c' * 64} {'d' * 64} 2020-01-02T00:00:00+00:00\n"
    journal = tmp_path / "journal.log"
    journal.write_text(old_line + newest_line)
    app.state.settings.audit_journal_path = str(journal)

    # One authenticated state owner makes the sweep exercise verification.
    # Seed the state directly: append_access_log uses a nested savepoint for
    # real cross-process collision recovery, which is incompatible with the
    # in-memory SQLite fixture's one shared connection while lifespan tasks
    # are active.
    async with app.state.sessionmaker() as session:
        state = AuditChainState(
            user_id=new_id(),
            head_seq=1,
            head_hash="e" * 64,
            head_at=utcnow(),
            first_retained_seq=None,
            first_retained_hash=None,
            state_version=1,
            mac_key_version=app.state.settings.audit_mac_key_version,
            updated_at=utcnow(),
        )
        state.state_mac = audit_module.compute_chain_state_mac(
            app.state.settings.audit_mac_keyring[state.mac_key_version], state
        )
        session.add(state)
        await session.commit()

    seen: dict[str, object] = {}

    async def spy(_session, cursor, user_id, **kwargs):
        from app.api._audit import IncrementalChainVerification, seal_verification_checkpoint

        seen.update(kwargs)
        cursor.last_user_id = user_id
        cursor.verification_owner_id = None
        cursor.verification_snapshot_head_seq = None
        cursor.verification_snapshot_head_hash = None
        cursor.verification_next_seq = None
        cursor.verification_previous_hash = None
        cursor.verification_rows_checked = 0
        seal_verification_checkpoint(
            cursor,
            kwargs["mac_keys"],
            kwargs["current_mac_key_version"],
        )
        return IncrementalChainVerification(ok=True, complete=True, rows_checked=0)

    monkeypatch.setattr(audit_module, "verify_access_log_chain_incremental", spy)
    await main_mod._prune_access_log_once(app)
    assert isinstance(seen.get("journal_evidence"), audit_module.JournalEvidenceIndex)
    # Compaction retains the newest external anchor per owner while dropping
    # its superseded pre-cutoff evidence.
    assert journal.read_text(encoding="utf-8") == newest_line
