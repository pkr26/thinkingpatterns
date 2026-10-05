"""Real connection-capacity oracle for queued private-history reads."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import _audit, therapist
from app.locks import sharing_locks, sharing_patient_lock_key
from app.models import Base, TherapistNote, TherapistNoteRevision, User


async def test_waiting_note_history_does_not_starve_patient_fence_owner(tmp_path, monkeypatch):
    # Use independent real connections with the smallest supported production
    # pool capacity. The SQLite driver is only the SQL transport here; this
    # exercises the same SQLAlchemy checkout/return behavior as asyncpg.
    engine = create_async_engine(
        f"sqlite+aiosqlite:///{tmp_path / 'bounded-history-pool.sqlite'}",
        pool_size=2,
        max_overflow=0,
        pool_timeout=0.25,
    )
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tasks = []
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        async with sessions() as session:
            patient = User(
                username="pool-patient", salt="salt", verifier=b"verifier", scrypt_salt=b"salt"
            )
            clinicians = [
                User(
                    username=f"pool-clinician-{i}",
                    role="therapist",
                    salt="salt",
                    verifier=b"verifier",
                    scrypt_salt=b"salt",
                )
                for i in range(2)
            ]
            session.add_all([patient, *clinicians])
            await session.flush()
            for registered in [patient, *clinicians]:
                await _audit.append_access_log(
                    session,
                    actor_id=registered.id,
                    actor_role=registered.role,
                    user_id=registered.id,
                    action="registered",
                    allow_new_chain=True,
                )
            notes = [
                TherapistNote(
                    therapist_id=clinician.id,
                    user_id=patient.id,
                    client_note_id="pool-note",
                    blob=b"current opaque blob",
                )
                for clinician in clinicians
            ]
            session.add_all(notes)
            await session.flush()
            session.add_all(
                [
                    TherapistNoteRevision(
                        note_id=note.id, therapist_id=clinician.id, blob=b"prior opaque blob"
                    )
                    for clinician, note in zip(clinicians, notes)
                ]
            )
            await session.commit()

        patient_key = sharing_patient_lock_key(patient.id)
        original_hold = sharing_locks.hold
        waiting = asyncio.Event()
        entered = 0

        @asynccontextmanager
        async def observed_hold(key):
            nonlocal entered
            if key == patient_key and asyncio.current_task().get_name().startswith("pool-history-"):
                entered += 1
                if entered == 2:
                    waiting.set()
            async with original_hold(key) as lock:
                yield lock

        async def history(clinician, note):
            async with sessions() as session:
                return await therapist.read_note_revisions(
                    note.id,
                    Response(),
                    user=clinician,
                    session=session,
                    offset=0,
                    limit=50,
                    page_bytes=None,
                    expected_revision=None,
                )

        # Deletion/purge and patient corpus rekey retain this fence while
        # opening new short DB transactions. Queued reads must return their
        # connections before waiting, so the fence owner can make progress.
        async with original_hold(patient_key):
            monkeypatch.setattr(sharing_locks, "hold", observed_hold)
            tasks = [
                asyncio.create_task(history(clinician, note), name=f"pool-history-{i}")
                for i, (clinician, note) in enumerate(zip(clinicians, notes))
            ]
            await asyncio.wait_for(waiting.wait(), timeout=5)
            async with sessions() as owner:
                assert (
                    await owner.scalar(select(User.id).where(User.id == patient.id)) == patient.id
                )

        pages = await asyncio.gather(*tasks)
        assert all(len(page) == 1 for page in pages)
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()
