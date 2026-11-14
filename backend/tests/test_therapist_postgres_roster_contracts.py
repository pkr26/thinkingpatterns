"""Opt-in roster paging against the dedicated local PostgreSQL test profile.

Set MINDPATTERN_MUTATION_POSTGRES and the absolute
MINDPATTERN_MUTATION_POSTGRES_SCHEMA_LOCK path to the shared schema-profile
flock. Each test owns a temporary schema; application/public tables are untouched.
"""

from __future__ import annotations

import fcntl
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import Response
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import therapist
from app.api._audit import append_access_log
from app.config import Settings
from app.deps import ApiError
from app.models import Base, Consent, User
from app.services.account_deletion import stage_account_deletion


@pytest.fixture
def postgres_roster_profile():
    url = os.environ.get("MINDPATTERN_MUTATION_POSTGRES")
    lock_name = os.environ.get("MINDPATTERN_MUTATION_POSTGRES_SCHEMA_LOCK")
    if not url or not lock_name:
        pytest.skip("opt in with the dedicated PostgreSQL URL and shared schema flock")
    parsed = make_url(url)
    assert (
        parsed.drivername,
        parsed.host,
        parsed.port,
        parsed.database,
    ) == ("postgresql+asyncpg", "127.0.0.1", 55488, "mindpattern_mutation_test")
    assert not parsed.query
    lock_path = Path(lock_name)
    assert lock_path.is_absolute() and lock_path.is_file()
    with lock_path.open("a") as resource:
        fcntl.flock(resource, fcntl.LOCK_EX)
        yield url


@pytest.mark.asyncio
async def test_roster_reports_collection_changed_after_two_accounts_retire(
    postgres_roster_profile, monkeypatch
):
    """Two retirements outside this page must produce the paging conflict.

    Logical account deletion commits before its bounded physical purge, so
    multiple inactive accounts can still have retained consent rows. Retire
    those accounts after the first roster probe, at a real audit await, and
    let the route execute its final native PostgreSQL query unchanged.
    """
    url = postgres_roster_profile
    schema = "roster_retirement_" + uuid.uuid4().hex
    admin = create_async_engine(url)
    engine = create_async_engine(url, connect_args={"server_settings": {"search_path": schema}})
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        clinician_id = "a" * 32
        patient_ids = [f"{i:032x}" for i in range(1, 4)]
        now = datetime(2026, 10, 21, tzinfo=timezone.utc)
        async with sessions() as session:
            session.add(
                User(
                    id=clinician_id,
                    username="roster-clinician",
                    role="therapist",
                    salt="salt",
                    verifier=b"v" * 32,
                    scrypt_salt=b"s" * 16,
                )
            )
            session.add_all(
                User(
                    id=owner,
                    username=f"roster-patient-{i}",
                    salt="salt",
                    verifier=b"v" * 32,
                    scrypt_salt=b"s" * 16,
                )
                for i, owner in enumerate(patient_ids)
            )
            await session.flush()
            session.add_all(
                Consent(
                    id=f"{i + 20:032x}",
                    therapist_id=clinician_id,
                    user_id=owner,
                    status="revoked",
                    granted_at=now - timedelta(days=i),
                    revoked_at=now,
                )
                for i, owner in enumerate(patient_ids)
            )
            for owner in patient_ids:
                await append_access_log(
                    session,
                    actor_id=owner,
                    actor_role="user",
                    user_id=owner,
                    action="account_created",
                    allow_new_chain=True,
                )
            await session.commit()

        original_audit = therapist._audit
        retired = []

        async def retire_after_real_audit(session, actor, owner, action):
            await original_audit(session, actor, owner, action)
            assert owner == patient_ids[0] and action == "list_patients"
            if retired:
                return
            async with sessions() as retirement_session:
                for patient_id in patient_ids[1:]:
                    patient = await retirement_session.get(User, patient_id)
                    stage_account_deletion(retirement_session, patient)
                    retired.append(patient_id)
                await retirement_session.commit()

        monkeypatch.setattr(therapist, "_audit", retire_after_real_audit)
        request = SimpleNamespace(
            app=SimpleNamespace(state=SimpleNamespace(settings=Settings(environment="development")))
        )
        async with sessions() as session:
            clinician = await session.get(User, clinician_id)
            with pytest.raises(ApiError) as refusal:
                await therapist.list_patients(request, Response(), clinician, session, 1, 0, "0")
            assert (refusal.value.status_code, refusal.value.code) == (409, "collection_changed")
            await session.rollback()
        async with sessions() as session:
            inactive = list(
                (await session.scalars(select(User.id).where(User.is_active.is_(False)))).all()
            )
            assert set(inactive) == set(retired) == set(patient_ids[1:])
    finally:
        await engine.dispose()
        try:
            async with admin.begin() as connection:
                await connection.execute(text(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE'))
        finally:
            await admin.dispose()
