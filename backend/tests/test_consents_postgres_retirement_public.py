"""Consent paging conflict when two therapists retire during a PostgreSQL read.

This opt-in test uses the dedicated mutation PostgreSQL profile and a unique
temporary schema. It does not use the shared public schema or SQLite.
"""

from __future__ import annotations

import fcntl
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi import Depends
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import Settings
from app.deps import get_session, require_regular_user
from app.main import create_app
from app.models import Base, Consent, User
from app.services.account_deletion import stage_account_deletion


@pytest.fixture(autouse=True)
def _shared_test_db_cleanup():
    """This module owns its temporary schema, never the general test database."""
    yield


@pytest.fixture
def owned_postgres_profile():
    url = os.environ.get("MINDPATTERN_MUTATION_POSTGRES")
    lock_name = os.environ.get("MINDPATTERN_MUTATION_POSTGRES_SCHEMA_LOCK")
    if not url or not lock_name:
        pytest.skip("requires the dedicated PostgreSQL profile and shared schema lock")
    parsed = make_url(url)
    assert (parsed.drivername, parsed.host, parsed.port, parsed.database) == (
        "postgresql+asyncpg",
        "127.0.0.1",
        55488,
        "mindpattern_mutation_test",
    )
    assert not parsed.query
    lock_path = Path(lock_name)
    assert lock_path.is_absolute() and lock_path.is_file()
    with lock_path.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield url


@pytest.mark.asyncio
async def test_consent_page_rejects_two_retirements_after_page_read(owned_postgres_profile):
    """A page invalidated before its final liveness fence returns a 409."""
    url = owned_postgres_profile
    schema = "consent_retirement_" + uuid.uuid4().hex
    admin = create_async_engine(url)
    engine = create_async_engine(
        url,
        isolation_level="READ COMMITTED",
        connect_args={"server_settings": {"search_path": schema}},
    )
    app = None
    schema_created = False
    try:
        async with admin.begin() as connection:
            await connection.execute(text(f'CREATE SCHEMA "{schema}"'))
        schema_created = True
        async with engine.begin() as connection:
            assert connection.dialect.name == "postgresql"
            await connection.run_sync(Base.metadata.create_all)
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        patient_id = "a" * 32
        therapist_ids = [f"{i:032x}" for i in range(1, 4)]
        now = datetime(2026, 10, 21, tzinfo=timezone.utc)
        async with sessions() as session:
            session.add(
                User(
                    id=patient_id,
                    username="consent-patient",
                    salt="salt",
                    verifier=b"v" * 32,
                    scrypt_salt=b"s" * 16,
                )
            )
            session.add_all(
                User(
                    id=therapist_id,
                    username=f"consent-therapist-{i}",
                    role="therapist",
                    salt="salt",
                    verifier=b"v" * 32,
                    scrypt_salt=b"s" * 16,
                )
                for i, therapist_id in enumerate(therapist_ids)
            )
            await session.flush()
            session.add_all(
                Consent(
                    id=f"{i + 20:032x}",
                    user_id=patient_id,
                    therapist_id=therapist_id,
                    status="revoked",
                    granted_at=now - timedelta(days=i),
                    revoked_at=now,
                )
                for i, therapist_id in enumerate(therapist_ids)
            )
            await session.commit()

        retired = []

        class RetirementAfterPageSession(AsyncSession):
            async def execute(self, statement, *args, **kwargs):
                result = await super().execute(statement, *args, **kwargs)
                entities = [
                    item.get("entity") for item in getattr(statement, "column_descriptions", ())
                ]
                if entities == [Consent, User] and not retired:
                    # The first liveness probe and page SELECT have completed.
                    # Commit two realistic logical retirements before the final
                    # PostgreSQL scalar-subquery fence executes.
                    async with sessions() as retirement_session:
                        for therapist_id in therapist_ids[1:]:
                            therapist = await retirement_session.get(User, therapist_id)
                            assert therapist is not None and therapist.is_active
                            stage_account_deletion(retirement_session, therapist)
                            retired.append(therapist_id)
                        await retirement_session.commit()
                return result

        request_sessions = async_sessionmaker(
            engine, class_=RetirementAfterPageSession, expire_on_commit=False
        )

        async def request_session():
            async with request_sessions() as session:
                yield session

        async def authenticated_patient(session: AsyncSession = Depends(get_session)):
            patient = await session.get(User, patient_id)
            assert patient is not None
            return patient

        settings = Settings(environment="development")
        settings.therapist_sharing_enabled = True
        app = create_app(settings)
        app.dependency_overrides[get_session] = request_session
        app.dependency_overrides[require_regular_user] = authenticated_patient
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://testserver"
        ) as client:
            response = await client.get("/api/consents", params={"limit": 1})

        assert set(retired) == set(therapist_ids[1:])
        assert response.status_code == 409
        assert response.json() == {
            "detail": "consents changed while paging; retry the request",
            "code": "collection_changed",
        }
        assert response.headers["X-Consents-Revision"] == "0"
        async with sessions() as session:
            inactive = set(
                (await session.scalars(select(User.id).where(User.is_active.is_(False)))).all()
            )
            assert inactive == set(therapist_ids[1:])
    finally:
        try:
            if app is not None:
                await app.state.engine.dispose()
        finally:
            try:
                await engine.dispose()
            finally:
                try:
                    if schema_created:
                        async with admin.begin() as connection:
                            await connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
                finally:
                    await admin.dispose()
