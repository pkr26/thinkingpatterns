"""Database models — the server stores ciphertext blobs and almost nothing else."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Date, DateTime, ForeignKey, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    # Deliberate deferral (documented so it is a choice, not an oversight):
    # primary keys are opaque random hex with NO CHECK constraints enforcing
    # length/format at the DB layer. Random ids need no shape policing at
    # this scale; the meaningful bounds (id lengths, enum-ish strings like
    # Insight.kind, date ranges) are enforced at the schema/config layers.
    return uuid.uuid4().hex


class UTCDateTime(TypeDecorator):
    """DateTime(timezone=True) that always reads back tz-aware UTC.

    SQLite has no tz-aware storage: aiosqlite returns NAIVE datetimes for a
    DateTime(timezone=True) column while asyncpg returns tz-aware ones, so
    API responses (entry received_at, insight created_at) would serialize
    differently per backend. Every value written here comes from utcnow(),
    so attaching UTC on load is normalization, not a guess. Binds are
    untouched — Postgres behavior is exactly as before.
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # b64 of the client KDF salt (public-ish material, needed to log in)
    salt: Mapped[str] = mapped_column(String(128))
    # scrypt(auth_key, scrypt_salt) — the server never sees the auth key itself
    verifier: Mapped[bytes] = mapped_column(LargeBinary)
    scrypt_salt: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    is_active: Mapped[bool] = mapped_column(default=True)
    # Bumped on logout: stateless HMAC tokens embed the epoch they were issued
    # under, so one integer per account is a full revocation list.
    token_epoch: Mapped[int] = mapped_column(default=1)
    # Per-user explicit opt-in before any journal text is sent to the
    # third-party LLM endpoint (MINDPATTERN_LLM_URL). Off by default.
    llm_consent: Mapped[bool] = mapped_column(default=False)
    # GDPR Art. 7 demonstrability: a bare bool cannot show WHEN consent was
    # given or WHICH disclosure text it answered. Recorded by
    # PUT /account/llm-consent on enable (utcnow + LLM_DISCLOSURE_VERSION),
    # both cleared on withdrawal — NULL means "no consent record".
    llm_consent_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    llm_consent_disclosure: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Entry(Base):
    __tablename__ = "entries"
    __table_args__ = (
        UniqueConstraint("user_id", "client_entry_id", name="uq_user_client_entry"),
        Index("ix_entries_user_date", "user_id", "entry_date"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    client_entry_id: Mapped[str] = mapped_column(String(64))
    blob: Mapped[bytes] = mapped_column(LargeBinary)  # opaque: nonce||ct||tag
    entry_date: Mapped[date] = mapped_column(Date)  # calendar day of the entry
    received_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Insight(Base):
    __tablename__ = "insights"
    __table_args__ = (
        Index("ix_insights_user_kind_date", "user_id", "kind", "for_date"),
        # Write idempotency key: the API upserts dated rows (questions) on
        # this constraint. NULL for_date rows (patterns/brain state) never
        # conflict under it — SQL NULLs are distinct — those stay
        # delete-then-insert under the per-user recompute lock.
        UniqueConstraint("user_id", "kind", "for_date", name="uq_insights_user_kind_date"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))  # "patterns" | "brain" | "question"
    for_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary)  # encrypted pattern/question payload
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
