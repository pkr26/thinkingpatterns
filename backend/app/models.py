"""Database models — the server stores ciphertext blobs and almost nothing else."""

from __future__ import annotations

import uuid
from datetime import date, datetime, timezone

from sqlalchemy import Date, DateTime, ForeignKey, Index, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return uuid.uuid4().hex


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
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    is_active: Mapped[bool] = mapped_column(default=True)
    # Bumped on logout: stateless HMAC tokens embed the epoch they were issued
    # under, so one integer per account is a full revocation list.
    token_epoch: Mapped[int] = mapped_column(default=1)
    # Per-user explicit opt-in before any journal text is sent to the
    # third-party LLM endpoint (MINDPATTERN_LLM_URL). Off by default.
    llm_consent: Mapped[bool] = mapped_column(default=False)


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
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Insight(Base):
    __tablename__ = "insights"
    __table_args__ = (Index("ix_insights_user_kind_date", "user_id", "kind", "for_date"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(String(32))  # "patterns" | "question"
    for_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary)  # encrypted pattern/question payload
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
