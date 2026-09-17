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


ROLE_USER = "user"
ROLE_THERAPIST = "therapist"


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
    # Therapist sharing (2026-09-16): one account namespace, two roles. The
    # role gates which router an authenticated token may reach — journal
    # endpoints require "user", sharing endpoints require "therapist".
    role: Mapped[str] = mapped_column(String(16), default=ROLE_USER)
    # Therapist-only: shown to patients in the pairing flow (their consent
    # screen must name a human, not a username handle).
    display_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    # Therapist-only: b64 SPKI DER of a P-256 public key. Patients wrap their
    # data key to it (ECDH + HKDF + AES-GCM); the private half never leaves
    # the therapist's device unencrypted.
    wrap_pub_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # Therapist-only: the P-256 PRIVATE key, PKCS8 DER, AES-256-GCM-encrypted
    # under an HKDF subkey of the therapist's password-derived master key.
    # The server stores the blob and cannot open it.
    wrap_key_blob: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
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


# --- therapist sharing (2026-09-16) -----------------------------------------
#
# Zero-knowledge sharing model: the server brokers WHO may read WHAT, but
# never holds anything that can decrypt it. A consent row carries the
# patient's data key wrapped to the therapist's public key (ECDH-derived
# KEK); the therapist's portal unwraps it locally after a password unlock.
# Revocation clears the wrapped key and every therapist read path checks the
# consent's status first — the server cannot "un-see" bytes a browser
# already downloaded, which the pairing disclosure states plainly.


class Consent(Base):
    __tablename__ = "consents"
    __table_args__ = (
        UniqueConstraint("user_id", "therapist_id", name="uq_consents_user_therapist"),
        Index("ix_consents_therapist_status", "therapist_id", "status"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    therapist_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # "active" | "revoked". A revoked row keeps the pair's history (and the
    # therapist's notes) but wrapped_key is NULL — nothing left to decrypt
    # with, and re-granting flips the same row back to active.
    status: Mapped[str] = mapped_column(String(16), default="active")
    # v1 scope is "full" (patterns + all entries). The column exists so a
    # future per-pattern scope is a data change, not a schema change.
    scope: Mapped[str] = mapped_column(String(16), default="full")
    granted_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    revoked_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    # b64 SPKI DER of the EPHEMERAL P-256 key the patient's client generated
    # for this grant. With the therapist's public key it pins the ECDH
    # inputs so both sides derive the same KEK deterministically.
    ephemeral_pub: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # AES-256-GCM(data_key) under HKDF(ECDH secret), AAD-bound to
    # ("consent-wrap", user_id, therapist_id) so a blob cannot be relocated
    # between consents undetected. NULL while revoked.
    wrapped_key: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    # Which sharing-disclosure copy the patient answered (the LLM consent's
    # Art. 7 record, applied to sharing).
    disclosure: Mapped[str | None] = mapped_column(String(64), nullable=True)


class PairingCode(Base):
    """A short-lived, single-use code a therapist displays and a patient
    types. The server stores only an HMAC of the code: a database leak must
    not turn unconsumed codes into grants."""

    __tablename__ = "pairing_codes"
    __table_args__ = (Index("ix_pairing_codes_hash", "code_hash"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    therapist_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    code_hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
    # Set when a patient redeems the code in a successful grant; a code with
    # consumed_at set is dead regardless of expiry.
    consumed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class TherapistNote(Base):
    """A clinician's note about a patient, optionally attached to one
    pattern id. The blob is AES-256-GCM under the therapist's own
    password-derived key: therapist-private by construction (the patient's
    app has no path to these rows at all), exactly like paper session notes.

    Notes key to (therapist, patient) rather than to a consent row, so
    revoking and re-granting access keeps the therapist's continuity."""

    __tablename__ = "therapist_notes"
    __table_args__ = (
        UniqueConstraint("therapist_id", "client_note_id", name="uq_notes_therapist_client"),
        Index("ix_notes_therapist_patient", "therapist_id", "user_id"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    therapist_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    # Client-generated id (the entries' client_entry_id pattern): the blob's
    # AAD binds to it, and it makes POST idempotent-retryable.
    client_note_id: Mapped[str] = mapped_column(String(64))
    # Pattern pid ("temporal:work", "mood_shift:", …) or NULL for a general
    # patient note. Pids survive recomputes; a semantic fork (~2) retires the
    # old pid and the note stays attached to the retired one.
    pattern_pid: Mapped[str | None] = mapped_column(String(200), nullable=True)
    blob: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class AccessLog(Base):
    """Who touched whose shared data, when. Clinically expected metadata:
    the therapist-facing reads are auditable even though their CONTENT is
    invisible to the server. actor_id/user_id are plain strings, NOT FKs —
    the audit trail must outlive the account rows it describes (a patient
    deleting their account does not erase the fact that a therapist read
    their patterns last week)."""

    __tablename__ = "access_log"
    __table_args__ = (
        Index("ix_access_log_actor", "actor_id", "at"),
        Index("ix_access_log_user", "user_id", "at"),
    )

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=new_id)
    actor_id: Mapped[str] = mapped_column(String(32))
    # "user" | "therapist" — who performed the action.
    actor_role: Mapped[str] = mapped_column(String(16))
    user_id: Mapped[str] = mapped_column(String(32))  # the patient whose data it concerns
    # "grant" | "revoke" | "read_insights" | "read_entries" | "read_notes" |
    # "write_note" | "update_note" | "delete_note"
    action: Mapped[str] = mapped_column(String(32))
    at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
