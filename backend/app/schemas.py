"""API request/response schemas."""

from __future__ import annotations

import base64
from datetime import date, datetime
from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .models import Entry

USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{3,64}$"
CLIENT_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"

# Hard request-size ceilings (defense against memory-exhaustion DoS).
# b64(16 bytes) = 24 chars for salts; b64(32 bytes) = 44 chars for keys;
# entries are journal-sized text, so ~1 MiB of decoded envelope is generous.
MAX_SALT_B64 = 128
MAX_VERIFIER_B64 = 64
MAX_DATA_KEY_B64 = 44  # b64(32 bytes) exactly — the endpoint enforces KEY_SIZE
MAX_BLOB_B64 = 1_500_000  # ~1.07 MiB decoded


class RegisterRequest(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    salt: str = Field(min_length=1, max_length=MAX_SALT_B64)  # b64, exactly 16 decoded bytes
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)  # b64, exactly 32 decoded bytes


class LoginRequest(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class TokenResponse(BaseModel):
    token: str
    user_id: str
    expires_in: int


class SaltLookupRequest(BaseModel):
    # No username pattern here, deliberately: any probe string (including
    # hostile-looking ones) must reach the decoy path — a 422 for invalid
    # formats would itself be an existence oracle. Body-size caps bound it.
    username: str = Field(min_length=1, max_length=128)


class SaltResponse(BaseModel):
    salt: str


class EntryCreate(BaseModel):
    client_entry_id: str = Field(pattern=CLIENT_ID_PATTERN)
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)  # b64 envelope
    entry_date: date


class EntryOut(BaseModel):
    id: str
    client_entry_id: str
    blob: str
    entry_date: date
    received_at: datetime


class ProcessingSessionRequest(BaseModel):
    data_key: str = Field(min_length=1, max_length=MAX_DATA_KEY_B64)  # b64, exactly 32 bytes


class ProcessingSessionResponse(BaseModel):
    session_token: str
    expires_in: int


class RecomputeResponse(BaseModel):
    phase: str
    active_days: int
    streak: int
    days_remaining: int
    patterns_stored: int
    question_stored: bool
    analyzer: str  # "none" (baseline) | "brain" | "llm"
    # v2 mini-brain lifecycle counters (absent/0 for old clients is fine).
    patterns_new: int = 0
    patterns_fading: int = 0


class AccountDeleteRequest(BaseModel):
    """Account destruction requires the password-equivalent credential —
    a stolen bearer token alone must not be able to erase a journal."""

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class LlmConsentRequest(BaseModel):
    """Opting into third-party LLM analysis is explicit, per-user, and
    re-authenticated — it gates sending decrypted journal text off-server."""

    enabled: bool
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class LlmConsentResponse(BaseModel):
    enabled: bool
    # GDPR Art. 7 record (additive): when consent was given and against
    # which disclosure version. Both null while consent is off.
    llm_consent_at: datetime | None = None
    llm_consent_disclosure: str | None = None


class MetaResponse(BaseModel):
    """Unauthenticated, non-personal server facts the client needs to render
    honest UI (threshold progress, whether the LLM path even exists)."""

    version: str
    api_version: str  # "v1" — the canonical mount is /api/v1 (/api is legacy)
    unlock_days: int
    llm_available: bool


class InsightsResponse(BaseModel):
    phase: str
    active_days: int
    streak: int
    days_remaining: int
    blob: str | None = None


class QuestionResponse(BaseModel):
    for_date: date
    blob: str


class InsightOut(BaseModel):
    kind: str
    for_date: date | None
    blob: str
    created_at: datetime


class ExportBundle(BaseModel):
    version: int
    exported_at: datetime
    username: str
    user_id: str  # required by the AAD binding — without it the bundle is undecryptable
    salt: str
    llm_consent: bool
    # Same Art. 7 record as the consent endpoint (additive; null when off).
    llm_consent_at: datetime | None = None
    llm_consent_disclosure: str | None = None
    entries: list[EntryOut]
    insights: list[InsightOut]


def entry_out(row: Entry) -> EntryOut:
    """Entry row -> wire shape; the one construction shared by the entries
    router and the account export."""
    return EntryOut(
        id=row.id,
        client_entry_id=row.client_entry_id,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
        entry_date=row.entry_date,
        received_at=row.received_at,
    )
