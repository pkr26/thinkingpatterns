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
    verifier: str = Field(
        min_length=1, max_length=MAX_VERIFIER_B64
    )  # b64, exactly 32 decoded bytes


class LoginRequest(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class TokenResponse(BaseModel):
    token: str
    user_id: str
    expires_in: int
    # Additive (2026-09-16): the portal branches on it; existing clients
    # ignore the extra field. Every pre-sharing account is "user".
    role: str = "user"


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
    # No username (2026-09-16 remediation, finding H2): the export is the
    # user's own document; a cleartext name was a free account marker for
    # anyone who obtained the file. user_id + salt stay — the AAD binding
    # needs the id, and any future re-import needs the salt.
    user_id: str  # required by the AAD binding — without it the bundle is undecryptable
    salt: str
    llm_consent: bool
    # Same Art. 7 record as the consent endpoint (additive; null when off).
    llm_consent_at: datetime | None = None
    llm_consent_disclosure: str | None = None
    # Sharing records (metadata only — no wrapped keys; they are useless
    # without the therapist's private key anyway). Additive: old bundles
    # predate sharing and decrypt unchanged.
    shares: list[ShareRecord] = []
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


# ---------------------------------------------------------------------------
# Therapist sharing (2026-09-16) — see app/security/sharing.py for the wrap
# construction and app/api/{consents,therapist}.py for the flows.
# ---------------------------------------------------------------------------

# b64(91-byte SPKI P-256) = 124 chars; the AES-GCM wrap of a 32-byte data
# key is 60 raw bytes -> 80 b64 chars. Caps sit just above the exact sizes.
MAX_SPKI_B64 = 128
MAX_WRAP_B64 = 512
# AES-GCM(PKCS8 DER P-256 private key ~=138 bytes) ~= 170 raw -> 232 b64.
MAX_THERAPIST_KEY_BLOB_B64 = 1024
DISPLAY_NAME_PATTERN = r"^[^\n\t]{1,120}$"


class TherapistRegisterRequest(BaseModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    salt: str = Field(min_length=1, max_length=MAX_SALT_B64)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    display_name: str = Field(pattern=DISPLAY_NAME_PATTERN)
    # b64 SPKI DER P-256 — validated server-side by security.sharing.
    wrap_pub_key: str = Field(min_length=1, max_length=MAX_SPKI_B64)
    # b64 AES-GCM(PKCS8 DER private key) under the therapist's
    # password-derived KEK; opaque to the server, size-capped only.
    wrap_key_blob: str = Field(min_length=1, max_length=MAX_THERAPIST_KEY_BLOB_B64)


class TherapistMeResponse(BaseModel):
    username: str
    display_name: str
    wrap_pub_key: str
    wrap_key_blob: str


class PairingCodeResponse(BaseModel):
    code: str
    expires_in: int


class PairingLookupRequest(BaseModel):
    # Free-form on purpose: a validation error would leak nothing here, but
    # the code alphabet is normalized in one place (security.sharing) and a
    # wrong code must simply 404.
    code: str = Field(min_length=1, max_length=32)


class PairingLookupResponse(BaseModel):
    therapist_id: str
    display_name: str
    wrap_pub_key: str


class ConsentGrantRequest(BaseModel):
    code: str = Field(min_length=1, max_length=32)
    ephemeral_pub: str = Field(min_length=1, max_length=MAX_SPKI_B64)
    wrapped_key: str = Field(min_length=1, max_length=MAX_WRAP_B64)
    # Which disclosure copy the patient answered (GDPR Art. 7 parity with
    # the LLM consent record). The client sends the version it displayed.
    disclosure: str = Field(min_length=1, max_length=64)


class ConsentOut(BaseModel):
    """The patient's view of their grants."""

    id: str
    therapist_id: str
    display_name: str
    username: str
    status: str
    granted_at: datetime
    revoked_at: datetime | None = None


class PatientOut(BaseModel):
    """The therapist's patient list — one row per consent, revoked ones
    included (the therapist knew the patient; hiding them would only be
    confusing, and the wrapped key is already gone)."""

    user_id: str
    username: str
    status: str
    granted_at: datetime
    revoked_at: datetime | None = None
    # Absent while revoked — there is nothing left to unwrap.
    ephemeral_pub: str | None = None
    wrapped_key: str | None = None


class NoteCreateRequest(BaseModel):
    client_note_id: str = Field(pattern=CLIENT_ID_PATTERN)
    pattern_pid: str | None = Field(default=None, max_length=200)
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)


class NoteUpdateRequest(BaseModel):
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)


class NoteOut(BaseModel):
    id: str
    client_note_id: str
    pattern_pid: str | None
    blob: str
    created_at: datetime
    updated_at: datetime


class ShareRecord(BaseModel):
    """A sharing consent, as it travels in the account export: metadata
    only (who, when, status) — the wrapped key is the therapist's to
    unwrap, not the patient's document."""

    therapist_username: str
    therapist_display_name: str
    status: str
    granted_at: datetime
    revoked_at: datetime | None = None
