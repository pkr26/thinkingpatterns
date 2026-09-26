"""API request/response schemas."""

from __future__ import annotations

import base64
from datetime import date, datetime
from typing import Annotated, TYPE_CHECKING

from pydantic import BaseModel, ConfigDict, Field

if TYPE_CHECKING:
    from .models import Entry

USERNAME_PATTERN = r"^[a-zA-Z0-9_.-]{3,64}$"
CLIENT_ID_PATTERN = r"^[A-Za-z0-9_-]{1,64}$"


class StrictRequestModel(BaseModel):
    """Base for every request body: unknown fields are a 422, not silent
    data loss (2026-09-20 audit fix L-27). A typo like ``pattern_pid`` →
    ``pattrn_pid`` used to save a general note while the client believed
    it had attached a pattern; response models stay plain BaseModel —
    additive response fields are the compatibility mechanism, and clients
    must never be broken by a server ADDING a field."""

    model_config = ConfigDict(extra="forbid")


# Hard request-size ceilings (defense against memory-exhaustion DoS).
# b64(16 bytes) = 24 chars for salts; b64(32 bytes) = 44 chars for keys;
# entries are journal-sized text, so ~1 MiB of decoded envelope is generous.
MAX_SALT_B64 = 128
MAX_VERIFIER_B64 = 64
MAX_DATA_KEY_B64 = 44  # b64(32 bytes) exactly — the endpoint enforces KEY_SIZE
MAX_BLOB_B64 = 1_500_000  # ~1.07 MiB decoded
# 2026-09-26 audit follow-up N-8: local-recompute STATE blobs are validated
# by the route against settings.max_user_blob_bytes (config-ceiling
# MAX_USER_BLOB_BYTES, 8 GiB). The schema cap here mirrors that hard
# CONFIG ceiling instead of the journal-sized MAX_BLOB_B64 — the first cut
# pre-empted the route authority at ~1.07 MiB, so a legitimately larger
# brain state could never be uploaded regardless of configuration (the
# request body is still bounded much earlier by max_body_bytes
# middleware, default 2 MiB / ceiling 64 MiB).
from .config import MAX_USER_BLOB_BYTES as _MAX_USER_BLOB_BYTES  # noqa: E402

MAX_STATE_BLOB_B64 = (_MAX_USER_BLOB_BYTES // 3 + 1) * 4  # b64 of the ceiling


class RegisterRequest(StrictRequestModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    salt: str = Field(min_length=1, max_length=MAX_SALT_B64)  # b64, exactly 16 decoded bytes
    verifier: str = Field(
        min_length=1, max_length=MAX_VERIFIER_B64
    )  # b64, exactly 32 decoded bytes


class LoginRequest(StrictRequestModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    # Optional therapist second factor (2026-09-22). Absent on the first
    # attempt; the server answers 401 totp_required when the account has
    # TOTP enabled, and the client re-sends with this field filled.
    totp_code: str | None = Field(default=None, min_length=6, max_length=6)


class TokenResponse(BaseModel):
    token: str
    user_id: str
    expires_in: int
    # Additive (2026-09-16): the portal branches on it; existing clients
    # ignore the extra field. Every pre-sharing account is "user".
    role: str = "user"


class SaltLookupRequest(StrictRequestModel):
    # No username pattern here, deliberately: any probe string (including
    # hostile-looking ones) must reach the decoy path — a 422 for invalid
    # formats would itself be an existence oracle. Body-size caps bound it.
    username: str = Field(min_length=1, max_length=128)


class SaltResponse(BaseModel):
    salt: str


class EntryCreate(StrictRequestModel):
    client_entry_id: str = Field(pattern=CLIENT_ID_PATTERN)
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)  # b64 envelope
    entry_date: date
    # v2 AAD contract (2026-09-20 audit fix M-2): a create is ALWAYS the
    # first content generation — the server rejects any other value so the
    # version the client bound into its AAD is the version the row stores.
    content_version: int = Field(default=1, ge=1, le=2**63 - 1)


class EntryReplace(StrictRequestModel):
    """Atomic replacement payload for an existing entry.

    The client entry id remains in the path (and therefore remains part of
    the ciphertext AAD); allowing it to change would turn an edit into a
    delete/create sequence with the same data-loss failure mode this route
    exists to remove.

    ``content_version`` (2026-09-20 audit fix M-2): modern clients send the
    version they bound into the new blob's v2 AAD; it must equal the stored
    version + 1 (409 ``version_conflict`` otherwise, so the client can
    refetch and retry). Legacy clients omit it; the stored version still
    advances so v2 clients observe a monotonic sequence.
    """

    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)
    entry_date: date
    content_version: int | None = Field(default=None, ge=1, le=2**63 - 1)


class EntryOut(BaseModel):
    id: str
    client_entry_id: str
    blob: str
    entry_date: date
    received_at: datetime
    # Additive (2026-09-20): the row's monotonic content generation — v2
    # clients bind it into the entry AAD and keep a per-id high-water mark.
    content_version: int = 1


class ProcessingSessionRequest(StrictRequestModel):
    data_key: str = Field(min_length=1, max_length=MAX_DATA_KEY_B64)  # b64, exactly 32 bytes


class ProcessingSessionResponse(BaseModel):
    session_token: str
    expires_in: int


class RekeyResponse(BaseModel):
    """Result of POST /processing/rekey (2026-09-20, audit fix H-1).

    Counts of rows re-encrypted from the old data key to the new one, so the
    client can verify nothing was silently skipped (each count must equal the
    collection sizes it knows from its own sync state).
    """

    entries: int
    insights: int
    measures: int


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
    # Analysis generation (2026-09-19): equals the ``state_seq`` embedded in
    # the encrypted patterns payload just stored. Clients verify equality
    # after decrypting and alarm if the value ever moves BACKWARDS across
    # sessions — that is the rollback-replay detection contract (a valid-GCM
    # old blob otherwise replays silently; see the Insight.state_seq note).
    state_seq: int = 0


class AccountDeleteRequest(StrictRequestModel):
    """Account destruction requires the password-equivalent credential —
    a stolen bearer token alone must not be able to erase a journal."""

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class CredentialRotateRequest(StrictRequestModel):
    """Rotate the LOGIN credential (2026-09-20, audit fix H-1/M-3).

    Re-authenticated with the CURRENT verifier: a stolen bearer alone must
    not be able to swap the credential (which would lock the real user out)
    and a phished verifier alone cannot survive the user rotating it. The
    new salt/verifier are exactly the register payload's shape (16-byte and
    32-byte values, base64). Rotation also bumps the token epoch and purges
    every processing session: all devices re-login under the new credential.

    Deliberately login-credential-only: the journal's data key is untouched,
    so no stored ciphertext changes meaning. A data-key change is the separate
    POST /processing/rekey flow (run BEFORE this endpoint with both keys).
    """

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    new_salt: str = Field(min_length=1, max_length=MAX_SALT_B64)
    new_verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class TotpSetupRequest(StrictRequestModel):
    """Begin optional therapist TOTP enrollment (2026-09-21 audit C-2/F-4,
    delivered 2026-09-22). Verifier-re-authenticated like every credential
    lifecycle action: a stolen bearer must not be able to arm a second
    factor on the account. The returned secret is PENDING until the
    confirm endpoint proves the authenticator holds it."""

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class TotpConfirmRequest(StrictRequestModel):
    """Enable (or disable) TOTP by proving possession of the authenticator."""

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    code: str = Field(min_length=6, max_length=6, pattern=r"^\d{6}$")


class TotpSetupResponse(BaseModel):
    # base32, exactly what an authenticator app takes for manual entry.
    secret_base32: str
    # otpauth:// URI for apps that accept it; the portal renders both as
    # copyable text (no QR dependency).
    otpauth_uri: str


class LlmConsentRequest(StrictRequestModel):
    """Opting into third-party LLM analysis is explicit, per-user, and
    re-authenticated — it gates sending decrypted journal text off-server."""

    enabled: bool
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class LlmConsentResponse(BaseModel):
    enabled: bool
    # `enabled` records the user's historic choice. This separate field is
    # false when the configured third-party policy changed, so a UI never
    # implies that a stale choice still authorizes new plaintext egress.
    active_for_current_policy: bool = False
    # GDPR Art. 7 record (additive): when consent was given and against
    # which disclosure version. Both null while consent is off.
    llm_consent_at: datetime | None = None
    llm_consent_disclosure: str | None = None
    # Opaque SHA-256 fingerprint of the provider/endpoint/model/retention
    # terms accepted by the account. It lets clients detect that consent is
    # stale after an operator changes third-party processing.
    llm_consent_policy: str | None = None


class MetaResponse(BaseModel):
    """Unauthenticated, non-personal server facts the client needs to render
    honest UI (threshold progress, whether the LLM path even exists)."""

    version: str
    api_version: str  # "v1" — the canonical mount is /api/v1 (/api is legacy)
    unlock_days: int
    llm_available: bool
    llm_provider_name: str | None = None
    llm_data_retention: str | None = None
    llm_policy_fingerprint: str | None = None
    sharing_available: bool = False
    sharing_disclosure_version: str | None = None
    sharing_access_log_retention_days: int | None = None


class InsightsResponse(BaseModel):
    phase: str
    active_days: int
    streak: int
    days_remaining: int
    blob: str | None = None
    # Analysis generation of the stored patterns blob (0 when none): must
    # equal the ``state_seq`` inside the decrypted payload and must never
    # decrease across a client's sessions (rollback-replay detection).
    state_seq: int = 0


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
    llm_consent_policy: str | None = None
    # Sharing records (metadata only — no wrapped keys; they are useless
    # without the therapist's private key anyway). Additive: old bundles
    # predate sharing and decrypt unchanged.
    shares: list[ShareRecord] = []
    entries: list[EntryOut]
    insights: list[InsightOut]
    # Wellbeing measures (2026-09-20 audit fix H-3): the export bundle used
    # to omit every Measure row, so the README's export-then-delete flow
    # silently destroyed the patient's entire PHQ-9 history. Additive — old
    # bundles decrypt unchanged; rows are the same MeasureOut shape the
    # /measures endpoints serve, ciphertext bound to AAD
    # ("measure", user_id, client_measure_id) exactly as the client
    # encrypted it.
    measures: list[MeasureOut] = []


def entry_out(row: Entry) -> EntryOut:
    """Entry row -> wire shape; the one construction shared by the entries
    router and the account export.

    ``content_version`` coalesces to 1: the column default applies at flush
    time, so an unflushed ORM instance (test doubles, in-memory constructs)
    still renders — and no stored row can legitimately be below 1.
    """
    return EntryOut(
        id=row.id,
        client_entry_id=row.client_entry_id,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
        entry_date=row.entry_date,
        received_at=row.received_at,
        content_version=row.content_version if row.content_version is not None else 1,
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
# Display names render on consent screens, where a spoofed identity is a
# consent decision, not cosmetics. The old pattern only excluded \n and \t;
# every OTHER control character and — worse — the bidi/format controls
# (RLM/LRM, directional embeddings and isolates, zero-width spaces) were
# admitted, letting a crafted name visually re-order or invisibly pad
# itself (2026-09-20 audit fix L-28). It is a single-line field: \n and \t
# stay excluded (now via the \x00-\x1f control range), and the whole Cc,
# invisible-Cf, Zl/Zp zoo is refused alongside them.
DISPLAY_NAME_FORBIDDEN = (
    "\x00-\x1f"  # Cc controls — includes \n and \t (single-line field)
    "\x7f-\x9f"  # Cc controls (DEL + C1 range)
    "\u00ad"  # soft hyphen (Cf)
    "\u200b-\u200f"  # ZWSP, ZWNJ, LRM, RLM (Cf)
    "\u2028\u2029"  # Zl/Zp line/paragraph separators
    "\u202a-\u202e"  # bidi embedding/override controls (Cf)
    "\u2060-\u206f"  # word joiner … invisible operators + bidi isolates (Cf)
    "\ufeff"  # zero-width no-break space / BOM (Cf)
    "\ufff9-\ufffb"  # interlinear annotation controls (Cf)
)
DISPLAY_NAME_PATTERN = "^[^" + DISPLAY_NAME_FORBIDDEN + "]{1,120}$"


class TherapistRegisterRequest(StrictRequestModel):
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
    # Additive (2026-09-22): lets the security panel show the honest TOTP
    # state without a probing round-trip. Existing clients ignore it.
    totp_enabled: bool = False


class WrapKeyRotateRequest(StrictRequestModel):
    """A fresh therapist wrap keypair (2026-09-21 audit C-2): the new
    public half patients re-wrap their data keys to, and the private half
    as a blob under the (current or new) password-derived KEK — same
    shape and validation as registration."""

    wrap_pub_key: str = Field(min_length=1, max_length=MAX_SPKI_B64)
    wrap_key_blob: str = Field(min_length=1, max_length=MAX_THERAPIST_KEY_BLOB_B64)


class PatientAccessLogOut(BaseModel):
    """One row of WHO-ACCESSED-MY-DATA (2026-09-21 audit B-4): the
    patient's consent-scoped view of their own audit trail. `actor` is
    "self" for the patient's own lifecycle actions (grant, revoke,
    rewrap) and "therapist" for portal reads; `actor_name` is the
    therapist's display name (the patient chose to share with them)."""

    at: datetime
    action: str
    actor: str
    actor_name: str | None = None


class TherapistAccessLogOut(BaseModel):
    """The therapist's own action history (accountability view): every
    read/write the portal performed, newest first. `patient_name` is the
    acted-on patient's display name (None for self-lifecycle rows such
    as wrap_key_rotate)."""

    at: datetime
    action: str
    patient_name: str | None = None


class PairingCodeResponse(BaseModel):
    code: str
    expires_in: int


class PairingLookupRequest(StrictRequestModel):
    # Free-form on purpose: a validation error would leak nothing here, but
    # the code alphabet is normalized in one place (security.sharing) and a
    # wrong code must simply 404.
    code: str = Field(min_length=1, max_length=32)


class PairingLookupResponse(BaseModel):
    therapist_id: str
    display_name: str
    wrap_pub_key: str


class ConsentGrantRequest(StrictRequestModel):
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
    # Additive (2026-09-20, rotation flow): the therapist's public wrap key,
    # so a client that just rotated its data key can re-wrap it to the same
    # therapist (PUT /consents/{id}/rewrap) without a new pairing round-trip.
    # Absent on legacy rows is impossible (registration requires the key);
    # the None default keeps the field additive for older serialized copies.
    therapist_wrap_pub_key: str | None = None


class ConsentRewrapRequest(StrictRequestModel):
    """Re-wrap the data key of an ACTIVE consent to the same therapist.

    Sent by the client after POST /processing/rekey rotated the account's
    data key: the old wrapped_key opened the PREVIOUS key and is now dead
    weight. Same shape/validation as the grant payload's key fields, and the
    same password re-auth (X-Account-Verifier): a stolen bearer must not be
    able to substitute key material inside a live share.
    """

    ephemeral_pub: str = Field(min_length=1, max_length=MAX_SPKI_B64)
    wrapped_key: str = Field(min_length=1, max_length=MAX_WRAP_B64)


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
    # Caseload summary (2026-09-19): the ECIES-wrapped per-consent summary
    # written at the patient's last post-grant recompute. Absent while
    # revoked and until that first recompute — the portal renders "—".
    summary_blob: str | None = None
    summary_eph_pub: str | None = None
    summary_updated_at: datetime | None = None


class MeasureCreate(StrictRequestModel):
    """One recorded questionnaire completion: an opaque blob (the client
    encrypts the score payload under the data key, AAD ("measure", user,
    client_measure_id)) plus the client's calendar day of completion."""

    client_measure_id: str = Field(pattern=CLIENT_ID_PATTERN)
    blob: str = Field(min_length=1, max_length=8192)  # b64 envelope; scores are tiny
    measure_date: date


class MeasureOut(BaseModel):
    id: str
    client_measure_id: str
    blob: str
    measure_date: date
    received_at: datetime


class NoteCreateRequest(StrictRequestModel):
    client_note_id: str = Field(pattern=CLIENT_ID_PATTERN)
    # min_length=1 (2026-09-20 audit fix L-29): an EMPTY string is not a
    # pid, and silently coercing it to the NULL "general note" semantics
    # let a client bug attach (or detach) a note from a pattern without
    # any error. Explicit null remains the only way to say "no pattern".
    pattern_pid: str | None = Field(default=None, min_length=1, max_length=200)
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)


class NoteUpdateRequest(StrictRequestModel):
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)


class NoteOut(BaseModel):
    id: str
    client_note_id: str
    pattern_pid: str | None
    blob: str
    created_at: datetime
    updated_at: datetime


class LocalRecomputeRequest(StrictRequestModel):
    """Phase 3 (2026-09-21): the on-device analysis upload. A client that
    ran the deterministic brain LOCALLY ships the two client-encrypted
    blobs (brain state + patterns payload, same AAD contracts the app
    already uses to decrypt what GET /insights serves) plus the analysis
    date-scope it claims. The server never sees the data key — no
    processing session exists on this path.

    2026-09-26 audit (LOW, batch item g): schema hardening for symmetry
    with EntryCreate/MeasureCreate — the blob fields carry the same
    max_length envelope (the route-level size checks in insights.py
    remain the authority; this bounds the parsed request earlier) and
    analysis_dates entries carry the ISO-date pattern so a malformed date
    is a 422 at validation instead of reaching the route loop."""

    base_state_seq: int  # the seq of the brain state the client built on
    state_blob: str = Field(min_length=1, max_length=MAX_STATE_BLOB_B64)
    patterns_blob: str = Field(min_length=1, max_length=MAX_STATE_BLOB_B64)
    analysis_dates: list[Annotated[str, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")]] = Field(
        min_length=1, max_length=366
    )


class NoteRevisionOut(BaseModel):
    """One superseded revision of a note (P3, 2026-09-21): the prior
    blob (same AAD as the live note — client_note_id is stable) and the
    moment it was superseded."""

    id: str
    blob: str
    created_at: datetime


class ShareRecord(BaseModel):
    """A sharing consent, as it travels in the account export: metadata
    only (who, when, status) — the wrapped key is the therapist's to
    unwrap, not the patient's document."""

    therapist_username: str
    therapist_display_name: str
    status: str
    granted_at: datetime
    revoked_at: datetime | None = None
