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

# 2026-09-26 v2 key scheme: the wrapped data key is nonce(12)+ct(32)+tag(16)
# = 60 decoded bytes -> 80 b64 chars. The cap sits just above the exact size.
MAX_WRAPPED_DATA_KEY_B64 = 128


class RegisterRequest(StrictRequestModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    salt: str = Field(min_length=1, max_length=MAX_SALT_B64)  # b64, exactly 16 decoded bytes
    verifier: str = Field(
        min_length=1, max_length=MAX_VERIFIER_B64
    )  # b64, exactly 32 decoded bytes
    # v2 registration (2026-09-26 envelope remediation) — BOTH fields come
    # together or neither does (the route enforces the pairing): the
    # versioned client KDF parameters blob (validated/canonicalized by
    # security.kdf.validate_kdf_params) and the opaque AES-GCM envelope of
    # the random 32-byte data key (server stores bytes it cannot decrypt).
    # Typed ``object`` deliberately: pydantic coercion must not silently
    # accept 600000.0-as-int or true-as-1 — the KDF bounds are judged by
    # the one validator that also canonicalizes the blob for the AAD rule.
    kdf_params: object | None = None
    wrapped_data_key: str | None = Field(
        default=None, min_length=1, max_length=MAX_WRAPPED_DATA_KEY_B64
    )


class LoginRequest(StrictRequestModel):
    username: str = Field(pattern=USERNAME_PATTERN)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    # Optional therapist second factor (2026-09-22). Absent on the first
    # attempt; the server answers 401 totp_required when the account has
    # TOTP enabled, and the client re-sends with this field filled. Width
    # covers BOTH accepted forms (2026-09-26 pentest S-3): the six-digit
    # authenticator code or a 10-char single-use recovery code; anything
    # that is neither simply fails the second factor.
    totp_code: str | None = Field(default=None, min_length=6, max_length=16)


class TokenResponse(BaseModel):
    token: str
    user_id: str
    expires_in: int
    # Additive (2026-09-16): the portal branches on it; existing clients
    # ignore the extra field. Every pre-sharing account is "user".
    role: str = "user"
    # Additive (2026-09-26 v2 key scheme): which client crypto flow the
    # account is on. "v1" = password-derived data key (rekey-on-change);
    # "v2" = random data key behind a password-wrapped envelope (fetch the
    # envelope material via GET /auth/key-envelope and unwrap locally).
    key_scheme: str = "v1"


class KeyEnvelopeResponse(BaseModel):
    """GET /auth/key-envelope — everything a v2 client needs to unwrap its
    random data key locally after login (the KEK input never exists
    server-side, so this response is safe to hand to the authenticated
    account). v1 accounts answer key_scheme="v1" with null envelope
    fields: the legacy password-derived flow, plus a hint that the client
    MAY offer the POST /account/key-envelope/upgrade path."""

    key_scheme: str
    salt: str
    kdf_params: dict[str, int | str] | None = None
    wrapped_data_key: str | None = None


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


class AudioAttachmentMeta(BaseModel):
    """Non-secret listing metadata (rides EntryOut pages and the portal's
    entries listing) so clients can render play buttons and expiry labels
    without fetching blobs. Defined here — before EntryOut — because
    EntryOut annotates with it (VOICE_PLAN 2026-09-29)."""

    attachment_id: str
    expires_at: datetime


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
    # Additive (2026-09-29, VOICE_PLAN): unexpired kept-recording metadata
    # for this entry, joined server-side (no decryption involved). Absent
    # on every pre-voice deployment and on entries without kept audio.
    audio: AudioAttachmentMeta | None = None


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
    analyzer: str  # "none" (baseline) | "brain" | "llm" | "local" (local-recompute)
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

    v2 accounts (2026-09-26): this endpoint answers 409 key_scheme_conflict
    — swapping a v2 account's salt WITHOUT re-wrapping the envelope would
    destroy the only copy of the data key's locker. v2 clients use
    PUT /account/password, which swaps credential AND envelope atomically.
    """

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    new_salt: str = Field(min_length=1, max_length=MAX_SALT_B64)
    new_verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class PasswordChangeRequest(StrictRequestModel):
    """PUT /account/password — the v2 password change (2026-09-26).

    One atomic swap of EVERYTHING the old password protects: the login
    credential (salt + scrypt verifier, exactly the register payload's
    shape) AND the data-key envelope. The client unwraps its random data
    key locally with the OLD password, derives a fresh salt + kdf_params
    from the NEW password, and uploads the re-wrapped envelope — the data
    key itself NEVER changes, so NO corpus rekey and no per-consent
    re-wrap is needed (the stored ciphertext and every therapist wrap
    keep opening under the same random key). The old-password verifier
    proof and the same lifecycle fence as PUT /account/credential apply;
    the token epoch bumps (all bearers die) and processing sessions
    purge. A v1 account that sends this endpoint migrates to v2 (the
    envelope upload IS the migration — it must wrap the account's CURRENT
    data key, which the client proves by opening a processing session
    with it first).
    """

    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    new_salt: str = Field(min_length=1, max_length=MAX_SALT_B64)
    new_verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    # Optional: defaults to keeping the account's current params blob (a
    # pure password change usually keeps the KDF; an explicit blob is how
    # a client UPGRADES its cost parameters together with the password).
    new_kdf_params: object | None = None
    wrapped_data_key: str = Field(min_length=1, max_length=MAX_WRAPPED_DATA_KEY_B64)


class RecoverySetupRequest(StrictRequestModel):
    """PUT /account/recovery — create/replace the recovery envelope.

    The verifier here is the RECOVERY KEY itself (a random 32 bytes the
    client generated and showed once): like the login scheme, the server
    stores only its scrypt hash. wrapped_key is the data key sealed
    CLIENT-side under a key derived from the recovery key — the server
    stores the blob and cannot open it. Setup additionally requires the
    PASSWORD verifier proof (every destructive lifecycle action does).
    """

    password_verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    wrapped_key: str = Field(min_length=1, max_length=MAX_WRAPPED_DATA_KEY_B64)


class RecoveryStatusResponse(BaseModel):
    enabled: bool
    set_at: datetime | None = None


class RecoveryLoginRequest(StrictRequestModel):
    """POST /auth/recover — username + the recovery key (as the verifier)."""

    username: str = Field(min_length=1, max_length=64)
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class RecoveryLoginResponse(BaseModel):
    token: str
    user_id: str
    expires_in: int
    role: str = "user"
    # Same additive contract as TokenResponse: which client crypto flow
    # the account is on.
    key_scheme: str = "v1"
    # The client-sealed data-key copy: only the recovery key opens it.
    recovery_wrapped_data_key: str


class RecoveryPasswordResetRequest(StrictRequestModel):
    """PUT /account/recovery/password — set a brand-new password using the
    RECOVERY key as the proof (the old password is unknown by definition).

    Same swap as PUT /account/password (salt + scrypt verifier + data-key
    envelope, one transaction, epoch bump) with the same X-Processing-Token
    possession probe — the popped key must authenticate stored ciphertext,
    so a recovery key alone can never overwrite the envelope with garbage.
    """

    proof: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    new_salt: str = Field(min_length=1, max_length=MAX_SALT_B64)
    new_verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)
    new_kdf_params: object | None = None
    wrapped_data_key: str = Field(min_length=1, max_length=MAX_WRAPPED_DATA_KEY_B64)


class KeyEnvelopeUpgradeRequest(StrictRequestModel):
    """POST /account/key-envelope/upgrade — v1 -> v2 self-service migration.

    After a v1 client unlocks locally (it holds the data key), it MAY wrap
    that SAME random-or-derived key under the password-derived KEK and
    upload the envelope, flipping the account to key_scheme="v2". From
    then on password changes are O(1). Verifier-gated (password
    re-authentication, like every destructive lifecycle action) AND
    possession-gated: the X-Processing-Token header must carry a live
    session whose key authenticates the account's stored ciphertext —
    the server cannot otherwise distinguish "the real data key" from any
    32 bytes.
    """

    kdf_params: object | None = None
    wrapped_data_key: str = Field(min_length=1, max_length=MAX_WRAPPED_DATA_KEY_B64)


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


class TotpEnableResponse(BaseModel):
    """Enable confirmation + the one-time recovery-code set (2026-09-26
    pentest S-3). The codes are returned EXACTLY ONCE, here: the server
    keeps only HMAC digests, so a lost set cannot be re-displayed — losing
    every code AND the authenticator is the documented operator path."""

    backup_codes: list[str]


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


class VoiceConsentRequest(StrictRequestModel):
    """Opting into third-party speech-to-text is explicit, per-user, and
    re-authenticated — it gates sending recorded audio off-server
    (VOICE_PLAN.md). Same shape as LlmConsentRequest."""

    enabled: bool
    verifier: str = Field(min_length=1, max_length=MAX_VERIFIER_B64)


class VoiceConsentResponse(BaseModel):
    enabled: bool
    # Same stale-choice honesty as LlmConsentResponse: false once the
    # configured STT policy changed under a recorded yes.
    active_for_current_policy: bool = False
    voice_consent_at: datetime | None = None
    voice_consent_disclosure: str | None = None
    voice_consent_policy: str | None = None


# Voice journaling request/response schemas (VOICE_PLAN.md). The audio_b64
# ceiling is a generous STATIC bound: the live route cap is the middleware's
# route-scoped settings.audio_max_body_bytes (4 MiB default); this field cap
# only bounds pydantic's own work before the route runs.
MAX_AUDIO_B64 = 6_000_000
MAX_AUDIO_MIME_CHARS = 64
# A transcript is journal-sized text (mirrors the analysis corpus bound);
# source_lang is a bare ISO 639-1 code when the client knows it.
MAX_TRANSLATION_TEXT_CHARS = 100_000
LANGUAGE_CODE_PATTERN = r"^[a-z]{2}(-[A-Za-z0-9]{2,8})?$"


class AudioTranscriptionRequest(StrictRequestModel):
    audio_b64: str = Field(min_length=1, max_length=MAX_AUDIO_B64)
    mime: str = Field(min_length=3, max_length=MAX_AUDIO_MIME_CHARS)
    # Client-declared recording length; the route tightens the bound to
    # settings.audio_max_duration_seconds.
    duration_seconds: int = Field(ge=1, le=86_400)


class AudioTranscriptionResponse(BaseModel):
    original_text: str
    # ISO 639-1 when the provider's detected language was recognized.
    language: str | None = None
    # The provider's own language string, preserved for debugging/diagrams.
    language_raw: str = ""
    # Null when translation was unavailable (LLM unconfigured / failed) —
    # degraded mode, not an error: the original transcript stands alone.
    english_text: str | None = None
    provider_name: str = ""
    policy_version: str = ""


class AudioTranslationRequest(StrictRequestModel):
    """Re-translate an EDITED transcript before saving (payload v3 keeps
    english_text in sync with the saved text)."""

    text: str = Field(min_length=1, max_length=MAX_TRANSLATION_TEXT_CHARS)
    source_lang: str | None = Field(default=None, pattern=LANGUAGE_CODE_PATTERN)


class AudioTranslationResponse(BaseModel):
    english_text: str | None = None


class AudioAttachmentCreate(StrictRequestModel):
    """Upload (or replace) the kept recording for one entry. The blob is
    the patient-side AES-GCM envelope (nonce||ct||tag, base64) under the
    audio AAD — opaque to the server."""

    client_entry_id: str = Field(pattern=CLIENT_ID_PATTERN)
    blob: str = Field(min_length=1, max_length=MAX_AUDIO_B64)
    mime: str = Field(min_length=3, max_length=MAX_AUDIO_MIME_CHARS)
    duration_seconds: int = Field(ge=1, le=86_400)


class AudioAttachmentOut(BaseModel):
    """Full attachment fetch (owner or consented therapist): the encrypted
    blob plus the metadata needed to label and play it client-side."""

    id: str
    client_entry_id: str
    blob: str
    mime_type: str
    duration_seconds: int
    size_bytes: int
    created_at: datetime
    expires_at: datetime


class AudioAttachmentCreated(BaseModel):
    attachment_id: str
    expires_at: datetime
    size_bytes: int


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
    # Voice journaling (2026-09-29, additive — older clients ignore it).
    # Same L-31 discipline as llm_*: every stt_* field is None unless the
    # feature flag AND an STT endpoint are both live.
    audio_available: bool = False
    stt_provider_name: str | None = None
    stt_data_retention: str | None = None
    stt_policy_fingerprint: str | None = None


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
    # 2026-09-28 deep audit (models INFO): additive state_seq — the export
    # bundle is the only insight read that omitted it, so a client
    # re-importing its own document could not run the echo-vs-embedded
    # equality check the live API contract promises. 0 for legacy bundles.
    state_seq: int = 0


class AudioExportRow(BaseModel):
    """One kept recording in the account export (additive, 2026-09-29)."""

    id: str
    client_entry_id: str
    mime_type: str
    duration_seconds: int
    size_bytes: int
    expires_at: datetime
    blob: str  # base64 of the stored ciphertext object


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
    # Kept voice recordings (2026-09-29 deep audit, additive): the export
    # used to omit every kept AudioAttachment, so "export my data" before
    # deletion silently destroyed the patient's recordings (portability
    # gap, GDPR Art. 20). Each row is the attachment's metadata plus the
    # base64 ciphertext object exactly as stored (still client-encrypted;
    # decrypts with the data key under the audio AAD binding).
    audio: list[AudioExportRow] = []
    # Wellbeing measures (2026-09-20 audit fix H-3): the export bundle used
    # to omit every Measure row, so the README's export-then-delete flow
    # silently destroyed the patient's entire PHQ-9 history. Additive — old
    # bundles decrypt unchanged; rows are the same MeasureOut shape the
    # /measures endpoints serve, ciphertext bound to AAD
    # ("measure", user_id, client_measure_id) exactly as the client
    # encrypted it.
    measures: list[MeasureOut] = []
    # v2 key scheme (2026-09-26, additive): the wrapped data-key envelope and
    # the account's kdf_params travel with the user's own document — for a
    # v2 account they are as essential as the salt (without them the random
    # data key is unrecoverable and the export is undecryptable after
    # account deletion). Null/absent for v1 accounts and old bundles: the
    # password-derived flow needs only the salt.
    key_scheme: str = "v1"
    wrapped_data_key: str | None = None
    kdf_params: dict[str, int | str] | None = None


def entry_out(row: Entry, audio: "AudioAttachmentMeta | None" = None) -> EntryOut:
    """Entry row -> wire shape; the one construction shared by the entries
    router and the account export.

    ``content_version`` coalesces to 1: the column default applies at flush
    time, so an unflushed ORM instance (test doubles, in-memory constructs)
    still renders — and no stored row can legitimately be below 1.
    ``audio`` (VOICE_PLAN 2026-09-29) is the caller's joined unexpired-
    attachment metadata, if any — kept a parameter so callers that do not
    join (account export) simply omit it.
    """
    return EntryOut(
        id=row.id,
        client_entry_id=row.client_entry_id,
        blob=base64.b64encode(bytes(row.blob)).decode("ascii"),
        entry_date=row.entry_date,
        received_at=row.received_at,
        content_version=row.content_version if row.content_version is not None else 1,
        audio=audio,
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
    # SAS out-of-band verification (2026-09-26 remediation): the 6-digit
    # string ("123 456") derived from HMAC(pairing_code, wrap-key DER +
    # patient user id) and the wrap key's SHA-256 fingerprint (first 16
    # hex). The therapist's portal derives and displays the SAME pair for
    # the same live pairing session (GET /therapist/pairing/sas); the two
    # humans compare them out of band before the patient confirms the
    # grant — a malicious server substituting its own wrap key changes
    # both values. Additive fields: older clients ignore them.
    sas: str = ""
    wrap_key_fingerprint: str = ""


class TherapistPairingSasResponse(BaseModel):
    """The therapist-side half of the out-of-band pairing comparison.

    Same SAS construction as the patient's pairing/lookup response, over
    the therapist's CURRENT live pairing session and the named patient;
    the portal displays it next to the wrap-key fingerprint."""

    sas: str
    wrap_key_fingerprint: str
    # How much longer the underlying pairing code lives (seconds) — lets
    # the portal warn "request a fresh code" instead of comparing a SAS
    # that is about to expire.
    expires_in: int


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
    # so a client that rotated its data key can re-wrap it to the same
    # therapist (PUT /consents/{id}/rewrap) without a new pairing round-trip.
    # Absent on legacy rows is impossible (registration requires the key);
    # the None default keeps the field additive for older serialized copies.
    therapist_wrap_pub_key: str | None = None
    # Additive (2026-09-29, VOICE_PLAN): whether the patient lets this
    # therapist fetch kept voice recordings (default false; toggled via
    # PUT /consents/{id}/share-voice).
    share_voice: bool = False


class ConsentRewrapRequest(StrictRequestModel):
    """Re-wrap the data key of an ACTIVE consent to the same therapist.

    Sent by the client after POST /processing/rekey rotated the account's
    data key: the old wrapped_key opened the PREVIOUS key and is now dead
    weight. Same shape/validation as the grant payload's key fields, and
    the same password re-auth (X-Account-Verifier): a stolen bearer must not
    be able to substitute key material inside a live share.
    """

    ephemeral_pub: str = Field(min_length=1, max_length=MAX_SPKI_B64)
    wrapped_key: str = Field(min_length=1, max_length=MAX_WRAP_B64)


class ShareVoiceRequest(StrictRequestModel):
    """Toggle the per-therapist voice-sharing grant (VOICE_PLAN 2026-09-29).

    Password re-auth rides the X-Account-Verifier header (the revoke
    convention): a stolen bearer must not be able to widen a share to the
    patient's actual voice."""

    enabled: bool


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
    # Voice-sharing grant (VOICE_PLAN P5, remediation 2026-09-29): present
    # (true/false) on ACTIVE consents so the portal roster can show which
    # patients let this therapist hear recordings; None while revoked
    # (a revoked grant shares nothing, and the older backend contract
    # predating the field also yields None — consumers fail closed).
    share_voice: bool | None = None


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


class MeasureDeleteResponse(BaseModel):
    """Outcome of the verifier-gated measure correction delete (2026-09-26
    audit item 21). The post-delete collection marker is echoed in the body
    AND the X-Measures-Revision header, so a paged-sync client can resume
    without an extra GET — exactly how the entry delete exposes its
    marker."""

    measures_revision: int


class NoteCreateRequest(StrictRequestModel):
    client_note_id: str = Field(pattern=CLIENT_ID_PATTERN)
    # min_length=1 (2026-09-20 audit fix L-29): an EMPTY string is not a
    # pid, and silently coercing it to the NULL "general note" semantics
    # let a client bug attach (or detach) a note from a pattern without
    # any error. Explicit null remains the only way to say "no pattern".
    pattern_pid: str | None = Field(default=None, min_length=1, max_length=200)
    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)


class NoteUpdateRequest(StrictRequestModel):
    """PATCH /therapist/notes/{id} payload (2026-09-26 audit item 15).

    Clinical notes now carry optimistic concurrency: the client MUST name
    the note version its edit was based on. ``base_version`` absent is a
    400 ``version_required`` (fail-closed — these are clinical notes, and
    last-write-wins would silently destroy a clinician's edit); a mismatch
    is a 409 ``version_conflict`` (refetch and re-apply). The same
    code convention as the entries' version-bound replacement.
    """

    blob: str = Field(min_length=1, max_length=MAX_BLOB_B64)
    base_version: int | None = Field(default=None, ge=1, le=2**63 - 1)


class NoteOut(BaseModel):
    id: str
    client_note_id: str
    pattern_pid: str | None
    blob: str
    created_at: datetime
    updated_at: datetime
    # Additive (2026-09-26 audit item 15): the note's optimistic-concurrency
    # version — 1 on create, +1 on every changing PATCH. Clients echo it
    # back as NoteUpdateRequest.base_version; older serialized copies
    # without the field still decode (additive response-field rule).
    version: int = 1


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
    # 2026-09-26 audit item 13: the client-declared count of patterns in the
    # opaque payload, so the response can report patterns_stored honestly.
    # The server CANNOT count them itself (the blob is client-encrypted and
    # this path exists precisely so the data key never crosses the wire), so
    # the truthful server-only alternative is 0; absent keeps that old value.
    patterns_count: int | None = Field(default=None, ge=0, le=10_000)


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
