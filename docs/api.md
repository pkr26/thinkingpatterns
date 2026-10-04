# API contract

The canonical route prefix is `/api/v1`. The deprecated `/api` alias remains
available for existing clients and returns `Deprecation: true`. Clients discover
the API version through `/api/v1/meta`. Development mode exposes the generated
OpenAPI documentation at `/docs`; production disables it.

## Authentication and content

Clients derive authentication and encryption keys locally. The API receives
verifiers and encrypted content. See the [architecture guide](architecture.md)
for key envelopes, server processing sessions, therapist consent, and recovery.

Sensitive operations require fresh authentication. The web client can use an
action-bound, single-use step-up proof; native clients retain the immediate
verifier compatibility path. Account deletion accepts the verifier in
`X-Account-Verifier`; the JSON-body fallback is deprecated.

Key-envelope routes include `GET /auth/key-envelope`, `PUT /account/password`,
and `POST /account/key-envelope/upgrade`. Full data-key rotation uses the
resumable processing rekey contract. All of these paths use the canonical
prefix above; credential-only changes must not bypass data-key custody.

Patient measures use `POST/GET /measures` and `DELETE /measures/{id}`.
Therapist reads use `GET /therapist/patients/{id}/measures` under active consent.
Measure ciphertext is bound to its account and object with the `measure` AAD
context. Deletion requires fresh authentication and records an audit event.

## Pagination and concurrent changes

Entry and measure collections support byte-bounded pages with `page_bytes` and
`X-Next-Offset`. Oversized legacy pages fail explicitly. Clients pass the returned
collection revision back as `expected_revision`; a concurrent mutation returns
`collection_changed` and requires restarting the traversal. Measure pages use
`X-Measures-Revision`. Creates, deletions, and rekeys advance the relevant
collection revision.

Object replacements compare the supplied version with the stored version.
A stale replacement returns `version_conflict`. Clinical-note edits require
`base_version`; omitting it returns `version_required`.

Access history is available through `GET /account/access-log` and
`GET /therapist/access-log`, with `X-Next-Cursor` continuation. The history is
metadata and remains subject to the configured retention policy.

## Operational endpoints

- `/healthz`: process liveness without a database query.
- `/readyz`: database and runtime readiness, including ownership and audit health.
- `/metrics`: aggregate operational counters, protected by the configured metrics token.

## Error envelope

Errors use `{"detail": "human-readable message", "code": "snake_case"}`.
Clients branch on `code`; they must not expose arbitrary server text in dialogs.
Validation errors do not echo request input. Rate-limit responses include
`Retry-After`.

The tables below include every literal code emitted by the backend and its
status-default mapping. `python tools/check-docs.py` enforces coverage in CI.

### Authentication and authorization

| Code | Meaning |
| --- | --- |
| `unauthorized` | Authentication is missing, expired, or invalid |
| `invalid_credentials` | Login credentials were rejected |
| `forbidden` | Role, ownership, or access policy denies the request |
| `verification_failed` | Fresh password verification failed |
| `step_up_required` | This action needs fresh, action-bound authentication |
| `step_up_invalid` | The step-up proof is invalid, expired, or already consumed |
| `mfa_enrollment_required` | A therapist must enroll a second factor before patient-data access |
| `totp_required` | Login requires the account's second factor |
| `totp_code_invalid` | A factor code is invalid, outside the accepted window, or already used |
| `disclosure_outdated` | The sharing disclosure has changed since acceptance |
| `consent_voice_share_required` | Retained audio is outside the current sharing consent |
| `voice_consent_required` | Speech processing requires separate consent |

### Data, versions, and limits

| Code | Meaning |
| --- | --- |
| `account_deleted` | The account was deleted during the operation |
| `collection_changed` | Restart pagination against a fresh collection revision |
| `version_conflict` | Another writer changed the object; refetch before retrying |
| `version_required` | An update omitted its required base version |
| `entry_blob_invalid` | Entry ciphertext failed validation |
| `entry_payload_malformed` | Decrypted entry content has an invalid shape |
| `feedback_blob_invalid` | Encrypted feedback failed validation |
| `payload_too_large` | The request or legacy response exceeds the supported byte limit |
| `quota_exceeded` | An account resource quota was reached |
| `blob_quota_exceeded` | An encrypted-content byte quota was reached |
| `rate_limited` | Retry after the indicated delay |
| `unknown_entry` | Audio refers to an entry that cannot be resolved |

### Processing, key custody, and recovery

| Code | Meaning |
| --- | --- |
| `processing_session_required` | The action needs an explicit processing session |
| `processing_session_invalid` | The processing session cannot be used |
| `rekey_in_progress` | An active key rotation blocks the operation |
| `rekey_key_mismatch` | The supplied rotation key did not authenticate stored ciphertext |
| `rekey_operation_conflict` | The request conflicts with the saved rotation operation |
| `key_scheme_conflict` | The credential operation is incompatible with the account key scheme |
| `envelope_key_mismatch` | The envelope upgrade key did not authenticate account content |
| `recovery_not_configured` | The account has no configured recovery material |
| `upgrade_required` | This operation requires a supported account or client upgrade |
| `audit_integrity_error` | Required access-audit integrity verification failed |
| `llm_unavailable` | The legacy provider-consent path is unavailable in this deployment |

### Speech and retained audio

| Code | Meaning |
| --- | --- |
| `audio_too_large` | The recording exceeds the per-object limit |
| `audio_quota_exceeded` | Retained audio exceeds the account quota |
| `audio_expired` | The retained recording has expired |
| `audio_storage_unconfigured` | No usable audio storage backend is configured |
| `audio_storage_failed` | An audio persistence operation failed |
| `audio_store_error` | The audio object store reported an error |
| `stt_unconfigured` | No transcription provider is configured |
| `stt_unavailable` | Transcription is unavailable |
| `stt_upstream` | The transcription provider request failed |

### General status defaults

`bad_request`, `not_found`, `method_not_allowed`, `request_timeout`, `conflict`,
`gone`, `validation_error`, `internal_error`, and `service_unavailable` provide
consistent defaults for their HTTP error classes. `error` is the fallback for
an otherwise unmapped status.
