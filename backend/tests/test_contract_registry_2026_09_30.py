"""Error- and logging-contract registries (2026-09-30 campaign).

The campaign showed 341 raise-path and 19 logger-call mutants surviving
every covering test: an error's status/detail and an operator-facing log
message could change with nothing failing. Both ARE contracts here —
deps.py documents error detail as client contract, and the runbooks key
on log prose — so this file freezes the inventory the same way the
tools/check-docs.py verifies the error-code list in docs/api.md: every
raise of an error type with constant status/detail, and every logger call with a
constant message template, per module. A deliberate contract change
regenerates the block below (run this file's module main).

Behavioral pins for the paths that matter most to clients live in
test_deep_mutation_pins.py / test_mutation_pins.py; this registry is the
exhaustive backstop for the long tail.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

BACKEND = Path(__file__).resolve().parents[1]
MODULES = [
    "app/config.py",
    "app/cache.py",
    "app/main.py",
    "app/middleware.py",
    "app/deps.py",
    "app/db.py",
    "app/schemas.py",
    "app/locks.py",
    "app/metrics.py",
    "app/singleprocess.py",
    "app/api/account.py",
    "app/api/audio.py",
    "app/api/auth.py",
    "app/api/consents.py",
    "app/api/entries.py",
    "app/api/insights.py",
    "app/api/measures.py",
    "app/api/meta.py",
    "app/api/therapist.py",
    "app/api/_audit.py",
    "app/api/_paging.py",
    "app/api/_custody.py",
    "app/api/_sharing_state.py",
    "app/security/crypto.py",
    "app/security/deletion_tombstone.py",
    "app/security/enclave.py",
    "app/security/envelope.py",
    "app/security/kdf.py",
    "app/security/sharing.py",
    "app/security/step_up.py",
    "app/security/tokens.py",
    "app/security/totp.py",
    "app/services/account_deletion.py",
    "app/services/audio_store.py",
    "app/services/crisis.py",
    "app/services/llm.py",
    "app/services/patterns.py",
    "app/services/phrases.py",
    "app/services/questions.py",
    "app/services/stt.py",
    "app/services/threshold.py",
    "app/services/brain.py",
]


def _const(node):
    return node.value if isinstance(node, ast.Constant) else None


def _name(node) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _extract(path: Path):
    tree = ast.parse(path.read_text())
    raises, logs = set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
            kwargs = {
                kw.arg: _const(kw.value)
                for kw in node.exc.keywords
                if kw.arg and _const(kw.value) is not None
            }
            name = _name(node.exc.func) or "?"
            if "status_code" in kwargs or "detail" in kwargs or name.endswith("Error"):
                key = tuple(sorted(kwargs.items(), key=repr))
                raises.add((name, key))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in ("exception", "error", "warning", "info")
                and _name(node.func.value)
                and "logger" in _name(node.func.value)
            ):
                if node.args and isinstance(node.args[0], ast.Constant):
                    logs.add((node.func.attr, node.args[0].value))
    return sorted(raises, key=repr), sorted(logs, key=repr)


# frozen 2026-09-30 — regenerate via PYTHONPATH=. python tests/test_contract_registry_2026_09_30.py
FROZEN_REGISTRY = {
    "app/api/_audit.py": [
        (
            "ApiError",
            (
                ("code", "audit_integrity_error"),
                ("detail", "audit chain head differs from durable state"),
                ("status_code", 500),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audit_integrity_error"),
                ("detail", "audit chain state does not verify"),
                ("status_code", 500),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audit_integrity_error"),
                ("detail", "audit chain state is missing"),
                ("status_code", 500),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "internal_error"),
                ("detail", "audit chain append lost the seq race repeatedly"),
                ("status_code", 500),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "malformed cursor"), ("status_code", 422)),
        ),
        ("ApiError", ()),
        ("RuntimeError", ()),
        ("ValueError", ()),
    ],
    "app/api/_custody.py": [
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "custody changed; reload account"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "operation identifier already used"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "forbidden"), ("detail", "not a therapist account"), ("status_code", 403)),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to advance notes revision"),
                ("status_code", 503),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "custody version must advance by one"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "invalid key material"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "password changes must preserve the sharing public key"),
                ("status_code", 422),
            ),
        ),
        ("ValueError", ()),
    ],
    "app/api/_paging.py": [
        ("ApiError", (("code", "payload_too_large"), ("status_code", 413))),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "expected_revision must be a canonical non-negative decimal"),
                ("status_code", 422),
            ),
        ),
    ],
    "app/api/_sharing_state.py": [
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "consent history has reached the retained safety limit"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to advance sharing snapshot"),
                ("status_code", 503),
            ),
        ),
    ],
    "app/api/account.py": [
        (
            "ApiError",
            (
                ("code", "audio_storage_failed"),
                ("detail", "audio export is incomplete; retry"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audio_storage_unconfigured"),
                ("detail", "audio export storage unavailable"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audio_store_error"),
                ("detail", "audio key proof storage unavailable"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "collection_changed"),
                ("detail", "access history changed during export; retry"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "collection_changed"),
                ("detail", "account changed during export; retry"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "collection_changed"),
                ("detail", "analysis changed during export; retry"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "collection_changed"),
                ("detail", "record disappeared during export; retry"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "envelope_key_mismatch"),
                (
                    "detail",
                    "the processing session's key did not authenticate stored ciphertext; open a session with "
                    "the account's current data key",
                ),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "envelope_key_mismatch"),
                ("detail", "stored kdf_params are invalid; contact the operator"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "invalid_credentials"),
                ("detail", "invalid credentials"),
                ("status_code", 401),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "key_scheme_conflict"),
                ("detail", "use the atomic envelope password endpoint"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "llm_unavailable"),
                ("detail", "third-party analysis is not configured on this server"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "account not found"), ("status_code", 404)),
        ),
        ("ApiError", (("code", "not_found"), ("detail", "totp not enabled"), ("status_code", 404))),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "export form too large"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "retained sharing history exceeds the supported export size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "processing_session_invalid"),
                ("detail", "processing session missing or expired"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "processing_session_required"),
                ("detail", "processing session token required (X-Processing-Token)"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "recovery_not_configured"),
                ("detail", "no recovery kit on this account"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "rekey_in_progress"),
                ("detail", "complete the pending key rotation first"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "export service busy; retry shortly"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "step-up service is temporarily at capacity"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "step_up_invalid"),
                ("detail", "step-up proof is invalid, expired, or already used"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "step_up_required"),
                ("detail", "fresh authentication is required for this action"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "stt_unavailable"),
                ("detail", "voice transcription is not configured on this server"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "totp_code_invalid"), ("detail", "invalid totp code"), ("status_code", 403)),
        ),
        (
            "ApiError",
            (("code", "unauthorized"), ("detail", "export session retired"), ("status_code", 401)),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "upgrade_required"),
                ("detail", "legacy recovery setup is retired; create a v2 recovery kit"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "upgrade_required"),
                ("detail", "upgrade the client to atomically rotate keys and credentials"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "account verifier required (X-Account-Verifier header)"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "invalid export form"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "new_salt, new_verifier and wrapped_data_key must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "proof must be exactly 32 bytes"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "proof, new_salt, new_verifier and wrapped_data_key must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "verifier and wrapped_key must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "verifier header required"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "verifier must be exactly 32 bytes"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "wrapped_data_key must be base64"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
        (
            "ApiError",
            (
                ("code", "verification_failed"),
                ("detail", "invalid credentials"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "totp already enabled — disable it (code required) before re-arming"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "totp setup changed, confirm again"),
                ("status_code", 409),
            ),
        ),
        ("AudioStoreError", ()),
    ],
    "app/api/audio.py": [
        (
            "ApiError",
            (
                ("code", "account_deleted"),
                ("detail", "account no longer exists"),
                ("status_code", 410),
            ),
        ),
        (
            "ApiError",
            (("code", "audio_expired"), ("detail", "recording expired"), ("status_code", 410)),
        ),
        (
            "ApiError",
            (
                ("code", "audio_quota_exceeded"),
                ("detail", "audio storage quota reached"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audio_storage_failed"),
                ("detail", "audio storage failed"),
                ("status_code", 502),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audio_storage_failed"),
                ("detail", "audio storage failed; try again"),
                ("status_code", 502),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audio_storage_unconfigured"),
                ("detail", "audio storage is not configured on this server"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (("code", "audio_too_large"), ("detail", "recording too large"), ("status_code", 413)),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "attachment not found"), ("status_code", 404)),
        ),
        ("ApiError", (("code", "not_found"), ("detail", "not found"), ("status_code", 404))),
        (
            "ApiError",
            (
                ("code", "stt_unconfigured"),
                ("detail", "speech-to-text is not configured on this server"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "stt_upstream"),
                ("detail", "speech-to-text provider failed; try again"),
                ("status_code", 502),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "unknown_entry"),
                ("detail", "no entry with that client_entry_id"),
                ("status_code", 404),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "audio must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "blob must be base64"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "recording duration exceeds the allowed maximum"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "recording is empty"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "unsupported audio format"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
        (
            "ApiError",
            (
                ("code", "voice_consent_required"),
                ("detail", "voice transcription consent required"),
                ("status_code", 403),
            ),
        ),
    ],
    "app/api/auth.py": [
        (
            "ApiError",
            (("code", "conflict"), ("detail", "username already taken"), ("status_code", 409)),
        ),
        (
            "ApiError",
            (
                ("code", "invalid_credentials"),
                ("detail", "invalid credentials"),
                ("status_code", 401),
            ),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "account not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "authentication service busy; retry shortly"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (("code", "totp_code_invalid"), ("detail", "invalid totp code"), ("status_code", 401)),
        ),
        (
            "ApiError",
            (("code", "totp_required"), ("detail", "totp code required"), ("status_code", 401)),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "salt and verifier must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "v2 registration requires kdf_params and wrapped_data_key together"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "wrapped_data_key must be base64"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
    ],
    "app/api/consents.py": [
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "consent already being granted"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "consent is revoked; re-grant it before changing scopes"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "disclosure_outdated"),
                ("detail", "sharing disclosure is outdated; refresh and review it again"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "account not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "consent not found"), ("status_code", 404)),
        ),
        ("ApiError", (("code", "not_found"), ("detail", "not found"), ("status_code", 404))),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "pairing code not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "retained sharing history exceeds the supported list size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "retained sharing history has reached the supported limit"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "sharing history exceeds the supported list size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "sharing history has reached the supported limit"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "therapist caseload has reached the supported limit"),
                ("status_code", 413),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "ephemeral_pub must be a P-256 SPKI key"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
    ],
    "app/api/entries.py": [
        (
            "ApiError",
            (
                ("code", "blob_quota_exceeded"),
                ("detail", "storage quota reached (total size)"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (("code", "conflict"), ("detail", "entry already exists"), ("status_code", 409)),
        ),
        (
            "ApiError",
            (
                ("code", "entry_blob_invalid"),
                ("detail", "entry blob failed authentication"),
                ("status_code", 400),
            ),
        ),
        ("ApiError", (("code", "not_found"), ("detail", "entry not found"), ("status_code", 404))),
        ("ApiError", (("code", "quota_exceeded"), ("status_code", 413))),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to advance entries revision; retry shortly"),
                ("status_code", 503),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "blob must be base64"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "content_version must be 1 on create"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "entry_date cannot be in the future"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "entry_date is before this account existed"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "entry was modified by another device; refetch and retry"),
                ("status_code", 409),
            ),
        ),
    ],
    "app/api/insights.py": [
        (
            "ApiError",
            (
                ("code", "account_deleted"),
                ("detail", "account no longer exists"),
                ("status_code", 410),
            ),
        ),
        (
            "ApiError",
            (("code", "bad_request"), ("detail", "no entries to analyze"), ("status_code", 400)),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "active sharing changed; rebuild the atomic rotation"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "conflict"), ("detail", "audio changed during rekey"), ("status_code", 409)),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "stored analysis cannot be migrated safely"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "the stored brain state moved since this analysis ran"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "therapist sharing key changed; rebuild the atomic rotation"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "entry_blob_invalid"),
                ("detail", "entry blob failed authentication"),
                ("status_code", 400),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "entry_payload_malformed"),
                ("detail", "entry payload malformed"),
                ("status_code", 400),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "entry_payload_malformed"),
                ("detail", "feedback blob is malformed"),
                ("status_code", 400),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "feedback_blob_invalid"),
                ("detail", "feedback blob failed authentication"),
                ("status_code", 400),
            ),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "account not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (
                ("code", "not_found"),
                (
                    "detail",
                    "no question for today; open a processing session and run /insights/recompute",
                ),
                ("status_code", 404),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "active sharing exceeds the supported rotation size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "active sharing exceeds the supported summary size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                (
                    "detail",
                    "analysis blob budget is smaller than the newest entry; refusing to "
                    "analyze an empty corpus",
                ),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "processing_session_invalid"),
                ("detail", "new-key processing session missing or expired"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "processing_session_invalid"),
                ("detail", "processing session missing or expired"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "processing_session_required"),
                ("detail", "missing processing session token"),
                ("status_code", 401),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "rekey_in_progress"),
                ("detail", "complete the pending key rotation before analysis"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "rekey_key_mismatch"),
                (
                    "detail",
                    "old key did not authenticate every blob; already-completed batches "
                    "remain rekeyed and the retry resumes from the journal. Verify the "
                    "account's current data key and retry.",
                ),
                ("status_code", 400),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "rekey_key_mismatch"),
                (
                    "detail",
                    "legacy interrupted rotation contains an unknown key generation; no "
                    "further rows changed",
                ),
                ("status_code", 400),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "rekey_operation_conflict"),
                ("detail", "operation identifier already used"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "rekey_operation_conflict"),
                ("detail", "resume the original operation with the same credentials and keys"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "analysis generation exhausted"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                (
                    "detail",
                    "processing session capacity reached; consume an existing session or "
                    "retry shortly",
                ),
                ("status_code", 503),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "upgrade_required"),
                ("detail", "upgrade the client to atomically rotate keys and credentials"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "a corpus rotation requires a different new data key"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "account verifier required (X-Account-Verifier header)"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "analysis_dates must be ISO dates"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "analysis_dates must carry between 1 and 366 dates"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "base_state_seq must be >= 0"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "blobs must be within the storage size bounds"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "duplicate consent identifier"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "invalid consent envelope size"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "invalid credential encoding"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "invalid credential size"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "invalid data key envelope size"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "invalid sharing key"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "state_blob and patterns_blob must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                (
                    "detail",
                    "two processing session tokens required (X-Processing-Token, "
                    "X-New-Processing-Token)",
                ),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "v1 rotation cannot install a v2 envelope"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "v2 rotation requires the new envelope and KDF parameters"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
        ("ValueError", ()),
    ],
    "app/api/measures.py": [
        (
            "ApiError",
            (("code", "conflict"), ("detail", "measure already exists"), ("status_code", 409)),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "measure not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (
                ("code", "quota_exceeded"),
                ("detail", "measure quota exceeded"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to advance measures revision; retry shortly"),
                ("status_code", 503),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "account verifier required (X-Account-Verifier header)"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "blob must be base64"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "measure_date cannot be in the future"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "measure_date cannot predate the account"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
    ],
    "app/api/therapist.py": [
        (
            "ApiError",
            (("code", "audio_expired"), ("detail", "recording expired"), ("status_code", 410)),
        ),
        (
            "ApiError",
            (
                ("code", "audio_storage_failed"),
                ("detail", "audio storage failed"),
                ("status_code", 502),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "audio_storage_unconfigured"),
                ("detail", "audio storage is not configured on this server"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "blob_quota_exceeded"),
                ("detail", "note storage quota reached (total size)"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "custody changed; reload account"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "install notes custody before rotating sharing keys"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "conflict"), ("detail", "note already exists"), ("status_code", 409)),
        ),
        (
            "ApiError",
            (
                ("code", "conflict"),
                ("detail", "note id already used for another patient"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (("code", "conflict"), ("detail", "username already taken"), ("status_code", 409)),
        ),
        (
            "ApiError",
            (
                ("code", "consent_voice_share_required"),
                ("detail", "patient has not shared voice recordings"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "forbidden"),
                ("detail", "account verifier required (X-Account-Verifier header)"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "account not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "attachment not found"), ("status_code", 404)),
        ),
        ("ApiError", (("code", "not_found"), ("detail", "not found"), ("status_code", 404))),
        ("ApiError", (("code", "not_found"), ("detail", "note not found"), ("status_code", 404))),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "note revision not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "pairing code not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (("code", "not_found"), ("detail", "patient not found"), ("status_code", 404)),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "active sharing exceeds the supported rotation size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "patient list exceeds the supported caseload size"),
                ("status_code", 413),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "payload_too_large"),
                ("detail", "retained patient history exceeds the supported list size"),
                ("status_code", 413),
            ),
        ),
        ("ApiError", (("code", "quota_exceeded"), ("status_code", 413))),
        (
            "ApiError",
            (
                ("code", "rekey_in_progress"),
                ("detail", "an active patient must finish their pending key rotation first"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to advance notes revision; retry shortly"),
                ("status_code", 503),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to allocate a unique pairing code; retry shortly"),
                ("status_code", 503),
            ),
        ),
        ("ApiError", (("code", "unauthorized"), ("detail", "invalid token"), ("status_code", 401))),
        (
            "ApiError",
            (
                ("code", "upgrade_required"),
                ("detail", "upgrade the client before writing notes"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "account verifier required (X-Account-Verifier header)"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (("code", "validation_error"), ("detail", "blob must be base64"), ("status_code", 422)),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "duplicate note identifier"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "duplicate revision identifier"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "rekey blob length mismatch (the content must be unchanged)"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "rekey revision blob length mismatch"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "revision blob must be base64"),
                ("status_code", 422),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "validation_error"),
                ("detail", "salt and verifier must be base64"),
                ("status_code", 422),
            ),
        ),
        ("ApiError", (("code", "validation_error"), ("status_code", 422))),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                (
                    "detail",
                    "a different note with this client_note_id already exists; edit it "
                    "with PATCH and a base_version",
                ),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "note changed; refetch"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "note was modified by another device; refetch and retry"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "notes custody changed; reload account"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "revision changed; refetch"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_conflict"),
                ("detail", "revision history changed or incomplete; refetch"),
                ("status_code", 409),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "version_required"),
                ("detail", "base_version is required (send the note version the edit is based on)"),
                ("status_code", 400),
            ),
        ),
    ],
    "app/cache.py": [("ValueError", ())],
    "app/config.py": [("RuntimeError", ()), ("ValueError", ())],
    "app/deps.py": [
        (
            "ApiError",
            (
                ("code", "account_deleted"),
                ("detail", "account no longer exists"),
                ("status_code", 410),
            ),
        ),
        (
            "ApiError",
            (("code", "forbidden"), ("detail", "not a therapist account"), ("status_code", 403)),
        ),
        (
            "ApiError",
            (
                ("code", "forbidden"),
                ("detail", "therapist accounts cannot access journal endpoints"),
                ("status_code", 403),
            ),
        ),
        (
            "ApiError",
            (
                ("code", "mfa_enrollment_required"),
                ("detail", "multi-factor enrollment is required before accessing patient data"),
                ("status_code", 403),
            ),
        ),
        ("ApiError", (("code", "not_found"), ("detail", "not found"), ("status_code", 404))),
        (
            "ApiError",
            (
                ("code", "rekey_in_progress"),
                ("detail", "complete the pending key rotation before writing"),
                ("status_code", 409),
            ),
        ),
    ],
    "app/locks.py": [("ValueError", ())],
    "app/main.py": [
        ("RuntimeError", ()),
        ("StarletteHTTPException", (("detail", "metrics token required"), ("status_code", 401))),
        ("StarletteHTTPException", (("detail", "not found"), ("status_code", 404))),
    ],
    "app/middleware.py": [("ValueError", ())],
    "app/security/crypto.py": [("CryptoError", ()), ("TamperError", ())],
    "app/security/enclave.py": [("ValueError", ())],
    "app/security/envelope.py": [("ValueError", ())],
    "app/security/kdf.py": [("KdfParamsError", ()), ("ValueError", ())],
    "app/security/sharing.py": [("SharingError", ())],
    "app/security/step_up.py": [("RuntimeError", ())],
    "app/security/tokens.py": [("TokenError", ()), ("ValueError", ())],
    "app/services/account_deletion.py": [("RuntimeError", ())],
    "app/services/audio_store.py": [
        (
            "ApiError",
            (
                ("code", "service_unavailable"),
                ("detail", "unable to advance attachment revision"),
                ("status_code", 503),
            ),
        ),
        ("AudioStoreError", ()),
        ("ValueError", ()),
        ("sqlite3.DatabaseError", ()),
    ],
    "app/services/llm.py": [("ValueError", ())],
    "app/services/patterns.py": [("ValueError", ())],
    "app/services/stt.py": [("RuntimeError", ()), ("ValueError", ())],
    "app/services/threshold.py": [("ValueError", ())],
    "app/singleprocess.py": [("LockPathError", ()), ("MultipleWorkersError", ())],
}
FROZEN_LOGS = {
    "app/api/_audit.py": [
        ("error", "audit journal append failed; readiness is now unhealthy"),
        ("error", "audit journal contains malformed evidence at line %d"),
    ],
    "app/api/account.py": [("error", "bounded account purge deferred to background worker")],
    "app/api/audio.py": [
        ("warning", "audio object get failed"),
        ("warning", "audio object put failed"),
        ("warning", "stt upstream failed"),
    ],
    "app/api/therapist.py": [
        ("error", "bounded therapist purge deferred to background worker"),
        ("warning", "audio object get failed"),
    ],
    "app/config.py": [
        (
            "warning",
            "MINDPATTERN_LLM_URL is set but MINDPATTERN_LLM_API_KEY is empty — LLM "
            "requests will go out without an API key",
        ),
        (
            "warning",
            "MINDPATTERN_STT_URL is set but MINDPATTERN_STT_API_KEY is empty — STT "
            "requests will go out without an API key",
        ),
    ],
    "app/main.py": [
        ("error", "account deletion sweep failed; category=%s; retrying with bounded backoff"),
        ("error", "audio retention sweep failed unexpectedly; retrying next cycle"),
        ("error", "audit chain verification failed for %d owner(s)"),
        ("error", "audit journal compaction failed; retrying next cycle"),
        ("error", "audit maintenance refused: MAC key ring is invalid"),
        ("error", "cross-host ownership lost; admission is closed until restart"),
        ("error", "initial housekeeping pass failed; retrying shortly"),
        ("error", "processing-key expiry sweep failed; retrying shortly"),
        ("error", "readiness check failed: database or schema unavailable"),
        ("error", "retention sweep failed; retrying shortly"),
        ("info", "audio retention sweep removed %d expired attachment(s)"),
        ("info", "audit journal compacted: %d lines kept, %d older than %s dropped"),
        (
            "warning",
            "MINDPATTERN_TRUST_PROXY_HEADERS is on: rate-limit identity comes only from "
            "X-Forwarded-For received over a direct peer in "
            "MINDPATTERN_TRUSTED_PROXY_IPS=%s. Keep the API unreachable except through that "
            "proxy, which must append its observation; do not enable uvicorn --proxy-headers "
            "because this middleware needs the raw peer to verify the boundary.",
        ),
        ("warning", "audio retention sweep deferred after storage failure"),
        ("warning", "pg_advisory_unlock failed; disconnect releases the lock"),
        ("warning", "token-revocation hydration skipped because storage is unavailable"),
    ],
    "app/middleware.py": [
        ("error", "unhandled request failure"),
        (
            "warning",
            "X-Forwarded-For chain contained only trusted-proxy addresses; rate "
            "limiting falls back to the proxy address for such requests (one shared "
            "bucket). If this recurs, MINDPATTERN_TRUSTED_PROXY_IPS is probably too "
            "broad.",
        ),
        (
            "warning",
            "X-Forwarded-For ignored: MINDPATTERN_TRUST_PROXY_HEADERS is off or the "
            "direct peer is outside MINDPATTERN_TRUSTED_PROXY_IPS; rate limiting keys "
            "on the direct peer",
        ),
    ],
    "app/services/audio_store.py": [
        ("warning", "audio deletion deferred after object-store failure"),
        (
            "warning",
            "audio lifecycle reconciliation deferred %d object(s); storage error class(es): %s",
        ),
    ],
    "app/services/llm.py": [
        ("warning", "llm enrichment failed; continuing with deterministic patterns only")
    ],
    "app/services/stt.py": [
        ("warning", "transcript translation failed; returning untranslated"),
        ("warning", "transcript translation was incomplete; returning untranslated"),
    ],
    "app/singleprocess.py": [
        ("warning", "could not tighten permissions on lock dir %r"),
        (
            "warning",
            "single-process lock path %r no longer names the locked inode; an "
            "external unlinked it — a second boot could now fragment in-process "
            "guarantees. Point %s at a persistent directory.",
        ),
    ],
}
FROZEN_LOGS = {
    "app/api/_audit.py": [
        ("error", "audit journal append failed; readiness is now unhealthy"),
        ("error", "audit journal contains malformed evidence at line %d"),
    ],
    "app/api/account.py": [("error", "bounded account purge deferred to background worker")],
    "app/api/audio.py": [
        ("warning", "audio object get failed"),
        ("warning", "audio object put failed"),
        ("warning", "stt upstream failed"),
    ],
    "app/api/therapist.py": [
        ("error", "bounded therapist purge deferred to background worker"),
        ("warning", "audio object get failed"),
    ],
    "app/config.py": [
        (
            "warning",
            "MINDPATTERN_LLM_URL is set but MINDPATTERN_LLM_API_KEY is empty — LLM "
            "requests will go out without an API key",
        ),
        (
            "warning",
            "MINDPATTERN_STT_URL is set but MINDPATTERN_STT_API_KEY is empty — STT "
            "requests will go out without an API key",
        ),
    ],
    "app/main.py": [
        ("error", "account deletion sweep failed; category=%s; retrying with bounded backoff"),
        ("error", "audio retention sweep failed unexpectedly; retrying next cycle"),
        ("error", "audit chain verification failed for %d owner(s)"),
        ("error", "audit journal compaction failed; retrying next cycle"),
        ("error", "audit maintenance refused: MAC key ring is invalid"),
        ("error", "cross-host ownership lost; admission is closed until restart"),
        ("error", "initial housekeeping pass failed; retrying shortly"),
        ("error", "processing-key expiry sweep failed; retrying shortly"),
        ("error", "readiness check failed: database or schema unavailable"),
        ("error", "retention sweep failed; retrying shortly"),
        ("info", "audio retention sweep removed %d expired attachment(s)"),
        ("info", "audit journal compacted: %d lines kept, %d older than %s dropped"),
        (
            "warning",
            "MINDPATTERN_TRUST_PROXY_HEADERS is on: rate-limit identity comes only from "
            "X-Forwarded-For received over a direct peer in "
            "MINDPATTERN_TRUSTED_PROXY_IPS=%s. Keep the API unreachable except through that "
            "proxy, which must append its observation; do not enable uvicorn --proxy-headers "
            "because this middleware needs the raw peer to verify the boundary.",
        ),
        ("warning", "audio retention sweep deferred after storage failure"),
        ("warning", "pg_advisory_unlock failed; disconnect releases the lock"),
        ("warning", "token-revocation hydration skipped because storage is unavailable"),
    ],
    "app/middleware.py": [
        ("error", "unhandled request failure"),
        (
            "warning",
            "X-Forwarded-For chain contained only trusted-proxy addresses; rate "
            "limiting falls back to the proxy address for such requests (one shared "
            "bucket). If this recurs, MINDPATTERN_TRUSTED_PROXY_IPS is probably too "
            "broad.",
        ),
        (
            "warning",
            "X-Forwarded-For ignored: MINDPATTERN_TRUST_PROXY_HEADERS is off or the "
            "direct peer is outside MINDPATTERN_TRUSTED_PROXY_IPS; rate limiting keys "
            "on the direct peer",
        ),
    ],
    "app/services/audio_store.py": [
        ("warning", "audio deletion deferred after object-store failure"),
        (
            "warning",
            "audio lifecycle reconciliation deferred %d object(s); storage error class(es): %s",
        ),
    ],
    "app/services/llm.py": [
        ("warning", "llm enrichment failed; continuing with deterministic patterns only")
    ],
    "app/services/stt.py": [
        ("warning", "transcript translation failed; returning untranslated"),
        ("warning", "transcript translation was incomplete; returning untranslated"),
    ],
    "app/singleprocess.py": [
        ("warning", "could not tighten permissions on lock dir %r"),
        (
            "warning",
            "single-process lock path %r no longer names the locked inode; an "
            "external unlinked it — a second boot could now fragment in-process "
            "guarantees. Point %s at a persistent directory.",
        ),
    ],
}

REGISTRY, LOGS = {}, {}
for _rel in MODULES:
    _r, _l = _extract(BACKEND / _rel)
    if _r:
        REGISTRY[_rel] = _r
    if _l:
        LOGS[_rel] = _l


def test_error_contract_module_inventory():
    """A module gaining or losing its first constant error remains visible."""
    assert set(REGISTRY) == set(FROZEN_REGISTRY)


def test_log_contract_module_inventory():
    """A module gaining or losing its first constant log remains visible."""
    assert set(LOGS) == set(FROZEN_LOGS)


@pytest.mark.parametrize("rel", sorted(FROZEN_REGISTRY))
def test_error_contract_registry(rel):
    """Every raise with constant status/detail/code kwargs, frozen per module."""
    got, _ = _extract(BACKEND / rel)
    assert got == FROZEN_REGISTRY[rel], (
        f"{rel}'s error contract changed — if deliberate, regenerate the "
        "FROZEN_* blocks via PYTHONPATH=. python tests/test_contract_registry_2026_09_30.py"
    )


@pytest.mark.parametrize("rel", sorted(FROZEN_LOGS))
def test_log_contract_registry(rel):
    """Every constant logger message template, frozen per module."""
    _, got_logs = _extract(BACKEND / rel)
    assert got_logs == FROZEN_LOGS[rel], (
        f"{rel}'s logging contract changed — if deliberate, regenerate the "
        "FROZEN_* blocks via PYTHONPATH=. python tests/test_contract_registry_2026_09_30.py"
    )


if __name__ == "__main__":
    print("FROZEN_REGISTRY = {")
    for rel, rows in sorted(REGISTRY.items()):
        print(f'    "{rel}": [')
        for name, kwargs in rows:
            print(f"        ({name!r}, {kwargs!r}),")
        print("    ],")
    print("}")
    print("FROZEN_LOGS = {")
    for rel, rows in sorted(LOGS.items()):
        print(f'    "{rel}": {rows!r},')
    print("}")
