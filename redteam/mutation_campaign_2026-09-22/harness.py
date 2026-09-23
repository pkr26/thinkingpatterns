#!/usr/bin/env python3
"""Behavioral mutation campaign, round 4 (2026-09-22): everything the deep
audits shipped AFTER round 3.

Rounds 1-3 (2026-09-18/19) covered the brain engine, crypto contracts,
crisis handling, sharing, authorization, DB/ORM, boundaries, error
handling, cache and rate limiting as of 2026-09-19. Since then the
2026-09-21/22 deep-audit waves landed large NEW surfaces this campaign
now targets with the same discipline: snapshot the target file's bytes,
apply ONE semantic mutation, run the targeted suite(s), restore the bytes
exactly (byte-wise, never git), record killed/survived + the failing
tests. Survivors are re-verified against the full fast suite by
verify_survivors.py; genuine survivors get pin tests or documented
residual entries.

  U  TOTP second factor (2026-09-21 audit C-2/F-4): the login gate, the
     missing-code machine-readable challenge, wrong-code rejection, the
     strictly-greater replay fence, the login counter persist, the
     setup-while-enabled refusal (factor stripping), the enable-time
     counter consumption, the disable replay fence, the RFC drift window.
  V  Measures / measurement-based care (M-4/L-5/L-6/L-7/M-3/A-3/A-7):
     per-account quota, date grace windows, legacy 2 MiB 413, the
     page_bytes budget walk, has_more/continuation arithmetic, the
     create-must-advance-revision coupling, the fail-closed increment
     guard, the final-drift fence (patient AND therapist mirror), the
     disclosure-version gate, the mirror byte sanity.
  W  Therapist note edit history (P3/V-4): the changed-detection that
     decides revision writes, the superseded-blob append, the
     superseded-vs-new blob identity, the idempotent-retry inner guard,
     the marker coupling on update AND create, revision-read scoping,
     newest-first ordering, the history page cap.
  X  Entry content versioning (M-2): the create-must-be-version-1 guard,
     the replace successor (409 version_conflict) guard, monotonic
     advance for legacy omitters, the v2 AAD version binding, the rekey
     re-encryption generation.
  Y  Time-of-day + Spanish parity (P3/H-7/D-2): strict tod-bucket
     validation, the temporal narrowing evidence bars (N and fraction,
     inclusive boundary), the language-gated theme map, the EN-wins
     lexicon merge order, ES topic eligibility stopwords, the language
     minimum-token floor, the Spanish crisis regex family.
  Z  Audit trail read path + lifecycle re-auth (phase 2): patient and
     therapist log scoping, actor redaction, the keyset cursor id
     tiebreak, the deactivated-therapist pairing refusal, the wrap-rotation
     deactivated recheck, the password-equivalent verifier gate.

A mutant is KILLED when any of its commands exits non-zero (or times out —
a hang is an observable behavior change). Pytest exits that mean the
ORACLE is broken (2/3/4/5) are SETUP-ERRORs, never kills.

Usage:
  python3 harness.py            # run all campaigns
  python3 harness.py U V        # run only campaigns U and V
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
OUT_DIR = pathlib.Path(__file__).resolve().parent / "results"
OUT_DIR.mkdir(exist_ok=True)

PY = ".venv/bin/python"
# The repo-root venv is the canonical interpreter (README); backend/.venv is
# not kept suite-healthy — every command runs the root venv absolutely.
ROOT_PY = os.environ.get("MUTATION_PY") or str(ROOT / ".venv" / "bin" / "python")


def backend_pytest(*targets: str, extra: tuple[str, ...] = ()) -> dict:
    return {
        "cwd": "backend",
        "cmd": [ROOT_PY, "-m", "pytest", "-q", "-x", "--no-header", "-p", "no:cacheprovider",
                "-m", "not slow", *extra, *targets],
        "timeout": 900,
        "kind": "pytest",
    }


MUTANTS: list[dict] = [
    # ---------------------------------------------------------------- U. TOTP second factor
    dict(
        id="U1", campaign="U", name="login TOTP gate removed (password-only login on a TOTP account)",
        expectation="an armed account must answer 401 totp_required without a code",
        file="backend/app/api/auth.py",
        find="        if user.totp_enabled:",
        replace="        if False:",
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U2", campaign="U", name="missing-code challenge collapsed into the generic invalid answer",
        expectation="a missing code is the machine-readable totp_required verdict",
        file="backend/app/api/auth.py",
        find=(
            "            if not code:\n"
            "                raise ApiError(\n"
            "                    status_code=401,\n"
            '                    detail="totp code required",\n'
            '                    code="totp_required",\n'
            "                )"
        ),
        replace=(
            "            if False:\n"
            "                raise ApiError(\n"
            "                    status_code=401,\n"
            '                    detail="totp code required",\n'
            '                    code="totp_required",\n'
            "                )"
        ),
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U3", campaign="U", name="wrong-code acceptance (matched None no longer refuses)",
        expectation="a wrong code must 401 totp_code_invalid, never issue a token",
        file="backend/app/api/auth.py",
        find="            if matched is None or replayed:",
        replace="            if replayed:",
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U4", campaign="U", name="login replay fence relaxed (<= becomes <, the consumed timestep replays)",
        expectation="the SAME code must be refused on the immediately following login",
        file="backend/app/api/auth.py",
        find=(
            "            replayed = (\n"
            "                user.totp_last_counter is not None and matched is not None\n"
            "                and matched <= user.totp_last_counter\n"
            "            )"
        ),
        replace=(
            "            replayed = (\n"
            "                user.totp_last_counter is not None and matched is not None\n"
            "                and matched < user.totp_last_counter\n"
            "            )"
        ),
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U5", campaign="U", name="login never persists the consumed timestep (fence frozen at arm time)",
        expectation="the replay fence must advance with every successful TOTP login",
        file="backend/app/api/auth.py",
        find="                .where(User.id == user.id, User.totp_enabled.is_(True))",
        replace="                .where(User.id == user.id, User.totp_enabled.is_(False))",
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U6", campaign="U", name="setup while ENABLED no longer refuses (factor stripped by re-arm)",
        expectation="a password-only holder must not disarm the second factor via /totp/setup",
        file="backend/app/api/account.py",
        find="    if user.totp_enabled:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U7", campaign="U", name="enable does not consume its timestep (code replayable at login)",
        expectation="the confirm code, once presented to the server, must not log in again",
        file="backend/app/api/account.py",
        find="            .values(totp_enabled=True, totp_last_counter=matched)",
        replace="            .values(totp_enabled=True)",
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U8", campaign="U", name="disable replay fence relaxed (<= becomes <)",
        expectation="the code that just logged someone in must not also disable the factor",
        file="backend/app/api/account.py",
        find=(
            "    replayed = (\n"
            "        user.totp_last_counter is not None\n"
            "        and matched is not None\n"
            "        and matched <= user.totp_last_counter\n"
            "    )"
        ),
        replace=(
            "    replayed = (\n"
            "        user.totp_last_counter is not None\n"
            "        and matched is not None\n"
            "        and matched < user.totp_last_counter\n"
            "    )"
        ),
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    dict(
        id="U9", campaign="U", name="RFC drift window closed (previous/current only, skew rejected)",
        expectation="codes from the previous and next timestep must verify",
        file="backend/app/security/totp.py",
        find="ALLOWED_DRIFT = 1",
        replace="ALLOWED_DRIFT = 0",
        tests=[backend_pytest("tests/test_totp.py")],
    ),
    # ---------------------------------------------------------------- V. measures / MBC
    dict(
        id="V1", campaign="V", name="per-account measure quota disabled",
        expectation="measure count over 2000 must 413",
        file="backend/app/api/measures.py",
        find="            if count >= MAX_MEASURES_PER_USER:",
        replace="            if False:",
        tests=[backend_pytest("tests/test_measures_api.py", "tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V2", campaign="V", name="forward date grace widened (far-future measure dates accepted)",
        expectation="a measure_date past server-today+1 must 422",
        file="backend/app/api/measures.py",
        find="    if measure_date > today + timedelta(days=FORWARD_GRACE_DAYS):",
        replace="    if measure_date > today + timedelta(days=30):",
        tests=[backend_pytest("tests/test_measures_api.py")],
    ),
    dict(
        id="V3", campaign="V", name="backdate floor removed (pre-account measure dates accepted)",
        expectation="a measure_date before account-creation-minus-1 must 422",
        file="backend/app/api/measures.py",
        find="    earliest = min(user.created_at.date(), today) - timedelta(days=BACKDATE_GRACE_DAYS)",
        replace="    earliest = min(user.created_at.date(), today) - timedelta(days=3650)",
        tests=[backend_pytest("tests/test_measures_api.py")],
    ),
    dict(
        id="V4", campaign="V", name="legacy measure page byte budget x100 (413 removed)",
        expectation="an unpaged request over 2 MiB ciphertext must 413",
        file="backend/app/api/measures.py",
        find="            if sum(size for _, size in selected) > MEASURE_PAGE_BLOB_BYTES:",
        replace="            if sum(size for _, size in selected) > MEASURE_PAGE_BLOB_BYTES * 100:",
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V5", campaign="V", name="page_bytes budget walk never stops (over-budget page served)",
        expectation="a byte-paginating client must receive at most its page_bytes budget",
        file="backend/app/api/measures.py",
        find="                if total_bytes + blob_bytes > page_bytes:",
        replace="                if False:",
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V6", campaign="V", name="has_more drops the short-page arm (byte-truncated pages look terminal)",
        expectation="a byte-truncated page must still advertise X-Next-Offset",
        file="backend/app/api/measures.py",
        find="        has_more = len(selected) < len(requested) or len(metadata) > limit",
        replace="        has_more = len(metadata) > limit",
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V7", campaign="V", name="measure create does not advance the revision marker",
        expectation="a create between pages must 409 collection_changed for stale snapshots",
        file="backend/app/api/measures.py",
        find="            await _increment_measures_revision(session, fresh_user)",
        replace="            pass",
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py", "tests/test_measures_api.py")],
    ),
    dict(
        id="V8", campaign="V", name="measures increment fail-closed guard removed",
        expectation="a create whose marker cannot advance must 503, not commit unmarked",
        file="backend/app/api/measures.py",
        find="    if db_rowcount(result) != 1:",
        replace="    if False:",
        tests=[backend_pytest("tests/test_snapshot_revisions.py", "tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V9", campaign="V", name="patient read drops the final revision drift fence",
        expectation="a collection that moved mid-read must 409, never a shifted page",
        file="backend/app/api/measures.py",
        find="        if final_revision != revision:",
        replace="        if False:",
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py", "tests/test_snapshot_revisions.py")],
    ),
    dict(
        id="V10", campaign="V", name="therapist measures mirror ignores the disclosure version",
        expectation="a v1-disclosure grant must 409 disclosure_outdated, serving nothing",
        file="backend/app/api/therapist.py",
        find="            if consent.disclosure != SHARING_DISCLOSURE_VERSION:",
        replace="            if False:",
        tests=[backend_pytest("tests/test_api_pins.py", "tests/test_api_resilience_coverage.py",
                             "tests/test_measures_api.py")],
    ),
    dict(
        id="V11", campaign="V", name="therapist measures mirror drops the final revision drift fence",
        expectation="the mirror must fail closed exactly like the patient read",
        file="backend/app/api/therapist.py",
        find=(
            "            final_revision = await current_measures_revision(session, consent.user_id)\n"
            "            if final_revision != revision:"
        ),
        replace=(
            "            final_revision = await current_measures_revision(session, consent.user_id)\n"
            "            if False:"
        ),
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V12", campaign="V", name="therapist mirror post-fetch byte sanity x100",
        expectation="the served page must respect the byte budget even after the blob fetch",
        file="backend/app/api/therapist.py",
        find=(
            "                byte_limit = page_bytes if page_bytes is not None else MEASURE_PAGE_BLOB_BYTES\n"
            "                if sum(len(bytes(row.blob)) for row in rows) > byte_limit:"
        ),
        replace=(
            "                byte_limit = page_bytes if page_bytes is not None else MEASURE_PAGE_BLOB_BYTES\n"
            "                if sum(len(bytes(row.blob)) for row in rows) > byte_limit * 100:"
        ),
        tests=[backend_pytest("tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="V13", campaign="V", name="therapist ENTRIES mirror drops the final revision drift fence",
        expectation="the entries mirror must fail closed exactly like the patient read",
        file="backend/app/api/therapist.py",
        find=(
            "            final_revision = await current_entries_revision(session, consent.user_id)\n"
            "            if final_revision != revision:"
        ),
        replace=(
            "            final_revision = await current_entries_revision(session, consent.user_id)\n"
            "            if False:"
        ),
        tests=[backend_pytest("tests/test_therapist_api.py", "tests/test_snapshot_revisions.py")],
    ),
    # ---------------------------------------------------------------- W. note edit history
    dict(
        id="W1", campaign="W", name="PATCH change detection disabled (edits never revision, never bump marker)",
        expectation="a text-changing PATCH must write exactly one revision and advance X-Notes-Revision",
        file="backend/app/api/therapist.py",
        find="        changed = bytes(row.blob) != blob",
        replace="        changed = False",
        tests=[backend_pytest("tests/test_note_history.py", "tests/test_snapshot_revisions.py")],
    ),
    dict(
        id="W2", campaign="W", name="PATCH no longer appends the superseded blob to history",
        expectation="the pre-edit text must survive as an immutable revision",
        file="backend/app/api/therapist.py",
        find=(
            "            session.add(\n"
            "                TherapistNoteRevision(\n"
            "                    note_id=row.id,\n"
            "                    therapist_id=user.id,\n"
            "                    blob=bytes(row.blob),\n"
            "                    created_at=utcnow(),\n"
            "                )\n"
            "            )"
        ),
        replace="            pass",
        tests=[backend_pytest("tests/test_note_history.py")],
    ),
    dict(
        id="W3", campaign="W", name="history stores the NEW text instead of the superseded one",
        expectation="the revision must decrypt to the ORIGINAL pre-edit text",
        file="backend/app/api/therapist.py",
        find="                    blob=bytes(row.blob),",
        replace="                    blob=blob,",
        tests=[backend_pytest("tests/test_note_history.py")],
    ),
    dict(
        id="W4", campaign="W", name="idempotent retry with new text skips the revision (history replaced in place)",
        expectation="a retried create with different content must preserve the superseded v1",
        file="backend/app/api/therapist.py",
        find="                if bytes(existing.blob) != blob:",
        replace="                if False:",
        tests=[backend_pytest("tests/test_note_history.py")],
    ),
    dict(
        id="W5", campaign="W", name="PATCH no longer advances the therapist-global note marker",
        expectation="every note mutation must invalidate note continuations",
        file="backend/app/api/therapist.py",
        find=(
            "        if changed:\n"
            "            await _increment_notes_revision(session, user)"
        ),
        replace=(
            "        if False:\n"
            "            await _increment_notes_revision(session, user)"
        ),
        tests=[backend_pytest("tests/test_snapshot_revisions.py", "tests/test_note_history.py")],
    ),
    dict(
        id="W6", campaign="W", name="note create/retry no longer advances the marker",
        expectation="a created note must invalidate note continuations",
        file="backend/app/api/therapist.py",
        find=(
            "            if changed:\n"
            "                # The note and global therapist marker commit together. Note"
        ),
        replace=(
            "            if False:\n"
            "                # The note and global therapist marker commit together. Note"
        ),
        tests=[backend_pytest("tests/test_snapshot_revisions.py", "tests/test_note_history.py")],
    ),
    dict(
        id="W7", campaign="W", name="revision read drops therapist scoping",
        expectation="oracle question: unreachable behind the still-scoped note fetch?",
        file="backend/app/api/therapist.py",
        find=(
            "                .where(\n"
            "                    TherapistNoteRevision.note_id == note_id,\n"
            "                    TherapistNoteRevision.therapist_id == user.id,\n"
            "                )"
        ),
        replace=(
            "                .where(\n"
            "                    TherapistNoteRevision.note_id == note_id,\n"
            "                )"
        ),
        tests=[backend_pytest("tests/test_note_history.py")],
    ),
    dict(
        id="W8", campaign="W", name="history read serves oldest-first",
        expectation="revisions must arrive newest-first for the portal timeline",
        file="backend/app/api/therapist.py",
        find="                .order_by(TherapistNoteRevision.created_at.desc(), TherapistNoteRevision.id.desc())",
        replace="                .order_by(TherapistNoteRevision.created_at.asc(), TherapistNoteRevision.id.asc())",
        tests=[backend_pytest("tests/test_note_history.py")],
    ),
    dict(
        id="W9", campaign="W", name="history page ceiling 200 -> 2000",
        expectation="oracle question: is the history read cap pinned anywhere?",
        file="backend/app/api/therapist.py",
        find=(
            "async def read_note_revisions(\n"
            "    note_id: str,\n"
            "    user: User = Depends(require_therapist),\n"
            "    session: AsyncSession = Depends(get_session),\n"
            "    limit: int = Query(default=50, ge=1, le=200),\n"
            "):"
        ),
        replace=(
            "async def read_note_revisions(\n"
            "    note_id: str,\n"
            "    user: User = Depends(require_therapist),\n"
            "    session: AsyncSession = Depends(get_session),\n"
            "    limit: int = Query(default=50, ge=1, le=2000),\n"
            "):"
        ),
        tests=[backend_pytest("tests/test_note_history.py")],
    ),
    # ---------------------------------------------------------------- X. entry content versioning
    dict(
        id="X1", campaign="X", name="create accepts any content_version (AAD/version echo can disagree)",
        expectation="a create with content_version != 1 must 422",
        file="backend/app/api/entries.py",
        find="            if body.content_version != 1:",
        replace="            if False:",
        tests=[backend_pytest("tests/test_rotation_pins.py")],
    ),
    dict(
        id="X2", campaign="X", name="replace drops the successor check (silent cross-device overwrite)",
        expectation="a replace whose version is not stored+1 must 409 version_conflict",
        file="backend/app/api/entries.py",
        find="            if body.content_version is not None and body.content_version != row.content_version + 1:",
        replace="            if False:",
        tests=[backend_pytest("tests/test_rotation_pins.py")],
    ),
    dict(
        id="X3", campaign="X", name="legacy replace stops advancing the stored version",
        expectation="an omitted version must still advance monotonically",
        file="backend/app/api/entries.py",
        find="                row.content_version = body.content_version or row.content_version + 1",
        replace="                row.content_version = body.content_version or row.content_version",
        tests=[backend_pytest("tests/test_rotation_pins.py")],
    ),
    dict(
        id="X4", campaign="X", name="v2 AAD binds a constant version instead of the row's",
        expectation="oracle question: the AAD byte contract is cross-platform (portal/mobile)",
        file="backend/app/security/crypto.py",
        find="    return build_aad(ENTRY_CONTEXT, user_id, client_entry_id, str(content_version))",
        replace='    return build_aad(ENTRY_CONTEXT, user_id, client_entry_id, "1")',
        tests=[backend_pytest("tests/test_rotation_pins.py", "tests/test_encrypt_vectors.py",
                             "tests/test_audit_2026_09_21_backend.py")],
    ),
    dict(
        id="X5", campaign="X", name="rekey re-encrypts under the legacy v1 AAD",
        expectation="oracle question: does any pin assert the post-rekey AAD generation?",
        file="backend/app/api/insights.py",
        find="                    new_key, plaintext, crypto.entry_aad_v2(user_id, client_entry_id, version)",
        replace="                    new_key, plaintext, crypto.entry_aad_v1(user_id, client_entry_id)",
        tests=[backend_pytest("tests/test_rotation_pins.py", "tests/test_audit_2026_09_21_backend.py")],
    ),
    # ---------------------------------------------------------------- Y. time-of-day + Spanish parity
    dict(
        id="Y1", campaign="Y", name="tod bucket validation disabled (unknown buckets accepted)",
        expectation="an unknown tod value must 400 entry_payload_malformed",
        file="backend/app/api/insights.py",
        find="            if not isinstance(tod_raw, str) or tod_raw not in _TOD_BUCKETS:",
        replace="            if False:",
        tests=[backend_pytest("tests/test_time_of_day.py")],
    ),
    dict(
        id="Y2", campaign="Y", name="temporal narrowing needs only ONE tod-bearing entry",
        expectation="oracle question: is the N>=3 evidence bar pinned?",
        file="backend/app/services/brain.py",
        find="TEMPORAL_MIN_TOD_N = 3",
        replace="TEMPORAL_MIN_TOD_N = 1",
        tests=[backend_pytest("tests/test_time_of_day.py")],
    ),
    dict(
        id="Y3", campaign="Y", name="temporal dominance fraction floor collapsed to 0.1",
        expectation="genuinely mixed writing windows must NOT narrow the weekday claim",
        file="backend/app/services/brain.py",
        find="TEMPORAL_MIN_TOD_FRACTION = 0.7",
        replace="TEMPORAL_MIN_TOD_FRACTION = 0.1",
        tests=[backend_pytest("tests/test_time_of_day.py")],
    ),
    dict(
        id="Y4", campaign="Y", name="dominance comparison strict at the exact bar (>= -> >)",
        expectation="oracle question: a corpus at EXACTLY 0.7 dominance",
        file="backend/app/services/brain.py",
        find="                if dominant_k / len(tod_seen) >= TEMPORAL_MIN_TOD_FRACTION:",
        replace="                if dominant_k / len(tod_seen) > TEMPORAL_MIN_TOD_FRACTION:",
        tests=[backend_pytest("tests/test_time_of_day.py")],
    ),
    dict(
        id="Y5", campaign="Y", name="theme lookup ignores the language (ES map never consulted)",
        expectation="Spanish corpora must read the Spanish theme map",
        file="backend/app/services/brain.py",
        find="    lexicon = THEME_WORDS_ES if language == \"es\" else THEME_WORDS",
        replace="    lexicon = THEME_WORDS",
        tests=[backend_pytest("tests/test_es_themes.py")],
    ),
    dict(
        id="Y6", campaign="Y", name="lexicon merge order flipped (Spanish overrides English collisions)",
        expectation="English must win every graded-sentiment collision",
        file="backend/app/services/brain.py",
        find="SENTIMENT_LEXICON: dict[str, float] = {**VADER_BASE_ES, **SENTIMENT_LEXICON_EN}",
        replace="SENTIMENT_LEXICON: dict[str, float] = {**SENTIMENT_LEXICON_EN, **VADER_BASE_ES}",
        tests=[backend_pytest("tests/test_audit_round2_2026_09_21_brain.py", "tests/test_brain.py")],
    ),
    dict(
        id="Y7", campaign="Y", name="ES topic-eligibility stopwords dropped (function words become topics)",
        expectation="Spanish function words must not mint presence topic cards",
        file="backend/app/services/brain.py",
        find="        TOPIC_STOPWORDS | LANGUAGE_FUNCTION_WORDS_ES if language == \"es\" else TOPIC_STOPWORDS",
        replace="        TOPIC_STOPWORDS",
        tests=[backend_pytest("tests/test_es_themes.py", "tests/test_audit_2026_09_21_brain.py")],
    ),
    dict(
        id="Y8", campaign="Y", name="language floor lowered 50 -> 5 tokens",
        expectation="oracle question: short corpora must keep the English default",
        file="backend/app/services/brain.py",
        find="LANGUAGE_MIN_TOKENS = 50  # too little text to judge a language honestly",
        replace="LANGUAGE_MIN_TOKENS = 5  # too little text to judge a language honestly",
        tests=[backend_pytest("tests/test_es_themes.py", "tests/test_audit_2026_09_21_brain.py")],
    ),
    dict(
        id="Y9", campaign="Y", name="Spanish hopelessness crisis phrase never matches",
        expectation='"no quiero vivir" must reach the crisis dialog tier',
        file="backend/app/services/crisis.py",
        find='    "\\\\bno\\\\s+quiero\\\\s+vivir\\\\b",',
        replace='    "\\\\bzz-quiero-nunca\\\\b",',
        tests=[backend_pytest("tests/test_crisis.py", "tests/test_security_fixes.py",
                             "tests/test_brain_hardening.py")],
    ),
    # ---------------------------------------------------------------- Z. audit trail + lifecycle re-auth
    dict(
        id="Z1", campaign="Z", name="patient access-log scoping inverted (other patients' rows served)",
        expectation="one patient's audit page must contain only their own rows",
        file="backend/app/api/account.py",
        find="        .where(AccessLog.user_id == user.id)",
        replace="        .where(AccessLog.user_id != user.id)",
        tests=[backend_pytest("tests/test_audit_trail_phase2.py")],
    ),
    dict(
        id="Z2", campaign="Z", name="actor redaction flattened to self (therapist reads masquerade)",
        expectation="therapist-actor rows must render actor=therapist with the display name",
        file="backend/app/api/account.py",
        find='            actor="self" if row.AccessLog.actor_id == user.id else "therapist",',
        replace='            actor="self",',
        tests=[backend_pytest("tests/test_audit_trail_phase2.py")],
    ),
    dict(
        id="Z3", campaign="Z", name="patient cursor loses the id tiebreak (same-timestamp rows skipped)",
        expectation="cursor pagination must be complete and unduplicated across equal timestamps",
        file="backend/app/api/account.py",
        find=(
            "        query = query.where(\n"
            "            or_(\n"
            "                AccessLog.at < cursor_at,\n"
            "                (AccessLog.at == cursor_at) & (AccessLog.id < parts[1]),\n"
            "            )\n"
            "        )"
        ),
        replace="        query = query.where(AccessLog.at < cursor_at)",
        tests=[backend_pytest("tests/test_audit_trail_phase2.py")],
    ),
    dict(
        id="Z4", campaign="Z", name="therapist access-log scoping dropped (every action visible)",
        expectation="a therapist's audit page must contain only their own actions",
        file="backend/app/api/therapist.py",
        find="        .where(AccessLog.actor_id == user.id)",
        replace="        .where(AccessLog.actor_id.isnot(None))",
        tests=[backend_pytest("tests/test_audit_trail_phase2.py")],
    ),
    dict(
        id="Z5", campaign="Z", name="pairing routes at deactivated therapists",
        expectation="a pairing code from a closed account must 404, not grant",
        file="backend/app/api/consents.py",
        find=(
            "    if (\n"
            "        therapist is None\n"
            "        or not therapist.is_active\n"
            "        or therapist.role != ROLE_THERAPIST\n"
            "        or not therapist.wrap_pub_key\n"
            "    ):"
        ),
        replace=(
            "    if (\n"
            "        therapist is None\n"
            "        or therapist.role != ROLE_THERAPIST\n"
            "        or not therapist.wrap_pub_key\n"
            "    ):"
        ),
        tests=[backend_pytest("tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="Z6", campaign="Z", name="wrap-key rotation skips the deactivated-account recheck",
        expectation="oracle question: rotation under the lock must re-see the account",
        file="backend/app/api/therapist.py",
        find="        if fresh is None or not fresh.is_active:",
        replace="        if False:",
        tests=[backend_pytest("tests/test_therapist_lifecycle.py", "tests/test_api_resilience_coverage.py")],
    ),
    dict(
        id="Z7", campaign="Z", name="password-equivalent verifier gate removed (setup/rotation on bearer alone)",
        expectation="every verifier-gated action must 403 without the password half",
        file="backend/app/api/account.py",
        find="    if not hmac.compare_digest(candidate, bytes(user.verifier)):",
        replace="    if False:",
        tests=[backend_pytest("tests/test_totp.py", "tests/test_therapist_lifecycle.py",
                             "tests/test_rotation_pins.py")],
    ),
]


def parse_failures(kind: str, output: str) -> list[str]:
    fails: list[str] = []
    if kind == "pytest":
        fails = re.findall(r"^(FAILED|ERROR) (\S+)", output, re.M)
    seen, ordered = set(), []
    for f in fails:
        if f not in seen:
            seen.add(f)
            ordered.append(f)
    return ordered[:8]


# pytest exit codes that mean the ORACLE (not the code under test) is
# broken: 2 interrupted, 3 internal error, 4 usage error (a renamed or
# deleted test file lands here), 5 no tests collected. Counting any of
# these as KILLED would print PASSED while verifying nothing — they are
# SETUP-ERRORs, reported loudly, never kills.
PYTEST_SETUP_EXITS = {2, 3, 4, 5}


def oracle_setup_error(kind: str, returncode: int, output: str) -> str | None:
    """Why this non-zero exit is a broken oracle rather than a kill, or None."""
    if kind != "pytest":
        return None
    if returncode in PYTEST_SETUP_EXITS:
        return f"pytest exited {returncode} (oracle broken, not a kill)"
    if "no tests ran" in output:
        return "pytest collected no tests (oracle broken, not a kill)"
    return None


def run_command(spec: dict, mutant_id: str) -> tuple[bool, str | None, list[str], str, float]:
    """One command against the mutated tree.

    Returns (failed, setup_error, failures, output, seconds). A non-zero
    pytest exit in PYTEST_SETUP_EXITS is a broken oracle (SETUP-ERROR),
    not a kill — oracle rot must not be able to green the gate."""
    env = dict(os.environ, CI="true")
    env["PATH"] = str(ROOT / ".tools/node/bin") + os.pathsep + env.get("PATH", "")
    # Round-2 hygiene: never write .pyc during mutant runs (same-second
    # apply/revert leaves stale MUTATED bytecode cached — found live in
    # round 2; every command runs with bytecode writing disabled).
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            spec["cmd"], cwd=ROOT / spec["cwd"], capture_output=True, text=True,
            timeout=spec["timeout"], env=env,
        )
        elapsed = round(time.monotonic() - t0, 1)
        out = (proc.stdout or "") + (proc.stderr or "")
        return (proc.returncode != 0,
                oracle_setup_error(spec["kind"], proc.returncode, out),
                parse_failures(spec["kind"], out), out[-1500:], elapsed)
    except subprocess.TimeoutExpired as exc:
        elapsed = round(time.monotonic() - t0, 1)
        out = ((exc.stdout or b"").decode(errors="replace")
               + (exc.stderr or b"").decode(errors="replace"))
        return True, None, [], out, elapsed


def run_mutant(m: dict) -> dict:
    target = ROOT / m["file"]
    original = target.read_bytes()
    text = original.decode("utf-8")
    n = text.count(m["find"])
    want = m.get("count", 1)
    if n < want:
        return {**m, "killed": None, "status": "SETUP-ERROR",
                "detail": f"find-string matched {n} times, expected {want}"}
    mutated = text.replace(m["find"], m["replace"], want)
    target.write_text(mutated)
    specs = m["tests"] if isinstance(m["tests"], list) else [m["tests"]]
    try:
        per_cmd: list[dict] = []
        killed = False
        for spec in specs:
            failed, setup_error, failures, out, seconds = run_command(spec, m["id"])
            per_cmd.append({"kind": spec["kind"], "cmd": " ".join(spec["cmd"][:6]),
                            "failed": failed, "setup_error": setup_error,
                            "failures": failures, "seconds": seconds})
            if setup_error:
                # The oracle could not run (renamed test file, collection
                # crash, bad flag): a KILLED verdict here would verify
                # nothing. Fail loudly instead of green.
                return {**m, "killed": None, "status": "SETUP-ERROR",
                        "detail": f"{spec['kind']}: {setup_error}",
                        "commands": per_cmd}
            if failed:
                killed = True
                break  # first failing oracle is enough
        status = "KILLED" if killed else "SURVIVED"
        return {**m, "killed": killed, "status": status, "commands": per_cmd}
    finally:
        target.write_bytes(original)
        if target.read_bytes() != original:
            raise RuntimeError(f"RESTORE FAILED for {m['id']} — {m['file']}")
        # Belt and braces for the stale-bytecode hazard (round 2).
        pkg = target.parent / "__pycache__"
        if pkg.is_dir():
            stem = target.stem
            for cache in pkg.glob(f"{stem}.*.pyc"):
                cache.unlink(missing_ok=True)


def main() -> None:
    wanted = sys.argv[1:]
    todo = [m for m in MUTANTS if not wanted or m["campaign"] in wanted]
    print(f"{len(todo)} mutants queued\n", flush=True)
    results = []
    for m in todo:
        print(f"[{m['id']}] {m['name']} ...", flush=True)
        r = run_mutant(m)
        results.append(r)
        if r["status"] == "SETUP-ERROR":
            print(f"    !! {r.get('detail', '')}", flush=True)
        else:
            which = " / ".join(
                f"{c['kind']}:{'fail' if c['failed'] else 'pass'}({c['seconds']}s)"
                for c in r.get("commands", [])
            )
            print(f"    -> {r['status']}  [{which}]"
                  + (f"  first: {r['commands'][0]['failures'][0]}"
                     if r.get("commands") and r["commands"][0]["failures"] else ""),
                  flush=True)
    killed = sum(1 for r in results if r["killed"])
    done = [r for r in results if r["killed"] is not None]
    print(f"\n{killed}/{len(done)} killed, {len(done) - killed} survived", flush=True)
    stamp = time.strftime("%Y-%m-%dT%H%M%S")
    path = OUT_DIR / f"mutation_results_{stamp}.json"
    path.write_text(json.dumps(results, indent=2))
    print(f"results: {path}")


if __name__ == "__main__":
    main()
