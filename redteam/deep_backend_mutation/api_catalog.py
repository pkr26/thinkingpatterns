"""Domain mutation controls for API workflows, run only in isolated copies.

Every source replacement is unique and every control names a behavioral oracle.
This catalog deliberately targets state transitions, ownership, retry, retention,
and disclosure semantics rather than mechanically mutating every expression.
"""

from __future__ import annotations


def pytest(*selectors: str, timeout: int = 240) -> dict:
    return {
        "kind": "pytest",
        "cwd": "backend",
        "cmd": [
            ".venv/bin/python",
            "-m",
            "pytest",
            "-q",
            "-x",
            "--no-header",
            "-p",
            "no:cacheprovider",
            *selectors,
        ],
        "timeout": timeout,
    }


CAMPAIGNS: list[dict] = []


def campaign(
    number: int, name: str, filename: str, selectors: list[str], rows: list[tuple]
) -> None:
    ident = f"A{number:02}"
    controls = []
    for index, row in enumerate(rows, 1):
        title, find, replacement, *override = row
        controls.append(
            {
                "id": f"{ident}-{index:02}",
                "name": title,
                "file": filename,
                "find": find,
                "replace": replacement,
                "tests": [pytest(*(override[0] if override else selectors))],
            }
        )
    CAMPAIGNS.append({"id": ident, "name": name, "mutants": controls})


campaign(
    1,
    "Journal sync and generation integrity",
    "backend/app/api/entries.py",
    [
        "tests/test_entries_api.py",
        "tests/test_rotation_pins.py",
        "tests/test_independent_remediation_2026_10_04_backend.py",
    ],
    [
        (
            "Non-first create generation accepted",
            "            if body.content_version != 1:",
            "            if False:",
        ),
        (
            "Stale edit generation accepted",
            "            if body.content_version is not None and body.content_version != row.content_version + 1:",
            "            if False:",
        ),
        (
            "Legacy edit generation stops advancing",
            "                row.content_version = body.content_version or row.content_version + 1",
            "                row.content_version = body.content_version or row.content_version",
        ),
        (
            "Pre-account backdating admitted",
            "    earliest = min(created_day, today) - timedelta(days=BACKDATE_GRACE_DAYS)",
            "    earliest = min(created_day, today) - timedelta(days=3650)",
        ),
        (
            "Create stores unauthenticated entry metadata",
            "            seal_entry_guard(row, request.app.state.settings, v2_bound=False)",
            "            pass  # omit authenticated entry metadata",
        ),
    ],
)

campaign(
    2,
    "Recorded measures and correction",
    "backend/app/api/measures.py",
    [
        "tests/test_measures_api.py",
        "tests/test_remediation_measure_quota.py",
        "tests/test_mutation_round4_pins.py::test_measure_create_fails_closed_when_revision_cannot_advance",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Measure quota disabled",
            "            if count >= MAX_MEASURES_PER_USER:",
            "            if False:",
        ),
        (
            "Future measure dates admitted",
            "    if measure_date > today + timedelta(days=FORWARD_GRACE_DAYS):",
            "    if measure_date > today + timedelta(days=30):",
        ),
        (
            "Measure create leaves snapshot unchanged",
            "            await _increment_measures_revision(session, fresh_user)\n            await session.execute(",
            "            # snapshot not advanced\n            await session.execute(",
        ),
        (
            "Correction does not recover quota",
            "                .values(measure_count=User.measure_count - 1)",
            "                .values(measure_count=User.measure_count)",
        ),
        (
            "Correction changes another owner's measure",
            "                    Measure.user_id == fresh_user.id,\n                    Measure.client_measure_id == client_measure_id,",
            "                    Measure.client_measure_id == client_measure_id,",
        ),
    ],
)

campaign(
    3,
    "Snapshot-consistent bounded paging",
    "backend/app/api/_paging.py",
    ["tests/test_deep_campaign_api.py"],
    [
        (
            "Legacy page silently exceeds budget",
            "        if total > hard_budget:",
            "        if False:",
        ),
        (
            "Later rows exceed requested byte budget",
            "        if used + size > page_bytes:",
            "        if False:",
        ),
        (
            "Byte-truncated page appears terminal",
            "    return BytePage(selected, more_after_request or truncated)",
            "    return BytePage(selected, more_after_request)",
        ),
        (
            "Missing fetched record accepted",
            "    if len(rows_by_id) != len(selected_ids):",
            "    if False:",
        ),
        (
            "Continuation skips unreturned rows",
            "        response.headers[NEXT_OFFSET_HEADER] = str(offset + rows_returned)",
            "        response.headers[NEXT_OFFSET_HEADER] = str(offset + 100)",
        ),
    ],
)

campaign(
    4,
    "Provider consent currency and decision evidence",
    "backend/app/api/account.py",
    [
        "tests/test_audio_api.py",
        "tests/test_account_api.py::test_llm_consent_records_timestamp_and_disclosure",
        "tests/test_consent_audit_2026_09_29.py",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Voice yes omits policy accepted",
            "            fresh.voice_consent_policy = policy",
            "            fresh.voice_consent_policy = None",
        ),
        (
            "Voice withdrawal retains accepted policy",
            "            fresh.voice_consent_policy = None",
            "            fresh.voice_consent_policy = event_policy",
        ),
        (
            "LLM consent response falsely claims current policy",
            "        active_for_current_policy=llm.consent_is_current(user, settings),",
            "        active_for_current_policy=bool(user.llm_consent),",
        ),
        (
            "Voice consent response falsely claims current policy",
            "        active_for_current_policy=stt.consent_is_current(user, settings),",
            "        active_for_current_policy=bool(user.voice_consent),",
        ),
        (
            "Voice withdrawal evidence records grant",
            '                kind="voice",\n                action="granted" if body.enabled else "withdrawn",',
            '                kind="voice",\n                action="granted",',
        ),
    ],
)

campaign(
    5,
    "Pairing and single-use sharing grants",
    "backend/app/api/consents.py",
    [
        "tests/test_therapist_api.py",
        "tests/test_api_resilience_coverage.py::test_stale_sharing_disclosure_is_rejected_without_burning_code",
        "tests/test_api_resilience_coverage.py::test_grant_fails_closed_when_atomic_pairing_claim_loses_race",
        "tests/test_voice_remediation_2026_09_29.py::test_revoke_and_regrant_never_reactivate_prior_voice_scope",
        "tests/test_deep_campaign_api.py::test_active_pairing_wrap_refresh_requires_a_new_voice_choice",
    ],
    [
        (
            "Expired code redeems at atomic claim",
            "                    PairingCode.expires_at > now,",
            "                    PairingCode.created_at < now,",
        ),
        (
            "Pairing claim never consumes code",
            "                .values(consumed_at=now)",
            "                .values(consumed_at=None)",
        ),
        (
            "Stale disclosure accepted",
            "    if body.disclosure != SHARING_DISCLOSURE_VERSION:",
            "    if False:",
        ),
        (
            "Failed atomic claim still grants",
            "            if db_rowcount(claim) == 0:",
            "            if False:",
        ),
        (
            "Active wrap refresh carries prior voice authorization",
            "                existing.share_voice = False",
            "                existing.share_voice = existing.share_voice",
        ),
    ],
)

campaign(
    6,
    "Therapist scope and revocation",
    "backend/app/api/therapist.py",
    [
        "tests/test_therapist_api.py",
        "tests/test_api_pins.py::test_v1_consent_refuses_measures_but_keeps_entries_and_insights",
        "tests/test_audio_attachments.py::test_therapist_audio_requires_share_voice_flag",
        "tests/test_deep_campaign_api.py::test_recording_identity_stays_bound_to_patient_in_shared_reads_and_deletes",
        "tests/test_deep_campaign_api.py::test_baseline_hides_stored_pattern_ciphertext_from_patient_and_clinician",
    ],
    [
        (
            "Revoked relationship still authorizes reads",
            '    if consent is None or consent.status != "active":',
            "    if consent is None:",
        ),
        (
            "Measures served under obsolete disclosure",
            "            if consent.disclosure != SHARING_DISCLOSURE_VERSION:",
            "            if False:",
        ),
        (
            "Kept voice served without separate scope",
            "            if not consent.share_voice:",
            "            if False:",
        ),
        (
            "Cross-patient recording served",
            "            if row is None or row.user_id != consent.user_id:",
            "            if row is None:",
        ),
        (
            "Baseline patient receives stale patterns",
            "                if latest and state.phase is threshold.Phase.INSIGHT\n                else None",
            "                if latest\n                else None",
        ),
    ],
)

campaign(
    7,
    "Therapist-private clinical notes",
    "backend/app/api/therapist.py",
    [
        "tests/test_therapist_api.py",
        "tests/test_note_rekey_2026_10_01.py",
        "tests/test_remediation_note_history.py",
    ],
    [
        (
            "Duplicate create silently rewrites another chart",
            "            if existing.user_id != patient_id:",
            "            if False:",
            [
                "tests/test_deep_campaign_api.py::test_equal_ciphertext_duplicate_note_cannot_resolve_to_another_chart"
            ],
        ),
        (
            "Different note POST bypasses edit conflict",
            "            if changed:\n                # Independent audit 2026-09-27:",
            "            if False:\n                # Independent audit 2026-09-27:",
        ),
        (
            "PATCH accepts stale clinical edit",
            "        if body.base_version != current_version:",
            "        if False:",
            [
                "tests/test_deep_campaign_api.py::test_stale_clinical_patch_preserves_current_note_and_history"
            ],
        ),
        (
            "History stores replacement rather than superseded content",
            "                    blob=bytes(row.blob),\n                    created_at=utcnow(),",
            "                    blob=blob,\n                    created_at=utcnow(),",
        ),
        (
            "Reseal accepts incomplete revision history",
            "            if {rev.id for rev in actual_revisions} != {rev.id for rev, _blob in rev_pairs}:",
            "            if False:",
            [
                "tests/test_deep_campaign_api.py::test_note_reseal_requires_the_complete_current_revision_set"
            ],
        ),
    ],
)

campaign(
    8,
    "Clinician custody and atomic password retry",
    "backend/app/api/_custody.py",
    [
        "tests/test_remediation_2026_10_03.py::test_clinician_password_is_one_atomic_custody_transaction",
        "tests/test_remediation_2026_10_03.py::test_clinician_custody_cas_and_public_identity_replacement_fail_closed",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Custody skips successor version rule",
            "    if body.custody_version != body.expected_custody_version + 1:",
            "    if False:",
        ),
        (
            "Custody accepts stale expected version",
            "    if user.custody_version != body.expected_custody_version:",
            "    if False:",
        ),
        (
            "Password retry ignores exact body digest",
            '                and hmac.compare_digest(fresh.custody_operation_digest or "", digest)\n            ):',
            "                and True\n            ):",
        ),
        (
            "Password change may replace sharing identity",
            "        if body.wrap_pub_key != fresh.wrap_pub_key:",
            "        if False:",
        ),
        (
            "Password swaps credential without notes keyring",
            "        fresh.notes_keyring_blob = keyring",
            "        fresh.notes_keyring_blob = fresh.notes_keyring_blob",
        ),
    ],
)

campaign(
    9,
    "Therapist sharing-identity replacement",
    "backend/app/api/therapist.py",
    [
        "tests/test_remediation_2026_10_03.py::test_clinician_custody_cas_and_public_identity_replacement_fail_closed",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Identity replacement leaves active grants",
            "        if body.wrap_pub_key != fresh.wrap_pub_key:\n            # A compromised sharing identity",
            "        if False:\n            # A compromised sharing identity",
        ),
        (
            "Identity replacement ignores custody CAS",
            "        if body.expected_custody_version != fresh.custody_version:",
            "        if False:",
        ),
        (
            "Rotation allowed before notes custody install",
            "        if fresh.notes_keyring_blob is None:",
            "        if False:",
        ),
        (
            "Revoked identity keeps voice authorization",
            "                        summary_updated_at=None,\n                        share_voice=False,",
            "                        summary_updated_at=None,\n                        share_voice=True,",
        ),
        (
            "Identity revoke retains wrapped data key",
            "                        revoked_at=utcnow(),\n                        ephemeral_pub=None,\n                        wrapped_key=None,",
            "                        revoked_at=utcnow(),\n                        ephemeral_pub=None,",
        ),
    ],
)

campaign(
    10,
    "Speech and translation dispatch workflow",
    "backend/app/api/audio.py",
    [
        "tests/test_audio_api.py",
        "tests/test_voice_fence_2026_09_29.py",
        "tests/test_voice_remediation_2026_09_29.py::test_provider_dispatch_attempts_are_durable_before_plaintext_leaves",
        "tests/test_voice_remediation_2026_09_29.py::test_translation_suppressed_without_llm_consent",
        "tests/test_voice_remediation_2026_09_29.py::test_retranslation_route_suppressed_without_llm_consent",
    ],
    [
        (
            "Transcription omits affirmative current voice consent",
            "    if not stt.consent_is_current(user, settings):",
            "    if False:",
        ),
        (
            "Automatic translation ignores LLM consent",
            "        if result.text and stt.translation_dispatch_allowed(fresh, settings):",
            "        if result.text:",
        ),
        (
            "Edited transcript dispatch ignores LLM consent",
            "        if not stt.translation_dispatch_allowed(fresh, settings):",
            "        if False:",
        ),
        (
            "Provider audio size cap removed",
            "    if len(audio) > settings.audio_max_body_bytes:",
            "    if False:",
            [
                "tests/test_deep_campaign_api.py::test_transcription_decode_enforces_decoded_provider_budget"
            ],
        ),
        (
            "Transcription accepts arbitrary recording duration",
            '    if not 0 < body.duration_seconds <= settings.audio_max_duration_seconds:\n        raise ApiError(\n            status_code=422,\n            detail="recording duration exceeds the allowed maximum",\n            code="validation_error",\n        )\n    audio = _decode_audio(body.audio_b64, settings)',
            '    if False:\n        raise ApiError(\n            status_code=422,\n            detail="recording duration exceeds the allowed maximum",\n            code="validation_error",\n        )\n    audio = _decode_audio(body.audio_b64, settings)',
        ),
    ],
)

campaign(
    11,
    "Kept-recording lifecycle",
    "backend/app/api/audio.py",
    [
        "tests/test_audio_attachments.py",
        "tests/test_remediation_2026_10_03.py::test_audio_replacement_commit_failure_preserves_original_and_cleanup_lease",
        "tests/test_remediation_2026_10_03.py::test_expired_audio_replacement_does_not_subtract_excluded_bytes",
        "tests/test_deep_campaign_api.py::test_recording_identity_stays_bound_to_patient_in_shared_reads_and_deletes",
    ],
    [
        (
            "Recording upload admits absent entry",
            "            if entry_exists.scalar_one_or_none() is None:",
            "            if False:",
        ),
        (
            "Recording quota subtracts already excluded expired bytes",
            "                existing.size_bytes if existing is not None and existing.expires_at > now else 0",
            "                existing.size_bytes if existing is not None else 0",
        ),
        (
            "Recording live byte quota disabled",
            "            if live_total - replaced_bytes + len(blob) > settings.audio_max_user_bytes:",
            "            if False:",
        ),
        (
            "Expired kept recording stays fetchable",
            "    if row.expires_at <= utcnow():",
            "    if False:",
        ),
        (
            "Foreign recording may be removed",
            "        if row is None or row.user_id != user.id:",
            "        if row is None:",
        ),
    ],
)

campaign(
    12,
    "Portable export completeness and snapshot",
    "backend/app/api/account.py",
    [
        "tests/test_account_api.py",
        "tests/test_api_pins.py::test_export_streams_measures_decryptable_with_client_aad",
        "tests/test_remediation_2026_10_03.py::test_export_has_one_audio_key_and_complete_v2_aad_metadata",
        "tests/test_export_download.py",
        "tests/test_deep_campaign_api.py::test_export_retains_all_snapshot_chunks_when_byte_pages_are_short",
        "tests/test_deep_campaign_api.py::test_completed_export_releases_capacity_for_next_download",
    ],
    [
        (
            "Export stops before all insight snapshot chunks",
            "                                chunk_ids[processed_pos + 1 :] + pending_ids[len(chunk_ids) :]",
            "                                chunk_ids[processed_pos + 1 :]",
        ),
        (
            "Export omits v2 data-key locker",
            "                if fresh.key_scheme == KEY_SCHEME_V2 and fresh.wrapped_data_key is not None\n                else None",
            "                if False\n                else None",
            [
                "tests/test_deep_campaign_api.py::test_v2_export_remains_decryptable_with_only_password_after_account_erasure"
            ],
        ),
        (
            "Export hides recorded measure history",
            "                            .where(Measure.user_id == fresh.id, Measure.received_at <= cutoff)",
            "                            .where(Measure.user_id != fresh.id, Measure.received_at <= cutoff)",
        ),
        (
            "Export hides kept recordings",
            "                                    AudioAttachment.user_id == fresh.id,\n                                    AudioAttachment.created_at <= cutoff,",
            "                                    AudioAttachment.user_id != fresh.id,\n                                    AudioAttachment.created_at <= cutoff,",
        ),
        (
            "Export does not release admission slot on completion",
            "                export_limiter.release_on_behalf_of(export_borrower)\n\n    return StreamingResponse",
            "                pass  # leak completed export admission\n\n    return StreamingResponse",
        ),
    ],
)

campaign(
    13,
    "Encrypted analysis input provenance",
    "backend/app/api/insights.py",
    ["tests/test_deep_campaign_api.py"],
    [
        (
            "Inner client date drives brain calendar",
            "                entry_date=outer,\n                sentiment=sentiment,",
            "                entry_date=inner,\n                sentiment=sentiment,",
        ),
        (
            "Inner date mismatch admitted",
            "        if abs((inner - outer).days) > INNER_DATE_TOLERANCE_DAYS:",
            "        if False:",
        ),
        (
            "Sleep scale accepts out-of-range rating",
            "                or not 1 <= sleep_raw <= 5",
            "                or not 0 <= sleep_raw <= 6",
        ),
        (
            "Unsupported transcript loses English analysis channel",
            "            text = english_text",
            "            text = text",
        ),
        (
            "Question feedback accepts numeric truth flags",
            "isinstance(resonated, bool)",
            "isinstance(resonated, (bool, int))",
        ),
    ],
)

campaign(
    14,
    "Server insight publication and live revelation",
    "backend/app/api/insights.py",
    [
        "tests/test_insights_api.py",
        "tests/test_api_hardening.py::test_repeated_recomputes_are_idempotent",
        "tests/test_api_pins.py::test_same_day_recompute_with_extra_pattern_serves_same_question",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Read serves stored patterns below threshold",
            "        if latest and state.phase is Phase.INSIGHT\n        else None",
            "        if latest\n        else None",
        ),
        (
            "Undated replacement erases unrelated insight kinds",
            "            delete(Insight).where(Insight.user_id == user_id, Insight.kind == kind)",
            "            delete(Insight).where(Insight.user_id == user_id)",
        ),
        (
            "Question may change after already served today",
            "                question_pinned = (",
            "                question_pinned = False and (",
            [
                "tests/test_deep_campaign_publication.py::test_persisted_daily_question_survives_restart_and_new_analysis_candidates"
            ],
        ),
        (
            "Publication generation stops advancing",
            "            state_seq = prior_seq + 1\n            insights_payload",
            "            state_seq = prior_seq\n            insights_payload",
            [
                "tests/test_deep_campaign_publication.py::test_each_server_recompute_advances_all_publication_generation_copies"
            ],
        ),
        (
            "Threshold counts foreign account dates",
            "                .where(Entry.user_id == user_id)\n                .order_by(Entry.entry_date.asc())",
            "                .where(Entry.user_id != user_id)\n                .order_by(Entry.entry_date.asc())",
        ),
    ],
)

campaign(
    15,
    "Local-analysis upload generation CAS",
    "backend/app/api/insights.py",
    ["tests/test_local_recompute.py", "tests/test_deep_campaign_api.py"],
    [
        (
            "Local upload accepts stale state sequence",
            "        if prior_seq != body.base_state_seq:",
            "        if False:",
        ),
        (
            "Local upload claims caller dates as real activity",
            "        state = threshold.evaluate(sorted(real_dates), settings.unlock_threshold_days)",
            "        state = threshold.evaluate(sorted({date_type.fromisoformat(day) for day in body.analysis_dates}), settings.unlock_threshold_days)",
        ),
        (
            "Local upload does not advance generation",
            "        state_seq = prior_seq + 1\n        try:",
            "        state_seq = prior_seq\n        try:",
        ),
        (
            "Local upload invents pattern count from claimed dates",
            "        patterns_stored = body.patterns_count if body.patterns_count is not None else 0",
            "        patterns_stored = len(body.analysis_dates)",
        ),
        (
            "Local upload accepts malformed calendar dates",
            "    for raw in body.analysis_dates:\n        try:\n            date_type.fromisoformat(raw)",
            '    for raw in body.analysis_dates:\n        try:\n            date_type.fromisoformat("2026-01-01")',
        ),
    ],
)

campaign(
    16,
    "Resumable corpus and credential rotation",
    "backend/app/api/insights.py",
    [
        "tests/test_remediation_2026_10_03.py::test_atomic_v1_rotation_response_loss_and_old_writer_fence",
        "tests/test_remediation_2026_10_03.py::test_atomic_v2_corpus_envelope_and_active_grant_commit_together",
        "tests/test_remediation_2026_10_03.py::test_v1_rekey_includes_audio_and_invalidates_obsolete_recovery",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Resume journal ignores requested operation",
            "            journal.operation_id != body.operation_id",
            "            False",
        ),
        (
            "Exact committed retry ignores payload digest",
            '                    and hmac.compare_digest(fresh.rekey_operation_digest or "", digest)',
            "                    and True",
        ),
        (
            "Rotation preserves obsolete recovery enrollment",
            "                    final_user.recovery_verifier = None",
            "                    final_user.recovery_verifier = final_user.recovery_verifier",
        ),
        (
            "Rotation does not retire old credential sessions",
            "                    final_user.token_epoch += 1",
            "                    final_user.token_epoch += 0",
        ),
        (
            "Rotation silently misses retained audio",
            "                            .where(AudioAttachment.user_id == fresh_user.id)\n                            .order_by(AudioAttachment.id)",
            "                            .where(AudioAttachment.user_id != fresh_user.id)\n                            .order_by(AudioAttachment.id)",
        ),
    ],
)

campaign(
    17,
    "Authenticated audit append and external evidence",
    "backend/app/api/_audit.py",
    [
        "tests/test_independent_remediation_2026_10_04_backend.py::test_recovered_real_savepoint_conflict_publishes_committed_audit",
        "tests/test_independent_remediation_2026_10_04_backend.py::test_uncommitted_audit_tail_never_reaches_journal",
        "tests/test_independent_remediation_2026_10_04_backend.py::test_later_outer_rollback_preserves_earlier_committed_audit",
        "tests/test_independent_audit_2026_09_27.py",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Audit hash omits authenticated actor role",
            "    if record_version >= 2:",
            "    if False:",
        ),
        (
            "Audit row seal omits chain position",
            'mac_key, f"{user_id}:{chain_seq}:{entry_hash}".encode("utf-8"), hashlib.sha256',
            'mac_key, f"{user_id}:{entry_hash}".encode("utf-8"), hashlib.sha256',
        ),
        (
            "Journal-ahead evidence accepted as ordinary lag",
            "        if evidence.seq > last.chain_seq:",
            "        if False:",
        ),
        (
            "Audit append accepts missing existing chain state",
            "                if db_head is not None or not allow_new_chain:",
            "                if db_head is not None:",
            [
                "tests/test_deep_campaign_audit_triage.py::test_ordinary_audit_append_cannot_restart_an_erased_database_trail"
            ],
        ),
        (
            "Compaction discards old owner high-water evidence",
            "                        retain = occurred_at >= cutoff_at or conflict or seq == head_seq",
            "                        retain = occurred_at >= cutoff_at or conflict",
        ),
    ],
)

campaign(
    18,
    "Authenticated audit retention and incremental checkpoints",
    "backend/app/api/_audit.py",
    [
        "tests/test_residual_architecture_2026_10_04.py::test_incremental_audit_verifier_resumes_signed_pages_across_sessions",
        "tests/test_residual_architecture_2026_10_04.py::test_incremental_audit_verifier_rejects_checkpoint_tampering",
        "tests/test_remediation_coverage_2026_10_04.py::test_incremental_verifier_rejects_state_tail_and_journal_discontinuities",
        "tests/test_deep_campaign_api.py",
    ],
    [
        (
            "Checkpoint seal ignores resume sequence",
            "            cursor.verification_next_seq,",
            "            None,",
        ),
        (
            "Unsealed migration checkpoint retains attacker traversal",
            "        cursor.last_user_id = None\n        _clear_incremental_verification(cursor)",
            "        # retain untrusted last owner\n        _clear_incremental_verification(cursor)",
        ),
        (
            "Incremental verifier accepts sequence gap",
            "        if row.chain_seq != expected_seq:",
            "        if False:",
            [
                "tests/test_deep_campaign_audit_triage.py::test_incremental_checkpoint_never_advances_across_an_authenticated_sequence_gap"
            ],
        ),
        (
            "Incremental verifier accepts snapshot tail mismatch",
            "        if previous_hash != snapshot_hash:",
            "        if False:",
            [
                "tests/test_deep_campaign_audit_triage.py::test_incremental_snapshot_rejects_an_authenticated_alternate_historical_tail"
            ],
        ),
        (
            "Retention accepts unauthenticated row contents",
            "                    row_error = _audit_row_integrity_error(row, effective_mac_keys)",
            "                    row_error = None",
        ),
    ],
)

CAMPAIGNS[12]["mutants"].append(
    {
        "id": "A13-06",
        "name": "Supplied malformed mute channels silently disappear",
        "file": "backend/app/api/insights.py",
        "find": '        raw_list = payload[key]\n        if not isinstance(raw_list, list):\n            raise ApiError(\n                status_code=400,\n                detail="feedback blob is malformed",\n                code="entry_payload_malformed",\n            )',
        "replace": "        raw_list = payload[key]\n        if not isinstance(raw_list, list):\n            return []",
        "tests": [
            pytest(
                "tests/test_deep_campaign_api.py::test_feedback_does_not_silently_drop_supplied_wrong_shape"
            )
        ],
    }
)

CAMPAIGNS[6]["mutants"].extend(
    [
        {
            "id": "A07-06",
            "name": "Historical note read bypasses custody and retirement fence",
            "file": "backend/app/api/therapist.py",
            "find": "    async with _notes_guard(session, user):\n        # The fresh therapist read reopens a transaction.",
            "replace": '    async with _note_locks.hold(f"unfenced-history:{user.id}"):\n        # The fresh therapist read reopens a transaction.',
            "tests": [
                pytest(
                    "tests/test_deep_campaign_api.py::test_note_history_response_linearizes_before_custody_change"
                )
            ],
        },
        {
            "id": "A07-07",
            "name": "Historical note continuation ignores changed snapshot",
            "file": "backend/app/api/therapist.py",
            "find": '        assert_expected_revision(\n            expected,\n            revision,\n            collection="note revisions",\n            header_name=NOTES_REVISION_HEADER,\n        )',
            "replace": "        pass  # accept continuation against a different history snapshot",
            "tests": [
                pytest(
                    "tests/test_deep_campaign_api.py::test_note_history_continuation_refuses_a_changed_snapshot"
                )
            ],
        },
        {
            "id": "A07-08",
            "name": "Historical private-note response races patient erasure",
            "file": "backend/app/api/therapist.py",
            "find": "        await session.commit()\n        async with sharing_locks.hold(sharing_patient_lock_key(patient_id)):\n            yield",
            "replace": '        await session.commit()\n        async with _note_locks.hold(f"unfenced-history-patient:{patient_id}"):\n            yield',
            "tests": [
                pytest(
                    "tests/test_deep_campaign_api.py::test_note_history_response_linearizes_before_patient_deletion"
                )
            ],
        },
        {
            "id": "A07-09",
            "name": "Fetched history access vanishes when consistency later fails",
            "file": "backend/app/api/therapist.py",
            "find": "        if fetched:\n            # Fetching private history is an access fact even if a later\n            # consistency check refuses the response.\n            await session.commit()",
            "replace": "        if fetched:\n            # Fetching private history is an access fact even if a later\n            # consistency check refuses the response.\n            pass",
            "tests": [
                pytest(
                    "tests/test_deep_campaign_api.py::test_note_history_fetched_access_remains_audited_after_consistency_refusal[size]"
                )
            ],
        },
        {
            "id": "A07-10",
            "name": "Historical page ignores changed final snapshot",
            "file": "backend/app/api/therapist.py",
            "find": '        if final_revision != revision:\n            raise collection_changed_error("note revisions", NOTES_REVISION_HEADER, final_revision)',
            "replace": '        if False:\n            raise collection_changed_error("note revisions", NOTES_REVISION_HEADER, final_revision)',
            "tests": [
                pytest(
                    "tests/test_deep_campaign_api.py::test_note_history_fetched_access_remains_audited_after_consistency_refusal[snapshot]"
                )
            ],
        },
        {
            "id": "A07-11",
            "name": "Queued history reads retain the patient-fence owner's database capacity",
            "file": "backend/app/api/therapist.py",
            "find": "        # The fresh therapist read reopens a transaction. Keep the lifecycle\n        # fence, but release that connection before waiting on patient erasure.\n        await session.commit()",
            "replace": "        # The fresh therapist read reopens a transaction. Keep the lifecycle\n        # fence, but release that connection before waiting on patient erasure.\n        pass",
            "tests": [pytest("tests/test_deep_history_pool.py")],
        },
        {
            "id": "A07-12",
            "name": "Live private-note response races patient erasure",
            "file": "backend/app/api/therapist.py",
            "find": "    byte_limit = page_bytes if page_bytes is not None else NOTES_PAGE_BLOB_BYTES\n    async with _note_chart_guard(session, user, patient_id):",
            "replace": "    byte_limit = page_bytes if page_bytes is not None else NOTES_PAGE_BLOB_BYTES\n    async with _notes_guard(session, user):",
            "tests": [
                pytest(
                    "tests/test_deep_note_erasure.py::test_live_note_response_linearizes_before_patient_deletion[list]"
                )
            ],
        },
        {
            "id": "A07-13",
            "name": "Created private-note response races patient erasure",
            "file": "backend/app/api/therapist.py",
            "find": "    async with _note_chart_guard(session, user, patient_id):\n        _assert_custody_write(user, body.custody_version)\n        patient_id = await _note_target(session, user, user_id)",
            "replace": "    async with _notes_guard(session, user):\n        _assert_custody_write(user, body.custody_version)\n        patient_id = await _note_target(session, user, user_id)",
            "tests": [
                pytest(
                    "tests/test_deep_note_erasure.py::test_live_note_response_linearizes_before_patient_deletion[create]"
                )
            ],
        },
        {
            "id": "A07-14",
            "name": "Updated private-note response races patient erasure",
            "file": "backend/app/api/therapist.py",
            "find": "    async with _note_chart_guard(session, user, patient_id):\n        _assert_custody_write(user, body.custody_version)\n        # Re-fetch under the same chart lock:",
            "replace": "    async with _notes_guard(session, user):\n        _assert_custody_write(user, body.custody_version)\n        # Re-fetch under the same chart lock:",
            "tests": [
                pytest(
                    "tests/test_deep_note_erasure.py::test_live_note_response_linearizes_before_patient_deletion[update]"
                )
            ],
        },
    ]
)


# Exact behavioral oracles observed in the broad isolated replay. The runner
# verifies each focused command on the unmodified snapshot before mutation.
OBSERVED_BEHAVIORAL_ORACLES = {
    "A01-01": ["tests/test_rotation_pins.py::test_create_rejects_non_first_version"],
    "A01-02": ["tests/test_rotation_pins.py::test_replace_enforces_next_version"],
    "A01-03": [
        "tests/test_rotation_pins.py::test_legacy_replace_without_version_still_advances"
    ],
    "A01-04": ["tests/test_entries_api.py::test_rejects_entries_predating_the_account"],
    "A01-05": [
        "tests/test_independent_remediation_2026_10_04_backend.py::test_api_entry_write_seals_guard_without_fixture_repair"
    ],
    "A02-01": [
        "tests/test_remediation_measure_quota.py::test_real_measure_quota_allows_last_slot_rejects_overflow_and_recovers_after_delete"
    ],
    "A02-02": ["tests/test_measures_api.py::test_date_bounds_mirror_entries"],
    "A02-03": [
        "tests/test_remediation_measure_quota.py::test_real_measure_quota_allows_last_slot_rejects_overflow_and_recovers_after_delete"
    ],
    "A02-04": [
        "tests/test_remediation_measure_quota.py::test_real_measure_quota_allows_last_slot_rejects_overflow_and_recovers_after_delete"
    ],
    "A02-05": [
        "tests/test_deep_campaign_api.py::test_measure_correction_is_owner_scoped_and_recovers_count"
    ],
    "A03-01": [
        "tests/test_deep_campaign_api.py::test_legacy_and_first_oversize_pages_fail_loudly"
    ],
    "A03-02": [
        "tests/test_deep_campaign_api.py::test_ciphertext_page_preserves_every_continuation"
    ],
    "A03-03": [
        "tests/test_deep_campaign_api.py::test_ciphertext_page_preserves_every_continuation"
    ],
    "A03-04": [
        "tests/test_deep_campaign_api.py::test_metadata_fetch_drift_cannot_be_reported_as_complete_history"
    ],
    "A03-05": [
        "tests/test_deep_campaign_api.py::test_ciphertext_page_preserves_every_continuation"
    ],
    "A04-01": ["tests/test_audio_api.py::test_consent_state_roundtrip_and_withdraw"],
    "A04-02": [
        "tests/test_deep_campaign_api.py::test_provider_withdrawal_clears_live_grant_and_preserves_decision_evidence[voice]"
    ],
    "A04-03": [
        "tests/test_deep_campaign_api.py::test_provider_choice_is_not_current_authorization"
    ],
    "A04-04": ["tests/test_audio_api.py::test_policy_change_makes_consent_inert"],
    "A04-05": [
        "tests/test_deep_campaign_api.py::test_provider_withdrawal_clears_live_grant_and_preserves_decision_evidence[voice]"
    ],
    "A05-01": [
        "tests/test_therapist_api.py::test_pairing_expiry_crossing_after_live_lookup_is_enforced_at_atomic_burn[True]"
    ],
    "A05-02": ["tests/test_therapist_api.py::TestPairing::test_grant_burns_code"],
    "A05-03": [
        "tests/test_api_resilience_coverage.py::test_stale_sharing_disclosure_is_rejected_without_burning_code"
    ],
    "A05-04": [
        "tests/test_therapist_api.py::test_pairing_expiry_crossing_after_live_lookup_is_enforced_at_atomic_burn[True]"
    ],
    "A05-05": [
        "tests/test_deep_campaign_api.py::test_active_pairing_wrap_refresh_requires_a_new_voice_choice"
    ],
    "A06-01": [
        "tests/test_therapist_api.py::TestTherapistReads::test_revoked_consent_reads_404"
    ],
    "A06-02": [
        "tests/test_api_pins.py::test_v1_consent_refuses_measures_but_keeps_entries_and_insights"
    ],
    "A06-03": [
        "tests/test_audio_attachments.py::test_therapist_audio_requires_share_voice_flag"
    ],
    "A06-04": [
        "tests/test_deep_campaign_api.py::test_recording_identity_stays_bound_to_patient_in_shared_reads_and_deletes"
    ],
    "A06-05": [
        "tests/test_deep_campaign_api.py::test_baseline_hides_stored_pattern_ciphertext_from_patient_and_clinician"
    ],
    "A07-02": [
        "tests/test_therapist_api.py::TestNotes::test_create_is_idempotent_on_client_note_id"
    ],
    "A07-04": [
        "tests/test_remediation_note_history.py::test_foreign_revision_metadata_cannot_disrupt_owned_history"
    ],
    "A07-06": [
        "tests/test_deep_campaign_api.py::test_note_history_response_linearizes_before_custody_change"
    ],
    "A07-07": [
        "tests/test_deep_campaign_api.py::test_note_history_continuation_refuses_a_changed_snapshot"
    ],
    "A08-01": [
        "tests/test_deep_campaign_api.py::test_custody_successor_and_compare_exchange[1-1-3-422]"
    ],
    "A08-02": [
        "tests/test_remediation_2026_10_03.py::test_clinician_custody_cas_and_public_identity_replacement_fail_closed"
    ],
    "A08-03": [
        "tests/test_remediation_2026_10_03.py::test_clinician_password_is_one_atomic_custody_transaction"
    ],
    "A08-04": [
        "tests/test_remediation_2026_10_03.py::test_clinician_custody_cas_and_public_identity_replacement_fail_closed"
    ],
    "A08-05": [
        "tests/test_remediation_2026_10_03.py::test_clinician_password_is_one_atomic_custody_transaction"
    ],
    "A09-01": [
        "tests/test_deep_campaign_api.py::test_sharing_identity_change_retires_all_grant_material"
    ],
    "A09-02": [
        "tests/test_deep_campaign_api.py::test_identity_rotation_requires_installed_current_custody"
    ],
    "A09-03": [
        "tests/test_deep_campaign_api.py::test_identity_rotation_requires_installed_current_custody"
    ],
    "A09-04": [
        "tests/test_deep_campaign_api.py::test_sharing_identity_change_retires_all_grant_material"
    ],
    "A09-05": [
        "tests/test_deep_campaign_api.py::test_sharing_identity_change_retires_all_grant_material"
    ],
    "A10-01": ["tests/test_audio_api.py::test_transcription_requires_consent"],
    "A10-02": [
        "tests/test_voice_remediation_2026_09_29.py::test_translation_suppressed_without_llm_consent"
    ],
    "A10-03": [
        "tests/test_voice_remediation_2026_09_29.py::test_retranslation_route_suppressed_without_llm_consent"
    ],
    "A10-05": ["tests/test_audio_api.py::test_transcription_input_validation"],
    "A11-01": [
        "tests/test_audio_attachments.py::test_upload_requires_consent_and_entry"
    ],
    "A11-02": [
        "tests/test_remediation_2026_10_03.py::test_expired_audio_replacement_does_not_subtract_excluded_bytes"
    ],
    "A11-03": ["tests/test_audio_attachments.py::test_quota_bounds_live_attachments"],
    "A11-04": [
        "tests/test_audio_attachments.py::test_lazy_expiry_answers_410_and_cleans_up"
    ],
    "A11-05": ["tests/test_audio_attachments.py::test_idor_on_fetch_and_delete"],
    "A12-01": [
        "tests/test_deep_campaign_api.py::test_export_retains_all_snapshot_chunks_when_byte_pages_are_short"
    ],
    "A12-03": [
        "tests/test_api_pins.py::test_export_streams_measures_decryptable_with_client_aad"
    ],
    "A12-04": [
        "tests/test_remediation_2026_10_03.py::test_export_has_one_audio_key_and_complete_v2_aad_metadata"
    ],
    "A12-05": [
        "tests/test_deep_campaign_api.py::test_completed_export_releases_capacity_for_next_download"
    ],
    "A13-01": [
        "tests/test_deep_campaign_api.py::test_analysis_uses_server_calendar_and_correct_voice_channel"
    ],
    "A13-02": [
        "tests/test_deep_campaign_api.py::test_analysis_rejects_semantically_invalid_authenticated_payload[payload0]"
    ],
    "A13-03": [
        "tests/test_deep_campaign_api.py::test_analysis_rejects_semantically_invalid_authenticated_payload[payload1]"
    ],
    "A13-04": [
        "tests/test_deep_campaign_api.py::test_analysis_uses_server_calendar_and_correct_voice_channel"
    ],
    "A13-05": [
        "tests/test_deep_campaign_api.py::test_feedback_truth_is_a_boolean_choice"
    ],
    "A13-06": [
        "tests/test_deep_campaign_api.py::test_feedback_does_not_silently_drop_supplied_wrong_shape[None-muted]"
    ],
    "A14-01": [
        "tests/test_deep_campaign_api.py::test_baseline_hides_stored_pattern_ciphertext_from_patient_and_clinician"
    ],
    "A14-02": ["tests/test_insights_api.py::test_full_pipeline_unlocks_at_threshold"],
    "A14-05": ["tests/test_insights_api.py::test_full_pipeline_unlocks_at_threshold"],
    "A15-01": ["tests/test_local_recompute.py::test_stale_base_state_seq_conflicts"],
    "A15-02": [
        "tests/test_deep_campaign_api.py::test_local_scope_claim_never_supplies_real_activity"
    ],
    "A15-03": [
        "tests/test_local_recompute.py::test_local_recompute_stores_blobs_without_a_processing_session"
    ],
    "A15-04": ["tests/test_local_recompute.py::test_validation_and_scope_grounded"],
    "A15-05": [
        "tests/test_deep_campaign_api.py::test_local_scope_claim_never_supplies_real_activity"
    ],
    "A16-01": [
        "tests/test_deep_campaign_api.py::test_resume_journal_binds_operation_even_for_same_payload_and_keys"
    ],
    "A16-02": [
        "tests/test_remediation_2026_10_03.py::test_atomic_v1_rotation_response_loss_and_old_writer_fence"
    ],
    "A16-03": [
        "tests/test_remediation_2026_10_03.py::test_v1_rekey_includes_audio_and_invalidates_obsolete_recovery"
    ],
    "A16-04": [
        "tests/test_remediation_2026_10_03.py::test_atomic_v1_rotation_response_loss_and_old_writer_fence"
    ],
    "A16-05": [
        "tests/test_remediation_2026_10_03.py::test_v1_rekey_includes_audio_and_invalidates_obsolete_recovery"
    ],
    "A17-01": [
        "tests/test_independent_audit_2026_09_27.py::test_deleted_chain_state_and_actor_role_tamper_fail_closed"
    ],
    "A17-02": [
        "tests/test_deep_campaign_api.py::test_audit_seals_bind_actor_role_and_chain_position"
    ],
    "A17-03": [
        "tests/test_independent_audit_2026_09_27.py::test_verifier_flags_malformed_hash_and_journal_ahead_with_rows"
    ],
    "A17-05": [
        "tests/test_deep_campaign_api.py::test_journal_compaction_preserves_old_final_owner_evidence"
    ],
    "A18-01": [
        "tests/test_residual_architecture_2026_10_04.py::test_incremental_audit_verifier_rejects_checkpoint_tampering"
    ],
    "A18-02": [
        "tests/test_deep_campaign_api.py::test_signed_checkpoint_binds_position_and_resets_unsealed_history"
    ],
    "A18-05": [
        "tests/test_deep_campaign_api.py::test_retention_refuses_to_destroy_a_tampered_prefix"
    ],
}

for _campaign in CAMPAIGNS:
    for _control in _campaign["mutants"]:
        if _control["id"] in OBSERVED_BEHAVIORAL_ORACLES:
            _control["tests"] = [pytest(*OBSERVED_BEHAVIORAL_ORACLES[_control["id"]])]
