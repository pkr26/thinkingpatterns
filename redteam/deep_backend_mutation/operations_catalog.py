"""Operational guarantees and complete account erasure: eight campaigns."""


def oracle(*targets, env=None, timeout=180):
    result = {
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
            *targets,
        ],
        "timeout": timeout,
    }
    if env:
        result["env"] = env
    return result


def mutant(identifier, name, file, find, replace, tests, count=1):
    return {
        "id": identifier,
        "name": name,
        "file": file,
        "find": find,
        "replace": replace,
        "tests": tests,
        "count": count,
    }


OPS = "tests/test_deep_campaign_operations.py::"
PG = oracle(
    OPS + "test_real_postgresql_upgrade_persists_schema_and_head",
    env={
        "DEEP_MUTATION_POSTGRES_URL": "postgresql+asyncpg://postgres@127.0.0.1:55488/mindpattern_mutation_test"
    },
)
CAMPAIGNS = [
    {
        "id": "O01",
        "name": "Request framing, body limits and error privacy",
        "mutants": [
            mutant(
                "O01-01",
                "Accept duplicate content length",
                "backend/app/middleware.py",
                "if len(content_lengths) > 1:",
                "if len(content_lengths) > 2:",
                oracle(OPS + "test_ambiguous_http_framing_never_dispatches"),
            ),
            mutant(
                "O01-02",
                "Accept length plus transfer coding",
                "backend/app/middleware.py",
                "if content_lengths and transfer_encodings:",
                "if False and content_lengths and transfer_encodings:",
                oracle(OPS + "test_ambiguous_http_framing_never_dispatches"),
            ),
            mutant(
                "O01-03",
                "Allow compound transfer coding",
                "backend/app/middleware.py",
                'len(transfer_encodings) != 1 or transfer_encodings[0].lower() != b"chunked"',
                "len(transfer_encodings) != 1",
                oracle(OPS + "test_ambiguous_http_framing_never_dispatches"),
            ),
            mutant(
                "O01-04",
                "Exceed complete body byte cap",
                "backend/app/middleware.py",
                "if seen > max_body_bytes:",
                "if seen > max_body_bytes + 1:",
                oracle(OPS + "test_unframed_body_limit_applies_to_every_method"),
            ),
            mutant(
                "O01-05",
                "Permit total body deadline exhaustion",
                "backend/app/middleware.py",
                "deadline = asyncio.get_running_loop().time() + self.body_read_timeout_seconds",
                'deadline = float("inf")',
                oracle(
                    OPS + "test_body_deadline_is_total_even_when_chunks_keep_arriving"
                ),
            ),
            mutant(
                "O01-06",
                "Accept a buffered receive after the total body deadline",
                "backend/app/middleware.py",
                "if remaining <= 0:",
                "if remaining <= -1:",
                oracle(
                    OPS
                    + "test_expired_deadline_refuses_even_an_already_buffered_receive_awaitable"
                ),
            ),
        ],
    },
    {
        "id": "O02",
        "name": "Rate windows, proxy identity and bounded counters",
        "mutants": [
            mutant(
                "O02-01",
                "Use wall time for sliding window admission",
                "backend/app/cache.py",
                "current = now if now is not None else time.monotonic()",
                "current = now if now is not None else time.time()",
                oracle(OPS + "test_rate_counter_monotonic_expiry_and_read_only_checks"),
                count=2,
            ),
            mutant(
                "O02-02",
                "Lose hits during compressed timestamp merge",
                "backend/app/cache.py",
                "state.log.appendleft((oldest_timestamp, oldest_count + next_count))",
                "state.log.appendleft((oldest_timestamp, next_count))",
                oracle(OPS + "test_rate_counter_compression_preserves_all_live_hits"),
            ),
            mutant(
                "O02-03",
                "Omit one recorded hit",
                "backend/app/cache.py",
                "state.total += 1",
                "state.total += 0",
                oracle(OPS + "test_rate_counter_monotonic_expiry_and_read_only_checks"),
            ),
            mutant(
                "O02-04",
                "Trust forwarded identity from arbitrary peer",
                "backend/app/middleware.py",
                "trusted_forwarding = self.trust_proxy_headers and direct_peer_is_trusted",
                "trusted_forwarding = self.trust_proxy_headers",
                oracle(
                    OPS
                    + "test_untrusted_socket_peer_cannot_supply_forwarded_rate_identity"
                ),
            ),
            mutant(
                "O02-05",
                "Admit exact exhausted failure budget",
                "backend/app/cache.py",
                "if result.count >= limit:",
                "if result.count > limit:",
                oracle(
                    "tests/test_infra_coverage.py::test_cache_keyed_limit_rejects_exactly_at_the_failure_budget"
                ),
            ),
        ],
    },
    {
        "id": "O03",
        "name": "Runtime ownership, locking, readiness and admission",
        "mutants": [
            mutant(
                "O03-01",
                "Admit past body buffer capacity",
                "backend/app/middleware.py",
                "if self._body_admitted >= capacity:",
                "if self._body_admitted > capacity:",
                oracle(
                    OPS
                    + "test_saturated_admission_rejects_before_reading_and_does_not_hang"
                ),
            ),
            mutant(
                "O03-02",
                "Serve after PostgreSQL ownership loss",
                "backend/app/main.py",
                "return owned is True",
                "return True",
                oracle(
                    OPS
                    + "test_lost_database_lock_disables_admission_and_scrubs_resident_keys"
                ),
            ),
            mutant(
                "O03-03",
                "Release nested process lock early",
                "backend/app/singleprocess.py",
                "if refs > 1:",
                "if refs > 2:",
                oracle(
                    "tests/test_infra_pins.py::TestSingleProcessGuard2026_09_20::test_inner_release_keeps_the_flock"
                ),
            ),
            mutant(
                "O03-04",
                "Treat a waiter lock as idle",
                "backend/app/locks.py",
                "entry.refs += 1",
                "entry.refs += 0",
                oracle(OPS + "test_cancelled_lock_waiter_does_not_split_owner_lock"),
            ),
            mutant(
                "O03-05",
                "Split live overflow lock into new dedicated lock",
                "backend/app/locks.py",
                "if shard.refs:",
                "if False and shard.refs:",
                oracle(
                    OPS
                    + "test_live_fallback_keeps_same_key_serialized_after_registry_space_opens"
                ),
            ),
        ],
    },
    {
        "id": "O04",
        "name": "Production startup, secret, transport and resource policy",
        "mutants": [
            mutant(
                "O04-01",
                "Allow insecure built-in production secret",
                "backend/app/config.py",
                'if self.token_secret == DEFAULT_INSECURE_SECRET and self.environment != "development":',
                'if False and self.token_secret == DEFAULT_INSECURE_SECRET and self.environment != "development":',
                oracle(
                    OPS
                    + "test_production_default_secret_refusal_is_not_masked_by_other_faults"
                ),
            ),
            mutant(
                "O04-02",
                "Lower signing secret floor",
                "backend/app/config.py",
                "if len(self.token_secret.strip()) < 32:",
                "if len(self.token_secret.strip()) < 3:",
                oracle(
                    "tests/test_hardening.py",
                    "tests/test_checklist_round1_crypto_auth.py",
                ),
            ),
            mutant(
                "O04-03",
                "Allow SQLite outside development",
                "backend/app/config.py",
                'if self.database_url.startswith("sqlite"):',
                'if False and self.database_url.startswith("sqlite"):',
                oracle(
                    "tests/test_hardening.py",
                    "tests/test_audit_oracles_remediation_2026_10_04.py::test_complete_staging_boot_and_single_fault_refusals",
                ),
            ),
            mutant(
                "O04-04",
                "Permit trusted forwarding without peer allowlist",
                "backend/app/config.py",
                "if self.trust_proxy_headers and not self.trusted_proxy_ips:",
                "if False and self.trust_proxy_headers and not self.trusted_proxy_ips:",
                oracle(
                    OPS
                    + "test_forwarding_trust_requires_an_actual_direct_peer_allowlist"
                ),
            ),
            mutant(
                "O04-05",
                "Disable aggregate body memory budget",
                "backend/app/config.py",
                "if worst_case_body_bytes * self.body_buffer_concurrency > MAX_BODY_BUFFER_BUDGET_BYTES:",
                "if False and worst_case_body_bytes * self.body_buffer_concurrency > MAX_BODY_BUFFER_BUDGET_BYTES:",
                oracle(
                    OPS + "test_complete_body_memory_budget_includes_larger_audio_cap"
                ),
            ),
        ],
    },
    {
        "id": "O05",
        "name": "Database constraints and real PostgreSQL migrations",
        "mutants": [
            mutant(
                "O05-01",
                "Disable SQLite foreign-key cascades",
                "backend/app/db.py",
                'cursor.execute("PRAGMA foreign_keys=ON")',
                'cursor.execute("PRAGMA foreign_keys=OFF")',
                oracle(OPS + "test_foreign_key_cascade_really_erases_child_rows"),
            ),
            mutant(
                "O05-02",
                "Remove journal client identity uniqueness",
                "backend/app/models.py",
                'UniqueConstraint("user_id", "client_entry_id", name="uq_user_client_entry")',
                'UniqueConstraint("user_id", "client_entry_id", "id", name="uq_user_client_entry")',
                oracle(OPS + "test_entry_duplicate_identity_is_a_database_constraint"),
            ),
            mutant(
                "O05-03",
                "Leave migration preamble transaction uncommitted",
                "backend/alembic/env.py",
                "        connection.commit()",
                "        pass",
                PG,
            ),
            mutant(
                "O05-04",
                "Omit trusted entry bootstrap marker row",
                "backend/alembic/versions/f4a2d8c6b901_entry_aad_guards.py",
                '    op.execute("INSERT INTO entry_guard_bootstrap (id, completed_at) VALUES (1, NULL)")',
                "    pass",
                PG,
            ),
            mutant(
                "O05-05",
                "Readiness accepts wrong schema revision",
                "backend/app/main.py",
                "if version != SCHEMA_HEAD:",
                "if False and version != SCHEMA_HEAD:",
                oracle(
                    "tests/test_infra_coverage.py::test_main_readyz_fails_closed_when_production_schema_is_not_at_head"
                ),
            ),
        ],
    },
    {
        "id": "O06",
        "name": "Privacy-safe metrics and maintenance visibility",
        "mutants": [
            mutant(
                "O06-01",
                "Lose histogram boundary observations",
                "backend/app/metrics.py",
                "if seconds <= bucket:",
                "if seconds < bucket:",
                oracle(OPS + "test_metrics_histogram_and_fixed_failure_categories"),
            ),
            mutant(
                "O06-02",
                "Expose wrong HTTP status family",
                "backend/app/metrics.py",
                'family = f"{status // 100}xx"',
                'family = f"{status // 10}xx"',
                oracle(OPS + "test_metrics_histogram_and_fixed_failure_categories"),
            ),
            mutant(
                "O06-03",
                "Suppress recompute count visibility",
                "backend/app/metrics.py",
                "self._recompute_count += 1",
                "self._recompute_count += 0",
                oracle(
                    "tests/test_ops_hardening.py::TestMetricsRegistry::test_recompute_histogram_is_cumulative"
                ),
            ),
            mutant(
                "O06-04",
                "Expose production metrics without scrape credential",
                "backend/app/main.py",
                'if live_settings.environment != "development":',
                'if False and live_settings.environment != "development":',
                oracle(
                    "tests/test_ops_hardening.py::test_metrics_hidden_without_token_in_production"
                ),
            ),
            mutant(
                "O06-05",
                "Stop reading the current metrics bearer",
                "backend/app/main.py",
                'expected = f"Bearer {live_settings.metrics_token}"',
                'expected = f"Bearer {settings.metrics_token}"',
                oracle(
                    "tests/test_ops_hardening.py::test_metrics_token_comes_from_the_live_settings"
                ),
            ),
        ],
    },
    {
        "id": "O07",
        "name": "Authenticated backup, exact retention and restore",
        "mutants": [
            mutant(
                "O07-01",
                "Decrypt unauthenticated backup bytes",
                "backup/backup_mac.py",
                "if not hmac.compare_digest(actual, sidecar.read_bytes().strip()):",
                "if False and not hmac.compare_digest(actual, sidecar.read_bytes().strip()):",
                oracle(
                    OPS + "test_backup_real_roundtrip_and_tamper_no_plaintext",
                    timeout=120,
                ),
            ),
            mutant(
                "O07-02",
                "Ignore mounted backup secret",
                "backup/backup_mac.py",
                "content = handle.read().strip()",
                'content = ""',
                oracle(
                    OPS + "test_backup_real_roundtrip_and_tamper_no_plaintext",
                    timeout=120,
                ),
            ),
            mutant(
                "O07-03",
                "Retain artifact at exact policy cutoff",
                "backup/backup_mac.py",
                "if child.stat().st_mtime <= cutoff:",
                "if child.stat().st_mtime < cutoff:",
                oracle(OPS + "test_backup_pruning_exact_boundary_and_scope"),
            ),
            mutant(
                "O07-04",
                "Leave orphan authentication sidecars forever",
                "backup/backup_mac.py",
                'or child.name.endswith(".dump.enc.hmac")',
                "or False",
                oracle(OPS + "test_backup_pruning_exact_boundary_and_scope"),
            ),
            mutant(
                "O07-05",
                "Authenticate original then decrypt changed original",
                "backup/backup_mac.py",
                "return _openssl(secret, snapshot, sys.stdout.buffer, decrypt=True)",
                'return _openssl(secret, ciphertext.open("rb"), sys.stdout.buffer, decrypt=True)',
                oracle(
                    OPS
                    + "test_decrypt_consumes_exact_authenticated_snapshot_despite_in_place_rewrite"
                ),
            ),
        ],
    },
    {
        "id": "O08",
        "name": "Logical account retirement and complete restart-safe erasure",
        "mutants": [
            mutant(
                "O08-01",
                "Leave retired account active",
                "backend/app/services/account_deletion.py",
                "    user.is_active = False",
                "    user.is_active = True",
                oracle(
                    OPS
                    + "test_logical_retirement_clears_credentials_and_queues_persistent_erasure"
                ),
            ),
            mutant(
                "O08-02",
                "Retain superseded recovery verifier",
                "backend/app/services/account_deletion.py",
                "    user.recovery_verifier = None",
                "    user.recovery_verifier = user.recovery_verifier",
                oracle(
                    OPS
                    + "test_logical_retirement_clears_credentials_and_queues_persistent_erasure"
                ),
            ),
            mutant(
                "O08-03",
                "Reset row budget at every purge phase",
                "backend/app/services/account_deletion.py",
                "remaining_budget = ACCOUNT_PURGE_ROW_BATCH - total_deleted",
                "remaining_budget = ACCOUNT_PURGE_ROW_BATCH",
                oracle(
                    OPS
                    + "test_purge_row_budget_is_shared_across_different_child_collections"
                ),
            ),
            mutant(
                "O08-04",
                "Declare erasure complete with pending objects",
                "backend/app/services/account_deletion.py",
                "if pending_audio is not None:",
                "if False and pending_audio is not None:",
                oracle(
                    "tests/test_residual_architecture_2026_10_04.py::test_ownerless_audio_tombstone_blocks_account_purge_completion"
                ),
            ),
            mutant(
                "O08-05",
                "Delete account before probing remaining dependent phases",
                "backend/app/services/account_deletion.py",
                "if remaining_phase is not None:",
                "if False and remaining_phase is not None:",
                oracle(
                    OPS
                    + "test_resumed_user_purge_phase_checks_dependents_before_bulk_cascade"
                ),
            ),
        ],
    },
]
