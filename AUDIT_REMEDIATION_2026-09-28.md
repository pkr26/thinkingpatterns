# Audit remediation — 2026-09-28

Every finding from `AUDIT_SESSIONS_2026-09-28.md` (the deep audit of the
last two sessions) was fixed and pinned with behavioral tests. This file
records the fixes; the audit doc carries the findings' full reasoning.

## Fix summary

| Finding | Fix | Pin |
|---|---|---|
| C-1 web v2 sign-in dead-end | `LoginView` installs the session BEFORE the envelope fetch (rolled back on every failure path; `adoptSession`'s refusal paths also clear it) | `web/tests/login.test.tsx` — fresh-module-state sign-in asserts the envelope request carries the bearer; red on the pre-fix code (verified by revert) |
| H-1 rekey stage-skip data loss | resume RE-WALKS every stage; journal cursors/counters are per-run bookkeeping, never resume input; docstrings corrected | `backend/tests/test_audit_remediation_2026_09_28.py` — post-crash writes rekeyed, stale journal cannot short-circuit, already-new measures resume without mismatch |
| H-2 journal anchor unwired | compose wires the named `auditjournal` volume + `MINDPATTERN_AUDIT_JOURNAL`; the Dockerfile owns the mount point for the app uid | compose YAML validated (env + volume + declaration); `verify.sh` remains the config gate |
| H-3 queue wiped by lockDown race | the write-after-abort "rollback" is gone: the raced enqueue throws honestly and storage keeps every parked entry | `web/tests/queue.test.tsx` — a parked entry + a raced second save both survive |
| M-1 v2 password probe exemption | `X-Processing-Token` required from EVERY caller of `PUT /account/password`; the possession probe (stored-ciphertext authentication) gates every envelope swap; web + mobile clients open the session first | `backend/tests/test_key_envelope_v2.py` — no token 422, wrong key 403, envelope untouched; client pins in web/portal settings tests + mobile rotation tests |
| M-2 portal composer jam | both 409 codes (`conflict`, `version_conflict`) burn the pending id; comment states the real byte-identical-replay contract | `portal/tests/views.test.tsx` — a timed-out save retries with a FRESH id and succeeds |
| M-3 Entry mood-log zeroize race | data key snapshotted before the encrypt await, re-checked before `recordMood`, honest abort on lock (the Measures P1 pattern) | `web/tests/entry.test.tsx` — mood history intact, nothing sent, honest message |
| M-4 second-tab old-key uploads | rotations broadcast a cross-tab lockdown (`BroadcastChannel`) before the first server step; every live tab funnels into the same lockDown | `web/tests/app.test.tsx` + `web/tests/settings.test.tsx` — broadcast locks the other tab; rotation broadcasts before any server call |
| M-5 journal growth + O(n²) sweep | single-pass `read_journal_heads` feeds the sweep; retention-aligned atomic compaction runs after verification | backend tests — heads map, compaction boundaries, sweep end-to-end |
| L-1 hydration truncation | `hydrate` sets the overflow flag when the table meets the cap → point-query fallback engages at boot | `test_hydration_truncation_marks_the_cache_overflowed` |
| L-2 MAC comparison | `hmac.compare_digest` in `verify_access_log_chain` (tokens.py discipline) | existing MAC pins |
| L-3 drift scope | `backup/` + `*.yaml` workflows join the scan | live walk collects the same 9 pins with the wider scope |
| L-4 metrics-token sinks | CI + release write BOTH sinks (`deploy/secrets/metrics_token` + `deploy/monitoring/token`) with a `cmp` equality assertion; release's existence loop includes the file; `verify.sh` checks on-host equality when both exist | workflow steps + verify.sh assertion |
| L-5 selftest coverage | every failure mode asserted INDIVIDUALLY (incl. the new future-dated-row fixture); live walk enforces `MIN_PINS_EXPECTED=9` | `--selftest` output proves each mode |
| L-6 release concurrency | single `release` group, `cancel-in-progress: false` — release runs serialize; nothing is killed mid-publish | YAML validated; comment states the semantics |
| L-7 Web Locks fallback | Lamport-bakery mutex over localStorage (monotonic tickets, randomized beat, stale-vote sweep, keepalive) for Safari < 15.2 | `web/tests/platform.test.ts` — mutual exclusion (stress-verified), stale sweep, no residue |
| L-8 stamp sweep | `sweepLegacyCrisisStamps()` runs at App mount for every visitor | `web/tests/app.test.tsx` |
| L-9 orphaned reminders | one-time migration: cancel-all + reschedule-from-prefs on first resync, guarded by a persisted flag | `mobile/tests/nativeFeatures.test.ts` |
| L-10 SAS cross-check copy | explicit "local cross-check could not run" note beside the key id | `portal/tests/views.test.tsx` |

## Honest residuals (documented, not hidden)

- The bakery fallback's mutual exclusion holds under localStorage's
  coherent same-origin store; browsers whose storage throws (private-mode
  edge) still degrade to the unlocked run — disclosed in `platform.ts`.
  Past `LOCK_MAX_WAIT_MS` (30s) liveness wins over exclusion.
- The audit journal's threat model is unchanged: it binds a DATABASE-only
  attacker; anyone who can write the volume can truncate the anchor (now
  stated in the compose comment). Compaction is retention-aligned and
  atomic.
- The rekey mismatch path is now loud where it was silently lossy: a
  journal abandoned under different keys answers `rekey_key_mismatch`
  until that rotation is completed with its own keys (v1 keys are
  password-derived, so "retry with the same intended new password" is the
  documented resolution).
- The v2 password change costs one extra `POST /processing/sessions`
  round trip — the price of the possession probe (no corpus walk).

## Verification (this round, all re-run)

| Gate | Result |
|---|---|
| backend pytest + coverage gate | 1,615 passed + 4 skipped (live-PG profile), exit 0 |
| backend coverage | 97.09% ≥ 97 gate |
| backend ruff / format / mypy | clean |
| backend probe_brain | 9/9 PASS, exit 0 |
| web (test + typecheck + build) | 647 passed + 5 skipped; all exit 0 |
| portal (test + typecheck + build) | 412 passed; all exit 0 |
| mobile (test + typecheck) | 1,928 passed + 1 skipped; exit 0 |
| mobile crypto-vector replay | 4 vectors + wrap/AAD sets verified |
| drift gate `--selftest` | exit 0 — all six failure modes proven individually |
| drift gate live walk | exit 0 — 9 pins current, min-count enforced |
| monitoring verify.sh | exit 0 (incl. the new sink-equality check) |
| compose / workflow YAML | parsed + asserted programmatically |
