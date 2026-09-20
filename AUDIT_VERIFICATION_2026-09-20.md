# MindPattern — Independent Audit-Fix Verification

**Date:** 2026-09-20
**Scope:** Every numbered finding in `AUDIT_FINDINGS.md` (2026-09-19): 1 Critical, 20 High, 36 Medium, 97 numbered Low, 33 numbered Info observations.
**Method:** 11 independent verifier agents + lead spot-checks, each reading the current working-tree fix code (not test names or CHANGELOG claims), running the engines on the audit's original repro inputs where applicable, and running targeted test files. Global gates re-run by the lead: backend pytest **exit 0 (all pass)**, mobile vitest **1501/1501**, portal vitest **166/166**.
**Verdicts:** FIXED · PARTIAL (fix incomplete on a named surface) · NOT FIXED · ACCEPTED (deliberate trade-off, documented) · for Info items: STILL-HOLDS / ADDRESSED / CHANGED.

> Note: `AUDIT_FINDINGS.md`'s own severity table (and the CHANGELOG's "114 actionable findings") counts 57 Low items, but the Low section numbers 97 items (1–46 backend, 47–72 mobile, 73–82 portal, 83–97 deploy/docs). This report verifies all 154 numbered actionable items + 33 Info items.

## Bottom line

| Severity | Fixed | Partial | Not fixed | Accepted |
|---|---|---|---|---|
| Critical (1) | 1 | 0 | 0 | 0 |
| High (20) | 19 | **1 (H-7)** | 0 | 0 |
| Medium (36) | 35 | **1 (M-4)** | 0 | 0 |
| Low (97) | 90 | **2 (L-38, L-54)** | **3 (L-19, L-30, L-55)** | 2 (L-22, L-26) |
| **Actionable total (154)** | **145** | **4** | **3** | **2** |

Info (33 observations): 28 still-hold exactly as documented (expected — no-action trade-offs), 4 addressed alongside related fixes (I-2, I-10, I-11, I-33), 1 changed (I-28: portal now has load-generation guards, rest of the note holds).

All three full test suites are green on the fixed tree.

## Close-out (second pass, same day): all 7 stragglers fixed

After the verification above, the 4 PARTIAL / 3 NOT-FIXED findings were fixed and re-verified; the table's deficits are now **0 across all severities** (154/154 actionable findings resolved; L-22/L-26 remain the two documented accepted trade-offs). Details:

- **H-7 → FIXED.** Both engines gained a fourth "letter-doubling" channel: same-letter runs collapse on BOTH sides — the folded text variant ("kiill myself" → "kil myself") is matched only against folded tier twins ("kill(?:ed|ing)? myself" → "kil(?:ed|ing)? myself"), consulted after the canonical channel (can only add catches). `off(?:ing)? myself` is exempt from the folded tier (its fold matches ordinary "of myself" prose — pinned by benign corpus rows); benign compounds re-mask after folding with folded spellings ("suiciide squaad" stays silent — pinned). Corpus +6 letter-doubling rows, fixtures extended, unit pins on both platforms, e_crisis re-run (0/79 crisis samples bypass; 0 contract drift), 272-case cross-engine differential: zero divergence. (crisis.py `_dedup_fold`/`_folded_variants`; crisisDetect.ts `dedupFold`/`foldedVariants`.)
- **M-4/L-55 → FIXED.** `api.listMeasures()` walks offset pages of 500 until a short page, dedups by id (concurrent-insert shift guard), stops at the 2000-quota bound; `listMeasuresPage(limit, offset)` exposed for direct paging. Pinned by 4 new client tests (walk, short-page, dedup, lying-server bound).
- **L-19 → FIXED.** `effective_sample_size` clamps outermost to n (`min(n, max(3, raw))`); docstring corrected; n<3 regression test added.
- **L-30 → FIXED.** `pattern_pid` disclosed in the models.py comment, README "Metadata the server does hold", and the DPIA (data-processed, minimisation, and metadata-risk rows).
- **L-38 → FIXED.** The `if True:` block in `_audit_measure.py` dedented.
- **L-54 → FIXED.** `classifyError` propagates `retryAfterMs` on the 5xx branch (503 advisories honored); pinned by a queue test.
- Extras from the verification pass: login requests send no bearer and never trip the vault-lock hook (the H-2 biometric wart — client.ts `noBearer` option + test); the M-5 test now asserts `patterns_new`/`patterns_fading` against the decrypted payload; three stale comments corrected (TherapistShareScreen v1 claim, brain.py "script-independent phrase repetition", AccessLog action docstring now listing `read_measures`/`list_patients` — Info I-12 addressed).

Final gates after the close-out: backend pytest **all pass**, mobile vitest **1533/1533**, portal vitest **166/166**, e_crisis 0 findings, tsc --noEmit clean.

Process note: during the close-out, a `git checkout` briefly reverted `shared/crisis_phrases.json` to HEAD, losing that file's uncommitted fix-wave edits. It was fully rebuilt from authoritative sources (the backend/mobile embedded pattern arrays, which are byte-pinned to the JSON, and the 84-row contract in `redteam/crisis_corpus.json`), extended with the new rows, and re-verified: backend crisis + contract-pin suites, both mobile crisis suites, the corpus replay on both engines, and a fresh e_crisis run all pass with zero drift.

## Outstanding items at verification time (all since fixed — see close-out above)

### H-7 (was PARTIAL) — crisis corpus: letter-doubling still bypassed every tier
Everything else in H-7 was verified fixed **live on both engines**: the Romance `suicid*` family, "no quiero vivir", "cansado de vivir", past-tense ("i almost killed myself last year", "i nearly took my own life"), SMS "2"→"to" ("i want 2 die", "no reason 2 live"), and trailing leet ("suicid3", "i want to d13") all reach the dialog tier on backend and mobile identically.
**Was missing:** doubled-letter variants — `"kiill myself"` and `"suiccide"` matched **neither tier on either engine** (re-verified independently by the lead on the backend engine after the agent's finding; no doubled-letter collapse existed in either engine and no test covered it). The CHANGELOG's H-7 entry omitted this sub-case. **Fixed in the close-out** (folded channel, above).

### M-4 (was PARTIAL — FIXED in close-out) — measures paging: mobile client surface was unfinished
Backend `list_measures` now takes `limit`/`offset` with a deterministic `(measure_date, received_at, id)` keyset (measures.py:236-269) and the therapist mirror pages identically (therapist.py:673-735); export includes measures (H-3) and the portal walks all pages up to the 2000 quota with a rendered truncation count (PatientView.tsx:313-335, 758-760).
**Still missing:** `mobile/src/api/client.ts:702` `listMeasures()` sends no paging params and MeasuresScreen makes one unpaged call with no truncation signal — the patient-facing app still silently shows only the newest 100 of up to 2000 quota-charged measures (this is also Low finding **L-55**, not fixed for the same reason).

### L-19 (was NOT FIXED — FIXED in close-out) — `statsig.py:232` `effective_sample_size` floor can exceed actual n for n<3 with strong lag-1 (returns 3.0 > n); the docstring's "clamped to [3, n]" is still false in that case. Byte-identical to pre-fix; only the unrelated M-7 BF fix landed in the file.

### L-30 (was NOT FIXED — FIXED in close-out) — `TherapistNote.pattern_pid` remains analysis-derived plaintext outside the documented clear-metadata set; neither models.py's comment, README's "Metadata the server does hold", nor the DPIA was updated to include it. Behavior is the conscious trade-off; the documentation gap is the unfixed part.

### L-38 (was PARTIAL — FIXED in close-out) — `_audit_measure.py` dead condition: `if seed == 2000 or True:` became a literal `if True:` with an explanatory comment — honest about it now, but still structurally dead in a scratch file (dedent was the real fix).

### L-54 (was PARTIAL — FIXED in close-out) — `client.ts` now parses `Retry-After` on 429 **and** 503, but `offlineQueue.ts:374-383` `classifyError` propagates `retryAfterMs` only on the 429 branch — a 503 advisory still falls to the generic 30s+ local backoff, the finding's exact symptom.

### Accepted by design (verified as such)
- **L-22** — concatenated "iwannadienow" still matches nothing; retained because the trailing anchor is what keeps "i wanna diet" benign (documented).
- **L-26** — future-dated entries still count toward unlock; kept as the documented trade-off, bounded by the API's +1-day forward-grace check.

## New observations surfaced during verification (not in the original audit)

1. **H-2 residual (minor, fail-closed):** in a biometric-unlocked session, the new online wrong-password check fires `api.login` → 401 → `client.ts`'s `onUnauthorized` hook locks the vault while the "wrong password" alert is showing. No data loss; user re-unlocks. The reauth tests mock `api.login` and never exercise this interaction.
2. **Measures paging has no collection-revision guard** (unlike entries' `X-Entries-Revision`): a concurrent insert during a multi-page walk can shift rows across pages. Portal tolerates it via id-dedup; mobile doesn't page at all (see M-4).
3. **Stale comments:** `TherapistShareScreen.tsx:42-50` still claims client.ts pins disclosure "v1" (it pins v2); `brain.py:3598` still says "script-independent phrase repetition still counts", contradicting the corrected README/comments from the M-10 fix.
4. **Language-tag edge (pre-existing):** a Cyrillic corpus yields `stats.language: "en"` (not "other") because `[a-z']+` scores zero tokens — the mobile "not yet supported" card keyed on `"other"` won't render for non-Latin journals.
5. **Test gaps (code verified correct by inspection):** the M-5 test doesn't assert `patterns_new`/`patterns_fading` counters; no test pins the Cyrillic quiet path from M-10.
6. **M-13 residual (unwedges):** the rejected store has no byte cap; an oversize row quarantines + clears instead of wedging, so the original failure mode cannot recur.

## Per-finding verdicts

### Critical
| ID | Verdict | Evidence |
|---|---|---|
| C-1 | FIXED | EntryScreen.tsx:274-286 acquires `vault.get()` AFTER the `getUserId` await (no await between get and `encryptEntry`); lock mid-save now throws → "Could not save". Mood chain snapshots `Buffer.from(keys.dataKey)` (EntryScreen.tsx:332, zeroized :337); moodLog re-snapshots in every public fn (moodLog.ts:164,193,207,237); moodLog.test.ts:233-258 arms the exact zeroize-mid-record interleaving. |

### High
| ID | Verdict | Evidence |
|---|---|---|
| H-1 | FIXED | `canonicalOrigin` shared helper (client.ts:105-119); both sides canonicalized at client.ts:427-431 and offlineQueue.ts:113-120; real-`request()` test against the default localhost base passes (client.request.test.ts:979-996). |
| H-2 | FIXED | `authKeyKnown` flag (vault.ts:34,44-50) + online `api.login` fallback with adoption (reauth.ts:77-92); honest offline copy (en.ts:38, SettingsScreen.tsx:202-205). Minor NEW wart noted above. |
| H-3 | FIXED | account.py:467-536 streams Measures with the byte-bounded keyset; schemas.py:216-223; decrypt_export.mjs:142-154 with the client's measure AAD; end-to-end tool run decrypted measures. |
| H-4 | FIXED | generate_vectors.py:184-225 merges (only `vectors`/`encrypt_vectors` regenerated; wrap/aad preserved — verified by backup/restore run); verify_vectors.mjs:29-54 fails closed on all 4 sections and verifies wrap vectors through shipping `sharing.ts` (:222-299). |
| H-5 | FIXED | prometheus.yml:55 `bearer_token_file`; compose `configs: metrics_token` mount (docker-compose.yml:33-37,119-121); gitignored token file; claims corrected; verify.sh:151-166 enforces it (ran: ALL CHECKS PASSED). |
| H-6 | FIXED | HistoryScreen.tsx:642-652 runs `detectCrisisLanguage(trimmed)` after successful `api.updateEntry` with the same throttle + copy as EntryScreen; historyScreen.test.tsx:1157-1235. |
| H-7 | **PARTIAL** | See "Outstanding items". All other sub-cases fixed and engine-verified live (crisis.py:67,74,111-113,302,386-389; crisisDetect.ts twins; shared/crisis_phrases.json). |
| H-8 | FIXED | `quiero` 0.3 (sentiment_lexicon_es.py:122); ES death-word class (:321-338); diacritic + U+2019 fold pre-tokenization both platforms (brain.py:1460-1500, sentiment.ts:90-114). Live: "tengo depresión" −0.75, "pienso en el suicidio" −0.95, "quiero morir" −0.65, U+2019 "don't" −0.351; 48-case vector set pinned both sides. |
| H-9 | FIXED | STATISTICAL_KINDS (brain.py:116-143) now gates cadence, avoidance, all three inertias, coupling, sense-making, diversity; rising topic via `_is_statistical` (:180-187); dead wiring connected (EVIDENCE_DATE_KINDS/WINDOW_STAT_KINDS :162-176 → `_replication_satisfied` :3259-3290). Live probes: energy_inertia/cadence stay candidate on first qualification; tests test_brain.py:1173-1189. |
| H-10 | FIXED | Writing calendar = all window entry dates (brain.py:3732-3734); mood-day censoring kept only for the weekday base rate (:3681-3683). German repro rerun: 60 daily entries, zero fabricated avoidance. |
| H-11 | FIXED | Flip reuses an existing fork matching kind + semantic detail before minting (brain.py:3306-3339). Probe: base + one `~2` with 14 qualification days that surfaces; no ~3..~14. |
| H-12 | FIXED | Same-day pin: existing `kind="question" AND for_date=today` row skips regeneration (insights.py:759-772, 993-999, 1071-1074); test asserts identical question + pid across same-day recompute. |
| H-13 | FIXED | PatientView.tsx:604 passes sentiment through (null preserved), sparkline filters non-numerics (:826-828); copy-forward `.at(-1)` (:956) over `created_at ASC` rows. |
| H-14 | FIXED | Disclosure **v2** naming measures + summaries on all four sides (consents.py:82, en.ts:717-718, es.ts:705-706, client.ts:67/905); v1 consents refuse measure reads with 409 `disclosure_outdated` while entries/insights continue (therapist.py:702-707); `list_patients` writes per-patient AccessLog rows (therapist.py:599-605); `disclosure_outdated` in API_ERROR_CODES (client.ts:340) + meta version compared pre-grant (TherapistShareScreen.tsx:87-89). |
| H-15 | FIXED | `PYTEST_SETUP_EXITS {2,3,4,5}` + no-tests check → SETUP-ERROR fails the gate (all 3 harnesses + run_pr_mutation_gate.py:106-111); `backend/tests/**` in paths (mutation-pr.yml:28); B1 sets `llm_url` (b_auth.py:37) and now reports a real FINDING; C2 gated on observed 503s (c_api.py:67-76); all results regenerated 2026-09-20, stale FINDINGs gone. |
| H-16 | FIXED | Summary served only when `active and insight_phase` via `_entry_dates`+threshold (therapist.py:562-571, 590-596); `state_seq=latest.state_seq` (:659) matching the patient path. |
| H-17 | FIXED | tokens.py:100-104 `try/except OverflowError` + `MAX_EXP_EPOCH` bound. Reproduced: exp=10**400 / −10**400 / 2**2048 → `TokenError("malformed payload")`. |
| H-18 | FIXED | Null-prototype tables via `nullProto` for all four Record tables (sentiment.ts:52-73); "constructor" vector in shared/brain_vectors.json; 52 vector tests pass. |
| H-19 | FIXED | DPIA_SKELETON.md:48-54 now describes server-side streamed ciphertext export + offline decrypt CLI and states there is no in-app export; SettingsScreen still fails closed — they now agree. |
| H-20 | FIXED | loadtest seeds 32 distinct days, backdates handles, asserts phase/analyzer (loadtest.py:174-188, 274-315); probe check B pinned to the sleep-cluster rumination label (probe_brain.py:251-254); live probe 9/9 with the sleep sentence surfaced as confirmed rumination. |

### Medium
| ID | Verdict | Evidence |
|---|---|---|
| M-1 | FIXED | Pre-dispatch limiter gate on buffered body (middleware.py:398-430), post-response 422-parse counting into the same bucket (:455-470), rules built from the live router. Reproduced: raw malformed body now 422×3 → 429s. |
| M-2 | FIXED | `expected_epoch` captured pre-fence (insights.py:606), in-fence epoch equality check before any decrypt (:698-704); test simulates the pre-logout bearer. |
| M-3 | FIXED | measures.py:159 + `_fresh_active_measure_user` (:115-128) epoch check before duplicate/quota queries. |
| M-4 | **PARTIAL** | Backend + therapist + portal + export fixed; mobile client still unpaged (client.ts:702, MeasuresScreen.tsx:105). |
| M-5 | FIXED | Unmuted-only cap with muted bypass (insights.py:819-836); counters recomputed over the final stored list (:1138-1141). |
| M-6 | FIXED | `_clean_narrative` guards: second-person advice, sentence-anchored imperatives, manipulation phrases, generic `word dot word` domains (llm.py:359-436). All four audit repro strings → rejected; benign prose passes. |
| M-7 | FIXED | Upper-tail only `min(1.0, f_sf(...))` (statsig.py:296); near-equal spreads now p=0.227 (was 2.4e-06). |
| M-8 | FIXED | Day-mean collapse before Welch/Cohen (brain.py:2156-2181); audit fixture now p=2.5e-13 vs 1.7e-37 entry-level; degenerate case p=1.0. |
| M-9 | FIXED | Stale candidates archive before the fading branch for all kinds (brain.py:3436-3439, `SURFACED_STATES` :284). |
| M-10 | FIXED | Docs-corrected route: README + comments now scope phrase repetition to tokenizable Latin scripts (README.md:112-118, brain.py:259-265); behavior matches docs. |
| M-11 | FIXED | Phase re-read + re-evaluation inside the fence (insights.py:713-728); test proves zero SQL post-fence on collapse. |
| M-12 | FIXED | Fresh `openProcessingSession` before the fallback recompute (QuestionScreen.tsx:143-153). |
| M-13 | FIXED | Byte cap 1 MB + `readItems` getItem inside try with quarantine-and-clear recovery (offlineQueue.ts:28,243-289,349). |
| M-14 | FIXED | 401 mid-flush keeps every item queued with `notBefore +15min` (offlineQueue.ts:418-443); auto-drain on reconnect intact. |
| M-15 | FIXED | All failure alerts (401/422/queueFull/queueAbandoned/outer catch) carry crisis onPress (EntryScreen.tsx:352-431). Residual: `!userId` alert (pre-existing edge). |
| M-16 | FIXED | MeasuresScreen fully `tr()`-driven incl. PHQ-9 items/options + crisis copy; keys in en.ts:662-674 and es.ts:654-666. |
| M-17 | FIXED | Corpus booleans regenerated from the live engine on every e_crisis run (e_crisis.py:29-36); f_mobile.test.ts measures against the contract + dialog-tier parity; re-verified all 84 rows: 0 mismatches. |
| M-18 | FIXED | Gate re-derived from persisted `hasSeenOnboarding` on every main entry (navigation.tsx:113-121) with boot-splash hold. |
| M-19 | FIXED | signOut calls `disableBiometricUnlock(userId)` + `cancelDailyReminder()` (store.tsx:272-284). |
| M-20 | FIXED | U+2065 added to the backend invisible set (crisis.py:216-226); differential fuzz 469 U+2065-spliced strings: 0 divergences. |
| M-21 | FIXED | Scan row preferred; summary renders "as of ${forDate}" (PatientsView.tsx:235-236, crypto.ts:342-343). |
| M-22 | FIXED | "Open my notes" for stopped patients + notesOnly chart mode (PatientsView.tsx:263-267, PatientView.tsx:258,305-308); backend `_note_target` requires any-status consent (therapist.py:919-939). |
| M-23 | FIXED | Two-step arm + confirm delete (PatientView.tsx:281,904-923). |
| M-24 | FIXED | Topic templates selected by `detail.trend`; steady set mirrors `Pattern.describe()` (questions.py:176-212); pinned by test_questions.py:114-136. |
| M-25 | FIXED | Meta version compared pre-grant, stale blocks the card with dedicated copy; 409 path handled via `isDisclosureOutdated` (TherapistShareScreen.tsx:87-89,202-213,301-308; client.ts:340). |
| M-26 | FIXED | Metrics outermost; Hardening's last-ditch/429/recursion paths call `status_observer` (main.py:353/403/418, middleware.py:236-237,480-502); 413 exclusion documented. |
| M-27 | FIXED | `(fd, refs)` refcounting; unlock only at depth 0 (singleprocess.py:62,157-164,209-224); subprocess test proves the flock survives inner release. |
| M-28 | FIXED | `make_url` normalization: loopback collapse, port materialization, sorted query params, normpath sqlite (singleprocess.py:73-120). |
| M-29 | FIXED | Boot-time `1 <= access_log_retention_days <= 3650` (config.py:398-399). |
| M-30 | FIXED | Audit row committed in a short transaction right after the blob fetch, before any raise (therapist.py:785/864, 1045/1101-1114); pre-fetch refusals documented as unaudited. |
| M-31 | FIXED | Per-kind AAD branch: question/brain/patterns (decrypt_export.mjs:119-126); end-to-end decrypt of all insight kinds verified. |
| M-32 | FIXED | `MUTATION_PY="$(command -v python)"` exported + venv symlink layout matches harness resolution (mutation-pr.yml:85). |
| M-33 | FIXED | N4 (and round-3 O6/S10) in `DOCUMENTED_RESIDUALS` (run_pr_mutation_gate.py:48). |
| M-34 | FIXED | c1 requires the literal "already serving this deployment" signature (c1_multiworker.py:140-166); h_privacy verdicts gate on `has_cleartext`/`keys_held` (h_privacy.py:94-95,135-137). |
| M-35 | FIXED | Readers through `serialized()`; migration inside the mutex (moodLog.ts:118,195,209); `feedbackMutex` on appendEvent (questionFeedback.ts:48-101); interleaving tests. |
| M-36 | FIXED | `localWeekday()` localizes English weekday names at render via Intl anchor (InsightsScreen.tsx:170-190); es register fixed (es.ts:360-363). |

### Low — backend (L-1…L-46)
| ID | Verdict | Evidence |
|---|---|---|
| L-1 | FIXED | test_crypto.py:128-155 rglob source-scan backs the docstring. |
| L-2 | FIXED | tokens.py:73-105 validates uid/ep/exp shapes (ep rejects bool). |
| L-3 | FIXED | sharing.py:70-75 comment now says 30 symbols / ≈39.2 bits, U deliberately excluded. |
| L-4 | FIXED | `_cors_extra_headers` on every short-circuit (middleware.py:182-208,506-528); negative tests. |
| L-5 | FIXED | UTC today in both bounds (entries.py:246, measures.py:66-74); frozen-clock test. |
| L-6 | FIXED | Duplicate check before quota (entries.py:309-322, measures.py:166-179); 409-at-boundary test. |
| L-7 | FIXED | Measures error envelope matches entries (422/validation_error, 401/unauthorized). |
| L-8 | FIXED | Insight.id snapshot frozen in the head transaction; pages walk the frozen id list (account.py:176-200,374-411). |
| L-9 | FIXED | Share pages select metadata columns only (account.py:238-254). |
| L-10 | FIXED | SecureProcessingContext constructed inside the worker callable (insights.py:883-894). |
| L-11 | FIXED | `_parse_feedback` raises 400 `entry_payload_malformed` (insights.py:429-468). |
| L-12 | FIXED | FK vs unique violation distinguished (therapist.py:204-217,1233-1252): FK → 404. |
| L-13 | FIXED | `repr=False` on all credential fields (config.py:166-239); masking tests. |
| L-14 | FIXED | Empty `last_qualified` treated as maximally stale → archive/drop (brain.py:3426-3434). |
| L-15 | FIXED | `isfinite` filter on "other" mood tags (brain.py:3616-3624). |
| L-16 | FIXED | Dict-shaped records re-validated via `_stored_from_dict` (brain.py:1889-1906,3506-3509). |
| L-17 | FIXED | Phrase pid = `phrase:{digest}` anchored on earliest member, kind-free (brain.py:2630-2648,2744). |
| L-18 | FIXED | Tripwire checks every cluster variant with a `suppress_variant_seen` bit (brain.py:2729-2737,3462-3477). |
| L-19 | **NOT FIXED** | statsig.py:232 unchanged (floor can still exceed n for n<3). |
| L-20 | FIXED | Stripped URL in emptiness check + fingerprint (llm.py:190,199). |
| L-21 | FIXED | Comment corrected to ≈0.9998 (phrases.py:27-28). |
| L-22 | ACCEPTED | Trailing-anchor trade-off retained and documented. |
| L-23 | FIXED | CJK/Spanish prevention-compound masking (crisis.py:177-185,506-513); "我们讨论了自杀预防" no longer fires, genuine CJK ideation still does. |
| L-24 | FIXED | GENERIC_QUESTIONS pinned byte-for-byte to shared JSON (test_contract_pins.py:294-306). |
| L-25 | FIXED | Taxonomy comment defers to brain.py, "17 kinds as of 2026-09-20" (patterns.py:188-190). |
| L-26 | ACCEPTED | Documented trade-off kept; forward-grace bound noted. |
| L-27 | FIXED | `StrictRequestModel(extra="forbid")` on all 15 request models (schemas.py:18-26). |
| L-28 | FIXED | Display-name excludes Cc/Cf(bidi,ZW,BOM)/Zl/Zp (schemas.py:258-275). |
| L-29 | FIXED | `pattern_pid` min_length=1 (schemas.py:368-374). |
| L-30 | **NOT FIXED** | pattern_pid still outside the documented metadata set; no doc update. |
| L-31 | FIXED | LLM fields None when unavailable (meta.py:31-38). |
| L-32 | FIXED | cache.py docstrings corrected ("login is deliberately IP-only"). |
| L-33 | FIXED | ORM `server_default` now matches the migration (models.py:95,229,232); create_all verified emitting the defaults. |
| L-34 | FIXED | gen_brain_vectors imports WORD_RE (gen_brain_vectors.py:117-120). |
| L-35 | FIXED | Throughput = successes/wall time (loadtest.py:66-74). |
| L-36 | FIXED | Deterministic domain-separated salt (409→login re-run works); usage documents --db-url; docstring says 84 (seed_demo.py:16-24,238,253-259). |
| L-37 | FIXED | Instructions corrected (dump_brain_lexicon.py:12-16). |
| L-38 | **PARTIAL** | `or True` gone, replaced by literal `if True:` + comment (scratch file). |
| L-39 | FIXED | Checks B/C/F iterate surfaced only (probe_brain.py:251-258,289-298). |
| L-40 | FIXED | Vacuous assertion replaced with the load-bearing one (test_redteam_fixes_2026_09_16.py:115-131). |
| L-41 | FIXED | Fast hard-fail committed-file test + slow test hard-asserts existence (test_kdf.py:107-145). |
| L-42 | FIXED | Existing-file sqlite test URLs rejected unless temp/absent/opt-in (conftest.py:78-111). |
| L-43 | FIXED | Case-insensitive exclusion; E3 BLOCKED (e_crisis.py:111-143). |
| L-44 | FIXED | Zero-request egress → ERROR verdict; D1 mismatches computed and asserted (d_llm.py:147-166,255-265). |
| L-45 | FIXED | Summary built from recorded outcomes — text always agrees with data (b_auth.py:129-139). |
| L-46 | FIXED | Refusal credited only on the expected stderr signature (g_infra.py:144-161). |

### Low — mobile (L-47…L-72)
| ID | Verdict | Evidence |
|---|---|---|
| L-47 | FIXED | Sources zeroized after copy in PBKDF2/HKDF (kdf.ts:85-120). |
| L-48 | FIXED | `ENTRY_PAYLOAD_VERSIONS [1,2]` loud-fail guard (MindPatternCrypto.ts:75,84-90). |
| L-49 | FIXED | 500ms local-mismatch delay (reauth.ts:29-33,96). |
| L-50 | FIXED | Per-account Keychain service slots + legacy migration cleanup (biometricUnlock.ts:37-53,89-138). |
| L-51 | FIXED | Server advisory honored up to 60min; RETRY_MAX_MS bounds only local backoff (offlineQueue.ts:355-360,463-481). |
| L-52 | FIXED | Foreign-userId records quarantined verbatim (offlineQueue.ts:265-278). |
| L-53 | FIXED | NFD + combining-mark strip + lowercase on both sides (historyFind.ts:24-35). |
| L-54 | **PARTIAL** | client parses 503 Retry-After; queue's classifyError drops it (offlineQueue.ts:374-383). |
| L-55 | **NOT FIXED** | listMeasures sends no paging params; one unpaged render (client.ts:702, MeasuresScreen.tsx:105). |
| L-56 | FIXED | No stash while save in flight; finally-stash only if `unmounted && !landed` (EntryScreen.tsx:214,341,350,371,435-443). |
| L-57 | FIXED | Status-0 → `phaseAssumedOffline` with offline captions (QuestionScreen.tsx:189-199,328-331). |
| L-58 | FIXED | Main list phase-gated like siblings (InsightsScreen.tsx:772-776). |
| L-59 | FIXED | Single GET /insights per load (InsightsScreen.tsx:667-671). |
| L-60 | FIXED | loadEpoch re-checked after every await (InsightsScreen.tsx:621-696). |
| L-61 | FIXED | Muted sensitive patterns keep the non-quoting support card (InsightsScreen.tsx:592-598,778-790). |
| L-62 | FIXED | 403 verification_failed retries with the card up (SettingsScreen.tsx:194-223,272-277). |
| L-63 | FIXED | One theme-load effect (SettingsScreen.tsx:434-453). |
| L-64 | FIXED | Localized mode names in the a11y label (SettingsScreen.tsx:558-579, es.ts:580-582). |
| L-65 | FIXED | `accountCreated` tracked; partial failure explains switch-to-sign-in (LoginScreen.tsx:119-171). |
| L-66 | FIXED | Failed consents load distinguished from empty (TherapistShareScreen.tsx:63-100,265-272). |
| L-67 | FIXED | Revision invalidated after edit/delete; loadOlder continues unpinned, filters survive (HistoryScreen.tsx:393-412,474-482,623-625). |
| L-68 | FIXED | `forgetLocalMoodDay` on both delete outcomes (HistoryScreen.tsx:484-517,532). |
| L-69 | FIXED | Dead import removed; item-9 via `phq9Item9Endorsed` (MeasuresScreen.tsx:22-44,134). |
| L-70 | FIXED | Local calendar day via UTC-of-local-Y/M/D (promptChips.ts:46-47). |
| L-71 | FIXED | iOS deliberately silent, documented (haptics.ts:12-19,53-60). |
| L-72 | FIXED | All four copy bugs fixed (en.ts:407,415,451-453; es.ts:376,409,470). |

### Low — portal (L-73…L-82)
All 10 FIXED: zeroized caseload plaintext (crypto.ts:339-348); same-origin docstring (api.ts:1-11); reviewed-anchors decision documented + sessionStorage anchors (App.tsx:64-96, platform.ts:107-121); full measure paging + instrument name + truncation count (PatientView.tsx:313-335,754-760); loader gated on !error (:783); per-entry decrypt degradation (:590-609); `conflict` retried (:222-231); local-date anchor/display (:97-103); textarea aria-labels (:880,977); honest "?" direction (:127-129). Portal suite 166/166.

### Low — deploy/docs/shared (L-83…L-97)
All 15 FIXED: verify.sh derives metrics from metrics.py render (:91-116); pre-commit scoped `^backend/`; compose cap_drop/no-new-privileges/read_only + tmpfs on all three services; hex-password constraint documented (L-86 accepted-doc route); release.yml comment corrected; .gitignore dedup; nginx exact `/api` + attribution + OCSP/ciphers; README error catalog complete (all 22 codes + status defaults); env table incl. LLM trio + fail-closed statement; deletion scope + access-log survivor; job/sentiment counts corrected (9 jobs / 48 cases); PSYBERGUIDE both stalenesses fixed; decrypt_export `user_id`; simulation60 timeline CSVs real + determinism wording; e2e oracle uses the real engine both tiers + dead branch removed.

### Info observations (I-1…I-33)
28 STILL-HOLD as documented (expected no-action trade-offs; spot-checks confirmed each). ADDRESSED: I-2 (enclave `owner` now required keyword), I-10 (= L-31 fixed), I-11 (measures id-tiebreaker + blob tests; immutability/quota remain by design), I-33 (= backend/tests/** now in mutation gate paths). CHANGED: I-28 (portal gained load-generation guards; remaining sub-notes hold).

## Verification hygiene
- No repository source files were modified during verification; artifacts were written to /tmp only. Two agents temporarily exercised file-writing tools (vector generator, redteam results) with backup/restore verified byte-identical via diff.
- Negative findings (H-7 letter-doubling, L-19, L-30, L-55, M-4 mobile surface, L-54) were re-checked against source by the lead before inclusion here.
