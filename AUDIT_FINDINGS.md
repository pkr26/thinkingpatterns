# MindPattern — Deep Audit Findings

**Date:** 2026-09-19
**Scope:** Full-repository line-by-line audit — backend (`app/**`, alembic, scripts), mobile (`src/**`), portal (`src/**`), redteam/mutation tooling, deploy/monitoring/CI, shared contract data, locales, docs.
**Method:** 35 independent auditor agents (34 delivered reports), each reading every assigned line and verifying intended behavior against docs/tests/callers, with live execution of test suites (pytest, vitest), crypto-parity probes, and purpose-built reproductions. The most severe findings were re-verified directly against source by the lead auditor.
**Severity scale:** Critical = exploitable security flaw or direct data loss · High = user-facing breakage, wrong/safety-critical results, false confidence in verification tooling · Medium = incorrect edge-case behavior, robustness, contract drift · Low = quality, minor bugs, doc rot · Info = observation / accepted trade-off.

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 20 |
| Medium | 36 |
| Low | 57 |
| Info | 42 |

"**2×**" marks issues independently found by two auditor agents.

---

## CRITICAL

### C-1. Mid-save vault lock can encrypt an entry (and mood log) under an all-zero key — silent, permanent data loss **2×**
- **Location:** `mobile/src/screens/EntryScreen.tsx:249` (save flow)
- **Confidence:** certain (code pattern, zeroize semantics, lock triggers all verified; no test covers it)
- **Issue:** `const keys = vault.get()` is taken **before** `await api.getUserId()` and used after. `vault.get()` returns buffers *shared* with the vault by design — `vault.lock()` (fires on every AppState background/inactive, the 5-minute idle timer, and any authenticated 401) zeroizes them in place. If a lock lands in the await window, `encryptEntry` runs AES-256-GCM with a still-32-byte all-zero key — a perfectly valid key — producing a blob that uploads (or queues) successfully, shows "Saved ✓", and can never be decrypted again. `recordMood(keys.dataKey, …)` and the chained `localStreak(keys.dataKey, …)` corrupt the device mood log the same way.
- **Evidence:**
  ```ts
  const keys = vault.get();               // line 249 — BEFORE the await
  const userId = await api.getUserId();   // line 250 — yield point (Keychain/AsyncStorage)
  ...
  const { blobB64 } = encryptEntry(keys, userId, clientEntryId, ...);
  void recordMood(keys.dataKey, userId, today, ...)
      .then(() => localStreak(keys.dataKey, userId))
  ```
  `vault.ts:46-47`: "The buffers are shared on purpose — zeroize-on-lock must still reach every copy." `moodLog.ts:20-24` documents and defends against exactly this hazard; every other writer snapshots after awaits.
- **Fix:** Re-acquire `vault.get()` after the await (it throws when locked → existing error path), or snapshot the key bytes (`Buffer.from(...)`) before the await and re-snapshot before the `localStreak` continuation.

---

## HIGH

### H-1. Offline queue can never flush under the shipped default server URL **2×**
- **Location:** `mobile/src/offlineQueue.ts:86-100,362` vs `mobile/src/api/client.ts:386-389` (`DEFAULT_BASE_URL = "http://localhost:8000"`)
- **Confidence:** certain (reproduced with node: `new URL("http://localhost:8000").origin` never equals the canonicalized pin `http://127.0.0.1:8000`)
- **Issue:** The queue canonicalizes loopback aliases (`localhost`, `::1` → `127.0.0.1`) before passing `expectedOrigin`, but `request()` compares against the **raw** origin of the stored base URL. With the default (or any stored `localhost`/`[::1]` spelling), every pinned upload throws `OriginPinnedError` *before the network*; `flushQueue` treats that as "origin moved" and returns. Offline saves accumulate silently, never sync, and eventually hit the 200-entry `QueueFullError`. All queue tests mock `createQueuedEntry`; the only real-`request()` pin test uses HTTPS origins.
- **Fix:** Apply the same loopback canonicalization inside `client.ts:387-388` (share one helper), or pass the raw origin as the pin and keep the canonical form only for storage keys.

### H-2. After a biometric unlock, password re-authentication can never succeed — correct password reported as "Wrong password" **2×**
- **Location:** `mobile/src/screens/UnlockScreen.tsx:104-107` + `mobile/src/reauth.ts:52-57`
- **Confidence:** certain (path fully traced; no alternate success path; untested — settings test mocks `verifyPasswordForVault` to always succeed)
- **Issue:** The biometric path stores `authKey: Buffer.alloc(32)` (zeros) in the vault. `verifyPasswordForVault` compares a freshly derived real auth key against those 32 zero bytes — false for every password. Delete-account and LLM-consent are permanently blocked for biometric-unlocked sessions, with `common.wrongPassword` copy — in an app with **no password reset**, actively harmful. Fails closed (no security bypass), hence High not Critical.
- **Fix:** Track whether the vault's authKey is known (nullable or `authKeyKnown` flag); on biometric unlock either fall back to an online `api.login` check or return an honest "re-auth unavailable — unlock with your password first" reason.

### H-3. Account export omits every `Measure` row — export-then-delete permanently loses PHQ-9 history
- **Location:** `backend/app/api/account.py:107-414` (docstring claims "Stream everything the server holds"), `backend/app/schemas.py` (`ExportBundle` has no measures field)
- **Confidence:** certain
- **Issue:** `bundle()` streams only shares/entries/insights. `Measure` rows (patient-owned ciphertext, added 2026-09-19) are deleted by cascade but never exported; `decrypt_export.mjs` also only knows entries/insights. The README's export-before-delete flow silently loses an entire data class.
- **Fix:** Add `measures` to `ExportBundle` and stream with the same byte-bounded keyset pattern; extend `decrypt_export.mjs`.

### H-4. Regenerating shared vectors silently deletes half the cross-platform crypto contract **2×**
- **Location:** `backend/scripts/generate_vectors.py:186-187`; compounding: `mobile/tools/verify_vectors.mjs:29,188`
- **Confidence:** certain (executed with redirected output: generator emits only `vectors` + `encrypt_vectors`; committed file has 4 sections)
- **Issue:** The generator overwrites `shared/vectors.json` wholesale, dropping `wrap_vectors` and `aad_edge_cases` (hand-maintained, no generator). `test_encrypt_vectors.py` instructs operators to regenerate with this script. `verify_vectors.mjs` never checks `wrap_vectors` and tolerates missing `aad_edge_cases` (`?? []` → exit 0, "+ 0 AAD edge cases verified"), so the JS-side gate stays green on a gutted file.
- **Fix:** Merge instead of overwrite (or add generators for the missing sections); make `verify_vectors.mjs` fail-closed on both keys and verify wrap vectors via the shipping `sharing.ts`.

### H-5. Monitoring stack is blind while appearing healthy: Prometheus bearer token env expansion doesn't exist
- **Location:** `deploy/monitoring/prometheus.yml:43` (`bearer_token: ${MINDPATTERN_METRICS_TOKEN}`), claims repeated at `prometheus.yml:21-25` and `deploy/monitoring/README.md:86-88`
- **Confidence:** certain (verified against pinned `prom/prometheus:v3.4.1` source: no env expansion of config file contents)
- **Issue:** The literal string is sent as the credential; `main.py` compares against the real token → 401 on every scrape → `up == 0` → `MindPatternAPIDown` pages permanently and the other four alerts can never fire. `verify.sh`/promtool only parse YAML, so they cannot catch it.
- **Fix:** `bearer_token_file:` with a 0600-mounted token file (or render the config via envsubst); correct the fail-closed claims in the three places.

### H-6. Entry EDIT path runs no crisis detection
- **Location:** `mobile/src/screens/HistoryScreen.tsx:518-582` (`saveEdit`)
- **Confidence:** certain
- **Issue:** Detection is wired only in EntryScreen (new entries) and MeasuresScreen. A user who edits yesterday's entry to crisis language and saves gets no support dialog; the same text as a new entry does. The on-device detector is the only net (server sees ciphertext).
- **Fix:** Run `detectCrisisLanguage(trimmed)` after a successful `api.updateEntry`, reusing the shared throttle helper.

### H-7. Crisis corpus coverage gaps on both engines (dialog tier misses)
- **Location:** `backend/app/services/crisis.py:65-124`, `:67,74`, `:269-286` + `shared/crisis_phrases.json`
- **Confidence:** certain (misses reproduced live against both engines)
- **Issue:**
  - Spanish/Italian/Portuguese: no `suicidio/suicidarme` pattern — "estoy pensando en el suicidio", "quiero suicidarme", "no quiero vivir", "estoy cansado de vivir" → `dialog=False` (German `suizid` fires; the Romance cognate doesn't — asymmetry, not choice).
  - Past tense: `kill(?:ing)? myself` and `(end|take)...my life` lack `killed`/`took`/`ended` — "i almost killed myself last year", "i nearly took my own life" miss both tiers.
  - SMS shorthand: standalone `2` never folds to "to" — "i want 2 die", "no reason 2 live" miss; letter-doubling ("kiill myself", "suiccide") bypasses everything.
  - Trailing leet digit: "suicid3" escapes the dialog tier (suppress catches it); "d13" escapes both (leading/interior digits fold, trailing doesn't).
- **Fix:** Add the missing pattern families to `shared/crisis_phrases.json` + both embeds; fold a standalone `2` token and trailing mapped digits.

### H-8. Spanish sentiment is semantically broken (three independent defects)
- **Location:** `backend/app/services/sentiment_lexicon_es.py:117` ("quiero": 2.2), whole ES lexicon (death-word class absent), `backend/app/services/patterns.py:19` (`WORD_RE = [a-z']+`) + `brain.py:762-791` (curly apostrophe)
- **Confidence:** certain (all reproduced against the live engine)
- **Issue:**
  1. `"quiero" = +2.2` (EN `want` = 0.3): "quiero morir" / "me quiero morir" score **+0.55** — the highest-frequency Spanish verb boosts ideation text positive; mood trends, PA/NA, rumination all read the wrong sign.
  2. No `suicidio, suicida, muerte, morir, matar, cortar, desaparecer, vivir, muerto` anywhere in the ES lexicon — "pienso en el suicidio" scores 0.0.
  3. `[a-z']+` tokenization mangles accented words: "tengo depresión" → `['tengo','depresi','n']` → **0.0** (unaccented typo scores −0.75). 70/476 ES keys are structurally unreachable; 5 have no unaccented twin and are dead for all inputs. `crisis.py` already folds diacritics; the sentiment pipeline doesn't.
  4. (cross-ES/EN) Curly apostrophe U+2019 (iOS smart punctuation, on by default) defeats all contraction negators: "don't feel good" → −0.35 but "don't feel good" (U+2019) → **+0.475**.
- **Fix:** Set "quiero" ≈ 0; add the ES death-word class; fold diacritics + U+2019 before tokenization on **both platforms** (backend and mobile `sentiment.ts` are pinned byte-equal, so both must change together).

### H-9. Newer statistical pattern kinds bypass the replication gate **2×**
- **Location:** `backend/app/services/brain.py:115-124` (`STATISTICAL_KINDS`), `:138-139` (dead `EVIDENCE_DATE_KINDS`/`WINDOW_STAT_KINDS` wiring), `:3214-3223`
- **Confidence:** certain (A/B-proven with live probes; the module's own noise measurements motivated the gate)
- **Issue:** `energy_inertia, pa_inertia, na_inertia, energy_mood_coupling, sense_making, activity_diversity, cadence, avoidance`, rising `topic` are p-value-tested inferences not in `STATISTICAL_KINDS`, so they take the direct-measurement promotion path and surface on their **first** qualification (their sample floors are ≥ `STRONG_EVIDENCE` by construction). Probe: gated mood `inertia` stayed candidate while ungated `energy_inertia` surfaced `emerging` on identical machinery; `cadence` surfaced first-run. This is exactly the single-run-fluke surfacing the gate was built to stop. The `avoidance`/`cadence` entries in the replication-kind sets are dead constants.
- **Fix:** Add the missing kinds to `STATISTICAL_KINDS` (assigning replication flavor); add a regression counting them in the noise bounds.

### H-10. "Other"-language journals get fabricated avoidance/cadence claims from a censored calendar
- **Location:** `backend/app/services/brain.py:3425-3434, 3527-3528, 3790`
- **Confidence:** certain (probe: German journal written every day, mood tags omitted on post-conflict days → surfaced card `avoidance | konflikt | silences: 30/30 / observed: 30 / expected: 10.07` — a user with zero silent days)
- **Issue:** When language detection returns "other", the writing calendar fed to `_detect_avoidance`/`_detect_cadence`/`active_days` is built from *mood-tagged* days only, manufacturing silence that never happened; `questions.py` then renders the false claim as a daily reflective question.
- **Fix:** Build the writing calendar from all window entry dates; keep mood-day censoring only for the weekday mood base rate.

### H-11. Semantic-flip forking mints a new pid on every subsequent run; the flipped claim can never re-establish itself
- **Location:** `backend/app/services/brain.py:3143-3163`
- **Confidence:** certain (probe: weekday switch → store holds `temporal:work` (archived) plus `work~2 … work~11`, each with one qualification day, nothing ever surfaces)
- **Issue:** The flip check compares the incoming signal against the base record whose detail froze at the flip, so every later run flips again and forks `~N`. README promises "retires the old pattern-id … and forks a fresh `~2` id" with a new candidate clock and re-applied replication gate — unreachable, because detectors always emit the base pid. The genuinely-supported new claim is silenced until the base record drops at 90 days, plus one store-churn record per recompute.
- **Fix:** On flip, search for an existing fork whose stored semantic detail matches and reuse that pid; only fork when no fork matches.

### H-12. "One question per day, stable within the day" breaks on same-day recompute
- **Location:** `backend/app/services/questions.py:294-297` + `backend/app/api/insights.py:716,874,147-152`
- **Confidence:** certain (reproduced: same user, same date, one extra pattern → different question)
- **Issue:** The rotation index is `modulo len(pool)` where the pool is the *current* recompute's surfaced patterns, and the question row is upserted in place. A user who recomputes after an evening entry (new pattern qualifying, a fade, a mute, feedback taps) gets a different question for the same day than one they may have already answered.
- **Fix:** Pin the day's question on first write (skip the upsert when a same-day row exists), or make the index depend only on stable inputs.

### H-13. Portal renders fabricated clinical data: mood sparkline invents 0 for null sentiment; "Copy forward last note" copies the oldest note
- **Location:** `portal/src/views/PatientView.tsx:650` (and dead guard at `:137`), `:751`/`762`
- **Confidence:** certain
- **Issue:** `sentiment: e.sentiment ?? 0` makes every point numeric so the sparkline's own non-numeric filter is dead code — patients who never make explicit mood picks (the normal case; mobile keeps payload sentiment null without a pick) get a fabricated mid-scale trend and average. Notes arrive `created_at.asc()`, so `[0]` in "Copy forward last note" seeds a new note with the *oldest* session's text.
- **Fix:** Pass `e.sentiment` through and let the filter drop nulls; use `.at(-1)` for copy-forward.

### H-14. Sharing-disclosure and audit-contract gaps (therapist compliance) **4×**
- **Location:** `backend/app/api/consents.py:67` + `mobile/src/locales/en.ts:651`/`es.ts:650` + `client.ts:62` (disclosure "v1"); `backend/app/api/therapist.py:15-18,455-531` (un-audited list)
- **Confidence:** certain (drift verified in code, copy, and CHANGELOG concession)
- **Issue:** PHQ-9 measures are readable under the same active consent whose disclosure copy says only "every entry and pattern" — `measures.py:13-14` states "The sharing disclosure copy (v2) names measures explicitly", but no v2 exists and the server hard-pins v1, so even an updated client cannot record an accurate consent (Art. 7 record understates the data scope). Separately, `GET /therapist/patients` — which since 2026-09-19 moves patient-derived caseload-summary content — writes no `AccessLog` row, against README's "every patient-data read/write is audit-logged". Also `disclosure_outdated` (409) is not in the mobile `API_ERROR_CODES` allowlist and `meta.sharing_disclosure_version` is ignored → an opaque dead-end after spending a password proof and a key wrap.
- **Fix:** Ship v2 copy naming measures (+ summaries), bump the version on both sides, decide the legacy-consent path; log a `list_patients` action; compare the meta version before showing the grant card.

### H-15. PR mutation gate can be defeated by oracle rot; several redteam probes cannot fire
- **Location:** `redteam/mutation_campaign_*/harness.py:615`; `redteam/b_auth.py:51-58`; `redteam/c_api.py:59-62`; `redteam/results/*.json`
- **Confidence:** certain (exit-code behavior verified live; probes re-run)
- **Issue:**
  - Any nonzero oracle exit counts as KILLED — a renamed/deleted pin test file (pytest exit 4) "kills" every mutant and the gate prints PASSED while verifying nothing; `mutation-pr.yml` paths don't include `backend/tests/**`.
  - B1 "verifier-enables-llm-egress" is structurally dead: settings never set `llm_url`, so the probe always sees 409 and prints BLOCKED even though the stolen verifier *passed* re-auth (reproduced: 200 with `llm_url` set).
  - C2 "scrypt-amplification" verdict is hardcoded BLOCKED — it can never report a finding.
  - Committed `results/*.json` contain stale **mutant-conditioned false FINDINGs** (A4, B1.wrong-verifier, C3.date-backdating, E1 drift — all re-run clean on the current tree); readers learn to ignore FINDINGs.
- **Fix:** Treat pytest exit 3/4 and empty test counts as SETUP-ERROR; add tests/** to workflow paths; set `llm_url` in the B1 probe; gate C2 on observed 503 counts; re-run and recommit results from a clean tree.

### H-16. Therapist insights read: stale caseload summary without phase gate; `state_seq` hardcoded 0 **2×**
- **Location:** `backend/app/api/therapist.py:504,521-527` (summary gated on consent status only); `:573-579` (`InsightsResponse` omits `state_seq`, always 0)
- **Confidence:** certain
- **Issue:** Every sibling patterns read is phase-gated ("nothing is revealed before the threshold, including stored leftovers"), but `list_patients` keeps serving the last insight-phase summary (pattern count, sensitive-card presence) after entry deletion drops the account below threshold — until revoke or a future insight-phase recompute. The therapist insights response always reports `state_seq=0` while the decrypted payload embeds N ≥ 1 — the documented rollback-replay detection (mobile implements it via `stateSeqGuard.ts`) does not exist on the therapist path, contradicting the endpoint's "byte-identical shape" docstring.
- **Fix:** Suppress `summary_*` unless the patient is currently INSIGHT phase (reuse `_entry_dates` + `threshold.evaluate`); populate `state_seq=latest.state_seq`.

### H-17. `tokens.py` huge-integer `exp` → uncaught `OverflowError` → 500 (violates the module's never-500 contract)
- **Location:** `backend/app/security/tokens.py:74` (`math.isfinite(exp)`)
- **Confidence:** certain (reproduced against shipping code: well-signed token with `exp = 10**400` raises OverflowError, not TokenError; `deps.require_user` catches only `TokenError`)
- **Issue:** `json.loads` accepts arbitrary-precision integers; `math.isfinite(<big int>)` converts to float and raises. The 2026-09 NaN/Infinity hardening closed the float-shaped holes but left the big-int one. Not externally exploitable (forging needs the HMAC secret), hence High per contract-breakage, not Critical.
- **Fix:** `try: finite = math.isfinite(exp) except OverflowError: finite = False`, or bound `exp` (reject > year-3000).

### H-18. Mobile on-device sentiment: prototype-chain lexicon lookup — token "constructor" scores NaN and silently deletes the day's mood-log entry
- **Location:** `mobile/src/brain/sentiment.ts:108-112,141-144` (plain-object lookups in generated `lexicon.ts`)
- **Confidence:** certain (JS semantics proven; server scores 0.0 — parity break; no vector contains the token)
- **Issue:** `emojiValences["constructor"]` resolves through `Object.prototype` and returns the inherited function → arithmetic yields NaN → `localSentiment` → `recordMood` stores NaN → `sanitize` drops the whole day on next read (day vanishes from local trend/streak). `"constructor"` is the only all-lowercase inherited name matching `WORD_RE`.
- **Fix:** Null-prototype tables (`Object.create(null)` + assign) or `Map`s for `emojiValences`, `sentimentLexicon`, `intensifiers`, `irregularForms`; add a vector for the token.

### H-19. DPIA claims an in-app export that the product deliberately disables
- **Location:** `docs/DPIA_SKELETON.md:48-50` vs `mobile/src/screens/SettingsScreen.tsx:283-289`
- **Confidence:** certain
- **Issue:** The DPIA's access/portability section asserts "in-app encrypted export + readable Markdown export (both decrypt on-device)". The in-app path fails closed in this build ("Re-enable only with a reviewed native streaming-to-file implementation"); Markdown exists only as a dev CLI tool (`mobile/tools/decrypt_export.mjs`). A regulator-completed DPIA would misstate the data-subject-right posture.
- **Fix:** Reword to the real state: server-side streamed ciphertext export API + offline decrypt tool; in-app export pending.

### H-20. Verification scripts produce wrong ground truth / measure nothing
- **Location:** `backend/scripts/loadtest.py:138-151,207-209` (recompute phase never crosses the 30-day threshold → measures a baseline no-op and counts it success); `backend/probe_brain.py:228` (check B passes via the *work* rumination, not the sleep cluster — "can't sleep, my mind won't stop" scores +0.222 and never classifies as rumination)
- **Confidence:** certain (both executed)
- **Issue:** CI gates on "9/9 ground truth" but the sleep-worry→rumination claim is unverified (any repetitive negative sentence keeps B green); the loadtest's capacity numbers for the "full recompute pipeline" describe a no-op.
- **Fix:** Pin check B to the sleep cluster's label (and fix the lexicon/corpus so it classifies); backdate loadtest handles or add distinct entry days; assert on `phase`/`analyzer` not just status 200.

---

## MEDIUM

### M-1. Malformed-JSON bodies bypass every rate limiter
- **Location:** `backend/app/middleware.py` (wiring) — FastAPI parses the body and raises `RequestValidationError` before route dependencies (limiters) run
- **Confidence:** certain (empirically: 8 × `POST /api/auth/salt` with `b"{not-json"` → 422×8, never 429; valid-JSON/schema-invalid → 422,422,429,429…)
- **Impact:** Unauthenticated flood gets unlimited 422s, each costing a ≤2 MiB buffer + parse. Bounded (no scrypt/DB reached), hence Medium.
- **Fix:** Count requests pre-parse in `HardeningMiddleware` (shared counter), or count body-parse 422s into the same buckets.

### M-2. Recompute's lifecycle-fence re-check omits `token_epoch`
- **Location:** `backend/app/api/insights.py:656-662`
- **Confidence:** certain (asymmetry vs `_fresh_processing_session_user` at `:177-180` and entries' equivalent)
- **Issue:** A recompute whose bearer authenticated pre-logout but acquires the fence post-logout passes the `is_active` check and proceeds to decrypt the corpus and — with consent — dispatch plaintext to the LLM, contradicting logout's "nothing may still hold the data key" contract. (The key is popped before the fence, so `destroy_all_for_owner` can't reach it.)
- **Fix:** Capture `expected_epoch` at handler start; add the epoch equality check inside the fence.

### M-3. `create_measure` skips the token-epoch re-check
- **Location:** `backend/app/api/measures.py:89-93,114-181`
- **Confidence:** certain (mirrors the entries invariant it documents)
- **Issue:** A retired (logged-out) bearer queued on the lifecycle lock can complete a measure insert after logout commits. Data written is the user's own → Medium.
- **Fix:** Mirror entries: capture and compare `expected_epoch`.

### M-4. Measures beyond the newest 100–200 are unreachable on every read path while the write quota is 2000
- **Location:** `backend/app/api/measures.py:52,198` (page limit 200, no offset param; client sends no limit → default 100), `backend/app/api/therapist.py:613-614` (hardcoded limit 200, no continuation), export omits measures entirely (H-3)
- **Confidence:** certain
- **Issue:** Measure #201+ is stored and quota-charged but invisible to patient, therapist (truncated MBC trend), and export. At the weekly cadence the module itself cites, the cliff arrives in <4 years; PHQ-9 cadences are often 2×/week. No truncation signal anywhere.
- **Fix:** Add keyset/offset paging to both read paths; include in export (H-3).

### M-5. LLM-path recompute truncates muted cards and desyncs counters
- **Location:** `backend/app/api/insights.py:729` (`merged = merged[:brain.MAX_SURFACED]` in the enricher branch only) **2×**
- **Confidence:** likely
- **Issue:** Brain surfaces up to 20 live + 10 muted cards; the extra slice in the LLM path cuts exactly the muted cards (appended last), so the unmute affordance disappears only when enrichment runs, and `patterns_new`/`patterns_fading` can count patterns not present in the stored payload.
- **Fix:** Cap the unmuted portion only; count over the final stored list.

### M-6. LLM narrative filter has no advice/derogation guard
- **Location:** `backend/app/services/llm.py:354-386` (`_clean_narrative`)
- **Confidence:** certain the strings pass (executed): "You should stop reaching out to your friends; they are tired of you." etc. pass verbatim
- **Issue:** The module's own threat model declares model output hostile; a prompt-injected journal steering the model can land manipulative isolation/self-blame content through the only free-text channel, rendered under pattern cards for vulnerable users. Spelled-contact TLD list is also finite ("quietplace dot online" passes).
- **Fix:** Reject imperatives/second-person advice constructions or require narrative tokens to be corpus-grounded like labels; widen the TLD handling (reject "dot" between alphabetic runs).

### M-7. Brown-Forsythe "two-sided" doubling manufactures significance on identical spreads
- **Location:** `backend/app/services/statsig.py:278`
- **Confidence:** certain (recomputed: near-equal spread groups → p = 2.36e-06; epsilon-different → 0.0; genuine 3× spread difference → 7.6e-12 via the upper tail)
- **Issue:** Standard BF is upper-tailed only; the lower tail fires precisely when the point estimate says "no difference". Contained today (both callers gate on spread ratios ≥1.5–1.6), but it's a public API one ungated caller away from a false "instability" claim, and `detail.p_value` records the wrong tail even when gates pass.
- **Fix:** `return min(1.0, upper)`.

### M-8. `mood_correlation` counts clustered same-day entries as independent observations
- **Location:** `backend/app/services/brain.py:2034-2038`
- **Confidence:** certain (10 theme-days × 5 entries → Welch n=50 vs 60, p=2.4e-46, d=4.8, on 10 independent days)
- **Issue:** The weekday test in the same function was converted to day-level for exactly this inflation ("entry-level over-counted clustered journals"); the mood branch wasn't. p-values and Cohen's d on cards are overstated for multi-entry days.
- **Fix:** Collapse to day means (as `day_buckets` already does) before `welch_test`/`cohens_d`.

### M-9. Never-surfaced direct-kind candidates later surface as "fading" cards
- **Location:** `backend/app/services/brain.py:3252-3259`
- **Confidence:** certain (4-occurrence phrase, one qualification day, hidden candidate → surfaced `fading` card at +9 days after the phrase left the corpus)
- **Issue:** Violates "weak signals stay hidden candidates until re-qualifying another day". The code's own comment refuses exactly this for statistical candidates; the direct path was left open.
- **Fix:** Route never-surfaced candidates of all kinds to `archived`, skipping user-visible fading.

### M-10. Phrase repetition does not surface for non-Latin scripts despite the documented promise
- **Location:** `backend/app/services/brain.py:210-213` (comment) + `patterns.py:19` (`WORD_RE`) vs README ("client mood tags and phrase repetition still count" under "other")
- **Confidence:** certain (identical Cyrillic sentence on 12 distinct days surfaces nothing; English control surfaces immediately)
- **Fix:** Script-agnostic tokenization for the phrase channel, or correct the comment/README.

### M-11. Recompute threshold phase TOCTOU (write-side)
- **Location:** `backend/app/api/insights.py:577-585` (phase fixed outside the lock) vs `:643-668`
- **Confidence:** certain mechanics; impact contained — read-side gates (`GET /insights`, `GET /questions/today`) re-evaluate phase live and never serve leftovers below threshold
- **Issue:** Entries deleted between the date read and the fence leave a stale INSIGHT phase; a row gets decrypted/stored while live distinct days are below 30. Self-inflicted (owner-only deletion race).
- **Fix:** Re-read dates and re-evaluate phase inside the fence.

### M-12. `feedback_blob_invalid` recovery reuses an already-consumed single-use session token **2×**
- **Location:** `mobile/src/screens/QuestionScreen.tsx:135-137`
- **Confidence:** certain (backend pops the key at `insights.py:615` before the feedback pre-flight raises)
- **Issue:** The retry always hits 403 `processing_session_invalid` → error card; the transparent recovery path is dead code (recovery happens on the *next* load with a fresh session).
- **Fix:** Open a new processing session before the fallback recompute (or surface a calm retry state).

### M-13. Offline queue is one AsyncStorage value with a *count* cap — byte oversize wedges the whole scope (Android)
- **Location:** `mobile/src/offlineQueue.ts:21,227,249-255`
- **Confidence:** likely (platform cursor-window limit; count-vs-bytes mismatch certain from code)
- **Issue:** ~15 max-size entries (100k chars each) exceed Android's ~2 MB per-row limit; `getItem` throws outside its try/catch, so `enqueue`/`flushQueue`/`queueLength` all reject and the scope stays wedged. History listing was byte-paginated for exactly this class; the queue wasn't.
- **Fix:** Bound by serialized bytes (~1 MB) or per-entry keys; move `getItem` inside the try.

### M-14. A single 401 mid-flush parks the entire queue in the rejected store; no auto-recovery
- **Location:** `mobile/src/offlineQueue.ts:371-382`
- **Confidence:** likely
- **Issue:** Natural token expiry mid-flush moves *all* queued entries (including unattempted ones) to the rejected store; after re-login, `flushQueueOnReconnect` sees an empty queue. Recovery is only the manual Settings "Recover" button; flush callers swallow `SessionExpiredError` silently.
- **Fix:** Auto-attempt `requeueRejected` once after successful re-auth, or keep items queued with a long `notBefore`.

### M-15. Crisis dialog skipped on the 401 and 422 save-failure paths **2×**
- **Location:** `mobile/src/screens/EntryScreen.tsx:309-326` (vs the deliberate wiring on the queueFull/queueAbandoned paths at `:336-354`)
- **Confidence:** certain
- **Issue:** A crisis-flagged entry that went nowhere (rejected/unsaved) — the case the queue-path comments call the most important — doesn't point at support on these paths, though `crisisLanguage` is already computed.
- **Fix:** Attach the same `onPress → maybeShowCrisisAlert` wiring to the 422/401/outer-catch alerts.

### M-16. PHQ-9 crisis-dialog copy (and the whole MeasuresScreen) is hardcoded English
- **Location:** `mobile/src/screens/MeasuresScreen.tsx:157-164` (and file-wide) **2×**
- **Confidence:** certain
- **Issue:** Spanish-locale users get English crisis copy on the questionnaire path — the most safety-adjacent string class. `strings.ts` claims "every screen resolves its copy through t()".
- **Fix:** Move the screen strings (and PHQ-9 item/option labels) into locales.

### M-17. Mobile redteam corpus verdicts stale → standing false E1 parity FINDING
- **Location:** `redteam/crisis_corpus.json` + `redteam/f_mobile.test.ts:69-78` + `redteam/results/f_mobile.json`
- **Confidence:** certain (stored booleans contradict both live engines; TS and Python now agree on all 38 rows)
- **Issue:** The parity check replays frozen verdicts instead of running the Python engine, so it reports 2 phantom divergences while being blind to the real U+2065 divergence (see I-set). Noise teaches readers to ignore FINDINGs.
- **Fix:** Regenerate the corpus booleans with the current engine (or shell out live); refresh results.

### M-18. Backgrounding mid-onboarding silently cancels the remaining panels
- **Location:** `mobile/src/navigation.tsx:100-104` + `mobile/src/onboarding.ts:25-39`
- **Confidence:** certain behavior
- **Issue:** Locking the vault flips `inMain` and consumes the one-shot pending flag; re-unlock lands on Entry with the privacy/13+ panels never shown or completed. iOS app-switcher swipes make this common, not the documented "restart before onboarding" edge.
- **Fix:** Re-derive the gate from the persisted `hasSeenOnboarding(userId)` on re-entry.

### M-19. Sign-out does not remove the biometric data-key wrap (and does not cancel the daily reminder)
- **Location:** `mobile/src/store.tsx:224-262` vs `biometricUnlock.ts:51-53` ("Sign-out hygiene … lands here") **2×**; reminders: same `signOut`
- **Confidence:** certain behavior; currently inert (unwrap requires a live session + matching userId)
- **Issue:** The data key remains sealed under device biometrics indefinitely after sign-out, contradicting the module's documented hygiene (the offline-unlock proof and cached salt *are* wiped). The device-global reminder keeps firing on a shared device after sign-out (deletion does cancel it).
- **Fix:** `disableBiometricUnlock(userId)` + `cancelDailyReminder()` in `signOut` (or correct the comments if retention is intentional).

### M-20. U+2065 asymmetry between mobile and backend invisible sets → cross-engine verdict divergence
- **Location:** `mobile/src/crisisDetect.ts:76` (range `\u2060-\u2069` includes U+2065) vs `backend/app/services/crisis.py:202-212` (enumerates, skips U+2065)
- **Confidence:** certain (58/7542 fuzz divergences, all U+2065; e.g. Arabic ideation detected mobile-only, benign compound masked mobile-only)
- **Fix:** Add `"\u2065"` to the backend list (stripping is the safer direction).

### M-21. Stale caseload summary shadows the fresher scan; decrypted `forDate`/`newest` never rendered
- **Location:** `portal/src/views/PatientsView.tsx:227-231` (also backend H-16 for the phase-gate side)
- **Confidence:** certain
- **Issue:** Mixed stale/fresh sources in one row; the as-of date needed to interpret the summary is parsed but dropped.
- **Fix:** Render `forDate` beside the count, or prefer the scan row when both exist.

### M-22. Revoked patients' notes are unreachable although the UI promises they stay
- **Location:** `portal/src/views/PatientsView.tsx:245-253` (no open action for stopped patients) vs copy "Your notes about this patient stay" and backend permitting note access at any consent status
- **Confidence:** certain
- **Fix:** Notes-only chart mode for stopped patients.

### M-23. One stray click permanently deletes a clinical note — no confirmation
- **Location:** `portal/src/views/PatientView.tsx:516-527,723`
- **Confidence:** certain
- **Fix:** Confirm step or undo window before DELETE.

### M-24. Question rotation renders rising-trend claims for steady-presence topics
- **Location:** `backend/app/services/questions.py:176-180` (template never reads `detail.trend`)
- **Confidence:** certain (steady-presence topic rendered "…taking up more space in your writing lately")
- **Fix:** Select topic templates by trend, mirroring `Pattern.describe()`.

### M-25. `TherapistShareScreen` ignores `meta.sharing_disclosure_version`; `disclosure_outdated` unreachable in code branching **2×**
- **Location:** `mobile/src/screens/TherapistShareScreen.tsx:47-61`, `mobile/src/api/client.ts:294-308`
- **Confidence:** certain
- **Fix:** Compare the meta version before showing the grant card; add the code to `API_ERROR_CODES` with dedicated copy.

### M-26. Crash-class 500s are invisible to `mindpattern_requests_total`
- **Location:** `backend/app/metrics.py:89-96` + `backend/app/main.py:286-295` (Metrics inside Hardening)
- **Confidence:** certain
- **Issue:** Unhandled exceptions propagate past the metrics layer; the last-ditch 500 goes to the raw send. An operator watching `status="5xx"` sees zero during a crash loop (only the 413 exclusion is documented).
- **Fix:** Have the last-ditch path call `registry.observe_request(500)`, or move Metrics outermost and document exclusions.

### M-27. Single-process guard: re-entrancy is not refcounted; first release drops the flock **2×**
- **Location:** `backend/app/singleprocess.py:100-103,148-156`
- **Confidence:** certain semantics; production topology (one lifespan per process) can't reach it
- **Issue:** Overlapping same-identity lifespans in one process (test topology) leave the outer scope serving with no flock — a second process could boot and fragment in-process state.
- **Fix:** Store `(fd, refs)`; close/unlock only at depth 0.

### M-28. Deployment identity is the literal (secret, URL) string pair
- **Location:** `backend/app/singleprocess.py:91-95`
- **Confidence:** likely
- **Issue:** Same DB spelled differently (`localhost` vs `127.0.0.1`, query-param variants) or different `MINDPATTERN_LOCK_DIR` derives different lock paths → two processes serve one DB silently.
- **Fix:** Normalize via `sqlalchemy.make_url()` before hashing; document.

### M-29. `access_log_retention_days` has no lower bound — 0/negative wipes the audit table
- **Location:** `backend/app/config.py:388-389` + shared prune statement `therapist.py:164-170`
- **Confidence:** certain
- **Fix:** Validate `1 <= value <= 3650`.

### M-30. Audit rows rolled back on error paths after ciphertext was fetched
- **Location:** `backend/app/api/therapist.py:689` vs `714-722,760-782,795-797` (same pattern in `list_notes` `935` vs `972-984,1009-1016`)
- **Confidence:** likely
- **Issue:** The `_audit` INSERT is only committed by the final commit; the 413/409 paths raise after the full-blob SELECT, rolling the audit row back — the server fetched journal ciphertext with no surviving access record.
- **Fix:** Commit the audit row in a short separate transaction before raising, or move `_audit` after all consistency checks and document that only delivered pages are audited.

### M-31. `decrypt_export.mjs` uses the wrong AAD context for `brain`-kind insight rows — they can never decrypt
- **Location:** `mobile/tools/decrypt_export.mjs:113-117` (everything non-"question" uses the "patterns" context; brain rows are AAD-bound to `"brain"` at `insights.py:870`)
- **Confidence:** certain
- **Impact:** Users decrypting a healthy export see brain-state rows reported as `"error": "authentication failed"`, indistinguishable from corruption.
- **Fix:** Branch the AAD context on kind.

### M-32. Mutation PR gate cannot run round-2/3 mutants in CI
- **Location:** `.github/workflows/mutation-pr.yml:59-65` (creates `backend/.venv`) vs harness `ROOT_PY = ROOT/.venv/bin/python` (repo root), `MUTATION_PY` never set
- **Confidence:** likely (static path analysis; local tree has a root `.venv`, CI runners don't)
- **Impact:** The gate either passes trivially or crashes on CI — the documented "round-2 standards cannot silently regress" guarantee is not enforced.
- **Fix:** Export `MUTATION_PY: $(command -v python)` in the workflow.

### M-33. N4 residual missing from `DOCUMENTED_RESIDUALS` → gate false-FAILs every brain.py PR
- **Location:** `redteam/run_pr_mutation_gate.py:44` vs `reports/mutation_campaign_2026-09-18_round2.md:124`
- **Confidence:** certain (replayed the mutant in-memory against e2's corpora → MISSED → failure)
- **Fix:** Add N4 to the set or land the promised e2 corpus.

### M-34. Redteam probes: boot-failure attribution and verdict wiring
- **Location:** `redteam/c1_multiworker.py:139-146` (any unhealthy boot reported as "deployment lock refused"); `redteam/h_privacy.py:88-94,125-131` (computed `has_cleartext`/`keys_held` checks never affect the verdict — export-with-plaintext or retained keys would still print BLOCKED)
- **Confidence:** certain (code paths; current recorded verdicts happen to be genuine)
- **Fix:** Require the expected log signature before claiming BLOCKED; include the computed conditions in the verdict gates.

### M-35. Mobile mood-log and question-feedback read-modify-write races
- **Location:** `mobile/src/moodLog.ts:184-218` (`recentMoods`/`localStreak` bypass the mutex whose comment exists for exactly this; legacy-migration write inside `read()` races `recordMood`); `mobile/src/questionFeedback.ts:74-88` (no serialization at all — same-frame taps lose events)
- **Confidence:** certain the paths are unprotected; windows are narrow
- **Fix:** Route readers through `serialized()`; add a mutex to `appendEvent`.

### M-36. Locale/i18n quality (Spanish)
- **Location:** `mobile/src/locales/es.ts:445,467,473,401` (raw English weekday names interpolated into Spanish sentences — "la mayoría de las veces en Monday"); `es.ts:355-356` (tu/usted register break in an otherwise 100%-usted catalog); backend `patterns.py:22` emits English `DAY_NAMES` always
- **Confidence:** certain
- **Fix:** Send a weekday index (or localize via `Intl`) before interpolation; fix the register.

---

## LOW

### Backend

1. **`backend/app/security/crypto.py:42-51`** — docstring claims `encrypt_with_nonce` is "asserted absent from production paths by tests"; no such test exists (the pins only assert the `encrypt()` signature seam). Add an rglob source-scan or soften the docstring.
2. **`backend/app/security/tokens.py:66-78`** *(Info-adjacent)* — payload field types other than `exp` unvalidated (`uid` may be any JSON value; signed `ep: true` compares equal to epoch 1 in `deps.py:78`). Reachable only with the signing secret.
3. **`backend/app/security/sharing.py:71-73,267-269`** — pairing alphabet is 30 symbols, not the documented 31 ("U" absent); entropy ≈39.2 not 39.6 bits; unbiased (limit derives from actual length), comment arithmetic mismatched.
4. **`backend/app/middleware.py:328-337`** — middleware-generated 400/408/413/500 responses carry no CORS headers (CORS sits inside Hardening) — browser clients see opaque failures for oversized bodies.
5. **`backend/app/api/entries.py:240`, `measures.py:73`** — date bounds use server-local `date.today()` while the contract (and grace-day math) assumes server-UTC. Correct only on UTC hosts, which nothing enforces.
6. **`backend/app/api/entries.py:302-310`** (same shape `measures.py:127-148`) — quota check precedes the duplicate check: an idempotent retry at the quota boundary returns 413 instead of 409, so the offline queue can't distinguish "already applied" from "genuinely full".
7. **`backend/app/api/measures.py:63-68` vs `entries.py:222-235`** — error-envelope drift for identical client-error classes (400/`bad_request` vs 422/`validation_error`; 410/`account_deleted` vs 401/`unauthorized`); clients branch on `code`.
8. **`backend/app/api/account.py:341-357`** — insights export keysets on `Insight.created_at`, which recompute mutates; a recompute between pages can drop a row from the bundle (self-race; the file's own comment states the rule for entries).
9. **`backend/app/api/account.py:210-239`** — share pages load full `Consent` entities incl. `wrapped_key`/`summary_blob` columns, defeating the metadata-first page design (bounded: ≤100 rows).
10. **`backend/app/api/insights.py:779-784`** — cancellation while queued on the analyze limiter strands the `SecureProcessingContext`'s key copy unzeroized (construct inside the worker callable).
11. **`backend/app/api/insights.py:443-448`** — `_parse_feedback` silently skips malformed items, drifting from its "never a silent skip" docstring.
12. **`backend/app/api/therapist.py:1114-1116`** — `create_note` maps every `IntegrityError` to 409 "already exists" (FK violation from concurrent deletion masquerades as conflict).
13. **`backend/app/config.py:156`** — generated `repr(Settings)` embeds every secret (latent; no current call site logs it). Use `field(repr=False)`.
14. **`backend/app/services/brain.py:1732-1733,3249-3250`** — corrupt record with empty `last_qualified` bypasses aging: surfaces forever, never drops (reachable only via genuine store corruption).
15. **`backend/app/services/brain.py:3425-3429`** — NaN mood tags enter the mood series when language == "other" (`is not None` instead of `isfinite`); production unreachable (API rejects non-finite).
16. **`backend/app/services/brain.py:3322-3325`** — `update()` crashes (`AttributeError`) on dict-shaped pattern records despite the docstring promising re-validation; direct callers (scripts/tests) only.
17. **`backend/app/services/brain.py:2499-2509,2596`** **2×** — phrase pid embeds the classification kind, so a cluster whose mean negativity oscillates across −0.30 flips between `rumination:`/`recurring_phrase:` pids: lifecycle churn + transient duplicate cards, outside the semantic-flip machinery.
18. **`backend/app/services/brain.py:2588,3282-3293`** — sensitive-word tripwire checks only the 3 lexicographically-first stored variants; a suppress-tier variant sorted 4th+ escapes the flag (mitigated: renderers only show `label`, which is checked, and `questions.py` re-filters).
19. **`backend/app/services/statsig.py:232`** — `effective_sample_size` floor can exceed actual n for n<3 with strong lag-1 (returns 3.0 > n); unreachable from current callers.
20. **`backend/app/services/llm.py:193`** — policy fingerprint uses the un-stripped URL (trailing space → different fingerprint, conservative direction).
21. **`backend/app/services/phrases.py:27-28`** — S-curve comment understates recall at s=0.8 (0.9998 vs "≈0.995"); conservative direction.
22. **`backend/app/services/crisis.py:446-465`** — fully-concatenated crisis phrase with a trailing word ("iwannadienow") matches no variant (documented accepted miss).
23. **`backend/app/services/crisis.py:165-171`** — benign-compound masking is English-only; CJK prevention-contexts false-positive ("我们讨论了自杀预防" fires) — accepted-FP posture, but unbounded in Spanish etc.
24. **`backend/app/services/questions.py:28-89`** — backend's embedded `GENERIC_QUESTIONS` is not pinned to `shared/generic_questions.json` by any backend test, despite `test_contract_pins.py:280-282` claiming it is (all three copies currently agree exactly).
25. **`backend/app/services/patterns.py:188`** — stale kind-taxonomy comment (lists 3 kinds; module handles 17).
26. **`backend/app/services/threshold.py:26-28,37-39`** *(Info-adjacent)* — future-dated entries count toward unlock and a grace-dated future entry zeroes the streak (documented trade-off, noted).
27. **`backend/app/schemas.py`** — no `extra="forbid"` on request models (typos in optional fields silently drop data, e.g. a mistyped `pattern_pid` saves a general note).
28. **`backend/app/schemas.py:230`** — display-name pattern admits control/bidi characters other than `\n\t` (spoofing vector on consent screens).
29. **`backend/app/schemas.py:332`** — `pattern_pid` accepts the empty string, conflating "empty pid" with NULL "general note" semantics.
30. **`backend/app/models.py:336`** *(Info-adjacent)* — `TherapistNote.pattern_pid` is analysis-derived plaintext outside the documented clear-metadata set (conscious, documented trade-off).
31. **`backend/app/api/meta.py:27-29`** — LLM provider/retention fields can be non-None while `llm_available` is false (contract drift).
32. **`backend/app/cache.py:77-79`** — docstrings describe a "login per-username bucket" that doesn't exist (login is deliberately IP-only; the helpers serve register only).
33. **`backend/alembic/versions/c41f8a92d5e7:40,61,62`** — migration-only server defaults (`role`/`status`/`scope`) create a fresh-vs-upgrade schema inequivalence invisible to both parity tests (snapshot excludes server_default). ORM always supplies values; nil operational impact.
34. **`backend/scripts/gen_brain_vectors.py:100-101`** — tokenizer duplicated by hand instead of importing `WORD_RE` (a future engine change leaves generator + checker stale together, all parity green).
35. **`backend/scripts/loadtest.py:59`** — "throughput" is 1/mean-latency, not completion rate (understates by ~concurrency).
36. **`backend/scripts/seed_demo.py:240,246-267`** — documented 409→login re-run path can never succeed (fresh random salt each run; login always 401); `:15-16` usage line omits the required `--db-url` and crashes as written; `:5-6` docstring says 70 days, default is 84.
37. **`backend/scripts/dump_brain_lexicon.py:12-13`** **2×** — stale run instructions (`lexicon.json` vs actual `lexicon.ts` output).
38. **`backend/scripts/_audit_measure.py:157`** — dead condition (`if seed == 2000 or True:`) — scratch file, no gating role.
39. **`backend/probe_brain.py:229,260-263`** — checks C and F accept stored-but-never-surfaced patterns, inconsistent with the probe's "what the brain ACTUALLY surfaces" framing (and with check G).
40. **`backend/tests/test_redteam_fixes_2026_09_16.py:117`** — vacuous assertion (`assert not X or True`) in 23k lines of tests — the only one found.
41. **`backend/tests/test_kdf.py:109-110`** — the only full-cost (600k) KDF vector test can silently skip (skipif not exists) and is `slow`-marked, so it gets zero mutation coverage; contrast `test_encrypt_vectors.py`'s hard-fail idiom.
42. **`backend/tests/conftest.py:80-89`** — destructive-cleanup name guard skips sqlite URLs (pointing `MINDPATTERN_TEST_DB_URL` at a real sqlite file wipes it).
43. **`redteam/e_crisis.py:109`** — case-sensitive exclusion never matches; standing false E3 FINDING from the prompt's own instruction line.
44. **`redteam/d_llm.py:222-232`** — D2 "no egress" also fires when the LLM was never called (drift/failure); D1's case table carries stale expectations (printed, not asserted).
45. **`redteam/b_auth.py:118-122`** — token-confusion summary text contradicts its own data (recorded `{'huge': 'accepted'}` vs printed "all rejected").
46. **`redteam/g_infra.py:141-148`** — any crash counts as an expected fail-closed refusal (stderr only inspected on failure).

### Mobile

47. **`mobile/src/crypto/kdf.ts:85,106`** — async PBKDF2/HKDF copies leave the original derived buffers un-zeroized (`Buffer.from` copy returned; source lingers to GC) — contract is "overwrite as soon as no longer needed".
48. **`mobile/src/crypto/MindPatternCrypto.ts:76-77`** — `decryptEntry` has no payload-version guard, inconsistent with `decryptInsights`' loud-fail contract (a future `v:3` blob would be silently miscast).
49. **`mobile/src/reauth.ts:54-57`** — no throttle on local wrong-password re-auth attempts (contrast UnlockScreen's 500 ms + PBKDF2 cost rationale).
50. **`mobile/src/biometricUnlock.ts:43,54`** — one Keychain generic-password item per service: enabling for account B overwrites A's wrap; disable wipes the whole service (feature loss only; username is verified on read — no cross-account key exposure).
51. **`mobile/src/offlineQueue.ts:407`** — `RETRY_MAX_MS` (30 min) re-clamps the server's 429 `Retry-After` (clamped to 1 h upstream): a 3600 s advisory guarantees one doomed request per item per pass.
52. **`mobile/src/offlineQueue.ts:241`** — foreign-userId records inside a scope key are silently dropped on rewrite, not quarantined (tamper/backup-restore only).
53. **`mobile/src/historyFind.ts:23-25`** — search does no Unicode normalization/diacritic folding (NFD paste won't match NFC-typed query).
54. **`mobile/src/api/client.ts:463-466`** — `Retry-After` parsed only on 429; backend also emits it on 503s (queue falls back to 30 s+ backoff).
55. **`mobile/src/api/client.ts:656`** — `listMeasures` sends no `limit` (server default 100, hard cap 200, no offset — see M-4); UI shows a truncated history with no indication.
56. **`mobile/src/screens/EntryScreen.tsx:200-202`** — unmount cleanup stashes the draft even while a save is in flight; the save completes → restored draft of an already-saved entry → duplicate on re-save (new `clientEntryId`, so server dedupe doesn't fire).
57. **`mobile/src/screens/QuestionScreen.tsx:172-178`** — every status-0 error (timeouts, local refusals) is treated as "offline" → phase flips to baseline with possibly-mislabeled question captions.
58. **`mobile/src/screens/InsightsScreen.tsx:709`** — main pattern-card list renders without the phase gate its siblings enforce (server-trust-boundary display inconsistency).
59. **`mobile/src/screens/InsightsScreen.tsx:561-562`** — every load issues two `GET /insights` requests (double latency + rate budget).
60. **`mobile/src/screens/InsightsScreen.tsx:584-636`** — no request sequencing/cancellation across overlapping loads (older response can briefly replace newer).
61. **`mobile/src/screens/InsightsScreen.tsx:561-562,709`** — a server-muted sensitive pattern vanishes entirely, including the non-quoting support card the design says must stay.
62. **`mobile/src/screens/SettingsScreen.tsx:216-223 vs 235-281`** — a 403 on account deletion clears the password card, contradicting the documented "card stays up for retry" (inner catch swallows; only the LLM path retries).
63. **`mobile/src/screens/SettingsScreen.tsx:430-464`** — two byte-for-byte identical theme-load effects (dead duplication).
64. **`mobile/src/screens/SettingsScreen.tsx:586`** — theme radio a11y label interpolates the raw enum token ("Tema: dark" for Spanish screen-reader users).
65. **`mobile/src/screens/LoginScreen.tsx:121-127`** — partial register failure (post-register await throws) strands the user on "username taken" with no hint to sign in.
66. **`mobile/src/screens/TherapistShareScreen.tsx:52`** — failed consents list renders as "You are not sharing with anyone" (a false certainty on the screen used to verify a revoke).
67. **`mobile/src/screens/HistoryScreen.tsx:518-582,462-490`** — successful edit/delete leaves the pagination revision token stale → next "Load older" always 409-restarts and wipes the user's search/day filters.
68. **`mobile/src/screens/HistoryScreen.tsx:462-490`** — deleting an entry does not remove that day's device-local mood-log value (local streak/trend keeps counting the deleted day).
69. **`mobile/src/screens/MeasuresScreen.tsx:26`** **2×** — `detectCrisisLanguage` imported but never used (dead import; item-9 detection uses `phq9Item9Endorsed`).
70. **`mobile/src/promptChips.ts:40`** — chips rotate on the UTC day, not the local calendar day (change mid-evening for non-UTC users).
71. **`mobile/src/haptics.ts:44-52`** — `Vibration.vibrate(10)` is Android-only duration; iOS produces the fixed ~400 ms system vibration — the opposite of "quiet haptics" for sensory-anxious users.
72. **`mobile/src/locales/en.ts:409`** — grammar error rendered on an evidence row ("your energy have been carrying over"); `en.ts:447` — fallback "certain" pluralizes to "certains" in `{day}s` templates; `es.ts:370` "diario diario" stutter; `es.ts:403,464` anglicized direction-word phrasing.

### Portal

73. **`portal/src/crypto.ts:328-348`** — `decryptCaseloadSummary` leaves the decrypted plaintext un-zeroized (every sibling decrypt zeroizes in `finally`).
74. **`portal/src/api.ts:5-7`** — stale docstring claims a configurable server field; the design is same-origin-only (a maintainer "restoring" the field would reopen the verifier-collection vector).
75. **`portal/src/App.tsx:62`** — every lock boundary (idle lock, expiry, sign-out) erases the "Mark reviewed" delta anchors, undermining the clinical delta the PatientView code builds (deliberate privacy trade-off — worth an explicit decision).
76. **`portal/src/views/PatientView.tsx:596,261`** — measures silently truncated to 60 newest (server cap 200); instrument name decrypted but never rendered (ambiguous the day a second instrument exists).
77. **`portal/src/views/PatientView.tsx:615`** — "Loading decrypted patterns…" stays forever after a failed insights load (gate on `!error`).
78. **`portal/src/views/PatientView.tsx:465-479`** — one undecryptable entry discards the entire evidence drill-down (notes/measures degrade per-item; entries don't).
79. **`portal/src/views/PatientView.tsx:182-184`** — backend 409 code `conflict` (rows-changed-while-paging) is not retried, only `collection_changed` — hard error where a single restart is safe.
80. **`portal/src/views/PatientView.tsx:576-578,795`** — UTC anchor/display dates can show "yesterday" for clinicians east of UTC.
81. **`portal/src/views/PatientView.tsx:696-711,766-780`** — note draft/edit textareas have no programmatic label (placeholder only).
82. **`portal/src/views/PatientView.tsx:95`** — `mood_correlation` fabricates "higher" when `direction` is absent (`undefined` falls to the else-branch; neighbors use `?? "?"`).

### Deploy / docs / shared

83. **`deploy/monitoring/verify.sh:75-84`** — metric grounding checks a hand-copied set, not `metrics.py` itself (drift scenario: removed metric still "grounded").
84. **`.pre-commit-config.yaml:11-15`** — unscoped ruff hooks fail on non-backend Python (`backup/backup_mac.py` non-executable, `redteam/` 223 errors) while CI lints only `backend/`.
85. **`docker-compose.yml`** — no `cap_drop`/`no-new-privileges`/`read_only` anywhere (below the hardening bar the rest of the file sets).
86. **`docker-compose.yml:18`** — DB password interpolated into the URL with no URL-encoding guard (hex-gen prescribed but unenforced).
87. **`.github/workflows/release.yml:243`** — comment references a `release-image-tags` job that doesn't exist.
88. **`.gitignore:24,31`** — `*.db` listed twice.
89. **`deploy/nginx/mindpattern.conf.example`** — `location /api/` doesn't match exact `/api` (SPA fallback returns index.html with 200 for the legacy mount); comment attributes proxy-header enforcement to the entrypoint (it's in `config.py`); no OCSP stapling/cipher tuning vs the file's own thoroughness.
90. **`README.md` error-code catalog** — omits 6+ actually-raised codes (`forbidden`, `disclosure_outdated`, `feedback_blob_invalid`, `llm_unavailable`, `collection_changed`, `method_not_allowed`/`gone`).
91. **`README.md` env table** — omits 9+ production-relevant vars (`MINDPATTERN_THERAPIST_ENROLLMENT_TOKEN`, `MINDPATTERN_TOKEN_TTL`, `MINDPATTERN_ANALYSIS_BLOB_BUDGET`, the LLM policy trio that is *mandatory* when `MINDPATTERN_LLM_URL` is set) and doesn't state that sharing/LLM fail closed OFF in production.
92. **`README.md` deletion scope** — omits the access-log survivor (up to 730 days post-deletion) and the full cascade scope (consents both sides, measures, notes, pairing codes).
93. **`README.md`** — "CI runs eight jobs" (nine); "32 sentiment cases" (39 in the artifact).
94. **`docs/PSYBERGUIDE_SELF_ASSESSMENT.md`** — stale both directions: lists the AsyncStorage device-key residual as open (remediated — Keychain-only, fail-closed) and calls the 60-day simulation "CI-gated" (it isn't; CI pins smaller regressions).
95. **`mobile/tools/decrypt_export.mjs:129,134`** — references removed `bundle.username` (output contains `undefined`).
96. **`reports/simulation60/simulate.py:17-18,20,28`** — docstring promises `timeline_*.csv` outputs that don't exist (dead `import csv`); determinism claim describes single-shot replay, not the daily replay's final day.
97. **`reports/e2e_live/campaign.py:448-456`** — crisis-leak oracle searches raw text with dialog regexes only (no normalization/variants/suppress tier) — weaker than the engine it audits; `:1017-1018` dead `decrypt_blob` branch.

---

## INFO (accepted trade-offs, latent hazards, observations)

1. **Crypto-core observations (no action):** random 96-bit nonces cap at 2³² encryptions/key (orders of magnitude below usage); Python-side derived keys are immutable `bytes` (zeroization impossible — documented); enclave `decrypt()` returns transient immutable plaintext (documented residue class); mobile sharing ephemeral private KeyObject not zeroizable through the engine seam; portal registration holds an extractable private-key copy in JS strings until GC (same standing as the password string); mobile `decryptEntry`'s engine loader has a silent quick-crypto→node:crypto fallback (fails loudly on device) and the react-native-quick-crypto engine itself is never byte-parity tested (documented gap).
2. **Enclave unbound sessions:** `create(owner=None)` would be consumable by any caller — docstring requires `owner` keyword; only production caller binds. Dormant.
3. **`enclave.py:251`** — each `decrypt()` return is a transient immutable bytes copy (within documented residue).
4. **`main.py:183-215`** — failed boot skips `engine.dispose()`/`destroy_all()` (acquisition before the try). Harmless under uvicorn.
5. **`cache.py:147-149`** — requests with no socket peer share one global bucket ("unknown-client") — global auth lockout lever on exotic transports; TCP prod unaffected.
6. **`main.py:106,136-147`** — 1-second key-sweep logs a full traceback per failure on persistent failure (theoretical).
7. **`docker-compose.dev.yml`** — dev overlay still serves with `MINDPATTERN_ENV: production` (fail-closed, deliberate — but no /docs or /metrics locally).
8. **`singleprocess.py:125-141`** — unlink-detection can only fire in a microsecond window; the documented tmp-cleaner scenario is invisible. `:115-124` any flock `OSError` is misreported as multi-worker. `:34-37` docstring says multi-host uncovered; the Postgres advisory lock covers it.
9. **`schemas.py:185-204`** — `ExportBundle` forward-references `ShareRecord` (lazily rebuilt; works).
10. **`meta.py`** — see L-31 above (drift classified Low).
11. **Measures have no PUT/DELETE** (immutable by design — coherent with entries' PUT rationale); `MAX_MEASURES_PER_USER` hardcoded rather than a setting; `list_measures` has no `id` tiebreaker (becomes M-4's bug the moment offset paging is added); no tests for invalid-base64/undersized measure blobs.
12. **`models.py` AccessLog** — no client-IP column (matches documented design); `action` docstring omits `read_measures`; `_active_consent` never checks patient `is_active` (unreachable — deactivation is hard delete).
13. **`alembic` d52c4e8f14a0** — pairing-code dedupe deletes *all* members of a duplicate group (documented, deliberate); downgrades are destructive (standard).
14. **`alembic.ini:2-4`** — comment says URL resolution goes through `app.config`; `env.py` deliberately reads the env directly (behaviorally identical).
15. **`insights.py:717-728`** — enricher invoked even with empty findings (pure waste, within consent); `:1053` — GET echoes a stale stored `state_seq` alongside `blob=None` (harmless for blob-gated clients).
16. **`brain.py` misc:** language defaults `"en"` under 50 scorable tokens (CJK journal reports en but claims correctly suppressed); `load_state` keeps first-90 history vs `update`'s last-90 (corrupt stores only); `PERSON_MIN_TOTAL_MENTIONS` counts distinct entries not mentions; window has no upper date bound (API validates today+1); `EVIDENCE_DATES_CAP=60` eviction slightly weakens replication independence for very long-lived patterns; `_inertia_signal` admits gap-2 pairs into "lag-1" (undocumented smoothing); emoji tokens appended at token-list end (trailing negators can scope onto emoji — pinned); `detail["sample_days"]` is an entry count; `avg_sentiment` still text-derived under "other"; muted-store eviction is alphabetical-first not LRU; `variants` not char-capped (bounded); LLM merge keyed `(kind, label)` can alias duplicates; `_mood_reanchor_day` re-anchors on candidate records (conservative).
17. **`statsig.py:97-104`** — BH accepts a NaN p-value as rejected (producers clamp NaN away; fail-closed guard would pin it). `correlation_p`/`f_sf` have no production call sites (documented primitives).
18. **`llm.py:134/151`** — "lately" duplicated in the allowlist (harmless).
19. **`threshold.py:49-64`** — `evaluate` consumes its iterable twice (all callers pass lists). `patterns.py:231-267` `describe()` numeric formatting assumes numeric detail values (hostile-store only).
20. **Test infrastructure:** `ClientEmulator` uses the server's own crypto modules (compensated by committed cross-platform vectors + CI verify tool — but the API suite is not client-server interop proof); mutation scope excludes `models.py` and `slow` tests (documented); two 2026-09-19 test modules hard-code sqlite fixtures (Postgres-job parity gap, DB-independent behavior).
21. **Mobile queue metadata** (`userId`, `entryDate`, `clientEntryId`) is plaintext in AsyncStorage (consistent with the documented metadata bar); `clearQueue` destroys the legacy recovery key even if another account owned it (documented right-to-erasure trade-off); quarantine store grows unbounded.
22. **`secureStore.ts:140`** — stored values are AAD-less (vector-pinned deliberate; relocation between keys of the same install possible — downstream fails closed).
23. **`store.tsx:29-38`** — stashed draft is plaintext in the JS heap and survives lock (documented: backgrounding must not destroy drafts); `stateSeqGuard.ts:71` `forgetAnalysisGeneration` has no production caller (a legitimate server-side reset would brick Insights with an unrecoverable retry — latent).
24. **`client.ts:450-460`** — any 401-with-token fires the vault-lock hook (a future semantic-401 endpoint would lock the app); `request` returns `Promise<any>` for most endpoints (documented server-untrusted posture; `MeasuresScreen.tsx:100` casts without validation).
25. **`exportAccount`** is dead code in the app (no call site) and would inherit the 15 s timeout — wire with a longer timeout when a UI lands.
26. **`crisisDetect`/`crisis.py`** — lone-surrogate normalization diverges in form only (verdicts agree; unreachable from real input); detection runs at save, not per keystroke (deliberate — "never before or instead of saving"; "Get help" is one tap away); backend corpus `v` field not pinned by backend tests (arrays are pinned byte-for-byte).
27. **`nativeFeatures.ts`/`healthkit.ts`** — all native seams dormant (notifee/react-native-health/biometrics not in package.json); hardcoded notifee enum constants match for when they link; watch Android DST drift on the native daily repeat. `healthkit.ts` is a write-only StateOfMind seam (no reads/sleep/step — brief's assumption corrected). `recordMood` doesn't validate its `date` argument (call sites pass `localDateISO`).
28. **Portal:** `crypto.ts:264` clamps measure scores to 0–100 (PHQ-9 ≤ 27 — future >100 instrument would silently cap); `<mark>` highlighting inside the drill-down re-styles already-displayed text (label itself never rendered — non-quoting contract holds); total measures-decrypt failure indistinguishable from "never recorded" (deliberate); English-only portal (consistent); `lastVisit` key literal duplicated between views; setState-after-unmount paths without generation guards (React-18-harmless); LoginView has no `<form>` (Enter doesn't submit).
29. **Redteam:** one `guard()` per series — a mid-function crash drops remaining sub-verdicts; `run()` exits 0 regardless of FINDINGs (dev-oracle posture, consistent); dead round-1 fallback in the gate would TypeError if round-2 were removed; embedded credentials are throwaway literals targeting localhost only.
30. **`verify_native_release.mjs`** — cwd-relative paths (fails from repo root — fails in the safe direction).
31. **Float-parity wording** — gen_brain_vectors/sentiment.ts headers say "exact/byte-identical" while the test wisely uses `toBeCloseTo(score, 12)` (measured ~1e-16 drift on 3/39 vectors — association-order ULPs).
32. **README supersets (no deficit):** `/meta` returns 4 documented + 7 more fields; `/readyz` also asserts exact Alembic head; measures have their own 2000 quota (not the entries quota the phrasing suggests).
33. **`mutation-pr.yml` paths** exclude `backend/tests/**` (see H-15 for the compounding effect).

---

## Verified solid (context for the findings above)

The audit confirmed, with live execution where possible: byte-identical crypto parity across backend/mobile/portal (every committed vector reproduces, including all 16 AAD edge cases and 3 wrap vectors); correct PBKDF2/HKDF/AES-GCM/ECIES constructions and nonce discipline; anti-enumeration decoys and uniform-CPU registration; scrypt off the event loop; single-use keystore mechanics (atomic pop, monotonic TTL, owner binding, zeroization on every exit); 30-day threshold enforced on every read path; complete deletion cascade + keystore purge; no plaintext columns; exact migration↔model parity (double-pinned); no lock-order cycles anywhere; EWMA/BH/Welch/binomial math recomputed correct; PYTHONHASHSEED-invariant determinism; crisis normalization surviving 8,000+ hostile fuzz inputs on both engines with zero crashes; portal free of XSS surfaces with a strict CSP; offline-queue 409 idempotency; PHQ-9 scoring standards-correct; and the README's load-bearing security claims verified accurate against code.
