# Deep Multi-Angle Independent Audit — 2026-10-01

**Method.** Twelve independent audits ran in parallel, each with exclusive scope, no shared
context, and instructions to read every in-scope file line-by-line and cite `file:line`
evidence (prior audit `.md` reports were excluded to preserve independence). A 13th
integrator pass re-read the backend core (main/config/deps/auth/middleware) and
**first-hand verified every CRITICAL/HIGH claim by executing the actual code** before it
entered this report. Verified findings are marked ✅ (executed or line-traced by the
integrator, not just reported by an agent).

| # | Angle | Result |
|---|---|---|
| 1 | Backend web security | No CRITICAL/HIGH; 6 LOW |
| 2 | Cryptography | 1 CRITICAL, 2 MEDIUM, 3 LOW |
| 3 | Clinical safety / crisis | 2 CRITICAL, 1 HIGH, 2 MEDIUM, 3 LOW |
| 4 | Statistics engine | No CRITICAL/HIGH math defects; 1 MEDIUM, 6 LOW/INFO |
| 5 | Backend robustness | 3 MEDIUM, 3 LOW |
| 6 | Mobile client | 1 HIGH, 3 MEDIUM, 6 LOW |
| 7 | Web patient client | 3 MEDIUM, 5 LOW |
| 8 | Therapist portal | 1 CRITICAL, 1 MEDIUM, 2 LOW + INFO |
| 9 | Contracts & i18n | 2 MEDIUM, 4 LOW |
| 10 | Test quality / mutation claims | 1 CRITICAL(process), 2 HIGH, 2 MEDIUM, 2 LOW |
| 11 | Infra / deploy / CI | 1 HIGH, 2 MEDIUM, 5 LOW |
| 12 | Repo hygiene / leaks | 2 MEDIUM, 6 LOW/INFO |

---

## CRITICAL

### C1. Recovery kit transmits the raw recovery key alongside the data key it seals — the zero-knowledge claim is broken ✅
- `mobile/src/screens/SettingsScreen.tsx:731-737`, `mobile/src/crypto/recovery.ts:22-33`,
  `backend/app/api/account.py:999-1041`, `backend/app/api/auth.py:434-493`.
- The client sends, in ONE request: the **raw 32-byte recovery key** (`recoveryKeyToB64`) plus the
  data key sealed under `HKDF(recovery_key, "mindpattern/recovery/v1")` — a public, deterministic
  derivation of exactly the transmitted value. The server decodes the key in cleartext
  (`base64.b64decode(body.verifier)`) before scrypt-hashing it, and stores the sealed blob.
- **Impact:** any honest-but-curious or compromised server, request-logging layer, or TLS
  termination point that observes a recovery-kit setup or recovery request can derive the KEK and
  unwrap the account's **data key → entire journal** (entries, PHQ-9, audio). The docstring's
  claim "the server can neither open the data-key copy nor reconstruct the recovery key"
  (`account.py:956-957`) is false; the "exactly like a login verifier" analogy fails because the
  auth key cannot decrypt anything — the recovery key can.
- **Fix:** domain-separate client-side: send only `HKDF(recovery_key, info="…/recovery-verifier/v1")`
  (scrypt-hashed server-side like login); seal the data key under the never-sent
  `"…/recovery-seal/v1"` label.

### C2. Crisis-dialog false negatives on high-frequency first-person ideation (EN and ES), plus an emoji bypass ✅
- `shared/crisis_phrases.json:5-128`, `backend/app/services/crisis.py:65-211,464-620`; engine
  executed directly by the integrator (mobile/web copies are byte-identical, so results hold on
  every surface; the dialog tier is **client-side only**).
- Confirmed executing the real engine (`dialog / suppress`):

  | phrase | dialog | suppress |
  |---|---|---|
  | "i wish i could disappear" | False | False |
  | "i cannot take it anymore" | False | False |
  | "the world would be better without me" | False | False |
  | "i would rather die" / "hoping i don't wake up" | False | False |
  | "me voy a suicidar" (ES: I'm going to kill myself) | **False** | True |
  | "pienso matarme" (ES: I'm thinking of killing myself) | **False** | True |
  | "acabar con todo" / "me gustaría morir" / "no puedo seguir" | False | False |
  | "k😊ll myself" | False | False |
  | (controls) "i want to die", "kill myself" | True | True |

- **Impact:** the Spanish suppress-only rows are the worst class: suppress-extra fires, so the
  phrasing never echoes in cards, but **no support dialog appears anywhere** (dialog tier is
  client-side and shares the same list). English wish/rather/wake-up/burden phrasings and the
  emoji-inside-short-word fold bypass miss both tiers, so the sentence can additionally be quoted
  verbatim as a rumination/topic card label to the patient (`InsightsScreen.tsx:582`) and
  therapist (`portal/PatientView.tsx:256-258`).
- **Fix:** promote first-person `suicidar(se)` conjugations, `acabar con todo/conmigo`,
  `pienso/debo/tengo que + matarme`, and the EN wish/rather/wake-up/gone/burden families to the
  dialog tier; fix normalization to drop (not space-fold) intra-word non-letters or extend
  orphan-glue to 1–3-letter fragments on both neighbors.

### C3. Therapist password change permanently and silently destroys every existing note ✅
- `portal/src/crypto.ts:8-11,77-91` (`note_key = HKDF(master=PBKDF2(password,salt))` — no
  indirection), `portal/src/views/PatientsView.tsx:257-341` (`changePassword` re-wraps the P-256
  sharing key and rotates the credential but never touches notes; no note-rekey endpoint exists),
  `portal/src/views/PatientView.tsx:829,931` (all decryption uses the current password's `noteKey`).
- **Impact:** after a routine password change, the server-side salt is rotated, the old `noteKey`
  is cryptographically unrecoverable, and every note + revision renders "(note could not be
  decrypted with this account's key)" — permanent loss of the therapist's private clinical
  record. Adjacent copy says "Your notes are unaffected" (true only for key rotation, misleading
  in the password-change flow). Verified by integrator line-trace of the full flow.
- **Fix:** re-encrypt all notes+revisions under the new `noteKey` while both passwords are
  derivable (page, decrypt, PATCH before `rotateCredential`), or redesign notes to seal under the
  password-independent wrap key, as the patient apps do for entries.

---

## HIGH

### H1. Mobile audio queue has no origin pin — a mid-flush server switch permanently destroys kept recordings ✅
- `mobile/src/audioQueue.ts:144-180`, `mobile/src/api/client.ts:1567-1578`.
- `flushAudioQueue()` captures `origin` once and loops for minutes; `uploadAudioAttachment`
  carries **no `expectedOrigin`** (unlike `createQueuedEntry`'s `OriginPinnedError` guard), and the
  origin-change handler bumps only the text queue's generation. If the user switches server and
  signs in mid-flush, remaining takes upload to the new origin → 404/409 →
  `AsyncStorage.removeItem(key)` — **the only copy of the user's kept recording is deleted**, and
  origin-A ciphertext lands on origin B.
- **Fix:** add `expectedOrigin` to `uploadAudioAttachment`, re-check `getBaseUrl()` per item, and
  abort the audio flush on origin change.

### H2. nginx example config: `location /api/ {{` syntax error breaks BOTH proxy blocks ✅
- `deploy/nginx/mindpattern.conf.example:162` and `:309`.
- Both the portal and web server blocks fail `nginx -t` (`unexpected "{"`). A fresh deployment
  following `deploy/README.md` cannot bring the TLS front up at all (existing deploys fail
  reload → fail closed on the old config). No CI step validates this file.
- **Fix:** single `{`; add an `nginx -t` CI gate over the example with substituted placeholders.

### H3. The "35,402 mutants, every killable survivor pinned" claim is not backed by the repo (process/trust, not code)
- `reports/mutation_report_2026-09-30.md` vs `mutation.yml:67,85`, `backend/pyproject.toml:87`,
  `redteam/run_pr_mutation_gate.py:33-38`.
- CI mutates only `app/security/ + app/services/` while the report claims api/middleware/cache/
  config/deps/db/main/schemas "plus" locks/metrics/singleprocess (two of which are excluded from
  the deep scope); CI tolerates 25 survivors vs the claimed residual 7; the campaign evidence
  lives outside the repo (`~/Desktop/mh_mutcamp`); the report simultaneously says a verification
  pass "is still running" and its ledger is "final", and disagrees with its own pin-suite
  docstrings on three counts (34,924 vs 35,402; 8 vs 6 suites; ES lexicon 1,752 vs 1,552).
  The committed pin suites themselves are genuine, green (168/168 verified live), and CI-run —
  what's unverifiable is the campaign summary and its "final residual 7".
- **Fix:** re-run the campaign scope in CI (or publish the cache/scripts), reconcile the numbers,
  and delete the 12 **untracked, dead** Python pin-test copies under `mobile|web|portal/tests/`
  (vitest-only dirs; pytest never collects them; one is a stale draft holding live object
  references) — they are phantom coverage one commit away from misleading review.

---

## MEDIUM (verified highlights; full detail in per-audit sections below)

**Cryptography & data protection**
- **M1. v1-AAD fallback ladder re-opens stale-ciphertext replay** — every client silently retries
  the legacy version-free AAD for ANY `contentVersion` (`mobile/src/crypto/MindPatternCrypto.ts:157-165`,
  `web/src/crypto/patient.ts:139-147`, `portal/src/crypto.ts:513-531`): a malicious server can
  replay a pre-edit blob with the truthful current version echo; the per-id high-water mark only
  flags declines. Restrict fallback to ids proven v1-bound.
- **M2. No data-key rotation exists under v2** — password change re-wraps the SAME key; revoke
  only nulls the wrap column (`mobile/src/rotation.ts:22-28`, `consents.py:664`). A therapist (or
  anyone via C1 or a processing session) who once held the data key can decrypt all future
  ciphertext forever; v1's O(corpus) rekey was dropped without replacement. Ship a rotate-data-key
  flow (rekey machinery already exists in `insights.py:482+`).

**Clinical safety (companion to C2)**
- **M3. Web crisis prompt is a dead-end card** — text-only, no resources/link/button, copy
  promises "the resources below are one tap away" with nothing following
  (`web/src/views/Entry.tsx:542-547`, `History.tsx:518-522`, `App.tsx:339` gives `EntryView` no
  `onCrisis`), and it fires **before** save (mobile fires after the entry is safely stored).
- **M4. PHQ-9 item 9 endorsed offline gets no support pointer** — the safety dialog runs only
  after a successful upload; the offline branch returns without it
  (`mobile/src/screens/MeasuresScreen.tsx:268-307`, `web/src/views/Measures.tsx:350-377`) —
  a self-harm endorsement with no network gets nothing in the moment.

**Statistics**
- **M5. Negated perseverative distress scores POSITIVE** ✅ — `"can't stop crying"` → **+0.444**,
  `"can't stop the tears"` → +0.407, `"can't stop the pain"` → +0.389 (integrator-executed;
  `brain.py:2274-2287`). crying −2.4 / tears −2.2 / pain −2.1 sit just above the −2.5 strong-
  negation guard, so the ×−0.74 negation scalar flips them — violating the module's own stated
  invariant (`brain.py:1141-1142`). Tag-less distress entries can read as elevated mood,
  inverting the direction of mood-derived pattern claims. Clamp negated negatives to ≤ 0
  (VADER-style) or extend the guard.

**Portal**
- **M6. Mood sparkline plots newest→oldest left→right**, opposite the PHQ/GAD trend chart in the
  same screen (`PatientView.tsx:1117` vs `:770`) — a clinician comparing slopes misreads
  direction of change.

**Mobile**
- **M7. RecoveryScreen unlocks the vault with a placeholder-zero authKey but `authKeyKnown`
  defaults true** ✅ (`RecoveryScreen.tsx:65-72`, `vault.ts:44-50`) — every subsequent password
  check compares against zeros: "Wrong password" blocks account deletion, consent, biometric
  enable, key upgrade and password rotation until a full sign-out/in, exactly on the user's
  worst day. Pass `{authKeyKnown: false}` as UnlockScreen's biometric path does.
- **M8. Settings recovery-kit status and language preference load only if a theme was ever
  stored** (`SettingsScreen.tsx:802-826`) — fresh installs permanently show "recovery unknown"
  and hide the kit-removal UI.
- **M9. Recovery flow persists the session token before the flow proves out**
  (`recoveryFlow.ts:48`) — a mid-flow failure leaves a stored bearer + switched account with no
  rollback.

**Web client**
- **M10. Journal draft is destroyed by plain navigation (Today→History→Today) while the UI
  promises "Your draft stays on this device, encrypted, until you save or discard it"**
  (`App.tsx:291-297` + `locales/en.ts:876`; the draft seals only on lock/crash) — and a stale
  sealed draft overwrites newer typing on restore.
- **M11. Unsaved safety-plan text has no seal on ANY path** (lock, crash, navigation;
  `SafetyPlan.tsx:54-71`) — the entry draft got this fix; the clinically-critical plan didn't.
- **M12. Dev/preview servers ship `microphone=()`**, killing the entire voice feature in
  `vite dev`/`preview` with misleading "permission denied" copy (`vite.config.ts:20,104-109`);
  the config test pins only `_headers`/nginx, so the drift the suite exists to catch passes.

**Backend robustness**
- **M13. `measure_count` quota counter is incremented on create but never decremented on delete**
  ✅ (`measures.py:271` vs `457-474` — contrast `entries.py:694-701`) — permanent upward drift;
  patients who delete and re-record eventually false-413 at the 2,000 lifetime cap.
- **M14. Blocking full-file journal I/O on the event loop** — daily sweep `read_journal_heads` +
  `compact_audit_journal` (full read/rewrite/fsync) and per-request journal appends run on the
  loop (`main.py:168-169,203-215`, `deps.py:113-116`); the journal is bounded only by retention
  (730d). Move to `anyio.to_thread` as scrypt already is.
- **M15. Schema drift: `users.recovery_set_at` is TIMESTAMPTZ in the model but TIMESTAMP in
  migration `b7c4e2f9a1d5`** (`models.py:204` vs migration `:31`) — invisible to the SQLite-only
  autogenerate parity gate. Fix the migration before any production DB applies it.

**Contracts & i18n**
- **M16. Web Patterns view fails OPEN on an unknown `phase`; mobile fails closed**
  (`web/src/views/Patterns.tsx:191-199,262` vs `InsightsScreen.tsx:683-685`) — a future/mangled
  phase silently renders the insight UI and burns the one-time threshold notice.
- **M17. Mobile `API_ERROR_CODES` allowlist lags the backend by 6 codes** — including
  `recovery_not_configured`, reachable from the shipped recovery flow, which therefore renders
  raw English detail for Spanish users (`mobile/src/api/client.ts:463-534`, `recoveryFlow.ts:45`).

**Infra**
- **M18. Rollback runbook dump uses `-pass env:BACKUP_KEY`** which production never sets
  (file-mount only) — the documented restore-point command fails exactly when needed
  (`deploy/README.md:425` vs `docker-compose.yml:293`).
- **M19. Backups + stale-backup alerting are triple opt-in; default prod silently has neither**
  (`docker-compose.yml:263` profiles, alerts group commented out) — make "no backups" a recorded
  decision, not a silent default.

**Hygiene**
- **M20. Tracked screenshots render decrypted journal entries and a TOTP enrollment secret**
  (`e2e_gui/screenshots/06-…decrypted-entries.png`, `13-totp-secret.png`, 38 PNGs in
  `gui-test-screenshots/`) — all synthetic today, but the repo bakes in committing rendered
  PHI-shaped screens. (Everything else is clean: no DB/log ever entered git history; on-disk DBs
  are ciphertext-only synthetic; zero secrets found.)

---

## LOW / INFO (selected)

- Backend: `_note_target` skips the `is_active` gate its siblings enforce (`therapist.py:1526-1536`);
  `/auth/recover` lacks the per-username keyed failure budget its siblings have; token `purpose`
  claim never cross-checked (dead claim, remove or assert); pairing-code entropy 2^39.2 per-IP-only
  (documented residual). WAL pragma ordered before `busy_timeout` (`db.py:98-101`); stale
  `demo.db`/`sim1y.db` dev artifacts; alembic.ini header misstates URL resolution.
- Crypto: PBKDF2-600k only (no Argon2id shipped; GPUs grind cheaper); pairing SAS substitution
  rests on user-compared fingerprint; entry dates/`content_version` are unauthenticated metadata
  (malicious server can shuffle dates into pattern inputs).
- Mobile: dead per-file coverage gate (`vitest.config.ts` pins nonexistent `src/kdf.ts`); recovery
  password policy weaker than registration (`RecoveryScreen.tsx:53` length-only); English-only
  failure copy on ES locale for recovery/rotation errors; **no ErrorBoundary anywhere**; quarantine
  on transient write failure; account-deletion residue (`unlockBackoff`, HealthKit mirror pref).
- Web: `History.submitEdit` uses the shared key buffer across awaits (saved today only because
  lock also clears the session — one soft-lock refactor from silent zero-key corruption);
  export 15s timeout + instant blob-URL revoke + no 401 latch; offline-queue plaintext metadata
  (dates/sizes/ids) in IndexedDB; threshold-notice date in plaintext localStorage (inconsistent
  with the crisisDialog precedent).
- Portal: crash-boundary reset key collapses all patients (`App.tssx:291`) + CrashPanel traps
  navigation; note-id console.warn.
- Contracts: `audio_vectors.json` error-code table missing `stt_unavailable`; stale drift-shim in
  `mobile/tests/genericQuestions.test.ts` "fixing" an already-fixed pronoun (with a comment
  claiming shared is unsynced — it is synced); web crisis-phrase pin compares sorted arrays;
  two awkward ES question calques ("lenta y lentamente").
- Stats: on-device language default ("en") diverges from server ("other") on zero-scored text —
  a latent parity break; RESEARCH.md documents retired `LANGUAGE_MIN_TOKENS` as shipped;
  deployed mood_shift false-alarm 5.3–5.4% vs the "≤5%" headline (true only under true-φ
  calibration; in-code comment is honest); avoidance null includes its own trials; topic-rising
  binomial uses data-dependent base (both gated/documented).
- Infra: gitleaks tests/ allowlist weakened in `--no-git`/pre-commit modes; dev minio `:latest` +
  hardcoded creds (dev-only, loopback); entrypoint doesn't validate postgres password charset;
  dual Python lock sources (uv.lock vs requirements.lock) can drift.
- Tests: over-pinned prose (deliberate, high friction); digest pins regenerate silently;
  contract-registry is static AST (unreachable-at-runtime raises still pass). Blind spots:
  `mobile/thresholdNotice.ts`, `RecoveryScreen` UI flow, `web/historyFind.ts`, `web/audio/player.ts`.

---

## Verified strong (what held up under 12 independent line-by-line passes)

- **AuthN/AuthZ (backend):** every query owner-filtered; every therapist read behind
  `_active_consent` (therapist, user, status, patient-is_active) under fixed-order locks;
  consent scopes (v2 measures, voice) enforced per-endpoint; revoke propagation complete
  including summaries; scrypt N=2^17, constant-time compares, decoy salts, per-username TOTP/
  verifier buckets, epoch + durable jti revocation; no SQLi/traversal/SSRF/default-secret paths.
- **Crypto:** genuinely four-way-pinned vectors incl. 16 AAD edge cases; fresh nonces everywhere;
  strict ECDH point validation; single-use TTL'd processing sessions; export bundle ciphertext-only.
  Web "memory-only custody" is TRUE (verified by grep of every storage write across all clients).
- **Statistics:** BH/binomial/t/Welch/Fisher-z/EWMA/entropy+Miller–Madow/MinHash-LSH all reproduced
  numerically; engine byte-deterministic under PYTHONHASHSEED and shuffled input; 30-day threshold
  exact; probe 11/11.
- **Concurrency/ops:** lock chain sound; migrations single-head with parity test; three-way
  single-process enforcement; quota races closed; retention sweeps; rehearsed encrypted backup
  restore incl. tamper rejection.
- **Infra/CI:** digest-pinned images throughout; file-mounted secrets; SHA-pinned actions;
  least-privilege permissions; container hardening; no PHI artifacts; privacy at the edge
  (no access logs, aggregate-only metrics).
- **Hygiene:** zero secrets ever committed; no DB/log in git history; all shared contracts and
  embedded copies currently in sync and pinned by exact-equality tests.
- **Prior remediation cross-check:** fixes claimed by earlier audit waves that these audits
  incidentally re-exercised (decoy salts, revoke propagation, memory-only custody, phrase-copy
  parity, migration parity, erfc tolerance) are genuinely in place — the one "fixed" narrative
  that does not fully hold is the mutation campaign summary (H3).

---

## Recommended fix order

1. **C2 crisis phrase gaps** (EN+ES dialog tier + emoji normalization) — life-safety, pure data fix.
2. **C1 recovery-key domain separation** — one-label change client-side + server verifier semantics.
3. **C3 portal note rekey on password change** — clinical data loss; blocks shipping portal notes.
4. **H1 audio origin pin**, **H2 nginx `{{`** — small, isolated patches.
5. **M5 sentiment clamp**, **M3/M4 crisis UX**, **M7 vault flag**, **M10/M11 draft seals** —
   clinical-facing correctness cluster.
6. **M1/M2 crypto eviction**, **M13–M15 backend integrity**, **M16–M19 contract/infra**,
   then the LOW backlog; **H3** is a documentation/CI-honesty task (re-run campaign in CI or
   retract the "final residual 7" claim; delete the 12 dead untracked test files).

---

## REMEDIATION RECORD (2026-10-01, same day)

| Finding | Status |
|---|---|
| C1 recovery-kit zero-knowledge break | **FIXED** — v2 domain-separated scheme (verifier label sent, seal label never leaves the device), scheme negotiation with `recovery_scheme_mismatch` retry, legacy v1 kits keep working, migration column + 7 new backend tests + updated mobile flow tests |
| C2 crisis phrase gaps + emoji bypass | **FIXED** — 20 new dialog patterns (EN wish/rather/burden/wake-up + ES first-person families), 3 suppress counterparts, intra-word symbol DROP + bounded vowel-reinsertion variants, letter-only script boundaries; fixtures + sample parity extended in all 4 copies |
| C3 portal password change orphans notes | **FIXED** — notes seal under the password-independent identity key (HKDF over the P-256 private key); changePassword runs a verifier-gated batch rekey of legacy blobs AND revision history through the new `PUT /therapist/notes/rekey` (same-length invariant, no version bump); 6 new backend tests; misleading copy corrected |
| H1 audio queue origin pin | **FIXED** — per-item `expectedOrigin`, `OriginPinnedError` keeps rows queued, origin-change aborts the flush; new test |
| H2 nginx `{{` | **FIXED** (both blocks) |
| H3 mutation-claim credibility | **FIXED** — 12 dead untracked client-dir test files deleted; erratum prepended to the report |
| M5 sentiment direction inversion | **FIXED** — perseverative-frame rule (stop/quit/dejar) suppresses the negation flip in both directions; 6-test regression suite; lexicon contract regenerated |
| M13/M14/M15 + backend LOWs | **FIXED** (measure counter, journal I/O off-loop, TIMESTAMPTZ migration, `_note_target` is_active, recover keyed budget, token purpose check, WAL pragma order, alembic.ini header, entrypoint hex gate) |
| M7/M8/M9/M17 + mobile LOWs | **FIXED** (authKeyKnown=false, settings hoist, session rollback, 7 error codes added, coverage-gate path, recovery password policy, root ErrorBoundary, deletion residue) |
| M4 offline item-9 pointer | **FIXED** (mobile + web) |
| M3/M10/M11/M12/M16 + web LOWs | **FIXED** (crisis prompt rides the save + real support button + dismiss; draft and safety-plan seals on nav/lock/crash; vite mic=(self); phase allowlist; History key snapshot; export 120s + 401 latch + delayed revoke; threshold stamp to kv) |
| M6 + portal LOWs | **FIXED** (sparkline chronology, per-patient resetKey, console.warn trimmed) |
| Contracts batch | **FIXED** (stt_unavailable documented, pronoun shim deleted, web pins exact-order, 2 ES calques corrected across all 5 copies, mobile language default = server parity) |
| M1 v1-AAD fallback | **FIXED** — encrypted per-id v2-bound marks (web+mobile), session-scope gate (portal); legacy fallback refused for ever-v2-bound ids |
| M2 data-key rotation | **TRACKED** — registered in docs/SECURITY_RESIDUALS.md with the full design sketch (corpus-wide rotation is the one change class that can brick a zero-knowledge journal; it gets its own wave, not a same-day patch) |
| M18/M19/M20 + infra LOWs | **FIXED** (rollback -pass form, backups decision gate in deploy README, screenshots untracked + ignored, RESEARCH.md corrections, minio pinned to dated release) |

**Verification.** Backend: 1,945 passed / 0 failed / 5 skipped (PG-only), ruff clean,
probe_brain 11/11, mutation pins + contract registry regenerated for the deliberate
changes. Mobile: 2,070 passed (2 pre-existing order-dependent calendar-test flakes,
verified failing on unmodified HEAD). Web: 744/744. Portal: 477/477. All four
typechecks clean (web's entryVoiceUi test-typing error pre-exists at HEAD).
