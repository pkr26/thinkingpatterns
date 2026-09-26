# Full-Codebase Deep Audit — 2026-09-26

Nine independent audit passes over every source file in the repository (mobile and web
audited independently, as requested), each pass reporting 100% file coverage of its scope:

| # | Scope | Files / lines | Result |
|---|-------|---------------|--------|
| 1 | Mobile core modules (crypto, api client, queue, vault, sync, crisis detect) | 50 files | 2 HIGH, 3 MEDIUM, 5 LOW, 4 INFO |
| 2 | Mobile screens, components, locales, tests | 49 files | 3 MEDIUM, 8 LOW, 5 INFO |
| 3 | Patient web client (src, views, crypto, tests, headers, SRI) | 100% incl. all 32 test files | 2 HIGH, 6 MEDIUM, 5 LOW, 4 INFO |
| 4 | Clinician portal (all src + tests) | 34/34 files | 1 MEDIUM, 3 LOW, 2 INFO |
| 5 | Backend core & security (main, config, middleware, security/*, alembic, supply chain) | 48 files | 4 LOW, 5 INFO |
| 6 | Backend API routes (47 routes, 7,378 lines) | 11/11 files | 2 HIGH, 2 MEDIUM, 3 LOW, 5 INFO |
| 7 | Backend services (brain 4,496L, crisis, llm, lexicons, corpora cross-check) | 100% | 1 HIGH, 2 MEDIUM, 4 LOW |
| 8 | Infra / deploy / CI / repo hygiene | 53 files | 3 MEDIUM, 6 LOW, 5 INFO |
| 9 | Shared corpora, redteam tooling, docs integrity, cross-platform parity | 100% | 1 HIGH, 2 MEDIUM, 4 LOW, 4 INFO |

**Verdict: no CRITICAL findings. Seven HIGH findings — one safety-critical (crisis-language
coverage gap, independently confirmed by two audit passes), two mobile device-runtime
breakages, one web data-loss flow, one web data-semantics inversion, two backend
availability/quota defects.** The overall security engineering remains exceptionally
strong (see §4); the findings below are the residual gap between that standard and
perfection, not systemic weakness.

---

## 1. HIGH findings

### H-1. Crisis-language coverage gap — ideation phrasings miss both tiers and are quoted back to users (SAFETY-CRITICAL)
*Found independently by audit passes 7 and 9 (consistent, complementary evidence) and echoed by pass 1.*

- EN gaps: "life is not worth living", "I no longer want to live" match neither the dialog
  nor the suppress tier (`backend/app/services/crisis.py:65-158`), while semantically
  identical "no reason to live" / "nothing to live for" are covered.
- ES gaps (broader): only six Spanish ideation phrases are covered. "me quiero cortar"
  (I want to cut myself), "me lastimo", "no vale la pena vivir", "no hay salida",
  "quiero desaparecer", "todos estarían mejor sin mí", "no tengo ganas de vivir",
  "estoy harto de la vida", "solo quiero dormir para siempre", and the natural conjugated
  forms "me quiero quitar la vida" all match **no tier**.
- EN/ES asymmetry in the dialog tier: "tired of living" fires in Spanish ("cansada de
  vivir") but not English; "can't do this anymore" has no Spanish counterpart.
- Verified end-to-end: a recurring uncovered phrase is surfaced by the brain as a
  recurring-thought card quoting the ideation **verbatim with no `sensitive` flag**, and
  `questions.build_pool()` generates reflective questions engaging with it ("what does it
  mean to you?") — the exact failure mode `questions.py`'s crisis-interlock docs say must
  never happen. Also reachable through LLM narrative echoes (`llm.py` uses the same matchers).
- The gap is corpus-level, so every parity test passes and `redteam/crisis_corpus.json`
  cannot see it.
- **Fix**: extend dialog+suppress tiers in `shared/crisis_phrases.json` first (the three
  embedded copies — backend `crisis.py`, `mobile/src/crisisPhrases.ts`,
  `web/src/crisisPhrases.ts` — are byte-identical and will follow via parity tests), and add
  adversarial EN+ES rows to the red-team corpus so CI pins them.

### H-2. Mobile password rotation crashes on device — `globalThis.crypto` does not exist in React Native
`mobile/src/rotation.ts:41-45` — `freshSalt()` uses `globalThis.crypto.getRandomValues`;
RN 0.87.1 ships no Web Crypto global, `react-native-get-random-values` is not a dependency,
and quick-crypto's `install()` is never called. The call at line 118 sits **outside** the
function's try block, so the TypeError escapes `rotatePassword` entirely. The whole
credential-rotation/recovery flow is unusable on-device; tests pass only because node
provides `globalThis.crypto`. Fix: use `engine.randomBytes(16)` and/or call
`QuickCrypto.install()` in `index.js`.

### H-3. Mobile: no runtime bootstrap installs `global.Buffer` — probable boot failure on device (needs device-build verification)
Bare `Buffer` is used at module scope (e.g. `mobile/src/unlockProof.ts:22`, executed at
import time via `store.tsx`) across ~20 modules; `mobile/index.js` (4 lines) installs
nothing, and `mobile/` has **no babel.config.js or metro.config.js**.
`@craftzdog/react-native-buffer` only sets `global.Buffer` inside its never-called
`install()`. If the bundle runs as configured, first import throws
`ReferenceError: Buffer is not defined` — app fails to boot. All 1,100+ tests run under
node globals that mask this. Fix: `QuickCrypto.install()` (or buffer polyfill install)
first thing in `index.js`; commit standard babel/metro configs; add a red-team test that
imports the bootstrap without node globals.

### H-4. Web: rotation failure after successful rekey leaves a live session holding the dead OLD data key — permanent data loss
`web/src/views/Settings.tsx:139-173` — mobile's audit-round-2 F-4 fix was never ported. If
`rekeyStoredData` succeeds but any later step throws (network drop during consent rewrap /
credential rotate), the web client does **not** lock the vault: the user keeps journaling
and every new entry is AES-GCM-sealed under the old data key that nothing can ever decrypt
again (server corpus is already under the new key; the old credential may still be valid,
so nothing forces re-login). Mobile (`mobile/src/rotation.ts:184-226`) locks the vault and
drops the biometric wrap on this exact path. Fix: call `props.onLockdown(...)` on any
failure at/after the rekey call; zeroize `newKeys` in a `finally` (also missing, see L-W6).

### H-5. Web: entry payload `sentiment` semantics inverted vs mobile — machine estimate written into the "user's own report" field
`web/src/views/Entry.tsx:43,87` writes `sentimentScore(text)` into the encrypted payload's
explicit mood-report field on **every** entry; mobile (`EntryScreen.tsx:322-328`) writes
only an explicit user pick and leaves it null otherwise; the backend engine explicitly
treats the field as the user's own report ("never a translation guess",
`backend/app/services/brain.py:272-278`), and therapists can read it via the portal.
Related: web mood-log/streak undercounts (records only on explicit tap; mobile records on
every save — `Entry.tsx:96-98` vs `EntryScreen.tsx:347`). Fix: pass `moodPick ?? null` into
`encryptEntry`; record `moodPick ?? sentiment` in the mood log like mobile.

### H-6. Backend: therapist note revisions bypass the chart storage quota — unbounded DB growth
`backend/app/api/therapist.py:1202-1234` (quota counts only live notes) vs `:1588-1595`,
`:1463-1470` (every edit inserts a full-blob `TherapistNoteRevision`, up to ~1.07 MiB, no
count/byte accounting, no pruning anywhere). An authenticated therapist looping PATCH with
distinct ~1 MiB blobs ≈ 7.7 GB/hour per source, forever — defeating the module's own stated
design goal ("a compromised clinician session cannot turn a patient relationship into an
unbounded database allocation"). Fix: count revision rows/bytes inside `_assert_note_quota`
(or per-note revision cap with oldest-eviction).

### H-7. Backend: `GET /therapist/patients` permanently 413s past 100 lifetime consent rows
`backend/app/api/therapist.py:669-690` counts **all** consent rows (active + revoked)
against `MAX_PATIENTS_PER_THERAPIST`, but the grant path caps ACTIVE only and consent rows
are only ever removed by account deletion. A therapist with 100 active + 1 revoked — or
101 historical patients with zero active — can never list their caseload again (the
portal's primary view). This is the therapist-side twin of the already-fixed patient-side
F-9. Fix: filter `status == "active"` for the cap; paginate revoked history separately.

---

## 2. MEDIUM findings

### Backend
- **M-B1. Verifier re-auth uses stale pre-rotation credentials; no `token_epoch` fence on
  verifier-gated routes** (`account.py:106-124`, `consents.py:273-326/480-576`,
  `therapist.py:429-564`). `_require_verifier` compares against the auth-time ORM object
  (`expire_on_commit=False`) and in-fence re-reads check only liveness — unlike
  entries/measures/recompute/rekey, which enforce epoch equality. An attacker with a phished
  verifier + bearer authenticated before the victim rotates or logs out can still complete a
  consent **grant** (journal exfiltration enablement), **LLM-consent enable** (plaintext
  egress), or **account deletion** after the recovery action committed.
- **M-B2. Caseload summaries written/served regardless of sharing-disclosure version**
  (`insights.py:1446-1452`, `therapist.py:727-753`): v1 consents receive summary metadata
  (pattern count, `sensitive` flag) the v1 disclosure copy never named, while measures are
  correctly gated (`therapist.py:866-870`). Compliance-level inconsistency; code-verified.
- **M-B3. Post-threshold daily questions are English-only; Spanish users get English
  templates with Spanish labels interpolated** (`services/questions.py:28-193`; clients
  localize only the baseline pool) — ES parity breaks exactly at the 30-day threshold.
- **M-B4. Spanish lexicon dead keys and value-divergent accented/folded twins**
  (`sentiment_lexicon_es.py:579,620,671,859,404,512`): `medía`, `razón`, `memoricé`,
  `quiénes` are unreachable post-fold; `hartó`/`harto` and `pérdida`/`perdida` carry
  different values — contradicting the fold-invariance claim at `brain.py:1750-1753`.

### Mobile (independent pass)
- **M-M1. Legacy-AAD fallback in `decryptEntry` lets a stale pre-v2 blob decrypt under any
  declared `contentVersion`** (`crypto/MindPatternCrypto.ts:126-134`): a compromised server
  can replay legacy blobs as "current" on fresh installs (no high-water mark to catch it).
  Gate the fallback on `contentVersion === 1` or retire it via an era marker.
- **M-M2. Offline-queue quarantine and rejected stores grow without bound; an oversize
  quarantine row wedges the whole scope** (`offlineQueue.ts:240,281-316`): no caps unlike
  the main queue; the catch-path `appendQuarantine` can itself throw, escaping `readItems`
  and rejecting every subsequent queue op for that scope.
- **M-M3. Two-writer conflict dialog interpolates both FULL decrypted entry texts (up to
  100k chars each) into an OS Alert** (`HistoryScreen.tsx:745-751`): OS truncates invisibly,
  so the user can approve the destructive overwrite while seeing only a fragment.
- **M-M4. All navigator screen titles + boot tagline are hardcoded English, bypassing i18n**
  (`navigation.tsx:78,162-207`) while `nav.*` keys exist in both catalogs — Spanish users
  get English headers on every main screen; the i18n test suite never checks navigator
  titles.
- **M-M5. `runRotate` has no `catch`** (`SettingsScreen.tsx:422-469`): unexpected throws
  become unhandled rejections with zero user feedback in the credential-rotation flow.

### Web (independent pass)
- **M-W1. Measures view wedges on "Loading…" forever for any non-network error** (`views/Measures.tsx:96-103`;
  only `status===0` handled — a 500/429/409 leaves `history === null` with no error/retry).
  The 2026-09-25 History fix was never applied here.
- **M-W2. No resume/idempotent-retry for `rekey_key_mismatch`; message factually wrong
  after a partial rotation** (`views/Settings.tsx:165-167`): web hard-fails claiming
  "NOTHING was changed", while mobile verifies-and-continues from the rewrap stage. A
  first attempt that died post-rekey dead-ends every retry.
- **M-W3. Account deletion leaves per-account data in IndexedDB** (`views/Settings.tsx:175-199`):
  no `clearQueue`, no `forgetAllEntryVersions`, no stateSeq cleanup — contradicting the
  W-6 "no per-account trace" comment two lines above and mobile's behavior (ciphertext
  only, so hygiene not confidentiality).
- **M-W4. Muted pattern IDs — journal-content-derived theme words — persist in plaintext
  localStorage** (`views/Patterns.tsx:71-93,184`): PIDs embed distress topics
  ("topic:divorce"); mobile keeps mutes in memory only. Move behind the encrypted kv seam.
- **M-W5. i18n: full en/es catalogs exist and pass parity tests, but almost all view copy
  is hardcoded English; prompt chips always English; generic-question pool is dead code on
  web** — a Spanish-locale user gets a mostly-English UI and **no daily question at all**
  during baseline/offline where mobile shows the localized one.
- **M-W6.** (part of H-4/H-5 cluster) mood log undercounts vs mobile — see H-5.

### Portal
- **M-P1. Sign-out / idle-lock / session-expiry never call `POST /auth/logout`** — the
  portal's `api` object has no logout method at all (`portal/src/api.ts:504-674`;
  `App.tsx:73` runs only `clearSession()`). The in-memory bearer stays server-valid up to
  the full 24 h TTL on a shared clinic machine. Both patient clients call it. Fix: best-effort
  `keepalive` logout before `clearSession()`.

### Infra
- **M-I1. Dependabot does not cover the `web/` npm workspace** (`.github/dependabot.yml:17-31`
  lists only `/mobile` and `/portal`) — the patient-facing web client gets no automated
  dependency PRs.
- **M-I2. No host-level monitoring**: no disk-full or TLS-cert-expiry alerts
  (`deploy/monitoring/alerts.yml`) — single-host clinical deployment takes silent
  availability hits.
- **M-I3. Containers have memory limits but no `cpus:` or `pids_limit` anywhere** —
  CPU-saturating paths degrade the co-located DB/backup on the shared host.

### Docs
- **M-D1. Web idle-lock documented as 10 minutes in README.md:308 and DPIA §7; code is
  5 minutes** (`web/src/sessionLock.ts:19`; the 10-minute lock belongs to the portal).
  Reality is stronger than the claim, but it's a security-control misstatement in the two
  most user-facing compliance docs.
- **M-D2. WEB_PLAN status dashboard contradicts shipped reality** (P7/P10 "not started"
  though shipped and E2E-verified 2026-09-26; P8/P9 rows absent; P9.10's promised
  sync-surface mutation campaign does not exist and is not registered as a deferral).

---

## 3. LOW / INFO findings (condensed; full detail in the per-pass reports above)

**Mobile**: `maxScoreForMeasure` prototype-chain leak (`"constructor"` → NaN score,
`measures.ts:124-127`); `request()` raw TypeError on corrupt persisted base URL
(`client.ts:463`); `exportAccount` not flagged `sensitive` (`client.ts:1038`); `clearQueue`
generation bump outside the storage mutex (`offlineQueue.ts:595-601`); dead
`biometricCapability()` probing a non-dependency; ambiguous Spanish conflict copy
("Su versión" for both sides); ES weekday grammar ("en lunes"); shared password state
between re-auth and rotation cards; measures cannot be recorded offline; ISO date in
filter line; UTC-sliced grant dates; never-clearing status line; draft re-stash on
same-tick unmount (needs verification); journaling **dates** plaintext in AsyncStorage
queue records; data key uploaded for processing sessions (at-rest, not E2E-vs-server —
documented); origin "pin" is first-seen phishing warning, not TLS cert pinning; decrypted
payloads cast without field validation; Android `versionName` 1.0 vs 1.0.0.

**Web**: `created_at` granularity drift vs mobile; measures pagination caps at 20 pages
with no terminal probe; LLM settings section silently disappears on fetch failure; dead
vars + missing zeroization in rotation; crisis prompt cadence per-draft vs mobile's
per-day; no-op kv enumeration assertion in redteam test; a11y tests cover only 7 of 12
views; no locale-flip consumption test (exactly how M-W5 went unnoticed);
`require-trusted-types` absent from CSP (no sinks today).

**Portal**: therapist insights `state_seq` rollback guard documented by the backend is not
consumed (backend comment even references a "portal stateSeqGuard" that doesn't exist);
measures traversal ignores `X-Measures-Revision` (can silently duplicate/skip rows);
portal EN-only while patients are bilingual; `style-src 'unsafe-inline'` (documented,
script-src strict); `dist/ coverage/ reports/` committed.

**Backend core**: `uv.lock` drifts from `requirements.in` (alembic 1.20.0 vs 1.19.2,
asyncpg 0.31.0 vs 0.30.0 — local dev validates versions prod never sees); token-secret
rotation silently locks out every TOTP therapist and shifts decoy salts (documented
residual, no runbook step); patient deletion cascades away therapist clinical notes
(medical-records retention vs GDPR Art. 17 trade-off — needs counsel); live SQLite DBs +
WAL remnants in `backend/` working dir (gitignored, never committed — verified against
full history); `max_body_bytes` lacks a direct ceiling; `LocalRecomputeRequest` blob
fields lack schema-level caps (route enforces); legacy unversioned `/api` mount doubles
the route surface (deprecated, rate-limit-shared); synthesized CORS lacks `Vary: Origin`.

**Backend API**: `X-Measures-Revision` / `X-Next-Cursor` missing from the CORS expose list
(browser clients can't read the pagination contracts); `create_note` holds its read
transaction while queued on the chart lock (pool pressure under contention);
`local_recompute` lacks the epoch re-auth `recompute` has; `/meta` unauthenticated and
unrate-limited; therapist account-delete missing `require_sharing_enabled`; patient
usernames exposed to therapists + cross-role username oracle; TOTP has no per-account
attempt ceiling; threshold backfill is effectively account-age-gated.

**Services**: temporal "time of day" tie-break iterates a `set()` → nondeterministic
across restarts (violates the module's absolute-determinism contract, `brain.py:2447-2450`);
residual exotic-homoglyph bypass family (`ʂuicide`, `ᵴuicide` — non-NFKC-foldable);
"English wins" lexicon merge dampens ES sentiment for 13 common words; ES negator "sin"
fires on English text; topic-miner candidate index over the whole corpus before the cap
(transient memory spike on adversarial input).

**Infra**: gitleaks allowlist exempts the *tracked, hand-written* `reports/` tree; no
secret-scanning pre-commit hook (detection post-push only); nginx rate-limit rejections
return 503 not 429 (pollutes the 5xx signal); unbounded tmpfs in the offsite overlay;
`.dockerignore` misses `.mypy_cache` (26 MB build-context bloat); DB password interpolated
raw into the SQLAlchemy URL (charset trap, documented); debug keystore tracked (AOSP
public credential, release-signing guard present — accepted); alert delivery example-only;
NEEDS VERIFICATION: branch protection on `main`; screenshot pixel content (provenance
verified synthetic).

**Shared/docs**: NFD combining form lost when the AAD edge-case vector was promoted into
`shared/vectors.json` (four-way CI gate no longer exercises decomposed input); README CI
job count stale (13 vs 14); local `redteam/results/*.json` stale relative to code (CI
immune — results gitignored); `run_all.sh` always exits 0 by design (gate parses JSONs);
feedback queue cap 100 (mobile) vs 64 (web); DPIA sub-processor wording could under-disclose
that **verbatim** journal text (bounded) is sent to the LLM with only *output* sanitized.

---

## 4. Verified-clean strengths (why the overall posture remains strong)

- **Crypto stack**: AES-256-GCM with random nonces and context/user/item AAD binding
  everywhere (byte-pinned across all four implementations); PBKDF2-SHA256 600k with 100k
  floor; HKDF subkey separation; scrypt N=2¹⁶ server-side; ECDH-P256+HKDF therapist wrap
  salted with both SPKIs; constant-time comparisons; keys memory-only and zeroized on every
  path incl. failures; pairing codes HMAC-only with TTL + single-use + rejection-sampled
  alphabet.
- **AuthN/AuthZ backend**: every route authenticated and role-gated; every patient-object
  query owner-scoped (**zero IDOR found across all 47 routes**); therapist reads
  consent-gated with flat-404 anti-enumeration under a verified deadlock-free lock order;
  opaque HMAC tokens with epoch kill-switch; login timing-parity + decoy salts;
  `extra="forbid"` on all 21 request models; 2 MiB body cap; request-smuggling and
  slowloris defenses; rate limits shared across both mounts.
- **Client hardening**: no `dangerouslySetInnerHTML`/`innerHTML` anywhere (pinned by
  tests, verified twice via corpus + real-DOM); bearer token memory-only; `credentials:
  "omit"`; `redirect: "error"` + origin re-check; strict CSP with SRI (recomputed and
  verified against `dist/` during this audit); crisis screen reachable from every nav
  state incl. boot and locked; crisis dialogs fire only after the entry is safely
  saved/queued; delete flows gated by typed-password re-auth in constant time.
- **Supply chain**: all 32 runtime packages hash-pinned; digest-pinned base and CI images;
  SHA-pinned actions; provenance attestation; `--require-hashes` builds; non-root uid;
  full-history gitleaks clean (**zero secrets ever committed across all 47 commits —
  verified**); no DBs/logs/binaries/venvs tracked.
- **Crisis normalization engine** (distinct from the H-1 *corpus* gap): the evasion
  hardening itself is exemplary — invisible chars, homoglyphs, leetspeak, split-word glue,
  letter-doubling, benign-compound masking — and defeated every practical bypass thrown at
  it (90 corpus rows + novel vectors + 3,000-case Unicode fuzz, zero exceptions).
- **Docs honesty**: SECURITY_RESIDUALS entries each correspond to real accepted behavior;
  claims-vs-reality spot-check went 20/25 MATCH with the 5 mismatches all reported above.

## 5. Red-team suite status (today)

10 harness result files, 106 verdicts, 0 ERROR, 9 FINDING — **exactly the 9 registered
residuals**, so the weekly gate passes: verifier replay (×2), LLM plaintext egress (×3),
mobile offline oracle, HTTP key shipment, `mobile/ios/.xcode.env` tracked, metadata
inference. Mutation campaigns' REPORT.md numbers match their machine-generated result
files exactly.

## 6. Prioritized remediation order

1. **H-1** crisis corpus (EN + ES) — user-harm path, small diff, corpus-level fix.
2. **H-2/H-3** mobile device boot/rotation — verify on a device build, then install
   quick-crypto/buffer in `index.js` + use `engine.randomBytes` in `freshSalt`; commit
   babel/metro configs.
3. **H-4/H-5** web rotation lockdown + sentiment semantics — data-loss and
   clinical-data-semantics fixes.
4. **H-7** therapist caseload 413 (active-only filter) and **H-6** note-revision quota.
5. **M-B1** verifier epoch fence; **M-P1** portal logout; **M-I1** dependabot `/web`.
6. Remaining MEDIUMs by area; LOWs opportunistically.

*Audit was strictly read-only: `git status --porcelain` clean before and after; no files
modified, created (other than this report), or deleted.*

---

## 7. Remediation status — 2026-09-26 (same day)

Every actionable finding above was fixed and re-tested after this report was filed.
Each fix carries an inline `2026-09-26 audit <ID>` annotation and new test coverage.
Change surface: 134 files, +5,576/−1,184 lines.

| Finding | Status |
|---|---|
| H-1 crisis corpus | **FIXED** — 22 dialog + 4 suppress patterns (EN + ES), 4-copy lockstep, corpus 90→119 rows all want==observed, per-pattern samples (78/23) |
| H-2 rotation CSPRNG | **FIXED** — engine.randomBytes inside guarded block; works with globalThis.crypto deleted (pinned) |
| H-3 Buffer bootstrap | **FIXED** — QuickCrypto.install() first in index.js; babel/metro configs added (.cjs) |
| H-4 web rotation loss | **FIXED** — F-4 lockdown + rekey-mismatch resume ladder + zeroization ported |
| H-5 sentiment semantics | **FIXED** — payload carries explicit pick only; mood log pick??estimate; calendar pick-first |
| H-6 note quota bypass | **FIXED** — revisions counted + per-note cap with oldest-eviction |
| H-7 caseload 413 | **FIXED** — active-only cap |
| M-B1..M-B4 | **FIXED** — verifier epoch fences; disclosure-gated summaries; ES post-threshold questions; ES lexicon fold invariance |
| M-M1..M-M5 | **FIXED** — v1-gated AAD fallback; bounded quarantine; conflict snippets; i18n navigator titles; rotation catch |
| M-W1..M-W5 | **FIXED** — terminal errors; rotation resume; deletion wipe; encrypted mutes; full bilingual UI + locale-flip test |
| M-P1 + portal LOWs | **FIXED** — server-side logout on all four lock paths; state_seq guard; measures revision contract |
| M-I1..M-I3, M-D1/M-D2 | **FIXED** — dependabot /web; optional disk/cert monitoring (digest-pinned, verify.sh-grounded); cpus/pids limits; doc corrections + deferral registered |
| LOW/INFO batch | **FIXED** per §3 (code items); retained by design: server-trust model (documented), origin-pin-not-cert-pinning (documented residual), portal EN-only (documented decision), notes-retention trade-off (documented residual flagged for counsel) |

**L-3 follow-through:** the language-gated Spanish scoring was additionally mirrored
on-device (dump emits `sentiment_lexicon_es`/`negators_en`/detection tables to shared +
both clients; client engines default byte-identical; `brainLanguage` parity pins added).

**Verification (all run post-fix):** backend `pytest` 1464 passed / 1 skipped, coverage
97.35% (floor 97), ruff + mypy clean; mobile vitest 1706 passed / 1 skipped + tsc clean;
web vitest 437 passed / 5 skipped + tsc clean; portal vitest 336 passed + tsc clean +
coverage gates exceeded; redteam `e_crisis.py` 0 harness errors; `deploy/monitoring/
verify.sh` (incl. `--production`) all checks passed; gitleaks full-history + working-tree
clean with a canary proving hand-written `reports/` source is scanned again.

**Deferred / accepted (documented, not code):** H-3 device-build confirmation needs a
native toolchain run (bootstrap + configs verified loadable under node); P9.10
sync-surface mutation campaign registered as a tracked deferral in SECURITY_RESIDUALS;
portal build-artifact directories were confirmed untracked (nothing to untrack).
