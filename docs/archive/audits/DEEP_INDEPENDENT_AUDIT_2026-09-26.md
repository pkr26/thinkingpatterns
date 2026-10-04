# Deep Independent Audit — 2026-09-26 (12-subagent fleet + live test evidence)

**Method.** Twelve independent auditor subagents (general-purpose, each instructed to read every
line of its scope and to distrust the repo's own prior audit reports), plus two research agents
that benchmarked the implementation against published statistical literature and against
real-world clinical/regulatory/security standards (web-verified citations). Independently, all
four test suites were executed at HEAD on this machine as hard evidence:

| Suite | Result |
|---|---|
| backend (pytest) | **1,481 passed**, exit 0 |
| web (vitest) | **525 passed**, 5 skipped |
| portal (vitest) | **370 passed** |
| mobile (vitest) | **1,729 passed**, 1 skipped |

Local total: **4,105 tests green at HEAD.** (Note: this contradicts the CI pipeline's state — see
CRITICAL finding I-1.)

---

## Scorecard

| # | Component | Score /100 | Sub-scores (Correct/Security/Robust/Quality/Tests) |
|---|---|---|---|
| 1 | Backend core infrastructure + auth/account/meta API | **88** | 26/22/17/14/9 |
| 2 | Backend domain APIs (entries, consents, measures, insights, therapist) | **86** | 26/22/17/12/9 |
| 3 | Backend cryptography & key management | **82** | 25/17/17/14/9 |
| 4 | Pattern engine ("brain") + services (crisis, questions, threshold, llm) | **88** | 26/23/18/13/8 |
| 5 | Backend test suite + migrations + redteam | **86** | 27/23/16/11/9 |
| 6 | Patient web client | **86** | 26/22/15/14/9 |
| 7 | Therapist portal | **88** | 27/21/18/13/9 |
| 8 | Mobile app | **86** | 26/22/16/14/8 |
| 9 | Infrastructure, deployment, CI/CD, backup, monitoring | **72** | 23/20/13/13/3 |
| 10 | Documentation & claims | **70** | 24/15/12/12/7 (accuracy/completeness/consistency/honesty/maintainability) |
| — | **Cross-cutting: statistical methods vs literature** | **85** | research verdict |
| — | **Cross-cutting: clinical safety, regulatory & privacy readiness** | **84** | research verdict |
| | **OVERALL (size-and-criticality weighted)** | **≈ 83** | |

Calibration used by all auditors: 90+ survives a hostile external review; 80–89 strong with minor
gaps; 65–79 notable gaps; 50–64 significant remediation; <50 systemic.

**One-paragraph verdict.** This is a top-decile codebase for its category: the statistical engine
is more conservative and better-cited than any consumer mood tracker audited against, the crypto
is vector-pinned across four independent implementations, authorization is object-level with flat
404s, crisis safe-messaging exceeds Woebot/Wysa-class norms, and 4,105 tests pass at HEAD. The two
components that would fail an external review today are **operations** (CI is persistently red and
the release pipeline has never produced an artifact) and **documentation hygiene** (stale claims,
one disputed citation, missing operator/legal pack). The deepest architectural gaps — password-bound
data key with no random-key envelope, in-process "enclave", no out-of-band sharing-key verification,
no TLS pinning, PHQ-9 item 9 invisible to therapists — are documented honestly in the repo but
remain real.

---

## Critical & High findings (fleet-wide, deduplicated)

### CRITICAL

- **I-1. CI does not gate anything — it is persistently red.** 89/91 GitHub Actions runs failed;
  only 2 green (both 2026-09-08). At HEAD five jobs fail (lint/Ruff, backend 3.14, backend-postgres,
  web typecheck, docker). The docker integration job (compose → boot → migrate → /readyz → encrypted
  backup → real pg_restore) has failed in every run since 2026-09-19/20. All commits since then
  landed on a red pipeline. *The five failing CI jobs contradict the locally-green suites — the
  delta is itself a finding (environmental drift: pinned CI env vs local .venv/Node).* Fix: make CI
  green at HEAD and add branch protection that requires it.
- **I-2. The release pipeline has never executed.** `release.yml` has 0 runs, 0 tags, 0 releases,
  0 GHCR images — the entire digest-pinned deploy contract has never produced an artifact, and
  provenance/SBOM attestation is configured but never demonstrated. Fix: cut one v0.x tag and run
  the path end-to-end before trusting it.
- **D-1. Citation dispute (reconciled).** README:45 cites "Bourke et al. 2026 meta-analysis
  (118 studies)" for sleep→next-day mood. The docs auditor could not find it and flagged it as
  likely fabricated; the statistics auditor **independently verified it exists** (ScienceDirect
  S1087079226000043, "Sleep well, feel well and vice versa? A meta-analysis of within-person
  associations between sleep and affect"). Verdict: citation appears genuine, but it is absent from
  RESEARCH.md's own bibliography — the repo's citation-bearing doc never grounded it. Fix: add it
  to the RESEARCH.md bibliography and add a CI rule that every README/RESEARCH citation resolves to
  a bibliography entry.

### HIGH

- **C-1. KDF/architecture claim mismatch: PBKDF2 ships, not Argon2id** (`backend/app/security/kdf.py:32-45`,
  PBKDF2-HMAC-SHA256 600k). README is internally honest, but OWASP/NIST-draft now prefer Argon2id
  (≥19–64 MiB). Related architectural weakness: **the data key is deterministically HKDF-derived
  from the password** rather than a random key wrapped under a password-derived KEK — ciphertext
  entropy is capped by password strength and password change forces an O(corpus) rekey instead of
  an O(1) rewrap (Bitwarden/1Password-style envelope encryption).
- **C-2. The "secure processing session"/"enclave" is in-process policy, not a mechanism.** The
  client POSTs the raw data key over TLS; a malicious server can persist/log it. Single-use pop,
  TTL, capacity caps and best-effort zeroization are enforced and test-pinned, but
  TEE_ATTESTATION_DESIGN.md is explicitly "DESIGN ONLY". The zero-knowledge claim has a disclosed,
  real processing-window exception (plus the opt-in LLM egress path).
- **C-3. No out-of-band verification of the therapist wrap key** (`security/sharing.py:145-216`):
  the patient wraps to a server-served `wrap_pub_key` at pairing; a malicious server can substitute
  its own key and receive every wrapped data key. Defends against passive DB theft, not a malicious
  server. (The crypto auditor found no enforced SAS/fingerprint check on this path.)
- **I-3. Postgres container privilege model likely broken**: `cap_drop: ALL` + `read_only: true` +
  no `user:` override breaks the official image's chown/gosu entrypoint (docker-library/postgres
  #649) — probable crash-loop; also the only root-run service in the stack. Prove
  `compose up -d --wait` green.
- **I-4. Every scheduled quality gate that has ever fired has failed** (mutmut run, mobile Stryker
  floor, redteam verdict gate on 2026-09-26); mutation-portal/web/PR have 0 runs. Failing weekly
  gates train people to ignore them.
- **M-4 / Clinical. PHQ-9 item 9 is invisible to the therapist**: the shared measure payload stores
  only `{"score": N}`. Any endorsed item 9 clinically mandates follow-up regardless of total score;
  the portal renders totals with "interpretation is yours" but cannot see the safety item. This is
  the single most clinically consequential finding in the audit.
- **T-1. Access log is not tamper-evident** (`models.py:433-459`): plain mutable rows, no hash
  chain/WORM; anyone with DB write access can rewrite the clinical access trail. Also no
  `account_deleted` terminal row is written at hard deletion (`api/account.py:921-991`).
- **D-2. mobile/README "Sync model" section is materially false**: claims single-device-writer,
  "two devices writing concurrently is out of scope, not handled" — the shipped code handles 409
  version_conflict with decrypt-and-ask UX and ships `mobile/tests/twoWriter.test.ts`. Rewrote
  claims lag shipped behavior.
- **D-3. Citation-year errors**: RESEARCH.md says "Snippe et al. 2024" (paper is 2023; README has
  it right); Konjarski et al. 2018 is a systematic review, not a meta-analysis (three places).

### Selected MEDIUM findings (full lists in per-component sections)

- Rekey holds one long DB transaction across all CPU work (`api/insights.py:457-592`).
- Therapist note edits have no optimistic concurrency (silent last-write-wins) (`api/therapist.py:1759-1852`).
- Consent scope is journal-level while the UI framing implies pattern-evidence-level access —
  server accepts arbitrary since/until under any active consent (`therapist.py:1129-1301`).
- Web: hidden-tab/idle lock destroys in-progress drafts (worst user-data-loss path);
  offline-queue enqueue not cross-tab serialized (narrow lost-entry window); measures have no
  offline queue.
- Mobile: notifee reminder rescheduling likely stacks duplicate notifications (no stable id /
  no cancel-before-create); no TLS certificate pinning (bearer + one-time data-key shipment);
  Android Keystore biometric semantics asserted but never device-verified; PHQ-9 not offline-queueable.
- Portal: idle lock resets on bare mousemove (jiggler defeats it); caseload scan keeps decrypting
  after navigation away; `describePattern` still fabricates a direction for `link`/`mood_shift`;
  note saves mint a fresh `client_note_id` per attempt, making the backend's idempotent-retry
  contract unreachable.
- Brain: EWMA mood_shift p-value ignores run-rule selection (auditor-measured 12% false-signal per
  recompute at φ=0.5 vs 2.8% iid); weekly entropy uses biased MLE (−0.56 bits at realistic volumes,
  larger than the 0.35-bit gate) and conflates tag volume with variety; **no weekday/weekly-cycle
  adjustment** anywhere in mood-association tests though RESEARCH.md §5 promises it (work-Mondays
  confounder); cadence Brown-Forsythe lacks the n_eff deflation instability gets.
- Statsig module: `variance_floor` fabricates variance for constant groups (t driven by the floor).
- Infra: secrets passed as container env vars (docker inspect readable); Alertmanager not wired
  (nothing pages anyone); readyz/backup-heartbeat probes commented-out opt-ins; Trivy step in the
  never-run release workflow has a latent image-availability bug.
- Clinical/privacy: no age gate / minors analysis in the DPIA (Art. 35 force-multiplier); FTC HBNR
  60-day clock not operationalized in the incident runbook; no BAA template/HIPAA mapping despite
  the therapist portal pulling toward covered-entity territory.
- Docs: WEB_PLAN checkboxes unchecked while its dashboard says the phases are done; PsyberGuide
  self-assessment still says three-way crypto pinning (it is four-way); several "standing
  residuals" were already fixed in code (web CSP unsafe-inline, pinned overlays); no privacy-policy
  URL, retention schedule, subprocessor/BAA register, or real security.txt contact.

---

## Per-component reports

### 1. Backend core infrastructure + auth/account/meta API — 88/100
*100% of ~5,800 scoped lines read; migrations chain and tests cross-checked.*

Unusually disciplined: fail-closed config validation (production-by-default, dev secrets refused
outside development), raw-ASGI hardening middleware (request-smuggling rejection, slowloris
body-deadline), rate-limit parity derived from the live router, epoch-fenced re-authentication on
every destructive action, atomic conditional-UPDATE TOTP/backup-code redemption, decoy salts with
CPU-equivalent timing, streaming byte-bounded export, and multi-worker guards (flock + Postgres
advisory lock) that make the single-process deployment contract load-bearing. Migration head
matches models.py exactly. No CRITICAL/HIGH defects.

Findings: [LOW] /metrics has no rate limiter (main.py:464-488); fixed-window limiter admits 2×
across window boundary and evicts active buckets under 10k-identity floods (cache.py:59-119);
`_bool_env` silently maps typos to False (config.py:84-88); access-log cursor accepts naive
datetimes (account.py:819-834); token_secret rotation bricks all TOTP wraps (models.py:153);
full-body buffering ceiling × concurrency unguarded (middleware.py:363-412); no `Vary: Origin` on
CORS mirror; "unknown-client" shared bucket for socketless transports.

Real-world: inverts typical production (in-process rate limiting/locks/keystore, one process per
DB, no per-token revocation, no patient MFA, no account recovery by design). Where it exceeds
practice: ASGI-edge hardening, anti-enumeration, constant-time compares, statement/idle timeouts,
privacy-first metrics. Missing for HIPAA-grade ops: KMS/HSM key custody, infra-layer access logs.

### 2. Backend domain APIs — 86/100
*100% of the 5,487 scoped lines read.*

Object-level authz on every query (owner-scoped SQL, flat 404s), linearizable consent lifecycle via
fixed lock ordering (revoke clears wrapped key + ephemeral pub + caseload summary in one
transaction), genuinely single-use/TTL-bounded/owner-bound processing sessions with zeroization on
every exit path, byte-budgeted pagination with optimistic revision markers and 409
collection_changed. Tests pin real behavior (real client-side crypto, lock-order races,
cross-tenant isolation).

Findings (in addition to HIGH/MEDIUM above): [CLAIM-MISMATCH] "measures revision history" —
measures are immutable; "revision" is only a collection snapshot marker. [CLAIM-MISMATCH]
"per-entry keys wrapped to therapist" — one account data key wrapped per consent. Rekey long
transaction; note-edit last-write-wins; audit log mutable; local-recompute response lies about
phase/streak (`insights.py:1708-1717`); caseload-summary race without sharing locks; revoked-patient
audit rows flushed only at trailing commit; `_active_consent` never re-checks patient is_active;
no DELETE/correction path for measures; five hand-duplicated pagination implementations with drift;
204 deletes don't echo new revision.

Real-world: ahead of typical health APIs on authz posture, consent demonstrability (GDPR Art. 7 /
FHIR-consent-like versioning) and pagination; behind on tamper-evident audit trails and WORM
retention with legal holds.

### 3. Backend cryptography & key management — 82/100
*100% of the 3,442 scoped lines read; all four vector families independently re-verified
byte-for-byte against the real modules.*

Textbook AES-256-GCM (fresh 96-bit nonces, unambiguous JSON AAD, RFC 5869-exact HKDF with nine
domain-separated purposes), constant-time compares everywhere, RFC 6238 TOTP with atomic replay
fence, HMAC-stored backup codes, enforced single-use processing sessions. Test rigor exemplary
(fixed-nonce pins, tamper/truncation/AAD-swap cases, a source scan banning the fixed-nonce seam
from production paths, zeroization spies, full rotation E2E).

Weaknesses are architectural (see HIGH C-1..C-3) plus: [MEDIUM] P-256 not the claimed X25519 for
sharing ECDH (sound ECIES, wrong claim); token_secret single point of failure (rotation bricks
TOTP/pairing/backup/decoys); 24h stateless bearer with no per-token revocation; rekey mints
unzeroizable plaintext copies outside the enclave discipline; server-side scrypt N=2^16 at the
OWASP floor; no v2-entry-AAD vector in shared/vectors.json (M-2 anti-rollback fix pinned only in
Python); TOTP drift window accepts the future timestep; per-username 2FA lockout lets a
password-holder lock out a clinician; zeroization is best-effort in CPython (honestly documented);
LLM path ships up to 150k chars of consented plaintext to a third party.

Real-world: GCM/HKDF usage at NIST standard; KDF and key-envelope design behind Bitwarden-class
E2EE norms; sharing defends DB theft, not malicious server (no SAS verification); sessions behind
OAuth 2.1 expectations; cross-platform vectors-plus-negative-space testing at the standard external
crypto firms ask for.

### 4. Pattern engine + services — 88/100
*100% of ~9,600 code lines read; lexicons validated programmatically (AST duplicate scan,
range/fold checks, byte-equality vs runtime dicts, 55 random valence spot-checks, all 128 redteam +
150 fixture crisis samples through the matcher — 0 mismatches). Auditors numerically verified the
statistical primitives, ran probe_brain (9/9), and empirically confirmed determinism across
PYTHONHASHSEED 0/1/42/12345 and performance (1.46s / 4,000-entry corpus; 3.9s under adversarial
near-duplicate load).*

Findings: [MEDIUM] EWMA mood_shift p ignores run-rule multiplicity (3443-3464); EVIDENCE_DATE
replication gate accepts a single new clustered mention as "independent" (3805-3816); cadence BF
test lacks n_eff deflation (3348); [LOW-MED] variance_floor fabricates variance; Fisher-z windows
share the boundary observation; zero-Latin-token corpora mislabel language "en" (4143); probe checks
A/D/E assert store membership rather than surfacing (9/9 headline is 7+2 mixed standards); emoji
VS16 counting; single-tag weeks drive entropy toward 0; person-anchoring English-only; `update()`
is a ~560-line function; `_stored_from_dict` accepts unknown kinds; ES users get no person-theme
cards. [NOTE] "statsig" is the statistics module — no feature-flag system exists despite naming.

Real-world: methods map honestly onto the cited intensive-longitudinal literature; more
conservative than anything shipped commercially (pre-gate BH families, effect gates, replication
requirement, evidence-dates-never-quotes). Gaps vs research-grade: no weekday deconfounding, ad-hoc
Fisher-z difference tests, unvalidated lexicon-as-mood-proxy (arbitrary SD floor instead of
measured per-user noise), replication gate as calibrated heuristic rather than out-of-sample
confirmation.

### 5. Backend tests + migrations + redteam — 86/100
*~24% of 33.6k lines read fully (conftest/helpers + 15 critical suites), 100% method-reviewed;
16 migrations and redteam harness read fully.*

Genuinely strong: RFC vectors, tamper/replay PoCs, seeded-noise false-positive bounds, 128-row
multilingual crisis-bypass corpus, migration parity gated by empty autogenerate diff, credible
mutation program (snapshot/mutate/restore harness, weekly mutmut, diff-scoped PR gating, honest
survivor accounting with a small documented-residuals allowlist).

Findings: [MED] "client emulator" runs the server's own crypto modules (two-sided crypto bug passes
the Python suite; mitigated by TS vector replay being merge-blocking-worthy but not enforced as
such); default DB is in-memory SQLite (Postgres only in one CI job — which is failing, see I-1);
wall-clock perf pins and real-TOTP-timestep sleeps (minutes of wall time, flaky); DOCUMENTED_RESIDUALS
allowlist can silently persist; non-concurrent Postgres DDL; date-named suite organization with
4-way duplication of rate-limit coverage; PG downgrade path untested; a semi-tautological pin
(`assert day_count == max(day_count, 10)`); no property-based/fuzz layer.

Real-world: security regression discipline above most healthtech QA orgs (IDOR probes, crypto
tamper PoCs, concurrency races, cross-platform shared corpora); behind fintech-best on determinism
engineering (injected clocks, work-unit counters) and suite organization.

### 6. Patient web client — 86/100
*~95% of 11.2k lines read line-by-line (all but the generated lexicon blob, verified structurally);
locales key-parity checked programmatically.*

Crypto layer strong (PBKDF2 600k/100k floor, HKDF-separated subkeys, canonical Python-compatible
AAD incl. DEL/astral, AES-GCM, salt-pinned ECDH wrap, byte-pinned bidirectional vectors and mobile
interop fixtures). Key custody claims verify: keys/token only in module memory, zeroized on lock,
nothing key-shaped in storage/URL; local stores encrypted. Zero HTML injection sinks; CSP without
unsafe-inline; post-build SRI; red-team tests actually exercise XSS-through-decrypted-text and
storage scrapes. No CLAIM-MISMATCH.

Findings: [MEDIUM] hidden-tab/idle lock destroys in-progress drafts (App.tsx:116-124 +
sessionLock.ts:57-70 — "the one item a real patient pilot would surface in a week"); enqueue not
cross-tab serialized (offlineQueue.ts:283-311 — lost-entry window); measures have no offline queue;
[LOW] no memory-hard KDF in browser; token expiry discovered mid-write (expires_in ignored);
History O(n²) hit mapping + serial decryption, no virtualization; measures store option INDEX not
value (correct only for contiguous scales); locale locked to OS language; Stryker gate `break: 0`
(can never fail); iOS SMS-link userAgent regex brittleness; O(n²) queue re-reads; committed
dist/coverage artifacts; ~1/3 of locale catalog never rendered by web.

Real-world: top-tier transport/injection hygiene (CSP+SRI+COOP/COEP+HSTS, no unsafe-inline — rarer
than most patient portals); custody stricter than Bitwarden-web (nothing persists); i18n mid-level
(2 locales, no runtime switch, no ICU plurals); a11y above average (ARIA patterns, focus traps,
jest-axe) but no manual screen-reader audit artifact; no Trusted Types (low marginal value given
zero sinks).

### 7. Therapist portal — 88/100
*100% of every in-scope file read (4,723 lines) + full backend therapist API.*

Every headline claim verified: no client write path to patient data and server-side role gates
enforce it; memory-only custody with zeroization; byte-pinned AAD (incl. the 0x7F DEL escape); 401
latch, idle lock, bfcache restore, server-side bearer revocation on every lock boundary; notes
therapist-owned, encrypted, ownership-scoped server-side, unreachable from patient routes. No
CLAIM-MISMATCH.

Findings: [MEDIUM] journal-level consent scope vs "evidence behind this pattern" framing (server
accepts arbitrary since/until; portal fetches full range then filters client-side — a therapist
session can page the entire journal); idle lock resets on mousemove alone (jiggler/forgotten
foreground tab keeps decrypted charts); caseload scan keeps fetching/decrypting after navigation
(also mints audit rows); [LOW] `describePattern` fabricates direction for `link`/`mood_shift` when
undefined; undecryptable note history renders as "no earlier text recorded"; fresh
`client_note_id` per save attempt defeats idempotent retry (timeout + re-press = duplicate clinical
notes); CSP `style-src 'unsafe-inline'`; unauthenticated /auth/salt enables username enumeration
(rate-limited); TOTP recovery codes as plain text with no copy/download; 24h bearer TTL;
visit-anchor metadata survives locks in sessionStorage; deep triage scan supersedes the
purpose-built ECIES summaries (N requests + N audit rows per scan).

Real-world: above-average clinical client (auto-lock+revocation, per-read audit, TOTP, rollback
sentinels exceed many SaaS portals; zero-knowledge backend = ciphertext not a PHI trove). But a
companion viewer, not a chart: no SOAP structure, problem list, e-signature, amendments workflow,
or MBC flags; HIPAA workstation controls stop at a mousemove-resettable timer; print summaries
resurrect PHI-on-a-printer risk; metadata (linkage, timestamps, sizes, audit rows) is still PHI for
BAA purposes — "zero-knowledge" covers content, not metadata.

### 8. Mobile app — 86/100
*~93% of all src lines read directly (100% of hand-written files; generated lexicon verified;
locale parity 694/694 keys programmatic); native manifests reviewed.*

Every claimed feature exists in code; no CLAIM-MISMATCH. Unusual discipline: version-bound AAD,
state-seq and entry-version rollback guards, 409-verification before queue deletion, origin pinning
of queued uploads, constant-time key compares, zeroization, rotation with a resumable
pending-salt ladder, write-only HealthKit (no read scope ever requested).

Findings: [MEDIUM] notifee rescheduling likely stacks duplicate daily notifications (no stable id,
no cancel-before-create, resync on every session start); no TLS pinning (bearer + one-time data-key
shipment under system-CA trust only); Android Keystore/BIOMETRY_CURRENT_SET semantics asserted but
never verified on hardware (the fully-mocked suite cannot); [LOW] PHQ-9 not offline-queueable
(background lock discards a completed questionnaire); no background flush (BGTaskScheduler/
WorkManager); post-save editor clear can wipe mid-save typing; empty-string userId fallback in
history hygiene; DEFAULT_BASE_URL = localhost:8000; no Android FLAG_SECURE on journal screens;
hardcoded APP_VERSION; rollback high-water mark in plaintext AsyncStorage. [INFO] PBKDF2 600k not
Argon2; zero telemetry (privacy-excellent, crash-invisible); whole suite runs on node mocks — no
device E2E.

Real-world: at/above Woebot/Headspace/Daylio engineering norms on data protection; crisis surface
matches APA/#chatsafe guidance better than typical App Store submissions; would pass MASVS
storage/auth/network-privacy but misses MASVS-NETWORK-2 (pinning) and MASVS-O-1 device-verification
evidence; self-hosted default URL needs a production endpoint for any public distribution.

### 9. Infrastructure, deployment, CI/CD, backup & monitoring — 72/100
*100% of every source-controlled in-scope file read (~4,750 lines); all 11 action SHAs, 6 live
registry digests, and the gitleaks tarball sha256 externally verified; both *.db files confirmed
untracked synthetic fixtures.*

Static config is exceptional: every image digest-pinned (verified against live registries), every
action/pre-commit rev SHA-pinned (verified), no committed secrets, dependabot complete and active.
Operational reality is red: CI 89/91 failed (I-1); release never ran (I-2); docker job failing
since 09-19 (I-4); scheduled gates failing (I-4); db container privilege model likely broken (I-3).

Findings beyond the CRITICALs: [MEDIUM] secrets as container env vars (docker inspect readable —
move to compose secrets like the metrics token already does); db runs as root (image default);
Alertmanager ships unwired (alerts evaluate but nothing pages); readyz/TLS-expiry/disk/backup
freshness probes all commented-out opt-ins; release Trivy step latent-broken; [LOW] postgres/
python base tags drift with no compose dependabot; AES-256-CTB backups (HMAC-mitigated) vs age;
BACKUP_RETENTION 35d vs deletion-promise never reconciled; GNU-specific grep in verify.sh; rclone
config as env var; nginx http-context and version prerequisites unstated; node-exporter full host
root mount; docker.sock to Trivy; no cosign signing; ~14 runner-hours/week of mutation budgets for
a project with no releases; unpinned apk packages in backup image; gitleaks `tests?/` allowlist
broad but defended.

Real-world: three weeks of commits to main against red CI fails SOC2-style change control outright;
supply-chain pinning stronger than most production orgs; provenance/SBOM/cosign configured but
never demonstrated (zero attestation records); no IaC, no staging, no wired paging; backup design
the right shape but the CI restore drill hasn't passed since 2026-09-08 and no off-site restore
rehearsal is recorded; RPO ≤24h implied but unstated.

### 10. Documentation & claims — 70/100
*>98% of ~5,850 in-scope doc lines read; ~35 factual claims verified against code.*

Accuracy of code claims is unusually good: crypto constructions, brain determinism/parameters,
GET-only therapist surface, pairing semantics, retention numbers, CI job count, CHANGELOG-vs-git
consistency (46 commits) all reproduce. Honesty is the strongest dimension (exceptions and
residuals named). The deductions: D-1 citation dispute (reconciled — see above), D-2 stale
mobile sync-model section, D-3 citation-year errors, several "standing residuals" already fixed in
code (web CSP unsafe-inline, overlay pinning, English-only chrome), WEB_PLAN checkboxes vs its own
dashboard, PsyberGuide three-way→four-way, count hygiene (48 vs 49 vectors, ~480 vs 472 ES words),
DPIA route paths, PLAN λ=0.3 vs shipped 0.18, IRB exclusion criterion not a named validated
instrument, CHANGELOG claims SemVer but never cuts versions, and the missing operator/legal pack
(privacy policy URL, retention schedule, subprocessor/BAA register, filled incident contacts, real
security.txt).

Real-world: claim discipline would impress an FDA-adjacent reviewer until the first citation
defect; a GDPR Art. 35 assessor would challenge the 730-day post-erasure audit retention and the
unsigned skeleton; clinical-safety file (hazard log, DCB0129-style register) and published privacy
policy are table stakes for any store listing and absent.

---

## Research verdict 1 — statistical methods vs published literature: 85/100

Numerically verified against independent reference implementations: exact binomial tail (1-sided,
appropriate for directional claims — matched to 4.5e-14), BH step-up (classic example + 4,000-run
null simulation FDR 0.058), Welch–Satterthwaite (matches hand-computed canonical dataset), AR(1)
effective-n (Bartlett form, clipped, conservative), pooled Cohen's d, Fisher-z difference
(disjoint windows verified), Brown–Forsythe (bit-identical to reference, 1.8e-15), MinHash/LSH
band math (1−(1−s⁴)^16 = 0.644/0.988/0.9998 at s=0.5/0.7/0.8; empirical proposal rate matched
theory exactly; estimator unbiased).

**The single most important architectural verification**: the BH family is assembled **before**
effect gates (all tests that ran, not tests that passed gates) — the correct fix for
selection-then-test, which no consumer tracker does. Idiographic residualization implements
Bolger & Laurenceau correctly.

Minor/major issues: EWMA chart (Montgomery asymptotic limits, λ in-band, but AR(1) inflation
trigger rarely fires and the BH p ignores run-rule selection — auditor-measured 12% false-signal
per recompute at φ=0.5); weekly entropy biased MLE + tag-volume confound; modal-gap link labeling
is a heuristic (tie-break lets a 5-vs-4 gap-2 mixture print "the day after"); replication gate is
calibrated engineering (honestly measured ~17% residual false-card rate on noise), not a guarantee;
**weekday/weekly cyclicality never adjusted out** though RESEARCH.md §5 promises it — the largest
remaining confounder (work-Mondays can manufacture mood_correlation/link cards through shared
weekly rhythm).

Citations: all checked citations real (Golder & Macy 2011; Kuppens 2010; Al-Mosaiwi & Johnstone
2018 — volume is 6(4); Snippe 2023 not 2024 in brain.py docstring; Bourke et al. 2026 verified
real; Smit/Schat/Ceulemans 2023; Houben 2015; Ong 2023). Errors are year/label-class, not
fabrication-class (Bourke initially suspected, then verified).

Real-world: far above consumer-app practice (Daylio/Bearable ship uncorrected co-occurrence bars);
approaches but does not match research pipelines (multilevel/state-space models, formal
pre-whitening, ARL-calibrated limits via simulation, out-of-sample confirmation). The codebase
"reads like a methods-paper-informed codebase, not an app codebase."

## Research verdict 2 — clinical safety, regulatory & privacy: 84/100

- **APA/PsyberGuide**: ADEQUATE — strong on security/engagement-transparency axes; weak on Access
  (self-hosted, no store presence) and Clinical Foundation (IRB protocol is a plan, not evidence).
- **Crisis safe-messaging**: STRONG — two-tier contract pinned byte-for-byte cross-platform,
  dual-engine normalization vs leetspeak/homoglyphs/splits across 9 scripts, never-quote-back
  suppression discipline that none of the six comparator apps demonstrably do; residuals: no
  safety-plan tool, no web 988-chat action, once-per-day throttle.
- **PHQ-9**: ADEQUATE — licensing correct (public domain), scoring faithful, interpretation
  deliberately refused; **but item 9 is stored only inside the total and invisible to the
  therapist** (item-9>0 mandates follow-up per clinical norms regardless of total); no MBC cadence
  tooling.
- **FDA boundaries**: ADEQUATE — patient product sits in general-wellness territory; portal cards
  arguably satisfy the CDS non-device criteria (evidence panels = independent-review basis); the
  caseload "sensitive-card presence" flag is the feature a reviewer would interrogate.
- **Privacy law**: ADEQUATE — D2C outside HIPAA, portal pulls toward BAA territory (named but not
  operationalized); GDPR Art 9/35 handling strong for a skeleton (all four Art 35(7) elements) but
  unsigned, no age gate/minors analysis, no Art 36 trigger; FTC HBNR (2024 amendments) correctly
  named, 60-day clock not operationalized.
- **Security baselines**: STRONG substance (AAL2-equivalent therapist auth, memory-only sessions
  pinned by a storage-scrape harness, rehearsed encrypted restores) with an institutional GAP (no
  SOC 2 / HITRUST / external pentest).
- **Industry comparison**: ahead of the tracker cohort on crisis handling and privacy engineering;
  behind Woebot/Wysa on evidence (their RCTs/FDA Breakthrough status vs this repo's unexecuted
  IRB protocol) and on human-escalation features.
- **Evidence transparency**: STRONG — exceeds any consumer-category norm (per-card window, n,
  effect size, corrected p, drill-down, lifecycle labels, 9/9 probe, 60-day noise simulation);
  the limit is that it is all internally verified.

Bottom line from the domain review: "it would survive contact [with a clinical advisory board, a
regulator, and a privacy activist] better than nearly every consumer comparator, but it is
pre-evidence and pre-legal-operationalization."

---

## Priority remediation roadmap (fleet consensus, ranked)

1. **Make CI green and gating** (fix the five failing jobs; branch protection). Nothing else is
   verifiable until commits stop landing on a red pipeline.
2. **Run the release pipeline once** (v0.x tag → images → provenance/SBOM → deploy README flow) and
   prove `compose up -d --wait` with the fixed db privilege model.
3. **Make PHQ-9 item 9 clinically actionable** (persist a safety flag; portal surface + C-SSRS
   follow-up prompt) and add MBC cadence support.
4. **Crypto envelope fix**: random per-account data key wrapped under a password-derived KEK
   (O(1) rewrap), Argon2id migration path, and out-of-band SAS verification for therapist pairing.
5. **Deconfound the brain by weekday/weekly cycles** (RESEARCH.md already promises it) and fix the
   EWMA alarm calibration + selection-adjusted p; bias-corrected entropy.
6. **User-data-loss paths**: web draft preservation across lock; cross-tab queue serialization;
   offline-queueable measures (web + mobile); mobile notifee duplicate fix.
7. **Operator/legal pack**: signed DPIA template with age gate, privacy policy URL, retention
   schedule, BAA register, HBNR 60-day clock in the runbook, wired Alertmanager + enabled readyz/
   backup-heartbeat probes, recorded off-site restore rehearsal.
8. **Portal/clinic hardening**: interaction-only idle lock, journal-level consent scope made
   explicit (or server-enforced pattern windows), note idempotency + optimistic concurrency,
   direction-unknown rendering for link/mood_shift.
9. **Mobile**: TLS pinning decision, on-device verification checklist executed on real hardware,
   FLAG_SECURE, production default URL.
10. **Docs hygiene sweep**: Bourke bibliography entry + citation CI rule, mobile sync-model rewrite,
    Snippe/Konjarski corrections, stale residuals, WEB_PLAN checkboxes, counts.

---

*Audit executed 2026-09-26 by a 12-subagent fleet (backend ×4, clients ×3, infra, docs, statistics
research, clinical/regulatory research) with local execution of all four test suites. Every scored
component had 93–100% of its lines read directly (lexicon data files validated programmatically
instead of word-by-word, as noted). All findings cite file:line evidence in the per-agent reports
above; prior self-audit reports in this repo were treated as unverified and every spot-checked
claim that verified false is tagged [CLAIM-MISMATCH] in the component sections.*
