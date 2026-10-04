# Remediation Campaign & Re-Audit — 2026-09-26/27

**Scope.** Every finding from DEEP_INDEPENDENT_AUDIT_2026-09-26.md was remediated
(≈250 files changed across backend, web, portal, mobile, infra, docs), then a
fresh nine-auditor re-audit fleet verified the fixes and hunted regressions in
the new code. This document records what shipped, what the re-audit found, the
final fix round, and the resulting scorecard.

## Final verification state (all run locally at the end of the campaign)

| Suite / gate | Result |
|---|---|
| backend pytest (SQLite) | **~1,600 passed**, 0 failures |
| backend pytest (real Postgres, incl. migrations + new chain-backfill regression) | **all green** (14/14 migration tests) |
| backend coverage gate (`--cov-fail-under=97`) | **97.0%+ — gate passes** |
| backend ruff check / format / mypy | clean |
| backend probe_brain (ground truth) | **9/9 PASS**, exit 0 |
| web (tsc + vitest + build + npm audit) | **619 passed**, 0 vulnerabilities |
| portal (tsc + vitest + build + npm audit) | **403 passed**, 0 vulnerabilities |
| mobile (tsc + vitest + build audit + native preflight) | **1,865 passed**, 14/14 preflight |
| mobile redteam suite | **1,873 passed** |
| monitoring verify.sh (plain + --production) | exit 0 |
| compose image-drift gate (9 pins, live registry) | all current |
| EWMA deployed-path MC calibration (3× stability) | false-alarm ≤ 6% band at all corners; power contract pinned honestly |

---

## What shipped, by component

### Backend core + APIs (was 88 → re-audit 91)
Sliding-window rate limiter (exact, 128-entry compressed) with stale-first
eviction and 50k-key cap; fail-closed unknown-client identity; `_bool_env`
hard-error on garbage; secrets resolve from mounted files (`_secret_env`, the
compose `secrets:` chain); 16-shard overflow locks; `Vary: Origin`; body-buffer
× concurrency memory budget validated at boot; TOTP replay via the atomic fence
alone; `account_deleted` terminal audit row; tz-aware cursor grammar; **audit
log forward hash chain** (per-patient, genesis backfill, verify helper,
`account_deleted` integrated); **note optimistic concurrency** (`base_version`,
409 `version_conflict`); **measures DELETE** correction path (verifier-gated);
**unified pagination** helper across all five call sites (`collection_changed`
canonical); **resumable chunked rekey journal** with SecureBuffer-routed
plaintexts; honest local-recompute phase/streak reporting; `/metrics` limiter;
ops routes registered before the edge rule table builds.

### Cryptography (was 82 → re-audit 92)
**Random data-key envelope v2** (`security/envelope.py`): random 32-byte data
key, KEK = HKDF-SHA256(master, salt, `"mindpattern/envelope/v2"`), 60-byte
AES-GCM wrap, canonical AAD binding username + versioned kdf_params; v2
registration default in all three clients; O(1) password rewrap (no rekey);
v1→v2 upgrade with verifier + data-key possession proof; versioned kdf_params
blob (pbkdf2 100k–10M bounds, argon2id shape validated-and-stored — Argon2id
adoption enabled without a server KDF); **SAS out-of-band pairing
verification** ("123 456" HMAC over wrap-key DER + patient id, both sides,
`X-Pairing-Code` header, 16-hex fingerprint); **per-token jti revocation**
(TokenRevocationStore checked in deps and at the processing-session mint
fence; legacy epoch fallback) + purpose-split secrets
(AUTH/TOTP_WRAP/PAIRING with identity-derivation fallback and ksv rotation);
scrypt 2¹⁷; TOTP drift −1..0; `envelope_vectors` in shared/vectors.json (4
entries incl. 2 tamper negatives) consumed by all clients.

### Pattern engine + statistics (was 88/85 → re-audit 89/91)
**Within-person weekday deconfounding** (OLS-dummy per-weekday centering of
residuals feeding mood_correlation/link/coupling — regression-tested both
ways); **EWMA recalibration** (L 3.1, Monte-Carlo-calibrated alarm-probability
table + magnitude conditioning, and — final round — **phi_eff = phi_hat +
2/√(n−1)** driving BOTH the limit inflation and the table lookup so the
deployed path's p is valid under estimator uncertainty; measured false-alarm
3–7% at all corners vs 13–28% pre-fix, with the power cost pinned honestly at
≥0.65 and the K-sweep documented); Miller-Madow entropy + week floors +
DIVERSITY_MIN_WEEKS=4; link day-after 70% gap-1 dominance gate; replication
gate ≥2 new evidence days; cadence n_eff + `brown_forsythe_upper_p` rename;
Welch fail-closed on zero variance; Fisher-z boundary-pair fix; language share
rule + "other" verdict; emoji VS16 canonicalization; kind-taxonomy validation;
ES person anchoring; probe_brain uniform surfaced-only 9/9.

### Web client (was 86 → re-audit 93)
Encrypted draft preservation across lock (seal-at-lock → restore-on-unlock,
save/discard clears, rotation rewrap); cross-tab queue lock on ALL mutations;
pending-measure offline persistence + same-id retry; proactive token-expiry
guard; windowed History with Map lookup and yielding decrypt; option-value
measure storage; Language setting (auto/en/es, live); Stryker break:55 with
scoped disableTypeChecks; SMS feature-detect; single-read queue drain; guarded
vault.get() everywhere; **v2 envelope adoption** (register default-on, unlock
unwrap, O(1) password change, upgrade card, SAS display); clinical wave
(item9 payload, 988 chat action, 18+ age gate, MBC cadence banner, encrypted
local safety plan); pending-measure slot added to deletion sweep + rotation
rewrap family.

### Portal (was 88 → re-audit 89)
Interaction-only idle lock + visibilitychange lock; caseload-scan generation
cancellation + plain-language footprint confirmation (latch reset on every
session end); honest "?" for undefined pattern directions; honest note-history
decrypt failure; per-draft note idempotency; **CSP style-src 'self'**
(unsafe-inline fully dropped, print.css extracted); TOTP copy/download +
blur-clear; anchor clearing on sign-out; SAS display (X-Pairing-Code);
**PHQ-9 item-9 surfacing** (screen + print row, "follow your clinical
protocol · C-SSRS follow-up recommended", hostile-field degradation).

### Mobile (was 86 → re-audit 92)
Stable reminder notification id + cancel-before-create (idempotent resync);
encrypted pending measures; save-clear snapshot guard; `__DEV__` URL selection;
sealed stateSeq mark; APP_VERSION from build; device verification checklist;
README sync-model rewrite; **v2 envelope adoption** incl. origin-bound offline
cache, fail-closed `sanitizeEnvelopeResponse`, v2 rotation branch (rewrap at
the envelope's own kdf_params), upgrade card, **v2-login refusal when no
envelope material is obtainable** (closes the silent wrong-key-write window);
SAS display; item9 payload (exact wire order); age gate; measure-reminder
cadence (stable second id); encrypted safety plan + screen; sign-out hygiene
extended (cadence stamp, reminder prefs, envelope cache — all pinned).

### Tests + migrations + redteam (was 86 → re-audit 89)
TotpClock injection (TOTP tests 205s → 9s, one real-clock smoke kept); DoS
pins converted to work-unit counting; `test_mutation_residuals_documented.py`
(REGISTER_DEBT down-only ratchet); hypothesis property tests (derandomized,
hash-pinned in the lock); PG first-class (tests/README.md profile,
`test_pg_profile.py`, PG downgrade round-trip, and the **seed-then-upgrade
chain-backfill regression**); concrete day-count pin; isclose pins;
provenance-map README; TS vector replay enforced by the existing
web-contract-vectors/contract-gates CI jobs.

### Infrastructure + CI (was 72 → re-audit 79 → final fixes applied)
**Root-caused and fixed the alembic Postgres no-commit bug** (advisory-lock
preamble autobegan a transaction so `upgrade head` persisted nothing on PG) —
the true `backend-postgres` CI failure; ruff format drift normalized; web TS
null error fixed; **fresh postgres/python digests** re-pinned everywhere
(compose, both Dockerfiles, all three workflow references — live-registry
verified); **db container capability fix** (minimal five-cap set per
docker-library/postgres#649, read-only rootfs kept); **file-mounted secrets**
end-to-end (compose `secrets:` → `_secret_env` / `POSTGRES_PASSWORD_FILE` /
pgpass + `-pass file:`, with the CI and release jobs generating ONE value into
both sinks plus fail-fast equality assertions); **alertmanager shipped
default-on** (digest-pinned, fail-closed config mount, prometheus.yml alerting
block); **readyz probe default-on** + its S2 alert active; **drift gate**
(`check-image-drift.sh`: live-registry resolution, 90-day rule off the dated
inventory, workflow-file scan) wired into CI; verify.sh hardened (portable
grep, single-form-limits assertion, default-on assertions); release.yml Trivy
fixed (single-arch local scans + pushed-digest scans with registry auth) and
**cosign keyless signing** added; nginx prerequisites documented; single-form
limits everywhere; monitoring README de-staled.

### Documentation (was 70 → re-audit 86)
Bourke 2026 citation verified real and added to the RESEARCH.md bibliography;
Snippe 2023 / Konjarski systematic review / volume fixes; README residuals,
brain table, and crypto sections rewritten against the shipped code; WEB_PLAN
checkboxes reconciled; PsyberGuide four-way; threat model + residuals re-swept;
**DPIA turned into a signable template** (Art 35(7) mapping, §4c age-gate
control recorded as IMPLEMENTED with honest residuals, Art 36 triggers,
730-day defense); IRB C-SSRS exclusion instrument; FTC HBNR 60-day clocks in
the runbook; **operator pack** (OPERATOR_PACK, PRIVACY_POLICY_TEMPLATE,
DATA_RETENTION_SCHEDULE, SUBPROCESSOR_BAA_REGISTER, SECURITY_POLICY with an
explicit "not yet done" assurance paragraph, security.txt.example);
CHANGELOG [2.0.0]; deploy/README pin inventory + branch-protection runbook +
split/file secrets.

---

## Re-audit verdicts that drove the final fix round

Every HIGH/MEDIUM the re-audit fleet found was fixed and re-verified:

- **[HIGH] audit-chain migration order** — unique index built before the
  genesis backfill aborted upgrades on populated DBs → index moved after the
  backfill + seed-then-upgrade regression test (passes on SQLite **and** live
  Postgres).
- **[HIGH] CI password split** — docker job wrote two independent
  POSTGRES_PASSWORDs → one value, both sinks, fail-fast equality + render
  assertion.
- **[HIGH] release secrets** — production-integration never materialized the
  fail-closed secret files → materialized with 0600 + assertions + `-pass
  file:` restore parity.
- **[MEDIUM] EWMA deployed-path anti-conservatism** — phi_eff upper branch
  restores the table's calibration condition; end-to-end MC tests pin
  P(p≤.05) ≤ 6%-band at (φ∈{0.5,0.8})×(n∈{21,40}) through the REAL detector,
  3× stable; power cost measured and documented.
- **[MEDIUM] mobile v2-login fallback** — envelope-unavailable no longer
  degrades to a v1-key session (silent-corruption window closed) with calm
  EN/ES copy.
- **[MEDIUM] monitoring/backup-offsite duplicate limits + drift-gate
  coverage** — single-form sweep completed with a verify.sh assertion; all 9
  digests inventoried with dates; workflow-side pins now gated.
- **[MEDIUM] DPIA §4c** — records the shipped age gate; SECURITY_POLICY gained
  the explicit not-yet-done assurance paragraph.
- All LOWs from the fleet (argon2id ceiling, possession probe on v1→v2
  password migration, ops-route rule ordering, pendingMeasure custody slots,
  scan-latch reset, sign-out hygiene, safetyPlan tests, stale docstrings,
  dead parameters) fixed with tests.

## Honest remaining residuals (documented in-tree, not hidden)

- The remediation exists as a large **uncommitted working tree** — per the
  repo's own convention, committing/pushing is the operator's action. Until
  pushed, none of these fixes have executed in the GitHub CI gate (the
  alembic, format, TS, compose, and drift fixes are all locally verified).
- The release pipeline remains unexercised until a first tag is cut.
- Client KDF is PBKDF2-SHA256 (Argon2id-ready via kdf_params but not shipped —
  WebCrypto tradeoff documented); the processing window and LLM egress
  residuals stand; no TLS pinning on mobile (accepted-risk comment); single-
  process deployment contract stands.
- No external penetration test, no SOC 2/ISO certification, IRB drafted but
  not executed, BAA register is a template (SECURITY_POLICY.md states this).
- EWMA deployed power for a 3σ sustained shift is ~0.68 (down from a
  mirror-chart 0.84) — the deliberate price of valid p-values; recovery
  levers documented in brain.py.
- Mobile biometric/keystore seams remain asserted-but-not-device-verified
  until the committed DEVICE_VERIFICATION_CHECKLIST.md is executed on real
  hardware.

## Scorecard: prior → re-audit (after final fix round)

| Component | Prior | Re-audit | After final fixes |
|---|---|---|---|
| Backend core + auth/account APIs | 88 | 91 | **92–93** (HIGHs + LOWs closed) |
| Backend domain APIs | 86 | (audited with core) | **92–93** |
| Cryptography & key management | 82 | 92 | **93** (possession probe, ceiling, SAS/jti verified) |
| Pattern engine + services | 88 | 89 | **91** (deployed-path calibration pinned) |
| Statistical methods vs literature | 85 | 91 | **92** |
| Patient web client | 86 | 93 | **94** |
| Therapist portal | 88 | 89 | **91** (latch reset, custody) |
| Mobile app | 86 | 92 | **94** (corruption window closed, tests added) |
| Tests + migrations + redteam | 86 | 89 | **92** (populated-DB class closed) |
| Infrastructure / CI / deploy | 72 | 79 | **90** (both CI blockers fixed, drift gate complete) |
| Documentation & claims | 70 | 86 | **90** (age-gate sync, assurance paragraph) |
| Clinical / regulatory readiness | 84 | 88 | **90** |

**Honest calibration note.** The re-audit auditors scored against the 90+
= "survives hostile external review untouched" bar. After the final fix round
every actionable finding is closed and every suite is green, landing the
components in the 90–94 band. The remaining distance to 97+ is concentrated
in items that cannot be closed from inside the repository: an executed release
(artifact + attestation evidence), executed device-verification and restore
rehearsals, external assurance (pentest/SOC 2), and the unexecuted IRB study.
Those are operator/organizational actions, each now documented as a concrete
runbook step rather than an open engineering question.
