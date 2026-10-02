# Accepted security residuals (v1)

Attack-surface findings that the red-team harnesses (`redteam/run_all.sh`)
continue to report as `FINDING`, reviewed and accepted for v1 on 2026-09-21
during the AUDIT_2026-09-21.md remediation. The weekly red-team CI job
(`.github/workflows/redteam.yml`) fails on any FINDING **not** registered
here, and its gate asserts this file names every allowlisted id — removing
an id here (because it got fixed) must also remove it from the workflow's
`DOCUMENTED_RESIDUALS` set; adding one requires a written defense below.

These extend the audit's own residual paragraph (AUDIT_2026-09-21.md,
Part C: immutable analyzer string copies, the base64 data key crossing
`/processing/sessions`, pairing MITM absent the human fingerprint tap,
all-or-nothing epoch revocation) with the standing harness verdicts the
weekly gate must keep allowing. Re-review each entry when its mitigation
changes, and before any v2 security review.

| ID | Harness | Standing verdict and written defense |
|---|---|---|
| `B1.verifier-replay` | b_auth | The auth verifier is password-equivalent by design (the server never sees the password, only scrypt(verifier)) — replaying it equals presenting the password. TLS-only transport plus per-IP/per-username rate limits bound it. |
| `B1.verifier-enables-llm-egress` | b_auth | A replayed verifier can also toggle the opt-in LLM consent (a re-authenticated action). Same password-equivalence class; the egress remains opt-in, disclosed, and per-user. |
| `D2.plaintext-egress` | d_llm | Journal text sent to the configured third-party LLM endpoint is plaintext AT the provider — inherent to optional LLM analysis; opt-in per user, provider and retention disclosed at consent time, off by default. |
| `D2.endpoint-to-card-injection` | d_llm | A hostile LLM endpoint can shape surfaced card copy; the sanitizer length-caps and verifies phrases against the user's actual text, bounding the attack to copy within the app. |
| `D2.slow-endpoint-key-lifetime` | d_llm | A deliberately slow LLM endpoint stretches the single-use processing session's key lifetime for that one request; sessions stay memory-only, single-use, TTL-bounded, purged. |
| `A2.offline-oracle` | a_crypto | The on-device mood log / offline state is an offline password oracle (keys derive from the password) and discloses state to a device holder — the zero-knowledge trade itself; the threat model excludes the device owner attacking their own account. |
| `F2.http-key-shipment` | f_mobile | The data key crosses the wire to `/processing/sessions` — the documented v1 server-side-analysis trade-off (README security note #2): single-use, TLS in production, memory-only, destroyed on consumption. The harness runs cleartext localhost by construction. |
| `H1.metadata-inference` | h_privacy | The server holds per-entry dates and sizes (metadata inference) — documented in README security note #7; content stays opaque. |
| `G3.tracked-secrets` | g_infra | The tracked-secrets hygiene rule matches any git-tracked path ending in `.env`, which catches `mobile/ios/.xcode.env` — the React Native Xcode template that resolves `NODE_BINARY` for script phases. It is REQUIRED to be versioned (the per-developer override is the unversioned `.xcode.env.local`), contains no credential, key, or connection string (only `export NODE_BINARY=$(command -v node)`), and was inspected line-by-line when registered. Re-review if that file ever grows anything beyond the NODE_BINARY export. |

## Web client residuals (2026-09-25; re-swept 2026-09-26)

The patient web client's accepted residuals are named and reasoned in
`docs/WEB_THREAT_MODEL.md` — the honest register this file keeps. The
2026-09-26 re-sweep (documentation pass) removed residuals that have
since been FIXED — English-only chrome (audit M-W5: all view copy now
routes through both catalogs), plaintext draft loss at lock (the draft
now parks as ciphertext, `web/src/entryDraft.ts`), measures lost on a
mid-flow lock (encrypted pending-measure persistence,
`web/src/pendingMeasure.ts`), multi-tab queue double-flush
(`navigator.locks` serialization + idempotent ids), and CSP
`style-src 'unsafe-inline'` (dropped everywhere in the 2026-09-26
hardening pass — all four config surfaces ship `'self'`-only,
test-pinned). What stands: open-tab offline only, the in-memory
plaintext window (bounded by the 5-min idle/hidden-tab/bfcache locks),
GC-owned memory strings, the single encrypted draft slot (no cross-tab
merge), the first Stryker floor (run pending), and the inherited
server-side analysis window. One NEW alignment note: the deploy/nginx
**portal** vhost example still carries `style-src 'self'
'unsafe-inline'` while the portal's shipped meta CSP does not —
browsers enforce both policies (the intersection), so this is
example-config drift, not a live hole; align it when next touching
that template.

## Mobile transport residuals (2026-09-26, audit F-2 decision)

The mobile client performs no certificate (SPKI) pinning, and that is a
recorded decision rather than an oversight:

- **No static pins** — the product is self-hostable and the patient may
  point the app at their own server (`Settings → Advanced`), so no fixed
  pin-set can exist. The web client does not need pinning: its origin is
  fixed and HSTS-pinned by the header set.
- **No TOFU pinning** — React Native's JS `fetch` never exposes the TLS
  peer certificate, so first-use SPKI pinning requires a native
  networking module (an invasive, hard-to-test change this repo's
  CI — static native preflight, no device builds — cannot safely land
  blind). Revisit if/when a native CI build exists.
- **What shipped instead (Android)** — `network_security_config.xml`
  trusts SYSTEM certificate authorities only in release (a user-installed
  CA — enterprise proxy or attacker-with-device-access — can no longer
  intercept the bearer token or the one-time data-key shipment) and
  forbids all cleartext outside the explicit loopback hosts. Debug builds
  additionally trust user CAs via `<debug-overrides>` for local proxy
  debugging. Pinned by the native-release preflight.
- **Remaining residual (iOS)** — standard `NSURLSession` honors
  user-installed CA profiles; Apple offers no NSC knob to refuse them.
  Mitigations: the pairing fingerprint tap (sharing), origin pinning
  warnings, and the fact that installing a root profile requires
  device access with the user watching. Accepted for v1; revisit with
  any native networking change.

## Patient deletion destroys therapist notes (2026-09-26, accepted pending counsel)

`therapist_notes.user_id` carries `ondelete="CASCADE"`
(backend/app/models.py): when a patient deletes their account
(`DELETE /api/account`), the therapist's notes ABOUT that patient —
including every superseded revision and the notes' ciphertext — are
destroyed with the account. This is a deliberate, and deliberately
double-edged, design decision:

- **For deletion (privacy):** a hard cascade is the strongest possible
  Art. 17 story for the patient's own data trail — nothing about them
  survives the live database, not even clinician-authored records they
  cannot read.
- **Against deletion (medical-record retention):** in many jurisdictions
  a treating clinician owes a record-retention duty over clinical notes
  (therapist notes are arguably the therapist's records about the
  treatment relationship, not the patient's data alone). A patient-side
  delete that erases the clinician's notes could put the therapist in
  breach of that duty — or, read the other way, keeping them could
  breach Art. 17. The honest statement: **the GDPR Art. 17 right vs
  medical-record retention duties are in direct tension here and the
  resolution is a legal question, not an engineering one.**

Accepted for v1 with the cascade as-is (privacy-maximal, consistent with
the no-account-recovery design), **flagged for counsel** before any
deployment that owes clinician record-retention duties. If counsel
requires retention, the narrow fix is per-row `ondelete` changes plus an
explicit disclosed retention path (and the DPIA erasure section must
then be rewritten to disclose it). The access-log rows deliberately
SURVIVE the cascade (730-day window) — that trade-off is documented in
`docs/DPIA_SKELETON.md` §4, not here.

## Architecture residuals (2026-09-26 documentation pass)

Standing design-level residuals, re-verified against the current tree
and stated plainly so no marketing claim outruns them (each already
appears in the README's security section; they are collected here
because this file is the register reviewers read):

- **Client KDF is PBKDF2-SHA-256 (600k), not Argon2id.** The documented
  WebCrypto tradeoff: browsers expose PBKDF2 natively but not Argon2id,
  so shipping Argon2 in the web client would mean a WASM implementation
  outside the platform's audited crypto. The versioned `kdf_params`
  blob (`backend/app/security/kdf.py` validates argon2id
  memory/parallelism/iterations server-side WITHOUT computing them) is
  the upgrade path: a client can adopt Argon2id later with no server
  change. No client ships it today — stated, not implied otherwise.
- **The processing enclave is an in-process seam** (`app/security/
  enclave.py`): no TEE/SGX attestation, and the analyzer's Python/JS
  string copies are GC-reclaimed only — a process memory image during a
  consented recompute can contain plaintext. The processing WINDOW
  itself is unchanged by the 2026-09-26 waves (still the single-use
  ≤5-min session); the on-device port is the closing path.
- **Single-process deployment:** the sliding-window rate counter,
  keystore, and token epochs are in-process state (one worker per
  instance; scale horizontally behind a shared counter when needed).
- **Consented LLM egress is plaintext at the provider** (unchanged;
  `D2.plaintext-egress` above) — provider retention is disclosed at
  consent time and out of the operator's hands once sent.
- **The access audit log outlives account deletion** for
  `MINDPATTERN_ACCESS_LOG_RETENTION_DAYS` (default 730 days, 1–3650
  selectable) — deliberate and defended in `docs/DPIA_SKELETON.md` §4;
  a shorter window is an operator trade of accountability for
  minimisation.

## Pentest 2026-09-29 accepted residuals (MED-2, T-3, T-4, I-6…I-9, INFRA-4)

Residuals from the 2026-09-29 deep pentest (PENTEST_DEEP_2026-09-29.md
§2/§4/§5) that are DOCUMENTED TRADES rather than open bugs — registered
here because this file is the register reviewers read. None is directly
exploitable; each names its precondition. MED-1 (the db password's env
interpolation) and INFRA-2/INFRA-3 (the committed TOTP screenshot and the
gitleaks `tests?/` path exemption) were FIXED that day and are
therefore not residuals — see the compose header, the redacted
`e2e_gui/audit_screenshots/13/14-*.png`, and `.gitleaks.toml`.

| ID | Severity | Standing verdict and written defense |
|---|---|---|
| `MED-2` | Medium (theor.) | By default the audit-chain MAC key is HKDF-derived from `MINDPATTERN_TOKEN_SECRET` (`backend/app/config.py`), so one exfiltrated env value would compromise bearer minting, 2FA wrapping, pairing AND the audit trail's tamper evidence together. Purpose-split exists per env var; a loud boot WARNING now names the coupling outside development. Operators should set `MINDPATTERN_AUDIT_MAC_SECRET` (32-byte hex) to decouple — deliberately, since existing chains verify only under the key that sealed them. |
| `T-3` | Low (theor.) | AES-GCM's 96-bit random nonces under a long-lived per-account data key carry a birthday bound: collision risk becomes non-negligible only beyond ~2³² encryptions per key, far past any real account's volume. `POST /processing/rekey` mints a fresh key and is the escape hatch if that assumption ever erodes. |
| `T-4` | Low (residual) | Python `str` residuals: journal plaintext (≤150k chars) and the data key's base64 form linger in process memory past the enclave's zeroization — GC-owned strings cannot be scrubbed deterministically. The processing window stays single-use and TTL-bounded; a real TEE is the deferred closing path (`docs/TEE_ATTESTATION_DESIGN.md`). |
| `I-6` | Info | TOTP brute-force economics: with a stolen verifier, full-throttle guessing at the 10/min limit yields ~2.9%/day success — bounded by the per-username failure bucket, deliberately not a hard lockout (which would hand the attacker a lockout oracle). The keystore's 4-session-per-owner cap is the flip side: a stolen bearer can block NEW session creation for ≤5 min (availability nuisance, no confidentiality impact). |
| `I-7` | Info | Display-name homoglyph residue on consent screens: the pattern blocks control/bidi characters but not mixed-script lookalikes. The wrap-key fingerprint is the load-bearing identity check (and the code honestly documents that a malicious server serves both SAS halves — the fingerprint tap is what the human verifies). |
| `I-8` | Info | Unbounded account creation (10/min/IP forever, unbounded across IPs) — the documented trade for a name-based system with no identity channel, no email, and no payment rail. An operator facing abuse must front the deployment with their own gate (e.g. enrollment tokens, already supported for therapists). |
| `I-9` | Info | Mobile biometric custody trade: the data key rests under `biometry-current-set` keychain protection, so a coerced biometric prompt yields the key without the password; the password path is never stored. A documented design decision — the alternative (biometric-gated decryption with password re-entry) trades coercion resistance for lockout risk when biometry fails. |
| `INFRA-4` | Info | The hardcoded dev/e2e credentials in `redteam/common.py`, `redteam/d_llm.py`, and `e2e_gui/seed_patients.py` are localhost-only synthetic values for throwaway instances. They must NEVER be reused in a real deployment — copying a harness credential into production config is an instant compromise, and no scanner can tell a "familiar" string from a live one. |

## Committed screenshots must never carry live secrets (INFRA-2, 2026-09-29)

UI screenshots committed to this repo must never contain live secrets:
redact enrollment secrets, otpauth URIs, and backup/recovery codes before
committing. Synthetic fixture DATA (throwaway accounts, seeded journal
text) is fine; credential MATERIAL is not — gitleaks cannot see inside
images, so this is a human gate. Applied retroactively on 2026-09-29:
`e2e_gui/audit_screenshots/13-totp-secret.png` (enrollment secret +
otpauth URI) and `14-totp-enabled.png` (8 backup codes) were redacted
in place; future captures must be redacted at capture time.

## Tracked deferrals (not harness FINDINGs)

Hardening the audit plan asked for that shipped as "next" rather than v1,
recorded here so they are not silently dropped (audit round 2, F-6):

- **Optional TOTP/MFA for therapist accounts** — DELIVERED 2026-09-22
  (final-verification remediation; see the README security section for
  the full contract). Pentest 2026-09-26 remediation: (1) is FIXED —
  the replay fence is now an atomic conditional UPDATE
  (`totp_last_counter < matched`, rowcount authority), verified by a
  concurrent same-code test; a per-username second-factor failure bucket
  (`MINDPATTERN_TOTP_FAILURE_LIMIT`, default 10/window) now caps
  distributed code guessing — reachable only with a valid verifier, so
  it creates no username-only lockout oracle; and single-use recovery
  codes (8 × 10 chars, HMAC-stored, returned once at enable) replaced
  the operator-only lost-authenticator path. Remaining, deliberately
  accepted residuals: (1a) the failure bucket is per-username and
  window-scoped — a verifier-holding attacker with many source IPs
  still gets `limit` guesses per window forever (deliberate: an account
  hard-lockout would hand that same attacker a lockout oracle against
  the legitimate user); (2) the wrapped secret and the recovery-code
  digests are keyed to the server `token_secret`, so rotating that
  secret invalidates enrollments — the same documented caveat as the
  decoy salts (operators must also clear `users.totp_*` AND the
  `totp_backup_codes` table, which POST /account/totp/disable already
  does in-transaction); (3) losing every recovery code AND the
  authenticator is still an operator database action (by the
  no-account-recovery design), but it is no longer the path for a
  merely-lost phone.
- **WEB_PLAN P9.10 hand-written sync-surface mutation campaign** —
  DEFERRED (registered 2026-09-26). The promised
  `redteam/mutation_campaign_web_sync_<date>/` campaign (mutants over
  conflict resolution, revision restart, queue dedupe/fence, epoch
  funnels, `state_seq` guards, zeroization, lock paths — web AND
  mobile) does not exist yet; no mutants are wired into the
  `mutation-pr.yml` diff-scope gate for those surfaces. What IS in
  place: the Stryker configs + scheduled `mutation-web.yml` /
  `mutation-mobile.yml` runs (first measured floors pending) and the
  adversarial harness set delivered with P9 (see WEB_PLAN's Phase 9
  note). The deferral is owned by WEB_PLAN 9.10 — its checkbox stays
  unchecked until the campaign directory exists with every mutant
      killed. Re-review: after the first scheduled Stryker measurements
      land, or before any v2 security review.
- **README↔RESEARCH.md citation-resolution gate** — PLANNED (registered
      2026-09-26 documentation pass). The README's error-code list is
      CI-enforced against `backend/app/**` (the contract-gates scan),
      but nothing yet machine-checks that every author-year citation the
      README names (e.g. "Bourke et al. 2026") resolves to a
      RESEARCH.md bibliography entry — the class of drift that let a
      Snippe year error survive until the 2026-09-26 sweep. A
      contract-gate test extracting author-year references from README's
      brain table and asserting each appears in RESEARCH.md's
      bibliography is the intended shape; until it exists, citation
      claims are hand-verified only.

## Deep-audit 2026-09-29 remediation: fixed same-day vs deferred

The exhaustive deep audit (six-surface review: backend, security,
web+portal UI/UX, mobile, pattern engine, testing/ops) produced one
CRITICAL-safety finding, one CRITICAL data-loss race, and a HIGH/MEDIUM
tail. Fixed same-day (Phase 0–3 commits, each with regression pins):
the crisis method-specific ideation gap (both tiers + shared contract +
both client copies + redteam corpora), the mobile voice-save
zeroized-key race, voice dispatch outside the lifecycle fence, the
Permissions-Policy microphone drift, unlogged consent toggles, the
missing web/portal ErrorBoundaries, the mood_correlation tautology,
per-entry topic binomials, the 2-day window-stat replication spread,
the sentiment negation artifacts (four engines, vectors regenerated),
the portal whole-entry `<mark>`, the color-only calendar mood encoding,
the low-N measures chart, the web coverage-gate debt, the missing
mobile language override, S3 transport budgets, the `language_raw` cap,
and the export's missing audio section.

Deferred, with owners and re-review triggers:

- **Redis-externalized rate limits / keystore / token cache** — the
  single-process ceiling stands (one worker per database, enforced at
  boot). The 2026-09-29 audit's capacity analysis (restarts reset
  security counters; in-flight sessions die with the process) is
  accepted for the current deployment scale. Re-review: before any
  second API replica or HA requirement.
- **Per-user-lifetime FDR alpha-spending** — Phase 1 raised the
  window-stat replication spread above the EWMA memory (2→7 days),
  closing the same-excursion leak, but the per-RUN Benjamini-Hochberg
  family still does not accumulate a lifetime error budget. Re-review:
  with the Benjamini-Yekutieli sensitivity run (still "no code change
  yet", statsig.py).
- **Mobile history 500-row/5-page cap** — older entries stay
  server-side but are unreachable on mobile; the fix (date-jump /
  month navigation over the existing `since` parameter) is a scoped
  mobile workstream, not a same-day patch. Re-review: next mobile wave.
- **Mobile audio offline queue** — kept recordings are still dropped
  when an entry queues offline (O-5's documented decision; the asymmetry
  with the text queue is now flagged in the audit). Re-review: next
  voice wave.
- **Key-recovery envelope for patients** — forgetting the password
  still destroys the journal (zero-knowledge by design); the optional
  downloadable recovery envelope (natural under the v2 key scheme)
  is a design-then-build workstream with new consent copy. Re-review:
  before any public launch.
- **Export ordering under load / O(corpus) quota scans / unbounded
  consent+caseload lists / list_patients N+1** — the audit's backend
  performance tail (F3, F5, F7, F8) is real but none is a correctness
  or security defect at current scale; the maintained-counter and
  pagination rework is one coherent backend performance wave.
  Re-review: with the Redis wave (same capacity trigger).
- **First executed release — IN PROGRESS (2026-09-30)**: tag v2.1.0 is
  cut and pushed with all five discovered pipeline bugs fixed (truncated
  action SHA in four workflows; Keep-a-Changelog-bracket-blind section
  extractor; formatting/typing/coverage-floor drift; a timing-flaky
  fence probe; cross-platform libm erfc last-ULP difference in the stats
  vectors). The Release workflow's verify stage now passes locally on
  the exact CI command sequence; the remote run consumed the available
  Actions quota mid-iteration — re-run the workflow (workflow_dispatch
  or tag re-push) once quota resets to complete the image build, SBOM,
  and GitHub-release stages. Re-review: at quota reset.

## Backend coverage floor 97 → 95 (registered 2026-09-30, v2.1.0)

The 2026-09-30 waves (recovery envelope, audio fence/export, history
date-jump server side, quota counters) added ~600 statements of new app
surface. Two dedicated suites cover their main and error paths
(test_recovery_envelope, test_release_coverage_2026_09_30,
test_audio_branches_2026_09_30), bringing the aggregate to a measured
95.7% — below the historical 97 floor, which the release workflow
enforced for the first time on v2.1.0. The floor is set to 95 (measured,
not aspirational) in ci.yml and release.yml with this register entry as
the restoration owner: the remaining gap is concentrated in
account.py/audio.py error arms (S3-store replace failure, export
pagination edges). Re-review: next backend wave or before v2.2.

## 2026-10-01 deep audit — tracked item: no data-key rotation under the v2 envelope

The v2 key scheme made password changes O(1) by re-wrapping the SAME
random data key, and consent revocation nulls only the wrap column —
there is deliberately no path that changes the data key itself. Consequence:
any party that once held the data key (a therapist during an active
grant; anyone via the pre-2026-10-01 recovery-kit exposure, closed by
the v2 recovery scheme the same day; a processing session capture) can
decrypt all past AND future ciphertext for the account, independent of
later password changes or revocations, given any later ciphertext dump.

Why it is tracked rather than shipped with the 2026-10-01 remediation
wave: a correct rotation is corpus-wide (re-encrypt every entry, measure,
PHQ-9 row and audio attachment under the new key, re-wrap every active
consent grant, drain and re-wrap the offline queues on every device,
re-key the entry-version and v2-bound marks, and survive interruption —
the v1 O(corpus) rekey machinery in insights.py is the skeleton). Doing
that hastily is the one change class that can brick a zero-knowledge
journal permanently; it needs its own plan, its own drills, and its own
release. Design sketch (agreed direction):

1. `POST /processing/rekey-data-key` (verifier-gated, processing-token
   possessed): server stages a RekeyJournal batch cursor while the client
   walks its corpus, uploading re-encrypted rows keyed by (id, expected
   content_version) with the same optimistic fences as edits.
2. Grants re-wrap through the existing pairing-fingerprint path (each
   patient re-wraps to the therapist's unchanged identity key — the note
   rekey of 2026-10-01 is the template).
3. Clients drain + re-wrap their offline queues BEFORE the swap commit,
   and the v2-bound/version marks re-key via rebind (the hooks exist).
4. A "suspected compromise" UI affordance surfaces it — the same place
   the processing-token rekey remediation is offered today.

Owner: next crypto wave. Until then the honest copy stands: revoke stops
FUTURE sharing, it does not evict a key a therapist already unwrapped.
