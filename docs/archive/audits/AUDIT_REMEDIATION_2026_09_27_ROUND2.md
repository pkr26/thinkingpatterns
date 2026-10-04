# Independent audit remediation — 2026-09-27 (second round)

An external-style independent audit re-reviewed commit `e4585b3` (the
2026-09-26/27 remediation campaign) area by area, re-ran every suite, and
produced ~30 findings (0 critical, 10 medium, the rest low/informational).
Every finding was then fixed and re-verified. This document records the
round; the findings and their fixes:

## Verification state after this round (all re-run locally)

| Suite / gate | Result |
|---|---|
| backend pytest (SQLite) | all green (incl. 18 new remediation pins) |
| backend ruff / format / mypy | clean |
| backend probe_brain | 9/9 PASS, exit 0 |
| web (tsc + vitest + build) | 634 passed, coverage gate green |
| portal (tsc + vitest + build) | 409 passed, coverage gate green |
| mobile (tsc + vitest) | 1,914 passed, **coverage gate green again** (global functions 84.34% → 86.11%; SafetyPlanScreen 46% → 100%) |
| mobile redteam specs | 8 passed |
| shared brain vectors replay (backend + mobile) | green (now incl. bare-VS16 emoji rows) |
| monitoring verify.sh (plain + --production) | exit 0 |
| drift gate `--selftest` + live registry walk | exit 0 (9+ pins incl. Dockerfiles and shell scripts) |

## Cryptography / auth

- **Durable single-token revocation** (`app/models.py` `TokenRevocation`,
  migration `a4e8c1f6b9d3`, `app/cache.py`, `app/api/auth.py`,
  `app/main.py` boot hydration, daily prune in the sweep): logout's jti
  revocation no longer dies with the process — a restart or deploy can no
  longer resurrect logged-out bearers. The in-memory map stays the fast
  path; once the cap has evicted entries the checked lookup falls back to
  a durable point query, so eviction pressure cannot resurrect a token.
- **Keyed audit-chain seals** (`app/api/_audit.py`, `entry_mac` column,
  migration `b7f2d8a4e6c1`): rows are HMAC-sealed under a key held
  OUTSIDE the database (`MINDPATTERN_AUDIT_MAC_SECRET` env/file, else
  HKDF-derived from the token secret). A DB-write attacker can no longer
  rewrite a whole trail and recompute the links.
- **Audit-journal tail anchor** (`MINDPATTERN_AUDIT_JOURNAL`, compose
  wires a named volume): every committed append also lines out to an
  append-only file outside the DB; verification flags a journal AHEAD of
  the database head as tail truncation (the forward chain's blind spot).
  A journal behind the head stays benign (crash-window semantics).
- **Chain-append retry**: losing the unique-seq race no longer 500s the
  audited action — the append rolls back to its savepoint and retries on
  the fresh head.
- **Runtime verification caller**: the daily sweep walks recently-active
  patients' chains (bounded) and raises `mindpattern_audit_chain_failures`
  — the verifier is load-bearing instead of test-only.
- **kdf_params re-store validation**: password-change/upgrade re-stores
  re-validate the account's stored blob; a corrupt column fails closed
  (409 `envelope_key_mismatch`) instead of propagating garbage.
- **`_secret_env` strip symmetry**: env values are stripped like file
  values; `MINDPATTERN_METRICS_TOKEN` gained `<VAR>_FILE` resolution (the
  last secret deliverable as plain env).

## Backend APIs

- **Note create-channel conflict contract** (`app/api/therapist.py`): a
  POST carrying DIFFERENT content under an existing `client_note_id` is
  now 409 `version_conflict` (the create channel was still
  last-write-wins; the exact semantics item 15 closed for PATCH).
  Byte-identical replays stay idempotent. Tests updated to the contract.

## Statistics (brain)

- **Link day-after gate counts MEASURED pairs only** (`brain.py`): the
  70% gap-1 numerator previously counted unmeasured outcome days, so
  "the day after" copy could ride a measured minority.
- **phi_eff honesty** (`brain.py` constant block): at K=2.0 the added
  SE term exactly cancels the shrinkage — the comment now states the
  chart runs on the raw estimate (the shrinkage is a gate), documents the
  conservative (1+φ)/(1−φ) inflation's power cost, and the K-sweep in
  `scripts/mc_phi_eff.py` includes the K=1.0 contrast it cites.
- **Weekday-centering df note** (`_strip_weekday_effects` docstring).
- **probe_brain**: the dead disjunct in verdict H removed (behavior
  unchanged, stated plainly).
- **VS16 parity vectors**: `gen_brain_vectors.py` tokenizes through the
  engine's canonical emoji counter (the old `text.count` loop was dead
  and missed bare spellings) and four new corpus rows pin bare/mixed
  VS16 spellings across both platforms; the test-suite tokenizer helper
  matches.
- **Calendar-validity boundary documented** (`brain.update`): the audit
  suggested clamping `entry_date <= today`; the repo's own engine
  contract tests run recomputes behind their fresh evidence, so the
  boundary is documented instead — the API owns calendar validity
  (`FORWARD_GRACE_DAYS`), and new callers own theirs.

## Clients (web / portal / mobile)

- **Web — rotation vs the offline queue**: v1 password rotation drains
  the pending queue first (aborts honestly if entries remain) and
  rewraps remaining queue/rejected blobs to the new key — offline-written
  entries are no longer destroyed by a password change. Mobile parity
  shipped in the same round.
- **Web — zeroized-key race in measure submit**: the data key is
  snapshotted before the persist-await and re-checked before encrypt; a
  lock mid-submit keeps the pending record instead of encrypting under
  zero bytes and destroying the retry slot.
- **Web — queue read APIs take the Web Lock** (`queueLength`,
  `rejectedEntries`), closing the unlocked self-heal read-modify-write.
- **Web — draft seal-vs-clear race**: clears are serialized behind
  in-flight seals; a saved entry can no longer resurrect as a draft.
- **Web — crisis-dialog stamp is session-scoped** (in-memory), legacy
  plaintext localStorage swept; argon2id iteration ceiling mirrors the
  backend; i18n test also pins no-extra-keys and no-empty-values.
- **Portal — SAS honesty + local fingerprint cross-check**: the portal
  now verifies the server's wrap-key fingerprint against its OWN wrap
  key and warns on mismatch; comments state plainly that the SAS is a
  server-computed convenience and the locally verified fingerprint is
  the load-bearing check.
- **Portal — idle-lock exactness**: the visibilitychange lock uses
  max(hidden-duration, idle-since-last-interaction); pending TOTP secret
  renders masked with an explicit reveal; scan latch resets on unmount.
- **Mobile — fingerprint tripwire fixed** (`crypto/sharing.ts`
  `serverFingerprintMatches`): the server's 16-hex fingerprint is now
  compared format-correctly; the "key substituted" alert fires only on
  genuine mismatches instead of every pairing.
- **Mobile — fail-closed scheme routing**: a failed envelope fetch plus
  a stale v1 marker now REFUSES the unlock (honest retry copy) instead
  of falling back to the v1-derived key — the silent wrong-key-write
  window is closed for future rotating schemes too.
- **Mobile — notifee fallback spares the sibling reminder**; VS16 emoji
  canonicalization shipped in `brain/sentiment.ts` (was missing bare
  spellings).

## Infrastructure / CI

- **Drift gate fail-closed** (`deploy/monitoring/check-image-drift.sh`):
  registry 404 (deleted tag) FAILs; transport failures retry then FAIL
  loud (`DRIFT_ALLOW_NETWORK_FAIL=1` is the conscious opt-out); a pin
  missing from the inventory FAILs; future-dated inventory rows FAIL.
  Scan scope now includes Dockerfiles and shell scripts (the stale
  superseded postgres digest lived in `backend/scripts/rehearse_restore.sh`
  and was invisible before — re-pinned to the current digest). `--selftest`
  proves every failure mode fails and runs in CI before the live walk.
- **CI secrets hygiene**: the fail-fast annotations no longer echo the
  connection URL's password; the metrics token is generated ONE value
  into the compose secret file chain (no env plaintext hop); release.yml
  gained a `concurrency` group.
- **Time-bomb tests defused**: `test_key_envelope_v2.py` and
  `test_ops_hardening.py` anchored entry dates on the server clock
  instead of fixed dates that age out at UTC midnight (the suite went
  red at 2026-09-28T00:00Z with zero code changes).
- **deploy/README**: digest-pin inventory row for the restore-script pin;
  metrics_token file documented in the secrets runbook.

## Documentation corrections (claims the audit found overstated)

- "envelope_vectors pinned across all three/four clients" — the portal
  does not consume them (no patient-envelope module); web and mobile
  replays are real.
- "item9 … backend side" — the backend stores opaque client-encrypted
  blobs; the item-9 contract is entirely client-side.
- "all suites green" (2026-09-27 commit) — the mobile suite's own
  coverage gate was failing (functions 84.37% < 85); fixed this round by
  real behavioral tests, thresholds untouched.
- The SAS docstrings' "the two screens cannot be made to agree" — both
  SAS strings are server-computed; corrected to the honest threat model.
- `models.py` referenced the wrong migration id for the chain backfill
  (`c6e0b4f8a2d9`, not `c3e9f2a6b8d4`) — fixed.
- `test_auth_api.py::test_logout_revokes_every_token` renamed — it pins
  the single-token contract.
