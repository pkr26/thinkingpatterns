# Mutation campaign round 2 (2026-09-18)

Ten campaigns over the areas the 2026-09-18 round-1 campaign (36/36,
`mutation_campaign_2026-09-18/`) did not reach. Same discipline: every
mutant is applied to production code, tested, reverted byte-wise; targeted
survivors are re-verified against the full fast suite; genuine survivors
get pin tests; documented residuals say why they are not pins.

**Headlines**

1. **The portal had effectively no mutation coverage.** First-ever Stryker
   run over `portal/src`: **2,262 mutants, score 1.41%** (32 killed,
   2,098 survived). The 124-test suite pins the *shared* crypto vectors
   but almost nothing portal-specific. The security-critical seams are now
   pinned (see §Portal); the views remain the largest open remediation
   front in the repo.
2. **The red-team harnesses had silently rotted.** The redteam-as-oracle
   campaign (N) found `a_crypto`, `b_auth`, `c_api`, `h_privacy`, `d_llm`
   all crashing at `/auth/register` (500) on the *clean* tree — an
   in-memory-SQLite assumption broken by the Alembic-first startup change —
   and `e2_brain` un-runnable (import order). All repaired this campaign;
   every script now reports 0 harness errors.
3. **The oracle harnesses are good but not self-evident**: 8/10 mutated
   security controls were caught by the attack harnesses; the two that
   sailed through were a self-referential check (read the contract value
   from the code under test — now pinned as constants) and a missing
   wrong-verifier probe (now added). One ALPHA-inflation mutant is a
   documented harness residual; one deletion mutant is equivalent by DB
   cascade.

## Harness hazard found live: stale-bytecode poisoning

Mid-campaign the FULL backend suite began failing 67 tests on a
byte-identical tree (`threshold.py` answered with the H4 mutant's
behavior; a pristine `git worktree` of HEAD passed). Root cause: CPython
validates `.pyc` freshness by source mtime at **second** granularity — a
same-size mutant (2.7→1.0, 45→44, days=1→2) applied and reverted inside
one clock second leaves the *mutated* bytecode cached while the source is
restored. The harness now runs every command with
`PYTHONDONTWRITEBYTECODE=1` and drops the target's `__pycache__` entry
after each restore; all campaign verdicts were re-computed from a purged
tree against a re-confirmed green baseline (1028 passed). The round-1
harness has the same latent flaw — its verdicts were re-derived under
the round-1 protocol at commit time and stand, but future campaigns
should copy the round-2 hygiene.

## Harness hazard found live: corpus-regenerating harnesses + mutants poison fixtures

Running `e_crisis.py` *while the suppress tier was mutated* (campaign N3)
re-exported `redteam/crisis_corpus.json` with every sample's observed
`suppress` verdict flipped to `false` — a tracked fixture poisoned by an
observation made under attack. Restored from git; the campaign driver now
treats corpus exports as clean-tree-only operations. (Rule for harnesses
that write fixtures: never regenerate them from a system under mutation.)

## Campaign results (round 2)

70 hand-written semantic mutants across eight campaigns. Harness:
`redteam/mutation_campaign_2026-09-18_round2/` (results JSONs under
`results/`).

| Campaign | Scope | Mutants | Killed | Targeted survivors |
|---|---|---|---|---|
| G | brain detectors round 2 (EWMA, MinHash/LSH, lag-1 links, replication, residuals, lifecycle boundaries) | 20 | 15 | 5 |
| H | 30-day threshold (distinct-vs-total, 29/30/31, streak grace, backdating, baseline reveal-nothing) | 7 | 7 | 0 |
| I | crypto contract & pairing (HKDF info swap ×2, nonce reuse, pairing TTL/single-use, tampered `shared/*.json` ×3) | 8 | 7 | 1 |
| J | crisis suppression deeper (pool filter, sensitive flag, rumination framing, split variants, benign mask, mobile dialog tier + crisis reachability) | 7 | 5 | 2 |
| K | fail-closed ops (env normalization, secret floor, SQLite, docs, HSTS, body cap, quota) | 7 | 4 | 3 |
| L | idiographic isolation (pooled baseline, population sleep norm, cross-user threshold leak, language gate, mood clamp) | 5 | 3 | 2 |
| M | mobile sync queue (dup suppression, origin pin, capacity, session-expired custody, retry accounting, quarantine) | 6 | 6 | 0 |
| N | **redteam-as-oracle**: mutate a control, check the attack harness notices | 10 | 8 caught | 1 residual + 1 equivalent |
| **total** | | **70** | **55** | **13 targeted → 10 genuine** |

### The oracle question for G (does `probe_brain.py` alone catch it?)

Every G mutant ran against BOTH the unit suite and the ground-truth probe.
The probe alone caught **2 of 20** mutants (G1 EWMA λ, and it corroborates
the link/residual kills); the unit suite is the primary net
(`test_brain.py` alone killed 13). Two honest readings: the probe is a
9-scenario ground-truth check, not a statistical-invariant fuzzer — it
catches *missing planted patterns*, not *loosened thresholds*; and the
detectors' statistical pins (noise sims, false-alarm budgets) live where
they belong, in the suite. Round-2 evidence: G2 (control limit 2.7→1.0),
G4 (autocorrelation inflation off) and G5 (run rule 3→1) all survived
`test_brain.py`+probe but died in the FULL suite — the EWMA honesty pins
live outside the brain's own test module. After this campaign they are
pinned next to the chart (see §Pins).

### Survivor verification (full fast suite, round-1 protocol)

13 targeted survivors re-run against the entire backend fast suite under
the canonical root venv (`verify_survivors.py`; 1028-test green baseline
re-confirmed first): 3 died in the full suite, 10 were genuine — every
one now pinned in `tests/test_mutation_pins_2026_09_18b.py` and
re-verified killed 8/8 by hand-applying the exact mutant (the two
remaining genuine survivors are documented defenses-in-depth, below).

| Mutant | Full suite | Disposition |
|---|---|---|
| G2 EWMA limit 2.7→1.0 | KILLED | `test_audit_fixes.py::test_ewma_limits_are_autocorrelation_aware` |
| G4 autocorr inflation off | survived | **pinned** — tuned AR(1) corpus (φ≈0.81): silent honestly, card at p≈1e-6 without inflation |
| G5 run rule 3→1 | survived | **pinned** — single-spike corpus: one beyond-limit point is not a shift |
| G14 GRACE_DAYS 7→6 | survived | **pinned** — exact boundary: active at stale=7, fading at 8 |
| G15 ARCHIVE_DAYS 45→44 | survived | **pinned** — exact boundary: fading at stale=45, archived at 46 |
| I4 pairing expiry burn dropped | survived | **documented** — `_live_code` already rejects expired codes; the burn's WHERE closes only the lookup→burn race window (defense in depth; pinning would need clock-injection seams) |
| J1 question-pool suppress filter | survived | **documented** — subsumed by the three upstream tripwires (sensitive flag / label / variants) for every current template; guards future templates |
| J2 sensitive flag never set | survived | **pinned** — e2e (crisis rumination card carries `detail.sensitive`) + the label-branch record shape the variants cap cannot reach |
| K1 env normalization | survived | **pinned** — 'DEVELOPMENT'/' Development ' reach the dev gates; no production spelling does |
| K4 /docs always mounted | survived | **pinned** — production app construction mounts neither /docs nor /openapi.json |
| K5 HSTS header dropped | KILLED | `test_mutation_pins.py::test_crypto_and_auth_constants_are_pinned` |
| L2 sleep split vs fixed 3.0 | survived | **pinned** — off-center median corpus (ratings {1,2}): poor nights are exactly the user's sub-median nights |
| L4 language floor 0.10→0.0 | KILLED | `test_brain_hardening_2026_09_17.py` (Spanish gating) |

### Campaign N — redteam-as-oracle (measuring the harnesses)

Each row: one mutated security control → did the attack harness report a
FINDING?

| Mutant | Oracle | Verdict |
|---|---|---|
| keystore pop no longer consumes | a_crypto A1 | **CAUGHT** (single-use FINDING) |
| KDF floor 100k→1 | a_crypto A4 | **CAUGHT after pin** — the original check read `MIN_ITERATIONS` from the code under test (self-referential: a lowered floor lowered the bar it probed). The harness now pins the contract constants `100_000/600_000` independently. |
| suppress tier → False | e_crisis E1 | **CAUGHT** (66/74 corpus divergence) |
| engine ALPHA 0.05→0.5 | e2_brain E2 | **RESIDUAL** — the harness's noise corpora stay silent even at q=0.5 because the effect-size gates and replication gate absorb the inflation; catching it needs a borderline-p planted-association corpus (follow-up in e2_brain). The unit suite pins ALPHA directly (mutant A4, round 1). |
| body cap ×1e6 | c_api C2 | **CAUGHT** (oversized-body FINDING) |
| entry quota off | c_api C2 | **CAUGHT** (quota FINDING) |
| backdating 400 days | c_api C3 | **CAUGHT** (date-backdating FINDING) |
| account verifier check off | b_auth B1 | **CAUGHT after pin** — b_auth never sent a *wrong* verifier, so the mutant sailed through; new `B1.wrong-verifier-rejected` audit asserts flat 403 for a wrong verifier on llm-consent + account-delete (under the mutant it got 409/204). |
| deletion keeps Entry rows | h_privacy H3 | **EQUIVALENT** — `Entry.user_id` is `ondelete=CASCADE` with FK enforcement on, so the DB cascade erases the rows even when the API's explicit delete is skipped. Defense in depth, not a blind spot. |
| LLM digit ban removed | d_llm D2 | **CAUGHT** (sanitizer corpus + egress FINDING) |

**Harness repairs found by this campaign** (all pre-existing on the clean
tree; `bash redteam/run_all.sh` had been green on 2026-09-16):

- `common.make_settings` used in-memory SQLite (`sqlite+aiosqlite://`),
  where every pool connection is a fresh empty DB — the dev-mode startup
  `create_all` laid schema on one connection and `/auth/register` 500'd
  ("no such table: users") on the next, killing 5 of 8 backend scripts
  mid-run. Now a per-process temp FILE database.
- `e2_brain.py` imported `app.services.brain` before `common` set up
  `sys.path` — un-runnable from `redteam/`. Import order fixed.
- `direct_insert_entry` handed a bare `date` to the tz-aware
  `received_at` column (B3/H1/H2 crashes). Now a tz-aware `datetime`;
  same fix in `c_api.py`'s hostile-payload insert.
- `a_crypto` A4 floor probe made self-referential (above).
- `b_auth` B1 missing wrong-verifier probes (above).

## Portal — first Stryker campaign (the biggest gap)

Config: `portal/stryker.config.json` (Stryker + vitest runner, in-place
with byte-verified restore; `npm run test:mutation`). Baseline over all
of `portal/src`:

| File | Mutants | Killed | Survived | Score |
|---|---|---|---|---|
| views/PatientView.tsx | 884 | 5 | 833 | 0.56% |
| views/PatientsView.tsx | 200 | 1 | 177 | 0.50% |
| views/LoginView.tsx | 271 | 0 | 256 | 0.00% |
| api.ts | 428 | 18 | 405 | 4.04% |
| App.tsx | 157 | 1 | 146 | 0.64% |
| crypto.ts | 169 | 6 | 161 | 3.55% |
| platform.ts | 41 | 1 | 39 | 2.38% |
| ui.tsx | 66 | 0 | 66 | 0.00% |
| aad.ts | 15 | 0 | 15 | 0.00% |
| main.tsx | 6 | 0 | 0 | n/a (no coverage) |
| **total** | **2,262** | **32** | **2,098** | **1.41%** |

**Pinned this campaign** (`portal/tests/crypto.pins.test.ts`, each
hand-verified by applying the exact mutant and watching the pin fail):
the two portal-only HKDF subkeys (byte-pinned against backend-derived
references — a round-trip survives ANY self-consistent key), the
identity cross-bindings (a private key sealed for therapist A must not
unlock under B; notes fail under every wrong id of the triple), and the
wrong-key-size guards. Scoped re-run over `crypto.ts`+`aad.ts` after the
pins: the info/context string literals and AAD bindings are now killed;
score 4.35% with the long tail (zeroize internals, equivalent length
guards, formatting fallbacks) remaining. Post-pin FULL-tree re-run:
**1.50%** (34 killed of 2,262) — the security seams are pinned; the
remaining survivors are the views front plus crypto long-tail.

**Documented residuals (honest scope):**
- `views/*` (1,266 mutants, ~0.5%) is unpinned — the drill-down
  ("Why this?"), notes UI, and triage scan have smoke tests only. This is
  the follow-up campaign, now unblocked by the delivered config.
- `aad.ts` survivors include the ensure-ascii boundary (`>= 0x7f` vs
  `> 0x7f`): the vector corpus has no DEL (0x7F) part, so the boundary
  arm is untestable without adding one — noted for the next vector rev.
- Several `MIN_BLOB_SIZE`-adjacent mutants are equivalent (the short-blob
  guard and the GCM failure path both raise the same `TamperError`).

## Mobile — scoped Stryker re-runs (current tree vs the 2026-09-15 99.64% campaign)

The 2026-09-15 campaign pinned the tree as of 09-15. Code shipped since
(keychain custody seam, reconnect flush, canonical origin) is measured
here for the first time:

| Scope | Mutants | Killed | Survived | Score |
|---|---|---|---|---|
| `src/crypto/**` | 212 | 176+1 timeout | 6 (+29 no-cov) | 83.49% (covered 96.72%) |
| `src/offlineQueue.ts` | 452 | 371+24 timeout | 54 (+3) | 87.39% |
| `src/screens/InsightsScreen.tsx` | 885 | 744 | 38 (+103 no-cov) | 84.07% (covered 95.14%) |
| mood/calendar (`mood.ts`,`moodLog.ts`,`HistoryScreen.tsx`) | 1,014 | 704+1 timeout | 192 (+64) | 73.36% |
| crisis (`crisisDetect.ts`,`crisisDialog.ts`,`crisisPhrases.ts`) | 367 | 271+4 timeout | 91 (+1 error) | 75.14% |
| **scoped total** | **2,930** | **2,267** | **381** | **~79%** |

The drop from 99.6% to the mid-80s is new/changed code since 09-15
without equivalent pins — the queue's 54 survivors concentrate in the
post-09-15 reconnect/origin-canonicalization paths. The semantic
non-negotiables of that file are separately guarded by campaign M (6/6
hand-written mutants killed). Full per-mutant triage of the scoped
survivors is the recorded follow-up (the same two-stage discipline:
pin killable, suppress equivalent with a proof comment).

## Pins added this campaign (backend)

`backend/tests/test_mutation_pins_2026_09_18b.py` — 8 pins, each
hand-verified by applying the exact campaign mutant and watching the pin
fail (8/8):

- **G4** EWMA autocorrelation limit inflation (tuned AR(1) corpus).
- **G5** the 3-point run rule (single transient spike is not a shift).
- **G14/G15** exact lifecycle boundaries (GRACE=7, ARCHIVE=45).
- **J2** crisis-adjacent surfaced cards carry `detail.sensitive` (e2e +
  the label-branch record shape).
- **K1** environment normalization ('DEVELOPMENT' reaches dev gates).
- **K4** production mounts no /docs / /openapi.json.
- **L2** the poor-sleep split is strictly below the user's OWN median.

Plus the harness-side pins (campaign N): the a_crypto KDF-contract
constants and the b_auth wrong-verifier-rejected audit.

## CI: per-PR incremental mutation gate

`.github/workflows/mutation-pr.yml` + `redteam/run_pr_mutation_gate.py`:

- **Behavioral layer** (fast, exact): every hand-written campaign mutant
  (round 1 + round 2; 106 total) whose target file appears in the PR diff
  is re-applied and must stay killed. A rotted find-string (SETUP-ERROR)
  also fails the gate — a pin that no longer matches its code stopped
  guarding. Runs the same harnesses, so a PR touching `brain.py` re-runs
  the brain-targeting mutants against targeted suites in minutes, not
  hours. Validated both ways: a `threshold.py` diff re-runs 5/5 killed;
  editing the gated line makes the gate fail with the rotted mutant ids.
- **mutmut layer** (bounded): diff-scoped `mutmut run --paths-to-mutate
  <changed backend files>` under a 20-minute timeout; survivors fail the
  PR; timeout is a neutral warning (the weekly deep run covers the rest).
- No mutmut cache in the PR gate on purpose: verdicts must be computed
  against the PR's code, never restored from an earlier campaign.

## Replay

```bash
# round-2 behavioral campaigns (all)
cd redteam/mutation_campaign_2026-09-18_round2 && ../../.venv/bin/python harness.py
# survivor full-suite verification
../../.venv/bin/python verify_survivors.py
# portal / mobile mutation runs
(cd portal && npm ci && npm run test:mutation)
(cd mobile && npm ci && npx stryker run --mutate "src/crypto/**")
# red-team harnesses (repaired this campaign)
bash redteam/run_all.sh
# per-PR gate driver, locally
git diff --name-only main... | python3 redteam/run_pr_mutation_gate.py -
```
