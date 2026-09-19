# Mutation campaign round 3 (2026-09-19): backend infrastructure

Six campaigns over the seams rounds 1–2 did not reach: authorization &
access control, database/ORM, boundaries & business logic, error handling &
transactions, cache/invalidation, and rate limiting/concurrency. Same
discipline as rounds 1–2 (`redteam/mutation_campaign_2026-09-19/`): every
mutant is applied to production code, tested, reverted byte-wise; targeted
survivors are re-verified against the full fast suite; genuine survivors get
pin tests (each hand-verified to kill its mutant, 14/14) or a documented
residual entry saying why it is not a pin.

**Headlines**

1. **62 mutants: 46 killed, 16 genuine, 14 pinned, 2 documented.** 36 died
   at their targeted suites; 10 more died in the full-suite re-verification
   (the two-stage protocol earned its cost — see the survivor table); 16
   were genuine, of which 14 are now pinned in
   `backend/tests/test_mutation_pins_2026_09_19.py` and two are unreachable
   mutants documented below.
2. **The self-referential test trap struck a third time.** Q1 (legacy entry
   page budget ×100) survived its own behavioral test because
   `test_entry_pagination_bytes.py` imports `ENTRY_PAGE_BLOB_BYTES` from the
   code under test and seeds blobs relative to it — the mutant scaled the
   test along with the budget. Round 2 found this pattern in `a_crypto`'s
   KDF-floor probe and `b_auth`'s missing wrong-verifier probe; the new pin
   uses independent literals (two ~1.05 MiB blobs vs a hardcoded 2 MiB).
3. **Defense-in-depth cuts both ways.** O2 (the `is_active` gate in
   `require_user`) is invisible on `/entries` because the route's
   `_fresh_active_entry_user` re-check refuses the same account — but routes
   WITHOUT that deeper gate (`GET /insights`) had no pin at all, so the
   mutant was genuine and is now pinned there. Conversely O6 and S10 are
   *unreachable* mutants (the still-scoped pre-lock read; the outer
   lifecycle fence) — documented, not pinned.

## Campaign results

| Campaign | Scope | Mutants | Killed targeted | Genuine survivors |
|---|---|---|---|---|
| O | authorization & access control (epoch kill switch, is_active, role walls ×2, revoked consent, note scoping, revoke ownership, feature flag, keystore owner binding, enrollment gate, recompute owner pin) | 11 | 7 | 3 → 2 pinned + 1 documented |
| P | database & ORM (load-bearing unique constraints, FK cascade, SQL DISTINCT, pagination tiebreak, upsert set_, delete scope, populate_existing, ownership filter, revision guard) | 10 | 6 | 2 pinned |
| Q | boundaries & business logic (response byte budgets, has_more, note quotas, page sizes, continuation arithmetic, retention windows, caseload caps, wrapped-key bound, inner-date tolerance) | 11 | 8 | 2 pinned |
| R | error handling & transactions (envelope fallback, deep-JSON 400, edge headers, FK→410, unique classification, atomic epoch bump, export admission release, grant conflict mapping, revoke recheck, retry filter) | 10 | 4 | 2 pinned |
| S | cache & invalidation (session TTL, owner purge, per-owner cap, revision markers, phase-gated blobs ×2, note marker, key sweep, recompute serialization) | 10 | 5 | 3 → 2 pinned + 1 documented |
| T | rate limiting & concurrency (limit off-by-one, window rollover, probe counting, eviction policy, stale drop, XFF trust, IPv6 /64, lock overflow, live eviction, single-process guard) | 10 | 6 | 2 pinned |
| **total** | | **62** | **36** | **16 → 14 pinned + 2 documented** |

## Survivor verification (full fast suite, round-1 protocol)

26 targeted survivors re-run against the entire backend fast suite under the
canonical root venv (`verify_survivors.py`; green baseline re-confirmed
first). 10 died in the full suite — each listed with the killing test, a
mapping of targeted-suite blind spots worth knowing about; 16 were genuine.

| Mutant | Full suite | Disposition |
|---|---|---|
| O2 is_active gate dropped | survived | **pinned** — suspended account refused on `GET /insights` (the route without the deeper re-check) |
| O6 note re-fetch scoping dropped | survived | **documented** — unreachable: the pre-lock scoped read 404s a foreign note id before the re-fetch runs; the inner scoping is defense-in-depth for a refactor that drops the pre-check |
| O10 enrollment-token gate removed | survived | **pinned** — wrong/absent `X-Therapist-Enrollment-Token` is a flat 404 when a token is configured; the right one registers |
| O11 recompute pop owner=None | KILLED | `test_adversarial.py::test_processing_token_is_bound_to_its_owner_at_api_level` |
| P3 Entry FK cascade dropped | KILLED | `test_migrations.py::test_migrations_reproduce_create_all_schema` (migration/model parity) |
| P4 SQL DISTINCT dropped | KILLED | `test_insights_api.py::test_get_insights_uses_a_distinct_date_scan` |
| P5 pagination id tiebreak dropped | survived | **pinned** — the metadata page query's ORDER BY must carry entry_date + received_at + id (SQL-shape pin; the blob-fetch query keeps its own ordering, so the pin targets the metadata query specifically) |
| P6 upsert keeps stale blob | survived | **pinned** — a same-day recompute must rewrite the question blob (the existing upsert test only checked row count + decryptability, never that the NEW content wins) |
| Q1 page byte budget ×100 | survived | **pinned** — independent 2 MiB literal; the existing test imported the constant from the code under test |
| Q9 caseload cap 100→10,000 | survived | **pinned** — 100 seeded consent rows; the 101st grant is 413 (filler count is a literal, not the code's constant) |
| Q11 inner-date tolerance 1→30 | KILLED | `test_deep_mutation_pins.py::test_parse_entries_inner_date_tolerance_edges` |
| R1 envelope string fallback removed | KILLED | `test_deep_mutation_pins.py::test_error_envelope_detail_is_always_a_string` |
| R2 deep-JSON 400→500 | KILLED | `test_coverage_gaps.py::test_middleware_maps_recursion_error_to_400` |
| R3 edge responses drop headers | KILLED | `test_coverage_gaps.py::test_middleware_rejects_non_numeric_content_length` (asserts the header set on middleware-produced responses) |
| R7 export admission never released | KILLED | `test_adversarial.py::test_export_has_a_dedicated_rate_bucket` |
| R8 grant conflict re-raises raw | survived | **pinned** — commit-time unique violation maps to the retryable 409 envelope (session-proxy bomb armed on the atomic claim UPDATE) |
| R10 retry filter removed | survived | **pinned** — non-unique IntegrityError propagates on the FIRST attempt (direct route call with fakes; the unique-violation retry path is the positive control). Note: an app-level session-poisoning version of this pin is impossible — the mutant's retry crashes the poisoned session with a different 500, so the pin counts attempts at the function boundary instead |
| S3 per-owner session cap removed | survived | **pinned** — 4 live sessions per account, the 5th is `KeyStoreFull("for account")`, another owner unaffected |
| S5 stale compare `!=`→`<` | survived | **pinned** — a marker AHEAD of the server is still a 409 collection_changed |
| S6 GET /insights ignores phase | survived | **pinned** — after a threshold regression (delete 3 of 32 days) the stored blob is not served in baseline |
| S7 therapist read ignores phase | survived | **pinned** — same regression through the therapist's view |
| S10 recompute lock keying broken | survived | **documented** — API-unobservable: the per-user lifecycle fence the route takes FIRST already serializes recomputes for one account; the inner lock guards a future refactor that drops the fence, not the current shape |
| T4 eviction ignores hit count | KILLED | `test_deep_mutation_pins.py::test_eviction_prefers_single_hit_garbage_over_multi_hit_victim` |
| T6 XFF trusted on flag alone | survived | **pinned** — a forged forwarded identity only wins when the middleware authenticated the direct peer (`mindpattern_trusted_proxy`), with a positive control for the trusted path |
| T7 IPv6 /64 aggregation off | KILLED | `test_mutation_pins.py::test_ipv6_addresses_aggregate_to_64` |
| T8 lock overflow discipline dropped | survived | **pinned** — while the overflow lock is live, an absent key JOINS it even when a stale registry slot could be evicted; otherwise one key can run concurrently with its own overflow-held section |

### What the targeted-suite misses say

The ten full-suite kills cluster into two lessons. First, several pins live
in *general* modules (`test_adversarial`, `test_coverage_gaps`,
`test_deep_mutation_pins`) rather than the feature's own test file —
targeting a campaign by feature file alone under-samples. Second, two of the
misses (R2, R3) were in files the campaign listed, but behind tests whose
*names* don't say middleware (`test_middleware_rejects_non_numeric_content_
length` asserting the header set is a side effect of its main assert).

## Pins added this campaign

`backend/tests/test_mutation_pins_2026_09_19.py` — 15 pins: the 14 campaign
pins below, each hand-verified by applying the exact campaign mutant and
watching the pin fail (`pin_check.py`, 14/14), plus the C3 re-pin found by
the PR gate (hand-verified the same way):

- **O2** suspended account refused on routes without a fresh re-check.
- **O10** therapist enrollment-token gate (wrong/absent header → flat 404).
- **P5** entry page metadata query carries the full deterministic ordering.
- **P6** a same-day recompute rewrites the stored question blob.
- **Q1** the legacy entry-page byte budget is exactly 2 MiB (independent literals).
- **Q9** the therapist caseload cap rejects the 101st grant.
- **R8** a losing concurrent same-pair grant answers the 409 contract.
- **R10** only unique violations are retried during pairing-code allocation.
- **S3** the per-owner processing-session cap.
- **S5** an ahead-of-server snapshot marker is still a conflict.
- **S6/S7** a threshold regression stops serving the stored blob on BOTH the
  patient's and the therapist's view.
- **T6** forwarded identity requires the trusted-peer decision, not just the flag.
- **T8** absent lock keys stay on the overflow lock until it drains.
- **C3** (round-1 re-pin, found by the gate) `pop()` is single-use by
  mechanism — a second pop of the same token raises `KeyNotFound`.

Documented residuals (genuine, deliberately unpinned):

- **O6** — cross-therapist note access via the under-lock re-fetch is
  unreachable today: the pre-lock scoped read 404s a foreign note id first.
  The inner scoping is defense-in-depth; pinning it would require deleting
  the pre-check.
- **S10** — the per-user recompute lock's keying is masked by the outer
  per-user lifecycle fence. Not pinnable without racing the fence itself.

## CI integration: the per-PR gate, hardened by this campaign

Registering round 3 with `redteam/run_pr_mutation_gate.py` (168 behavioral
mutants total) and smoke-testing it against every round-1/2/3 target file
found and fixed three pre-existing gate defects, then two integration gaps:

- **The gate served every mutant with round-1's `run_mutant`**, which only
  accepts a single-suite `tests` dict — any round-2/3 mutant carrying a
  list of suites crashed the gate (`TypeError`). It now uses the round-2
  implementation, which accepts both forms and carries the redteam-oracle
  verdicts and the stale-bytecode/corpus hygiene.
- **Documented residuals failed the gate forever.** A PR touching
  `consents.py` or `questions.py` would have failed on round-2's I4/J1
  (documented defense-in-depth) since the gate first shipped; round 3 adds
  O6/S10 to the same trap. The gate now carries an explicit
  `DOCUMENTED_RESIDUALS` allowlist (I4, J1, N9, O6, S10 — each with its
  report argument) that downgrades their verdicts to a printed note.
- **Killed-elsewhere mutants failed the gate.** The gate replays each
  mutant's *targeted* list; ten round-3 mutants (and round-2's K4/K5) are
  killed only by suites outside those lists. The killing files — including
  this campaign's pins file — are now folded into the mutant definitions,
  so the gate replays the true killers.
- **A round-1 pin had rotted: C3.** The gate re-applied
  "keystore.pop does not consume the token" and nothing in the current
  suite killed it (round 1 recorded 36/36 post-pins). Re-pinned in
  `tests/test_mutation_pins_2026_09_19.py`
  (`test_keystore_pop_is_single_use_by_mechanism`), verified both ways.
  This is the gate working as designed: a pin that rotted is a pin that
  stopped guarding.
- **Oracle replays poisoned tracked result files** (the round-2 corpus
  hazard's sibling, found live): re-running the redteam scripts under an
  oracle mutant rewrites `redteam/results/*.json` with mutant-conditioned
  verdicts. The round-2 harness's `run_mutant` (which the gate now uses)
  snapshots that directory alongside the corpora and restores it after
  every mutant.

End-to-end validation: the gate re-runs **83/83 killed/caught** over a
synthetic diff touching every round-1/2/3 target file, and the full fast
suite is green with all 15 new pins.

## Replay

```bash
# all six campaigns (or a subset: O P Q R S T)
cd redteam/mutation_campaign_2026-09-19 && ../../.venv/bin/python harness.py
# survivor full-suite verification
../../.venv/bin/python verify_survivors.py
# hand-verify every pin kills its mutant (must print 14/14)
../../.venv/bin/python pin_check.py
# the per-PR gate over every round-1/2/3 target file (must print 83/83)
cd /Users/pradeepreddy/Desktop/mental_health_application 2>/dev/null || cd ../..
printf '%s\n' backend/app/api/insights.py backend/app/api/therapist.py backend/app/main.py \
  backend/app/middleware.py backend/app/models.py backend/app/api/account.py \
  backend/app/api/consents.py backend/app/cache.py backend/app/locks.py backend/app/deps.py \
  backend/app/security/enclave.py backend/app/singleprocess.py backend/app/api/auth.py \
  backend/app/api/entries.py | .venv/bin/python redteam/run_pr_mutation_gate.py -
```
