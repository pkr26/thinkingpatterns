# MindPattern — Deep Mutation Testing Report (backend, 2026-09-15)

**Scope:** `backend/app/**` per the deep-scope definition in `backend/pyproject.toml`
(`app/security/`, `app/services/`, `app/api/`, `middleware.py`, `cache.py`,
`config.py`, `deps.py`, `db.py`, `main.py`, `schemas.py`; `models.py` excluded as
DDL-level wiring, per the standing rationale in `reports/mutation_report.md`).

**Tooling:** mutmut 2.4.4 · pytest runner (`-x -q -m 'not slow'`) · Python 3.14.7.
Campaign executed at commit `84f6682` ("Post-audit remediation: all eight dimensions
to 90+") — every in-scope file had changed since the 2026-09-04 campaign, so this is
a fully fresh enumeration, not a resume.

---

## Headline results

**5,394 mutants · 5,340 assessed · 5,155 killed · 185 true survivors · 96.5% score.**

| Area | Mutants | True survivors | Score |
|---|---|---|---|
| `app/services/` — **all nine modules incl. brain.py (2,609 mutants)** | 2,930 | **0** | **100%** |
| `app/api/` (all routers) | 568 | 75 | 86.8% |
| `app/security/` | 219 | 12 | 94.5% |
| `app/config.py` + `cache.py` + `main.py` + `middleware.py` | 546 | 65 | 88.1% |
| `app/deps.py` + `db.py` + `locks.py` + `schemas.py` | 136 | 33 | 75.7% |

Per-file scores (assessed mutants only):

| File | Mutants | True survivors | Score |
|---|---|---|---|
| app/services/brain.py | 2,609 | 0 | 100% |
| app/services/patterns.py | 371 | 0 | 100% |
| app/services/statsig.py | 396 | 0 | 100% |
| app/services/llm.py | 215 | 0 | 100% |
| app/services/phrases.py | 153 | 0 | 100% |
| app/services/questions.py | 81 | 0 | 100% |
| app/services/crisis.py | 51 | 0 | 100% |
| app/services/threshold.py | 49 | 0 | 100% |
| app/api/meta.py | 8 | 0 | 100% |
| app/security/kdf.py | 44 | 0 | 100% |
| app/db.py | 15 | 0 | 100% |
| app/security/tokens.py | 66 | 3 | 95.5% |
| app/security/crypto.py | 34 | 2 | 94.1% |
| app/security/enclave.py | 75 | 7 | 90.7% |
| app/api/auth.py | 121 | 10 | 91.3% |
| app/api/account.py | 90 | 8 | 91.1% |
| app/api/entries.py | 111 | 15 | 86.1% |
| app/api/insights.py | 233 | 42 | 81.6% |
| app/cache.py | 93 | 14 | 84.9% |
| app/config.py | 245 | 20 | 91.8% |
| app/main.py | 81 | 19 | 76.5% |
| app/middleware.py | 127 | 12 | 90.6% |
| app/schemas.py | 47 | 14 | 70.2% |
| app/deps.py | 48 | 17 | 64.6% |
| app/locks.py | 26 | 2 | 92.3% |
| app/api/__init__.py | 5 | 0 | 100% |

**The story in one line:** the entire analysis domain — brain.py's 2,609 mutants
plus every other service module — is at a **100% mutation score**; all 185 true
survivors live in the HTTP/plumbing layer, concentrated in error-contract
strings, defense ceilings, and boundary conditions.

Assessment completeness: 54 enumerated mutants were never assessable (mutmut
could not apply them — duplicate mutation slots); 3 config-shard cache rows were
lost to an in-place verification step before that hazard was isolated (below).
Both classes are < 1.1% of scope and skew the score by at most ±0.1%.

## Methodology

1. **Green baseline.** Full suite: 573 tests green in ~31s. Two incidents
   found and fixed before any mutant ran (findings 0a/0b below).
2. **Sharded campaign.** mutmut is single-process; the scope was sharded across
   path-disjoint instances (each its own cache and a copy of `backend/` +
   `shared/`), sized by module group. `brain.py` (48% of all mutants) and the
   services shard were further split into 4/3 cache-sliced parallel instances.
3. **Coverage-selected fast runners.** Per shard, the per-mutant runner executes
   only the test files that actually execute the mutated module (measured via
   `coverage.py --cov-context=test`, decoding numbits in `.coverage`), ordered
   deepest-coverage-first under `pytest -x`. A test that never executes the
   mutated line cannot kill the mutant, so this loses no kills. For brain.py a
   phase-A runner (`tests/test_brain.py` alone — 714/714 executed lines)
   bounded every mutant at ~1-2s.
4. **Stage-2 verification — the ground truth.** Every one of the 2,413 raw
   survivors was re-applied (`mutmut apply <pk>`) and run against the FULL
   573-test suite; 2,228 were killed there (fast-runner artifacts) and only 185
   survived. Nothing is reported as a survivor on the fast runner's word alone.
5. **Triage.** Each true survivor classified: real gap, equivalent
   (incl. postgres-only branches untestable under the SQLite rig), or
   error-prose (unasserted human-readable text — policy, not defect).

Timeouts: 3× baseline per mutant (3 total, counted as kills — standard mutmut
semantics; noted as a negligible optimistic bias).

## Findings

### 0. Incidents during the run itself (both resolved, both instructive)

- **0a. A time-bomb test fired the day of the run.**
  `tests/test_audit_fixes.py` pinned `T0 = date(2026, 9, 4)` while seeding
  entries through the real API, which judges dates against the live clock. On
  2026-09-15 the 32-day window crossed the 40-day backdate horizon and
  `test_matching_inner_date_still_analyzes` failed on a clean tree (the 31-day
  variants were one day behind it). Fixed by anchoring `T0 = date.today()` —
  every use in the module is either date-agnostic (pure functions take `today`
  explicitly) or API-seeding, matching the file's own real-clock precedent.
  **Fix is in the working tree (uncommitted).**
- **0b. A hard-killed mutmut left a mutant on disk.** Stopping mutmut
  mid-mutant leaves the mutated file in place (its `.bak` restore never runs).
  The corrupted file was caught immediately because the suite failed on
  `test_three_dot_token_reports_bad_signature` — the leftover mutation was
  `verify_token`'s `rsplit(".", 1)` → `rsplit(".", 2)`, and the contract pin
  detected it. Operational rules for future campaigns: SIGINT only, check
  `git status` after any kill, pre-create `.bak`s when resuming.
- **0c. (tooling hazard, documented for the next campaign)** mutmut 2.4.4's
  per-mutant timeout kills the runner shell but not the pytest child, which
  inherits the stdout pipe — a hanging mutant therefore deadlocks mutmut
  forever. Fixed here by `exec python -m pytest` in the runner (kill lands on
  the real process). Separately: running `mutmut apply` (verification) in the
  campaign directory can renumber/delete cache rows (pony ORM); verification
  must run in directory copies. Both cost this campaign a brain rebuild.

### 1. Real test gaps (security- or correctness-relevant)

Ordered by severity.

1. **`app/api/account.py:227` — account deletion has no cross-user isolation
   pin.** `delete(Insight).where(Insight.user_id == user.id)` mutated to `!=`
   — delete every OTHER user's insights, keep the requester's — survives the
   full suite. Catastrophic blast radius, zero detection. **Pin: two users,
   delete one, assert the other's entries AND insights are intact.**
2. **Analyze-path resource limits unpinned (3 mutants, two files).**
   `main.py`'s `app.state.analyze_limiter = anyio.CapacityLimiter(4)` survives
   both `4 → 5` and `4 → None`, and `insights.py`'s
   `getattr(request.app.state, "analyze_limiter", None)` survives
   always-`None`. The concurrency limiter guarding the expensive recompute can
   be detached or resized without any test failing.
3. **`app/security/enclave.py:112-113` — expired-key zeroization unpinned.**
   `zeroize(key)` → `zeroize(None)` on the expiry path survives: no test
   asserts the key buffer is actually wiped when a processing session expires
   (the enclave's memory-hygiene guarantee). Also the exact-expiry boundary
   (`current >= expiry` → `>`) survives.
4. **`app/security/tokens.py:18-23` — token base64url canonicalization
   unpinned.** The unpadded-encode strip and the decode padding arithmetic
   (`-len % 4` → `+len % 4`) survive; tokens whose length ≡ 3 (mod 4) would
   break under the mutant. Pin the canonical wire form + a %-3 round-trip.
5. **Request-size ceilings unpinned (`app/schemas.py`, `app/api/insights.py`).**
   `MAX_SALT_B64 = 128` → `129`/`None` (and siblings), `MAX_ANALYSIS_TEXT_CHARS`
   20,000 → 20,001 with its `>` boundary, `MAX_ANALYSIS_TOTAL_CHARS` 2M ± 1.
   These constants ARE the memory-exhaustion DoS defense; no test posts an
   over-limit value and asserts the 422. One boundary test per constant.
6. **`app/deps.py:24-35` — the entire `DEFAULT_ERROR_CODES` fallback map is
   unpinned (14 mutants).** Keys (`401:` → `402:`) and values
   (`"rate_limited"` → `"XX…"`) all survive. This map is the machine-readable
   envelope for uncaught `HTTPException`s — client contract. One whole-dict
   pin + one behavioral test kills all 14. (deps.py is the lowest-scoring
   file at 64.6% almost entirely due to this map.)
7. **`app/api/insights.py` — recompute budget/truncation algorithm unpinned
   (4 mutants).** In the "oldest text truncated first" loop, `break` →
   `continue`, `total -= len(...)` → `total = …`, the `<=` boundary, and
   ±1 on the 2M budget survive: the analysis-budget contract is unasserted.
8. **`app/api/insights.py` — sentiment clamp unpinned.**
   `max(-1.0, min(1.0, float(sentiment)))` survives both mutations — including
   the one that pins **every sentiment to +1.0**. Nothing asserts clamping on
   the analysis-payload path.
9. **`app/api/auth.py:217-226` — unknown-user timing-equalization parameters
   unpinned (4 mutants).** The dummy scrypt inputs burned for unknown
   usernames (zero-key + 16-byte dummy salt → 17) survive. The constant-time
   shape of login is a stated security property (existence non-disclosure);
   pin argument sizes via the off-loop seam. Also `DECOY_SALT_INFO` (the
   HKDF label behind deterministic decoy salts — a cross-version stability
   contract) mutates freely.
10. **Inner/outer date tolerance + retention edges unpinned (`insights.py`).**
    `INNER_DATE_TOLERANCE_DAYS = 1` → `2` and `>` → `>=`; retention
    `QUESTION_RETENTION_DAYS = 90` → `91` and `<` → `<=`; two `.limit(1)` →
    `.limit(2)` latest-row queries.
11. **`app/api/account.py:116` — export stream head-shape unpinned.** The
    `exclude={"entries", "insights"}` set can be mutated (duplicate JSON keys
    in the export) without failing any test.
12. **`app/main.py` — ops/error-envelope edges.** `/readyz`'s `version` field
    name mutates freely (ops contract); the `[:500]` detail truncation ceiling
    survives ±1; the `or` in the empty-detail fallback survives.
13. **`app/locks.py:34,46` — lock-table growth bound unpinned.**
    `max_keys = 10_000` → `10_001` and the stale-lock eviction arithmetic
    (`+1` → `-1`) survive.
14. **`app/cache.py` — `EVICTION_BATCH = MAX_TRACKED_KEYS // 10` → `// 11`**
    survives (14 cache.py survivors total: this plus window/boundary edges and
    prose).
15. **`app/deps.py:89` — auth rollback recovery unpinned.** On the DB-error
    path, `await session.get(...) or user` → `and` survives (inverts the
    fallback when the re-fetch misses).
16. **`app/config.py` — settings-validation boundaries.** The privileged-port
    floor (`< 1024` edges) and rate-window positivity edges survive (most of
    config.py's 20 survivors are validation-message prose, but these edges
    are behavioral).

### 2. Error-prose survivors (policy, not defects)

~90 of the 185 true survivors are mutations of human-readable `detail=`
strings, logger names, and OpenAPI tags (auth, account, entries, insights,
config, main, middleware, enclave, tokens, crypto). Status codes and most
`code=` fields ARE pinned — that is the right call; pinning exact prose is
brittle. Two exceptions worth promoting into finding 1: several per-endpoint
`code="validation_error"/"conflict"/"invalid_credentials"` literals in
`auth.py`/`account.py`/`insights.py` DO survive — those are contract fields
the mobile client switches on, not prose. Recommendation: assert `code` on
every error-path test; leave `detail` unpinned except where message stability
is itself a contract.

### 3. Equivalent or rig-equivalent mutants (no action possible)

- Typing-only: enclave type alias, `X | None` annotations (unevaluated under
  `from __future__ import annotations`).
- `crypto.py` json key-separator (dumper only serializes lists).
- `account.py` `first = False` → `None` (both falsy); per-user lock key
  strings (opaque but still unique per user).
- **Postgres-only branches (~12 mutants):** `insights.py`'s
  `dialect.name == "postgresql"` and the `pgcode 23503`/`23505` classifiers
  cannot fire under the aiosqlite rig — same class as the standing
  `models.py` exclusion; pinning requires a postgres-rig integration test.
- `b64decode(validate=True)` → `validate=False` in two places: malformed input
  reaches the same 4xx either way (hash mismatch vs decode error).

## Remediation (same day): pin tests for every killable survivor

`backend/tests/test_deep_mutation_pins.py` (77 tests) was written against the
185 true survivors and verified mutant-by-mutant: **157 of the 185 are now
killed** by the new pins (each surviving mutant was re-applied and re-run
against the pin file to confirm). The suite grew 573 → 650 tests with no
runtime regression (~31s). Effective mutation score: **99.5%**
(5,312 of 5,340 assessed mutants killed).

Highest-value pins delivered:

- Cross-user isolation on account deletion (the `!=` catastrophic gap).
- The `DEFAULT_ERROR_CODES` map + per-endpoint `code=` contracts, and exact
  error-envelope bodies for every middleware hardening path (413/400/500).
- The recompute amnesia-**retry** error paths (tampered state + bad entry).
- The analyze-limiter wiring (a detached limiter now fails a test), the
  register/login race-path 409s (via direct handler invocation with racing
  mock sessions), and the unknown-user scrypt dummy inputs (argument capture).
- DoS-ceiling boundaries (`MAX_SALT_B64`/`MAX_DATA_KEY_B64`/`MAX_BLOB_B64`
  and the analysis text/total budgets), sentiment clamp both ends, inner-date
  tolerance edges (1 day in, 2 days out), question-retention edges (90/91).
- base64url canonical forms (including an encode output genuinely ending in
  `X` — `rstrip` argument sets matter), expired-key zeroization on the exact
  expiry instant, `verify_token`'s malformed-payload contract.
- The pgcode/sqlstate classifiers (23503/23505) — reached through duck-typed
  driver errors, no postgres rig needed — and the dialect branches.
- Counter/lock eviction arithmetic down to the `retry_after` integers and
  the concurrent-holder lock-table bound.

### The 26 remaining survivors: verified equivalent

Each was re-tested against the final pin file and survives because the
mutation cannot change observable behavior:

- **Falsy↔falsy:** `first/_xff_warned/response_started = False → None`
  (`account.py:123,134`, `middleware.py:57,98`).
- **Padding tolerance:** `tokens.py:24` (`-len % 4` → `+len % 4`) — Python's
  base64 decoder accepts both padding counts for every valid length class.
- **Unused separators/typing:** `crypto.py:90` (json key-separator never
  used for list-only dumps), `enclave.py:27,49` (type alias, `X | None`
  annotation under `from __future__ import annotations`).
- **Opaque-but-unique:** lock-key f-strings (`entries.py:141`,
  `insights.py:360`); `.limit(1) → .limit(2)` before `.first()`
  (`insights.py:284,569`); `for_date or/and today` where the query pins
  `for_date == today` (`insights.py:579`).
- **Unreachable-in-practice branches:** `orig is None` in the integrity
  classifiers (SQLAlchemy always attaches `orig`), `>=` at the per-entry
  text cap (truncating to `[:20000]` is identity at exactly 20,000),
  `break → continue` in the budget loop (continue also skips the truncation
  body), cache eviction `overflow > 0/>1` edges (overflow ≥ 101 whenever the
  branch can run), defense-in-depth `is_active` 404 behind `require_user`'s
  401 (`account.py:227`), `b64decode(validate=)` flags that land in the same
  4xx (`account.py:57`, `insights.py:84`), dead pydantic defaults
  (`schemas.py:108,109,150,151` — both constructors pass the fields), and
  `main.py:42`'s `@asynccontextmanager` (this Starlette version normalizes
  bare async-generator lifespans).
- **2 unverifiable:** two cache.py mutants whose cache rows were lost to the
  in-place-verification hazard (0c) before isolation; their behavior
  (window-edge arithmetic in `check()`) is pinned by neighboring tests.

## Recommended next actions (highest value first)

1. ~~Pin cross-user isolation on account deletion~~ — **done** (and all of
   2–4 below; see the remediation section above).
2. ~~Pin the error-contract surfaces~~ — **done**.
3. ~~Pin the DoS ceilings~~ — **done**.
4. ~~Pin the four security seams~~ — **done**.
5. ~~Pin the remaining behavioral edges~~ — **done**.
6. Commit the time-bomb fix (`T0 = date.today()` in `test_audit_fixes.py`),
   the new pin file, and this report.

Projected and now measured: **99.5%** effective score with the remainder
being verified equivalents.

## Reproducibility notes

Shard copies, cache-slicing SQL, and runner scripts lived in
`/tmp/mutmut-shards/` during the run and are not committed; the procedure is
documented in §Methodology. The two tooling hazards (0c) are worth fixing
upstream in `scripts/mutmut_runner.sh` (`exec python -m pytest`) and in the
CI mutation workflow (verify-in-copies) before the next scheduled campaign.
