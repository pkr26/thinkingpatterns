# MindPattern — Deep Mutation Testing Report (full-stack run)

> **Historical snapshot — read this first.** This report describes the
> mutation-testing exercise as of its commit (~2026-09-04). Test counts and
> coverage figures below are from that run and differ from HEAD (the suites
> have grown since; see README.md for current numbers). In particular, the
> mobile 100% Stryker score does **not** reproduce at HEAD: the Stryker
> suppression comments it relied on are all still in place, but code added
> since this run has not been through a fresh full Stryker pass (see the
> note in `mobile/stryker.config.json`). The methodology, triage, and
> equivalent-mutant analysis remain valid context.

**Scope:** the ENTIRE application, both sides —
`backend/app/**` (security core, services, every API router, middleware,
cache, config, deps, db, main, schemas; `models.py` excluded, see below) and
`mobile/src/**` (crypto stack, vault, store, offline queue, API client,
navigation, and all six screens).

**Tooling:** mutmut 2.4.4 (backend, pytest runner, fail-fast, `-m 'not slow'`)
· Stryker 10.0.0 + vitest 3 (frontend, `@stryker-mutator/vitest-runner`,
per-test coverage analysis) · Python 3.14 · Node 22

---

## Headline results

| Side | Mutants | Killed | Survived | Score |
|---|---|---|---|---|
| **mobile (Stryker)** | 1,062 | 1,059 (+3 timeout) | **0** | **100.0%** |
| **backend (mutmut), final** | 1,529 | 1,502 | **27** (all equivalent, below) | **98.2%** |
| backend, expanded scope, run 1 | 1,529 | 1,214 | 315 | 79.5% |
| backend, expanded scope, run 2 (after pins) | 1,529 | 1,418 | 111 | 92.7% |

Coverage after this exercise: **backend 100% of lines on every file**
(25/25 files; was 96% with 10 files below 100%), **frontend 100% lines /
statements / functions on every file, ≥98.8% branches on every file**
(the single sub-100% branch is a compiler artifact of an infinite
`for(;;)` pagination loop — a "condition falls through" edge that cannot
exist). Suites: backend 397 tests, frontend 227 tests, all green;
`tsc --noEmit` clean; `verify_vectors` (real compiled modules × shared
vectors) green.

`models.py` is excluded from backend mutation scope deliberately: its
SQLAlchemy column definitions are DDL-level constraints enforced by the
database engine (VARCHAR lengths are not enforced by the SQLite test rig),
so mutants there are structurally unkillable under unit tests rather than
test gaps. `db.py`'s engine construction IS in scope and pinned.

---

## Real bugs found and fixed

1. **`mobile/src/api/client.ts` — the insecure-HTTP warning could never
   fire.** The URL regex captures the scheme as `"http"`, but the check
   compared against `"http:"` — so `insecure` was always `false` and
   `setBaseUrl` never demanded the explicit plain-HTTP consent the security
   model promises. Found by the pre-existing (failing) test; fixed in source.
2. **`backend/app/cache.py` — eviction used the wall clock instead of the
   counter's (injectable) `now`.** `_evict_oldest_locked` called
   `time.time()` while `hit()` accepts `now=...`, so synthetic-clock windows
   were judged against the real clock and every window looked stale. Fixed
   by passing the recording clock through.
3. **Dead state in `InsightsScreen`** (`days`) and a redundant ternary in
   `client.ts` (`body === undefined ? undefined : JSON.stringify(body)`,
   where `JSON.stringify(undefined)` is already `undefined`) — removed.
4. **Pre-existing typecheck failures** (unrelated to tests):
   `noUncheckedIndexedAccess` violations in `parseServerUrl`, `"Booting"`
   missing from `RootStackParamList`, and a quick-crypto `Buffer` type
   mismatch — fixed.

A latent design observation (not fixed, flagged): `InsightsScreen`'s effect
depends on `[load]`, whose identity follows the unmemoized
`refreshActiveDays` from the real store — in production the load effect
re-runs on every render that changes session state. Under the test seam
(stable mocks) the deps are constant, which is why the constant-deps-array
mutants are equivalent there.

---

## Tooling findings (each materially distorted results until worked around)

**Frontend (Stryker 10 + vitest-runner):**
1. The runner's default `vitest.related: true` only ran tests "related" to
   mutated files through vitest's module graph — with our resolve aliases
   that dropped 5 of 15 test files (all crypto/queue/client/engine/vector
   tests) from coverage attribution, marking their kills as survivors.
   `related: false` + `inPlace: true` (the sandbox cannot see
   `../shared/vectors.json`, which lives outside the package) fixed it.
2. **Vitest 3 silently accepts a RegExp value in `toMatchObject`** —
   `{message: /xyz/}` "matches" any string, making such assertions vacuous.
   Every one was rewritten to exact-message or captured-error assertions.
3. Suite-level (collection) failures are not counted as kills by the
   vitest runner — mutants that crash a test file at import read as
   "survived". Test files were restructured so mutants fail at test level
   (lazy `deriveKeys` fixtures, dynamic `engine.ts` imports).
4. `disable-next-line` comments were not honored in this setup; only the
   range form (`// Stryker disable <mutators>` … `restore`) reliably
   suppresses equivalent mutants. Line exclusions were removed from the
   schema in v10.

**Backend (mutmut 2.4.4):** the exit-code normalization from the previous
report (`scripts/mutmut_runner.sh`) remains load-bearing; additionally,
`mutmut apply` mutates the working tree in place — always verify survivors
by hand-applying them before writing tests (several "survivors" turned out
to be exactly-killable; several "obvious" kills turned out to be genuinely
equivalent).

---

## Survivor disposition (frontend: 0 remain)

All 1,062 mutants are killed or timeout-killed. Equivalent mutants were
suppressed at the mutation site with `Stryker disable` comments carrying
their justification inline (constant deps arrays, React-key strings,
`"utf8"` encoding arguments where Node decodes an empty encoding
identically, post-settlement timer cleanup).

## Survivor disposition (backend: 27 remain, every one equivalent)

The final 27 survivors, each verified by hand-applying the mutant to the
source and running the suite:

1. **Provable equivalents** — same observable API/DB behavior on every
   reachable input:
   - `b64decode(validate=True→False)` on the account verifier and login
     verifier: lenient decoding changes which exception path raises, but
     both paths answer the identical `401 invalid credentials` (register's
     salt/verifier and the processing key are NOT equivalent — whitespace
     payloads distinguish them, and tests pin that).
   - CPU-burn placeholders in login (`b"\x00"*32` vs any other bytes): the
     hash result is discarded; only timing is affected, by design.
   - Logout epoch bump `+1 → -1/+2`: token revocation compares for
     inequality — any consistent bump retires every prior token.
   - `first = False → None` in export streaming: both falsy.
   - `response_started = False → None` in middleware: both falsy.
   - `json.dumps(separators=(",", "XX:XX"))` in `build_aad`: the payload is
     a list; the key separator never participates.
   - `Insight.for_date ... or today` in the question-serving path: the
     SELECT already filters `for_date == today`, so the fallback arm is
     unreachable; same for `.limit(1)→limit(2)` behind `.first()`.
   - Internal `ValueError` message strings in the insights payload parser:
     deliberately never echoed (the 400 detail is generic by hardening
     design).
   - Type-alias/annotation-only values under `from __future__ import
     annotations` (`EncryptedItem`, `str | None` → `str & None`).
   - Sentiment `sum(1→2)` scaling and `p+n == 0` vs `p-n == 0`: the ratio
     is invariant under uniform scaling (documented in the prior report;
     re-verified).
   - Keyed-limit bucket prefix strings (`register-name:`/`login-name:`):
     any per-username-unique prefix yields identical throttle behavior;
     the names are pinned by counter-key introspection tests regardless.
   - `@asynccontextmanager` removal on the app lifespan: Starlette
     normalizes the undecorated coroutine — entering and exiting the
     lifespan context initializes and disposes state identically.
   - LLM budget `break → continue` once the char budget is exhausted: the
     budget only decreases, so no later entry can ever be added — both
     control flows produce the identical payload.
   - b64url token padding arithmetic (`rstrip(b"=")` set extension,
     `-len % 4` → `+len % 4`): the base64url quantum sizes that occur make
     both computations produce identical decoding (re-verified from the
     prior report).
2. **Killed across runs 2–3 by the pin batches** — schemas boundaries
   (1-char, min/max, pattern and constraint-removal edges distinguished by
   pydantic-list vs handler-string 422 shapes on every request schema),
   `from_env` inline defaults, exact config error text, middleware
   body-count boundaries observed through a silent ASGI app, keyed-limit
   bucket names via counter introspection, `Retry-After` floor, LLM
   prompt/payload/budget boundaries, non-ASCII `build_aad` escaping,
   validation-handler loc/msg VALUES (not just keys), the `mindpattern`
   logger name and exact log message, question-pool dedup, and
   phrase/theme scan ordering (skip-and-continue vs break).

## Reproduce

```bash
# Backend
cd backend
../.venv/bin/python -m pytest -m "not slow" -q --cov=app --cov-report=term-missing
PATH="$PWD/../.venv/bin:$PATH" ../.venv/bin/mutmut run   # ~2.5 h, full scope
../.venv/bin/mutmut results

# Frontend (Node >= 18)
cd mobile
npm install && npm test                       # 227 tests
npx vitest run --coverage.enabled             # 100% lines/functions everywhere
npx stryker run                               # ~40 s, 100% mutation score
```
