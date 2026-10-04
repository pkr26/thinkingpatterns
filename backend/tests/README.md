# Backend test suite

Run the regression suite from `backend/`:

```console
../.venv/bin/python -m pytest tests/ -q
```

Every test gets a fresh in-memory SQLite database and a fresh app instance
(`conftest.py`'s `settings`/`app`/`client` fixtures). The process pins
itself to UTC at conftest-import time — see the comment block in
`conftest.py` for why host-local timezones must not leak into the suite.

The app fixture also awaits the initial account-deletion maintenance pass.
This prevents a startup read from rolling back a concurrent request on
in-memory SQLite's shared connection.

The CI gates that must stay green (`../.venv/bin/python -m ruff check .`,
`ruff format --check .`, `mypy`, `pytest tests/ -q`) are documented in
`pyproject.toml` and `.github/workflows/ci.yml`.

---

## Running the suite against real Postgres (one command)

SQLite is the default (fast, hermetic) but is NOT what production runs:
Postgres differs on constraints, locking, transaction semantics, and DDL.
`MINDPATTERN_TEST_DB_URL` switches the whole suite onto a real Postgres
server. The seam is read by `conftest.py::_test_db_url()` and pinned by
`test_pg_profile.py`.

The URL shape is the SQLAlchemy asyncpg dialect — note the `+asyncpg`:

```console
export MINDPATTERN_TEST_DB_URL="postgresql+asyncpg://postgres@127.0.0.1:5432/mindpattern_test"
../.venv/bin/python -m pytest tests/ -q
```

Rules (enforced, not conventions):

- **The database name must contain `test`** — `conftest.py`'s autouse
  cleanup DELETEs every row of every app table after each test and
  refuses to run against any non-SQLite database whose name lacks it.
- A file-backed SQLite URL is accepted only when the file does not exist
  yet, lives under the system temp dir, or you set
  `MINDPATTERN_TEST_DB_ALLOW_EXISTING_SQLITE=1` explicitly.
- Unset the variable and everything silently falls back to in-memory
  SQLite; the Postgres-only tests skip themselves.

### Recipe A: Docker (CI parity)

CI's `backend-postgres` job uses a `postgres:16-alpine` service container
(digest-pinned in `ci.yml`) with `POSTGRES_DB: mindpattern_test`. The
local equivalent:

```console
docker run -d --name mindpattern-test-pg \
  -e POSTGRES_DB=mindpattern_test \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -p 127.0.0.1:5432:5432 \
  postgres:16-alpine

export MINDPATTERN_TEST_DB_URL="postgresql+asyncpg://postgres@127.0.0.1:5432/mindpattern_test"
../.venv/bin/python -m pytest tests/ -q
```

Loopback-only port publishing and trust auth are fine for a throwaway
local container; CI's container uses a password because it is a service
container on a shared runner.

### Recipe B: the `pgserver` pip package (no Docker)

[`pgserver`](https://pypi.org/project/pgserver/) bundles a real Postgres
binary behind a pip install — handy on machines without Docker:

```console
# in a THROWAWAY venv (pgserver is a local convenience, not in the lock —
# CI reaches Postgres via service containers, so the dependency stays out
# of requirements.dev.lock.txt):
python -m venv /tmp/pgserver-venv && /tmp/pgserver-venv/bin/pip install pgserver

/tmp/pgserver-venv/bin/python - <<'PY'
import pgserver
server = pgserver.get_server("/tmp/mindpattern-pgdata")  # persists across runs
if not server.psql("SELECT 1 FROM pg_database WHERE datname = 'mindpattern_test'").strip():
    server.psql("CREATE DATABASE mindpattern_test")
print(server.get_uri())  # base URI — swap the db name, keep the transport
PY

# then point the suite at it, e.g. for a TCP server:
export MINDPATTERN_TEST_DB_URL="postgresql+asyncpg://postgres@127.0.0.1:<port>/mindpattern_test"
# or for a unix-socket URI (pgserver's default) — empty host means "socket":
export MINDPATTERN_TEST_DB_URL="postgresql+asyncpg://postgres@/tmp/mindpattern-pgdata/socket/mindpattern_test"
../.venv/bin/python -m pytest tests/ -q
```

`postgresql+asyncpg://` accepts both TCP and socket transports; whatever
pgserver prints, keep `mindpattern_test` (the name must contain `test`)
as the database component. See pgserver's own README for its API.

### CI parity notes

- CI installs with `pip install --require-hashes -r
  requirements.dev.lock.txt` — the local venv should match that lock
  (asyncpg is pinned there; a drifted local asyncpg is a common source
  of "works in CI, fails locally" PG weirdness).
- The PG job runs the identical suite with no coverage gate; its signal
  is "passes under Postgres semantics".
- Postgres-specific deep coverage lives in PG-gated tests:
  `test_migrations.py::test_postgres_alembic_upgrade_head_and_current`
  and `test_postgres_downgrade_base_upgrade_head_roundtrip` (the latter
  creates and drops its OWN `<name>_downgrade_rt` database derived from
  the URL — a downgrade-to-base destroys data and must never run against
  the shared test database).

---

## Suite layout

The suite combines module tests with regression files grouped by the audit
or mutation campaign that identified each issue. Module docstrings link
findings to their source reports; this index groups suites by topic.

| Layer | Suites | What they pin |
|---|---|---|
| Core engine | `test_patterns`, `test_brain`, `test_brain_api`, `test_phrases`, `test_questions`, `test_statsig`, `test_crisis`, `test_threshold`, `test_es_themes`, `test_structured_channels`, `test_time_of_day` | deterministic extraction, statistics, lifecycle, question engine, crisis interlock |
| Core crypto | `test_crypto`, `test_kdf`, `test_enclave`, `test_sharing_crypto`, `test_encrypt_vectors`, `test_brain_vectors`, `test_key_envelope_v2`, `test_key_zeroize` | envelope crypto, key schedule, enclave windows, cross-platform byte parity, v2 key scheme |
| Core API | `test_auth_api`, `test_account_api`, `test_entries_api`, `test_insights_api`, `test_measures_api`, `test_therapist_api`, `test_feedback_loop`, `test_rate_limit`, `test_note_history`, `test_entry_pagination_bytes` | every endpoint contract, isolation, paging |
| 2026-09-07 remediation | `test_api_hardening` | first API+DB hardening round |
| 2026-09-17 hardening | `test_brain_hardening` | Brown-Forsythe, day-level counting, regex classes |
| 2026-09-19 pentest round 2 | `test_attack_resistance`, `test_dos_hardening`, `test_state_seq`, `test_singleprocess_lock`, `test_repo_secret_scan` | LSH work bounds, cardinality caps, rollback visibility, lock semantics, secret hygiene |
| 2026-09-20 audit | `test_infra_pins`, `test_api_pins`, `test_rotation_pins` | infra + API + rotation pins |
| 2026-09-21 audit + Phase 2 | `test_audit_2026_09_21_backend`, `test_audit_2026_09_21_brain`, `test_audit_round2_2026_09_21_brain`, `test_audit_trail_phase2`, `test_crypto_residuals_phase2`, `test_db_hardening_phase2`, `test_therapist_lifecycle`, `test_local_recompute` | Part 1 findings, audit trail, DB hardening, therapist lifecycle, local recompute |
| 2026-09-22 round 3 | `test_audit_round3_2026_09_22` | third independent-audit wave |
| 2026-09-23 checklists | `test_checklist_round1_crypto_auth` … `test_checklist_round5_sharing_ops` | external verification sweeps (crypto/auth, threshold/tz, brain, crisis, sharing/ops) |
| 2026-09-26 waves | `test_audit_2026_09_26`, `test_audit_2026_09_26_remediation`, `test_pentest_2026_09_26_fixes` | full-codebase audit, remediation pins, deep-pentest fixes (CORS, TOTP fence/throttle/recovery codes) |
| Mutation campaigns | `test_mutation_pins`, `test_deep_mutation_pins`, `test_mutation_round4_pins`, `test_mutation_residuals_documented` | survivors of each hand-written campaign pinned by name; the gate's residual allowlist cross-checked against `docs/SECURITY_RESIDUALS.md` |
| Cross-cutting | `test_hardening`, `test_security_fixes`, `test_contract_pins`, `test_adversarial`, `test_ops_hardening`, `test_api_resilience_coverage`, `test_coverage_gaps`, `test_coverage_services`, `test_infra_coverage`, `test_snapshot_revisions` | production hardening, exact behavioral boundaries, adversarial inputs, cold-branch coverage |
| Infrastructure | `test_migrations`, `test_pg_profile`, `test_totp` | alembic parity + PG round-trips, the PG profile seam, TOTP ladder |
| Property-based (2026-09-26) | `test_property_based` | hypothesis-driven adversarial-input properties for `_parse_entries` and `build_aad` (derandomized; see its module docstring) |

### Regression file names

Audit and mutation harnesses reference these files by name. Preserve their
finding-to-test links when reorganizing tests; a rename must update the
corresponding harnesses and report references.

---

## Conventions worth knowing before adding tests

- **Run tests serially.** Rate counters, key stores, and token epochs are
  process-local, and shared-database cleanup removes rows between tests.
  Parallel workers require separate databases and application state.
- **Use deterministic clocks and work counts.** TOTP tests use
  `helpers.TotpClock` and `install_totp_clock`. Performance tests count
  operations with spies instead of asserting elapsed time; see
  `test_dos_hardening` and `test_attack_resistance`. `test_totp.py` retains
  one documented real-clock smoke test with a generous bound.
- **The `slow` marker is quarantined** to the grandfathered KDF/vector
  pins (see `pyproject.toml`); a ratchet test fails if any other file
  acquires it.
- **Property tests are derandomized** (`test_property_based.py`) so CI is
  reproducible; when investigating locally, drop `derandomize=True`
  temporarily to let hypothesis explore.
