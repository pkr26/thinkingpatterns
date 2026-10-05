# Entire backend mutation campaign — 2026-10-05

The campaign covers all **95 tracked backend production Python files**: 52 application modules, 34 Alembic files, seven utility scripts, `bootstrap_entry_guards.py`, and `probe_brain.py`. Ninety-two files contain eligible mutmut 2.4.4 operators; three empty package initializers contain none. No production file was excluded. Tests and installed dependencies are outside the mutation target scope.

## Current-source dispositions

| Disposition | Canonical controls |
| --- | ---: |
| Killed by runtime behavior assertions | **42,663** |
| Caught by the uncached full application type-check gate | **142** |
| Reviewed equivalent under declared contracts | **1,259** |
| Invalid syntax, independently reproduced by compilation | **25** |
| **Total** | **44,089** |
| Unresolved survivors, timeouts, or oracle errors | **0** |

Equivalent, static and invalid controls receive no runtime kill credit. The [published evidence index](mutation-2026-10-05/README.md), [per-file summary](mutation-2026-10-05/summary.json), and [compressed canonical ledger](mutation-2026-10-05/ledger.json.gz) retain current target hashes and accepted per-ID dispositions.

The original source contained 44,012 operators. Nine production modules received fixes and were re-enumerated and replayed in full, superseding every earlier operator in those modules. Unchanged targets retain evidence from recorded immutable source, dependency and oracle snapshots; their exact target bytes match the final production source. The campaign does not claim that every control ran against one identical final dependency snapshot. Forty supplemental unchanged-module witnesses used current dependencies and add zero canonical IDs.

| Corrected module | Operators | Runtime killed | Type-check caught | Equivalent | Invalid |
| --- | ---: | ---: | ---: | ---: | ---: |
| `app/api/_audit.py` | 1,324 | 1,254 | 32 | 38 | 0 |
| `app/api/account.py` | 1,324 | 1,239 | 17 | 67 | 1 |
| `app/api/insights.py` | 1,186 | 1,123 | 5 | 54 | 4 |
| `app/api/therapist.py` | 1,073 | 1,002 | 2 | 69 | 0 |
| `app/deps.py` | 183 | 175 | 1 | 7 | 0 |
| `app/locks.py` | 106 | 92 | 5 | 9 | 0 |
| `app/middleware.py` | 419 | 399 | 8 | 11 | 1 |
| `app/services/statsig.py` | 533 | 517 | 0 | 16 | 0 |
| `app/singleprocess.py` | 89 | 88 | 0 | 1 | 0 |

## Production fixes

- **Audit indexing:** journal-stat failures return corrupt evidence with `io_failure`, force a subsequent rescan, and retain temporary-index custody until disposal or replacement.
- **Transactions:** failed savepoint flushes discard the audit/audio work owned by that savepoint. Repeated rollback events retain the correct marker until outer completion.
- **Statistics:** the incomplete-beta implementation has a native 10,000-iteration bound, exact symmetry handling and explicit `BetaConvergenceError` for singular, unconverged or invalid results. An arbitrary tiny replacement for cancelled limbs no longer fabricates finite probabilities.
- **Therapist pairing:** retries preserve the clinician ID before rollback expires the ORM object.
- **Process guards:** truncation, identity-write and short-write failures close the newly opened lock descriptor. Short writes raise `OSError`.
- **Middleware:** duplicate deprecation-header detection compares existing header names as bytes.
- **Insights:** both replacements run inside the integrity-error handler, including SQLAlchemy autoflush. Account-deletion races return the documented account-gone error.
- **Overflow locks:** task ownership permits same-task fallback reuse and rejects saturated nested contention with retryable `503`/`service_unavailable` before waiting. This closes self-deadlocks, opposite-shard cycles and mixed dedicated/fallback cycles. Pure dedicated ordered nesting continues to queue; native-capacity probes verify exclusion, handoff, reentry and cancellation cleanup.
- **Account export:** removing an audio provider during a live settings swap cannot silently omit durable recordings from a completed bundle. Durable metadata is inspected and unavailable live audio aborts export. Empty and expired audio collections still complete normally.

## Evidence rules and corrections

Each canonical control changes one operator in an isolated immutable snapshot. Its exact selector group must pass on pristine source first. Runtime credit requires a real pytest CALL failure, HTTP/OpenAPI behavior difference, or asset export/consumption assertion. Collection, setup, teardown, runner errors and timeouts receive no kill credit. Accepted evidence includes canonical positions and source lines, pristine baselines, target-source restoration, and raw verdicts. The [independent audit](mutation-2026-10-05/independent-audit.json) records verification and its scope.

Checksum-only, value-digest and source/AST registry verdicts were withdrawn. Hashes identify provenance. Fixed private allocation, prefix, diagnostic and entropy-width assertions receive no runtime credit. During publication review, **M010117 and M010648** lost their earlier kill credit: changing opaque processing-session and step-up capabilities from 32 to 33 random bytes preserves their URL-safe, owner-bound, expiring, one-use contracts and increases entropy. Their successful behavioral replays and scoped causal reviews are retained separately.

Equivalent means preservation of the declared contract, not identical private bytes or scheduling. Private lock pool-size and capacity variants can change allocations, collision patterns and transient capacity-503 schedules. An earlier pool-size equivalence was withdrawn after a supported native-capacity nested-sharing operation proved that the old implementation could self-deadlock. Its entire module was corrected and superseded by 106 new controls. Native ownership probes retain outer custody after inner contexts exit.

Fresh enrollment, login, recovery, independent HMAC and AES-GCM tests establish variable-length TOTP interoperability, including 21-byte and native-default 32-byte secrets. Private scrypt salt length is also variable under its storage and entropy contract. Public client wire sizes remain tested independently. Invalid schema construction and post-construction mutation of validated requests supply no runtime credit.

Native pagination, history and numerical budgets stay unchanged in accepted tests, including 100-row pages and the 2 MiB export byte budget. Finite-work assertions measure SQL calls and buffers; external timeouts do not establish kills. Historical timeouts were resolved through accepted same-ID replays.

The SQLite review withdrew an initial equivalence for C000016: the backend declares no SQLite 3.43 minimum, so replacing binary `length` with newer `octet_length` breaks older supported engines. Real encrypted BLOB queries on official **SQLite 3.42.0** killed that control and four helper-polarity controls. Seven pristine native cases passed. C000017 preserves the SQLite branch and PostgreSQL BYTEA aliases resolve to the same native implementation.

All 142 static findings have target-file diagnostics and passing uncached full-52-module baselines. All 25 invalid controls independently reproduce `SyntaxError`. Reviewed equivalents have per-ID successful execution and causal producer/schema/invariant evidence; passing sampled tests alone is insufficient. The 284 supplemental domain controls and 220 historical controls remain separate from the canonical total.

## Validation and cleanup

The fresh backend gate passed **3,298 tests** with **98.15% application statement coverage** against the unchanged 95% floor. Six PostgreSQL cases were separately executed successfully. The raw SQLite report also contains one obsolete skip collected before its removal; the replaced private lock-helper test was checked again with behavioral assertions in a four-case cleanup supplement. Together these checks cover **all 3,304 retained backend cases**, with no unresolved skips or failures.

Fresh tooling passed **662 cases**, including the real PostgreSQL and SQLite 3.42 integration profiles, with no skips. The isolated clean-parent runner passed **21 cases** and the utility/probe suite passed **82 cases**. Backend Ruff and uncached Mypy over all 52 application modules pass. Both mutation preflights pass (220 historical and 284 supplemental controls); the repaired A15-03 anchor also passes its pristine baseline and produces an actual HTTP assertion failure when mutated. The [validation artifact](mutation-2026-10-05/validation.json) binds these results to the corrected ledger and independent audits.

Publication cleanup removes one-off disposition scripts, the unused digest oracle, obsolete source-pinning suites, a duplicate generator check, private token/lock pins, and an unconditional skip for an outdated S3 delete-before-put expectation. The current put-before-deferred-delete behavior and fake-S3 storage contracts remain tested. Maintained JSON fixtures retain their full contents with compact storage. CI installs locked dependencies and runs pytest tooling in separate processes so the mutation fork parent starts clean.

The compact evidence index records original hashes, explicit redactions and the local archive boundary. Documentation and staged credential checks also pass before publication.

## Reproduction and archive limits

The checked-in [whole-backend runner](../redteam/run_automatic_backend_mutation.py) can enumerate a new frozen checkout and execute a behavioral oracle plan. Its [guide](../redteam/README.md#whole-backend-automatic-mutation-runner) explains pristine baselines, isolation, operator parity and separate dispositions. Utility/probe contracts remain in [the script oracle suite](../redteam/automatic_backend_script_oracles.py). The [development guide](../docs/development.md#validation) documents the regular tooling commands.

Published compressed evidence supports inspection of accepted identities, verdicts, prerequisite baselines and reviews. Recorded historical paths and hashes identify original sources; they are not promises that every old worker directory is in a fresh clone. Re-executing an archived result requires its exact recorded snapshot, oracle plan, dependencies and runner. Some early custom stages did not retain a standalone execution-runner checksum; the independent audit names those stages. Evidence inspection and a new campaign against current source remain available from the checkout. Temporary worker copies, caches and superseded run output are removed after compact evidence preservation; the published index describes the archive boundary.

## Correction to the September report

The earlier narrative crisis `or`→`and` equivalence claim was incorrect. Suppression-only input such as `the urge for cutting was loud` lies outside dialog detection but inside suppression. An actual narrative rejection test kills this mutant. Streaming exception-envelope and lock-liveness gaps are also covered by behavioral assertions.
