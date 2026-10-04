# Validation evidence

These directories contain dated, scoped validation results. They are retained
because audit reports and manifests refer to the exact logs, screenshots,
fixtures, and source snapshots. They are not runtime dependencies or a statement
of current release readiness.

| Directory | Evidence |
| --- | --- |
| [audit-2026-10-03](audit-2026-10-03/) | Component audit findings and validation logs |
| [remediation-2026-10-03](remediation-2026-10-03/README.md) | Remediation checks, browser journeys, and native review |
| [independent-commit-audit-2026-10-03](independent-commit-audit-2026-10-03/README.md) | Independent regression checks and source manifests |
| [e2e_live](e2e_live/README.md) | Live API and client evidence |
| [simulation1y](simulation1y/SIMULATION_REPORT.md) | Reproducible one-year synthetic simulation |
| [simulation60](simulation60/SIMULATION_REPORT.md) | Reproducible 60-day simulation |
| [Mutation report](mutation_report_2026-09-30.md) | Dated mutation-testing results |

See [current remediation status](../docs/remediation-status.md) for open release
work and the [audit archive](../docs/archive/README.md) for earlier reviews.
Keep new local run output outside version control unless it is deliberately
reviewed and published as synthetic evidence.
