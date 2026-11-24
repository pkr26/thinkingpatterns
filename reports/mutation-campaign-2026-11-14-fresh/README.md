# Fresh mutation campaign: November 14–19, 2026

All **125,982 canonical controls** have verified current execution results.
Backend completion was recorded at **2026-11-19 22:26:29 UTC**. This publication
preserves the completed campaign against frozen source commit
`8e692b8b876ca902c1eb6bf0f7923a008c4c62cf`; it does not describe later code changes
or declare unresolved findings fixed.

| Package | Controls | Killed | Survived | Errors | Timeouts | No coverage | Invalid syntax |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Backend | 44,104 | 39,932 | 3,417 | 670 | 60 | 0 | 25 |
| Web | 34,130 | 33,069 | 943 | 2 | 74 | 42 | 0 |
| Mobile | 41,313 | 39,702 | 1,389 | 1 | 126 | 95 | 0 |
| Therapist portal | 6,435 | 5,925 | 367 | 0 | 109 | 34 | 0 |
| **Total** | **125,982** | **118,628** | **6,116** | **673** | **369** | **171** | **25** |

Errors, timeouts, invalid syntax and no coverage receive **no kill credit**.
Baseline passes and qualification replays add no canonical controls. Effective
frontend outcomes include deadline corrections and the completed web causal
qualification overlay; original raw verdicts remain unchanged in the backup.

The [summary](summary.json) and four gzip JSONL ledgers
([backend](backend-outcomes.jsonl.gz), [web](web-outcomes.jsonl.gz),
[mobile](mobile-outcomes.jsonl.gz), [portal](portal-outcomes.jsonl.gz)) are safe
public exports. Each row includes a canonical package/source/control identity,
raw and effective outcome, credit decision, original artifact reference and a
canonical-JSON record hash. The schema deliberately excludes free-form test
output, tracebacks, contracts, response bodies, status reasons, replacement
strings and parametrized test selectors. The [backup catalog](backup-catalog.json)
pins the private manifest and compressed raw component hashes.

## Recover on another laptop

The byte-exact raw evidence is retained in the access-controlled private backup:

[Private backup release](https://github.com/pkr26/thinkingpatterns-mutation-backup-2026-11-14/releases/tag/fresh-2026-11-14)

Follow [RESTORE.md](RESTORE.md) to download all assets, verify their SHA-256
checksums and restore the original campaign layout with the standalone
[verify/restore helper](verify_restore.py). A public clone contains the compact
ledgers and the trusted catalog; access to the private backup is necessary for
full logs, unmodified raw reports, oracle plans, final receipts and frozen inputs.
Installed dependencies, redundant runtime copies and machine-specific session
orchestration are excluded. No original evidence was deleted during export.

Historical absolute paths inside raw evidence remain unchanged so their hashes
continue to match. The helper maps the old campaign-root prefix to the chosen
extraction root in memory. Source snapshots include old reports only as frozen
input bytes; those reports are not reused as outcomes in these totals.

The raw private logs can contain generated synthetic credentials, encryption
keys and journal text. Keep the backup private; the structured public ledgers are
the deliberately limited publication. The [exporter](archive_campaign.py)
documents the field allowlist, exclusions, byte checks and deduplicated object
format used to create the migration bundle.

The remaining work is survivor triage, investigation of execution errors and
timeouts, coverage improvements and focused reruns. These campaign results are
evidence of completed execution, not approval for a production release.

## Laptop migration checks, November 24

[Remote verification](migration-verification.json) records the download and
SHA-256 verification of all 14 private release assets, followed by verification
of all 111,124 recovered files, all 125,982 controls and the four frozen-source
fingerprints. The [asset index](private-backup-assets.json) lists their exact
names, sizes and checksums. [Clean-restore validation](restore-validation.json)
also records the independent restore and 20 corruption/path-safety checks.

[Code validation](code-validation.json) records 35 planner/runner tests, five
backend pentest tests, 133 focused web tests, web typechecking and focused Python
lint/format checks. Existing assertions and test declarations were preserved.
The web checks used locked dependencies with Node 24.21.0; the repository's
Node 22 version pin remains unchanged.
