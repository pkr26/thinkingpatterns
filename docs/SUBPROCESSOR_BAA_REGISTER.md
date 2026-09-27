# Subprocessor / BAA register — MindPattern deployment (TEMPLATE)

Complete for YOUR deployment before enabling each processor. The
product's defaults engage NONE of these rows (no LLM URL set, backups
local-only, no analytics) — the register exists because each row, once
enabled, is a disclosure obligation (GDPR Art. 28/30; state privacy
laws; HIPAA where covered).

| # | Processor | Role | Data categories disclosed | Region/transfer basis | DPA signed | BAA required | Notes |
|---|---|---|---|---|---|---|---|
| 1 | `OPERATOR-FILL: LLM provider (MINDPATTERN_LLM_URL)` | Optional AI narrative analyzer | Verbatim recent journal text (bounded corpus) + deterministic findings; plaintext AT the provider by design; only for accounts that re-authenticated consent | `OPERATOR-FILL` — if outside EEA: SCCs/adequacy BEFORE enabling | `OPERATOR-FILL` | `OPERATOR-FILL` — YES if any sharing therapist is a HIPAA covered entity, or the operator holds the data out as a PHR; else document the determination | Consent copy must mirror the provider's declared retention (`MINDPATTERN_LLM_DATA_RETENTION`); provider name + policy version are fingerprinted into each consent (`MINDPATTERN_LLM_POLICY_VERSION`) |
| 2 | `OPERATOR-FILL: hosting provider (VM/container host)` | Infrastructure | Encrypted at rest by the application (ciphertext, metadata, audit rows); memory-plaintext only within consented processing windows | `OPERATOR-FILL` | `OPERATOR-FILL` | `OPERATOR-FILL` — same HIPAA test: infrastructure hosting PHI under a BAA where covered | The application encrypts content client-side; hosting staff with DB access still see metadata |
| 3 | `OPERATOR-FILL: backup/off-site object storage (deploy/backup-offsite/)` | Encrypted backup replication | BACKUP_KEY-encrypted database dumps only (ciphertext + metadata inside) | `OPERATOR-FILL` — bucket region must be documented | `OPERATOR-FILL` | `OPERATOR-FILL` | The overlay never sees BACKUP_KEY; off-site retention is the operator's lifecycle policy (see DATA_RETENTION_SCHEDULE) |
| 4 | `OPERATOR-FILL: any additional (email, monitoring SaaS, error tracking…)` | — | — | — | — | — | NOTE: the product ships with NO analytics/crash reporting by design — each added processor is a new disclosure and likely contradicts the privacy-policy template's "no tracking SDKs" line; update both together |

**BAA-required flag, explained for rows 1–2.** Sharing journal data
with clinicians can move the OPERATOR into health-data territory
(HIPAA business-associate obligations in the US). The determination is
legal, not technical: if any therapist using the deployment is a
covered entity, or the deployment is marketed as a personal health
record, execute BAAs with every processor that touches the data
(infrastructure and LLM included) or keep those paths off. The
product's architecture (explicit consent records, revocation, access
audit, client-side encryption) is built to make the BAA conversation
short; the obligation itself remains real.

Maintenance rules: review the register at every DPIA review; record
the date each processor was enabled; when a processor is removed,
verify deletion per its contract and close the row with a date.
