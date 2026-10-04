# Subprocessor / BAA register — Fathom deployment (TEMPLATE)

Complete for YOUR deployment before enabling each processor. Every placeholder
row has status **BLOCKED / DISABLED**. A URL, API key, bucket, export target,
agent, or SDK must not be configured until that row's activation checklist is
approved. The journal-pattern LLM integration is dormant in production
recompute; configuring legacy variables does not make it an approved feature.

| # | Processor | Role | Data categories disclosed | Region/transfer basis | DPA signed | BAA required | Notes |
|---|---|---|---|---|---|---|---|
| 1 | `OPERATOR-FILL: future journal-LLM provider` | **Dormant; no production journal dispatch** | Would receive journal plaintext if a future reviewed feature reactivates it | `OPERATOR-FILL` — if outside EEA: SCCs/adequacy BEFORE enabling | `OPERATOR-FILL` | `OPERATOR-FILL` — qualified determination required | **BLOCKED / DISABLED.** Reactivation requires code/privacy/clinical review and new consent; legacy `MINDPATTERN_LLM_*` settings are not approval |
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


## Voice journaling subprocessors (added 2026-09-29, VOICE_PLAN.md)

| Subprocessor | Purpose | Data disclosed | Retention | BAA status |
|---|---|---|---|---|
| `OPERATOR-FILL: STT provider` | Speech-to-text transcription of consented recordings | Raw audio, one call per recording; never stored by us | `OPERATOR-FILL: provider retention/deletion terms` | `OPERATOR-FILL` — **BLOCKED / DISABLED until approved** |
| `OPERATOR-FILL: object-storage provider` | Storage of recordings the user chooses to keep | Client-encrypted ciphertext plus object metadata; provider-side encryption at rest | App retention default 30 days; provider-native lifecycle at or below `OPERATOR-FILL: deployed ceiling` | `OPERATOR-FILL` — **BLOCKED / DISABLED until approved and lifecycle evidence attached** |
| `OPERATOR-FILL: translation provider, if distinct` | Translation of consented transcript text | Transcript plaintext for one request | `OPERATOR-FILL: provider retention/deletion terms` | `OPERATOR-FILL` — **BLOCKED / DISABLED until separately disclosed and approved** |

## Fail-closed activation checklist (one copy per enabled row)

- [ ] Processor legal name, product, purpose, data categories, and production
  endpoint/account are recorded.
- [ ] Processing/storage regions, transfers, subprocessors, government-access
  posture, and data-residency choices are recorded.
- [ ] Retention, deletion-on-request, backup deletion, no-training/secondary-use,
  and incident-notification terms match the user disclosure.
- [ ] DPA is executed; SCC/adequacy and transfer assessment are attached where
  applicable.
- [ ] A qualified owner recorded whether HIPAA, HBNR, state consumer-health,
  medical-device, or other sector rules apply; any required BAA is executed.
- [ ] Least-privilege credentials are file-mounted, rotation/revocation is
  rehearsed, and production logs/telemetry do not add undisclosed data.
- [ ] Consent/disclosure version and provider-policy fingerprint are verified
  against the candidate build; withdrawal and provider deletion are tested.
- [ ] Security/privacy owner approval, legal approval, enable date, next review
  date, and evidence links are recorded below.

| Processor row | Status (`BLOCKED`/`APPROVED`) | Security/privacy owner + date | Legal/BAA owner + date | Evidence links | Next review |
|---|---|---|---|---|---|
| `OPERATOR-FILL` | `BLOCKED` | `OPERATOR-FILL` | `OPERATOR-FILL` | `OPERATOR-FILL` | `OPERATOR-FILL` |
