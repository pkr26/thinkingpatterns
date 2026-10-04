# Fathom incident response runbook

**For a mental-health product, an outage or a safety defect is a safety
issue, not just an SLO miss.** This runbook is the operator's checklist.

## Severity levels

| Level | Meaning | Examples | Target first response |
|---|---|---|---|
| **S1** | User safety or data exposure | crisis screen defect; journal plaintext leak; key disclosure | 15 min, all hands |
| **S2** | Service unusable | API down; login broken; recomputes 500ing | 1 hour |
| **S3** | Degraded | elevated latency; one client version broken; rate-limit storms | next business day |

## Detection & escalation (S1)

Alertmanager ships in the operator monitoring stack, but a repository cannot
prove that a real receiver is configured or staffed. Until the operator has
retained a received-page drill, **whoever deployed the system is on-call by
default.**

**Where signals surface today**

| Signal | Source | Notes |
|---|---|---|
| `MindPatternAPIDown`, `MindPatternHigh5xxRatio`, `MindPatternRecomputeP95Slow`, `MindPatternKeystoreSessionsStuck`, audit-chain/journal alerts, audio-deletion backlog/age alerts | `deploy/monitoring/alerts.yml` | Check Prometheus `/alerts`; the rule set is metric-grounded and tested in CI. The keystore alert is the plaintext-retention tripwire. |
| Liveness / readiness | `/healthz`, `/readyz` | The `/readyz` blackbox probe is default-on; readiness requires both the database and configured audit journal to be usable. Production-origin TLS probes remain operator-configured. |
| Backup freshness | `deploy/monitoring/check-backup-freshness.sh` + heartbeat rules | Run during any incident touching the host or DB (step 4 below). |
| Attack-surface regression | weekly `redteam` CI job (Saturdays) | Fails on any new FINDING; the accepted standing set is registered in `docs/SECURITY_RESIDUALS.md`. |

**Escalation ladder (S1 — 15-minute target).** Fill in the bracketed
contacts at deployment; they are deliberately part of this file so the
lives in exactly one place.

1. **0–5 min — whoever sees it**: run "The first five minutes" below and
   declare the severity, with timestamps, in your incident channel.
2. **5–15 min — primary operator** `[OPERATOR_PRIMARY — name/contact]`:
   confirm severity, execute the matching S1 section. Unreachable at
   minute 10 → secondary `[OPERATOR_SECONDARY — name/contact]` takes over.
3. **Safety-content defects** (crisis screen copy, resources): also bring
   in the clinical advisor `[CLINICAL_ADVISOR — contact]` — bad safety
   copy is a user-safety issue even with every system green.
4. **Suspected data exposure**: start the Art. 33 / breach-notification
   clock immediately (see the plaintext-exposure section) and involve the
   DPO `[DPO — contact]` — the 72h runs from awareness, not confirmation.

**Manual operator levers (v1):** account deactivation
(`UPDATE users SET is_active = false WHERE ...` via direct database
access) is reserved for incident response — every auth path checks
`is_active`, but no API or job exposes it (see [deployment boundary](architecture.md#deployment-boundary)).
Token invalidation is rotation of the dedicated `auth_token_secret` file
(`MINDPATTERN_AUTH_TOKEN_SECRET_FILE`), not the root compatibility secret.

## The first five minutes (any severity)

1. **Look at the four signals that exist**: `/healthz` (liveness), `/readyz`
   (database and audit-journal readiness), `/metrics` (status-code families,
   recompute histogram, keystore length, audit-chain/journal failures,
   audit-maintenance backlog/overdue/cycle-age probes, and audio-deletion backlog/age),
   container logs.
2. **Do not restart the database on a hunch** — the evidence must support
   the specific action (restarts destroy the in-memory keystore and rate
   counters; sessions opened in the last TTL window die with them).
3. **Write down the time** — everything below wants timestamps.
4. **Backup freshness** — during any incident that risks the host or the
   database, run `bash deploy/monitoring/check-backup-freshness.sh`
   (nonzero exit = the newest encrypted dump is older than
   `BACKUP_MAX_AGE_HOURS`). A stale backup turns any data-loss incident
   into an S1-scale recovery problem — see Off-site replication below.

## S1: suspected plaintext exposure

The design exposes plaintext in the single-use processing session (server
memory, ≤5 min TTL) and, after purpose-specific consent, to configured speech
transcription/translation providers. Production journal recompute does not
dispatch journal text to an LLM. For anything else claiming "leak":

1. Capture evidence: which endpoint, which auth state, what was observed.
2. Check `/metrics` `mindpattern_keystore_sessions` — an unexpectedly
   LARGE value means processing sessions are not being consumed.
3. If a speech/translation provider is implicated, disable the corresponding
   endpoint/API-key configuration, preserve consent/dispatch evidence, and
   invoke the provider's contractual deletion/incident path.
4. Rotate `auth_token_secret` if bearer tokens are implicated (invalidates
   every session; users re-login). Leave the TOTP-wrap, pairing, decoy, and
   audit-MAC keys unchanged unless the incident specifically compromises one
   of those purposes. See "Rotating purpose-split and audit keys" below.
   `BACKUP_KEY` rotation requires the dual-key procedure (below).
5. Disclosure: journal content is special-category data. Prepare the
   notification per your jurisdiction (GDPR Art. 33: 72h to the SA;
   FTC Health Breach Notification Rule for US non-HIPAA deployments —
   see "Breach-notification clocks" below).

## Breach-notification clocks (GDPR Art. 33/34 + FTC HBNR)

Two independent clocks can run at once. **GDPR (if EU/EEA data
subjects):** notify the supervisory authority within **72 hours of
becoming aware** (Art. 33); communicate to affected data subjects
without undue delay when the risk to them is high (Art. 34) — the
client-side encryption posture is the argument that a ciphertext-only
breach is "unlikely to result in a high risk", and the processing-
session window is where that argument is weakest; make the argument
per-incident, never by default.

**FTC Health Breach Notification Rule (16 CFR Part 318, as amended
2024)** — applies to US deployments that are NOT covered by HIPAA
(the rule explicitly reaches health apps like this one; a deployment
whose therapists are HIPAA-covered entities follows HIPAA's own
60-day rule and BAAs instead/alongside):

- **Trigger**: a breach of unsecured identifiable health information
  (IHI) — acquisition without authorization. Encrypted data where the
  key was NOT compromised is generally NOT unsecured IHI; the moment a
  compromised server could have captured keys or plaintext (the
  processing-session window or a consented speech/translation dispatch),
  assume the trigger.
  **Discovery** = the first day the breach is known, or reasonably
  would have been known with diligence — the clock starts there, not
  at confirmation.
- **≤60 calendar days from discovery — individual notice** (without
  unreasonable delay; 60 days is the ceiling, not the target). Each
  affected individual must receive, in clear language: (1) what
  happened, including the date(s) of the breach and the number of
  individuals affected; (2) the TYPES of unsecured IHI involved (e.g.
  journal text, measures, metadata); (3) steps individuals should take
  to protect themselves (e.g. password change — the product's key
  rotation path is the concrete remedy to point at); (4) what you are
  doing to investigate, mitigate harm, and protect against recurrence;
  (5) contact procedures — a toll-free number, email, website, AND
  postal address.
- **≥500 individuals — FTC notice AND media notice, same 60-day
  ceiling**: notify the FTC electronically (the HBNR form at
  ftc.gov) within 60 days of discovery, AND notify prominent media
  outlets in any state/jurisdiction where ≥500 residents are affected.
- **<500 individuals — annual FTC notice**: report to the FTC within
  60 days AFTER the end of the calendar year in which the breach was
  discovered (batched on the same FTC form). Keep the running log of
  sub-500 breaches so the annual report is not assembled from memory.
- **Log everything** against the timeline: discovery timestamp, key/
  plaintext exposure assessment, notification drafts and send dates.
  The audit log's forward hash chain (`verify_access_log_chain`) is
  evidence of what was actually accessed — run the chain verification
  during the assessment and preserve the output.

**Contact-role table (OPERATOR-FILL at deploy time — this is the one
table the 60-day clock must never wait on):**

| Role | Name / channel | Note |
|---|---|---|
| DPO / privacy lead (owns the 72h + 60-day clocks) | `OPERATOR-FILL` | Art. 33/34 and HBNR filings |
| Incident commander (this runbook) | `OPERATOR-FILL` | = OPERATOR_PRIMARY above unless split |
| Legal counsel (breach counsel, per-jurisdiction) | `OPERATOR-FILL` | determines HIPAA vs HBNR applicability |
| Supervisory authority (EU) | `OPERATOR-FILL` | the member-state SA of the controller's establishment |
| FTC HBNR filing owner (US) | `OPERATOR-FILL` | ftc.gov breach-report form account holder |
| Affected-user comms channel (email/postal/notice page) | `OPERATOR-FILL` | the product has NO user email addresses — plan the in-app + website notice path; postal notice is required for 10+ unreachables |
| Clinical advisor (safety-content incidents) | `OPERATOR-FILL` | = CLINICAL_ADVISOR above |

(The product collects no email/phone by design — that is a privacy
feature that makes individual HBNR notices harder to deliver: plan the
substitute notice mechanism — in-app banner on next login plus a
website notice — and say so in the filing.)

## Rotating purpose-split and audit keys

Production mounts independent files for bearer signing, TOTP wrapping,
pairing-code HMAC, decoy salts, audit MAC, metrics access, backups, and the
legacy/root compatibility secret. Rotate only the compromised purpose:

1. **Bearer compromise:** replace `auth_token_secret`; every outstanding
   bearer becomes invalid and users re-authenticate. Do not change the TOTP,
   pairing, decoy, or audit files.
2. **Pairing compromise:** replace `pairing_secret`; every live 15-minute
   pairing code becomes unusable. Issue new codes.
3. **TOTP-wrap compromise:** the backend has no dual-key rewrap path. Stop
   traffic, preserve the incident evidence, clear `users.totp_secret`,
   `users.totp_enabled`, and `users.totp_last_counter` and delete the matching
   `totp_backup_codes` rows (whose digests use the same key) in one reviewed
   database transaction, then replace
   `totp_wrap_secret`. Every therapist must sign in and enroll a new factor
   before patient-data routes reopen; retain a test of that fail-closed gate.
4. **Audit-MAC compromise/rotation:** never overwrite the current key and
   restart blindly. Stop the API, verify every chain and preserve that output
   plus the journal anchor, then copy the old current key into the file named by
   `MINDPATTERN_AUDIT_MAC_PREVIOUS_SECRETS_FILE` as
   `old-version:64-hex-key`. Generate a distinct 32-byte key for
   `audit_mac_secret`, increment `MINDPATTERN_AUDIT_MAC_KEY_VERSION` in the
   non-secret operator env (never reuse a version), and restart. Require
   `/readyz`, chain verification, and one successful audited action before
   reopening traffic. Duplicate versions/keys or malformed ring entries fail
   boot. Remove a historical entry only after every row and state anchor under
   that version has aged out or an explicit reviewed re-seal migration has
   completed. A missing historical key is loss of audit evidence and is S2.
5. **Root compatibility key:** with all dedicated production secrets present,
   changing it must not be used as a shortcut for any rotation above. Legacy
   deployments must first split every purpose and prove historical audit/TOTP
   compatibility.

Record old/new key versions, custody approvals, change time, pre/post chain
verification, affected sessions/codes, and rollback decision in the incident
timeline. Never put any key bytes in that record.

## S1: crisis-screen defect

The crisis screen is offline static content on the client — a server
outage cannot break it. A CLIENT defect (bad number, broken link) is an
app-release emergency: hotfix, expedite review, and pin a regression test
against `shared/crisis_phrases.json` + the screen copy (both suites gate
this).

## S2: API down

1. `/readyz` 503 → first inspect the readiness response and
   `mindpattern_audit_journal_failures_total`. Check the `db` container and
   Postgres logs for a database failure; use "Audit-journal failure" below if
   the journal is unhealthy. The app is fail-closed on either dependency.
2. `/healthz` failing → the process itself: container logs, OOM (the
   memory limits exist to make this visible), CPU saturation from
   recomputes (`mindpattern_recompute_seconds` histogram — p95 climbing
   past ~5s means the analyze slots are saturated).
3. **Do not scale to a second instance.** The deployment contract is one
   host per database (in-process keystore/locks/counters; the boot guard
   enforces it). Saturation means: shed load (tighten
   `MINDPATTERN_PROCESSING_RATE_LIMIT`), then plan the Redis migration.

## Audit-journal failure

`MindPatternAuditJournalFailure` (S2) means an append or compaction could not
fsync the out-of-database audit anchor. `/readyz` also returns 503 while that
runtime fault remains active; an invalid or unwritable configured path fails
production startup.

1. Stop new traffic. Preserve the database chain-verification output, current
   journal bytes, volume metadata, and failure time; do not delete, truncate,
   hand-edit, or rotate the journal to clear the alert.
2. Inspect capacity, mount presence, ownership, permissions, and storage I/O
   for the existing `auditjournal` volume. Restore that same durable volume;
   starting with an empty replacement destroys the independent tail evidence.
3. After the storage cause is fixed, require a successful audited action (or
   scheduled compaction), `/readyz` 200, and no new counter increment. Run full
   chain+journal verification and retain its output before reopening traffic.
4. If the original journal cannot be recovered or verification fails, keep the
   service closed, classify the affected interval as an audit-integrity loss,
   and follow the breach/evidence assessment rather than silently re-anchoring.

## Audit-maintenance backlog or failure

`MindPatternAuditMaintenanceFailure` (S2) means a bounded retention or
verification pass failed and readiness stays closed until a complete
authenticated pass succeeds. The two persistent-backlog alerts are S3 early
warnings; the two-hour prune-overdue or verification-cycle alerts are S2
because a deletion commitment or timely evidence check has been missed.

1. Preserve the database, journal, durable verifier cursor/checkpoint, and
   reusable journal-index artifact. Do not clear a gauge by deleting evidence,
   resetting a cursor, or bypassing MAC/chain verification.
2. Check `/readyz`, the failure counter, database health, audit-key-ring files,
   journal volume identity/permissions/capacity, and the fixed-text service
   logs. Restore the original inputs; never substitute an empty journal.
3. Compare the bounded pending-row/owner probes across successive scrapes.
   They may stay capped during a large backlog, so also confirm the durable
   cursor advances and prune-overdue/cycle-age eventually decrease. Repeated
   snapshot restarts indicate ongoing writes or checkpoint-integrity failure.
4. Keep one API worker and preserve ordinary request headroom. Do not raise the
   transaction/page bounds merely to silence the alert; repair capacity or the
   failed dependency and let cooperative catch-up drain.
5. Before reopening after an S2 failure, require `/readyz` 200, a complete
   authenticated maintenance pass, stable journal/index evidence, and no new
   failure increment. If the retention deadline was exceeded, involve the
   privacy lead; if verification cannot complete, treat the interval as an
   audit-integrity incident.

## Account-deletion backlog

`MindPatternAccountDeletionBacklogPersistent` (S3) means at least one durable
bounded physical-purge job remained for 30 minutes.
`MindPatternAccountDeletionOldestTooOld` (S2) means the oldest logically erased
account has awaited physical purge for over two hours.
`MindPatternAccountDeletionFailure` (S2) means a worker pass failed; its only
label is the fixed safe category `database`, `object_store`, `state`, or
`unexpected`.

1. Preserve `account_deletion_jobs`, deletion tombstones, and pending audio
   tombstones. Never delete them merely to clear an alert.
2. Confirm `mindpattern_account_deletion_pending_probe` decreases and
   `mindpattern_account_deletion_oldest_seconds` resets. A probe value of 1001
   is saturated: there may be more jobs, but metric work remains bounded.
3. Use the failure category to choose the dependency to inspect. Do not add
   exception text, account identifiers, object keys, or storage paths to
   metrics or routine logs.
4. For `object_store`, restore the original recorded backend/locator and let
   the durable audio tombstone retry. The worker sleeps up to 60 seconds while
   all jobs await a future retry, but a new deletion wakes it immediately.
5. For `state`, preserve the failed transaction and inspect revision exhaustion
   or invalid phase/checkpoint state before repair; do not bypass the atomic
   counterpart-revision fence. For `database`, restore availability and verify
   bounded page commits resume.
6. If the two-hour threshold or the deployment's promised erasure window was
   exceeded, involve the privacy lead and retain job/metric/provider evidence.

## Audio-deletion backlog

`MindPatternAudioDeletionBacklogPersistent` (S3) means at least one durable
tombstone remained for 30 minutes. `MindPatternAudioDeletionOldestTooOld`
(S2) means a deletion has been pending over two hours—longer than the one-hour
maximum retry delay plus multiple default sweeps.

1. Preserve the database tombstones; never delete them to clear the gauge.
2. Confirm the originally recorded backend/locator is reachable with the
   configured least-privilege credentials. Do not redirect an old tombstone to
   a different bucket/path.
3. Restore provider access and wait for the 15-minute default sweep; confirm
   both backlog and oldest-age gauges return to zero and the exact ciphertext
   objects are absent.
4. Check the provider/host-native `audio/` lifecycle rule and the configured
   `MINDPATTERN_AUDIO_LIFECYCLE_CEILING_DAYS`. The application inventory sweep
   removes untracked objects at that ceiling, but a process/provider outage is
   why the independent rule is mandatory.
5. If the ceiling or a promised user deletion window was exceeded, involve the
   privacy lead, preserve object/tombstone/provider evidence, and assess breach
   or rights-request notification obligations.

## Backups

- The compose backup service writes encrypted daily dumps; retention is
  the deletion promise (default 35 days).
- **Rehearse restores** — `bash backend/scripts/rehearse_restore.sh` is
  the scripted rehearsal (add `--remote` to rehearse the off-site,
  host-gone path); an unrehearsed restore is not a backup.
- `BACKUP_KEY` loss = all backups unreadable. Store it in a second secret
  location. Rotation: decrypt-and-redump the corpus under the new key in a
  maintenance window (the dumps are the only ciphertext that does not
  re-encrypt on the live path).

### `BACKUP_KEY` second-location custody

With off-site replication the ciphertext survives the host, so `BACKUP_KEY`
is the **only** path back to plaintext. The requirement, stated plainly:
**the key must survive the host AND the operator** — losing both together
loses the journal corpus. Concrete options (combine at least two):

- **Sealed envelope in a safe** (or a bank safe-deposit box): print the
  `openssl rand -base64 32` value, seal it, and record custody transfers.
- **Password manager with break-glass access**: a shared vault — not just
  the operator's daily account — where a second trusted party can retrieve
  the key under a logged, alarmed procedure.
- **Split knowledge**: split the key across two custodians (two half-keys,
  or an `ssss`-style secret-sharing scheme) so no single person alone can
  decrypt the corpus.

Prove it during every off-site rehearsal: if the second location cannot
produce the key while the exercise pretends the host is gone, you do not
have off-site backups.

### Off-site replication

`deploy/backup-offsite/` is an opt-in overlay that replicates the
`pgbackups` volume to an S3-compatible remote hourly with `rclone copy`
(copy, never sync — replication can never delete from the remote; remote
retention is the operator's lifecycle policy). It ships ciphertext only and
never sees `BACKUP_KEY`. Enable it with the layered command in
`deploy/backup-offsite/README.md` (its non-secret `BACKUP_OFFSITE_*` deployment
choices live in the owner-only operator env, while provider credentials live
only in the mounted `rclone_config` secret; neither belongs in the release env
asset).

**Recovery when the HOST is gone** (database, local backups, and the
compose stack are all lost):

1. New host: follow deploy/README.md "Deploy a tagged release" through
   `compose pull`, but do not serve user traffic yet. Recover
   `/etc/mindpattern/operator.env` plus `/etc/mindpattern/secrets/`; restore
   the `backup_key` file from its second location (above).
2. Start only the database: `compose up -d db`.
3. Fetch the newest ciphertext from object storage with the overlay's
   one-shot mode (a host with the recovered operator env, mounted secret, and
   release assets can run it):
   ```bash
   mkdir -p /srv/restore
   docker compose --env-file "$OPERATOR_ENV" --env-file "$RELEASE_ENV" \
     -f "$APP_DIR/docker-compose.yml" \
     -f "$APP_DIR/deploy/backup-offsite/docker-compose.yml" \
     --profile backups-offsite run --rm -v /srv/restore:/restore \
     -e BACKUP_OFFSITE_MODE=fetch -e BACKUP_FETCH_DIR=/restore backup-offsite
   ```
4. Authenticate before decrypting (the fetch brings the `.hmac` sidecars;
   a missing or mismatching tag is a hard stop), then pipe the decrypt
   straight into the running database — plaintext never touches host disk.
   `$NEWEST` is the bare FILE NAME: `/srv/restore` is the HOST path, the
   containers see the same directory mounted at `/restore`, so every
   in-container reference must be `/restore/$NEWEST` (the rehearsal script
   machine-tests exactly this shape). Select ONLY the dump — never its
   `.hmac` sidecar — and only a dump that HAS its sidecar: newest-first
   over `mindpattern-*.dump.enc`, skipping any candidate without the
   matching `.hmac` (a dump without its sidecar is never a restorable
   backup). This is the exact selection
   `backend/scripts/rehearse_restore.sh` performs in `--remote` mode:
   ```bash
   SECRET_DIR=/etc/mindpattern/secrets
   NEWEST=""
   for f in $(ls -1t /srv/restore/mindpattern-*.dump.enc); do
     [ -f "$f.hmac" ] && { NEWEST=$(basename "$f"); break; }
   done
   [ -n "$NEWEST" ] || { echo "no authenticated mindpattern-*.dump.enc (+ .hmac) in /srv/restore" >&2; exit 1; }
   set -o pipefail
   docker run --rm -i -v /srv/restore:/restore \
     -v "$SECRET_DIR/backup_key:/run/secrets/backup_key:ro" \
     -e BACKUP_KEY_FILE=/run/secrets/backup_key \
     --entrypoint mindpattern-backup-mac "$BACKUP_IMAGE" decrypt "/restore/$NEWEST" \
     | docker compose --env-file "$OPERATOR_ENV" --env-file "$RELEASE_ENV" \
     -f "$APP_DIR/docker-compose.yml" \
     exec -T db pg_restore -U "${POSTGRES_USER:-mindpattern}" -d "${POSTGRES_DB:-mindpattern}" --clean --if-exists
   ```
   (The helper authenticates before emitting plaintext and uses the same
   600,000-iteration KDF and secret resolver as the encryptor; `BACKUP_IMAGE` is the validated `@sha256` reference from the
   release env asset.)
5. `compose up -d --wait` — the api entrypoint runs `alembic upgrade head`
   — then verify `curl http://127.0.0.1:8000/readyz` before serving
   traffic.

**Rehearse this quarterly**: `bash backend/scripts/rehearse_restore.sh
--remote --env-file <operator.env> --env-file <release.env>` IS steps 3–4
— it fetches from the off-site store through the overlay's one-shot mode
(the `BACKUP_OFFSITE_*` values must live in one of the passed `--env-file`
arguments), then authenticates, decrypts via the `/restore/$NEWEST`
container path, and restores into a scratch Postgres, tearing everything
down. An off-site copy that has never been restored from is a hypothesis,
not a backup.

## Post-incident

- Blameless postmortem within 5 business days: timeline, root cause,
  detection gap (what would have caught it sooner), and one concrete
  change wired into CI/monitoring so the class cannot recur silently.
- The repo's own history is the pattern: every audit wave ended with
  regression tests pinning the fix.
