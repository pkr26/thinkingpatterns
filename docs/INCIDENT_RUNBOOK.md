# MindPattern incident response runbook

**For a mental-health product, an outage or a safety defect is a safety
issue, not just an SLO miss.** This runbook is the operator's checklist.

## Severity levels

| Level | Meaning | Examples | Target first response |
|---|---|---|---|
| **S1** | User safety or data exposure | crisis screen defect; journal plaintext leak; key disclosure | 15 min, all hands |
| **S2** | Service unusable | API down; login broken; recomputes 500ing | 1 hour |
| **S3** | Degraded | elevated latency; one client version broken; rate-limit storms | next business day |

## The first five minutes (any severity)

1. **Look at the four signals that exist**: `/healthz` (liveness), `/readyz`
   (DB reachability), `/metrics` (status-code families, recompute
   histogram, LLM failures, keystore length), container logs.
2. **Do not restart the database on a hunch** — the evidence must support
   the specific action (restarts destroy the in-memory keystore and rate
   counters; sessions opened in the last TTL window die with them).
3. **Write down the time** — everything below wants timestamps.

## S1: suspected plaintext exposure

The design exposes plaintext in exactly two places: the single-use
processing session (server memory, ≤5 min TTL) and the consent-gated LLM
egress. For anything else claiming "leak":

1. Capture evidence: which endpoint, which auth state, what was observed.
2. Check `/metrics` `mindpattern_keystore_sessions` — an unexpectedly
   LARGE value means processing sessions are not being consumed.
3. If a third-party LLM endpoint is implicated: disable
   `MINDPATTERN_LLM_URL` at the next deploy (consent per user remains,
   but the egress point dies with the unset URL), and note which accounts
   had `llm_consent_at` set (their data may be in the provider's hands —
   provider retention is disclosed in the consent copy).
4. Rotate `MINDPATTERN_TOKEN_SECRET` if tokens are implicated (invalidates
   every session; users re-login). `BACKUP_KEY` rotation requires the
   dual-key procedure (below).
5. Disclosure: journal content is special-category data. Prepare the
   notification per your jurisdiction (GDPR Art. 33: 72h to the SA;
   FTC Health Breach Notification Rule for US non-HIPAA deployments).

## S1: crisis-screen defect

The crisis screen is offline static content on the client — a server
outage cannot break it. A CLIENT defect (bad number, broken link) is an
app-release emergency: hotfix, expedite review, and pin a regression test
against `shared/crisis_phrases.json` + the screen copy (both suites gate
this).

## S2: API down

1. `/readyz` 503 → database: check the `db` container, then Postgres logs.
   The app is fail-closed by design; it will not serve on a dead DB.
2. `/healthz` failing → the process itself: container logs, OOM (the
   memory limits exist to make this visible), CPU saturation from
   recomputes (`mindpattern_recompute_seconds` histogram — p95 climbing
   past ~5s means the analyze slots are saturated).
3. **Do not scale to a second instance.** The deployment contract is one
   host per database (in-process keystore/locks/counters; the boot guard
   enforces it). Saturation means: shed load (tighten
   `MINDPATTERN_PROCESSING_RATE_LIMIT`), then plan the Redis migration.

## Backups

- The compose backup service writes encrypted daily dumps; retention is
  the deletion promise (default 35 days).
- **Rehearse restores** — `bash backend/scripts/rehearse_restore.sh` is
  the scripted rehearsal; an unrehearsed restore is not a backup.
- `BACKUP_KEY` loss = all backups unreadable. Store it in a second secret
  location. Rotation: decrypt-and-redump the corpus under the new key in
  a maintenance window (the dumps are the only ciphertext that does not
  re-encrypt on the live path).

## Post-incident

- Blameless postmortem within 5 business days: timeline, root cause,
  detection gap (what would have caught it sooner), and one concrete
  change wired into CI/monitoring so the class cannot recur silently.
- The repo's own history is the pattern: every audit wave ended with
  regression tests pinning the fix.
