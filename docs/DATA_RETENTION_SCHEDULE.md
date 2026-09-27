# Data retention schedule — MindPattern

Every retention/deletion number in the product, verified against the
code and configs on 2026-09-26 (file:line given for each). Operators:
your deployed values are the env vars you set — this table is the
default contract; re-verify against your own environment and attach
the result to your Art. 30 RoPA (`docs/DPIA_SKELETON.md` §4b).

| What | Where | How long | Deletion path / mechanism | Source |
|---|---|---|---|---|
| Journal entries (ciphertext) | `entries`, live DB | Until user action — no automatic expiry | Per-entry `DELETE /api/v1/entries/{client_entry_id}`; account delete cascades | models.py; api/entries.py |
| Wellbeing measures (PHQ-9 family, ciphertext) | `measures`, live DB | Until user action | `DELETE /api/v1/measures/{id}` (verifier-gated); account delete cascades | api/measures.py:396 |
| Pattern/insight blobs (ciphertext) | `insights` | Replaced each recompute; kinds upsert per day | Overwritten on recompute; account delete cascades | api/insights.py; models.py `UniqueConstraint(user_id, kind, for_date)` |
| Daily questions | question rows | **90 days**, purged during recompute | Age-based purge at recompute | api/insights.py:95 `QUESTION_RETENTION_DAYS = 90` |
| Brain analysis window (what recompute reads) | in-memory only | **180 days** sliding window (newest entries; SQL-bounded to `MINDPATTERN_RECOMPUTE_ENTRY_LIMIT` = 2000) | Never persisted beyond the insights blobs | services/brain.py:94 `WINDOW_DAYS = 180`; config.py |
| Therapist notes (ciphertext) | `therapist_notes` + immutable revisions | Until either account dies (cascade) or therapist deletes | Cascade on patient OR therapist deletion — the Art. 17 / record-retention tension is documented in SECURITY_RESIDUALS ("Patient deletion destroys therapist notes", flagged for counsel) | models.py `ondelete="CASCADE"` (11 cascade points); SECURITY_RESIDUALS.md |
| Sharing consents (both directions) | `consents` | Until revoke/deletion | Revoke clears the wrapped key (future access ends); account delete cascades both directions | api/consents.py; models.py |
| Caseload summaries | per-consent ciphertext | Null until first post-grant recompute; cleared on revoke | Written inside the processing session; revoke clears | api/therapist.py (caseload summary) |
| Pairing codes | `pairing_codes` (HMAC only) | **15 minutes, single use** | Burned in the grant transaction; expiry sweep | security/sharing.py:77 `PAIRING_TTL_SECONDS = 900` |
| Processing-session keys | in-memory keystore | **≤5 minutes TTL, single use** (`MINDPATTERN_PROCESSING_TTL`, ceiling 300 s) | Consumed at recompute; purged on logout/deletion; destroyed with the process | config.py:43 `MAX_PROCESSING_SESSION_TTL = 300` |
| Session tokens | bearer + `jti` revocation store | `MINDPATTERN_TOKEN_TTL` default **86400 s** (idle ceiling only) | Single-token logout revokes the presented `jti`; rotation/password change/deletion bump the epoch (all tokens) | security/tokens.py; config.py:38 |
| Access audit log (metadata only: actor, action, target, time — never content) | `access_logs`, forward hash-chained per patient | **730 days default** (`MINDPATTERN_ACCESS_LOG_RETENTION_DAYS`, selectable 1–3650), DELIBERATELY surviving account deletion | Startup retention sweep; deletion writes a terminal `account_deleted` chain row | config.py:316 + 622; models.py:468; api/_audit.py; api/account.py:1372 |
| Account row + metadata (username, entry dates/sizes) | `users`, `entries` metadata | Life of account | `DELETE /api/v1/account` (verifier-gated) hard-cascades; audit log survives per above | api/account.py |
| Encrypted database backups | `pgbackups` volume (+ optional off-site) | `BACKUP_RETENTION_DAYS` default **35 days** — this IS the deletion promise for already-deleted rows | Pruned before every backup run; off-site remote retention is the operator's lifecycle policy | docker-compose.yml:195 |
| LLM provider copies (only if a user consented) | third party | Per provider terms (disclosed at consent) | Out of operator hands once sent — disclose in consent copy | api/insights.py LLM path; SECURITY_RESIDUALS `D2.plaintext-egress` |
| Offline queue (ciphertext only) | client: IndexedDB / RN storage | Until flushed (capped 200 items / 1 MB) | Flush uploads then clears; generation fence at sign-out | web/src/offlineQueue.ts |
| Device-local mood log / streaks (pre-threshold) | client, data-key encrypted | Until deletion | Local delete; never synced | web/src/moodLog.ts |
| Journal draft | mobile: memory-only stash (survives lock, wiped at sign-out); web: encrypted slot | Until saved/cleared/sign-out | Account-bound; sign-out wipes | mobile/src/store.tsx:25; web/src/entryDraft.ts |
| Reverse-proxy / API access logs | host nginx / API container | **Disabled** (`access_log off` in the nginx template; uvicorn access logs off in the image) | N/A — keep them off; configure any front tier likewise | deploy/nginx/mindpattern.conf.example; backend image config |
| Metrics (`/metrics`) | in-process counters | Process lifetime (aggregate counts only, no per-user data) | Process restart; token-gated in production | app/metrics.py |

Operator checklist: (1) set `BACKUP_RETENTION_DAYS` to the expiry you
actually promise users; (2) choose `MINDPATTERN_ACCESS_LOG_RETENTION_DAYS`
consciously (the 730-day default is defended in `docs/DPIA_SKELETON.md`
§4 — a shorter window trades auditability for minimisation); (3) if the
LLM path is enabled, transcribe the provider's retention terms into the
subprocessor register and the consent copy; (4) confirm your reverse
proxy does not log request paths at a retention that contradicts this
schedule.
