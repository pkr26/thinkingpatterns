# Data retention schedule — MindPattern

Every retention/deletion number in the product, verified against the
code and configs on 2026-09-26 (file:line given for each). Operators:
your deployed values are the env vars you set — this table is the
default contract; re-verify against your own environment and attach
the result to your Art. 30 RoPA (`docs/DPIA_SKELETON.md` §4b).

| What | Where | How long | Deletion path / mechanism | Source |
|---|---|---|---|---|
| Journal entries (ciphertext) | `entries`, live DB | Until user action — no automatic expiry | Per-entry `DELETE /api/v1/entries/{client_entry_id}`; account delete cascades | models.py; api/entries.py |
| Wellbeing measures (PHQ-9 family, ciphertext) | `measures`, live DB | Until user action | `DELETE /api/v1/measures/{id}` (verifier-gated); account delete cascades | api/measures.py:401-412 |
| Pattern/insight blobs (ciphertext) | `insights` | Replaced each recompute; kinds upsert per day | Overwritten on recompute; account delete cascades | api/insights.py; models.py `UniqueConstraint(user_id, kind, for_date)` |
| Daily questions | question rows | **90 days**, purged during recompute | Age-based purge at recompute | api/insights.py:107 `QUESTION_RETENTION_DAYS = 90` |
| Brain analysis window (what recompute reads) | in-memory only | **180 days** sliding window (newest entries; SQL-bounded to `MINDPATTERN_RECOMPUTE_ENTRY_LIMIT` = 2000) | Never persisted beyond the insights blobs | services/brain.py:94 `WINDOW_DAYS = 180`; config.py |
| Therapist notes (ciphertext) | `therapist_notes` + immutable revisions | Until either account dies (cascade) or therapist deletes | Cascade on patient OR therapist deletion — the Art. 17 / record-retention tension is documented in SECURITY_RESIDUALS ("Patient deletion destroys therapist notes", flagged for counsel) | models.py `ondelete="CASCADE"` (11 cascade points); SECURITY_RESIDUALS.md |
| Sharing consents (both directions) | `consents` | Until revoke/deletion | Revoke clears the wrapped key (future access ends); account delete cascades both directions | api/consents.py; models.py |
| Caseload summaries | per-consent ciphertext | Null until first post-grant recompute; cleared on revoke | Written inside the processing session; revoke clears | api/therapist.py (caseload summary) |
| Pairing codes | `pairing_codes` (HMAC only) | **15 minutes, single use** | Burned in the grant transaction; expiry sweep | security/sharing.py:81 `PAIRING_TTL_SECONDS = 900` |
| Processing-session keys | in-memory keystore | **≤5 minutes TTL, single use** (`MINDPATTERN_PROCESSING_TTL`, ceiling 300 s) | Consumed at recompute; purged on logout/deletion; destroyed with the process | config.py:43 `MAX_PROCESSING_SESSION_TTL = 300` |
| Session tokens | bearer + `jti` revocation store | `MINDPATTERN_TOKEN_TTL` default **86400 s** (idle ceiling only) | Single-token logout revokes the presented `jti`; rotation/password change/deletion bump the epoch (all tokens) | security/tokens.py; config.py:38 |
| Access audit log (metadata only: actor, action, target, time — never content) | `access_logs`, forward hash-chained per patient | **730 days default** (`MINDPATTERN_ACCESS_LOG_RETENTION_DAYS`, selectable 1–3650), DELIBERATELY surviving account deletion | Startup retention sweep; deletion writes a terminal `account_deleted` chain row | config.py:388 (`access_log_retention_days` field) + :712 (1–3650 bounds); main.py:109 / :218 (`_prune_access_log_once` / `_access_log_retention_sweep`); models.py:471 (`AccessLog`); api/_audit.py; api/account.py:1510 (`account_deleted` terminal row) |
| Account row + metadata (username, entry dates/sizes) | `users`, `entries` metadata | Life of account | `DELETE /api/v1/account` (verifier-gated) hard-cascades; audit log survives per above | api/account.py |
| Encrypted database backups | `pgbackups` volume (+ optional off-site) | `BACKUP_RETENTION_DAYS` default **35 days** — this IS the deletion promise for already-deleted rows | Pruned before every backup run; off-site remote retention is the operator's lifecycle policy | docker-compose.yml:268 (`BACKUP_RETENTION_DAYS` wiring, backup service env) |
| LLM provider copies (only if a user consented) | third party | Per provider terms (disclosed at consent) | Out of operator hands once sent — disclose in consent copy | api/insights.py LLM path; SECURITY_RESIDUALS `D2.plaintext-egress` |
| STT provider copies of recordings (only if a user consented; VOICE_PLAN 2026-09-29) | third party | **Zero retention on our side** — audio exists in API memory for ONE upstream transcription call and is never persisted anywhere by us | Provider-side copies per provider terms (disclosed at consent; `MINDPATTERN_STT_DATA_RETENTION`) | api/audio.py (stateless transcription route); services/stt.py |
| Kept voice recordings (client-side AES-GCM ciphertext) | `audio_attachments` rows + S3/local object store | **30 days default** (`MINDPATTERN_AUDIO_RETENTION_DAYS`, selectable 1–3650) | Swept every `MINDPATTERN_AUDIO_SWEEP_INTERVAL_SECONDS` (900 s) + lazy expiry on every fetch; entry deletion cascades row + object (same transaction); account erasure removes rows via cascade and best-effort-deletes every object first (remediated 2026-09-29 — an object-store failure at erasure time is logged and left to the optional S3 lifecycle backstop; the local-dir store has no such backstop, so operators relying on it must verify the scratch dir after an erasure) | config.py `audio_retention_days`; services/audio_store.py `sweep_expired_audio`; api/audio.py `_owner_attachment`; api/entries.py `delete_attachment_for_entry` |
| Therapist voice-access audit rows | `access_logs` (`audio_access` action) | Same 730-day access-log retention as every therapist read | The existing access-log retention sweep | api/therapist.py `read_patient_audio` |
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
