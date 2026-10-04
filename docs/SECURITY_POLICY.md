# Security policy (operator-side) — Fathom deployment

What the CODE enforces (so the operator does not have to), and what
the OPERATING ORGANIZATION must own. Adopt, adapt to your
organization's names, and sign. Verified against the tree 2026-09-28.

## Enforced by the codebase (verify, then trust the CI)

- Client-side AES-256-GCM for all content; random data keys in
  password-wrapped envelopes (v2; v1 accounts self-upgrade via
  `POST /api/v1/account/key-envelope/upgrade`); the server never holds
  a KEK input. Password change for v2 is O(1) (`PUT /api/v1/account/password`).
- Server-side verifier hashing scrypt N=2¹⁷ (`MINDPATTERN_SCRYPT_N`;
  note the migration caveat for pre-2¹⁷ fleets in the README env
  table). Argon2id is validated-but-not-computed server-side; no
  client ships it yet.
- Purpose-split server secrets (`MINDPATTERN_AUTH_TOKEN_SECRET`,
  `_TOTP_WRAP_SECRET`, `_PAIRING_SECRET`; legacy `MINDPATTERN_TOKEN_SECRET`
  falls back as the documented identity derivation). Setting the auth
  secret invalidates all bearers cleanly via the `ksv` claim.
- Per-token `jti` revocation at logout; account-wide epoch bump on
  rotation/password change/deletion.
- Exact sliding-window rate limits everywhere (auth/entries/
  processing/reads/export/ops/metrics) with sharded overflow locks;
  strict `_bool_env`/`_int_env` parsing — a typo'd env value refuses
  to boot; edge body-buffer memory budget validated at startup.
- Forward hash-chained access audit log with a terminal
  `account_deleted` row; chain verifier exposes silent edits.
- Fail-closed production posture: production is the default env;
  SQLite, dev secret, and /docs refuse to boot outside exact
  `development`; CORS empty by default; LLM and therapist sharing off
  by default with mandatory provider declarations; `/metrics` 404s
  without its token.
- Digest-pinned deployment contract (every compose image is an
  `@sha256` reference; CI's monitoring-verify fails mutable refs);
  multi-job CI incl. gitleaks full-history secret scans, pip-audit,
  supply-chain pinning, mutation gates, and the red-team weekly job.
- Security headers on every response (nosniff/DENY/no-referrer/
  no-store + HSTS); 2 MiB body cap with a complete-read deadline;
  offline crisis resources in every client.

## Owned by the operator (this policy's actual content)

1. **Secrets custody.** The root compatibility, bearer-signing, TOTP-wrap,
   pairing, decoy, audit-MAC, metrics, database, and backup credentials live
   as separate mode-0600 files under `/etc/mindpattern/secrets/` (or an
   equivalent secret manager), never in a Compose environment file.
   Production requires every purpose-split key. The current audit key is
   exactly 32 bytes as 64 hex characters; audit rows record
   `MINDPATTERN_AUDIT_MAC_KEY_VERSION`, and old `version:64hex` keys remain in
   the file named by `MINDPATTERN_AUDIT_MAC_PREVIOUS_SECRETS_FILE` until their
   rows/state expire. The HKDF root-token fallback is development-only.
   BACKUP_KEY needs a documented second-location
   custody procedure (the runbook's sealed-envelope / break-glass /
   split-knowledge options) — rehearse it quarterly.
2. **Rotation.** Rotate only the affected purpose. Audit-key rotation must
   preserve the old version in the historical file and increment the current
   version before serving new writes. Follow `docs/INCIDENT_RUNBOOK.md`
   "Rotating purpose-split and audit keys"; never overwrite all keys under
   pressure.
3. **Patching & host hardening.** The container images are
   digest-pinned; adopting a new image is a deliberate re-pin through
   the release workflow. Host OS patching, firewalling, and access
   control to the Docker daemon are yours. Single-process deployment:
   do NOT scale to a second API instance against one DB.
4. **Branch protection.** Require the CI check on `main` before first
   deployment (exact `gh api` commands are in `deploy/README.md` —
   the repo cannot enable protection for you). Unprotected main means
   anyone with push access can bypass every gate above.
5. **Monitoring.** Enable the alert stack (`deploy/monitoring/`),
   keep `MINDPATTERN_METRICS_TOKEN` secret, and wire alert delivery to
   a watched channel — until then, whoever deployed is on-call
   (runbook). Rehearse `rehearse_restore.sh` (including `--remote`)
   on a schedule.
6. **Incident clocks.** GDPR 72h and FTC HBNR 60-day obligations are
   operationalized in the runbook; the contact-role table must be
   filled at deploy time, and the substitute-notice path (no user
   emails exist by design) decided BEFORE an incident.
7. **People.** Named roles: incident commander, DPO/privacy lead,
   breach counsel, clinical advisor. Background/least-privilege
   policy for host and DB access is yours to define; DB write access
   can defeat the audit chain's trust anchor (the chain detects
   tampering; it cannot prevent it).
8. **Disclosure.** Publish `security.txt` (template:
   `docs/security.txt.example`), keep the privacy policy in sync with
   the retention schedule, and re-run the DPIA on any architecture
   change.

## Accepted product residuals the operator inherits

Read `docs/SECURITY_RESIDUALS.md` in full before signing. The ones
with operator-facing consequences: plaintext within consented
processing windows (no TEE); PBKDF2-600k client KDF (Argon2id-ready
but not shipped); no mobile TLS pinning (Android system-CA-only; iOS
user-CA residual); single-process scaling boundary; the 730-day
post-deletion audit retention; consented LLM egress is plaintext at
the provider; the patient-deletion/therapist-notes cascade flagged
for counsel.

## Assurance boundary — not yet done (read before relying on this policy)

Everything above is what THIS codebase and THIS documentation enforce
and require; it is not an assurance claim, and the following has NOT
been done as of this writing: no external penetration test has been
performed to date (the repo's red-team suite and the audit waves are
internal artifacts, and self-testing is not independence); there is no
SOC 2 or ISO 27001 certification of any kind, and none of the CI gates
constitutes an audit opinion; the IRB study protocol
(`docs/IRB_STUDY_PROTOCOL.md`) is drafted but NOT yet submitted to a
review board and NO research activity has been executed or cleared; and
`docs/SUBPROCESSOR_BAA_REGISTER.md` is a template only — it lists no
executed BAAs or DPAs because the operator has engaged no vendors yet.
Each of these becomes an operator obligation (or a documented,
accepted gap) at adoption: commission the external test, pursue
certification when the organization is large enough for it to mean
something, submit the protocol before any research use, and execute
the vendor agreements before enabling the features that need them.

| Field | Value |
|---|---|
| Adopted by (org) | `OPERATOR-FILL` |
| Policy owner | `OPERATOR-FILL` |
| Signature / date | `OPERATOR-FILL` |
| Next review | `OPERATOR-FILL` (at least annually) |
