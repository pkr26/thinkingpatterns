# Security validation history

Source paths and shell commands in this guide are relative to the repository root.

## Security & analysis hardening history

This codebase went through an internal multi-pass security program
(red-team harness campaigns, two pentest rounds, full-codebase audits
with independent verification, four mutation-testing rounds, and a
365-day simulation pass) between 2026-09-15 and 2026-09-21. Every
code-fixable finding was remediated and pinned by a regression test that
names the finding it guards; the durable summary lives in CHANGELOG.md
("Security hardening close-out"), and the full per-finding history is
preserved in git history. The executable attack harnesses remain in
`redteam/` (`bash redteam/run_all.sh`).

A dated, scoped E2E campaign extends that history: **the 1-year,
13-user (10 typed + 3 voice) simulation**
(`reports/simulation1y/`, 2026-09-29, **366/366 checks**) drives the routes
listed in its report over live HTTP with the real client crypto — a full
simulated journaling year per persona (including a 365-day pure-noise
control that surfaces zero statistical kinds and a spoken-year voice
control), encrypted PHQ-9 measures, the therapist-sharing lifecycle end
to end, key rotations/rekey/envelope-v2/TOTP, exports, deletion, and
sampled at-rest ciphertext checks and fixed plaintext probes of the raw
database file and audio object store. Recovery, recovery-kit administration,
clinician note rekey and note deletion routes added outside that run are
not covered by its historical result. The voice users exercise the whole voice pipeline against
in-process fake STT/LLM providers: consent walls (voice ≠ LLM
translation consent — the H4 gate), 995 spoken takes transcribed,
translated, and saved as payload-v3 entries, kept-recording
upload/fetch/replace/delete/expiry/quota, the share-voice therapist
playback path with audited access, STT retry/502 behavior, and account
erasure that deletes the audio objects. Re-run instructions and the
per-persona pattern story: `reports/simulation1y/SIMULATION_REPORT.md`.

Facts an operator should know from that history:

- **Statistical honesty is regression-pinned.** All statistical pattern
  kinds pass a replication gate before surfacing; claims carry real
  p-values inside the Benjamini-Hochberg family. Single-shot pure-noise
  runs surface 0 false statistical cards (0/60); daily-cadence pure noise
  surfaces >=1 false card in <=1/24 runs, the survivor being a documented
  FDR-budget boundary case (pinned by
  `test_daily_cadence_pure_noise_replication_bound`).
- **Crisis interlock.** Crisis-adjacent (suicidal-ideation/self-harm)
  rumination or phrase patterns never feed question generation; the
  offline crisis-resources screen is the path instead. Crisis-language
  normalization (NFKC, invisible characters, homograph/leet folding,
  SMS-digit and past-tense forms, Spanish) runs on both engines.
- **Analysis runs on server-validated dates only**; the brain never
  trusts client-controlled dates inside encrypted blobs.
- `probe_brain.py` (9/9 planted-pattern corpus) gates CI and exits
  non-zero on any failure.
- Documented residuals (accepted with written rationale; the full
  register is `docs/SECURITY_RESIDUALS.md`, and the operator-facing
  statement lives in `docs/OPERATOR_PACK.md`): data-key escrow during
  requested recomputes (future ciphertext can use a rotated key, but rotation
  cannot retract disclosed keys or plaintext; the v2 envelope makes the
  credential side O(1), while corpus rekey remains checkpointed); the client KDF is PBKDF2-600k, not Argon2id — the
  documented WebCrypto tradeoff, with the versioned `kdf_params` blob
  ready for a later client switch; the processing enclave is an
  in-process seam (no TEE attestation — deployment work); no TLS
  certificate pinning on mobile (a written decision in
  SECURITY_RESIDUALS: self-hosted deployments cannot have static pins;
  Android ships system-CA-only trust, the iOS user-installed-CA residual
  stands); single-process deployment (in-process counters/keystore/
  locks); the access audit log outlives account deletion for the
  configured 730-day window (defended in the DPIA); historical provider
  retention and separately opted-in voice/translation egress remain
  provider/operator obligations. Narration-only journal dispatch is disabled.
  Both deployment vhosts now align with the clients' self-only style policy
  and blob audio permission. Previously listed and now FIXED: CSP
  `unsafe-inline` in the shipped clients, operator-tooling mutable
  image tags (every compose image is digest-pinned and CI-gated by
  `deploy/monitoring/verify.sh --production`), rekey as a single
  all-or-nothing transaction (now a resumable per-stage journal), note
  last-write-wins edits (now `base_version` compare-and-swap with 409
  `version_conflict`), unversioned measures corrections (DELETE
  correction path, verifier-gated, audit-logged), and the web client's
  plaintext draft-at-lock (now preserved as ciphertext;
  mobile typed drafts are also encrypted on-device for process restart;
  its account/origin-bound RAM fallback can retain unsaved plaintext across
  a lock and is wiped at sign-out. A compromised live app process can read
  its editor state; an unsaved recording is outside the typed-draft backup).
