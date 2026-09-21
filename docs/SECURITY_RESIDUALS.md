# Accepted security residuals (v1)

Attack-surface findings that the red-team harnesses (`redteam/run_all.sh`)
continue to report as `FINDING`, reviewed and accepted for v1 on 2026-09-21
during the AUDIT_2026-09-21.md remediation. The weekly red-team CI job
(`.github/workflows/redteam.yml`) fails on any FINDING **not** registered
here, and its gate asserts this file names every allowlisted id — removing
an id here (because it got fixed) must also remove it from the workflow's
`DOCUMENTED_RESIDUALS` set; adding one requires a written defense below.

These extend the audit's own residual paragraph (AUDIT_2026-09-21.md,
Part C: immutable analyzer string copies, the base64 data key crossing
`/processing/sessions`, pairing MITM absent the human fingerprint tap,
all-or-nothing epoch revocation) with the standing harness verdicts the
weekly gate must keep allowing. Re-review each entry when its mitigation
changes, and before any v2 security review.

| ID | Harness | Standing verdict and written defense |
|---|---|---|
| `B1.verifier-replay` | b_auth | The auth verifier is password-equivalent by design (the server never sees the password, only scrypt(verifier)) — replaying it equals presenting the password. TLS-only transport plus per-IP/per-username rate limits bound it. |
| `B1.verifier-enables-llm-egress` | b_auth | A replayed verifier can also toggle the opt-in LLM consent (a re-authenticated action). Same password-equivalence class; the egress remains opt-in, disclosed, and per-user. |
| `D2.plaintext-egress` | d_llm | Journal text sent to the configured third-party LLM endpoint is plaintext AT the provider — inherent to optional LLM analysis; opt-in per user, provider and retention disclosed at consent time, off by default. |
| `D2.endpoint-to-card-injection` | d_llm | A hostile LLM endpoint can shape surfaced card copy; the sanitizer length-caps and verifies phrases against the user's actual text, bounding the attack to copy within the app. |
| `D2.slow-endpoint-key-lifetime` | d_llm | A deliberately slow LLM endpoint stretches the single-use processing session's key lifetime for that one request; sessions stay memory-only, single-use, TTL-bounded, purged. |
| `A2.offline-oracle` | a_crypto | The on-device mood log / offline state is an offline password oracle (keys derive from the password) and discloses state to a device holder — the zero-knowledge trade itself; the threat model excludes the device owner attacking their own account. |
| `F2.http-key-shipment` | f_mobile | The data key crosses the wire to `/processing/sessions` — the documented v1 server-side-analysis trade-off (README security note #2): single-use, TLS in production, memory-only, destroyed on consumption. The harness runs cleartext localhost by construction. |
| `H1.metadata-inference` | h_privacy | The server holds per-entry dates and sizes (metadata inference) — documented in README security note #7; content stays opaque. |
| `G3.tracked-secrets` | g_infra | The tracked-secrets hygiene rule matches any git-tracked path ending in `.env`, which catches `mobile/ios/.xcode.env` — the React Native Xcode template that resolves `NODE_BINARY` for script phases. It is REQUIRED to be versioned (the per-developer override is the unversioned `.xcode.env.local`), contains no credential, key, or connection string (only `export NODE_BINARY=$(command -v node)`), and was inspected line-by-line when registered. Re-review if that file ever grows anything beyond the NODE_BINARY export. |
