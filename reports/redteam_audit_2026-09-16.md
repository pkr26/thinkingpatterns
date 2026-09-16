# MindPattern — Full Red-Team Audit Report

**Date:** 2026-09-16 · **Scope:** entire repository (backend, mobile, shared contracts, CI/CD, infra config) · **Method:** executable attack harnesses against the real shipping code — every verdict below is backed by a reproducible script in `redteam/` (runner: `bash redteam/run_all.sh`, machine-readable results in `redteam/results/*.json`, raw verdict lines `AUDIT|<id>|<verdict>|<evidence>`).

**Totals: 96 verdicts — 53 BLOCKED (attack repelled), 32 FINDING, 2 PARTIAL, 8 INFO, 1 NOT-RUN (offline), 0 harness errors.**

Context: this codebase already carries an adversarial test suite (658 backend tests), two deep mutation campaigns (99%+), and four documented remediation waves. This audit measured the surfaces those waves did **not** cover. Many classic web-app attack classes are genuinely closed here (see "Defenses that held"); the findings concentrate in (1) the crisis-language contract, (2) one availability crash in the statistics engine, (3) the documented device-custody TODOs, and (4) deployment-conditional assumptions.

---

## Findings by severity

### P0-1 · Crisis-language detection is bypassable by trivial obfuscation — and bypassed text gets quoted back to the user (E1, E2)

The most serious finding in the audit, by potential for harm to a vulnerable user.

- **Evidence (E1.python-suppress-bypass / E1.ts-dialog-bypass / E1.ts-suppress-bypass):** of 35 crisis-language samples, **30 evade both tiers** of the cross-platform regex contract on *both* engines (they stay in perfect parity with each other — the contract is synced; it is just too narrow). Bypass rate by technique: leetspeak 4/4 (`su1c1de`, `k1ll myself`), homoglyphs 4/4 (Cyrillic `ѕuicide`, `kіll`), zero-width/soft-hyphen 3/3, intra-word punctuation 3/3 (`s.u.i.c.i.d.e`), intra-word spacing 2/2, unlisted plain-English phrasing 4/4 (`off myself`, `put me out of my misery`), **non-English 10/10** (Spanish, French, German, Italian, Portuguese, Chinese, Japanese, Arabic, Hindi).
- **Evidence (E1.bypass-to-question-quote):** of 10 bypassing labels fed to the real question generator, **10/10 are interpolated verbatim into reflective questions**. The full attack chain is: disguised crisis text in journal → pattern-card label → daily question quoting it back. E2.disguised-crisis-recurrence confirms the engine level: `"the s u i c i d e thoughts are loud again"` ×81 days surfaces as a **quoted `recurring_phrase` card with `sensitive=false`**.
- **Root cause:** `backend/app/services/crisis.py` / `mobile/src/crisisPhrases.ts` match raw regex against un-normalized text. There is no NFKC normalization, no homoglyph folding, no invisible-character stripping, no separator collapsing, and the phrase list is English-only.
- **Remediation:** normalize before matching (NFKC → strip zero-width/bidi → collapse non-alphanumeric separators → fold confusable homoglyphs to Latin) on **both** engines, keep it pinned by the existing `shared/crisis_phrases.json` sync tests; add the bypass corpus (`redteam/crisis_corpus.json`) as a regression fixture; treat non-English coverage as a product decision (either add languages or degrade gracefully — see E2.non-latin-corpus: the engine produces no insight value for non-Latin journals at all).
- **Also noted (E1.*.false-positives, P3):** `"that movie was suicide squad"` fires the dialog tier — a known, accepted cost of the conservative tier.

### P0-2 · Recompute permanently 500s for a near-constant-sentiment account — `phi = 1.0` division by zero (C3.mood-shift-phi-1)

A new availability bug that survived the 658-test suite and both mutation campaigns (mutants change code; they do not invent this input shape).

- **Evidence:** a 35-day account whose daily sentiments are equal to within float noise (e.g., journaling near-identical words daily — a realistic "routine responder") makes `_lag1_autocorr` return exactly `1.0`; `brain.py:1224` then evaluates `inflation = (1.0 + phi) / (1.0 - phi)` → `ZeroDivisionError` → **every recompute for that account returns 500 forever** (entries/auth unaffected; no data loss). Reproduced end-to-end through the live API and at engine level (`redteam/c_api.py` victim `c3_phiona`).
- **Remediation:** clamp phi (e.g., `phi = min(phi, 0.99)`) or guard `phi < 1.0` before the division; pin with the 35-day constant-corpus regression.
- Note: 120-day versions of the same corpus survive (E2) — the trigger depends on baseline window size, which makes it more insidious, not less.

### P0-3 · Stolen-device chain: SecureStore device key sits next to its ciphertext; the offline unlock proof is an unthrottled password oracle; a consented HTTP server receives the data key in cleartext (A3, A2, F2.http-key-shipment)

Three independent, individually documented weaknesses that compose into full journal compromise from a device backup or a network observer:

- **A3 (P0):** a simulated device backup (AsyncStorage contents) contains both `@mindpattern/device_k` and the token ciphertext; a 10-line offline AES-GCM snippet recovers the session bearer token. The header of `mobile/src/secureStore.ts` honestly flags Keychain/Keystore custody as pending — it is the top at-rest gap, exactly as the code says.
- **A2 (P1):** the offline unlock proof is an offline password-guessing oracle — measured **73 ms/guess at PBKDF2-600k on one CPU core** with no throttle that an attacker's script honors (the 500 ms UI delay is client-side only), and `verifyUnlockProof` returns `"absent"` vs `"wrong"`, disclosing whether the oracle is enabled for an account. Documented in `unlockProof.ts` as an accepted trade-off; the audit quantifies it.
- **F2.http-key-shipment (P1):** after one consent click, `openProcessingSession` POSTs the **full 32-byte data key in cleartext** to any consented `http://` URL; there is no certificate pinning on any URL. A passive network observer captures the key that decrypts the entire journal. (Their own redirect defense works — it refused the empty-final-URL case during the audit — but the leak is on the first hop, as the client's own comment admits.)

**Remediation:** Keychain/Keystore (`ThisDeviceOnly`) for the device key; make `https://` mandatory for the key-ship flow specifically (consent to plain HTTP for ordinary requests is a defensible BYO-server stance; shipping the data key over it is not); consider a guess-limiting lockout or biometric gate on offline unlock.

---

### P1 findings

- **B1.verifier-replay / B1.verifier-enables-llm-egress — the auth_key is a password-equivalent credential with no revocation.** A captured verifier logs straight back in after logout (epoch revocation kills tokens, not the credential) and flips `llm-consent` ON — the most sensitive setting in the system. Structural to the zero-knowledge design; mitigate with verifier-epoch binding or a re-auth cadence.
- **C1.keystore-fragmentation / C1.rate-limit-fragmentation / C1.quota-race — every in-process guarantee breaks under `--workers 2`, and nothing refuses that configuration.** Live 2-worker uvicorn: one "single-use" session token answered **6/6** recomputes (destroy lands on one worker's keystore only); a 5/min export limit admitted 6–9 of 12 concurrent requests; the entry quota race exceeded quota in some runs (6/5; SQLite narrows the window, Postgres widens it). Also: dev-mode `create_all` races at boot. The docs say single-process; the process does not enforce it. **Cheapest high-value fix in this report:** refuse to boot with >1 worker (or emit a loud startup warning), or move locks/keystore/counter to shared infrastructure.
- **G1.backup-profile-config / G1.dump-contents — unencrypted 35-day pg_dump retention conflicts with the deletion promise.** Acknowledged in `docker-compose.yml` itself; any backup exposes usernames, the full journaling calendar, and ciphertext sizes. Live-dump simulation was not possible (no Docker on the audit host); the dev-DB inspection shows exactly what the columns carry. Pair erasure with encrypted-at-rest backups or a restic-style key rotation on deletion.
- **D2.slow-endpoint-key-lifetime + A1.abandoned-session — server-side plaintext/key exposure windows are wider than the consent copy.** The LLM call runs *inside* `SecureProcessingContext`, so a slow endpoint keeps the data key + decrypted corpus live in server memory for up to the 30 s httpx timeout per recompute (measured: 4 s hang → 4 s exposure). Separately, an opened-but-never-consumed session holds the key in RAM for the full operator TTL (up to 3600 s) with no destroy on client exit. Tighten: call the LLM outside the secure context on a corpus digest, destroy abandoned sessions aggressively, cap TTL closer to the "minutes" the consent text claims.

### P2 findings

- **D1.planted-vocab-injection / D1.spelled-url — the LLM sanitizer's corpus grounding is satisfied by construction.** An entry plants the words (`call five five five zero one three four` / `visit evil dot com`); the model echoes them as a label; grounding passes because the attacker made the user's "own vocabulary" contain the payload, and the URL/phone regex cannot see word-spelled contact strings. Bounded by the 80-char label cap and the kind allowlist — the structural defenses (digit phones, ungrounded vocab, injection imperatives, bad kinds, oversize labels: all dropped; numeric clamps all held) are genuinely solid. Consider n-gram-level grounding or a contact-phrase classifier for labels.
- **D2.endpoint-to-card-injection — a rogue LLM endpoint can plant narratives** (fabricated `work dominates` pattern, occurrences=99, confidence=1.0, stored into the user's encrypted insight blob) within the user's vocabulary. Rogue-operator scenario; the consent model already assumes endpoint trust — record it as an explicit assumption.
- **D2.missing-generation-limits — no `max_tokens`/`temperature`** in the LLM payload (cost/jailbreak surface; the sanitizer still bounds what is stored).
- **D2.plaintext-egress — recorded, by-design:** consent-ON recompute ships decrypted journal text verbatim (4,235 chars of entries JSON, bearer key) to the configured endpoint. The consent gate itself held perfectly (0 requests without consent).
- **B2.xff-direct-origin — with `TRUST_PROXY_HEADERS=1` and direct origin access, one spoofed XFF per request defeats per-IP limits entirely** (20/20 passed a 5/min limit). Deployment-conditional; safe only behind a proxy that always appends its observation.
- **A4.server-accepts-weak-kdf / A4.ts-kdf-no-floor — nothing pins the 600k KDF anywhere at runtime.** Server accepts a 1-iteration registration/login; client `deriveMasterKey` accepts `iterations=1`. Structural (modified client or attacker-chosen registration → trivially crackable keys); a server-side minimum-iterations attestation field in the envelope would at least pin the contract.
- **H1.metadata-inference — quantified:** from `entry_date` + blob length alone, an operator (or backup reader) inferred: journals exclusively on Sundays, a 21-day silence ending 2026-08-02, and that 40% of entries are 10× longer than the rest. Content stays encrypted; behavior does not.
- **E2.disguised-crisis-recurrence** (folded into P0-1) and **F2.detail-sanitizer** — hostile-server strings surviving into the error dialog: scheme-less domains (`evil.com`), digit and spelled-out phone numbers. Character-level tricks (bidi, zero-width) are correctly stripped.

### P3 findings

- **A5.nonce-seam** — production `encrypt()` accepts a caller-supplied nonce on both platforms (test seam shipped; birthday risk within quota is negligible at P≈6.3e-22, so this is hygiene).
- **A5.no-rekey-path (INFO-elevated)** — no password change/rotation/re-key exists; a compromised master secret has no recovery, a forgotten password is permanent loss (documented design).
- **G2.lockfile-hashes** — `requirements.lock.txt` carries no `--hash` pins (installed `--no-deps`; pip-audit clean today).
- **H2.export-cleartext-fields** — export bundle carries username + KDF salt in cleartext (content is ciphertext-only; export is auth-scoped).
- **B2.fixed-window-boundary / B2.eviction-flood (both PARTIAL)** — classic fixed-window doubling at the boundary (20 hits in ~1 s vs 10/s nominal, bounded by the capacity limiters), and eviction-flooding is possible but costs ~121k requests to reset one bucket (the smallest-count/oldest eviction bias makes it strictly worse than waiting).
- **C1.server-boot (INFO)** — the app boots happily under `--workers 2` (see P1); **C3.entry-recycling (INFO)** — an account can rewrite its own evidence trail (self-affecting only); **C2.meta-unauthenticated (INFO)** — `/meta`+`/healthz` are unauthenticated by design and leak no user data; **F1.draft-survives-lock (INFO)** — the plaintext draft survives vault lock in the JS heap by design (wiped on sign-out; no Android FLAG_SECURE exists yet).

---

## Defenses that held (53 BLOCKED — the audit's positive results)

- **Zero-knowledge core:** single-use session keys (atomic `pop()`), owner binding (foreign-account token theft → 403), TTL expiry, wrong-key recompute leaves prior insights intact, AEAD-valid hostile inner payloads (NaN sentiment, year-3000 dates) → clean 400s, no account bricking; post-run GC scan found zero lingering plaintext copies on the happy path.
- **Cross-platform crypto:** 16 edge-case AAD vectors (lone surrogates, DEL, CJK, RTL, combining marks) byte-identical between the Python and TS engines.
- **Auth hardening:** hostile token shapes all flat-401; token type-confusion rejected even with a leaked secret; epoch revocation covers both URL mounts; decoy salts stable and indistinguishable; login timing known-vs-unknown at ratio 1.01; no anonymous victim lockout; no data bleed across username recycling.
- **Abuse resistance:** IPv6 /64 aggregation; quota enforcement; 413 before parse; 50k-deep JSON → 400; scrypt amplification bounded (8 concurrent registrations, RSS 90→348 MB, CapacityLimiter held); date backdating bounded to ±1 day (threshold cannot be inflated); cross-mount shared rate buckets; insight idempotency.
- **LLM structural defenses:** consent gate (0 egress without consent), kind allowlist, grounding for ungrounded vocab, digit-URL/phone regex for literal contact strings, numeric clamps, control-char stripping, verbatim rule for `recurring_phrase`.
- **Statistics engine honesty:** manufactured trends, boilerplate spam, and pure noise all failed to produce statistical pattern cards (only direct-measurement topics surfaced on a degenerate 14-word vocabulary — by design); CJK-only corpora produce no false patterns.
- **Fail-closed operations:** all six production/staging boot checks refused/started exactly as designed (default secret, short secret, SQLite, HTTP LLM URL, typo'd env with dev secret); no tracked secrets; `.dockerignore` excludes dev DBs; GitHub Actions fully SHA-pinned; pip-audit clean.
- **Erasure:** live-DB deletion is complete and immediate (users/entries/insights zero rows, keystore purged) — the residual is backups (G1).
- **Clinical boundary:** no diagnosis vocabulary anywhere in output-generating code; LLM kinds cannot express clinical claims; crisis screen copy checks out (988, 741741, 911, findahelpline, no method detail).

## Not run (environment limits)

- **G2.npm-audit** — registry unreachable from the audit host (CI runs it, with the known 5 Metro-chain highs and `continue-on-error`).
- **G1 live pg_dump** — Docker unavailable; replaced by config audit + dev-DB column inspection.

## F3 synthesis — what still holds when the client is malicious

Server-side re-validation that a modified client cannot skip: blob AEAD + AAD binding, entry-date bounds, inner-payload shape, quota, crisis suppress tier (duplicated server-side), LLM sanitizer, verifier re-auth for destructive ops. What the server *cannot* verify: client KDF work factor (A4) and client-side crisis dialog (E1-TS).

## Operational disclosure

During cleanup between multi-worker runs, a broad `pkill -f uvicorn` killed a dev server belonging to an unrelated project of yours (`goat-farm-management-main/backend`, port 8000). An attempt to restart it in place failed because its Postgres role/env is not present in this shell (`role "pradeepreddy" does not exist`). It should be restarted from its own environment. All audit infrastructure now uses isolated process groups and port 8971 only.

## Reproduction

```bash
bash redteam/run_all.sh          # everything; prints AUDIT|id|verdict|evidence lines
# individual campaigns:
.venv/bin/python redteam/a_crypto.py   # (also b_auth, c_api, d_llm, e_crisis, e2_brain, g_infra, h_privacy, c1_multiworker)
cd mobile && PATH=../.tools/node/bin:$PATH node_modules/.bin/vitest run --config redteam.vitest.config.ts redteam
```

Fixtures worth promoting into the main suites: `redteam/crisis_corpus.json` (E1 regression corpus), the 35-day constant-corpus repro (P0-2), and the planted-vocab LLM cases (D1).


---

# Remediation addendum (same day)

Every fixable finding from this audit was remediated and verified by
re-running the full campaign (`bash redteam/run_all.sh`). Result:
**BLOCKED 53 -> 63; FINDING 32 -> 16**, with each remaining finding now a
documented design residual rather than an open defect.

| Finding | Fix | Post-fix verdict |
|---|---|---|
| P0-1 crisis bypass (E1/E2) | normalization pipeline (NFKC, invisible strip, homoglyph fold, leet fold, punct fold, single-letter join) + new English & 9-language phrases, both engines, pinned by shared fixtures | 30/35 -> 1/35 bypasses; disguised recurrence now surfaces `sensitive=true` (non-quoting card) |
| P0-2 phi=1.0 crash (C3) | `phi = min(phi, 0.99)` in brain.py (saturates the existing inflation cap) | crash corpus recomputes 200 |
| P0-3/F2 key over HTTP | `openProcessingSession` refuses non-loopback http before fetch | refused pre-fetch |
| A1 abandoned-session TTL | ceiling 3600s -> 300s (== consent copy "up to 5 minutes") | exposure bounded at the disclosed window |
| A4 KDF downgrade | MIN_ITERATIONS=100k floor on both platforms (tests derive via hashlib) | honest downgrades impossible; hand-rolled bypass remains structurally unverifiable (documented) |
| A5 nonce seam | `encrypt()` has no nonce param; `encrypt_with_nonce`/`encryptWithFixedNonce` for vectors only | seam gone from both production APIs |
| B2 XFF warning | startup warning when TRUST_PROXY_HEADERS=1 | deployment-conditional residual documented |
| C1 multi-worker | `app/singleprocess.py` deployment lock; second worker refuses to boot (incl. the dev create_all race) | live 2-worker boot now fails fast |
| D1 planted-vocab / spelled-url | spelled-contact + number-word-run label rejection | both injection chains dropped |
| D2 LLM limits/latency | max_tokens=512, temperature=0, timeout 10s | bounded; inside-context latency residual documented |
| F2 detail sanitizer | scheme-less domain + phone digit-run stripping | actionable contact info neutralized (spelled-out text remains, non-dialable) |
| G1 backups | pg_dump piped through AES-256-CBC with REQUIRED BACKUP_KEY | stolen volume = ciphertext at rest; retention window documented |
| H2 export | username dropped from the bundle | salt-only (needed for re-import) |

**Remaining 16 findings, all documented residuals:**

- *Native custody required (cannot be coded in this JS-only tree):* A3
  SecureStore device key in AsyncStorage (Keychain/Keystore TODO),
  A2 offline unlock oracle (~75 ms/guess/core; inherent to offline
  unlock), F1 plaintext draft across locks (by design, wiped on sign-out).
- *Product-scope features:* B1 auth_key replay (needs password-change +
  re-key infrastructure), H1 metadata inference (dates/sizes are visible
  to the operator by architecture; the privacy policy discloses this).
- *By-design with disclosure:* D2 plaintext egress (consent-gated),
  D2 endpoint-to-card injection (the consent model trusts the endpoint),
  E1 "suicide squad" dialog false positive (documented stance),
  E1 "k ill myself" partial-split bypass (the join threshold protects
  ordinary prose), suppress-only hopelessness phrasing (dialog stays
  conservative).
- *Environment-bound:* G2 lockfile hashes (needs a networked
  `pip-compile --generate-hashes`), G2 npm audit (offline host; CI runs
  it), G1 retention-vs-deletion window (encrypted, documented).

Verification after remediation: backend suite green incl. new
`tests/test_redteam_fixes_2026_09_16.py` (coverage 97.45% >= 97 gate),
mobile suite green incl. new `tests/redteamFixes2026.test.ts` (1065
tests; crisisDetect.ts at 100% coverage), `probe_brain.py` 9/9,
`tools/verify_vectors.mjs` all vectors verified.
