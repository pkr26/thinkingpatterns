# MindPattern web client — threat model (WEB_PLAN P9.1, 2026-09-25)

The patient web client carries the same zero-knowledge contract as the
mobile app, plus the browser's own threat surface. This document names the
attackers, walks each surface, and states the accepted residuals honestly —
it feeds `SECURITY_RESIDUALS.md`.

## Attacker classes

| Attacker | Capability | Primary defenses |
|---|---|---|
| Network MITM (behind TLS termination) | Sees origin traffic | TLS at nginx; `connect-src 'self'`; same-origin API; no mixed content possible |
| Malicious/compromised server | Serves hostile payloads, replays blobs, lies about metadata | AEAD with AAD binding; `state_seq` guard; entry-version high-water marks; pagination validators; version-conflict CAS; sensitive non-quoting |
| XSS attacker | Tries to execute injected journal content | React-only rendering; no innerHTML anywhere (source-scanned + red-team corpus); strict CSP `script-src 'self'` |
| Hostile sibling tab / tab-nabbing | Manipulates `window.opener`, races shared storage | COOP/CORP same-origin; session memory-only per tab; Web Locks serialize queue/reconcile |
| Local-device snooper | Reads browser storage | Nothing decryptable persisted (D-4); queue/mood/version marks are ciphertext; drafts memory-only |
| Replay attacker with a stolen bearer token | Reuses a token, replays queues | Server idempotency + single-use processing sessions; epoch death on logout/rotation; 409-verify before queue drops |
| Phished password holder | Knows the password | Not in web scope beyond the server's verifier/KDF (the password IS the key holder's threat — disclosure copy says so) |

## Surface-by-surface

**Key custody (D-4).** Token AND keys are memory-only; refresh/new tab
re-authenticates. Nothing decryptable in localStorage, sessionStorage, or
IndexedDB — the storage-scrape harness asserts this after every flow.
Residual: a memory image of the live tab contains plaintext (inherent to
any client); the 5-minute idle lock (mobile parity), the bfcache guard,
and the hidden-tab lock (visibilitychange → hidden locks immediately —
W-1, audit 2026-09-25) bound the exposure window.

**The one key shipment (processing sessions).** The data key travels only
on the explicit "Refresh patterns" button, inside a single-use TTL
session, over same-origin TLS. No automatic shipment path exists — pinned
by tests. Residual: unchanged from the mobile app (README security §2).

**Multi-device (D-1/D-8).** Two writers are refereed by server CAS
(`version_conflict`), idempotent ids, and revision snapshots. Account-wide
death (logout/rotation/deletion from another device) funnels lazily: 401
vs 410 with distinct copy; a decrypt failure with a live session means
remote rotation → actionable lockout, never a loop.

**Offline queue.** Ciphertext only, origin+account scoped, byte+count
capped, quarantine for corrupt/foreign records, lying-409 verification
before any drop (M-5), generation fence at sign-out, Web-Locks-serialized
across tabs.

**Render pipeline.** Decrypted journal text renders exclusively through
React's escaped text nodes. Sensitive pattern cards never place their
label in the DOM (asserted on DOM text, not markup). The crisis dialog
tier runs PRE-encryption on typed text.

**Transport/edge.** Same-origin only (no configurable server URL — the
verifier-collection vector stays closed). Hardened fetch: credentials
omitted, redirects refused, no-store, no-referrer, 15 s deadline,
post-fetch origin recheck, one-shot session-abort. CSP/HSTS/COOP/CORP
shipped in three aligned places, pinned by test.

## Accepted residuals (web-specific)

1. **Open-tab offline only (D-6):** without a service worker, offline
   works while a tab lives; a cold load offline fails. Accepted for v1.
2. **Web chrome copy is English v1** (catalog-backed surfaces localize) —
   safety content (crisis card) included in the follow-up sweep.
3. **In-memory plaintext window:** between decrypt and lock, a live tab
   holds plaintext; the OS/user owns that window (same as any webmail).
4. **Memory-hygiene limits:** WebCrypto zeroizes what it owns; GC-owned
   strings follow the platform (same honesty as the mobile README).
5. **Single-tab assumption for drafts:** a draft is per-tab memory; no
   cross-tab draft merge (two tabs' drafts are independent by design).
6. **First Stryker floor:** the campaign is wired (workflow + config); the
   measured floor lands with the first scheduled run — not claimed before
   it exists.
