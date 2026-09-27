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
| Multi-tenant insider (another account holder on the same instance, incl. a recycled username) | Tries to read or corrupt a neighbor tenant's data: replay a token against foreign ids, inject another account's ciphertext/AAD, re-register a deleted username and inherit its trail | Per-account ownership walls on every route; AAD binds every blob to the account id (foreign AAD/blobs fail closed); tokens are account-scoped with epoch death; hard cascade on deletion leaves nothing to inherit — cross-account bleed is adversarially tested by the red-team B3 (username recycling: new account must see 0 old entries) and C3 (cross-account AAD injection rejected; entry recycling self-affecting only) suites |
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
across tabs. Offline-safety additions since the first write: an
in-progress measure survives a lock/offline gap as a ciphertext
pending-measure record (`web/src/pendingMeasure.ts`), and the active
journal draft survives lock-time unmounts as ciphertext at rest —
never plaintext (`web/src/entryDraft.ts`; a 2026-09-26 audit fix — the
draft used to be lost on lock).

**Render pipeline.** Decrypted journal text renders exclusively through
React's escaped text nodes. Sensitive pattern cards never place their
label in the DOM (asserted on DOM text, not markup). The crisis dialog
tier runs PRE-encryption on typed text.

**Transport/edge.** Same-origin only (no configurable server URL — the
verifier-collection vector stays closed). Hardened fetch: credentials
omitted, redirects refused, no-store, no-referrer, 15 s deadline,
post-fetch origin recheck, one-shot session-abort. CSP/HSTS/COOP/CORP
shipped in three aligned places, pinned by test — CSP carries
`style-src 'self'` with zero `'unsafe-inline'` anywhere (the
2026-09-26 hardening pass moved the shell stylesheet to a same-origin
file; React's CSSOM inline styles are outside style-src). A token-expiry
guard funnels an expired session to re-auth instead of retrying queued
writes against a dead bearer.

## Accepted residuals (web-specific)

Re-swept 2026-09-26 against the current tree — items fixed since the
2026-09-25 first write (English-only chrome, plaintext-at-lock draft
loss, measures lost on a mid-flow lock, queue double-flush races) are
removed; what remains:

1. **Open-tab offline only (D-6):** without a service worker, offline
   works while a tab lives; a cold load offline fails. Accepted for v1.
2. **In-memory plaintext window:** between decrypt and lock, a live tab
   holds plaintext; the OS/user owns that window (same as any webmail).
   The 5-minute idle, bfcache, and hidden-tab locks bound it; the draft
   no longer widens it (it parks as ciphertext at lock).
3. **Memory-hygiene limits:** WebCrypto zeroizes what it owns; GC-owned
   strings follow the platform (same honesty as the mobile README).
4. **Single draft slot:** one encrypted draft slot per account; there is
   no cross-tab draft merge (two tabs' concurrent drafts do not
   combine — the slot is last-writer's, at lock time).
5. **First Stryker floor:** the campaign is wired (workflow + config); the
   measured floor lands with the first scheduled run — not claimed before
   it exists.
6. **The server-side analysis window (inherited, unchanged):** the
   explicit recompute still ships the data key to the single-use
   processing session — the v1 trade the on-device port (WEB_PLAN /
   `mobile/src/brain/PORT.md`) is the path to removing. Not a web
   regression; listed so the web threat model is complete.
