# MindPattern — Live End-to-End Multi-User Campaign (2026-09-16)

**Result: 148/148 checks passed** against a real running server
(`uvicorn app.main:app`, development mode, fresh SQLite DB, port 8907).

The harness ([campaign.py](campaign.py)) is black-box over HTTP but uses the
**real client-side crypto stacks** — the mobile app's key schedule
(PBKDF2 → HKDF auth/data keys, AES-256-GCM envelopes, exact AAD bindings)
and the portal's (password-KEK-wrapped P-256 keypair, ECDH→HKDF→GCM key
wrap, notes key) — so the server only ever saw bytes a real device would
send. The full per-check ledger is [results.json](results.json); the
annotated run is [run.log](run.log).

## Cast (9 accounts exercising the system simultaneously)

| User | Role | Story |
|---|---|---|
| alice | patient | 84-day structured journal (Sunday work dread, recurring sleep worry, family-visit dips, rising guitar topic, late mood decline); shares with a therapist, revokes, re-grants |
| bob | patient | week-old account, 5 entries — entry mechanics + baseline-phase honesty |
| carol | patient | 84-day journal mixing benign worries with crisis-adjacent lines — suppression contract |
| dave | patient | export → LLM consent → hard delete → username recycling |
| eve | patient | hostile AEAD-valid payloads (non-JSON, NaN sentiment, lying inner dates) |
| frank | patient | zero entries |
| gina | patient | export-burst rate-limit target |
| dr_house | therapist | happy-path clinician: pairing, reads, notes |
| dr_wilson | therapist | cross-access attacker |

Direct-DB touchpoints (account aging to give honest history, byte-flips to
simulate at-rest corruption) mirror what `scripts/seed_demo.py` already
does; all HTTP flows are pure black-box.

## What was covered (14 groups, 148 checks)

1. **Meta & mounts (4)** — `/api/meta`, canonical `/api/v1` mount, flat
   error envelope `{detail: str, code}` on unknown routes, dev `/docs`.
2. **Registration (10)** — happy path, duplicate 409, username/salt/
   verifier validation, string-detail validation envelope.
3. **Enumeration posture (3)** — real salt for known users; decoy salt
   (same shape) for unknown; hostile probe strings give no oracle.
4. **Login/logout (9)** — correct/wrong/unknown credentials (identical
   401), two concurrent device tokens, logout epoch-bump kills **all**
   tokens at once, re-login, missing/garbage bearer.
5. **Entry sync (15)** — AES-GCM create/list/delete, client-side decrypt
   roundtrip, stable pagination, `?since=`, duplicate id 409, future-date
   422, UTC+14 forward grace, pre-account backdate 422 (threshold cannot
   be fast-forwarded), non-base64/undersized/pattern-invalid 422s.
6. **Threshold honesty (5)** — baseline phase: no analysis, no key, no
   blob, honest `days_remaining`, 400 on empty account.
7. **Insight phase (13)** — 84-day corpus crosses to `phase=insight` with
   the deterministic brain; patterns decrypt client-side (recurring_phrase,
   rumination, topic surfaced day-1 — statistical kinds correctly wait for
   a second observation day); every card carries label + evidence detail;
   the planted sleep worry is found; daily question stored + decrypts;
   same-day recompute is deterministic (identical surfaced set).
8. **Processing sessions (5)** — missing token 401, forged token 403,
   single-use consumption (reuse 403), wrong-size/non-base64 key 422.
9. **Tampering & hostile payloads (11)** — crisis-language journal: the
   **only** crisis-quoting patterns are exactly those flagged
   `sensitive=true` (clients render non-quoting); question engine never
   quotes crisis language; corrupted stored ciphertext → 400
   `entry_blob_invalid` (GCM auth) and recovers; corrupted brain state →
   amnesia retry (account not bricked); AEAD-valid non-JSON / NaN-
   sentiment / lying-inner-date payloads → 400 `entry_payload_malformed`;
   account healthy again after cleanup.
10. **Account lifecycle (16)** — streaming export decrypts locally
    (zero-knowledge export); LLM consent: verifier-in-body required, wrong
    verifier 403, correct verifier 200 + Art. 7 record, disable clears it;
    deletion gated by password proof (422/403/204), token dies with the
    account, deleted login = unknown login, deterministic decoy salt
    (never the real salt), username recyclable as a fresh empty account.
11. **Zero-knowledge sharing (34)** — therapist register/login/`me`,
    local private-key unlock; 15-min pairing code; lookup shows name +
    pubkey without burning; grant is password-gated (422/403/201), code
    burns on grant, replay 404; **portal unwraps the patient's data key
    and it equals the real key**; therapist insight read is byte-identical
    to the patient's own blob and decrypts to the same payload; entry
    evidence windows (`since`/`until`) decrypt; notes CRUD under the notes
    key; revoke is password-gated and kills insight/entry reads while key
    material is cleared from the list row; notes survive revoke;
    re-grant reactivates the **same** consent row with note history
    intact; garbage `ephemeral_pub` 422.
12. **Cross-user & role attacks (19)** — therapist B cannot read
    therapist A's patient (insights/entries/notes all 404); therapist
    cannot reach any journal route (403 across entries/insights/
    processing/consents/export/questions — no therapist write path
    exists); patient cannot reach therapist routes (403); users see only
    their own entries; unknown consent/patient ids flat 404; garbage wrap
    key 422 at therapist registration; foreign note delete 404.
13. **Rate limiting (3)** — default export bucket (5/min): burst trips
    429 + `Retry-After` + `rate_limited` code, stays closed, other users
    unaffected. (Auth buckets were raised for the campaign so multi-user
    flows wouldn't false-trip; bucket mechanics verified on the untouched
    default.)
14. **Body limits (1)** — 3 MiB body rejected before parsing (413).

## Verdict

No application defects found. Every behavior that initially looked like a
failure turned out to be the product's documented design, verified live:

- **0 patterns on a 48-day corpus** — the brain's replication discipline:
  statistical kinds need 2 distinct recompute days; direct kinds need
  STRONG_EVIDENCE (10 occurrences). An 84-day corpus surfaces day-1
  direct-measurement cards exactly as `seed_demo` does.
- **`patterns_new = 8` on a same-day rerun** — the field counts surfaced
  cards first-qualified within the new-pattern window, not deltas since
  the previous run; the surfaced set itself was byte-identical.
- **Crisis-quoting labels present** — by contract: those cards carry
  `detail.sensitive = true` and clients render them non-quoting; the
  question engine independently avoided them.

Artifacts: [campaign.py](campaign.py) (re-runnable: start the server, run
`python campaign.py`), [probe_corpus.py](probe_corpus.py) (offline corpus
strength probe), [results.json](results.json), [run.log](run.log).
