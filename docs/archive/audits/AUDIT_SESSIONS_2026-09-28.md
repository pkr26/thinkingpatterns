# Deep audit of the last two sessions — 2026-09-28

**Scope.** Everything changed by the two most recent commits — `e4585b3`
(audit remediation + re-audit, 2026-09-27) and `7b7337a` (independent-audit
remediation round 2, 2026-09-27): 283 files, ~29.7k insertions across
backend, web, portal, mobile, infra, and docs. Method: line-level review of
every security-critical backend module by hand, four parallel adversarial
audits of the API/web/portal+mobile/infra surfaces, independent
re-verification of every HIGH+ finding against the current code, and a full
re-run of every gate.

**Gates re-run (all green — the commits' verification claims hold):**

| Gate | Result |
|---|---|
| backend pytest | 1,607 passed + 4 skipped (live-PG profile), exit 0 |
| backend coverage | 97.02% ≥ 97 gate |
| backend ruff / format / mypy | clean |
| probe_brain | 9/9 PASS, exit 0 |
| web vitest (tsc+build suite path) | 639 passed + 5 skipped, exit 0 |
| portal vitest | 409 passed, exit 0 |
| mobile vitest | 1,918 passed + 1 skipped, exit 0 |
| mobile crypto-vector replay | 4 vectors + wrap/AAD sets verified |
| drift gate `--selftest` / verify.sh | exit 0 |

Every gate passing did not catch the findings below. That is itself the
meta-finding: three of the four worst issues live in seams the suites
structurally cannot see (module-state carryover between test halves, a
cross-component contract changed on one side only, and an infra claim
never checked against the shipped compose file).

---

## CRITICAL

### C-1. Web v2 sign-in dead-ends on every fresh page load (registration bricks the account)

`web/src/views/LoginView.tsx:232` → `adoptEnvelopeDataKey` (line 137) calls
`api.keyEnvelope()`, which goes through `requestWithResponse`
(`web/src/api/client.ts:355-356`) — and that throws `ApiError(0, "not
signed in")` unless the module-level `session` is set. `setSession` runs
only inside `adoptSession` (line 122), which the sign-in flow calls at
line 236 — AFTER the envelope fetch. `session` is never persisted (pure
module state), so on any fresh page load or post-lockout sign-in of a
key_scheme="v2" account: login succeeds server-side, the envelope fetch
throws before any HTTP request is made, the catch zeroizes everything, and
the user sees `login.envelopeUnlockWeb` ("key envelope could not be
opened"). Because registration defaults to v2, a user can create an
account and then **never sign in again** after the first reload.

Why the suite is green: `tests/login.test.tsx` runs register-then-signin
inside one module scope — registration's `adoptSession` leaves `session`
set, so the signin half's envelope fetch succeeds spuriously. The other
v2 sign-in tests assert fail-closed shapes that the "not signed in" throw
satisfies without exercising the stubs they set up.

Mobile is NOT affected (`src/screens/LoginScreen.tsx:211` calls
`api.setSession` before the envelope fetch, plus the offline envelope
cache).

**Fix:** call `setSession` before `adoptEnvelopeDataKey` (rolling back on
failure), or pass the fresh token explicitly to the envelope fetch. Then
add a sign-in test that runs against fresh module state (e.g. vi.resetModules)
— the roundtrip test cannot stay the only v2 sign-in coverage.

## HIGH

### H-1. Rekey-journal stage skip can permanently brick the journal

`backend/app/api/insights.py:577/635/732`. The chunked rekey persists
`stage` (only ever `"entries"` → `"measures"`; `"insights"` is never
written) and on resume gates whole stages with `stage_floor`. With
`stage="measures"`, the entries and insights stages are **skipped
entirely** — not resumed from cursor, skipped. Concrete loss path: a run
crashes at/after the first measures batch; the rotation never completed,
so the client keeps journaling under the OLD key; the retry adopts
`stage="measures"`, never walks the new old-key rows (the skip also
bypasses the already-new/mismatch probe that would have caught them),
finalize bumps revisions, deletes the journal, and reports success; the
client then completes the credential swap and the missed rows become
permanently undecryptable. Worse: `_load_or_create_rekey_journal`
(:443-462) binds no key identity, so a journal abandoned mid-measures
weeks ago is adopted by a *fresh* rotation (deterministic v1 keys make
"same new password" a realistic collision) — zero entries rekeyed,
finalize succeeds, stale counts are returned as truth. No test exercises
a resume from `stage="measures"` (no reference to `stage=`/`entry_cursor`
anywhere in `tests/`). Secondary: `insights_done` double-counts on resume
(re-seeded then re-incremented, :662). **Fix direction:** never skip the
entries/insights stages (the already-new probe makes re-walking
idempotent), and/or bind the journal to the run's key identity.

### H-2. The audit-journal tail anchor is not wired anywhere — three artifacts claim it is

Commit `7b7337a`'s message ("journal tail anchor … compose volume
wired"), `AUDIT_REMEDIATION_2026_09_27_ROUND2.md` ("compose wires a named
volume"), and `backend/app/config.py:331` ("compose wires a named volume
by default so production gets the anchor for free") — none of it is in
the shipped `docker-compose.yml`: no `MINDPATTERN_AUDIT_JOURNAL` env var
on the api service, no journal volume (only `pgdata`/`pgbackups`), and
the api container is `read_only: true` with no writable persistent path.
`audit_journal_path` defaults to `""`, so `flush_audit_journal` no-ops
and **every production deployment runs the chain without the tail
anchor**: deletion of the newest audit rows is undetectable while the
docs say the control is active. **Fix:** wire the env + named volume (and
document rotation, see M-5), or correct the three claims.

### H-3. Web offline queue is wiped wholesale by a lockDown race

`web/src/offlineQueue.ts:330-333`. After `await writeItems(...)` the
enqueue rechecks the generation fence and "rolls back" with
`kv.removeItem(scope.queue)` — deleting EVERY parked entry, not this
item. The rollback's stated premise ("a clearQueue that won the race") is
now unreachable: this diff moved every mutation under the shared
`queue-flush` Web Lock, and `clearQueue` bumps the generation *inside*
that lock — it cannot interleave with an enqueue holding it. The only
generation bumper that can land during the write is
`abortInFlightFlush()` (sign-out, idle lock, **hidden-tab lock**, token
expiry — the proactive-expiry guard added in this window widened it),
which deliberately preserves ciphertext ("sign-out keeps ciphertext").
Net effect: an offline save racing a tab-hide/sign-out destroys the whole
queue. The rollback code itself predates these commits (2026-09-25), but
the lock change made the only reachable trigger the one that must not
wipe. **Fix:** on fence trip, rewrite the previously-read contents (minus
this item) instead of removing the key.

## MEDIUM

### M-1. `PUT /account/password` v2→v2 stores an unproven envelope

`backend/app/api/account.py:924-942`. The v1→v2 path demands
`X-Processing-Token` and authenticates a stored blob under the popped key
before storing the uploaded envelope; the v2→v2 path skips both. The
docstring's justification — "it re-wraps the SAME key the client just
proved it holds by unwrapping under the old password (the verifier
proof)" — is factually wrong: the verifier proves the auth credential;
the unwrap is client-side and invisible to the server. That is exactly
the reasoning the sibling `POST /account/key-envelope/upgrade` gives for
demanding the probe on every envelope replacement. An attacker with a
stolen bearer + phished verifier (the endpoint's own modeled threat) can
PUT a random 60-byte `wrapped_data_key`: 204, epoch bump, and the only
copy of the data key's locker is permanently destroyed. **Fix:** require
the possession probe on every `wrapped_data_key` write, or an equivalent
proof (e.g. HMAC over the new blob under the key being replaced).

### M-2. Portal note composer permanently jams after one timed-out save

`portal/src/views/PatientView.tsx:840-875`. The retry design reuses
`client_note_id` across attempts and only burns it on
`err.code === "conflict"`. But every attempt calls `encryptNote` → a
fresh random GCM nonce → different ciphertext for the same text, and the
backend's NEW create-channel contract (this same commit window,
`therapist.py:1727-1742`) answers different content under an existing id
with 409 `version_conflict`. So a timeout-then-retry — the exact
scenario the comment describes — hits `version_conflict`, never clears
the pending id, and every further press re-encrypts and 409s again: the
draft is unsavable from that composer until unmount, with an error that
blames the client. A cross-component contract change shipped with only
one side updated. **Fix:** treat `version_conflict` as burn-worthy (or
persist the sealed blob for byte-identical retries), and update the
stale "rewrites in place" comment.

### M-3. Entry.save can seal the mood log under an all-zero key

`web/src/views/Entry.tsx:165-191`. `encryptEntry` awaits on the shared
vault buffers; a lock landing during that await zeroizes `keys.dataKey`,
and `recordMood` (which snapshots the key at call time) then reads the
existing log under the zero key, gets `[]`, and **replaces** the mood-log
blob with ciphertext under 32 zero bytes — the device-local mood history
becomes unreadable. This is the identical race class the same window
fixed in `Measures.tsx` (snapshot-before-await + recheck); Entry's
mood-log write did not get the fix.

### M-4. v1 rotation drain is a per-browser snapshot; a second tab can still strand old-key blobs

`web/src/views/Settings.tsx:306-383`. The drain runs once in this tab;
another signed-in tab retains the old data key and a valid bearer through
the multi-request rekey window and can POST old-key-sealed entries
(direct save or its own reconnect flush) to the already-rekeyed corpus.
The server has no possession check on entry uploads, so those rows are
permanently undecryptable — the exact outcome the drain was added to
prevent. Options: hold the queue lock across the server steps,
lockdown-all-tabs via BroadcastChannel before the rekey, or a server-side
key-epoch check on writes.

### M-5. Audit journal: unbounded growth and O(patients × file) verification

The DB trail is pruned by retention; the journal file is never pruned or
rotated, and `read_journal_head` (`_audit.py:210-234`) linearly scans the
whole file per patient — the daily sweep does this for up to 500 patients
daily. Sweep cost grows without bound with file size; the volume can fill
its mount over months. A retention-aligned truncation tool (safe: a
journal behind the head is benign by design) or an indexed head cache is
needed once H-2 actually wires the volume.

## LOW

- **L-1.** `TokenRevocationStore.hydrate` (`cache.py:499-528`) loads only
  the newest `max_entries` rows but never sets `_overflowed` when the
  table exceeded the cap — the point-query fallback that makes eviction
  safe is bypassed exactly when hydration truncated. (Needs >100k
  unexpired revocations; the stated invariant should still hold by
  construction.) Set `_overflowed = True` when `len(rows) == max_entries`.
- **L-2.** `_audit.py:439` verifies `entry_mac` with `!=` instead of
  `hmac.compare_digest`, against the codebase's own documented
  constant-time discipline (`tokens.py:130`). Offline sweep path only;
  not attacker-observable. Consistency fix.
- **L-3.** Drift-gate scan scope (`check-image-drift.sh:208-210`) misses
  the repo-root `backup/` directory; `backup/Dockerfile`'s postgres pin is
  collected only because it currently equals compose's (dedup). The next
  re-pin that misses it ships a silently aging base image. The inventory
  row exists; the scanner path doesn't.
- **L-4.** The "metrics token: ONE value into both sinks with equality
  assertions" promised in `docker-compose.yml:394-398` is not implemented:
  no workflow writes `deploy/monitoring/token`, no equality assertion
  exists anywhere, and `release.yml:243-245`'s secret-existence loop omits
  `deploy/secrets/metrics_token`. Divergent hand-filled files mean every
  scrape 401s with nothing to catch it.
- **L-5.** Drift `--selftest` does not exercise the future-dated-inventory
  branch, and the live walk has no minimum-pin-count assertion (zero
  collected pins → "ALL CHECKS PASSED"; e.g. if workflows gain `.yaml`).
- **L-6.** `release.yml` concurrency (`group: release-${{ github.ref }}`)
  does not cancel distinct near-simultaneous tags (the comment's own
  scenario); same-tag cancel can kill a run mid-Release-upload.
- **L-7.** Web Locks fallback (`web/src/platform.ts:106-110`): browsers
  without `navigator.locks` (Safari < 15.2) silently run every queue
  mutation unlocked — the cross-tab last-write-wins the lock was added to
  prevent returns, undisclosed. At minimum detect-and-disclose; ideally
  serialize via BroadcastChannel/storage mutex.
- **L-8.** Legacy plaintext crisis stamp (`crisisDialog.ts:39-49`) is
  swept only when the crisis module is first consulted; a user who never
  triggers a crisis-flagged save keeps the pre-fix plaintext date in
  localStorage indefinitely (locks preserve `mindpattern.*` keys).
- **L-9.** Mobile: the reminder fix cancels only the new stable ids;
  devices upgrading from the pre-fix build keep every orphaned random-id
  daily notification forever (notifee's store survives app updates). A
  one-time cancel-all + reschedule migration is needed.
- **L-10 (info).** Portal SAS local fingerprint cross-check silently
  no-ops when the local digest is unavailable while still rendering
  "(key id X)" — the honest "could not run" copy covers only the
  server-side-null case (`PatientsView.tsx:626-632, 820-837`).

## Verified clean (highlights)

Durable jti revocation design (fence, write-through, boot hydration,
eviction fallback — modulo L-1); the audit chain itself (MAC construction
and out-of-DB key, savepoint retry, journal staging strictly post-commit
via session events, retention-aware verification anchoring); the note 409
contract on the backend side (byte-exact replay compare, race closed by
the unique index, PATCH base_version discipline); kdf_params validation
bounds; SAS construction (mod-10⁶ bias negligible, code-as-HMAC-key
design); envelope AAD binding; sharded overflow locks (refs accounting is
race-free); the alembic PG autobegin root-cause fix; drift-gate fail-closed
core logic (404/transport/missing-inventory all fail, empirically
probed); annotation password redaction; digest re-pin consistency;
brain statistics (measured-pairs day-after gate, phi_eff applied to both
limit and table, weekday deconfounding feeding only the association
tests); access-log cursor grammar and ownership scoping; error envelopes
(no input echo). The new round-2 test file is real behavioral coverage
(restart-model hydration, race-injection fences, truncation detection),
not theater.

## Scorecard for the two sessions

The remediations themselves are largely real and well-engineered — the
crypto/auth hardening, the statistical honesty work, and the drift gate
held up under adversarial reading. The failures are concentrated in (a)
new code shipped without coverage for its own failure modes (rekey
resume, web v2 sign-in on cold state), (b) one contract changed on the
backend without its client (portal composer), (c) an infra claim never
validated against the artifact it describes (journal volume), and (d)
pre-existing latent races the new code made more reachable (queue wipe,
Entry mood log). Recommended fix order: C-1, H-1, H-2, H-3, then the
mediums.
