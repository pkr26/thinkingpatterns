# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

> **Versioning convention (adopted 2026-09-26, at [2.0.0]).** This file
> previously accumulated dated campaign headers without ever cutting a
> version. Going forward: new work lands under `## [Unreleased]` at the
> top and is folded into a `## [X.Y.Z] - date` header when a release is
> cut. The dated 2026-09-25/26 wave headers below are the pre-versioning
> campaign logs and are summarized (not deleted) under [2.0.0]; they stay
> in place below it as the detailed history, newest first.

## [Unreleased]

### Security — voice-journaling audit remediation (2026-09-29, same day)

Full remediation of the independent post-commit audit
(`AUDIT_VOICE_SESSION_2026-09-29.md`):

- **Consent scope (H4):** transcripts are no longer dispatched to the
  LLM translation endpoint on voice consent alone — a configured LLM now
  requires the account's CURRENT llm consent (null/degraded translation
  otherwise). Privacy-policy copy updated to disclose the coupling.
- **Dark-launch completeness (M1):** the therapist audio route and the
  share-voice toggle now answer the flag-off flat 404 (checked in the
  body so the authenticate → role → flag wall order holds: anonymous
  stays 401).
- **Erasure (M2):** account deletion best-effort-deletes every kept-
  recording OBJECT before the row cascade; retention schedule wording
  corrected.
- **STT resilience (M8):** one bounded retry (Retry-After honored,
  ceiling 5 s) on transient 429/5xx upstream refusals; the upstream
  budget is operator-tunable via `MINDPATTERN_STT_TIMEOUT_SECONDS`
  (1–600 s, default 120).
- **Dev MinIO parity (M4):** `MINDPATTERN_AUDIO_S3_ENDPOINT` override
  (path-style addressing) — the dev overlay's bucket finally resolves
  against the compose MinIO instead of real AWS.
- **Storage hygiene (M9 + LOW):** one cached store instance per
  configuration (no per-request boto3 client); S3/local reads are
  capped at `audio_max_body_bytes`.
- **Cross-client crypto pins (M3):** `shared/audio_vectors.json` now
  carries real deterministic vectors (fixed key + nonce) for the audio
  envelope and the v3 entry payload; web/mobile assert byte-equality
  through their fixed-nonce seams, portal pins the decrypt side. The
  AAD tuple doc now states the version's wire form is the string "1".
- **Redteam (H5):** `redteam/g_voice.py` is an EXECUTABLE campaign (9
  verdicts, all BLOCKED) and is wired into `run_all.sh` — the P6 gate
  is no longer satisfied by a docstring.
- **Docs:** nginx example gained the audio location with an 8 m body
  cap; VOICE_PLAN drift (12 MiB → 4 MiB, retry/timeout env) corrected;
  DPIA skeleton and web threat model gained voice addenda.
- **Web/mobile/portal fixes** (recorder lifecycle, playback gating,
  voice request deadlines, v3-preserving edits, consent pre-checks,
  mobile native wiring) landed in the same wave — see the audit
  report's remediation map.

### Added — voice journaling (VOICE_PLAN.md, 2026-09-29)

Patients can record up to 5 minutes in any language on web and mobile;
audio is transcribed server-side by an OpenAI-compatible Whisper
endpoint (consent-gated, never persisted), the transcript is shown in
its original language plus an English translation, and patterns run on
the routed text (en/es native, other languages via the English
translation). Kept recordings are AES-GCM-encrypted on-device, stored
in S3 (local-dir dev fallback), expire after 30 days, and are playable
by the patient anywhere; a therapist can hear the actual voice only
behind the patient's per-consent `share_voice` grant (default off,
every fetch audit-logged). Backend: `services/stt.py`,
`services/audio_store.py`, `api/audio.py`, voice-consent + share-voice
endpoints, attachment sweeper, entry-payload v3 (voice channels).
Web/mobile: recorder + review flow, playback, Settings/Share toggles,
en/es strings. Portal: English-first display with show-original
toggle + consented playback. Pinned by `shared/audio_vectors.json`;
dark-launched behind `MINDPATTERN_AUDIO_ENABLED` (default off in
production, on in development). Mobile note: `expo`/`expo-audio`/
`expo-file-system` are installed as dependencies — run `pod install`
before the next iOS build.


### Security

- **Deep penetration test 2026-09-29 + full remediation** (report:
  `PENTEST_DEEP_2026-09-29.md`; 4 parallel white-box audits + a 35-probe
  live campaign + the existing 9-campaign harness as baseline — no
  Critical/High findings, every actionable Low/Medium fixed same-day and
  re-verified under live fire):
  - **Backend — note-revisions byte-paging (BE-1):**
    `GET /therapist/notes/{id}/revisions` was the only blob read outside
    the shared `_paging` contract (~32 MiB ciphertext per request on a
    near-quota chart). It now sizes metadata-first, enforces the 2 MiB
    hard page budget (legacy over-budget reads fail loudly with 413;
    byte-paginating clients get short pages + `X-Next-Offset`), and
    guards the blob fetch against mid-page drift.
  - **Backend — edge rate gate before the body drain (BE-2):** the
    pre-dispatch limiter check now runs BEFORE the middleware buffers the
    request body, so an over-limit client's flood no longer costs a full
    max-body buffer per refused request (pinned by a raw-ASGI test proving
    `receive()` is never called for a refused request).
  - **Backend — catch-all edge bucket (BE-3):** requests that resolve to
    no limiter-bearing route (unknown paths → framework 404s, CORS
    preflights, dev-only docs routes) now land in one generous
    per-identity `edge-catchall` bucket sized to the read budget — a 404
    or preflight flood is bounded instead of drawing unlimited responses.
  - **Backend — KDF write floor (T-2):** registration, envelope upgrade,
    and password-change envelope swaps refuse `kdf_params.iterations`
    below the shipped 600k contract (a hostile client could previously
    register at the 100k library floor). Read-validation keeps the
    historical 100k floor so pre-constraint blobs keep validating.
  - **Backend — aggregate verifier-failure budget (I-2):** wrong-verifier
    failures across ALL 13 verifier-gated endpoints now share one
    per-username budget (`MINDPATTERN_VERIFIER_FAILURE_LIMIT`, default
    30/min), closing the 13×-per-IP scrypt fan-out a stolen bearer had;
    counts only actual failures (no anonymous lockout oracle — the bucket
    is reachable only past a valid bearer).
  - **Backend — misc:** `local_recompute`'s dead `analysis_dates`
    accumulation removed and its docstring corrected (I-1: the real
    grounding — threshold evaluated over the account's DB dates — is
    stronger than the intersection the docstring claimed); deactivated
    patients no longer linger in the therapist's revoked history (I-5,
    consistent with the active pass); boot WARNs loudly outside
    development when the audit-chain MAC key is only derived from the
    token secret (MED-2 — one exfiltrated value would compromise both
    bearer minting and the audit trail; set
    `MINDPATTERN_AUDIT_MAC_SECRET` to decouple).
  - **Web — v1 rotation snapshots vault buffers (FE-4):** the one
    rotation path missing the snapshot-and-recheck idiom (an idle-lock
    mid-flow zeroized shared buffers and the rotation continued with zero
    keys) now snapshots both buffers before the first await, re-checks at
    every pre-server boundary, and zeroizes in `finally`.
  - **Web — in-memory lock fallback (T-1):** `withLock`'s final fallback
    (browsers with neither Web Locks nor writable localStorage) now
    serializes same-tab sections via a per-name memory mutex instead of
    running unlocked.
  - **Web — post-password-change rekey hint (MED-3):** a successful v2
    password change plants a dismissible notice that changing the
    password does NOT rotate the encryption key, with a button that runs
    the FULL rotation (rekey + new-key envelope swap — scheme-aware,
    because the plain credential route 409s `key_scheme_conflict` for v2
    accounts). An old-envelope attacker survives a password change unless
    the data key is rotated; the flow now says so at the moment it
    matters.
  - **Portal — error-banner sanitizer (FE-1):** the phishing-vector
    sanitizer web/mobile already ship (URLs, scheme-less domains,
    phone-like digits, bidi/zero-width) is ported to `portal/src/api.ts`
    with web's adversarial test corpus.
  - **Portal — SRI in the build (FE-3):** `tools/add-sri.mjs` (adapted
    from web) stamps subresource integrity on the built bundle, verified
    by test.
  - **Deploy — nginx template sync (FE-2):** the operator template's
    portal CSP dropped its stale `style-src 'unsafe-inline'` (now
    byte-identical to `portal/public/_headers`) and gained the web
    block's `X-Robots-Tag`.
  - **Deploy — DB password out of the api env (MED-1):** the api
    container no longer receives the database password through its
    environment (`docker inspect` readable); the entrypoint assembles
    `MINDPATTERN_DB_URL` from the 0600 `POSTGRES_PASSWORD_FILE` secret
    mount, the same posture every other secret already had.
  - **Repo hygiene:** the synthetic TOTP enrollment secret visible in a
    committed e2e screenshot is redacted, with a screenshot-hygiene
    policy note (INFRA-2); the gitleaks `tests?/` path allowlist now also
    requires clearly-fake fixture VALUES (INFRA-3); the accepted-risk
    residuals (GCM nonce birthday bound, Python string residuals, TOTP
    economics, homoglyph display names, unbounded account creation,
    biometric custody trade, dev-credential never-reuse rule) are
    documented in `docs/SECURITY_RESIDUALS.md`.
  - **Verification:** backend 1660 passed / 4 skipped (18 new tests in
    `tests/test_pentest_2026_09_29_fixes.py`), web 676 / 5 skipped (+8),
    portal 459 (+9), ruff + mypy + tsc clean, redteam harness 96 verdicts
    unchanged (77 BLOCKED, the same 8 documented accepted-risk residuals),
    and 4 live fix-verification probes all BLOCKED.

### Changed

- **Therapist portal — teal accent wave (2026-09-29, user-directed)**: the
  violet is gone. The accent family moves to a calm clinical TEAL on the
  unchanged dark base, every ratio recomputed and enforced from the CSS by
  `portal/tests/designTokens.test.ts`: `--primary` #0c7268 (white label
  5.80:1, hover darker #085b53 at 7.98:1), `--primary-strong` #7ce4d2
  (12.42:1 on --bg, 11.39:1 on cards — text, ghost labels, sparkline/trend
  strokes), `--primary-focus` #3fcfb9 (7.73–9.70:1 on EVERY dark surface
  including the banner softs — enforced per-surface now, not just the three
  mains), `--info-accent` #aeebe0 (11.24:1/13.59:1), `--primary-soft`
  #122b28. Gold/orange/red tones unchanged; the pw-meter ladder is now
  red/orange/teal/gold (fills 6.68–9.38:1 vs the track). The unused base
  `--ok`/`--warn` tokens are deleted (nothing rendered with them). The
  checkbox accent-color moved to `--primary-focus` — the violet wave left it
  on the base accent, a 2.77:1 regression on --surface below the 3:1
  non-text floor (now 8.89:1, pinned in CI). Live-verified in a real
  browser: computed styles, meter rungs, reveal toggle
  (`e2e_gui/audit_screenshots/30–31`).

- **Therapist portal — "warm dusk" palette (2026-09-28 UI/UX audit,
  user-directed; superseded above within the same unreleased cycle)**: the
  blue accent and green success tones were replaced by violet/gold —
  `--primary` #6748cc violet (white label 6.22:1), `--primary-strong`
  #b3a4f5 lavender, `--primary-focus` #8b6ef0, `--info-accent` #c3b4f0,
  `--ok`/`--ok-strong` gold, `--warn`/`--warn-strong` orange. (Audit
  follow-up 2026-09-29 correction: the focus ring's originally claimed
  "≥4.5:1 on every dark surface" held only on the three main surfaces —
  on the banner softs it was 4.22–4.41:1, still above the 3:1 floor. The
  teal wave makes the per-surface claim exact and enforced.)

### Fixed

- **Therapist portal — 2026-09-29 independent-audit remediation** (every
  finding of the independent audit of commit efe1b5f, fixed and pinned):
  - checkbox `accent-color` rode the base accent and fell to 2.77:1 on
    --surface (below the 3:1 WCAG 1.4.11 floor) — now `--primary-focus`
    (8.89:1), pinned by a CSS-rule assertion in designTokens.
  - evidence phrase highlighting now also folds DIACRITICS (the engine
    ASCII-folds labels "café"→"cafe" while entries keep accents), and the
    match guard tests the normalized needle so a punctuation-only label
    can never mark every entry.
  - `patternAnchorLabel` covers every pid kind the engine emits, including
    the legacy `recurring_phrase:` pid (which rendered "a pattern" while
    its twins `phrase:`/`rumination:` said "a recurring phrase") and the
    `coupling:`/`sensemaking:`/`diversity:` kinds.
  - the 2026-09-28 F10 password reveal toggle and F5 Disclosure had zero
    automated coverage (the toggle's handler was the uncovered line in
    ui.tsx) — both pinned end to end in
    `portal/tests/remediation_2026_09_29.test.tsx` (toggle flips type and
    label, independent state across the two register rows, toggle is
    type=button, details/summary structure).
  - the test `press()` helper fired the form `onSubmit` even for DISABLED
    submit buttons (a real browser does nothing) — it now rejects loudly.
  - contrast comments across portal.css/PatientView state the exact
    measured ranges (the old "4.58–5.00:1 on every dark surface" and
    "8.2:1" sparkline numbers were overstated); the designTokens suite now
    enforces the focus ring per surface (bg, surface, surface-deep, and
    the three softs) and the sparkline stroke floor.

- **Therapist portal — every finding of the 2026-09-28 UI/UX audit
  (AUDIT_PORTAL_UIUX_2026-09-28.md, 87 → 97 after that wave), each
  re-verified live in a real browser:**
  - **F1 (Enter-to-submit)**: the UI kit rendered every button
    `type="button"`, so the multi-field login/register forms had NO submit
    control and a real browser's Enter silently did nothing (the fix-18
    tests dispatched `onSubmit` directly, which is why CI never caught
    it). `Button` gained a `type` prop; the primary actions are real
    `type="submit"` buttons with no onClick (the click routes through the
    form's onSubmit). New pins hold the type AND the no-onClick contract,
    and the test `press()` helper routes submit-button clicks through the
    owning form like a browser.
  - **F2 (phrase highlighting)**: pattern labels are punctuation-stripped
    by the engine while journal entries are not, so the raw
    `includes()` never matched multi-word phrases (live: 0 `<mark>`
    elements). Both sides now normalize to letters+digits before matching
    (live: 10/10 evidence entries highlight).
  - **F3 (stale "new" badges)**: per-card badges rode the server's
    `is_new` flag and stayed green after Mark reviewed while the header
    count reset to 0. Badges now derive from the same local anchor as the
    count (and say "new for you to review" before the first anchor).
  - **F4 (SAS mismatch copy)**: names the likely cause first — the
    account id was entered wrong — before the key-substitution alarm.
  - **F5 (copy density)**: a native accessible `<details>` Disclosure
    component collapses the longest policy paragraphs (login crypto note,
    note-encryption note, change-password mechanics, rotation grants)
    behind one-line summaries.
  - **F6 (raw error strings)**: `invalid credentials` maps to
    "Sign-in failed — check your username and password."; the api layer's
    "check the server URL" copy (the portal has no server-URL field) is
    now "check your connection". Unknown errors still surface verbatim.
  - **F7 (text-only measures trends)**: each instrument renders a
    per-instrument SVG trend with a full aria-label above the exact text
    line.
  - **F8 (raw pids)**: notes-only anchors render in human terms ("on a
    recurring phrase"), screen and print.
  - **F9 (date seam)**: the caseload "N patterns as of …" date is the
    clinic-LOCAL calendar day of the summary update timestamp (the same
    L-80 basis as the delta anchors; forDate remains the fallback) — it
    used to read "tomorrow" for clinicians west of UTC in their evening.
  - **F10 (toolbar labels, password reveal)**: caseload search/sort
    labels are proper 13px/600 labels; password fields carry a
    Show/Hide-password toggle.

### Fixed

- **Therapist portal — pattern-anchored notes invisible after a revoke**
  (GUI drill 2026-09-28 finding F1, pinned by two new `F1` cases in
  `portal/tests/views.test.tsx`): the notes-only chart (stopped consent)
  rendered only `pattern_pid === null` notes, so a note anchored to a
  pattern the therapist could no longer select — still stored, still
  served by the API at any consent status — had no UI surface, against
  the list view's own "Your notes about this patient stay" copy. The
  notes-only card now renders the WHOLE chart chronologically under "My
  notes about this patient", each anchored note carrying its pid as the
  one surviving anchor (`on pattern phrase:…`, the same coarse topic id
  the server already holds in plaintext); "copy forward last note" and
  the printed session summary (heading "Therapist notes (all)") cover
  the same whole-chart set. Verified live against the drill state that
  exposed it (see `e2e_gui/GUI_DRILL_REPORT_2026-09-28.md`, screenshot
  11): the anchored note, its edit history, and its Edit/Delete
  affordances render post-revoke. The active chart's general-notes card
  is unchanged (anchored notes still surface only via their pattern).
  Test-harness note: the M-22 case's `createNote` mock now answers with
  a contract-shaped `NoteOut` (id/created_at) — the old bare `{}` mock
  rendered an id-less row once the notes-only list stopped filtering.
- **Sentiment-lexicon polysemy at the rumination gate** (found by the
  1-year simulation above, pinned by
  `backend/tests/test_lexicon_remediation_2026_09_28.py`): "down" was
  curated at -1.3, so the directional particle ("took it down", "wrote
  it down") pushed mundane clusters past the -0.30 rumination bar alone
  — a recycling chore surfaced as a "repeated worry". Re-curated to
  -0.6 (VADER's own affective-sense weight, x4 scale): "feeling down"
  stays mildly negative, direction no longer classifies. "stop"
  inherited VADER's -1.2, so perseverative negation INVERTED it
  ("can't sleep, my mind won't stop" scored +0.222) and the flagship
  worry shape escaped the rumination kind entirely; curated to 0.0 —
  the word's affect lives in what is stopped — the phrase now lands
  non-positive and classifies through the negation-heavy path built
  for exactly that perseverative shape. Regenerated
  `shared/brain_lexicon.json`, both TS lexicon modules and
  `shared/brain_vectors.json` (one sentiment row: -0.95 -> -0.65);
  backend 1629 / web 668 / mobile 1965 / portal 413 tests green, and
  the 1-year campaign re-run proves both flips end-to-end (tom: zero
  rumination cards; maya: the sleep worry is rumination).

### Added

- **1-year, 10-user, every-endpoint E2E simulation** (2026-09-28,
  `reports/simulation1y/`): the simulation60 approach extended to 365
  days, ten personas (incl. a 365-day pure-noise control, a
  crisis-language persona, a structured-channels + PHQ-9 power user, an
  editor, and a sharing/key-lifecycle user) and all 52 mounted routes —
  live HTTP, real client crypto, clock-accurate per-day brain replays,
  determinism cross-checks (live == single-shot, 10/10), the full
  therapist-sharing lifecycle with both-end SAS verification and
  wrap-key rotation, data-key rekey, v1→v2 envelope upgrade + O(1)
  password change (consents survive), TOTP lifecycle, exports decrypted
  locally, access-log pagination, deletion + decoy salts, at-rest
  zero-knowledge probes (raw DB and WAL), and default-bucket rate
  limiting. **245/245 checks passed**; full story in
  `reports/simulation1y/SIMULATION_REPORT.md`.

Deep-audit remediation 2026-09-28, second batch (same audit wave,
continued): the LLM narrative sanitizer truncates BEFORE its rejection
chain (an over-length narrative used to return early, skipping the
URL/contact/advice/crisis checks entirely); the crisis engine's
concat-evasion channel marks original token boundaries ("weekend it
all" no longer contains "enditall"), gains Spanish past-tense/
periphrastic/progressive/idiom coverage ("me corté", "terminar con
todo", "no le veo sentido a la vida" + suppress-tier counterparts),
writes the Turkish dotless-ı pattern post-fold so BOTH engines match,
folds the small-capital homoglyphs (ꜱ ᴜ ɪ ʟ) NFKC leaves alone, and
maps leet "1" contextually (myse1f → myself while k1ll stays kill); the
recompute path accepts the full ISO-timestamp `created_at` every real
client writes (date-only parsing 400'd client-saved entries); the
portal decrypts entries under the four-part v2 AAD with a legacy v1
fallback (the therapist evidence drill-down was permanently
undecryptable) and sends `base_version` on note edits (the required
field 400'd every edit); the compose backup worker resolves
`BACKUP_KEY_FILE` like the app's `_secret_env` (the env-only read
failed every run — zero backups published) and the api service actually
mounts its `auth_token_secret` (the env pointed at an unmounted file
and crash-looped the boot); the Spanish sentiment lexicon drops the
ambiguous "solo"/"sola" ("only" was being scored as loneliness); docs
refreshed to match (release runbook's six-asset download, README
env-var table's missing rows, retention-schedule anchors).

Deep-audit remediation 2026-09-28 (see AUDIT_SESSIONS_2026-09-28.md for the
findings and AUDIT_REMEDIATION_2026-09-28.md for the fixes): web v2 sign-in
fresh-page-load dead-end fixed (session installed before the envelope
fetch, rolled back on every failure); rekey resume re-walks every stage
(the stage-skip could permanently strand old-key rows); the audit-journal
tail anchor actually wired (compose volume + env, Dockerfile-owned mount,
single-pass heads + retention-aligned atomic compaction); the offline
queue no longer wiped by a lockDown racing an enqueue; PUT
/account/password requires the processing-session possession probe from
every key scheme (web + mobile clients updated); the portal note composer
recovers from a timed-out save (both 409 codes burn the retry id); the
Entry mood log gets the Measures zeroize-race fix; rotations broadcast a
cross-tab lockdown before their first server step; Safari <15.2 gets a
real localStorage bakery mutex under withLock; legacy plaintext crisis
stamps swept at app mount; mobile sweeps orphaned random-id reminders
once; drift gate scans backup/ + *.yaml, proves every selftest failure
mode individually, and enforces a minimum pin count; metrics-token sinks
generated + asserted equal in CI/release and checked by verify.sh;
release runs serialize without mid-publish cancellation; token-revocation
hydration marks overflow; MAC verification constant-time.

## [2.0.1] — 2026-09-27

Independent-audit remediation round 2 (see AUDIT_REMEDIATION_2026_09_27_ROUND2.md):
durable jti revocation (token_revocation table + boot hydration + prune),
keyed audit-chain MAC seals + append-only journal tail anchor + seq-race
retry + daily chain-verification sweep, note create-channel 409 on changed
content, kdf_params re-store validation, _secret_env strip symmetry +
metrics-token file path, measured-only link day-after gate, honest phi_eff
documentation + K=1.0 sweep row + VS16 bare-emoji parity vectors, web
rotation-vs-offline-queue + measure zeroize-race + queue-lock fixes, portal
SAS/fingerprint cross-check + exact idle lock + masked TOTP secret, mobile
fingerprint-tripwire fix + fail-closed scheme routing + reminder-fallback
fix + VS16 canonicalization, fail-closed digest-drift gate with selftest
(now scanning Dockerfiles and shell scripts) + restore-script re-pin, CI
password-annotation redaction + metrics-token secret chain + release
concurrency, and defused time-bomb tests. Mobile coverage gate green again
(functions 86.11%); all suites re-verified.

## [2.0.0] - 2026-09-26

The 2026-09-25 → 2026-09-26 remediation and hardening campaign, cut as
a MAJOR because it is breaking-ish for integrators: the v2 key envelope
changes the registration contract (new `wrapped_data_key` +
`kdf_params` fields), v2 accounts are refused on the legacy
`PUT /account/credential` (409 `key_scheme_conflict`), the default
server scrypt work factor moved 2¹⁶ → 2¹⁷ (accounts hashed under the
old factor fail login after upgrade unless the operator pins
`MINDPATTERN_SCRYPT_N=65536`), and setting the new dedicated auth
secret deliberately invalidates every outstanding bearer (the `ksv`
bump). Existing v1 clients keep working (v1 flows unchanged and
supported; the `/api` legacy alias still answers with `Deprecation`
headers).

### Security & crypto

- **Random data-key envelope v2** (`backend/app/security/envelope.py`):
  the data key is a random 32-byte key wrapped under
  `HKDF-SHA256(master, info="mindpattern/envelope/v2")`; the server
  stores only the opaque 60-byte AES-256-GCM envelope. O(1) password
  change for v2 (`PUT /api/v1/account/password` — no corpus rekey);
  v1 self-upgrade via `POST /api/v1/account/key-envelope/upgrade`
  (password re-auth + a processing session that must authenticate
  stored ciphertext); `kdf_params` is a server-validated versioned
  blob (pbkdf2 100k–10M iterations; argon2id 19–256 MiB / t≥2 / p≤4 —
  validated but never computed server-side; no client ships Argon2id
  yet, the documented WebCrypto tradeoff).
- **SAS out-of-band pairing verification**: pairing lookup answers a
  6-digit SAS (`HMAC-SHA256(pairing_code, wrap-key DER + patient id)`,
  first six decimal digits) plus the wrap key's 16-hex fingerprint;
  `GET /api/v1/therapist/pairing/sas` (code in the `X-Pairing-Code`
  header) derives the identical pair therapist-side; both humans
  compare in the room/on the phone. A substituted server key changes
  the SAS.
- **Per-token `jti` revocation** (single-device logout) alongside the
  account-wide epoch bump; **purpose-split secrets**
  (`MINDPATTERN_AUTH_TOKEN_SECRET` / `_TOTP_WRAP_SECRET` /
  `_PAIRING_SECRET`, legacy fallback = identity derivation); server
  scrypt N=2¹⁷; **exact sliding-window rate limiters** with sharded
  overflow locks; `/metrics` joins the ops limiter; strict `_bool_env`
  parsing and an edge body-buffer memory budget validated at boot.
- **Audit-log forward hash chain** (per-patient `prev_hash` →
  `entry_hash`, canonical encoding) with a terminal `account_deleted`
  row; chain verification exposes silent edits/removals.
- **Therapist notes optimistic concurrency** (`base_version` required:
  400 `version_required` / 409 `version_conflict` — no more
  last-write-wins) with immutable revisions under the chart quota.
- **Measures DELETE correction path** (verifier-gated, advances
  `measures_revision`, audit-logged `delete_measure`).
- **Resumable chunked rekey journal** (per-stage cursor; interrupted
  runs resume idempotently; wrong-old-key still aborts with
  `rekey_key_mismatch`).
- Client waves in the same campaign: web (encrypted draft preservation
  across lock, cross-tab queue lock, pending-measure persistence,
  proactive token-expiry guard, language setting, windowed history,
  CSP `style-src 'self'` with zero `unsafe-inline`, SRI stamping);
  portal (interaction-only idle/visibility lock, scan cancellation +
  confirmation, CSP hardened, note idempotency + honest
  history-failure rendering, TOTP recovery codes copy/download);
  mobile (stable reminder notification id, encrypted pending measures,
  `__DEV__` URL selection, sealed `stateSeq` mark, `APP_VERSION` from
  the build, device verification checklist
  `mobile/tools/DEVICE_VERIFICATION_CHECKLIST.md`, README sync-model
  rewrite to the two-writer S-contract).

### Statistics engine (2026-09-26 statistical review)

- Within-person **weekday deconfounding** for every mood-association
  test (per-weekday centering of residuals).
- EWMA control limit **recalibrated to L=3.1 by Monte Carlo** (≤5%
  false-alarm at φ=0.5; λ stays 0.18; calibrated alarm-probability
  p-value with magnitude conditioning replaces the marginal erfc tail).
- **Miller–Madow bias-corrected** weekly activity-tag entropy with
  tag-volume floors and `DIVERSITY_MIN_WEEKS=4`.
- Link labeling honesty: "the day after" only when gap-1 is the mode
  AND ≥70% of measured exposed outcomes (`LINK_DAY_AFTER_SHARE`).
- Replication gates split into EVIDENCE_DATE (needs a NEW evidence
  day) vs WINDOW_STAT (qualification days ≥2 calendar days apart)
  kinds; cadence comparisons deflate n to `n_eff`; language verdict by
  share rule with an honest `"other"` (short windows no longer default
  English); Spanish person anchoring; daily question pool pinned on
  first computation.

### Documentation & compliance (2026-09-26 pass)

- New operator/legal pack: `docs/OPERATOR_PACK.md` (index),
  `PRIVACY_POLICY_TEMPLATE.md`, `DATA_RETENTION_SCHEDULE.md`,
  `SUBPROCESSOR_BAA_REGISTER.md`, `SECURITY_POLICY.md`,
  `security.txt.example`.
- `DPIA_SKELETON.md` completed into a signable template (controller
  block, Art. 35(7) elements from code reality, REQUIRED age-gate
  control (the app ships none — self-declared 18+ design included),
  Art. 36 prior-consultation triggers, journal-retention statement,
  730-day audit retention defended, signature blocks).
- `INCIDENT_RUNBOOK.md`: FTC HBNR operationalized (60-day individual
  notices with the five required content elements, ≥500 FTC + media
  notices, sub-500 annual reporting, OPERATOR-FILL contact-role
  table, no-user-email substitute-notice path).
- `IRB_STUDY_PROTOCOL.md`: exclusion screening now names validated
  instruments (PHQ-9 item 9 ≥1 + C-SSRS screener) instead of the app's
  own crisis-phrase gate.
- RESEARCH.md citation corrections (Snippe 2023; Konjarski 2018
  relabeled systematic review; Al-Mosaiwi 6(4); Houben 141(4):904–940;
  λ band softened to "recommended range"; Bourke et al. 2026
  meta-analysis added) + a shipped-methodology addendum with the
  in-code constants; README brain-table constants, residuals list, and
  crypto/API sections updated to the shipped tree (49 brain-vector
  sentiment cases, 472 Spanish lexicon words, L=3.1, sliding-window
  limiter wording); WEB_PLAN 7.x/9.x boxes squared with reality;
  PSYBERGUIDE self-assessment moved to four-way crypto pinning;
  SECURITY_RESIDUALS/WEB_THREAT_MODEL re-swept (fixed residuals
  removed: English-only chrome, draft loss, measures offline loss,
  CSP unsafe-inline in shipped clients, mutable operator image tags).

## 2026-09-26 (iii) — deep-penetration remediation: every actionable finding fixed and re-tested

The deep penetration campaign (`PENTEST_DEEP_2026-09-26.md`: four parallel
static audits + a fresh 13-probe live exploit suite on top of the 96-verdict
redteam baseline) found no Critical/High remote exploits. Every actionable
finding is fixed below; each fix carries a pinning test that fails against
the pre-fix code.

### Backend

- **D-1 — CORS omitted `X-New-Processing-Token`.** Allow-listed browser
  clients could not preflight `POST /processing/rekey`, functionally
  blocking data-key rotation after a suspected compromise. Added to
  `allow_headers` (`app/main.py`); preflight pinned in
  `tests/test_pentest_2026_09_26_fixes.py`.
- **D-3 — TOTP same-code race (live-confirmed: two concurrent logins with
  one fresh code both returned 200).** The replay fence is now an atomic
  conditional UPDATE (`totp_last_counter IS NULL OR < matched`), rowcount
  authoritative — the pinning test fires two concurrent logins and asserts
  exactly one 200 / one 401.
- **D-4 — no per-account TOTP guessing throttle.** New per-username
  failure bucket (`totp_failure_limit`, env `MINDPATTERN_TOTP_FAILURE_LIMIT`,
  default 10/window) checked inside the second-factor branch — reachable
  only with a valid verifier, so it is not a lockout oracle for
  unauthenticated spray.
- **S-3 — lost authenticator required an operator clear.** Enable now mints
  8 single-use recovery codes (10 chars from the pairing alphabet,
  ~49.1 bits each): HMAC-SHA256 digests only at rest (domain-separated
  HKDF subkey), returned EXACTLY once in the enable response, redeemed at
  login in place of the 6-digit code via an atomic `used_at` UPDATE,
  cascade-deleted with the account, purged on disable. New table
  `totp_backup_codes` (alembic `e8b2d6f4a1c7`; schema-parity gate green,
  `SCHEMA_HEAD` updated).
- **D-2 mitigation — `credential_rotated` access-log row.** A stolen
  verifier's full takeover chain (login → rotate → victim lockout,
  live-demonstrated in the campaign) is architecturally inherent to
  no-PAKE, but the rotation is now auditable in the victim's access log,
  in the same transaction as the swap.

### Web client

- **S-1 — password rotation bypassed the password policy.** The rotation
  gate checked length only, silently lowering the offline-guessing floor
  exactly where it matters most. `rotatePassword` now applies the full
  registration policy (`passwordPolicyError`), matching mobile; the old
  fixture passwords in the parity tests violated the policy and were
  rotated to policy-passing passphrases (the policy rejecting them IS
  the fix working).

### Portal

- **S-3 — recovery codes surfaced in the UI.** Enable renders the one-time
  set with a shown-once warning; the sign-in code field accepts both the
  6-digit code and a 10-char recovery code; disable destroys the set.
- **S-4 — interrupted password change stranded the sharing key on reload.**
  The recovery salt is mirrored into sessionStorage (never localStorage),
  so a reload of the still-open tab re-arms the repair form; scrubbed at
  every lock boundary in `App.tsx` and on completed repair.
- **S-12 — patient-role login minted a bearer that stayed live.** The role
  rejection path now fires best-effort `auth.logoutBearer` (epoch bump)
  before surfacing the error, closing the asymmetric session-end gap.

### Mobile

- **S-5 — offline unlock guessing ran at a flat 500 ms cadence.** New
  `src/unlockBackoff.ts`: durable per-account consecutive-failure counter
  in the encrypted secure store, doubling pause per failure
  (500 ms → 30 s cap, saturating at 12), cleared on any successful unlock;
  the offline wrong-proof and online-401 paths funnel through one
  record+pause site. Curve and persistence unit-pinned; screen wiring
  pinned in `tests/screens/unlockScreen.test.tsx`.
- **S-7 — iOS had no screen-recording cover while foreground-active.**
  `AppDelegate` now observes `UIScreen.capturedDidChangeNotification` and
  raises the same opaque shield during capture/recording (independent of
  the transition snapshot shield). Native change — needs on-device
  verification in the next build.

### Hygiene

- **S-14 — `mobile/ios/.xcode.env` flagged by secret scans.** Verified
  content (one `export NODE_BINARY=$(command -v node)` line — no secret);
  the file is the RN template's committed build shim, so untracking it
  would break fresh clones. Allowlisted with a written defense in
  `.gitleaks.toml` and in the redteam G3 probe instead.

### Deliberately not code-changed (documented trades, see the pentest report)

- **D-2 (full fix)** — PAKE (OPAQUE) migration to retire the
  password-equivalent verifier: an architecture decision, not a patch.
- **S-2** — TLS SPKI pinning for the consented key-shipment hop: JS
  `fetch` cannot inspect certificates, so this needs per-platform native
  networking work plus a pins-distribution decision for a self-hostable
  deployment; the report carries a concrete implementation plan.
- **S-6** — plaintext entry dates in the offline queue: the meaningful
  fix (metadata encryption) interacts with the data-key rekey/queue
  interplay and needs its own design pass; documented residual.
- **S-9/S-10/S-11/S-13** — documented residuals (enumeration oracle,
  intended `/meta` ops data, synthetic-event lock semantics, legacy
  `/api` mount sunset policy).

Suite results after this pass: web 449 passed + tsc clean, portal 342
passed + tsc clean, mobile 1729 passed + tsc clean, backend full suite
green including the new `tests/test_pentest_2026_09_26_fixes.py`; ruff +
mypy clean; the 13-probe pentest suite re-run confirms the rotation-header
preflight now passes and the TOTP race is closed.

## 2026-09-26 (ii) — audit-of-the-audit: every residual finding fixed and re-tested

An independent verification pass over the 2026-09-26 remediation commit
audited all 135 changed files against their claims. The four suite-count
claims reproduced exactly, but the pass found 1 HIGH and ~13 MEDIUM
defects the remediation itself introduced or left open — including two
claimed fixes that did not actually work (H-6's byte quota, M-B1's epoch
fences) and three green tests that pinned production-impossible states.
Everything actionable is fixed below, each annotated
`2026-09-26 audit follow-up` inline. Suite results after this pass:
backend 1465 passed / 97.35% coverage (floor 97) + ruff + mypy clean,
mobile 1723 passed + tsc clean, web 448 passed + tsc clean, portal 337
passed + tsc clean; redteam `e_crisis` 0 errors (corpus 119→128 rows,
want==observed); monitoring `verify.sh` (incl. `--production`) all
green.

### HIGH

- **N-1 — the H-6 chart byte quota double-counted every edited note.**
  The budget SELECT summed note bytes across the revision outer join, so
  a note with N revisions was charged ~2N blobs: edited charts hit the
  cap at roughly half the budget, and a note at the revision cap could
  never be edited again (only deletion recovered). Both byte totals are
  now scalar subqueries over their own tables; the pinning test uses a
  budget where correct and fan-out math diverge (mutation-verified).
- **Test masking, three ways (N-3 + web/mobile rotation tests).** The
  M-B1 epoch-fence tests passed detached ORM objects the request session
  could not refresh, the web resume-ladder test pinned the RNG to a
  fixed salt, and the mobile ladder test used an empty journal — each
  green test pinned a state production cannot reach. All three now
  exercise the real wiring (attached identity-map users; the persisted
  pending salt; a v2-bound journal row).

### MEDIUM

- **N-2 — six `account.py` epoch fences were no-ops** (LLM consent,
  account deletion, TOTP setup/enable/disable, and — a regression —
  `rotate_credential`): `expected_epoch` was captured AFTER
  `_require_verifier`'s in-place `populate_existing` refresh of the very
  same ORM object, so the fence compared the post-bump epoch against
  itself. All six now capture the epoch BEFORE the proof (the pattern
  consents.py/therapist.py already used); rewritten tests fail loudly
  against the old ordering (mutation-verified).
- **Rotation resume ladder, all clients (B-1).** The M-W2/F-4 ladder was
  unreachable in production: every retry drew a FRESH salt, so the
  re-derived key could never read the corpus the earlier attempt
  rekeyed — and the UI told users to "repeat the password change to
  finish it", an instruction that always dead-ended. Web and mobile now
  persist the pending salt before the rekey attempt (cleared only on
  full completion) and reuse it on retry; the mobile probe also passes
  `content_version` through (every entry since M-2 is v2-AAD-bound; the
  legacy-only retry read false for any real journal).
- **B-2 — an empty journal no longer trivially verifies the ladder** on
  either client: the rekey also moves measures, so the probe falls
  through to a PHQ-9 row (both empty still trivially verifies).
  Previously a measures-only user could "verify", finish the rotation,
  and silently orphan every stored score.
- **B-3 — the unverifiable-mismatch path now locks down** (web and
  mobile): the corpus is provably under a key the vault cannot read, so
  a live session must never keep writing under the dead old data key —
  the H-4 rule, applied to the one path that escaped it.
- **B-4 — web rotation tolerates per-grant rewrap failures** like
  mobile: one therapist's 503 (or a failed listing) no longer aborts a
  rotation whose corpus and credential already moved; completion now
  carries an honest partial notice (new bilingual copy).
- **N-4 — the ʂ/ᵴ homoglyph additions were server-only.** The TS
  crisis engines' lookup character class did not cover the Phonetic
  Extensions block, so the mapped ᵴ could never fire client-side
  ("ʂuicide" folded server-side, no client dialog). Both engines now
  mirror the map AND the class; pinned by dialog_fires fixtures and two
  new corpus rows.
- **Crisis false positives on everyday Spanish (the H-1 cost).** "me
  quiero cortar el pelo" (a haircut) and "no hay salida de emergencia"
  (an emergency exit) fired the interruptive dialog. Fixed with the
  engine's own benign-compound masking (same mechanism as "suicide
  squad"): grooming/nail-cutting, emergency-exit/navigation, colloquial
  disappearing, and the common body-part injury forms; the bare
  self-harm phrasings keep full recall. 7 new dialog_silent fixtures + 5
  benign corpus rows pin the silent side; "tired of living in <place>"
  (EN) and "me lastimo cuando corro" (no body part) stay accepted
  conservative triggers, mirroring their pre-existing twins.
- **N-5 — therapist self-erasure un-gated** (deletion-availability
  reversal): the audit's LOW item e had added `require_sharing_enabled`
  to DELETE /therapist/account, retiring the deliberate 2026-09-21
  guarantee that a feature shutdown must block sharing, never
  self-erasure. Deletion is not a sharing surface (verifier-gated,
  epoch-fenced, serves no patient content); the gate is removed again
  and the availability guarantee re-pinned.
- **N-6 — caseload listing work is bounded again.** With the lifetime
  413 gone, the listing serialized a per-patient lock + queries for
  EVERY historical consent under one therapist fence. Per-patient
  fences now guard ACTIVE grants only (bounded by the 100 cap);
  revoked rows assemble from one bulk read with a batched existence
  check preserving the concurrent-deletion skip semantics.
- **Portal N-1 — the state_seq guard now covers the caseload scan**,
  its second consumer: a replayed older insights blob degrades to the
  honest error row instead of feeding stale sensitive-flags into triage
  sort (exported the chart's guard; rollback test added).
- **Infra B1 — the root compose `backup` service got the M-I3
  treatment** it was missed by: cpus 1.0 / pids 64 / mem 512M (the dev
  overlay inherits via merge). Also: blackbox `http_2xx` truly
  equivalent to the stock module (5s timeout + ip4 preference — the
  claim was false before), `verify.sh` now actually cross-checks the
  module names prometheus.yml names (commented optional jobs included),
  and WEB_PLAN's P8 row no longer dates i18n done before M-W5 closed it.

### LOW / INFO

- ES temporal questions no longer double-pluralize ("los martess"):
  dedicated `{day_plural}` forms (lunes..viernes invariant;
  sábados/domingos plural), all seven days pinned.
- `LocalRecomputeRequest` state blobs: schema ceiling now mirrors the
  config ceiling instead of pre-empting the route at ~1.07 MiB.
- Rotation now REWRAPS the mood log, question feedback, and pattern
  mutes under the new key instead of clearing them (B-7; clear remains
  the fallback), and the "Get help" crisis chrome + login placeholder
  are localized (B-5), legacy plaintext mutes are adopted at unlock
  instead of at first Patterns visit (B-6).
- Portal logout carries `keepalive` (N-2) and the failed-unlock path
  revokes the freshly minted bearer server-side (N-3); the bfcache lock
  route's logout fire is now asserted (coverage gap).
- Merged-map fold-invariance: the one divergent twin (`tensión`) is
  canonicalized and the class is pinned over both merged maps (N-11);
  the stale "port is the follow-up" comment corrected (N-10).
- Python sentiment scoring accumulates floats naively (left-to-right)
  to match the TS ports — builtin `sum()` is Neumaier-compensated since
  3.12, so bit-identical walks could diverge in the last ULP; a
  divergent golden vector pins the order (E-7).
- Mobile: `@react-native/babel-preset` pinned as a direct devDependency
  (it resolved only via hoisting); the polyfill bootstrap extracted to
  `installPolyfills.cjs` with a real child-process test that deletes
  `Buffer`/`crypto` before loading it; quarantine/rejected byte bounds
  never drop the last remaining (newest) record; the conflict-snippet
  "(N characters total)" reports the raw text length.
- Corpus/doc accuracy: the unpinned "life doesn't feel worth it"
  pattern gained corpus rows; the audit report's change-surface figure
  corrected to the actual 135 files / +8,411 (insertions were
  understated by ~2.8k).

## 2026-09-26 — full-codebase deep audit: every finding fixed and re-tested

A nine-pass exhaustive audit of every file (mobile and web audited
independently; report: `AUDIT_FULL_CODEBASE_2026-09-26.md`) found no
CRITICAL issues, 7 HIGH, ~20 MEDIUM and a LOW/INFO tail. Everything
actionable was fixed the same day, each fix annotated inline with its
finding ID and covered by new tests. Suite results after remediation:
backend 1464 passed / 97.35% coverage (floor 97), mobile 1706 passed +
tsc clean, web 437 passed + tsc clean, portal 336 passed + tsc clean +
coverage gates exceeded; redteam `e_crisis` 0 errors; monitoring
`verify.sh` (incl. `--production`) all green; gitleaks full-history and
working-tree scans clean.

### HIGH

- **H-1 — crisis-language coverage gap (safety-critical; found
  independently by two audit passes).** EN: the worth-living family
  ("life is not worth living", "life doesn't feel worth it"), "no longer
  want to live", "tired of living", first-person "want to overdose" and
  "suicidality" matched NEITHER tier. ES: only six ideation phrases
  existed — "me quiero cortar", "no vale la pena vivir", the conjugated
  "quitar(se) la vida" forms and ~15 other first-person self-harm /
  hopelessness phrasings fired nothing, and an uncovered phrase could be
  quoted verbatim into reflective questions. Fixed at the contract level
  (`shared/crisis_phrases.json` + all four embedded copies in lockstep):
  22 new dialog patterns, 4 new suppress_extra patterns, 30 new
  dialog_fires fixtures, 3 new benign fixtures, 4 suppress-only
  fixtures, 29 new red-team corpus rows (corpus now 119 rows,
  want==observed on every row), and one verbatim firing sample per new
  pattern in `test_checklist_round4_crisis.py` (78 dialog / 23
  suppress samples, index-parity).
- **H-2 — mobile password rotation crashed on-device**: `freshSalt()`
  used `globalThis.crypto` (absent in RN) and ran outside the try. Now
  uses the engine CSPRNG seam inside the guarded block; rotation works
  with `globalThis.crypto` deleted (pinned).
- **H-3 — mobile app could fail to boot on device**: no bootstrap
  installed `global.Buffer`/`global.crypto` and no babel/metro configs
  existed. `index.js` now runs `QuickCrypto.install()` before anything
  else; `babel.config.cjs` + `metro.config.cjs` added (.cjs because the
  package is ESM).
- **H-4 — web rotation data loss**: a failure after the server rekeyed
  left a live session writing under the dead old key. The F-4 lockdown
  is ported (honest message + `onLockdown`), the mobile
  `rekey_key_mismatch` resume ladder is ported (verify-and-continue from
  the rewrap stage), and derived keys are zeroized on every exit.
- **H-5 — web inverted the sentiment contract**: the machine text
  estimate was written into the encrypted payload's explicit-mood field
  on every entry. The payload now carries only an explicit pick (mobile
  parity); the mood log records on every save with
  `pick ?? estimate`; the mood calendar sources pick-first.
- **H-6 — therapist note revisions bypassed the chart quota** (~7.7
  GB/hour unbounded growth). Revisions now count into the quota
  (rows+bytes) with a per-note revision cap and deterministic
  oldest-eviction.
- **H-7 — therapist caseload permanently 413'd past 100 lifetime
  consents.** The cap now counts ACTIVE consents only (the F-9 fix's
  therapist twin).

### MEDIUM

- **M-B1** verifier-gated lifecycle ops (grant/revoke/rewrap, LLM
  consent, account delete, TOTP, wrap-key rotate) now re-read the user
  row inside their fences and enforce `token_epoch` equality — a stale
  pre-rotation verifier+token can no longer complete them.
- **M-B2** caseload summaries now gated on the v2 sharing disclosure on
  both the write and serve paths, matching the measures discipline.
- **M-B3** post-threshold daily questions render in Spanish for Spanish
  corpora (ES template set + ES generic pool, byte-pinned to
  `shared/generic_questions_es.json`); EN unchanged.
- **M-B4** ES lexicon dead accented keys replaced/aligned (fold
  invariance now exhaustively pinned).
- **M-M1** the legacy-AAD decrypt fallback is gated to `contentVersion
  === 1`; version ≥ 2 fails closed.
- **M-M2** offline-queue quarantine/rejected stores are count+byte
  capped with drop-oldest; the catch-path quarantine append can no
  longer wedge a scope.
- **M-M3** two-writer conflict dialog snippets both sides (300 chars +
  honest total length) before the overwrite choice.
- **M-M4** all navigator titles + boot tagline resolve through i18n in
  both locales (pinned by a new Spanish-render test).
- **M-M5** password rotation catches unexpected throws with calm copy.
- **M-W1** web Measures view handles every terminal load error (no more
  permanent "Loading…").
- **M-W3** account deletion wipes the per-account IndexedDB surface
  (queue, version marks, analysis generation, mutes).
- **M-W4** muted pattern IDs moved behind the data-key-encrypted kv
  seam (legacy plaintext adopted once and removed).
- **M-W5** the web client is genuinely bilingual: all view copy routed
  through the catalogs (256 keys added to both), locale-aware prompt
  chips, the localized daily question on 404/offline, and a locale-flip
  consumption test that would have caught the original drift.
- **M-P1** the portal now revokes its bearer server-side on sign-out,
  idle lock, 401 expiry and bfcache restore (best-effort keepalive
  `POST /auth/logout`), consumes the insights `state_seq` rollback
  guard, and honors the `X-Measures-Revision` snapshot contract with the
  same one-restart traversal as entries/notes.
- **M-I1/M-I2/M-I3** Dependabot covers `/web`; optional node/blackbox-TLS
  monitoring (disk-full + cert-expiry alerts, digest-pinned, grounded in
  `verify.sh`); CPU + pids limits on every container.
- **M-D1/M-D2** docs corrected: 5-minute web idle lock (README + DPIA),
  14 CI jobs, 7,726-word lexicon count, WEB_PLAN dashboard brought up
  to shipped reality with the P9.10 deferral registered in
  SECURITY_RESIDUALS.

### L-3 follow-through (cross-platform parity)

The backend's language-gated Spanish scoring (ES-winning merge,
EN-scoped negators) is now mirrored on-device: the lexicon dump emits
`sentiment_lexicon_es`, `negators_en` and the detection tables to all
three artifacts (shared JSON + mobile + web TS), both client engines
select the merge by detected language with the no-language default
byte-identical to the pinned vectors, and the mood-log callers detect
per text. New `brainLanguage` parity pins on both clients.

### Also fixed (LOW/INFO selection)

Mobile: prototype-chain guard on `maxScoreForMeasure`, corrupt base-URL
typed error, `exportAccount` strict-redirect flag, `clearQueue` mutex,
dead `biometricCapability` removed, ambiguous ES conflict copy, ES
weekday grammar, rotation-card password state separation, measures
status timer + localized history labels, offline measures retry
affordance, locale-formatted filter/share dates, draft re-stash guard,
measures intro naming all three instruments, `versionName` 1.0.0.
Web: measures pagination terminal probe, LLM-settings unknown state,
per-day crisis prompt cadence, real kv enumeration in the red-team
scrape, a11y scans for the remaining five views. Backend: CORS expose
list carries the measures/cursor headers, `create_note` releases its
read transaction before the chart lock, `local_recompute` epoch fence,
`/meta` rate-limited, therapist-delete sharing gate, `MAX_BODY_BYTES`
ceiling, recompute schema caps, `uv.lock` aligned to `requirements.in`
(+ drift guard), orphaned `e2e_test.db-*` sidecars removed, exotic
homoglyphs (ʂ, ᵴ) mapped. Infra: gitleaks allowlist narrowed to
generated artifacts (hand-written `reports/` source is scanned again —
canary-verified), gitleaks + shellcheck pre-commit hooks, nginx
`limit_req_status 429`, sized offsite tmpfs, `.dockerignore` caches.
Docs: token-secret rotation runbook section (TOTP lockout + decoy
boundary), multi-tenant/insider threat row, notes-retention residual
documented for counsel.

## 2026-09-26 — independent E2E browser campaign: 24-point pass, all three findings fixed and re-verified

A black-box end-to-end pass over the patient web client (and, where the
patient flow requires a counterpart actor, the therapist portal) driven
through a real browser against the real FastAPI backend — the true
production bundles (`tsc + vite build + SRI`), not component tests. 22 of
24 points passed outright; 2 flows were honestly untestable in the runtime
(offline-queue reconnect needs network emulation; the Spanish locale needs
a locale-capable runtime). Full report with screenshots:
`E2E_TEST_REPORT_2026-09-26.md` + `gui-test-screenshots/`. Three findings,
all fixed the same day:

- **F1 (Blocker — dev tooling only; production bundles were never
  affected) — `npm run dev` rendered a permanently blank page in web AND
  portal**: the app's own CSP (`script-src 'self'`, no `'unsafe-inline'`,
  enforced by both the index.html meta tag and the dev-server header copy)
  blocks @vitejs/plugin-react's inline react-refresh preamble, so every
  transformed module throws on boot and React never mounts (all modules
  200; `$RefreshReg$` undefined; `#root` empty). Fix: a dev-only
  `devInlineScriptHashes()` plugin in both `vite.config.ts` files
  (`apply: "serve"`, `transformIndexHtml` order `post`) hashes the inline
  module scripts the dev server actually serves and appends those
  `'sha256-…'` tokens to the meta CSP, while the dev server drops its CSP
  header so the hashed meta policy governs. No `'unsafe-inline'`
  introduced (the pinned `securityConfig.test.ts` ban still holds); the
  production triple (index.html file, `public/_headers`, nginx) is
  untouched. Verified live: both dev servers now render their sign-in
  screens in the browser.
- **F2 (P3) — Privacy view's Back button stretched ~1000px wide** (Card
  is a flex column; the bare stretch child ignored the codebase's
  flex-row idiom): wrapped in the standard row container; measured 55px
  in the served production bundle.
- **F3 (P3) — "Delete my account" was clickable before the typed
  confirmation** (the guard lived only in the click handler): the button
  is now `disabled` until the field reads exactly DELETE, with the
  handler guard retained as defense in depth. The parity test now pins
  the stronger contract (disabled state, not a forced click), and the
  `rtr.tsx` `press()` helper fails loudly when asked to press a disabled
  button.

Post-fix gates: web suite 407 passed / 5 skipped (coverage thresholds and
the SRI/security-config pins green), portal suite 316 passed, both
typechecks and production builds clean; every fix re-verified live in the
browser against the real backend.

## 2026-09-26 — independent mobile+web security audit: all four findings fixed, web hardened to industrial header policy

A fresh audit of both patient clients (verification: source-level control
comparison, both test suites executed, `npm audit` clean, repo secret scan)
found no exploitable vulnerability and four hardening gaps — F-1 Medium
(Android release signing), F-2 Low (no mobile cert pinning posture), F-3
Low (iOS snapshot shield race), F-4 Low (no secret-scanning gate). All four
are fixed here, plus an industrial hardening pass on the web client's
policy files:

- **F-1 (Medium) — Android release artifacts are never debug-signed
  again**: the `release` buildType now signs from a private
  `android/keystore.properties` (gitignored; `keystore.properties.example`
  documents the shape), and a `gradle.taskGraph.whenReady` guard throws a
  clear `GradleException` when a release output is demanded without it —
  debug builds are untouched. R8 minification is enabled for release with
  obfuscation deliberately off (`-dontobfuscate` + conservative keeps:
  the Hermes bundle carries the app logic; un-renamed symbols keep
  reflective bridge lookups safe). Pinned by new preflight checks 9-10.
- **F-2 (Low) — mobile transport trust posture**: Android now ships
  `network_security_config.xml` — release trusts SYSTEM certificate
  authorities only (a user-installed CA can no longer MITM the bearer
  token or the one-time data-key shipment), cleartext is banned outside
  the explicit loopback hosts the JS client already permits, and debug
  builds keep user-CA debugging via `<debug-overrides>`. SPKI pinning is
  recorded as a written decision (not an oversight) in
  `docs/SECURITY_RESIDUALS.md`: no static pins can exist for user-hosted
  servers and RN's JS fetch never exposes the peer certificate, so TOFU
  needs a native module this repo's CI cannot land safely; the iOS
  user-installed-CA residual is documented. Pinned by preflight check 11.
- **F-3 (Low) — iOS app-switcher shield is now native**: a synchronous
  `willResignActiveNotification` observer in `AppDelegate.swift` drops an
  opaque cover over the window BEFORE iOS captures the transition
  snapshot — the JS overlay in `App.tsx` (kept as belt-and-braces, with
  the themed color) rendered asynchronously through the bridge and could
  lose the race. Pinned by preflight check 12.
- **F-4 (Low) — secret-scanning CI gate**: a new `secrets` job in
  `ci.yml` runs gitleaks 8.30.1 (version- AND sha256-pinned, like every
  external tool in the pipeline) over the full git history AND the
  working tree. `.gitleaks.toml` extends the default rules; every
  allowlist entry (published crypto vectors, test fixtures, generated
  trees) carries a written defense. Verified clean locally in both modes.
  Preflight check 13 additionally refuses any tracked release-keystore
  material.
- **Web industrial hardening — CSP with zero `'unsafe-inline'`**: the
  shell stylesheet moved from an inline `<style>` block to the
  same-origin `/app.css` (React's CSSOM inline styles are outside
  style-src, so nothing else needed it), letting `style-src` tighten to
  `'self'` across all four configs (meta, `_headers`, nginx, dev
  server).
- **Web industrial hardening — policy upgrades**: `form-action 'none'`
  (zero native form submissions exist), `frame-src 'none'`,
  `upgrade-insecure-requests`, `Cross-Origin-Embedder-Policy:
  require-corp`, an extended deny-list `Permissions-Policy`
  (accelerometer, gyroscope, magnetometer, display-capture,
  idle-detection, browsing-topics, serial, bluetooth), HSTS with
  `preload` (submission to hstspreload.org is the operator step,
  documented in deploy/README.md), and `X-Robots-Tag: noindex, nofollow`
  + a robots meta — a mental-health journal must stay out of search
  indexes and referrer graphs. All four configs carry the identical CSP
  literal, now with a comment-stripped no-`unsafe-inline` drift pin.
- **Web industrial hardening — integrity + disclosure**: `npm run build`
  now stamps sha384 Subresource Integrity on every local subresource of
  the built shell (`tools/add-sri.mjs`, fail-closed), and the static host
  ships an RFC 9116 `.well-known/security.txt` (operators replace the
  placeholder contact — called out in deploy/README.md).

Verification: web 407 green (coverage over the 85/75/85/90 floors),
`tsc` + production build clean with both SRI stamps, mobile 1648 green +
typecheck + native-release preflight all-green (13 checks), gitleaks
clean in git-history and working-tree modes.

## 2026-09-25 (c) — mobile-parity security audit of the web client: all six findings fixed

`AUDIT_WEB_PARITY_2026-09-25.md` compared the patient web client control-by-
control against the standard the mobile client was held to. Core architecture
(crypto stack, key custody, transport hardening, queue/integrity, sharing,
crisis safety) was already at parity; six deviations were found and are all
fixed and tested here (web 406 green, coverage 89.3/80.2/88.3/93.3 over the
85/75/85/90 floors; build clean, 156.65 kB gz):

- **W-1 (Medium) — hidden-tab lock (mobile background-lock parity)**: the
  web client now locks the session the moment the tab is hidden
  (`visibilitychange → hidden`), exactly like mobile locks on AppState
  background — decrypted text no longer stays rendered (and readable in
  tab-hover previews) while the user is elsewhere. The idle window
  tightened from 10 to 5 minutes at mobile parity, and `mousemove` no
  longer counts as activity (a mouse jiggler used to defeat the idle
  lock; only click/keydown/scroll/touchstart reset it now).
- **W-2 (Medium) — anti-phishing error sanitizer (mobile F2 parity)**:
  server-supplied `detail` is now run through the mobile client's
  sanitizer before any banner render — URLs of ANY scheme, scheme-less
  domains (any alpha TLD, no allowlist), phone-like digit runs, bidi
  overrides, and invisible/zero-width characters are stripped, then
  capped at 200 chars + ellipsis. The 2026-09-19 mobile corpus (bit.ly,
  mindpattern-support.de, discord.gg, word-joiner domain splits) now pins
  the web client too (`detailToMessage` in `api/client.ts`).
- **W-3 (Med-Low) — password shape rules (mobile L-6 parity)**: web
  registration now enforces the common-word blocklist ("password",
  "qwerty", "123456"…, "mindpattern", "journal"), whole-password
  single-character runs, and keyboard walks — the shape rules a
  zero-knowledge server can never enforce. The policy is now genuinely
  identical to mobile's.
- **W-4 (Med-Low) — fingerprint attestation gate (mobile C-7 parity)**:
  granting therapist access now requires BOTH attestations — an explicit
  "we read the fingerprint back and it matched" confirmation AND the
  disclosure terms. Passive display plus a warning no longer suffices.
- **W-5 (Low) — server `user_id` validation (mobile L-7 parity)**: a
  login/register response whose `user_id` falls outside the 32-hex
  contract is refused fail-closed (keys zeroized, vault locked, no
  session) — a hostile server can no longer feed malformed ids into the
  vault owner binding, AAD contexts, or storage keys.
- **W-6 (Low) — sign-out flag hygiene**: explicit sign-out and account
  deletion now wipe this browser's non-content `mindpattern.*`
  localStorage flags (onboarding/mute/threshold stamps), matching
  mobile's origin-bound state wipe — a shared computer keeps no trace an
  account used it. Idle/expiry locks deliberately keep the flags (they
  are not sign-outs), and onboarding therefore honestly repeats after an
  explicit sign-out.

Threat-model and plan docs updated (`WEB_THREAT_MODEL.md` key-custody
residual now names the 5-min idle + hidden-tab bounds; `WEB_PLAN.md` 2.7
carries the correction note).

## 2026-09-25 (b) — independent-audit remediation of the web client commit

Every finding from the independent audit of the patient web client commit
was fixed and re-tested (web 386 green, coverage 89.1/79.8/88.0/93.2 over
the 85/75/85/90 floors; mobile 1648 green; build clean, audit clean):

- **Session custody**: the idle lock, bfcache guard, reconnect flush, and
  reconciliation were disarmed on the Measures/Share/Settings views
  (`sessionActive` had drifted); every authenticated view now locks, with
  per-view regression tests.
- **Offline queue**: a `Retry-After: 0` (or past-date) advisory caused a
  zero-pause re-POST storm — advisories now carry a 1 s floor; entries
  parked while "online" could strand for the session — the queue now also
  flushes at sign-in, on a 30 s periodic retry, and after any successful
  direct save (and the flush throttle no longer wedges on a backwards
  clock step); the generation fence gained a write-after-wipe rollback;
  corrupt member records are quarantined instead of dropped; the
  quarantine store is capped at 50 records; `enqueue` dedupes by
  `client_entry_id`.
- **Honesty on 409**: a direct save that answers 409 no longer claims
  success and discards the plaintext — every online failure parks the
  entry in the queue where the M-5 GET-verification referees it.
- **Logout**: the epoch-bump request no longer aborts itself when
  `clearSession()` fires in the same tick.
- **Patterns**: the sensitive non-quoting contract no longer trusts the
  payload flag alone — the suppress-tier matcher runs on every label,
  belt-and-braces with mobile and the backend.
- **Reconcile**: focus-time reconciliation no longer re-downloads the
  entire journal ciphertext to discard it — it is one insights round-trip;
  the History view owns the revision-pinned walk (now unit-covered:
  snapshot pinning, restarts, mode switches, dedupe, page cap, terminal
  probe).
- **Mobile two-writer**: the conflict-overwrite path now runs the FULL
  post-save work (H-6 crisis detection included — it used to skip it);
  "Keep theirs" applies the server's text and version locally; the 410
  funnel is code-checked (`account_deleted`/`gone` added to the mobile
  error-code contract — the codes were being sanitized away) with
  conflict/funnel tests added.
- **Security tests made honest**: hostile decrypted text now renders
  through a real jsdom DOM (inert, asserted); the sensitive-pattern
  accessible-name contract is actually asserted; the interop fixtures'
  "both sections exist" guards fail instead of skip; `listEntriesWalk`
  and the future-date classifier gained direct coverage; dead code
  removed (`sessionStore`, `phq9.ts`, an unused import).
- **Release provenance**: `mindpattern-web-<tag>.tar.gz` + sha256 are now
  actually attached to the GitHub Release (they were built, verified, and
  silently dropped); `mutation-web.yml`'s 65.0 floor is labeled what it is
  — portal-inherited and provisional until web's first measured run.
- **Docs**: the promised DPIA web addendum exists
  (`docs/DPIA_SKELETON.md` §7 — browser storage surface); the bundle-size
  figure is corrected everywhere it was stated; deploy/README names nginx
  as the production header enforcer.

## Unreleased

### Patient web client (2026-09-25): the web app, built phase by phase per WEB_PLAN.md

`web/` — the mobile app's journaling experience in the browser, against the
unchanged backend, as a full multi-device peer of the mobile app. Ten
phases, each with its verification gate recorded in `WEB_PLAN.md`:

- **Zero-knowledge parity, four-way pinned**: the complete patient crypto
  (PBKDF2-600k → HKDF auth/data subkeys, AES-256-GCM envelopes, entry
  payloads v1+v2 with version-bound AAD, insights/question blobs, the
  therapist wrap both directions, fingerprints) byte-pinned to
  `shared/vectors.json`; `shared/interop_fixtures.json` (generated by BOTH
  platforms' real modules) cross-pins web⇄mobile in both directions; the
  new `web-contract-vectors` CI job makes backend+mobile+portal+web the
  four-way vector gate.
- **Strict session custody (D-4)**: token AND keys memory-only — refresh
  re-authenticates; 10-min idle lock, bfcache guard, lazy account-wide
  death funnels (401 expired/rotated vs 410 deleted, distinct honest copy).
- **Journaling**: entry editor with on-device sentiment (the real brain
  port), structured v2 channels, PRE-encryption crisis tier; byte-paged
  history with search + mood calendar; honest version-conflict editing
  ("reload theirs / reapply mine"); ciphertext-only offline queue
  (IndexedDB, origin+account scoped, lying-409 verification, quarantine).
- **Multi-device contract (S-1…S-11)** implemented + adversarially tested:
  the L3 dual-client live drill scripts concurrent creates, the CAS race,
  delete-vs-edit, cross-session visibility, and epoch death against the
  real backend. MOBILE changed too (honestly two-writer): the 410 funnel
  joins the client lock; HistoryScreen's edit race now decrypts and SHOWS
  the other device's text before overwriting; deleted-elsewhere gets its
  message; the all-rows-failed decrypt signature surfaces the
  remote-rotation funnel; +2 interop suites and a two-writer regression
  suite (mobile 1644 tests green).
- **Patterns + question**: lifecycle labels, "Why am I seeing this?"
  evidence panels, sensitive non-quoting cards (label never reaches the
  DOM — asserted), per-pattern mute (local + server-side via the encrypted
  feedback blob), the explicit-only recompute (the single-use processing
  session opens by the button alone).
- **Measures/share/settings**: PHQ-9/GAD-7/PHQ-2 with score-ceiling
  honesty and the post-save item-9 support pointer; verifier-gated
  therapist sharing with the fingerprint read-back; LLM consent, access
  log, encrypted-bundle export (the web-first gain), queue recovery, the
  full rekey→rewrap→credential rotation with epoch-death disclosure,
  typed-DELETE account deletion.
- **Security campaign (P9)**: threat model
  (`docs/WEB_THREAT_MODEL.md`), full-offset fuzz sweep (every byte × 3
  masks — all fail closed), red-team harnesses (XSS corpus through the
  real render pipeline, storage-scrape, replay/stale-token set), the
  four-way CI gate, Stryker + weekly `mutation-web.yml` (floor lands from
  the first measured run — configured, not claimed). 356 tests green,
  coverage 87.2/75.7/85.6/91.3 (floors 85/75/85/90), bundle 144 KB gz at
  the P7-phase measurement (the as-committed tree built at 155.7 KB gz —
  under the 250 KB budget; figure corrected 2026-09-25).
- **Deployment**: the nginx template carries the live `app.example.com`
  block (same-origin /api proxy — CORS stays empty); the release workflow
  builds, verifies, and ships `mindpattern-web-<tag>.tar.gz` + sha256
  beside the portal's.

### Frontend mutation campaign (2026-09-22): fresh full-scope Stryker over portal + mobile

Both frontends re-measured from scratch on the current tree
(`redteam/mutation_campaign_2026-09-22_frontend/`), covering everything the
four audit-remediation waves added since the last campaigns:

- **Round 2 (same day)**: 30 more pin tests closed the deepest killable
  survivors — URL-policy arms, error taxonomy, derive-path wipes, the
  windowless platform seams, the idle-lock event matrix, the ui theme/tone
  contracts, crisisDetect's trail/orphan/mask/folded arms, and the
  MoodCalendar mood-dot semantics — 114 further verified kills (campaign
  total **494 across 122 pin tests, zero regressions**), portal to 65.65%
  (floor 65) and mobile to ~84.8% (floor 84). The report carries a
  per-class equivalent-mutant ledger documenting why 100% is not reachable
  (pre-lowercased regex flags, identity expressions, inequality-only
  counters, environment-baked MODE/DEV, backstopped channels).
- **Portal: all of `src` measured with the working command runner for the
  first time** — 3,549 mutants, fresh baseline 55.68% (the round-2 1.41%
  number came from the broken vitest-runner wiring; the scoped 74.10% baseline
  covered only the four contract modules). 70 survivor pins added
  (`tests/mutation_2026_09_22_frontend.pins.test.tsx` + the App-shell
  companion): api transport/pagination contracts (timeout deadline, session
  replacement, signed-64 revision ceiling, canonical continuation corpus),
  crypto sanitization windows (F-6 score boundaries via an independently
  constructed caseload-summary oracle), TOTP stage discipline and input
  sanitization, review ordering, collection-restart bounds, key-zeroization
  across every flow, note/search/delete machinery, the 10-minute idle lock,
  and the platform/UI seams. **278 mutant-by-mutant verified kills, zero new
  survivors, aggregate 55.68% → 64.80%**; the weekly gate's scope widened to
  match with the floor honestly re-based at 64.0. Remaining survivors are
  triaged in the campaign REPORT (style/theme literals,
  environment-limited equivalents, view copy fragments).
- **Mobile: first full run since 2026-09-15** — 15,990 mutants over the
  current tree (was 4,356), fresh baseline **83.86%** with the crypto
  modules still at 100%. The campaign found and fixed a gate-breaking
  test first: `healthBridge.pins.test.ts`'s NEW-2 source-text pin dies under
  whole-tree Stryker instrumentation, which would have failed the weekly
  gate's dry run from its next execution; the pin now steps aside while the
  file is instrumented and still enforces the shipped source in every normal
  run. 22 survivor pins added (`tests/mutation_2026_09_22_frontend.pins.test.ts`)
  over the safety/contract modules — the crisis matcher's complete
  homoglyph/leet folding tables and normalization pipeline, the measure
  registry's scoring/validation contracts, the entry-version monotonicity
  mirror, and the password-rotation stage/reason map — with **102
  mutant-by-mutant verified kills, zero regressions** (crisisDetect
  64.4→76.0%, measures 76.8→89.4%, entryVersions 67.4→76.4%, rotation
  47.8→80.1%). The weekly floor moved 81 → 83 (fresh level minus margin);
  screen-level residuals are mapped per file in the campaign REPORT.

### Final-verification remediation (2026-09-22): all residual gaps closed

Follow-up to the final independent verification
(`INDEPENDENT_AUDIT_FINAL_VERIFICATION_2026-09-22.md`): the three new
defects found during verification, the D-7 residue, every documented
deferral (TOTP, jest-axe, real portal mutation floor), and the
doc-drift bundle. Each fix carries its regression test where testable:

- **Portal note-edit-history was unreachable** (verification defect 1):
  the only "view history" trigger lived inside the hidden print-only
  block — invisible on screen, unclickable on paper; its tests passed
  only because react-test-renderer ignores CSS. The affordance now
  renders in the INTERACTIVE notes card ("View history" → inline prior
  revisions, toggleable), and the printed summary carries only a
  non-interactive "edited" marker plus whatever history was loaded. The
  P3 tests drive the reachable button and pin that no `edited`-labeled
  button exists anywhere.
- **Rollback runbook step 1 was unexecutable** (verification defect 2):
  `deploy/README.md` pointed at a nonexistent `backup.sh` and the
  monitoring `verify.sh`. Replaced with the real one-shot pipeline the
  backup service itself runs (pg_dump | openssl enc |
  `mindpattern-backup-mac write`, sidecar-first publication, then
  `mindpattern-backup-mac verify`), plus the off-site fetch and
  rehearsal pointers.
- **Grafana mounted tmpfs AND a named volume at `/var/lib/grafana`**
  (verification defect 3): one mount shadows the other — the tmpfs
  winning would silently discard `grafana.db` on every recreate. The
  named volume owns the path; tmpfs covers `/tmp` only.
- **Optional therapist TOTP shipped** (audit C-2/F-4, was a documented
  deferral): RFC 6238 (SHA-1, 6 digits, 30 s ±1 step). Verifier-gated
  three-step enrollment (`POST /account/totp/setup` → `enable` →
  `disable`; therapist tokens only), the secret AES-256-GCM-wrapped at
  rest under an HKDF subkey of the server `token_secret`, login answers
  `401 totp_required`/`totp_code_invalid`, every accepted code is
  single-use (persisted consumed-timestep replay fence), and re-running
  setup while ENABLED is a 409 so a phished password cannot strip the
  factor. Portal: LoginView code step (the password survives only
  inside the TOTP stage) and a full enrollment/disable section in
  Account security. Migration `d4e5f6a7b8c9` (three nullable columns);
  `backend/tests/test_totp.py` (5 tests) +
  `portal/tests/totp_2026_09_22.test.tsx` (4 tests); README error-code
  list and SECURITY_RESIDUALS updated (deferral closed, accepted
  residuals documented).
- **Portal jest-axe a11y suite delivered** (audit H-9c/F-6j, was
  deferred): `jest-axe` + `jsdom` dev dependencies;
  `tests/a11y.test.tsx` mounts every view (LoginView both modes,
  PatientsView caseload + account-security panel, PatientView chart)
  into a real DOM and asserts zero axe violations. It immediately found
  real violations — every Card title rendered `h3` straight under the
  page `h1` (heading-order skips) — fixed by promoting Card titles to
  `h2` (visuals unchanged) and demoting the PatientsView group labels
  to `h3`. The node-window shim in the shared setup no longer clobbers
  a real DOM window.
- **Portal mutation gate is real now** (audit H-5, was near-vacuous):
  root cause found and reproduced — `@stryker-mutator/vitest-runner`
  10 + vitest 5 silently ran ZERO tests per mutant (a body-emptied
  `buildAad` "survived"; 0.00 tests/mutant, 1.26% baseline). Switched
  to Stryker's command runner (a fresh `vitest run` process per mutant
  — no shared module graph to go stale; validated scoped: aad.ts 0% →
  100%), scoped `mutate` to the security/contract modules
  (crypto/aad/api/platform, mirroring the mobile per-file-floor
  philosophy). Full re-measured baseline: **74.10%** (652 killed /
  3 timeout / 229 survived; aad 100.00, crypto 81.18, api 74.16,
  platform 53.27) — `thresholds.break` and the weekly workflow floor
  raised 1.0 → **70.0**. `tests/securityConfig.test.ts` skips its
  out-of-package nginx read inside a mutation sandbox.
- **D-7 residue:** the five duplicate literals in
  `LANGUAGE_FUNCTION_WORDS_ES` (`que`, `cuando`, `donde`, `quien`,
  `otros`) removed — 185 literals → 180, zero behavior change (the
  frozenset collapsed them anyway) — with a no-duplicates invariant
  test next to the whitespace one.
- **Rewrap post-commit refresh race** (the narrow 500 window
  verification flagged beyond A-5): `ObjectDeletedError` from the
  post-commit `session.refresh` now maps to the same flat 404 as the
  commit-stage race, with a mock-race regression test.
- **Contract cosmetic:** the patient measures read now uses the same
  `has_more and rows` continuation guard as the three therapist reads
  (an empty page must never advertise a non-advancing offset;
  unreachable today behind the revision fence, pinned for symmetry).
- **Doc drift:** stale "promote both" TODO in `redteam/README.md` (the
  promotion shipped), the release.yml comment describing nonexistent
  tag-push steps (deployment is digest-only),
  `deploy/monitoring/prometheus.yml`'s pre-pinning comment, and the
  Trivy scanner image is now digest-pinned in both workflows
  (`@sha256:6967db29…`, resolved from Docker Hub).

### Independent-audit round 3 remediation (2026-09-22): NEW-1..NEW-4 + low-bundle residuals closed

Follow-up to the third independent verification pass (re-audit of
AUDIT_2026-09-21.md remediation at `64a99e1`). Every open item fixed,
each with its regression test:

- **NEW-1, the weekly mutation ceiling could never trip.** The
  surviving-mutant counter in `mutation.yml` counted *lines* containing
  "survived", but mutmut 2.4.4 prints ONE grouped header —
  `Survived 🙁 (500)` — so 500 real survivors parsed as 1 and the
  ceiling of 25 was unreachable. The parser now sums the header's own
  `(N)` (per-line counting survives only as a fallback for formats
  without a header). New tests in
  `backend/tests/test_audit_round3_2026_09_22.py` execute the ACTUAL
  python block extracted from `mutation.yml` against byte-faithful
  grouped results: 500 survivors must fail, a healthy 3 passes, and the
  F-7 refuse-unparseable guard still fires. The workflow header's stale
  "survivors do not fail the run" sentence is corrected too.
- **NEW-2, the HealthKit mirror was permanently inert.**
  `react-native-health@1.19.0` (the newest published) links and
  autolinks but predates iOS 18 — its native module exposes no
  `requestAuthorization`/`saveStateOfMind`, so the
  `src/healthkit.ts` seam always read "too old". Shipped
  `ios/MindPattern/HealthBridge/RCTAppleHealthKit+MindPatternStateOfMind.m`:
  a category on the pod's module implementing exactly the seam's
  documented contract (three promise-based methods,
  `@available(iOS 18.0, *)`-gated, `HKStateOfMindKindDailyMood` writes
  with the discrete -2..2 valence, write-only — `readTypes:nil` — API
  spellings pinned against Apple's documentation JSON). The HealthKit
  entitlement (`MindPattern.entitlements`) is declared and signed by
  both target configurations; `verify:native-release` grew from 5 to 9
  checks (FLAG_SECURE, adjustResize, entitlement signing, bridge
  presence + contract surface); `tests/healthBridge.pins.test.ts` pins
  the same facts in the ordinary suite; `healthKitCapability()` now
  answers "requires iOS 18 or later" on older devices instead of
  blaming the module. Honest limit: no Xcode exists on the authoring
  machine, so the ObjC is CI-preflight- and source-pinned but not
  compile-verified here (same caveat class as the 2026-09-21 native
  projects).
- **NEW-3, therapist rotation was unreachable from the portal.** New
  "Account security" panel in PatientsView (the access-history idiom):
  **Change password** (fetch salt → derive current keys → fresh salt →
  derive new keys → open the wrap blob with the current KEK → re-seal
  under the new KEK → `PUT /therapist/wrap-key` → `PUT /account/credential`
  with up-to-3 retries on network/5xx only → sign out; every derived
  byte zeroized), **Recover sharing key** (repairs the
  interrupted-change window: the blob is under the intended-new KEK
  while the credential never moved — re-seals under the current one),
  and **Rotate sharing key (compromise)** (fresh keypair,
  confirm-gated, with the backend docstring's "intentionally lost"
  copy). `crypto.ts` gains `openSealedPrivateKey` (fail-closed decrypt
  counterpart of `sealPrivateKeyForUpload`, returning caller-owned
  PKCS#8). `TherapistMe.wrap_key_blob` was already exposed. The
  previously untested note-edit-history UI is now covered. Portal:
  191 → 211 tests, typecheck clean.
- **NEW-4, `verify.sh --production` existed but was enforced nowhere.**
  The four overlay images are pinned to digests (re-verified against
  the Docker Hub registry API): monitoring prometheus/grafana/blackbox
  + offsite rclone — the offsite compose's `rclone/rclone:v1.69.1` tag
  turned out not to exist on Docker Hub at all (a latent pull-time
  failure; tags are unprefixed — now `1.69.1@sha256:600f…`). The
  monitoring-verify CI job now runs `verify.sh --production` as its own
  step (a mutable ref fails the build), the promtool extraction uses
  the same digest-pinned image, and both READMEs document the
  deliberate-re-pin policy.
- **Consent-revival cap gap (B-5 residual).** Re-granting a REVOKED
  consent skipped the ACTIVE-only grant-cap checks entirely — a patient
  at the cap could exceed it by one via revival. Revivals now count;
  a wrap REFRESH of an already-active row (which adds no live grant)
  still passes. Two API-level tests.
- **Foreign-store cap direction (D-1 hardening).** `_stored_from_dict`
  truncated over-cap evidence/qualification lists to the OLDEST N days
  while every merge path keeps the NEWEST N — a hand-edited store with
  >60 dates would silently lose its high-water mark and reopen the
  replication-bypass shape D-1 fixed. Load now keeps the newest window.
- **A-8 wording.** Middleware-SYNTHESIZED envelopes (429/413/400/408/
  500) on the deprecated `/api` mount now carry the `Deprecation`
  header, so README's "every response it serves" is true without
  qualification. The README error-code list also documents the
  `error` unmapped-status fallback, and the CI completeness gate now
  matches dict-literal `"code": "..."` envelopes (middleware,
  exception handlers) in addition to `code="..."` kwargs.
- **H.9d convention documented + ratcheted.** The "no slow markers on
  security pins" rule is written down where markers are registered
  (backend/pyproject.toml) and enforced by a test that freezes the
  grandfathered slow set to the two crypto-pin files — a new slow
  marker anywhere else fails the suite instead of silently removing a
  pin from every mutation campaign.
- **Ops/doc residuals.** The incident runbook's `NEWEST` selection now
  mirrors `rehearse_restore.sh --remote` exactly (newest-first over
  `*.dump.enc`, `.hmac` sidecar required, fails loudly when nothing
  qualifies); the rollback paragraph's wrong justification is corrected
  (the hazard is the NEW image auto-upgrading before the rollback
  decision, and an old image lacks the new migration files outright);
  redteam.yml's "eight FINDING verdicts" comment is now count-agnostic;
  the e_crisis/a_crypto harnesses regenerate their corpora into
  gitignored `redteam/results/corpus/` instead of dirtying tracked
  files at runtime (committed fixtures stay read-only inputs for
  f_mobile); mobile README documents the Podfile.lock-not-committed
  first-build step and the HealthBridge.

### Independent-audit round 2 remediation (2026-09-21): F-1..F-12 closed

Follow-up to the second independent audit
(INDEPENDENT_AUDIT_ROUND_2_2026-09-21.md) — every finding fixed, each with
its regression test:

- **F-1, the full-engine golden vectors were unpinned.** No test covered
  `shared/brain_vectors.json`'s `updates` section (the three full-engine
  corpora that are the acceptance gate for the on-device port).
  `backend/scripts/gen_brain_vectors.py` is refactored into importable
  builders and `test_brain_vectors.py` now regenerates the `updates`
  payload in-process and asserts it equals the committed JSON
  float-for-float — a hand-edit or engine regression in the full-engine
  vectors now fails the suite.
- **F-2/F-3, the truncated-entry fabrication class survived two paths the
  D-3 fix missed.** `stats.avg_sentiment` (and the legacy analyzer's
  copy) averaged blanked entries as neutral 0.0 — rendered to therapists
  as "average reading"; mood-correlation theme residuals likewise scored
  tag-only blanked entries 0.0. Both now apply the D-3 predicate
  (blank text with no explicit mood tag contributes no mood value; tagged
  entries still count). While fixing the residual path, a latent crash
  was found and closed: a theme day conferred only by tags on blank
  entries raised `KeyError` in `_detect_links` (a 500 on recompute);
  outcome days without mood evidence are now skipped as unmeasured.
- **F-4, rotation failure paths left the vault on the old key.** If the
  credential rotation or the re-login fails after the server already
  rekeyed, `rotatePassword` now locks the vault and drops the biometric
  wrap before returning `{ok:false}` — the C-1 "self-completing rotation"
  guarantee now holds on failure paths too (an entry can no longer be
  sealed under the dead old key while the vault sits unlocked).
- **F-5, the dead multi-word Spanish lexicon class.** 28 keys containing
  spaces (e.g. "sin esperanza", "sin dormir", "me duele") could never
  match under per-token lookup; removed, with a new invariant test
  forbidding whitespace in every per-token-consumed lexicon map (this
  would have caught all 30 dead entries including the audit's original
  three). `shared/brain_lexicon.json` + the mobile lexicon regenerated;
  the golden vectors stayed byte-identical (dead keys never matched).
- **F-6, TOTP deferral registered.** Optional TOTP/MFA for therapist
  accounts (audit Phase 2 workstream 2) was silently dropped from the
  wave-1 deliverables; it is now recorded as a tracked deferral in
  docs/SECURITY_RESIDUALS.md (verifier-gated re-auth, rate limits and
  access logging remain the standing controls).
- **F-7, the mutation gate could pass vacuously.** If `mutmut results`
  produced empty or error-only output, the survivor ceiling counted zero
  survivors and passed. The gate now asserts the results file carries
  recognizable mutant-status lines and a minimum processed-mutants floor
  before judging the ceiling. (Fixing this surfaced that the ceiling step
  also lacked `working-directory: backend` — the old check could never
  have run; both fixed.)
- **F-8, the portal banner fold let a failed scan hide a sensitive
  summary.** A scan row with `patterns: -1` (revoked mid-scan, dead key)
  unconditionally overrode a server summary flagging sensitivity — an
  in-session undercount of the safety banner. A successful scan still
  wins; a failed scan now falls back to the summary, matching the per-row
  display; the fold has its first tests (plus caseload-ordering and
  per-context note-draft pins).
- **F-9, revoked history no longer trips the consent list cap.** The
  grant path counted active consents only (Phase 2 B-5), but
  `GET /consents` counted every historical row — 100 revoked former
  therapists made the share screen fail to load. The cap now counts
  ACTIVE consents; the retained history (unique per therapist) still
  lists for disclosure.
- **F-10, claim wording and operator docs squared with behavior.** The
  CHANGELOG's "cannot be replayed across recomputes" now states the
  bounded ~48h window it actually is; the feedback AAD comment states the
  client seals the UTC day; `BACKUP_OFFSITE_RESTART` (default `no`, and
  never combine it with `MODE=fetch`) is documented in the offsite
  overlay README; the README's Spanish section now states the per-corpus
  (not per-entry) language gating for mixed-language journals.
- **F-11, previously untested fixes pinned.** New regression tests for
  the rekey executemany batch form (130 entries → exactly 2 batched
  UPDATE executions per the 100-row batching), the rekey-preserves-
  `content_version` half of the A-1 pin, onboarding panel persistence,
  the foreground `activeDays` refresh wiring, portal note-draft context
  isolation, and the caseload ordering branches.

- **F-12 (found during remediation), the C3 date-backdating red-team
  verdict was timezone-flaky.** The full re-run surfaced a tenth FINDING:
  `C3.date-backdating` reported the ±1-day grace window shifted by one
  day. Not a product change — the harness anchored its date offsets to
  the machine's LOCAL `date.today()` while the entry-date contract
  (entries.py, audit fix L-5) is server-UTC ±1; on this UTC-7 machine
  after 17:00 local the two diverge and the verdict flips (UTC CI runners
  never see it). The harness now anchors to server-UTC; verified BLOCKED
  at the same local hour that produced the false FINDING.

Verified: backend pytest green (1,323 tests), mobile 1581/1581 and portal
191/191 suites green (mobile +10, portal +6 tests), probe_brain 9/9,
crypto vectors pass, brain vectors regenerate deterministically
(byte-identical), monitoring verify passes, red-team gate green with all
9 residuals registered.

### Independent-audit remediation (2026-09-21): V-1..V-4 closed

Follow-up to the independent verification audit
(INDEPENDENT_AUDIT_VERIFICATION_2026-09-21.md) — every fixable finding
fixed, each with its regression test:

- **V-1, the weekly red-team gate was red.** `mobile/ios/.xcode.env`
  (committed with the Phase 1 native projects) trips the
  `G3.tracked-secrets` hygiene rule (`*.env` suffix). It is the
  React Native Xcode template (NODE_BINARY export only, no credential,
  required to be versioned) — registered as the ninth residual with a
  written defense in docs/SECURITY_RESIDUALS.md and the workflow's
  DOCUMENTED_RESIDUALS, so the weekly gate passes again while staying
  strict for everything else.
- **V-2, the Spanish theme lexicon (audit Phase 2 workstream 1's
  deferred demand).** `THEME_LEXICON_ES` in brain.py: the same nine
  canonical themes with Spanish words, LANGUAGE-GATED per corpus (an
  English theme word never reads Spanish text and vice versa — "son las
  cinco" mints no family theme; Spanish words never fire on English
  corpora; "other" keeps the historical English-map behavior). Language
  detection moved ahead of theme extraction; topic eligibility excludes
  Spanish theme words under "es". Spanish journals now get
  temporal/mood_correlation/link cards from Spanish text; the golden
  vectors' spanish-mixed case was strengthened to a 70-day corpus and now
  pins ES-derived candidates for the on-device port. The mobile app
  renders theme/tag labels localized (`insights.theme.*`, usted-register
  Spanish) — topics and phrases stay raw user words, and unknown labels
  pass through untouched.
- **V-3, provisioned Grafana dashboard + Alertmanager example (audit
  workstream 6's deferred demand).** A dashboard ships as code
  (mindpattern-overview.json: up/keystore/backup-age/5xx stats, request
  rate, recompute p50/p95, LLM outcomes) via a read-only provisioning
  provider; `verify.sh` now grounds every panel expression against
  backend/app/metrics.py exactly like alerts.yml. The minimal
  Alertmanager example (severity routing per the runbook, inhibit rule,
  enable-in-comments) lives at alertmanager/alertmanager.example.yml —
  delivery stays an operator decision.
- **V-4, note edit history missed the POST retry path.** An idempotent
  note-create retry arriving with different content now preserves the
  superseded blob as an immutable revision, exactly like PATCH; a
  byte-identical replay still writes none.
- V-5 needed no code (behavior was correct; the claims' wording was
  imprecise). V-6's `verify:native-release` preflight passes 5/5; a full
  Xcode/Gradle build still requires the operator toolchain (CocoaPods,
  Android SDK), which is a machine-setup step, not a repo fix.

Verified: backend pytest green (+9 ES-theme tests, +1 note-history
test), mobile and portal suites green, probe_brain 9/9, crypto vectors,
brain vectors regenerate deterministically, deploy/monitoring/verify.sh
(dashboard grounding live), redteam run_all 9/9 FINDINGs registered —
the weekly CI gate simulates green.

### Deep-audit Phase 3 (2026-09-21): MBC depth, time-of-day, note history, the on-device protocol

- **Measurement-based care depth.** GAD-7 (anxiety) and PHQ-2 (brief
  depression core) join PHQ-9 through a multi-instrument registry
  (mobile/src/measures.ts): one screen, one selector, the same
  zero-knowledge measure path; per-instrument score ceilings, history
  clamping, and en/es item copy. The portal labels the trend lines per
  instrument. No interpretation, as ever.
- **Time-of-day analysis (v2 channel).** The entry payload gains an
  optional coarse writing-window bucket (morning/afternoon/evening/
  night — never a clock time); ≥70% one window on a weekday narrows the
  temporal card to "Sunday evening". Strict server validation, v1
  corpora unchanged.
- **Note edit history (clinic readiness).** Every changing note update
  preserves the superseded blob as an immutable revision (new table,
  migration b8f4e2a7c9d1); GET /therapist/notes/{id}/revisions serves
  them ownership-scoped and audit-logged; the portal shows "edited —
  view history" with decrypted prior texts.
- **The on-device brain protocol.** POST /api/v1/insights/
  local-recompute: client-encrypted state + patterns with state_seq
  discipline and server-grounded analysis dates — no processing
  session, no key shipment. The port plan and acceptance gate:
  mobile/src/brain/PORT.md + shared/brain_vectors.json v2 full-engine
  golden cases (calm/work-anxiety/Spanish corpora).
- **Research + TEE design docs.** docs/IRB_STUDY_PROTOCOL.md (single-arm
  usability study, zero-knowledge-consistent data handling,
  comprehension benchmark as the published-claims gate) and
  docs/TEE_ATTESTATION_DESIGN.md (client-verified attestation flow for
  the interim server path).
- Deferred (tracked): the TS port itself per PORT.md; multi-device sync;
  multi-therapist organizations and handoff; clinician-configured
  measure cadence.

### Deep-audit Phase 2, waves 6–8: mobile polish, Spanish parity, ops maturity (2026-09-21)

- **Spanish parity (E-3 High, E-8, D-7).** The pre-threshold baseline
  loop is localized: `shared/generic_questions_es.json` (60 questions,
  position-parity with the English pool, embedded in the app with
  sync/invariant/parity tests) and a parallel Spanish prompt-chip pool —
  both keyed off the device locale; usted register, and the six
  remaining tú-form strings in the es catalog normalized. The three dead
  multi-word ES sentiment-lexicon entries ("eterno es", "por eso",
  "darme cuenta" — unreachable under per-token lookup) removed, mobile
  lexicon regenerated.
- **Mobile polish (E-9, E-10).** History is a windowed FlatList (header/
  footer chrome preserved; far-offscreen rows unmount — up to 500
  decrypted rows used to stay mounted forever), with the rnMock gaining
  a FlatList stub. Calendar VoiceOver speaks human dates instead of raw
  ISO strings; foregrounding refreshes activeDays (no more stale count
  across midnight in an always-open app); onboarding resumes at the
  persisted panel position instead of restarting at panel 1 (completing
  the M-18 intent); the mobile README screens table lists
  Measures/TherapistShare.
- **Ops maturity (G-3..G-7, H-4, H-6).** Rollback procedure documented
  (restore-point + image re-pin; never `alembic downgrade` live data);
  the operator overlays (backup-offsite, monitoring) carry the
  production hardening quartet (cap_drop ALL, no-new-privileges,
  read_only + tmpfs); fetch mode defaults `restart: no` (the
  restart-forever re-fetch trap); rclone excludes in-flight `.tmp`
  dumps; json-file log rotation on every service; Trivy image scans in
  the CI docker job and the release pipeline (fixable HIGH/CRITICAL
  fail); `deploy/monitoring/verify.sh --production` enforces the
  digest-pinned image contract (overlays fail until pinned); the weekly
  backend mutation run enforces a surviving-mutant ceiling; mobile
  coverage gains per-file floors for the security-critical modules
  (crisisDetect 98, questionFeedback 90, strings 90, rotation 85,
  aad/envelope/kdf 95); the release coverage gate runs on Python 3.14,
  the production interpreter. Portal Stryker weekly gate follows.

### Deep-audit Phase 2, wave 5: portal polish (2026-09-21)

The F-6 low-bundle, per item: the sensitive-caseload banner folds in
fresher manual-scan rows (per patient, a scan row outranks the summary
it supersedes); the note composer keeps SEPARATE drafts for the general
and pattern-anchored contexts (a general draft no longer rides into a
pattern note); `window.print()` and randomness go through the platform
seam (`printPage`/`randomBytes`) instead of bare globals;
`decryptMeasure` REJECTS out-of-range scores instead of clamping them
into plausible-looking clinical values; the caseload list no longer
flashes "No patients" before the first fetch (loading state), and
gains username search plus ordering (newest share / username /
post-scan triage: sensitive first, then most-new). jest-axe a11y suite
deferred (new dev dependency).

### Deep-audit Phase 2, wave 4: audit-trail read path + DPIA (2026-09-21)

- **The access audit trail is readable (B-4).** `GET /api/v1/account/
  access-log` — the patient's who-accessed-my-data view (GDPR Art. 15
  parity; own lifecycle rows as "self", therapist reads with display
  names); `GET /api/v1/therapist/access-log` — the therapist's own
  action history. Both cursor-paginated (`X-Next-Cursor`), consent-
  scoped, no cross-subject leakage; the previously dead
  `ix_access_log_actor`/`ix_access_log_user` indexes now serve them.
  The portal gains an on-demand "My access history" panel (loads only
  when asked).
- **DPIA completed for H-7**: the erasure section now discloses the
  730-day access-log retention residual (rows deliberately outlive the
  account for the compliance window); a subprocessor + international-
  transfer table (LLM provider, off-site backup — both optional and
  off by default); and an Art. 30 RoPA section pointing at the DPIA
  and docs/SECURITY_RESIDUALS.md.

### Deep-audit Phase 2, waves 1–3 (2026-09-21)

- **Therapist lifecycle (C-2/F-4).** `PUT /api/v1/account/credential` now
  accepts therapist tokens (a forgotten/phished therapist verifier was
  fixable only by deleting the account), and a new verifier-gated
  `PUT /api/v1/therapist/wrap-key` replaces the sharing keypair — the
  same route serves password changes (re-wrap the blob under the new KEK
  first) and wrap-key compromise. Patients see the new public half in
  `ConsentOut` and re-wrap via the existing `PUT /consents/{id}/rewrap`
  without re-pairing; rotations are audit-logged (`wrap_key_rotate`).
  Five lifecycle tests including an end-to-end rotation + patient
  re-wrap + successor-key unwrap.
- **DB hardening (B-3/B-5/B-6/B-7).** asyncpg pool connections now carry
  `statement_timeout` (30s default) and `idle_in_transaction_session_timeout`
  (5min default) via `MINDPATTERN_DB_STATEMENT_TIMEOUT_MS` /
  `MINDPATTERN_DB_IDLE_IN_TX_TIMEOUT_MS` — a leaked transaction can no
  longer pin xmin indefinitely; the rekey's per-row UPDATE loops became
  one executemany round-trip per batch; consent caps count ACTIVE grants
  only (100 grant/revoke cycles no longer lock a patient out of sharing
  forever); the redundant `ix_notes_therapist_patient` prefix index is
  dropped (migration a3e7c9d5f1b2); dead pairing codes are pruned by the
  daily sweep, not only opportunistically inside code mint.
- **Crypto residuals (C-5/C-6/C-7).** The feedback-blob AAD now carries
  the seal date (client seals under its local UTC date; the server
  accepts today-or-yesterday), so a blob captured by a hostile server is
  dead from the second day after sealing — the acceptance is a bounded
  ~48-hour clock-skew window (unlimited replays inside it, question
  ranking only, recomputes client-initiated), not an absolute
  replay-proof seal. `MINDPATTERN_DECOY_SECRET`
  decouples unknown-username decoy salts from token-secret rotation.
  The therapist-pairing fingerprint check is now an action: the grant
  dialog proceeds only through an explicit "fingerprints match" tap;
  a mismatch opens do-not-continue guidance instead of the password
  step.

### Deep-audit gap closure (2026-09-21, follow-up to AUDIT_2026-09-21.md)

The seven findings the Phase 1 plan left unscheduled (verified open during
remediation review), each with a regression test where testable:

- **A-7:** corrected the three stale "empty pages are unaudited" comments
  in the therapist read endpoints — empty pages ARE audited (the trailing
  commit persists the unconditionally-written audit row); only refused
  413 pages are unaudited.
- **A-8:** config now enforces upper bounds on `unlock_threshold_days`,
  `max_entries_per_user`, `max_user_blob_bytes` and `db_pool_timeout`;
  `analysis_blob_budget` must be >= `max_body_bytes` (one max-size entry
  always fits); a recompute whose budget loads zero rows refuses with
  413 instead of overwriting stored patterns with an empty run; the
  deprecated unversioned `/api` mount serves every response with
  `Deprecation: true`.
- **B-8 (half):** `users.is_active` documented as a reserved operator
  lever (README "Scope decisions" + runbook "Manual operator levers") —
  checked on every auth path, set only by direct DB action in v1.
- **D-6:** phrase pattern ids re-link to their stored record across
  window/budget rotation (anchor + variants matched at the clusterer's
  own Jaccard bar), so a chronic rumination's lifecycle no longer
  restarts as a fresh candidate when its anchor sentence leaves the
  180-day window.
- **D-8:** the per-character fold cache is explicitly bounded (cap +
  clear; behavior unchanged).
- **F-4 (warning half):** therapist registration now warns, before the
  account exists, that a forgotten password is unrecoverable.
- **F-3 residual:** removed the stale "a second browser sees the same
  anchor" comment contradicting the per-tab visit-anchor contract.
- **H-8:** incident runbook gained a Detection & escalation section for
  S1 (alert-rule inventory incl. the keystore tripwire, escalation ladder
  with bracketed contacts, manual operator levers).
- **H-1 caveat:** the red-team CI gate's 8 allowlisted FINDING ids now
  live in an authoritative register, `docs/SECURITY_RESIDUALS.md` (one
  written defense per id); the workflow asserts the register names every
  allowlisted id.

### Deep-audit Phase 1 remediation (2026-09-21, AUDIT_2026-09-21.md)

All 33 Phase 1 items from the eight-area deep audit, each with a
regression test naming its finding:

- **Brain correctness (the two verified HIGH defects).** The replication
  gate no longer reads set membership in the EVIDENCE_DATES_CAP-truncated
  list — genuinely new evidence must postdate the newest stored day, so a
  same-corpus recompute can never satisfy "independent replication" for a
  >60-evidence-day pattern. Spanish topic mining unions the Spanish
  function-word set into eligibility (no more presence cards for "cuando"
  et al.); the README's Spanish claim now states what actually fires.
  Budget-truncated (textless, untagged) entries stay out of the mood and
  PA/NA series instead of injecting fabricated neutral days; person-name
  anchoring is English-only (German noun orthography minted person cards
  for common nouns); the confirmation clock restarts at the
  candidate→emerging transition (a late-replicating claim surfaces as
  "emerging", never straight to "confirmed").
- **Security lifecycle.** Password rotation self-completes: the vault
  locks and the biometric wrap is disabled inside `rotatePassword` before
  the success alert (an Android-dismissable alert can no longer leave the
  vault on the old key). The biometric unlock path verifies the unwrapped
  key against the unlock proof and auto-deletes a stale wrap. The session
  device key uses the `WHEN_PASSCODE_SET_THIS_DEVICE_ONLY` Keychain class.
- **Backend correctness.** Rekey advances `entries_revision` AND
  `measures_revision` in its commit (mid-pagination clients get
  `collection_changed`, never mixed-key pages). The GDPR export keeps
  every insight id queued past the first metadata chunk (the pending-tail
  truncation) and snapshots consent-share ids in the head transaction (a
  re-grant mid-download can no longer drop a share). Consent
  revoke/rewrap map a concurrently cascade-deleted grant to 404, never a
  500. Measures reads (patient + therapist) carry the full entries
  pagination contract: `page_bytes` byte-bounded pages with
  `X-Next-Offset`, legacy 413 over the 2 MiB budget, and the
  `X-Measures-Revision` snapshot marker backed by a new
  `measures_revision` column + migration.
- **Portal.** Printing emits only the `.print-only` summary (the
  interactive cards — including the decrypted journal drill-down — no
  longer print light-on-dark or leak raw text onto paper); notes and
  entries render with `white-space: pre-wrap`; load failures offer a
  retry button; the login form submits on Enter with `role="status"`
  notices.
- **Mobile UX.** The haptics preference loads at session start (not
  first-visit-to-Settings); the phishing warning uses the theme error
  color (WCAG-passing, no hex literals); the check-in vocabulary
  (moods/energy/sleep/activity tags) renders localized labels keyed by
  value while wire values stay English; reminder notification copy
  routes through the catalog; chips/options/radios meet the 44pt touch
  contract; the mute note auto-dismisses.
- **Ship blockers.** `ios/` and `android/` native projects are committed
  (generated from the pinned RN 0.87.1 toolchain with the hardening
  checklist applied: Health usage strings, `allowBackup="false"`,
  `adjustResize`, FLAG_SECURE in `MainActivity`), `@notifee/react-native`
  and `react-native-health` are declared dependencies (reminders and the
  HealthKit mirror are no longer permanent "unavailable" seams; audit
  overrides neutralize their build-tooling transitive advisories), and
  `verify:native-release` runs in CI (`native-release-preflight`).
- **Ops, docs, gates.** The incident runbook's host-gone restore commands
  work as written (`basename` + container `/restore` paths) and
  `rehearse_restore.sh --remote` machine-tests the off-site fetch path.
  `deploy/monitoring/verify.sh` + shellcheck run in CI; the red-team
  harnesses run weekly in CI failing on any FINDING. Stale README claims
  corrected (rotation model, LLM testing, error-code list with a CI
  completeness grep, `ANALYSIS_BLOB_BUDGET` semantics, portal per-tab
  anchor). Alembic autogenerate now compares types and server defaults,
  and the schema-parity test asserts both flags.

### Security hardening close-out (2026-09-15 -> 2026-09-21)

Between first release and this point the codebase went through an
internal security program whose artifacts (per-finding audit reports,
campaign result dumps, dated wave changelog entries) were removed in the
production cleanup. This section is the durable summary; the full
per-finding history and remediation diffs live in git history (commits
2026-09-15 .. 2026-09-21).

- **Red-team campaign (2026-09-16).** 96 executable attack verdicts
  against the running stack; every code-fixable finding fixed. The
  lasting changes: crisis-language normalization on both engines (NFKC,
  invisible-character stripping, homograph and leet folding, SMS-digit
  and past-tense forms, Romance-language suicidio family) taking the
  bypass corpus from 30/35 evasions to effectively zero; scrypt N=2^16
  KDF floor with decoy-salt timing cover; rate-limit and enumeration
  hardening. The executable harnesses stay in `redteam/` and remain
  runnable via `bash redteam/run_all.sh`.
- **Mutation-testing program (2026-09-15 .. 2026-09-19).** Four campaign
  rounds (mutmut over the backend cores; three hand-written behavioral
  campaigns; Stryker over mobile and portal). Every surviving mutant was
  either pinned by a new regression test or documented as a residual
  with a written defense. Durable artifacts: the pin suites in
  `backend/tests/test_mutation_pins.py` / `test_deep_mutation_pins.py`,
  the weekly scheduled campaigns, and the per-PR behavioral mutation
  gate (`.github/workflows/mutation-pr.yml`) that re-runs every mutant
  targeting a changed file.
- **Pentest rounds (2026-09-19).** Two independent rounds, 11 verified
  findings + 2 informational, all fixed and pinned (algorithmic-DoS
  budgets, single-use-code defeat under StaticPool, trusted-proxy CIDR
  discipline, feedback-blob pre-flight).
- **Full-codebase audit + verification (2026-09-19/20).** 154 actionable
  findings across engine/NLP, API/security, mobile, portal and deploy;
  all fixed, then re-verified by an independent pass. Highlights:
  mid-save vault-lock key zeroization, Spanish sentiment/diacritics
  parity on both platforms, replication gates extended to every
  statistical pattern kind, streaming measure export, phase-gated
  therapist insights.
- **Rotation machinery (2026-09-20 fourth pass).** The zero-knowledge
  recovery path: `POST /api/v1/processing/rekey` re-encrypts every blob
  under a new data key in one transaction; `PUT /api/v1/account/credential`
  retires a phished login credential; consent grants re-wrap to the same
  therapist. Entries gained monotonic `content_version` AAD binding with
  rollback detection on-device. Mobile orchestrates rotation with
  interrupted-rotation resume ("Change password" in Settings).
- **365-day simulation remediation (2026-09-21).** Long-horizon
  simulation pass; mute-only feedback blobs and TZ-pinned tests.
- **Accepted, documented residuals.** Data-key escrow during consented
  recomputes (now recoverable via rotation), CSP `style-src
  'unsafe-inline'` (no injection path), plaintext draft surviving vault
  lock (pinned trade-off), operator tooling mutable tags (flagged to pin
  before production).

Every remediation above is pinned by a regression test that names the
finding it guards; treat any of those failing as a release blocker.

### 2026-09-19 — Final wave: Spanish analysis language, monitoring, off-site backups, HealthKit seam, native checklist

Spanish + language detection by the coordinating engineer; monitoring and
off-site backups; HealthKit State of Mind seam and the native-project
checklist by parallel work streams. All gates green at close.

- **Spanish is the second analysis language.** A curated graded Spanish
  lexicon (~480 valences, negators, intensifiers, "pero" contrast,
  absolutist and sense-making sets, and a 180-word function-word
  detection set) ships in `sentiment_lexicon_es.py`. The English-only
  language gate became language DETECTION with per-language detection
  sets built from language-specific sources (merged lookup words cannot
  inflate the wrong side); Spanish prose now receives the full analysis
  — mood series, PA/NA, rumination, sense-making, topics — in Spanish,
  while German/French/other keep the honest historical suppression and
  now carry `stats.language = "other"` so the app shows a calm
  "not yet supported" card instead of an unexplained quiet analysis.
  English wins every lexicon collision by merge order. The historical
  "negation-dense Spanish is gated" pin was deliberately INVERTED (the
  same corpus now legitimately surfaces Spanish rumination — the honest
  reading in the user's language), with the gate's original intent
  preserved via a German corpus. The on-device engine received the
  Spanish tables through the same generated-artifact pipeline, and 7 new
  Spanish vector cases pin both platforms' Spanish behavior (39 sentiment
  vectors total). Mobile UI language (en/es) and journal analysis
  language remain deliberately independent systems.
- **Monitoring stack** (`deploy/monitoring/`): Prometheus scrape +
  alert rules grounded in the exact metric names the API exports (API
  down, 5xx ratio, slow recomputes, stuck processing sessions, LLM
  failure ratio), a profile-gated compose file kept deliberately
  OUTSIDE the digest-pinned production contract (operator tooling with
  a documented pinning step), plus backup-freshness checking (a
  textfile-collector heartbeat and a standalone cron-friendly script).
- **Off-site backup replication** (`deploy/backup-offsite/`): an
  overlay service syncing the already-encrypted pg_dump volume to an
  S3-compatible remote (rclone copy, never deletes), with the host-loss
  recovery path, BACKUP_KEY second-location custody options, and the
  rehearsal step documented in the incident runbook.
- **HealthKit State of Mind seam (mobile)**: the capability-probe
  pattern gains `src/healthkit.ts` — WRITE-ONLY mood mirroring to the
  Health app (discrete -2..2 valence classification), opt-in per
  account with honest disclosure (MindPattern writes, never reads;
  Health-side data stays in Health), fire-and-forget after a mood
  check-in, real when the native module links.
- **Native-project checklist (mobile)**: `verify_native_release.mjs`
  gained fail-closed checks (Health usage strings when the seam is
  imported, allowBackup=false, keychain dependency assertion), and the
  README's native section is now an ordered setup guide: iOS keychain
  accessibility verification, backup-exclusion trade-offs, notification
  prompt timing, the App Store health declaration, Android FLAG_SECURE
  and allowBackup reasoning, and a DESIGNED TLS/SPKI pinning approach
  with the self-hoster bypass requirement spelled out.

### 2026-09-19 — Third product wave: on-device brain begins, sense-making/diversity kinds, MBC measures, full i18n

All gates green at close: backend 1133 tests + probe 9/9 + mypy/ruff;
mobile 1339 tests + tsc + crypto vectors; portal 145 tests + tsc.

- **The on-device brain port begins (closing the processing-session
  exception).** The graded sentiment engine — the full merged lexicon
  (7,267 words + emoji valences), negation/intensifier/"but" rules,
  morphological candidates — is ported to TypeScript
  (`mobile/src/brain/`), with the statistics core (erfc via a
  derivation-first-principles Maclaurin+continued-fraction
  implementation agreeing with math.erfc to 2e-16, Pearson, Fisher-z
  difference p). Cross-platform vectors
  (`shared/brain_vectors.json`, 32 sentiment cases + stats) pin the two
  engines together, with a REGRESSION-guard test on each side: the
  mobile suite runs the TS port against the vectors, and
  `backend/tests/test_brain_vectors.py` regenerates them from the live
  Python engine so a server-side change that would break on-device
  parity fails first on the server. The lexicon artifact is GENERATED
  (`scripts/dump_brain_lexicon.py` → shared JSON + TS module) and
  byte-pinned both ways. Consequences shipped today: the device-local
  mood estimate, History badges and fallback mood-log values now use
  the REAL engine (the 20-word ratio hack is retired; its test pins
  moved to the graded engine's exact verdicts — e.g. "nothing" now
  scores mildly negative, VADER lineage). Honest scope: this is the
  foundation (sentiment + stats), not the cutover — day series, the
  inertia family, themes, phrases and lifecycle port next; only when
  the whole `update()` runs client-side can the data-key shipment end.
- **Two new pattern kinds.** `sense_making` (causal+insight word
  density per day, recent vs the user's earlier norm, Welch's t with a
  measurement-noise floor; grounded in the Pennebaker-lineage finding
  that RISING causal/insight language tracks benefit — surfaced only as
  a within-person rise) and `activity_diversity` (weekly Shannon
  entropy over activity tags, recent vs earlier weeks; both directions
  surface — narrowing and widening are different, equally honest
  observations; Ong et al. 2023). Both ship with question templates,
  describe() copy and mobile card rendering, and enter the same BH
  family and replication gates as every statistical kind.
- **The MBC module (measurement-based care), full stack.** The patient
  can complete the PHQ-9 (public-domain instrument) in the app; the
  score is an opaque encrypted blob (AAD context `"measure"`) stored
  under the same date/quota/idempotency discipline as entries
  (Alembic `b1c7f2e9a4d6`, `SCHEMA_HEAD` bumped; migration parity
  re-pinned). The therapist portal reads it through the SAME active
  consent, decrypting with the per-consent unwrapped data key — the
  server never learns a score, and the read is audit-logged like every
  patient-data access. The charter holds everywhere: the app computes
  and displays no severity bands and gives no interpretation (the
  screen says interpretation belongs to the clinician); SAFETY: item 9
  (self-harm) endorsement gently points at the offline crisis
  resources only AFTER the response is safely saved, throttled through
  the same per-day stamp as the entry crisis dialog. Portal renders a
  "Recorded measures" trend card; cross-implementation pinned with a
  Python-generated fixture. KNOWN SCOPE NOTE: measures are readable by
  an active consent that predates them — the grant disclosure copy
  should move to "v2" naming measures for new grants (follow-up).
- **Full i18n (mobile).** A rebuilt `strings.ts` i18n module (en/es
  catalogs of 551 keys each — completeness enforced by test; `t()`
  with interpolation and an es→en→key fallback chain; device-locale
  detection with an en-pinned test seam). ~540 user-visible strings
  extracted across every screen and component, including all
  accessibility labels; dates and calendars are now Intl/locale-aware
  (the en-US pinning and English month tables are gone). The drifted
  legacy keys were reconciled to the shipped copy. Crisis numbers and
  URLs are never translated; Spanish copy keeps the calm, non-clinical,
  advice-free register (verified by es render tests). Residual: no
  manual language override UI yet; mood.ts data labels and the
  prompt/generic question pools remain English this wave.
- **Housekeeping:** mobile navigation enumerations gained the Measures
  screen; the apiMock helper gained the measures methods; the mobile
  import-style quirk that produced TS5097 during the wave was resolved
  (extensionless imports everywhere).

### 2026-09-19 — Product wave: PA/NA + energy detectors, caseload summaries, reminders/biometrics, check-in collapse

Four features from the independent product audit, all cross-stack, all
gates green (backend 1117 tests + probe 9/9 + mypy/ruff; mobile 1283
tests + tsc; portal 140 tests + tsc; cross-platform crypto vectors).

- **Four new pattern kinds (mini-brain).** The sentiment walk was
  extracted into `_valence_walk` (byte-identical compound, pinned by a
  regression test) with a new `sentiment_components` summing valences by
  SIGN — positive and negative affect are separable streams, not ends of
  one scale (Emmons & Diener 1985; Abitante et al. 2024). Three new
  inertia-family claims ride the same Fisher-z machinery, BH family and
  replication gates: `energy_inertia` (the payload-v2 energy pick,
  finally analyzed — collected since 2026-09-17, read by nothing until
  now), `pa_inertia` and `na_inertia` (text-scored entries only; an
  explicit mood check-in is one valence judgment and cannot be honestly
  split). The fourth, `energy_mood_coupling`, is the cross-channel
  concordance claim: Pearson correlation of energy and mood within-person
  residuals, recent vs the user's own earlier norm, surfaced only as a
  rise. Each kind ships with question templates (advice-free,
  question-only invariants enforced), `describe()` copy and mobile card
  rendering (channel-aware evidence rows).
- **Per-pattern mute** (from the week-1 wave, folded into this entry for
  release notes): "stop showing me this" rides the encrypted feedback
  channel (`{"feedback", "muted", "unmuted"}`), lands in a muted set
  inside the encrypted brain state that survives the dump/load
  roundtrip, and removes the pattern from question generation while its
  lifecycle keeps evolving underneath. Muted cards surface after all
  live cards (never displacing them), never marked "new", and the mobile
  app collapses them into a reversible "Muted (N)" section. Sensitive
  cards offer no mute and are never quoted in the muted section.
- **Encrypted caseload summaries (therapist portal).** At every patient
  recompute the server — inside the processing session, where the
  surfaced patterns already exist in memory — writes a small per-consent
  summary (pattern count, sensitive-card presence, newest first-seen)
  wrapped to the therapist's PUBLIC key with the same ECIES construction
  as the data-key wrap (new AAD context `"caseload-summary"`, bound to
  the patient/therapist pair; Alembic revision `f0b3d8e5a7c2` adds the
  three nullable consent columns; `app.db.SCHEMA_HEAD` bumped). The
  portal decrypts N small blobs instead of N full insight payloads when
  triaging, and — the safety point — a sensitive card's PRESENCE now
  surfaces as a calm non-quoting banner on the caseload screen without
  opening every chart. Summaries are null until the patient's first
  post-grant recompute, cleared on revoke, skipped (never failing the
  recompute) for a malformed therapist key. Cross-implementation pinned:
  the portal's WebCrypto opens a fixture produced by the Python
  reference; the backend test unwraps through the reference too.
- **Mobile: local journaling reminders.** Opt-in (onboarding panel 1 +
  Settings), local-only daily notification at a chosen time (default
  20:00), no streak-shaming copy, per-account prefs in AsyncStorage with
  hostile-input sanitization, and a pure `nextReminderFireTime` (tested
  across midnight/month/year boundaries). The last-mile notification
  uses the existing `nativeFeatures` seam: with `@notifee/react-native`
  linked it schedules a repeating daily trigger (permission asked
  honestly; provisional = denied); without the module the Settings row
  honestly reports "not linked in this build" and the pref still
  round-trips. Account deletion clears prefs and cancels schedules.
- **Mobile: biometric unlock.** The derived DATA key can optionally rest
  in the OS keystore wrapped under biometry-current-set
  (`react-native-keychain`, service `com.mindpattern.biometric-unlock.v1`,
  this-device-only). UnlockScreen offers "Unlock with biometrics" only
  when hardware + wrap exist; success restores local decryption only
  (documented dummy master/auth keys — server re-auth still needs the
  password), failure is a calm inline note and the password path is
  never demoted. Settings toggle states the trade plainly before
  enabling; disabling and account deletion remove the wrap.
- **Mobile: check-in collapse.** The four optional check-in rows (mood,
  energy, sleep, tags) now live behind an "Add details (optional)"
  disclosure directly under the editor — a daily writer no longer
  scrolls past ten rows of optional chips. Save sits under the
  disclosure; a collapsed summary line ("Details added: mood, sleep")
  names exactly what is set so nothing is silently attached to an entry.
- **Earlier this wave (already noted above in the week-1 entry):** the
  HistoryScreen edit data-loss fix (structured channels now survive
  edits), question auto-load with the key-shipment step still
  explicitly tap-gated, and the one-time threshold-crossing card.
- **Housekeeping:** the committed `redteam/results/f_mobile.json` was
  stale — a re-run at clean HEAD reproduces today's verdicts (2/35
  dialog-tier misses, a 2-sample TS/Python parity break that predates
  this wave; none of this session's code touched crisis detection). The
  refreshed artifact is committed as-is; the parity finding deserves its
  own triage.

### Added — Therapist sharing (zero-knowledge patient→clinician sharing)

The feature this app was building toward: a patient can let their therapist
see every surfaced pattern and, on click, the journal entries behind it —
read-only, with the therapist's own encrypted notes. The server stays blind
to content throughout.

- **Zero-knowledge grant (E2E preserved).** The therapist portal (new
  `portal/`, React + WebCrypto) registers with a P-256 wrap keypair; the
  private key is stored only as a password-encrypted blob. A patient types
  a short-lived single-use pairing code in the app ("Share with my
  therapist" in Settings), sees the therapist's name, re-authenticates with
  their password, and their client wraps the data key to the therapist's
  public key (ECDH → HKDF salted with both SPKI keys → AES-256-GCM, AAD
  `("consent-wrap", user, therapist)` — see
  `backend/app/security/sharing.py`, the reference implementation). The
  portal unwraps locally after login; the server never holds anything that
  decrypts patient content.
- **Pairing codes.** 8 chars, 15-minute TTL, single-use, stored only as an
  HMAC; unknown/expired/consumed answer the same 404. Codes replace
  username search so no therapist-enumeration oracle exists.
- **Role separation.** `users.role` gates every route: therapist tokens
  cannot reach journal endpoints (403 by dependency, not UI convention);
  patient tokens cannot reach therapist routes. There is NO therapist
  write path to patient data — read-only by construction.
- **Therapist reads + audit.** `GET /therapist/patients`, per-patient
  insights (byte-identical blob to the patient's own view) and entries
  (paginated, `since`/`until`). Every grant/revoke and patient-data
  read/write appends an `access_log` row; the log outlives account
  deletion (plain-string ids, no FK).
- **Evidence drill-down.** Surfaced patterns now carry
  `detail.evidence_dates` (the capped list of days whose entries fed the
  pattern) and `detail.pattern_pid` (stable id for note attachment). The
  portal fetches exactly those days' entries, decrypts them, and
  highlights label occurrences with per-entry mood — the "see all the data
  under this pattern" view. Sensitive (crisis-adjacent) cards stay
  non-quoting; the drill-down shows the patient's own words.
- **Notes.** Therapist-private (encrypted under the therapist's
  password-derived `portal-notes` key before leaving the browser),
  attachable to a patient or a pattern id, surviving revoke, cascading
  with account deletion on either side.
- **Revoke semantics, honestly stated.** Revoke (password-gated) clears
  the wrapped key — future access dies immediately; already-read data
  cannot be unread (the grant disclosure says so). Re-granting reactivates
  the same consent row, keeping the therapist's note continuity.
- **Cross-platform pins.** `shared/vectors.json` gains `wrap_vectors`
  (fixed test keypairs); backend, mobile (real quick-crypto seam code
  under node) and portal (real WebCrypto) all verify against them.
  Export bundles now carry share records (metadata only). GDPR posture:
  grant records the disclosure version, mirroring the LLM-consent record.
- **Tests.** Backend +64 API/crypto tests (role separation, pairing
  lifecycle, consent boundaries, cross-therapist isolation, E2E decrypt
  round-trips, audit, cascades, evidence dates) — suite 814. Mobile +26
  (wrap vectors, client wire shapes, full share-screen flows incl. wrong
  password/verifier/session-death branches) — suite 1103 at the same 98%
  per-file coverage floor. Portal: 62 (crypto vectors incl. the unwrap
  path, api client, app state machine, all views) with per-file coverage
  thresholds and a CI job.


## 1.0.0 - 2026-09-07

First release-quality tree after three audit/remediation rounds (security
adversarial audit, analysis-methodology audit, red-team round).

### Engine

- Deterministic, idiographic "mini-brain" v3: temporal (every weekday
  tested, Benjamini–Hochberg FDR), within-person mood correlations on
  residuals, lag-1 day-after links, inertia, instability, EWMA mood shift,
  rumination clustering, emergent topics, MinHash/LSH recurring phrases.
- Pattern lifecycle (`candidate → emerging → confirmed → fading →
  archived`, 45-day evidence half-life) with per-card evidence panels.
- Graded VADER-style sentiment engine; corrupt state degrades to amnesia.
- Ground-truth probe (`probe_brain.py`, 9/9 required, zero false
  associations) that exits non-zero on failure.

### Security model

- Client-side key derivation (PBKDF2-HMAC-SHA256, 600k) with HKDF split
  into auth key (server stores `scrypt(auth_key)`) and data key.
- AES-256-GCM blobs AAD-bound to (user, entry, context); cross-platform
  TS⇄Python crypto pinned by `shared/vectors.json` (incl. non-ASCII AAD).
- Single-use, memory-only processing sessions with key zeroization;
  30-active-day revelation threshold enforced server-side.
- Enumeration-resistant salt lookup with decoys; epoch token revocation;
  re-authentication for account deletion and LLM enablement.
- Fail-closed ops gates (production default env, ≥32-char token secret, no
  SQLite outside development), security headers on every response, 2 MiB
  body cap, bounded rate limiting, no access logs in the image.

### Platform

- FastAPI backend (Python 3.12+), Alembic migrations run by the container
  entrypoint, docker-compose stack (postgres + api).
- React Native mobile client (iOS/Android) with offline sync queue,
  device-local baseline mood trend, offline crisis resources screen.
- Optional consent-gated, output-sanitized LLM analysis path (off by
  default).

### Verification

- 573 backend tests (unit + API integration + crypto vectors +
  production-hardening + adversarial regressions), 97% coverage floor.
- 425 mobile tests with 98% per-file coverage thresholds.
- Mutation-tested security + services cores (mutmut; Stryker on mobile).
