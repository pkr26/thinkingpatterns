# 1-Year, 13-User (10 Typed + 3 Voice), Scoped E2E Simulation — 2026-09-29

**Scope clarification — October 3, 2026:** the results below describe the
September 29 run, not the current API. Recovery/kit administration,
clinician note rekey and note deletion were not exercised. Providers were
synthetic. Daily lifecycle replay reused the same engine; the live server
performed a final recompute per persona. At-rest checks sampled 200 entry,
up to 100 insight and up to 100 measure blobs, with nine fixed plaintext
probes. Rate limiting required a 429 within 241 attempts, not exactly on
attempt 241. These are integration diagnostics, not clinical validation.


**Result: 366/366 checks passed** (`run_voice.log`, `results.json`; the
campaign exits non-zero on any failure). Wall time 4.9 min for 8,629
entries, 995 spoken takes through the real transcription pipeline, 54
kept recordings, ~2,900 total API calls.

The standing campaign (2026-09-28: 246/246, 10 users) extended for the
voice feature (2026-09-29): the same live-API philosophy — every entry
synced through the real server over real HTTP, encrypted with the real
client crypto stack (real 600k-iteration PBKDF2, HKDF auth/data keys,
AES-256-GCM with the exact AAD contracts of the mobile/web apps) — now
covering **thirteen personas** (ten typed, three who journal by VOICE
and by text), the routes listed below, and the voice
surface against two in-process fake providers (OpenAI-compatible STT
and chat-completions endpoints) that the campaign script itself serves,
so the server's real `services/stt.py` / `services/llm.py` clients make
genuine HTTP round-trips.

## How to re-run

The campaign serves the two fake providers itself on 127.0.0.1:8912
(STT) and :8913 (LLM); the SERVER must be booted pointing at them:

```bash
cd backend
MINDPATTERN_ENV=development \
MINDPATTERN_DB_URL="sqlite+aiosqlite:///./sim1y.db" \
MINDPATTERN_AUTH_RATE_LIMIT=1000 \
MINDPATTERN_ENTRIES_RATE_LIMIT=20000 \
MINDPATTERN_PROCESSING_RATE_LIMIT=300 \
MINDPATTERN_READ_RATE_LIMIT=30000 \
MINDPATTERN_EXPORT_RATE_LIMIT=60 \
MINDPATTERN_STT_URL="http://127.0.0.1:8912/v1" \
MINDPATTERN_STT_API_KEY="sim-stt-key" \
MINDPATTERN_STT_MODEL="whisper-1" \
MINDPATTERN_STT_PROVIDER_NAME="SimWhisper" \
MINDPATTERN_STT_DATA_RETENTION="simulated zero-retention" \
MINDPATTERN_LLM_URL="http://127.0.0.1:8913/v1" \
MINDPATTERN_LLM_API_KEY="sim-llm-key" \
MINDPATTERN_LLM_MODEL="sim-chat" \
MINDPATTERN_LLM_PROVIDER_NAME="SimLLM" \
MINDPATTERN_LLM_DATA_RETENTION="simulated zero-retention" \
MINDPATTERN_AUDIO_TRANSCRIBE_RATE_LIMIT=3000 \
MINDPATTERN_AUDIO_UPLOAD_RATE_LIMIT=300 \
MINDPATTERN_AUDIO_MAX_USER_BYTES=262144 \
MINDPATTERN_AUDIO_LOCAL_DIR="./data/audio-sim1y" \
../.venv/bin/uvicorn app.main:app --port 8908 --log-level warning

# from the repo root, fresh DB each time:
rm -f backend/sim1y.db* && rm -rf backend/data/audio-sim1y
E2E_BASE=http://127.0.0.1:8908 \
E2E_DB="sqlite+aiosqlite:///$(pwd)/backend/sim1y.db" \
.venv/bin/python reports/simulation1y/simulate.py
```

Rate limits are raised exactly like the 2026-09-28 run (the machinery
itself is still verified against the DEFAULT ops bucket — phase 18);
the audio quota is lowered to 256 KiB so the quota refusal (413) is
reachable in a year-scale run.

## The three voice personas (365 days each, mixed voice + text)

| user | spoken takes | story planted | what surfaced |
|---|---|---|---|
| rosa | 365 (es) | M/W/F Spanish sleep worry + Sunday work dread, typed Spanish notes | `rumination` on BOTH Spanish worry sentences (n=36 + n=27) analyzed natively in Spanish; 15 patterns total |
| amara | 365 (fr) | Thu/Sun chest-tightness worry spoken in French, typed French notes | `recurring_phrase` "my chest tightens before the weekly review" (n=39) — clustered from the ENGLISH translation (D-7 routing); zero French words in any pattern label |
| kwame | 266 (en) | **VOICE CONTROL**: mundane varied takes, 54 kept recordings | zero statistical kinds AND zero false phrase cards; the whole kept-recording lifecycle ran on his account |

Every spoken take made the real round trip: synthetic recording →
`POST /audio/transcriptions` (multipart, bearer-keyed, whisper-1
verbose_json) → transcript + detected language + phrasebook English
translation → payload-v3 entry (`input_mode=voice`, `transcript_lang`,
`english_text`) encrypted under the entry AAD → `POST /entries` →
(optional) client-encrypted kept recording → `POST /audio/attachments`.

## What the campaign verified (19 phases)

- **0 boot** — /healthz, /readyz, /api/meta (unlock 30, disclosure v2,
  llm_available with the fake provider, **audio_available with the STT
  policy fingerprint**), /api/v1 canonical mount parity.
- **1 registration** — 13 patients + 2 therapists; duplicate username
  409, charset/salt/unknown-field 422s, garbage wrap key 422, salt
  decoy for unknown users (deterministic, same shape).
- **2 the year of entries** — typed entries for all 13 (voice users'
  typed notes included), all 201; duplicate cid 409, future/past date
  422s, non-b64 blob 422, 3 MiB body 413, missing/bogus bearer 401.
  ben's entries carry payload v2 (energy/sleep/tags/tod).
- **3 voice year (NEW)** — the full voice surface:
  - consent wall: transcribe/attachment without voice consent → 403
    `voice_consent_required`; therapist token → 403; anonymous → 401;
    voice-consent enable without/wrong verifier → 422/403, with
    verifier → 200 recording the CURRENT policy fingerprint (Art. 7);
  - **H4 privacy gate live**: kwame with voice consent but NO llm
    consent transcribes fine with `english_text: null`, and the fake
    LLM's dispatch log stays EMPTY — voice consent alone never sends
    journal text to the LLM provider; after his llm consent, exactly
    one re-translation dispatch;
  - rosa's patient journey: take → Spanish detected (`language_raw`
    "spanish" → ISO es) → phrasebook translation → v3 save → **edits
    the transcript** → re-translates via `/audio/translations` → PUT
    with version bump, v3 channels preserved;
  - 995 takes transcribed+translated+saved across the three personas,
    each asserted against the expected transcript/language/translation;
  - kwame keeps 54 recordings (client-side AES-GCM under the "audio"
    AAD), every expiry ≈ upload + 30 days;
  - STT provider discipline: all 998 upstream calls bearer-keyed,
    whisper-1 + verbose_json, filename derived from the mime table;
  - **STT retry (M8)**: a 429-with-Retry-After take is retried exactly
    once (2 upstream sends) and succeeds; a hard-failing take → 502
    `stt_upstream` after the one bounded retry;
  - route validation: unsupported mime 422, duration over cap 422,
    empty/non-b64 audio 422, 5 MiB take 413 at the audio body cap;
  - owner listing carries audio metadata exactly on kept takes.
- **4 editing lifecycle** — dev's PUTs with content_version bump + AAD
  ladder, stale version 409, DELETE + revision header, pagination walk,
  expected_revision conflict, page_bytes budget, since= filter.
- **5 measures** — ben's 26 PHQ-9s as opaque ciphertext, DESC ordering,
  revision header, DELETE with wrong verifier 403 / right verifier 200.
- **6 recompute / insights / questions** — 13 users: processing session
  (bad key 422), single-use token (reuse 403), recompute without token
  401, insight blob decrypt, **live == single-shot determinism (13/13,
  including the three voice users whose analysis text follows D-7)**;
  analyzer is `brain` for the ten text users and `llm` for the voice
  users (consented enricher, brain-first); rosa's Spanish worry
  surfaces as `rumination` (n=36+n=27), amara's from the ENGLISH
  translation (n=39) with no French in any label, kwame (voice control)
  surfaces nothing; the enricher dispatched exactly where findings were
  narratable (2 calls) with findings-only payloads; chloe feedback taps
  + malformed feedback 400; control tom surfaces no statistical kind
  after a noise year and no rumination cards.
- **7 local-recompute** — chloe's on-device brain run uploaded as two
  client-encrypted blobs, seq+1, stale base_state_seq 409, GET
  /insights serves the payload byte-identically.
- **8 sharing lifecycle** — the full zero-knowledge flow (pairing +
  SAS on both ends, grant, therapist reads, notes with versions +
  revisions + idempotent retries, revoke, re-grant, wrap-key rotation +
  rewrap, caseload summaries) **plus kwame's voice share**: share-voice
  verifier-fenced toggle (422/403/200), portal roster serves the live
  `share_voice` grant, therapist entry listing carries audio meta,
  portal decrypts a v3 voice entry with the unwrapped key, therapist
  plays the kept recording (decrypts to the exact take bytes, honest
  mime/duration/size/expiry metadata), other therapist → flat 404,
  share-voice off → 403, re-enable → playback resumes, consent revoke →
  audio path dies (404).
- **9 kept-recording lifecycle (NEW)** — owner fetch decrypts
  byte-identically; another patient's attachment id → 404; re-upload
  replaces (same row, refreshed expiry, old object deleted — no disk
  orphans); DELETE keeps the entry and drops its audio meta; **lazy
  expiry**: an aged row answers 410 `audio_expired` then disappears;
  **quota**: 150 KiB re-upload within the 256 KiB cap → 201, the next
  → 413 `audio_quota_exceeded`; unknown entry → 404 `unknown_entry`,
  sub-MIN_BLOB_SIZE blob 422, unsupported mime 422; voice-consent OFF →
  transcribe/upload 403 while kept recordings stay PLAYABLE (playback
  dispatches nothing); re-enable → 200.
- **10 key lifecycle** — priya rekey, elena v1→v2 envelope upgrade +
  O(1) password change (therapist consent survives), ava documented
  v1 ordering.
- **11 TOTP** — therapist setup/enable/login/backup codes/replay/
  disable, role walls.
- **12 LLM consent lifecycle** — defaults disabled; enable → 200
  against the live policy fingerprint (the 409 honest-refusal case
  stays pinned by unit tests for unconfigured deployments); double-
  enable idempotent; disable wipes the Art. 7 record.
- **13 logout** — 204, that jti dead, other token alive.
- **14 export** — 13 bundles decrypted locally; the voice users'
  bundles carry their v3 payloads (input_mode/transcript_lang/
  english_text verified after local decrypt); elena's active grant.
- **15 access logs** — elena's cursor-paginated log records therapist
  reads; **kwame's log records every audited therapist playback
  (`audio_access`, 2 rows, actor=therapist) and his own share-voice
  on/off toggles**; therapist log names the patient.
- **16 boundaries, roles, deletion** — cross-therapist 404s, patient
  token on therapist routes 403, therapist token on patient routes +
  **both /audio routes** 403; therapist + fred deletion lifecycles;
  **gina (voice user): account erasure removes her kept-recording
  OBJECTS from the store — and the account's directory — not just the
  rows (M2)**.
- **17 storage at rest** — 13 tables inspected (incl.
  `audio_attachments`, 52 live rows); the sampled entry/insight/measure blobs
  fail the structural plaintext test; the raw DB file and WAL contain
  none of 9 journal/note/voice probes (Spanish + French + the
  synthetic-audio marker); **every object in the local audio store is
  opaque ciphertext — no take plaintext on disk**.
- **18 rate limiting** — the default ops bucket returns 429 with
  Retry-After within 241 burst attempts.

## Honest observations (not failures)

- The H4 gate did exactly what the audit required — the first campaign
  run forgot to grant rosa/amara LLM consent and their translations
  came back null; the server was right, the campaign was wrong. That
  interplay (voice consent ≠ translation consent) is now an explicit
  3-check story instead of an assumption.
- amara's first draft (two worry variants at ~11 takes each) fell
  under the phrase-support gate and honestly surfaced nothing; the
  persona now plants one canonical sentence (maya's shape), and the
  cluster earns its n=39.
- The LLM enricher dispatched only for rosa and amara: kwame (voice
  control) surfaces no findings, and a findings-less enrichment call
  is skipped by design (nothing to narrate).
- **Fixed during the run (2026-09-29):** the first green run showed
  account erasure deleting gina's kept-recording OBJECTS correctly but
  leaving the empty `audio/<user-id>/` directory behind — and the key
  layout embeds the account id, so the erased identity survived on
  disk as a directory name. `LocalAudioStore.delete` now prunes the
  account's directory once its last object is gone (pinned by
  `test_local_store_prunes_empty_user_dirs` and the extended M2
  erasure test), and this campaign's gina check is tightened back to
  asserting the whole directory is gone.
- Everything from the 2026-09-28 report's observation list still
  holds: single-shot recomputes surface only direct-measurement kinds;
  tom earns filler-phrase cards (repeated text is direct measurement);
  ava/priya's planted arcs stayed under the statistical bars while
  priya's inertia surfaced.

## The ten typed personas (unchanged from 2026-09-28)

| user | entries | story planted | what surfaced (daily-user view) |
|---|---|---|---|
| maya | 730 | work-dread Sundays + M/W/F sleep worry, next-day dips | `mood_correlation sleep` (n=73, day 36), `mood_correlation/temporal work` (n=31), rumination on the work-dread sentence (n=26) |
| omar | 730 | stable; guitar topic rising the last 90 days | `topic guitar` **confirmed n=61 from day 350** |
| priya | 772 | doomscroll nights; late-year decline + inertia | `inertia day-to-day mood` (n=28, day 352) |
| lena | 782 | family visits with next-day dips; Sunday grandma calls | `link family` (n=66) + `temporal family` (n=66) |
| tom | 489 | **CONTROL: pure noise all year** | **zero statistical kinds, 365 days** |
| ava | 730 | mid-year decline, late recovery, run days higher | run-sentence phrase cards only |
| ben | 730 | payload-v2 structured channels + 26 encrypted PHQ-9s | `mood_correlation poor sleep` (n=44, day 37) |
| chloe | 766 | crisis episodes ~10-dayly | crisis-phrase cluster flagged `sensitive=True`; questions never quote it |
| dev | 730 | editor: rewrites 8% of the year, deletes 12, weekly stress | `mood_correlation/temporal work` + rumination (n=21) |
| elena | 624 | stable journaler; sharing + key-lifecycle persona | filler-phrase cards only |

Every user's **live single recompute == offline single-shot replay**
(determinism, 13/13), and each user's full year was replayed
clock-accurately day by day through the same `brain.update` the server
runs (`timeline_<user>.csv` × 13).

## Artifacts

- `simulate.py` — the campaign (13 personas, client crypto incl. the
  audio envelope, the two in-process fake providers, 19 phases).
- `run_voice.log` — full 366-check output.
- `results.json` — per-user patterns (live + daily replay), timelines,
  checks, table counts.
- `timeline_<user>.csv` × 13 — per-day surfaced counts, new pids,
  state transitions.

## Remediation addendum (2026-09-28, kept for the record)

The original 245-check run surfaced one real product finding — affect
misclassification at the rumination gate, in both directions, from two
polysemous words:

- **"down" curated at −1.3** made the directional particle ("took it
  down") carry whole clusters past the −0.30 rumination bar: tom (the
  pure-noise control!) and chloe both received a "repeated worry" card
  for a recycling chore (n=5–7).
- **"stop" inheriting VADER's −1.2** meant perseverative negation
  inverted it — maya's flagship "i can't sleep, my mind won't stop"
  (61 occurrences) scored **+0.222** and stayed a neutral
  recurring_phrase instead of the rumination the negation-heavy path
  exists to catch.

**Fix** (brain.py `CURATED_SENTIMENT`): `down → −0.6`, `stop → 0.0`.
Regenerated `shared/brain_lexicon.json`, both TS lexicon modules, and
`shared/brain_vectors.json`. Pinned by 9 tests in
`backend/tests/test_lexicon_remediation_2026_09_28.py`, and re-proven
live in this campaign (tom: zero rumination cards; maya: sleep worry
is rumination; rosa's Spanish twin of maya's worry now also surfaces
as rumination natively in Spanish).

Known remaining gap (documented, deliberately not changed here):
"can't stop crying" still reads positive because the negation window
flips "crying" *through* the now-neutral "stop" — that is VADER's
pinned negation semantics, a separate, heavier change than a word
weight.
