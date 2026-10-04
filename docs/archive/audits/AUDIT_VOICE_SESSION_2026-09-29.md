# Independent exhaustive audit — commit d577a69 (Voice journaling, VOICE_PLAN P0–P6)

Date: 2026-09-29 (post-commit, same day)
Scope: everything changed in `308d403..d577a69` — 66 files, +9,457/−432
(backend, web, mobile, portal, shared contracts, redteam, docs).
Method: fresh-eyes read of every security-critical backend path by the
auditor, three parallel independent review passes (web+portal, mobile,
contracts/docs/tests), every claimed-green suite re-run from scratch, and
personal re-verification of each HIGH/CRITICAL claim against source
(including the installed expo native sources). Nothing was modified
except this report; test runs were isolated from the running dev
servers (`MINDPATTERN_LOCK_DIR`).

---

## 0. Verdict

The **backend voice surface is genuinely well-engineered** — consent
fingerprinting, bounded STT transport, opaque-ciphertext storage, quota,
lazy expiry, and therapist gating all check out under adversarial
reading. The **web crypto layer is equally solid**. But the commit is
not shippable as a whole:

1. **Mobile voice journaling cannot work on any device as shipped**
   (CRITICAL ×3 + HIGH): expo autolinking is absent, microphone
   permissions are undeclared, and the recorder call sequence silently
   no-ops on both platforms. The test suite stays green because the expo
   mocks are inert (one mock even misspells the API it mocks).
2. **The web recorder has real defects** in exactly the untested
   interactive code: inverted unmount teardown (hot mic after navigating
   away), N simultaneous autoplaying `<audio>` elements in History, and
   a 15-second client timeout that makes the advertised 5-minute takes
   untranscribable.
3. **A consent-scope gap**: transcripts are dispatched to the LLM
   translation endpoint without the user's `llm_consent` and without the
   voice-consent copy disclosing it.
4. **Process claims don't reproduce**: the P6 "redteam campaign" is a
   docstring that was never wired or run; the dev MinIO round-trip
   claimed green cannot work as shipped; and the "web 691 green" claim
   fails on the tree as left (1 SRI test failure against the session's
   own unstamped `dist/`).

---

## 1. Test-suite verification (re-run from scratch, 2026-09-29)

| Suite | Commit claim | My result | Notes |
|---|---|---|---|
| backend | "685 green (38 new voice)" | **green** (~1,702 collected, 0 failed, 4 skipped) | First run errored with `MultipleWorkersError` — a *dev-server collision* (two uvicorns on :8000/:8001 share the lock dir), not a code failure; green once isolated. The "685" number is also wrong: the suite is ~1,698 passing tests. |
| web | "691 green (16 new)" | **691 passed, 1 FAILED, 5 skipped** | `tests/securityConfig.test.ts` SRI pin fails: the session's `dist/index.html` (built 07:48, commit 08:18) carries **zero** integrity attributes. `npm run build` cannot have produced it — the fail-closed `security.txt` placeholder gate currently aborts `add-sri` *before* stamping. The dist was built by bypassing the post-build step. |
| mobile | "1,973 green (8 new)" | **1,973 passed, 1 skipped** | Matches — but is green only because the voice-path mocks are vacuous (§4, H3-m). |
| portal | "459 green" | **459 passed** | Matches. |

Operational note: two uvicorn dev servers were left running from the
session (ports 8000/8001); they poison any un-isolated backend test run.

---

## 2. Verified solid (adversarially read, no issues found)

- **Route wall order** (`backend/app/api/audio.py:62-76`): authenticate →
  role → `audio_enabled` flag, flat 404 when off; anonymous probes get
  the standard 401, therapists the standard 403.
- **Consent discipline** (`services/stt.py:180-206`,
  `api/account.py:1496-1552`): Art. 7 record (timestamp + disclosure
  version + SHA-256 policy fingerprint over url/model/provider/
  retention/policy/disclosure), verifier re-auth, lifecycle fence,
  epoch re-check, stale-consent inertia on operator policy change.
- **STT transport** (`services/stt.py:234-278`): wall-clock deadline +
  per-I/O timeouts, `follow_redirects=False`, `trust_env=False`,
  Content-Length pre-check, 1 MiB streamed response cap, control-char
  stripping, 100k-char transcript caps. https-only is enforced **at
  boot** in `config.py:908-936` (exact loopback exemption in
  development) — the module docstring's claim holds.
- **Upload path** (`api/audio.py:293-423`): per-user lock + lifecycle
  fence + fresh epoch-checked re-read; entry-existence check; quota
  arithmetic `live_total − replaced + new ≤ 64 MiB`; put-then-repoint
  replace semantics (never a row without its object); bounded schemas
  (`schemas.py:376-431`).
- **Therapist audio route** (`api/therapist.py:1410-1510`): dual
  therapist/patient locks, `_active_consent` + `share_voice` gate,
  owner check, lazy expiry, `audio_access` audit row committed before
  the response leaves the fence.
- **Storage** (`services/audio_store.py`): server-generated keys
  (`audio/{user_id}/{uuid}.enc`, nothing client-controlled in a path),
  resolved-containment check on the local store, idempotent deletes,
  objects-before-rows sweep discipline, batch cap.
- **Migrations** (`c3e7f1a9d2b4`, `e8a4c2f7b1d6`): additive,
  fail-closed defaults, model parity (L-33), unique
  (user, client_entry_id), user+expires index.
- **Middleware** (`middleware.py:97-109, 229-252`): exact-segment audio
  path matching (no `/audiobook` swallow), live-settings route-scoped
  cap; config boot-validates every audio knob against real ceilings
  (`config.py:714-745`).
- **Crypto v3 (all three clients)**: AES-256-GCM, fresh 96-bit nonce
  per encrypt, AAD context separation `("audio", userId,
  clientEntryId, "1")` with cross-user/cross-entry/entry↔audio grafts
  failing closed (tested on web and mobile); v1/v2 payloads stay
  byte-identical (typed entries unchanged); unknown-version loud-fail
  correctly bumped to v4; web decryptAudio zeroizes on failure; portal
  zeroizes the unwrapped data key after each playback.
- **No XSS sinks**: transcripts/translations render only as React text
  children across web/portal/mobile; no `innerHTML`/
  `dangerouslySetInnerHTML` in scope; no plaintext audio or transcripts
  in localStorage/AsyncStorage/logs.
- **Backend test quality** (38 voice tests): real ASGI+DB+filesystem
  paths, behavior assertions (lazy expiry asserts row AND file AND
  listing metadata gone; therapist gate asserts exactly one audit row,
  none on refusal/expired; quota replace-adjusts). No skips, no vacuous
  asserts.

---

## 3. Findings — CRITICAL (ship-blockers, mobile)

**C1. expo native modules are not linked — the app crashes at launch on
device, and the commit's own "run pod install" note does not fix it.**
`mobile/ios/Podfile` has no `use_expo_modules!` stanza and
`mobile/android/settings.gradle` no `useExpoModules`; this is a bare
React Native app. expo's autolinking disables itself when the Podfile
lacks the stanza (`node_modules/expo/react-native.config.js` gates
`ios:` on a `/use_expo_modules!/` file match — verified via
`npx react-native config`: only the `expo` package is discovered;
`expo-audio`, `expo-modules-core`, `expo-file-system` are absent).
`expo-audio` resolves its native module eagerly
(`src/AudioModule.ts:6`, `requireNativeModule('ExpoAudio')`) and
`src/navigation.tsx:9-10` statically imports screens that import
`expo-audio` → `Cannot find native module 'ExpoAudio'` at startup on
both platforms.

**C2. Microphone permissions are not declared on either platform.**
`mobile/ios/MindPattern/Info.plist` has no `NSMicrophoneUsageDescription`;
`mobile/android/app/src/main/AndroidManifest.xml` declares only
`INTERNET`. On iOS, `requestRecordingPermissionsAsync()`
(`mobile/src/audio/recorder.ts:134`) hits the TCC hard-abort
(uncatchable by the surrounding try/catch); on Android the request
auto-denies and the UI tells the user to change *their* settings when
the manifest is the blocker.

**C3. `recorder.record()` is called without `prepareToRecordAsync()` —
a silent no-op on both platforms; a recording can never start.**
`mobile/src/audio/recorder.ts:146`. Verified against the installed
expo-audio native sources: iOS `AudioRecorder.startRecording()` guards
`currentState == .prepared || .paused` and nothing ever calls
`prepareToRecordAsync()` (only that call sets `.prepared`); Android
`AudioRecorder.record()` safe-calls a `recorder` that is null until
`prepareRecording()` runs — while still setting `isRecording = true`.
Symptom: "Recording…" UI with a running timer while nothing is
captured; on stop, `recorder.uri` was never set, the file read throws,
and the user sees "Recording failed" every time.

**C4 (HIGH, bundled). The recording options are invalid for both
platforms in ways the `as const`/`as never`/`as unknown as number`
casts hide from TypeScript.**
`mobile/src/audio/recorder.ts:19-41`. Android passes numeric
`outputFormat: 2, audioEncoder: 3` where expo-audio 57 expects string
enums (`'mpeg4'`/`'aac'`) — `EnumTypeConverter` throws at recorder
construction, i.e. **EntryScreen render crash on Android**. iOS passes
`outputFormat: "lpcm"` into an `.m4a` container (LPCM requires
caf/wav/aiff) → init failure, or if it ever records: uncompressed
16 kHz/16-bit mono ≈ 9.6 MB per 5-minute take ≈ 12.8 MB base64 —
guaranteed 413 `audio_too_large` against the 4 MiB route cap. Also
`audioQuality: 96` is `HIGH`, not the commented "Medium". The pinned
codec contract (mono ~24 kbps AAC/m4a, `shared/audio_vectors.json`)
is not what either platform is configured to produce.

**C5 (HIGH). The mobile voice-consent flow is a dead end: there is no
Settings toggle, but the shipped copy sends the user to one.**
`getVoiceConsent`/`setVoiceConsent`/`setShareVoice` exist in
`mobile/src/api/client.ts` but zero screens call them (repo grep: 0
matches outside the client; `SettingsScreen.tsx` contains no voice
code). A user who records without consent gets 403 after up to 5
minutes of speaking, with "turn it on in Settings" pointing at a
toggle that does not exist. The commit message and CHANGELOG both
claim mobile "Settings/Share toggles" — the mobile half was not
delivered.

---

## 4. Findings — HIGH (web + backend)

**H1. Web recorder "unmount teardown" is inverted — the mic stays live
after navigating away.** `web/src/audio/recorder.ts:144-157`. The
teardown logic sits in the effect *body* (which runs at mount, when
every ref is null) and the returned cleanup is `() => undefined`. React
runs the body on mount and the cleanup on unmount — so nothing is torn
down on unmount: MediaStream tracks keep running (browser mic
indicator on), the 500 ms interval and rAF loop keep firing against a
dead component for up to 5 minutes, and the cap-time `finalize()` sets
state on an unmounted component. Verified: the comment
("Unmount is a hard teardown") describes exactly what the code fails
to do. Fix shape: `useEffect(() => () => { …body… }, [teardown])`.

**H2. History playback mounts one autoplaying `<audio>` per voice
entry, all bound to the same URL.** `web/src/views/History.tsx:586-588`
gates only on `{playing && …}` inside every `entry.audio` block — not
on *which* entry is playing. N kept recordings → N simultaneous
`<audio autoPlay>` elements; the first `onEnded` revokes the object URL
under the others. The portal got this right
(`PatientView.tsx:1381-1389` keys on `playingId === attachment_id`),
confirming the web side simply missed the guard. Also places the audio
element under every audio-capable card (visual cross-entry
association).

**H3. The 15-second client request timeout makes the advertised
5-minute takes untranscribable.** `web/src/api/client.ts:25`
(`REQUEST_TIMEOUT_MS = 15_000`) applies to `transcribeAudio`
(`client.ts:793`) and the attachment upload via the shared
`fetchWithTimeout`. The server budgets 120 s for the STT round-trip
(`stt.py:52`) — multi-minute takes routinely exceed 15 s of
upload+transcribe. On timeout there is **no retry path**: the blob is
consumed, the user's only recovery is re-recording. (Mobile has the
same 15 s wall on transcription, retry exists only for attachments.)

**H4. Consent-scope gap: transcripts are dispatched to the LLM endpoint
without `llm_consent` and without the voice consent disclosing it.**
`services/stt.py:313-353` (`translate_to_english`) constructs
`LLMAnalyzer` gated only on `settings.llm_url`; the callers
(`api/audio.py:176-178, 214-217`) check voice consent only. Everywhere
else in the codebase LLM dispatch is per-user consent-gated
(`insights.py:1380,1452` → `llm.get_enricher(settings,
llm_consent=…)`). A user who declined LLM processing still has their
transcript (journal-equivalent plaintext) POSTed to the LLM provider
through the voice path. The voice-consent copy
(`web/src/locales/en.ts:1225-1226`) discloses only
"{provider} to be transcribed and deleted immediately after" — the
second subprocessor is neither consented nor disclosed, and the voice
policy fingerprint does not cover the LLM endpoint. Either gate
translation on `llm.consent_is_current` or fold the LLM endpoint into
the voice disclosure + fingerprint.

**H5. The P6 "redteam campaign" is a non-executable docstring, unwired
and unrun.** `redteam/g_voice.py` is 73 lines of module docstring — no
imports, no harness, no verdicts; `redteam/run_all.sh:35-42` never
invokes it and `redteam/results/g_voice.json` does not exist. Every
other campaign in the repo is executable. The P6 gate "redteam findings
triaged to zero highs" was satisfied by a no-op, and several of its
"TESTED" labels overstate (no rate-bucket test anywhere; the actual
`_post_audio` guards execute in zero tests — always monkeypatched; the
recurring sweeper task is untested). The adversarial coverage that
*does* exist lives in the pytest suites and is real — but the campaign
artifact is not.

**H6. Both platforms' recorder-lifecycle test coverage is vacuous —
every defect above is in exactly the untested code.** Web: the
`useRecorder` hook (unmount teardown, reset-during-recording,
double-start, auto-stop), the Entry voice flow, History playback
gating, and the Settings/Share toggles have zero tests. Mobile: the
expo mocks are inert — `expoAudioMock.ts:6` defines
`requestRecorderPermissionsAsync` (the real API is
`requestRecordingPermissionsAsync`; production code would hit
`undefined is not a function` if any test actually drove it),
`useAudioRecorder` never yields a take, and `expoFsMock.ts` puts
`readAsStringAsync` only on the default export while production
imports `* as FileSystem from "expo-file-system/legacy"`. 1,973 green
while the feature cannot function on a device.

---

## 5. Findings — MEDIUM

**M1. Dark-launch flag does not cover the therapist audio route or the
share-voice toggle.** `api/therapist.py:1414-1419` and
`api/consents.py:673-678` lack the `audio_enabled` check the patient
`/audio` router has. During a flag-off rollback, patients lose even the
standalone "remove audio, keep entry" DELETE (flag-gated) while
therapists can still fetch previously stored recordings.

**M2. Account erasure orphans audio objects.**
`alembic/versions/e8a4c2f7b1d6:40` cascades rows via FK; `delete_account`
(`api/account.py:1642`) deletes no objects; the sweeper selects rows so
it can never catch orphans; the S3 31-day lifecycle backstop is an
optional operator gate and nonexistent for the local-dir store.
`docs/DATA_RETENTION_SCHEDULE.md` claims "(row + object)" — overclaim.

**M3. `shared/audio_vectors.json` ships zero crypto vectors and its AAD
pin misdescribes the wire format.** No fixtures (keys/nonces/ct/tag)
exist despite being the named P0 cross-platform pin; cross-client
(web↔portal — the actual production pairing) audio decryptability is
pinned nowhere. The pinned tuple types the version as number `1` while
every client builds the string `"1"`
(`web/src/crypto/patient.ts:231`, `mobile/.../MindPatternCrypto.ts:229`,
`portal/src/crypto.ts:701`); a client implemented from the file would
fail every decrypt. No audio entry in `redteam/aad_corpus.json` either.

**M4. The dev MinIO round-trip claimed green in the P2 gate cannot work
as shipped.** `docker-compose.dev.yml:20-29` points the API at MinIO
(`minioadmin`) but neither the compose nor `S3AudioStore`
(`audio_store.py:81-92`) sets an endpoint override — boto3 resolves the
bucket against real AWS and fails. `S3AudioStore` also has zero tests
(SSE header, thread offload, error mapping all unexecuted).

**M5. Web recorder/flow defects (all verified in source):**
- `start()` has no re-entrancy guard; the first mic press awaits a full
  `meta()` round-trip with the button enabled — a double-click runs two
  `getUserMedia`/`MediaRecorder` sequences, orphaning the first stream
  (live mic) and interleaving both recorders' chunks into the shared
  `chunksRef` (`recorder.ts:159-190`).
- `reset()` during recording resurrects the discarded take:
  `teardown()` stops the tracks, which (per spec) asynchronously fires
  `dataavailable`+`stop` on the still-attached `onstop`, re-setting the
  recording after `reset()` cleared it — reachable via Record → Discard
  (`recorder.ts:191-203, 245-251`).
- `transcribing` can stick `true` forever when the effect's cleanup
  fires mid-flight (`Entry.tsx:230-232`) — the mic button is then
  disabled for the view's lifetime.
- Consent is only discovered *after* recording (403 on transcribe) with
  no way to consent and re-submit the blob — the take is simply lost
  (`Entry.tsx:106-125`).
- Editing a voice entry silently strips the v3 voice channels
  (`History.tsx:336-350` re-encrypts without `voice`) — "recorded" badge
  and the portal's translation/original-toggle vanish while the kept
  audio (same `clientEntryId`) survives with no matching metadata.
  Mobile edit has the identical gap (`HistoryScreen.tsx:781-791`).
- `stt_unavailable` is missing from the web `API_ERROR_CODES`
  allowlist (`client.ts:79-123`; mobile has it) so the localized
  Settings branch at `Settings.tsx:323` is dead code.
- Save during recording/transcription is allowed and the late
  transcript repopulates the freshly-cleared editor (`Entry.tsx:428-438`).

**M6. Mobile privacy/correctness:** the plaintext recording persists in
the OS cache dir on unmount/backgrounding (cleanup only clears the
timer, `recorder.ts:169-173`; no EntryScreen unmount path discards the
take) — contradicting the module's own "cache file is deleted" claim;
playback scratch file leaks on player-construction failure
(`HistoryScreen.tsx:288-295`); duration is wall-clock so a backgrounded
take can arrive >310 s and be 422-rejected, voiding the recording
(`recorder.ts:108,150`); a successful transcription silently overwrites
typed text with no confirmation (`EntryScreen.tsx:148-149`).

**M7. Portal:** play buttons render for every `entry.audio` regardless
of the consent's `share_voice` flag, and every playback failure
(revoked share, expiry, storage, GCM tamper) is silently swallowed
(`PatientView.tsx:113-116`) — therapists of non-sharing patients get
buttons that can never work with zero feedback. Portal decrypt also has
no payload-version guard (any future `v` renders as today's shape).

**M8. Deployment/docs drift:** `deploy/nginx/mindpattern.conf.example`
still `client_max_body_size 2m` with no audio location (plan promised
the raise; a copied config proxy-413s uploads the app would accept);
plan's 12 MiB cap vs shipped 4 MiB; no STT 429/5xx retry and no
`MINDPATTERN_STT_TIMEOUT_SECONDS` (both promised; timeout is hardcoded
120 s); DPIA_SKELETON.md and WEB_THREAT_MODEL.md contain zero
voice/audio mentions; "recording expires in Nd" (`history.recordingExpires`)
is defined in both locales and rendered nowhere; the 30-day countdown
data is fetched and never shown.

**M9. Store construction per request.** `get_audio_store(settings)` is
called per request in every audio route — for S3 this constructs a
fresh boto3 client each call (no connection reuse; the class's lazy
client cache never survives), and `LocalAudioStore.__init__` runs
`mkdir` per request. Cache the store on `app.state` (invalidate on
settings swap, per the live-settings discipline).

**M10. The as-left `web/dist` fails the suite.** The session built dist
bypassing `add-sri.mjs` (which itself currently aborts fail-closed on
the `security.txt` placeholders — so `npm run build` is red too). Any
CI or teammate running `npm test` on this tree gets 1 failure. Rebuild
dist properly (after filling security.txt or consciously gating) or
remove dist from the working tree.

---

## 6. Findings — LOW / INFO (abridged)

- Dead ternary `playing ? t("history.playRecording") :
  t("history.playRecording")` (`History.tsx:570`); no stop-state
  affordance on web playback.
- Toggle-anywhere semantics: playing A and pressing B only stops A
  (web `History.tsx:113-119`, mobile `HistoryScreen.tsx:272-275`);
  `removeRecording` stops playback even for unrelated deletions.
- Three dead i18n keys (`history.recordingExpires`,
  `settings.voiceTitle`, `share.voiceTitle`) — the title keys suggest
  the Settings/Share section headers were planned but the sections use
  inline headers.
- No `onerror` on MediaRecorder or any `<audio>` element; `finalize()`
  calls `recorder.stop()` unguarded before `teardown()`.
- `keepAudio` defaults to **true** (opt-out retention) — debatable for
  a privacy-critical app.
- Transient `meta()` failure permanently disables voice for the view's
  lifetime; object URL minted inside `useMemo` (side effect in render).
- `S3AudioStore.get` reads without any size bound (own-bucket trust);
  entry-delete cascade deletes the object before the transaction
  commits (a later commit failure leaves a row without its object —
  502-on-fetch, not a leak).
- `_LANG_CODE_RE` duplicates `LANGUAGE_CODE_PATTERN` from schemas;
  `__import__("re")` inline in `insights.py`; `normalize_language`
  accepts any 2-alpha pair ("zz").
- Commit-message numbers wrong ("backend 685" vs ~1,698 actual;
  "expo/exop-audio" typo); sub-agent counted the full suite green in
  isolation.
- Un-localized error strings reach users (`TamperError` detail,
  ApiError detail) on web/portal.
- `toBase64` per-char string concat on multi-MB audio (main-thread
  cost, tolerable via V8 ropes).

---

## 7. Recommended remediation order

1. **Mobile C1–C5** before any release build: wire expo autolinking
   (`use_expo_modules!` / `useExpoModules`), declare mic permissions on
   both platforms, call `prepareToRecordAsync()` before `record()`,
   fix the recording options to the pinned codec contract (AAC/m4a
   enums), and ship the mobile Settings/Share toggles the copy already
   references. Replace the inert mocks (correct API names, filesystem
   star-import shape) and add one lifecycle-shaped test
   (start → auto-stop → take → discard).
2. **Web H1–H3**: invert the unmount effect, key History playback to
   the playing entry id, and give transcription its own (longer,
   retryable) deadline.
3. **H4 consent scope**: gate `translate_to_english` on
   `llm.consent_is_current` (or extend the voice disclosure +
   fingerprint to cover the LLM translation endpoint).
4. **H5**: implement and wire `g_voice.py` into `run_all.sh`, or delete
   the artifact and stop claiming the gate.
5. M1/M2 (flag coverage of the therapist route + share-voice toggle;
   erasure object cleanup), M3 (real audio vectors incl. the
   string-typed version), M4 (MinIO endpoint override + first S3 store
   tests), M5–M10 as batched follow-ups.
6. Rebuild `web/dist` through the real pipeline (and resolve the
   `security.txt` placeholder gate) so `npm test` is green on the tree
   as left.

— Independent auditor, 2026-09-29

---

## 8. Remediation record (same day, ordered by the audit report's §7)

| Finding | Fix | Verified by |
|---|---|---|
| C1 expo autolinking | `use_expo_modules!` (Podfile) + `useExpoModules` (settings.gradle) wired | mobile agent (native build itself requires pod install on a device host) |
| C2 mic permissions | `NSMicrophoneUsageDescription` + `RECORD_AUDIO` declared | mobile agent |
| C3 recorder no-op | `prepareToRecordAsync()` before `record()` | mobile agent + lifecycle tests |
| C4 invalid options | real expo-audio 57 option shapes (string enums; AAC/m4a) | mobile agent + typecheck |
| C5 consent dead-end | mobile Settings voice-consent section + Share share-voice toggle (en/es) | mobile agent |
| H1 unmount teardown | cleanup/body inverted back; handlers detached before track stop | web agent + recorder tests |
| H2 multi-<audio> | playback keyed to the playing attachment id; B-press switches | web agent + gating test |
| H3 15s deadline | `VOICE_REQUEST_TIMEOUT_MS` (180 s) for transcribe/upload | web agent + pin test |
| H4 consent scope | `stt.translation_dispatch_allowed` gates both routes on current llm consent; privacy copy discloses | backend tests + G-VOICE.V-11 |
| H5 docstring campaign | executable `g_voice.py` (9 verdicts, all BLOCKED) wired into `run_all.sh` | campaign run |
| H6 vacuous tests | real API-name mocks + recorder-lifecycle/flow/gating/vector tests on all clients | all suites |
| M1 flag gaps | therapist audio route + share-voice toggle flag-checked in-body (wall order preserved) | backend tests + G-VOICE.V-1 |
| M2 erasure orphans | account deletion best-effort-deletes objects first | `test_account_erasure_removes_audio_objects` |
| M3 no vectors | deterministic crypto_vectors in shared/audio_vectors.json; web/mobile byte-equality, portal decrypt-side | web/mobile tests |
| M4 MinIO/boto3 | `MINDPATTERN_AUDIO_S3_ENDPOINT` + path-style; dev overlay wired; fake-client S3 tests | `test_s3_store_*` |
| M5/M6/M7 client defects | recorder/flow/playback/portal fixes per §5-6 | web+portal agents |
| M8 docs/deploy drift | nginx 8m audio location; plan numbers; retry + `MINDPATTERN_STT_TIMEOUT_SECONDS`; DPIA/threat-model addenda | docs + retry tests |
| M9 per-request clients | cached store per configuration | `test_cached_store_reuses_instance_per_configuration` |
| M10 stale dist | unstamped `web/dist` deleted (SRI gate now runs only on a real build; the security.txt placeholder gate remains an operator to-do) | web suite |
| LOW items | dead ternary, i18n keys used, onerror handlers, keepAudio default false, capped S3 read, import hygiene | respective suites |

Re-verification: backend suite green (incl. 13 new remediation tests);
g_voice campaign 9/9 BLOCKED; ruff clean. Web/mobile/portal suites
re-run after the frontend waves — see the final delivery note.
