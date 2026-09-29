# MindPattern — Voice Journaling Build Plan (record → Whisper → patterns)

> **Status: BUILD COMPLETE 2026-09-29 — P0–P6 delivered. Backend 685
> tests green (including 38 new voice tests); web 691 green (16 new);
> mobile 1,973 green (8 new); portal 459 green. Contracts pinned by
> shared/audio_vectors.json. Remaining operator/deployment gates (not
> code): `pod install` before the next mobile iOS build; production
> needs MINDPATTERN_AUDIO_ENABLED + an STT provider config + the S3
> bucket with its 31-day lifecycle backstop; real-provider smoke test of
> stt.py against the live endpoint (the suite pins the wire shape via the
> `_post_audio` seam). All changes are uncommitted in the working tree.**

## Goal

A patient can press a microphone button on the Entry screen (web **and**
mobile), speak in **any language** for up to **5 minutes**, and get back a
transcript they can review and edit before saving. The pipeline:

1. **Record** on-device (web: `MediaRecorder`; mobile: `expo-audio`).
2. **Transcribe + language-detect** via an OpenAI Whisper-compatible
   `/audio/transcriptions` endpoint (server-side, consent-gated, audio
   plaintext transits server memory only and is **never persisted**).
3. **Translate** the transcript text to English (reusing the existing
   OpenAI-compatible LLM client in `backend/app/services/llm.py`) so the
   US-based therapist can read any language.
4. **Review/edit** the transcript client-side (original language shown,
   English translation preview), crisis scan runs on the final text exactly
   as for typed entries, then the normal `encryptEntry` flow stores it as
   entry payload **v3** (`transcript_lang`, `english_text`, `input_mode`).
5. **Patterns** run as today, routed by detected language: `en`/`es` use
   native lexicons; every other language is analyzed on `english_text`.
6. **Kept recordings** (default ON, toggleable per recording) are
   AES-GCM-encrypted **on the device** and stored in **S3** as opaque
   attachments that **expire after 30 days**; the patient can replay them
   anywhere, and the therapist can hear the actual voice **only if** the
   patient turned on the per-patient **share-voice consent flag**
   (default off, every access audit-logged).

The zero-knowledge contract is preserved end-to-end: the server stores only
ciphertext (entries, insights, audio attachments) plus non-content metadata,
and only ever holds plaintext during the consent-gated, TTL-bounded
transcription call — the same egress discipline as the LLM enrichment path
(`backend/app/services/llm.py`).

## Locked decisions (2026-09-29)

| ID | Decision | Rationale / consequence |
|---|---|---|
| D-1 | **STT = OpenAI Whisper-compatible API**, server-side, via a new `stt.py` service mirroring `llm.py` guards | Client-direct calls would leak API keys. `MINDPATTERN_STT_*` env vars point at OpenAI by default (`https://api.openai.com/v1`, model `whisper-1`) but any OpenAI-compatible provider works. `gpt-4o-mini-transcribe` ($0.003/min, more accurate) is a config flip, not a code change. |
| D-2 | **Transcription is consent-gated and ephemeral** | Raw audio to a third party is materially different PHI exposure than text. New consent kind `voice_transcription` with its own disclosure version (GDPR Art. 7 record, `consents.py` pattern). Audio bytes live in server memory for the duration of one upstream call — never written to disk, S3, logs, or the LLM enrichment input. |
| D-3 | **Kept recordings: client-side encrypted, stored in S3, expire in 30 days; default ON with per-recording toggle** | User wants replay ("what if the user wants to play the audio?"). Encryption on-device with the patient data key keeps the server zero-knowledge; 30-day expiry caps storage (~27 MB steady state per daily user) and is the defensible voice-PHI retention story: *transcript is the durable record, audio is a 30-day convenience*. Toggle lives in the review sheet + a default in Settings. |
| D-4 | **Therapist voice access is a per-patient consent flag, default OFF, audit-logged** | Hearing tone/affect is clinically valuable but is the most identifying PHI in the system. The flag extends the existing therapist sharing consent; the portal audio endpoint hard-enforces it and writes an access-log row on every fetch (existing `therapist.py` access-log pattern). |
| D-5 | **5-minute max recording**, compressed mono speech codecs (~24 kbps) | Matches journaling cadence, keeps uploads ~900 KB (≈1.2 MB base64), well under the raised audio body cap. Client auto-stops at 5:00; server validates claimed duration ≤ 310 s and enforces the size cap (it cannot verify true duration without decoding — documented trust boundary, size cap is the backstop). |
| D-6 | **Language flow: STT auto-detects (no separate detection call) → original transcript → English translation from *text* via the existing LLM client** | `whisper-1`/`gpt-4o-transcribe` return the detected language with the transcript (one call, one audio fee). `/audio/translations` (second per-minute audio fee, whisper-1-only) is **not** used; translating the text via `llm.py` costs pennies and reuses existing consent plumbing. |
| D-7 | **Pattern routing: `en`/`es` native lexicons, everything else analyzes `english_text`** | Brain engine (`brain.py`) is already language-gated EN+ES. Analyzing the English translation gives "any language" pattern support without curating lexicons per language. Fallback to original text (EN pipeline) if translation is unavailable. |
| D-8 | **S3 primary storage; local-filesystem fallback when unconfigured; MinIO in dev compose** | Mirrors the repo's "disabled/fallback when unconfigured" philosophy (`get_enricher()` returns `None`). Self-hosters without S3 get a working feature via `MINDPATTERN_AUDIO_LOCAL_DIR`; dev parity via MinIO in `docker-compose.dev.yml`. |

**Out of scope (explicit, v1):** offline queueing of audio uploads
(transcription already requires connectivity; a failed upload drops the
audio with a notice while the entry survives); speaker diarization;
server-side duration verification (ffprobe); re-transcription of stored
audio after expiry; audio in the GDPR export bundle (transcript is the
portable record — revisited in O-3); web push-to-talk during backgrounded
tabs; transcript confidence scores.

## User experience

**Patient — recording (web `Entry.tsx` / mobile `EntryScreen.tsx):**
mic button next to the existing text editor → permission prompt (first
time) → recording state with elapsed timer, live level meter, stop button,
auto-stop at 5:00 → **review sheet**: playback of the recording, editable
transcript pre-filled with `original_text` and a language badge
(`🇪🇸 Español` etc.), collapsible English translation preview, per-recording
"Keep recording for 30 days" toggle, Save / Discard. Saving runs the
existing crisis scan on the final text, encrypts as payload v3, creates the
entry, then uploads the encrypted audio attachment if kept (best-effort,
3 in-session retries; on final failure the entry stands and the user is
told the recording wasn't kept).

**Patient — playback (`History.tsx` / `HistoryScreen.tsx`):** voice entries
show a play button and a "recording expires in Nd" label; tapping fetches
the encrypted blob, decrypts in memory, plays, revokes the object URL.
Patients can also delete just the recording (entry stays).

**Patient — consent & settings:** first mic press surfaces the
voice-transcription disclosure (provider name, "deleted immediately after
transcription, only encrypted text is stored", policy version) with
Allow / Not now; Settings holds the default for keep-recording and
consent revoke. The Share screen gains the "let my therapist hear my
recordings" toggle (default off).

**Therapist — portal (`PatientView.tsx`):** entries list shows the English
translation by default with a "show original" toggle for non-English
entries; a play button on entries that have unexpired audio *and* a
share-voice grant. Every play streams through the audited endpoint.

## Architecture

```
 Patient device (web / mobile)
 ┌────────────────────────────────────────────────────────────────┐
 │ Entry screen: text editor + 🎤 mic                              │
 │   record (MediaRecorder | expo-audio) ≤ 5 min, ~24 kbps mono    │
 │   review: playback ▸ editable transcript ▸ keep-toggle          │
 │                                                                 │
 │ crypto: encryptEntry v3 {text, sentiment, …, transcript_lang,   │
 │        english_text, input_mode}                                │
 │        encryptAudio AAD ("audio", userId, clientEntryId, 1)     │
 │        → nonce‖ct‖tag, base64                                    │
 └──────┬───────────────────────────────┬─────────────────────────┘
        │ ① POST /audio/transcriptions │ ② POST /entries (v3 blob,
        │    audio_b64 (plaintext,      │    as today, unchanged)
        │    never persisted)           │ ③ POST /audio/attachments
        ▼                               ▼   (encrypted audio_b64)
 ┌─────────────────────────────────────────────────────────────────┐
 │ FastAPI backend — new api/audio.py in _module_routers            │
 │  /audio/transcriptions: consent-gated → stt.py (httpx, https-    │
 │    only, timeout, 1 MiB resp cap) → OpenAI-compatible            │
 │    /audio/transcriptions ⇒ {text, language} → llm.py translate   │
 │    ⇒ {original_text, language, english_text}; audio discarded    │
 │  /audio/attachments{,/{id}}: quota, upsert, lazy expiry          │
 │  sweeper task: every 15 min delete expired rows + objects        │
 │  therapist.py: /patients/{id}/audio/{att} — share_voice flag +   │
 │    audit-log row, returns encrypted blob                         │
 └──────┬────────────────────────────────────┬────────────────────┘
        │ aioboto3 (SSE-S3 at rest)          │ opaque blobs only
        ▼                                    ▼
 ┌───────────────┐                    ┌──────────────────────────┐
 │ S3 bucket     │                    │ Postgres (audio_attach-  │
 │ audio/{uid}/… │◀── delete ─────────│ ments rows, metadata +   │
 │ .enc objects  │    sweeper/31d     │ expires_at; entries,     │
 └───────────────┘    lifecycle       │ consents — unchanged     │
                                        └──────────────────────────┘
 Therapist portal: unwraps patient data key (existing consent grant),
 decrypts entry v3 + (only if share_voice) audio, plays via <audio>.
```

## The voice contract (what all four codebases implement)

Same discipline as the multi-device sync contract in `WEB_PLAN.md` — one
table, pinned by `shared/audio_vectors.json` (P0), enforced by tests on
every side.

| # | Area | Contract |
|---|---|---|
| V-1 | Formats | Web records `audio/webm;codecs=opus` → `audio/webm` → `audio/ogg;codecs=opus` → `audio/mp4` (first that `MediaRecorder.isTypeSupported` accepts; Safari only reliably does mp4/AAC). Mobile records m4a/AAC 16 kHz mono ~24 kbps. File extension is always derived from the *actual* winning mime (the .webm-named-MP4 bug). Server mime allowlist: `audio/webm`, `audio/mp4`, `audio/m4a`, `audio/x-m4a`, `audio/ogg`, `audio/mpeg`, `audio/wav`. |
| V-2 | Duration & size | Client auto-stops at 300 s; requests carry `duration_seconds` (≤ 310 server-validated) and the audio route has its own body cap (`MINDPATTERN_AUDIO_MAX_BODY_BYTES`, default 12 MiB) replacing the global 2 MiB on `/api/{v1,}/audio` paths only. |
| V-3 | Transcription request/response | `POST /audio/transcriptions {audio_b64, mime, duration_seconds}` → `200 {original_text, language (ISO 639-1), language_raw (provider string), english_text|null, provider_name, policy_version}`. Stateless; audio bytes never persisted. Errors: `403 voice_consent_required`, `413 audio_too_large`, `503 stt_unconfigured`, `502 stt_upstream`, a flat `404 not_found` when the flag is off (the shared vectors' `feature_flag` note). |
| V-4 | Entry payload v3 | `{text, sentiment, created_at, energy, sleep, tags, tod}` + `transcript_lang` (ISO 639-1 or absent), `english_text` (string or null), `input_mode: "typed"|"voice"`. Decryptors accept v1/v2/v3 (missing fields default to typed behavior). `english_text` always matches the *saved* text: if the patient edits the transcript, the client re-translates via `POST /audio/translations {text, source_lang}` before saving. |
| V-5 | Audio blob crypto | Same patient data key as entries, AES-256-GCM, AAD `("audio", userId, clientEntryId, 1)`, serialized `nonce‖ct‖tag` base64 in JSON. AAD binding makes cross-entry swaps and cross-user grafts fail closed. Implemented once per client: `web/src/crypto/patient.ts`, `mobile/src/crypto/MindPatternCrypto.ts`, `portal/src/crypto.ts` (decrypt only). |
| V-6 | Attachment lifecycle | Max one attachment per entry (`user_id`+`client_entry_id` unique); re-upload is an upsert that deletes the previous S3 object first. `expires_at = created_at + MINDPATTERN_AUDIO_RETENTION_DAYS` (30). Deletion cascades: entry delete, audio delete, account erasure, and expiry sweeper all remove row + object. Lazy expiry check on every fetch → `410 audio_expired`. |
| V-7 | Playback | Fetch encrypted blob → decrypt in memory → object URL → play → revoke. Never cached at rest by any client; portal included. |
| V-8 | Offline | Voice requires connectivity (mic disabled offline). Attachment upload is best-effort in-session retry; on failure the entry persists and the user is told the recording wasn't kept. No offline audio queueing in v1 (O-5). |
| V-9 | Crisis scan | Runs on the final (possibly edited) transcript text client-side pre-encryption, identical to typed entries (`web/src/views/Entry.tsx` line ~157 path). |
| V-10 | Consents | Two independent gates: `voice_transcription` consent kind (own disclosure + `MINDPATTERN_STT_POLICY_VERSION`, re-consent on bump) gating all `/audio/*` patient routes; `share_voice` boolean scope on the existing therapist sharing consent gating the portal audio endpoint (default false, patient-toggled, audit-logged per access). |
| V-11 | Feature flag | `MINDPATTERN_AUDIO_ENABLED` (default **false in production, true in development** → all `/audio` routes answer a flat 404 `not_found` — the repo's `require_sharing_enabled` convention, see shared/audio_vectors.json error_codes.feature_flag), same fail-closed pattern as `require_sharing_enabled` (`backend/app/deps.py:220`). Clients learn availability from the existing meta/config surface. |
| V-12 | Language codes | Provider language strings ("spanish") normalize to ISO 639-1 (`es`) via a pinned map; unknown → `language_raw` kept, routing falls back to English-translation analysis. |

## Data-flow sequences

**Transcribe (online, consented):**
`record → stop → POST /audio/transcriptions (audio_b64) → server: consent
check → stt.transcribe() → llm.translate() → {original_text, language,
english_text} → audio bytes dropped → client review sheet`.

**Save with kept audio:**
`review/edit → (if edited) POST /audio/translations → crisis scan →
encryptEntry v3 → POST /entries → encryptAudio → POST
/audio/attachments → {attachment_id, expires_at}`.

**Patient playback (any later day ≤ 30):**
`History play → GET /audio/attachments/{id} → decryptAudio → play`.

**Therapist playback:**
`PatientView play → GET /therapist/patients/{pid}/audio/{att} → server:
require_therapist + active consent w/ share_voice → audit row → encrypted
blob → portal unwrap key → decryptAudio → play`.

**Expiry sweep (every 15 min):**
`SELECT audio_attachments WHERE expires_at < now() LIMIT 500 → delete S3
objects (parallel) → delete rows → log count`. Optional S3-native 31-day
lifecycle rule on the bucket as a belt-and-braces backstop (the app
sweeper stays authoritative so DB and storage stay in sync).

## Backend specification

### Configuration (`backend/app/config.py`, follows `_secret_env` + `_FILE` variant convention)

| Env var | Default | Purpose |
|---|---|---|
| `MINDPATTERN_AUDIO_ENABLED` | `false` | Fail-closed feature flag (V-11) |
| `MINDPATTERN_STT_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL |
| `MINDPATTERN_STT_API_KEY` (+`_FILE`) | unset → STT off | Provider key; unconfigured ⇒ `503 stt_unconfigured` |
| `MINDPATTERN_STT_MODEL` | `whisper-1` | `gpt-4o-mini-transcribe` is a flip (O-2) |
| `MINDPATTERN_STT_PROVIDER_NAME` | `OpenAI` | Disclosure copy / consent record |
| `MINDPATTERN_STT_DATA_RETENTION` | provider default | Disclosure copy |
| `MINDPATTERN_STT_POLICY_VERSION` | `1` | Consent disclosure version |
| `MINDPATTERN_STT_TIMEOUT_SECONDS` | `60` | Upstream call budget |
| `MINDPATTERN_AUDIO_MAX_BODY_BYTES` | `12582912` (12 MiB) | Route-scoped body cap for `/audio` |
| `MINDPATTERN_AUDIO_MAX_DURATION_SECONDS` | `310` | Claimed-duration bound |
| `MINDPATTERN_AUDIO_RETENTION_DAYS` | `30` | `expires_at` delta |
| `MINDPATTERN_AUDIO_MAX_USER_BYTES` | `67108864` (64 MiB) | Live (unexpired) attachment quota |
| `MINDPATTERN_AUDIO_BUCKET` / `_REGION` | unset → local mode | S3 target |
| `MINDPATTERN_AWS_ACCESS_KEY_ID` / `_SECRET_ACCESS_KEY` (+`_FILE`) | unset | Least-privilege IAM creds (put/get/delete on `bucket/audio/*` only) |
| `MINDPATTERN_AUDIO_LOCAL_DIR` | `./data/audio` | Filesystem fallback store (dev/self-host) |
| `MINDPATTERN_AUDIO_SWEEP_INTERVAL_SECONDS` | `900` | Sweeper cadence |
| `MINDPATTERN_RATE_AUDIO_TRANSCRIBE` / `_WINDOW` | e.g. `10` / `3600` | Rate bucket for transcription (cost-abuse bound) |
| `MINDPATTERN_RATE_AUDIO_UPLOAD` / `_WINDOW` | e.g. `30` / `3600` | Rate bucket for uploads |

### `backend/app/services/stt.py` (new — mirrors `llm.py` discipline)

- `class SpeechToText` + `get_stt()` factory returning `None` when
  unconfigured (off by default, no import-time key reads).
- `async transcribe(audio: bytes, mime: str) -> TranscriptionResult` —
  httpx multipart POST to `{STT_URL}/audio/transcriptions`; `whisper-1` ⇒
  `response_format=verbose_json`, `gpt-4o-*` ⇒ `json` (both return
  `language`); guards: `https://` enforced, total timeout, **1 MiB response
  cap**, one retry with backoff on 429/5xx, upstream error bodies never
  echoed to clients (mapped to `502 stt_upstream`).
- `async translate(text: str, source_lang: str) -> str | None` — thin
  wrapper reusing `llm.py`'s `_post_async` plumbing with a deterministic
  system prompt, `temperature 0.0`, token budget sized to input; `None`
  when the LLM client is unconfigured (degraded mode: portal shows original
  text + "translation unavailable").

### `backend/app/services/audio_store.py` (new)

- `AudioStore` protocol: `put/get/delete/exists(key, …)`; implementations
  `S3AudioStore` (aioboto3, `PutObject` with `ServerSideEncryption=AES256`
  as defense-in-depth under the client-side AES-GCM) and `LocalAudioStore`
  (filesystem, dev/self-host). `get_audio_store()` factory picks by config.
- Keys are **always server-generated**: `audio/{user_id}/{uuid4().hex}.enc`
  — `client_entry_id` is UUID-validated and never used in a path.

### `backend/app/models.py` + Alembic migration (new)

```
audio_attachments
  id            UUID PK
  user_id       FK users, indexed
  client_entry_id  str  (matches entries.client_entry_id; UNIQUE with user_id)
  backend       str  ("s3" | "local")
  s3_key        str
  size_bytes    int
  mime_type     str
  duration_seconds  int   (client-declared, advisory)
  content_version    int   (audio crypto version = 1)
  created_at    timestamptz
  expires_at    timestamptz, indexed (sweeper + lazy checks)
```

Consent extension: `share_voice` boolean (default false) on the sharing
consent per the existing `Consent` schema style (`models.py:299`); surfaced
in the consent grant the portal already consumes, so the portal can hide
the play button without an extra round-trip.

### `backend/app/api/audio.py` (new router, added to `_module_routers` → `/api/v1/audio` + legacy `/api/audio`)

All routes: `Depends(require_regular_user)`, feature-flag dependency
(flat 404 when off), rate-limited, flat `{"detail", "code"}`
error envelope (`ApiError`), per-user lifecycle locks on writes.

1. `POST /audio/transcriptions` — consent check (`voice_transcription`,
   else `403 voice_consent_required`) → mime allowlist → b64 decode +
   size cap (`413 audio_too_large`) → duration bound → `stt.transcribe` →
   `stt.translate` → response per V-3. **Audio bytes are function-local
   and dropped on return — no disk, no S3, no logs.**
2. `POST /audio/translations` — `{text, source_lang}` → `stt.translate`
   → `{english_text}`; same consent + rate bucket; caps input at the
   entry-text size limit. Used when the patient edits a transcript (V-4).
3. `POST /audio/attachments` — `{client_entry_id, blob, mime,
   duration_seconds}` → entry must exist (else `404 unknown_entry`) →
   quota check over live attachments (`413 audio_quota_exceeded`) →
   upsert (delete previous object first) → store via `AudioStore` →
   `{attachment_id, expires_at, size_bytes}`.
4. `GET /audio/attachments/{id}` — owner-only (other user ⇒ `404`) →
   lazy expiry (`410 audio_expired` + delete) → encrypted blob b64.
5. `DELETE /audio/attachments/{id}` — owner-only; row + object deleted;
   entry survives.

Entries listing integration (patient `GET /entries` pages and portal
`GET /therapist/patients/{id}/entries`): join `audio_attachments` to add
`audio: {has_audio, expires_at}` metadata — server-side join, no
decryption involved.

### `backend/app/api/therapist.py` (extension)

`GET /therapist/patients/{pid}/audio/{attachment_id}` —
`require_therapist` + active consent **with `share_voice=true`** (else
`403 consent_voice_share_required`; revoked/expired consent ⇒ same) →
write an access-log row (existing audit pattern, `therapist.py:523`
family, new kind `audio_access`) → return encrypted blob b64. The portal
never learns the plaintext; it decrypts client-side as it does for
entries.

### Sweeper (lifespan task in `main.py` `create_app()`)

Every `MINDPATTERN_AUDIO_SWEEP_INTERVAL_SECONDS`: select expired rows in
batches (500), delete S3/local objects in parallel, then rows; failures
logged and retried next cycle (row deletion only after object deletion
succeeds — orphaned objects are picked up by the optional 31-day S3
lifecycle backstop, orphaned rows can't happen).

### HardeningMiddleware (`main.py:648`) + nginx

`/api/v1/audio` and `/api/audio` paths switch from the global
`MINDPATTERN_MAX_BODY_BYTES` (2 MiB) to `MINDPATTERN_AUDIO_MAX_BODY_BYTES`
(12 MiB); every other route keeps the 2 MiB posture. `deploy/nginx`
raises `client_max_body_size` for the audio location to match.

## Client implementation

### Web (`web/`)

- `src/audio/recorder.ts` — `useRecorder` hook: `getUserMedia({audio})`,
  mime fallback chain (V-1), chunk collection, elapsed timer, optional
  `AnalyserNode` level meter, hard 300 s auto-stop, full teardown on
  unmount (stream tracks stopped, recorder state cleared).
- `src/audio/player.ts` — `playAttachment(id)`: fetch → `decryptAudio` →
  object URL → `HTMLAudioElement` → revoke on ended/error.
- `src/crypto/patient.ts` — `encryptAudio`/`decryptAudio` (V-5) beside the
  existing `encryptEntry`; payload **v3** branch in encrypt + v1/v2/v3 in
  decrypt (V-4). New vectors pinned from `shared/audio_vectors.json`.
- `src/api/client.ts` — `transcribeAudio`, translateText,
  `uploadAudioAttachment`, `fetchAudioAttachment`, `deleteAudioAttachment`;
  canonical `/api/v1` only.
- `src/views/Entry.tsx` — mic button (disabled offline / when flag off),
  recording UI, review sheet (playback, editable transcript + language
  badge, translation preview, keep-toggle default from Settings),
  crisis scan on final text, then entry save + optional attachment upload.
- `src/views/History.tsx` — play button + "expires in Nd" on entries with
  audio; delete-recording action.
- `src/views/Settings.tsx` — keep-recording default; voice consent
  grant/revoke (calls the existing consent endpoints).
- `src/views/Share.tsx` — "let my therapist hear my recordings" toggle
  (share-voice scope).
- `src/locales/{en,es}.ts` + `strings.ts` — all new copy in both languages.

### Mobile (`mobile/`)

- `expo-audio` (works in bare RN: adds `expo` + `expo-audio`, autolinking,
  `pod install`; it is the maintained successor of the deprecated
  `react-native-audio-recorder-player`). Records m4a/AAC, 16 kHz mono
  ~24 kbps; `requestMicrophonePermissionsAsync()` for the runtime prompt.
  Manifest/Info.plist: `RECORD_AUDIO` + a patient-facing
  `NSMicrophoneUsageDescription`; recording starts foreground-only
  (Android while-in-use rule) — backgrounding mid-recording stops and
  keeps the partial take for review.
- `src/nativeFeatures.ts` — recorder behind the existing dynamic-import
  capability pattern so the app degrades gracefully if the native module
  is unavailable.
- `src/crypto/MindPatternCrypto.ts` — `encryptAudio`/`decryptAudio` + v3
  payload (same vectors as web).
- `src/screens/EntryScreen.tsx` / `HistoryScreen.tsx` /
  `SettingsScreen.tsx` / `TherapistShareScreen.tsx` — same UX as web;
  playback + recording via expo-audio's player/recorder APIs.
- `src/locales/{en,es}.ts` — mirrored strings.

### Portal (`portal/`)

- `src/crypto.ts` — `decryptAudio` beside `unwrapPatientDataKey`
  (`portal/src/crypto.ts:185`).
- `src/views/PatientView.tsx` — non-English entries render `english_text`
  first with a "show original" toggle; play button only when the consent
  grant carries `share_voice` **and** the entry has unexpired audio;
  playback per V-7 (no at-rest caching, object URL revoked).
- `src/views/PatientsView.tsx` — share-voice status indicator in the
  patient roster.

### Brain / insights routing (`backend/app/services/brain.py`)

In the processing-session recompute worker: payload v3 entries route by
`transcript_lang` — `es` ⇒ ES lexicons on `text` (existing path);
`en`/absent ⇒ EN lexicons on `text`; any other code ⇒ EN lexicons on
`english_text` (fallback `text`). `state["language"]` accounting
(`brain.py:5206`) and daily-question rendering (`questions.py`
`render_pattern_questions`) unchanged — language still flows from state.
Client-side quick mood estimate (`web/src/mood.ts`, mobile twin) runs on
the transcript text unchanged. LLM enrichment keeps reading decrypted
`text` only — audio never enters enrichment input.

## Privacy, consent & disclosure

- New consent kind **`voice_transcription`** (disclosure version =
  `MINDPATTERN_STT_POLICY_VERSION`; recorded via the existing
  `consents.py` / `account.py` GDPR Art. 7 machinery). Disclosure copy
  (drafted in P6, surfaced at first mic press + Settings): *"Your
  recording is sent to {provider} to be transcribed, is deleted
  immediately after transcription, and only encrypted text is stored on
  our servers. Recordings you keep are stored encrypted for 30 days."*
- **`share_voice`** scope on the sharing consent — patient-toggled in
  Share/TherapistShare screens, default off, enforced server-side on the
  portal audio route, audit-logged per access.
- Docs to update in P6: `docs/DATA_RETENTION_SCHEDULE.md` (audio 30-day
  row), `docs/SUBPROCESSOR_BAA_REGISTER.md` (STT provider + S3 rows),
  `docs/DPIA_SKELETON.md` and `docs/PRIVACY_POLICY_TEMPLATE.md` (voice
  section), `docs/WEB_THREAT_MODEL.md` (audio attack surface).

## Security / red-team checklist (new campaign in `redteam/`)

1. IDOR on attachment fetch/DELETE (user A vs user B ⇒ 404).
2. Therapist audio route: no consent / flag off / revoked / expired ⇒ 403;
   every allowed access writes an `audio_access` audit row.
3. Body-cap bypass: oversized `/audio` payloads ⇒ 413; non-audio routes
   still 2 MiB; `Content-Length` spoofing; chunked encoding.
4. `client_entry_id` path/key injection (UUID validation before any
   storage key derivation).
5. Mime allowlist enforcement + extension derived server-side from
   validated mime.
6. Rate-limit abuse of transcription (cost attacks) — per-user bucket
   plus flag-off kill switch.
7. Upstream error-body leakage (never echoed), `https://` only, timeout +
   response-cap enforcement on the STT call.
8. Expiry bypass via clock skew / stale reads (server clock authoritative,
   lazy check on every fetch).
9. Audio blob tampering / cross-entry / cross-user graft — AAD binding
   fails closed (pinned cross-client vectors).
10. Sweeper resilience: S3 delete failure must not orphan rows; entry
    delete / account erasure removes audio (GDPR erasure drill).
11. Portal: no at-rest caching of decrypted audio; object URL lifecycle.
12. Plaintext audio never reaches logs, metrics, enrichment input, or
    storage at any layer (grep + runtime assertion in tests).

## Testing plan (repo style: vector-pinned, adversarial)

- **P0 vectors:** `shared/audio_vectors.json` — payload v3 encrypt/decrypt
  fixtures (incl. v1/v2 back-compat), `encryptAudio` AAD fixtures (wrong
  user / wrong entry / wrong version must fail), language normalization
  table, mime→extension map. All four clients pinned to it.
- **Backend pytest:** stt client against a mocked httpx transport
  (whisper-1 verbose_json + gpt-4o json shapes, 429 retry, response-cap
  trip); translate fallback-None; consent gates (incl. bypass attempts);
  mime/size/duration validation; quota math; upsert deletes prior object;
  lazy expiry; sweeper with frozen clock; deletion cascades (entry,
  account erasure); therapist flag enforcement + audit rows; IDOR; error
  envelope codes; flag-off 404; entries-listing audio metadata. S3 store
  tested against MinIO (dev compose), LocalAudioStore against a temp dir.
- **Web vitest:** `useRecorder` with a MediaRecorder mock (fallback-chain
  order, 5-min auto-stop, teardown); v3 crypto round-trip + back-compat
  vectors; review-sheet state machine (edit ⇒ re-translate call);
  history playback (mocked audio element); crisis scan on transcript;
  offline mic disabled; jest-axe on the new sheets. Stryker on crypto v3
  + recorder state machine.
- **Mobile:** jest units for crypto v3 + api client; native manual matrix
  (permission denied / revoked mid-flow, call interruption, backgrounding,
  iOS + Android emulators).
- **E2E (`e2e_gui`):** stubbed-STT happy path record → transcribe →
  review → save → history playback; therapist portal playback with flag
  on/off; 30-day-expiry drill (clock-shifted fixture).

## Phases & gates

| Phase | Scope | Gate |
|---|---|---|
| **P0** Contracts | `shared/audio_vectors.json` schema + fixtures; freeze env names, error codes, payload v3, AAD tuple | Vector file reviewed; contract table above final |
| **P1** Backend STT | `stt.py`, `/audio/transcriptions` + `/audio/translations`, `voice_transcription` consent, route-scoped body cap, flag | pytest suite green incl. consent-bypass + cap-bypass tests; manual curl against real OpenAI key (optional, env-gated) |
| **P2** Backend storage | models + migration, `audio_store.py`, attachment endpoints, entries-listing join, sweeper, therapist audio route + audit, MinIO dev service | storage/expiry/IDOR/quota/erasure suites green; docker-compose.dev MinIO round-trip |
| **P3** Web | recorder + player hooks, v3 crypto, Entry/History/Settings/Share UI, i18n, offline gating | vitest + Stryker green on new code; jest-axe; browser matrix (Chrome/Firefox/Safari incl. iOS Safari mime chain) |
| **P4** Mobile | expo-audio integration, nativeFeatures wrapper, v3 crypto, screens, permissions, i18n | iOS simulator + Android emulator manual matrix; jest green |
| **P5** Portal + brain | portal decrypt/play + translation toggle, `brain.py` v3 routing re-pinned, insights E2E with voice fixtures | portal playback with flag on/off verified; brain vector tests re-pinned green |
| **P6** Hardening & docs | redteam campaign, threat-model + retention/subprocessor/DPIA/privacy updates, disclosure copy, load test on transcription path, README/CHANGELOG | redteam findings triaged to zero highs; docs merged |

Rough effort: P1 2–3 d, P2 3–4 d, P3 3–4 d, P4 3–4 d, P5 2–3 d, P6 2 d
≈ **15–20 focused days** end to end.

## Deployment notes

- Bucket: dedicated, SSE-S3 default encryption, optional 31-day lifecycle
  rule (backstop only), IAM creds limited to
  `s3:PutObject|GetObject|DeleteObject` on `bucket/audio/*`.
- `docker-compose.dev.yml`: add MinIO service + env wiring
  (`MINDPATTERN_AUDIO_BUCKET`, endpoint override for local testing).
- `deploy/nginx`: `client_max_body_size 12m;` scoped to the `/api/` audio
  locations.
- Dark-launch order: merge P1–P2 with `MINDPATTERN_AUDIO_ENABLED=false`
  → flip flag for internal accounts → full enable after P6.

## Cost model (steady state)

- STT: `whisper-1` $0.006/min (`gpt-4o-mini-transcribe` $0.003/min) ⇒ a
  5-min worst-case entry ≈ 1.5–3¢; 10 users × daily 2-min ≈ $2–4/month.
- Translation: pennies per thousand entries via the existing text LLM.
- S3: ~900 KB × 30-day window ⇒ ~27 MB steady state per daily user ⇒
  well under $0.01/user/month; 64 MiB per-user quota is the hard bound.

## Open questions (non-blocking, defaults chosen)

- **O-1** Keep-recording default is ON (D-3). Flip before P3 if you want
  opt-in-per-recording instead.
- **O-2** Launch STT model: `whisper-1` (max compatibility) vs
  `gpt-4o-mini-transcribe` (half price, better accuracy). Env-switchable;
  A/B after launch.
- **O-3** GDPR export bundle excludes kept audio in v1 (transcript is the
  portable record). Revisit if users ask.
- **O-4** Degraded mode when the translation LLM is unconfigured:
  `english_text = null`, portal shows original text + "translation
  unavailable".
- **O-5** Offline queueing of audio uploads (v2 candidate).
- **O-6** Server-side duration verification (ffprobe) if claimed-duration
  trust ever becomes a real abuse vector; size cap is the current bound.
