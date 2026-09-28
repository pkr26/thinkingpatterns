# 1-Year, 10-User, Every-Endpoint E2E Simulation — 2026-09-28

**Result: 246/246 checks passed** (`run.log`, `results.json`; the campaign
exits non-zero on any failure). Wall time 3.8 min for 7,083 entries, 26
measures, ~1,600 total API calls, ~3,350 offline brain recomputes.
*(Originally 245/245; the campaign then surfaced a real lexicon finding —
see the remediation addendum at the bottom — now fixed, pinned by new
tests, and re-proven end-to-end with a 246th check.)*

Successor to `reports/simulation60` (60 days, 5 users, 5 endpoints): the
same live-API philosophy — every journal entry synced through the real
server over real HTTP, encrypted with the real client crypto stack (real
600k-iteration PBKDF2, HKDF auth/data keys, AES-256-GCM with the exact
AAD contracts of the mobile app) — extended to a full simulated year, ten
personas, and **every route the backend mounts (52 endpoints)**, plus
every functionality a year of data exercises.

## How to re-run

```bash
cd backend
MINDPATTERN_ENV=development \
MINDPATTERN_DB_URL="sqlite+aiosqlite:///./sim1y.db" \
MINDPATTERN_AUTH_RATE_LIMIT=1000 \
MINDPATTERN_ENTRIES_RATE_LIMIT=20000 \
MINDPATTERN_PROCESSING_RATE_LIMIT=300 \
MINDPATTERN_READ_RATE_LIMIT=30000 \
MINDPATTERN_EXPORT_RATE_LIMIT=60 \
../.venv/bin/uvicorn app.main:app --port 8908 --log-level warning

# from the repo root, fresh DB each time:
rm -f backend/sim1y.db*
E2E_BASE=http://127.0.0.1:8908 \
E2E_DB="sqlite+aiosqlite:///$(pwd)/backend/sim1y.db" \
.venv/bin/python reports/simulation1y/simulate.py
```

Rate limits are raised exactly like simulation60 raised auth (the
machinery itself is still verified against the DEFAULT ops bucket —
see phase 16). Server env: development (sharing enabled, no LLM URL —
which the llm-consent phase verifies is refused honestly).

## The ten personas (365 days each)

| user | entries | story planted | what surfaced (daily-user view) |
|---|---|---|---|
| maya | 730 | work-dread Sundays + M/W/F sleep worry, next-day dips | `mood_correlation sleep` (n=73, day 36), `mood_correlation/temporal work` (n=31), rumination on the work-dread sentence (n=26) |
| omar | 730 | stable; guitar topic rising the last 90 days | `topic guitar` **confirmed n=61 from day 350** (rising vs his own base rate) |
| priya | 772 | doomscroll nights; late-year decline + inertia | `inertia day-to-day mood` (n=28, day 352) |
| lena | 782 | family visits with next-day dips; Sunday grandma calls | `link family` (n=66) + `temporal family` (n=66) — the literal day-after pattern |
| tom | 489 | **CONTROL: pure noise all year** | **zero statistical kinds, 365 days** — no false claims |
| ava | 730 | mid-year decline, late recovery, run days higher | run-sentence phrase cards only; the planted arc stayed under the statistical bars (honest) |
| ben | 730 | payload-v2 structured channels + 26 encrypted PHQ-9s | `mood_correlation poor sleep` from his own 1–5 ratings (n=44, day 37) |
| chloe | 766 | crisis episodes ~10-dayly | crisis-phrase cluster flagged `sensitive=True` (n=13); today's question never quotes it |
| dev | 730 | editor: rewrites 8% of the year, deletes 12, weekly stress | `mood_correlation/temporal work` + rumination (n=21), consistent through the edit/delete churn |
| elena | 624 | stable journaler; sharing + key-lifecycle persona | nothing but filler-phrase cards — correct for a stable user |

Every user's **live single recompute == offline single-shot replay**
(determinism, 10/10), and each user's full year was also replayed
clock-accurately day by day (~335 recomputes per user through the same
`brain.update` the server runs) so pattern lifecycles (candidate →
emerging → confirmed, with transitions and fades) are visible per day in
`timeline_<user>.csv`.

## What the campaign verified (16 phases)

- **0 boot** — /healthz, /readyz, /api/meta (unlock 30, disclosure v2),
  /api/v1 canonical mount parity.
- **1 registration** — 10 patients + 2 therapists; duplicate username 409,
  charset/salt/unknown-field 422s, garbage wrap key 422, salt decoy for
  unknown users (deterministic, same shape).
- **2 the year of entries** — 7,083 POSTs, all 201; duplicate cid 409,
  future/past date 422s, non-b64 blob 422, 3 MiB body 413, missing/bogus
  bearer 401. ben's entries carry payload v2 (energy/sleep/tags/tod).
- **3 editing lifecycle** — dev's PUTs with content_version bump +
  AAD ladder, stale version 409, DELETE + revision header, deleted GET
  404, full offset/limit pagination walk, expected_revision conflict,
  page_bytes ciphertext budget + truncation, since= filter.
- **4 measures** — ben's 26 PHQ-9s as opaque ciphertext (score arc 14→4
  visible only after local decrypt), DESC ordering, revision header,
  DELETE with wrong verifier 403 / right verifier 200.
- **5 recompute / insights / questions** — per user: processing session
  (bad key 422), single-use token (reuse 403), recompute without token
  401, insight blob decrypt, question decrypt, **live == single-shot
  determinism**, zero-pattern users correctly get no question (404);
  chloe feedback taps accepted + malformed feedback 400; control tom
  surfaces no statistical kind after a full noise year.
- **6 local-recompute** — chloe's on-device brain run uploaded as two
  client-encrypted blobs (no processing session, data key never sent),
  seq+1, stale base_state_seq 409, GET /insights serves the uploaded
  payload byte-identically; server recompute re-asserts afterwards.
- **7 sharing lifecycle** — pairing code, SAS verified on BOTH ends
  against the locally computed value (MITM check), wrong code 404,
  outdated disclosure 409, grant without/wrong verifier 422/403, code
  burned, therapist patient list with wrapped key + caseload summary
  (decrypts, count matches), portal unwrap == real data key, therapist
  insight read byte-identical + portal decrypt, entry window since/until,
  ben's measures read (v2 disclosure), notes POST/idempotent
  retry/conflict/PATCH+stale 409/missing base_version 400/revisions,
  revoke (403 wrong verifier, 204 right) → reads 404, key material
  cleared, revoked row kept, notes survive, re-grant same row id,
  therapist wrap-key rotation + patient rewrap + unwrap under new key.
- **8 key lifecycle** — priya: pure data-key rotation via rekey
  (old+new sessions + verifier; entries/insights re-encrypted, old key
  dead, login credential untouched, recompute works under new key);
  elena: v1→v2 envelope upgrade (possession probe, envelope round-trip,
  same data key), then O(1) v2 password change (possession probe, old
  bearer dies, new envelope unwraps, **therapist consent survives —
  data key never moved**); ava: documented v1 ordering rekey-then-
  credential-rotate, year decrypts under the new password's key, old
  credential dead.
- **9 TOTP (therapist role)** — setup (secret + otpauth), wrong code
  403, enable → 8 backup codes, login without code 401 totp_required,
  fresh-code login, replayed code 401, backup-code login then burn,
  /therapist/me flag, patient token 403, disable, password-only login
  again.
- **10 LLM consent** — defaults disabled; enable with no provider
  configured → 409 llm_unavailable (honest refusal); disable 200.
- **11 logout** — 204, that jti dead, other token alive.
- **12 export** — every user's full bundle decrypted locally (entries,
  measures, shares; elena's active grant present), exported blobs opaque.
- **13 access logs** — elena's full cursor-paginated log records
  therapist reads by actor; malformed cursor 422; therapist log names
  the patient.
- **14 boundaries & deletion** — cross-therapist 404s, unpaired note
  404, random patient 404, therapist token on 8 patient routes 403,
  patient token on 3 therapist routes 403, therapist account delete
  (wrong verifier 403 → 204 → login 401); fred: baseline recompute
  (no token, analyzer none), no question 404, account delete
  (422/403/204), token dies, login 401, decoy salt (never the real one,
  deterministic), username reusable, re-registered account empty.
- **15 storage at rest** — 12 tables inspected; every entry/insight/
  measure blob fails the structural plaintext test (valid-UTF-8+JSON);
  the raw DB file and its WAL contain **none** of six journal/note
  plaintext probes.
- **16 rate limiting** — the default ops bucket trips at exactly the
  241st burst request with Retry-After (0.2 s).

## Honest observations (not failures)

- A single fresh recompute (the "imported history" view) surfaces only
  direct-measurement kinds; every statistical kind (incl. omar's rising
  topic) correctly waits for the replication gate — the daily user sees
  them from their second qualifying day. This is the H-9/replication
  discipline working, and it is why the campaign asserts rising topics
  on the daily-replay view.
- tom (control) earns filler-sentence `recurring_phrase` cards — his
  corpus literally repeats those sentences ~7×. Direct measurement of
  repeated text is the product working; the control assertion (no
  statistical kind after a noise year) held.
- ava's planted mood arc and priya's scrolling correlation stayed under
  the bars; priya's inertia surfaced. The engine does not manufacture
  the stories we hoped for — it reports the ones that earn their p-values.

## Artifacts

- `simulate.py` — the campaign (personas, client crypto, 16 phases).
- `run.log` — full 245-check output.
- `results.json` — per-user patterns (live + daily replay + first day),
  timelines, checks, table counts.
- `timeline_<user>.csv` × 10 — per-day surfaced counts, new pids, state
  transitions.

## Remediation addendum (same day): lexicon polysemy fix, re-proven live

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

**Fix** (brain.py `CURATED_SENTIMENT`, overriding VADER word-for-word the
sanctioned way): `down → −0.6` (VADER's own affective-sense weight),
`stop → 0.0` (the word's affect lives in what is stopped). Regenerated
`shared/brain_lexicon.json`, both TS lexicon modules, and
`shared/brain_vectors.json` (exactly one sentiment row changed:
−0.95 → −0.65). Pinned by 9 new tests in
`backend/tests/test_lexicon_remediation_2026_09_28.py` (word weights,
sentence scores, cluster classification, and the negative controls — a
genuinely negative cluster keeps its rumination kind).

**Proof, all gates green after the change:** backend 1,629 / web 668 /
mobile 1,965 / portal 413 tests, mobile+web brain-parity vector suites
included; and this campaign **re-run end-to-end with two tightened
assertions — 246/246**:

- tom: **zero rumination cards** (his recycling sentence is a plain
  recurring_phrase now) — plus the standing zero-statistical-kinds
  control.
- maya: the sleep worry now surfaces as **rumination** (n=61) live,
  beside the work-dread worry (n=26); chloe keeps rumination only for
  her genuinely negative cluster ("everything felt heavy again",
  n=17) while her crisis card remains recurring_phrase **[SENSITIVE]**
  — sensitivity is suppress-tier matching, independent of kind.

Known remaining gap (documented, deliberately not changed here):
"can't stop crying" still reads positive because the negation window
flips "crying" *through* the now-neutral "stop" — that is VADER's
pinned negation semantics (x−0.74 flip), a separate, heavier change
than a word weight.
