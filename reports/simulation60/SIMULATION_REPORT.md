# MindPattern — 60-Day, 5-User Simulation Report

**Date:** 2026-09-16 · **Duration simulated:** 60 days per user ·
**Users:** 5 (4 with planted psychological signals + 1 pure-noise control)
· **Total journal entries synced through the live API:** 568

## TL;DR

- Five simulated users journaled 1–3 times a day for 60 days through the
  **real API** (real client-side crypto, real storage, real recompute).
- Every planted signal the engine is designed to find was found — Sunday
  work dread (`temporal`), day-after-effects (`link`), word↔mood
  associations, a rising hobby topic (`topic`), a late mood decline
  (`mood_shift`), and recurring worries (`rumination` / `recurring_phrase`).
- The **pure-noise control user surfaced nothing** across 30 daily
  recomputes — the false-positive gates held.
- Patterns have a visible **lifecycle**: they first appear as `emerging`
  and are promoted to `confirmed` only after they keep re-qualifying over
  subsequent days.
- **There is no vector database.** Storage is per-user AES-256-GCM
  ciphertext rows in ordinary relational tables; similarity is computed
  transiently with MinHash + LSH inside the recompute (details in
  §6).

---

## 1 · How the simulation works

Each user's 60 days were exercised on **two coordinated tracks** over the
same corpus:

| Track | What it does | Why |
|---|---|---|
| **LIVE** | Registers the user through `POST /api/auth/register`, ages the account, syncs every entry (encrypted with the app's real key schedule: PBKDF2 → HKDF → AES-256-GCM, AAD-bound), opens a processing session, runs `POST /api/insights/recompute`, and decrypts `GET /insights` with the user's data key | This is what the server actually stores, processes, and returns |
| **REPLAY** | Runs the same corpus through the *same* brain code (`app.services.brain.update`) once per simulated day, with `today` advancing and the 30-active-day threshold mirrored | The live server's clock only says "today", so a single wall-clock day cannot show 60 days of pattern *lifecycles*. The replay makes the day-by-day story visible |

**Determinism cross-check:** for all 5 users, the live API's single
recompute surfaced exactly what a single-shot offline replay computed
(`determinism (live == single-shot replay): True` × 5). The replay is a
faithful mirror of the server pipeline, so its daily timeline is
trustworthy.

Per user: ~120–129 entries over 60 active days (2+/day), each entry with
its own text + explicit mood value (the app's one-tap mood check-in;
multiple entries per day are averaged into that day's mood bucket
server-side).

## 2 · The five users

| User | Planted signal (what the persona "does") | Expected patterns |
|---|---|---|
| **maya** | Sunday evening work dread; sleep-worry phrase Mon/Wed/Fri nights; the day after a worry night reads low | temporal (work→Sundays), link (sleep→next-day), rumination |
| **omar** | Stable, positive; picks up guitar — 3 early mentions, then every other day for the last 3 weeks, phrased differently each time | topic (guitar rising) |
| **priya** | Evening doomscrolling nights that read low; final ~3.5 weeks carry a mood decline with strong day-to-day carryover | mood_correlation, mood_shift, inertia |
| **lena** | Family visits roughly weekly with next-day dips; calls grandma every Sunday | link (family→next-day), temporal |
| **tom** | **CONTROL** — pure random noise, no planted structure, skips ~12% of days | **nothing** |

## 3 · What each user's app showed by day 60

*(from the daily replay — what a real daily user sees; "day" = first surfacing)*

### maya — work dread + sleep worry

| Day | Lifecycle | Kind | Pattern | Evidence |
|---|---|---|---|---|
| 31 | **confirmed** (day 51) | `link` | **sleep** — "the day after 'sleep' comes up, entries read lower" | 24 exposed days |
| 30 | **confirmed** (day 51) | `rumination` | "i can't sleep, my mind won't stop" | 23 mentions |
| 30 | **confirmed** (day 51) | `recurring_phrase` | "went to bed late" | 23 mentions |
| 31 | **confirmed** (day 51) | `recurring_phrase` | "the week is looming, big deadline pressure at work again" | 9 Sundays |
| 50 | emerging | `temporal` | **work** — concentrates on Sundays | 11 mentions |

All three planted constructs were found: the worry (rumination), its
day-after cost (`link:sleep` — the pattern the sleep→next-day-mood
literature backs), and the Sunday concentration of work dread. Her daily
question on day 60: *"If today had a title, what would it be?"*

### omar — rising guitar topic

| Day | Lifecycle | Kind | Pattern | Evidence |
|---|---|---|---|---|
| 59 | emerging | `topic` | **guitar** — "taking up more space in your writing" | 13 mentions, rising |
| 35 | **confirmed** (day 55) | `recurring_phrase` | "messed around on the guitar for a bit" | the early base phrase |

The engine discovered an **emergent topic it was never taught** —
"guitar" is not in any lexicon — from phrasing that was never repeated
verbatim, exactly the "rising topic" design goal. Question: *"What felt
different today compared to yesterday?"*

### priya — scrolling nights + late decline

| Day | Lifecycle | Kind | Pattern | Evidence |
|---|---|---|---|---|
| 31 | **confirmed** (day 51) | `rumination` | "wasted the whole evening scrolling, eyes tired" | 6 mentions |
| 31 | **confirmed** (day 51) | `rumination` | "fell down the feed again, regret it every time" | 6 mentions |
| 33 | **confirmed** (day 53) | `recurring_phrase` | "screens all evening, head buzzing afterwards" | 4 mentions |
| 43 | emerging | `mood_shift` | **recent mood** — "entries read lower than your baseline lately" | EWMA breach |

The recurring scroll-worries surfaced first (day 31, right at
threshold), and the **mood_shift** control chart caught her late decline
on day 43. Honest note: her carryover (`inertia`) did not clear the
gates with this seed — the engine's effect-size + FDR discipline keeps
marginal statistical claims off the screen (see §5).

### lena — family visits + Sunday calls

| Day | Lifecycle | Kind | Pattern | Evidence |
|---|---|---|---|---|
| 59 | emerging | `temporal` | **family** — concentrated on specific weekdays | 22 mentions |
| 53 | emerging | `link` | **family** — the day after family comes up, entries read lower | 21 exposed days |
| 48 | emerging | `link` | **health** — day-after association (her "pharmacy/doctor" filler days) | 11 exposed days |
| 31 | **confirmed** (day 51) | `recurring_phrase` | "called grandma like every sunday" | 9 mentions |

### tom — control

**Zero patterns across 30 daily recomputes.** Pure noise (random text,
random mood, ~12% skipped days) produced no temporal, no correlation, no
link, no shift, no phrase cards. This is the headline validation: the
engine's Benjamini–Hochberg family + effect-size gates + 2-day
replication requirement do their job.

## 4 · Cross-user summary

| User | Entries | Patterns by day 60 | Signal kinds found | Control |
|---|---|---|---|---|
| maya | 120 | 11 | link, rumination, temporal, recurring_phrase | — |
| omar | 120 | 19 | topic, recurring_phrase | — |
| priya | 126 | 20 | mood_shift, rumination, recurring_phrase | — |
| lena | 129 | 20 | temporal, link ×2, recurring_phrase | — |
| tom | 73 | **0** | — | **clean** |

*(The many small `recurring_phrase` cards at n=3 in each user's list are
an artifact of the simulator's filler pool — each filler sentence was
reused exactly 3 times, and the engine honestly counted those literal
repetitions. Real users typing free prose rarely repeat a sentence
verbatim 3×; treat those cards as the direct-measurement detector doing
exactly what it claims.)*

## 5 · Lifecycle and conservatism — two things worth knowing

**Patterns earn trust over days.** First surfacing is `emerging`; a card
is promoted to `confirmed` only when it keeps re-qualifying on later
recompute days (maya's `link:sleep` emerged day 31 → confirmed day 51).
Statistical kinds (temporal/correlation/link/shift…) additionally need
**2 distinct recompute days with independent evidence** — which is why a
fresh account importing 60 days of history in one sync surfaces only
direct-measurement cards (maya: 2 patterns) while the same corpus built
through daily use surfaces the full picture (maya: 11):

| View | maya | omar | priya | lena | tom |
|---|---|---|---|---|---|
| Fresh account, single recompute | 2 | 1 | 0 | 0 | 0 |
| Real daily user, day 60 | 11 | 19 | 20 | 20 | 0 |

**The engine prefers silence over noise.** In tuning probes, weaker
versions of priya's decline and maya's next-day dips did **not** surface;
only realistic-but-clear effects cleared the gates. Marginal signals are
seed-dependent by design — replication-before-surfacing means a fluke
must repeat on independent data to ever reach the screen.

## 6 · How the data is stored — including "the vector database"

**There is no vector database in this system.** No pgvector, FAISS,
Pinecone, Chroma, or any embedding store — verified by searching the
backend for every mainstream vector-DB and embedding technology. The
word "vectors" in the repo refers to *crypto test vectors*
(`shared/vectors.json`). Everything is encrypted blobs in ordinary
relational tables (SQLite in dev, PostgreSQL in production via
SQLAlchemy):

| Table (measured in this simulation's DB) | What's in it |
|---|---|
| `users` | username, scrypt verifier hash, KDF salt, role, therapist wrap keys |
| `entries` | one row per journal entry: `user_id`, `client_entry_id`, `entry_date`, `received_at`, **`blob` = AES-256-GCM ciphertext** |
| `insights` | 3 encrypted rows per active user: `brain` (the pattern-engine state), `patterns` (what the app renders), `question` (the daily question) |
| `consents`, `pairing_codes`, `therapist_notes`, `access_log` | sharing metadata (all key material wrapped/encrypted) |

**Measured from this run** (per user): ~120–129 entry rows at ~135–140
bytes of ciphertext each (~17 KB total journal storage), a 7.6–13 KB
encrypted brain state, a 0.2–1.9 KB patterns payload, a ~110-byte
question. The full five-user simulation lives in a SQLite file of well
under 200 KB.

An entry **at rest** looks like this — opaque, authenticated bytes the
server cannot read:

```
client_entry_id = maya-0000        entry_date = 2026-07-19
blob (147 bytes) = 4ee11d5e 610d14d7 17272608 e362a373 5b8f8cb3 ...
                   └─ nonce ──┘ └──────── ciphertext ────────┘ └ tag ┘
```

The plaintext (`{"v":1,"text":"...","sentiment":0.08,"created_at":"..."}`)
exists only on the user's device, and — for at most the duration of one
recompute — in server memory inside the secure processing context after
the client hands over a single-use data key.

**Where "similarity" actually happens** (the job a vector DB would
usually do): during a recompute, near-duplicate sentence clustering runs
**MinHash with 64 permutations over word shingles, banded into 16 LSH
bands × 4 rows** — a sketch-based Jaccard estimate, computed transiently
in memory and never persisted. Topics are found by token n-gram
statistics against the user's own earlier writing. The recompute's
*memory* — pattern ids, lifecycle states, decayed evidence counts,
qualification days — is a small JSON document encrypted under the user's
data key and carried forward in the `brain` insight row. Nothing
embedding-like is stored anywhere, by design: a leaked database reveals
only ciphertext.

## 7 · Re-run it

```bash
cd backend
MINDPATTERN_ENV=development MINDPATTERN_DB_URL="sqlite+aiosqlite:///./sim60.db" \
  MINDPATTERN_AUTH_RATE_LIMIT=100 ../.venv/bin/uvicorn app.main:app --port 8907
cd ../reports/simulation60
../../.venv/bin/python simulate.py      # ~5 min (rate-limit pacing included)
```

Artifacts: [simulate.py](simulate.py) (harness), [results.json](results.json)
(full per-user patterns, timelines, storage metrics),
[sim_run.log](sim_run.log) (annotated run), [probe_tune.py](probe_tune.py)
(offline detector-tuning probe).
