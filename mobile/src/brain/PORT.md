# The on-device brain port — tracked plan (Phase 3)

Goal: run the ENTIRE deterministic analysis on the phone so the data key
never crosses the wire — the server becomes blind end to end. The server
side of the protocol already ships: `POST /api/v1/insights/local-recompute`
(backend/app/api/insights.py) stores the client-computed, client-encrypted
brain state and patterns payload with state_seq discipline and NO
processing session. What remains is the TypeScript port itself.

## The acceptance gate (already in place)

`shared/brain_vectors.json` (v2) carries **full-engine golden cases**:
deterministic corpora → the complete surfaced-card list and the full new
state (every StoredPattern field, floats rounded to 9 decimals). A port
is correct when `mobile/tests/brainVectors.test.ts` runs it against
every case and matches exactly. The sentiment + statistics cores already
pass (sentiment.ts, stats.ts — 48 sentiment vectors, erfc/pearson/
fisher-z). Regenerate with:
`cd backend && MINDPATTERN_ENV=development ../.venv/bin/python scripts/gen_brain_vectors.py`

## Ported ✅

| Piece | Source of truth | Mobile module |
|---|---|---|
| Graded lexicons (en/es), emoji, negators, intensifiers | sentiment_lexicon*.py → shared/brain_lexicon.json | `brain/lexicon.ts` |
| Sentiment scoring incl. PA/NA splits, "but" reweighting, stemming | brain.py sentiment helpers | `brain/sentiment.ts` |
| erfc, Pearson r, Fisher-z | statsig.py + brain.py | `brain/stats.ts` |

## To port, in dependency order

1. **Tokenization + fold** — `_fold_sentiment_text` (NFKC, U+2019, Latin
   base fold), `WORD_RE`, `SENTENCE_RE`, `sentences_of`
   (brain.py ~1469-1511). The fold must stay byte-identical (the ES
   lexicon's accented keys depend on it).
2. **Language detection + topic mining** — the function-word ratio
   detector, shingle/LSH clustering (phrases.py — blake2b shingles,
   splitmix64 banding, the comparison/proposal budgets), topic presence
   + rising with the ES eligibility union (D-2).
3. **Day series + structured channels** — mood series (empty-text skip,
   D-3), PA/NA day buckets, energy/sleep/tags channels, active days,
   cadence; EWMA + the inertia/instability family (statsig.py).
4. **Themes + statistical detectors** — THEME_LEXICON extraction — BOTH
   language maps now: the English set and THEME_LEXICON_ES (2026-09-21
   follow-up, language-gated per corpus; the spanish-mixed golden case
   pins ES-derived candidates), the
   weekday Bernoulli family with the tod narrowing (P3-B), mood-shift,
   mood_correlation (Welch day-means, M-8), links, avoidance.
5. **Phrase family** — rumination classification (negativity/negators,
   language gate), `_phrase_pid` + the D-6 anchor/variant re-link.
6. **Lifecycle merge** — StoredPattern state machine (candidate →
   emerging → confirmed → fading → archived), the replication gate
   (newest-day comparison, D-1), confirm-clock restart (D-5), semantic
   flips, decay, FDR selection (BH over the full family), surfaced-card
   assembly incl. sensitive/suppress handling (crisis.matches_suppress —
   port shared/crisis_phrases.json + the fold).
7. **State serialization** — load_state/dump_state compat with the
   server's JSON (older blobs lack new fields; treat as absent).
8. **The client flow** — fetch entries + prior state (GET /insights),
   decrypt, run the port, encrypt both blobs with the existing AAD
   contracts, POST local-recompute; on 409, re-fetch and re-run.

## Rules

- Determinism is the product: no Date.now/RNG inside the engine; the
  corpus + prior state + today must fully determine the output.
- Every tranche lands with its vector cases green — regenerate the
  corpus when adding cases, never hand-edit expected outputs.
- Keep parity with probe_brain.py's ground truths (A-H) by adding the
  same assertions as mobile tests where applicable.
