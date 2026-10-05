# Pattern analysis

The deterministic engine computes observations against the user's own history.
`update(state, entries, today)` takes its clock input explicitly; the same corpus,
prior state, and date produce the same result. Patterns become available after
30 distinct active journaling days.

The [research reference](research.md) records citations, design rationale, and
scientific limitations. These methods support reflective observations; they do
not establish diagnostic accuracy, clinical benefit, or a user-level false
positive rate. Citation-to-bibliography checking remains a documented validation
task in [security residuals](SECURITY_RESIDUALS.md).

## Pattern kinds

| Pattern kind | What it says | Method | Grounding |
|---|---|---|---|
| `temporal` | "'work' concentrates on Sundays" | weekday concentration vs your own writing schedule; exact binomial; **every** candidate weekday tested (not just the argmax), Benjamini–Hochberg FDR across all claims | day-of-week effects: Golder & Macy 2011 (*Science*); Mappiness |
| `mood_correlation` | "entries read lower on days 'work' appears" | **within-person residuals** (your mood minus your own rolling baseline — the intensive-longitudinal standard), **deconfounded for the weekly cycle** (per-weekday centering: a work-Monday mood dip cannot masquerade as a theme association) + Welch's t on autocorrelation-deflated effective sample sizes + Cohen's d gate | Bolger & Laurenceau 2013; Fisher (idiographic models); day-of-week confounder: Golder & Macy 2011 |
| `link` | "the day after 'sleep' comes up, entries read lower" | lag-1 day-after association on the same weekday-deconfounded residuals, same gates; the label reports the **modal exposed gap** (`lag_days` + gap1/gap2 counts) and says "the day after" only when gap-1 is both the mode and ≥70% of measured exposed outcomes (`LINK_DAY_AFTER_SHARE`) | sleep→next-day mood: Bourke et al. 2026 meta-analysis (118 studies); stress spillover: Bolger et al. 1989 |
| `inertia` | "mood carries over day to day more than usual" | lag-1 autocorrelation, recent vs your earlier norm (Fisher-z difference test) | Kuppens et al. 2010; Houben et al. 2015 meta-analysis |
| `energy_inertia` | "your energy carries over day to day more than usual" | the same inertia machinery over the optional energy picks (payload v2 channel) | affect-dynamics methods as `inertia`; mood–energy dissociation is circumplex-standard |
| `pa_inertia` / `na_inertia` | "your positive / negative feelings carry over more than usual" | the same machinery over the graded lexicon's POSITIVE and NEGATIVE streams summed by sign (`sentiment_components`), text-scored entries only | differential dynamics of PA vs NA: Emmons & Diener 1985; Abitante et al. 2024 |
| `energy_mood_coupling` | "your energy and your mood move together more than usual" | Pearson correlation of energy and mood within-person residuals, recent vs your own earlier norm (Fisher-z); surfaced only as a rise | mood–energy concordance as a within-person affect-dynamics signal |
| `sense_making` | "your writing has leaned more on sense-making words" | causal+insight word density per day (LIWC-style dictionary), recent vs your earlier norm (Welch's t + density gates) | rising causal/insight word use tracks benefit in expressive writing: Pennebaker & Francis 1996; Campbell & Pennebaker 2003; Hevey 2014 |
| `activity_diversity` | "the variety in your tagged activities has narrowed/widened" | weekly Shannon entropy over activity tags with **Miller–Madow bias correction** (raw plug-in entropy under-estimates by more than the effect gate), low-volume weeks excluded (≥2 tagged days and ≥2 distinct tags to count), recent vs earlier weeks (≥4 weekly observations per side; Welch's t + change gate); both directions surface | variety of pleasant activities tracks symptoms: Ong et al. 2023; Miller 1955/Madow (bias correction) |
| `instability` | "bigger daily swings than usual" | spread of within-person residuals, recent vs earlier | affective instability literature |
| `mood_shift` | "entries read lower than your baseline lately" | EWMA control chart (λ=0.18, ±3.1σ — the limit recalibrated 2026-09-26 by Monte Carlo simulation of the exact rule to keep the per-recompute false-alarm probability ≤5% at φ=0.5; run-of-3 beyond-limit points in the last 5, personal baseline, AR(1)-inflated limits) | Snippe et al. 2023; Smit, Schat & Ceulemans 2023 (methods) |
| `rumination` | "the worry 'X' keeps returning" | near-duplicate **negative** phrase clusters + negation-heavy phrasing + absolutist-word density | Ehring & Watkins 2008 (RNT); Al-Mosaiwi & Johnstone 2018 (absolutist words) |
| `topic` | "'guitar' has been taking up more space in your writing" | emergent topic discovery: recurring content n-grams beyond the fixed lexicon (function/theme/sentiment words excluded); RISING topics tested against your own earlier entries (exact binomial, BH) or persistent presence (≥30% of entries — a direct measurement requiring ≥4 distinct following-token contexts, suppressed when ≥80% covered by the run's own recurring-phrase clusters; carries `detail.presence=true`) | bursty recurring topics are a standard diary-analysis signal |
| `recurring_phrase` | "the phrase 'X' keeps returning" | MinHash (64-perm) + LSH (16×4 bands) near-duplicate clustering | — |
| `avoidance` | "the day after 'X' comes up, you go quiet" | theme-days followed by journaling silence vs your own base skip rate (censoring-honest, exact binomial, BH) | avoidance/silence after stressors is a standard diary-analysis signal |
| `cadence` | "your writing rhythm has been less regular" | gap spread, recent vs your earlier norm (Brown-Forsythe) | engagement-rhythm change as a within-person signal |


## Evidence and lifecycle

Patterns carry a **lifecycle** (`candidate → emerging → confirmed → fading →
archived`, 45-day evidence half-life). Statistical kinds (`temporal`,
`mood_correlation`, `link`, `inertia`, `instability`, `mood_shift`) surface
only after qualifying on **≥2 distinct recompute days** — evidence-date kinds need a qualification
day contributing NEW evidence; window-stat kinds (computed on a sliding
window — consecutive recomputes share ~179 of 180 days) need qualification
days ≥2 calendar days apart. This is a repeated-qualification guard, not
independent replication: overlapping windows reuse observations. It does
not by itself establish a user-level false-discovery rate or clinical
validity. Consequence: re-running an unchanged corpus the next day
surfaces nothing new. Direct-measurement
kinds (a literally repeated phrase, a persistent topic presence) report
what is in the text and keep immediate surfacing. A **semantic flip**
(dominant weekday, direction) retires the old pattern-id to fading and
forks a fresh `~2` id instead of silently relabeling under an intact
history. The app renders lifecycle states as evidence labels ("early
evidence" / "established" / "fading") with a **"Why am I seeing this?"
panel** per card — window, sample size, effect size, significance, and the
method in plain language.

Entries can carry **structured channels** (payload v2): a 1-5 sleep rating, an energy pick,
and activity tags. Poor-sleep nights (strictly below YOUR median rating) and recurring
proper names (person anchoring) ride the same theme machinery as every lexicon word —
same gating, same correction, rating-aware copy. Question feedback ("this resonated /
not me") is encrypted on-device, rides the next recompute as an opaque blob, and
reorders future questions.

## Language and sentiment

Sentiment uses a curated graded lexicon with emoji valence, negation,
intensifiers, contrast weighting, and morphological candidates. Curated rules
override the underlying VADER entries. The generated lexicon is shared with the
TypeScript port and checked against Python through golden vectors.

Analysis supports English and Spanish. Eligibility compares recognized words
and requires a majority of the text's letters to survive the Latin tokenizer;
non-Latin letters count in that coverage denominator. A short English quotation
inside predominantly unsupported-script text therefore cannot enable scoring.
The window and each entry are checked; eligible entries use their own EN/ES
lexicon. This conservative gate is not a general language identifier or a
validated multilingual classifier. Unsupported text is excluded from mood
analyses, rumination classifications, person/topic interpretation and account
averages, while explicit finite mood ratings, neutral phrase repetition and the
writing calendar remain usable. No eligible mood evidence is reported as
unavailable, not neutral. Summary metadata gives the number of explicit ratings,
text estimates and excluded entries. Phrase matching remains limited by the
tokenizer's supported scripts.

Spanish has its own sentiment and theme lexicons, negators, intensifiers,
function words, and generic question catalog. Person-name anchoring remains
English-only. Interface language and journal-analysis language are independent.

## Statistical constraints

The backend regression suite checks schedule-adjusted baselines, within-person
detrending, weekly-cycle adjustment, and one Benjamini–Hochberg family over the
run's statistical candidates. Candidate p-values are computed before effect-size
filtering. Corrupt stored analysis state is discarded and rebuilt; authenticated
entry failures remain errors.

The technical panel's `p_value` is the detector's raw, unadjusted p-value;
the displayed number is not a BH-adjusted p-value. Passing the multiple-testing
selection gate and displaying a numerically adjusted value are different facts.

The engine deliberately excludes relapse prediction, diagnosis, bipolar
classification, and critical-slowing-down claims. The research reference records
the rationale and evidence limits.

## On-device analysis

The mobile app currently ports sentiment scoring and the statistics core.
Full pattern detection, lifecycle merging, serialization, and client orchestration
remain tracked in [the port plan](../mobile/src/brain/PORT.md). Local sentiment
supports device-local mood estimates; it does not mean full recompute already
runs on the device.

The server provides `POST /api/v1/insights/local-recompute` for a future complete
port. It accepts client-encrypted state and patterns with `base_state_seq`
concurrency checking and server-grounded analysis dates, without opening a
processing session.

`shared/brain_vectors.json` contains sentiment, statistics, and full-engine golden
cases. Generate it with `backend/scripts/gen_brain_vectors.py`; regenerate the
lexicon through `backend/scripts/dump_brain_lexicon.py`. A complete port must match
the full-engine fixtures before clients switch to the local protocol.
