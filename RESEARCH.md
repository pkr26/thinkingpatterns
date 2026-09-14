# Deep Research: Industry Standards & Clinical Evidence for the MindPattern Mini-Brain

*Compiled 2026-09-04. Sources cited inline; full bibliography per section. This document
grounds the v3 mini-brain design in (a) what the consumer mental-health app industry
actually ships, (b) what clinical psychology has actually validated, and (c) what
safety/ethics/regulatory standards expect. It follows the code audit (`probe_brain.py`
reproduces the audit's main finding).*

---

## 0. Executive summary — what the research says

1. **Our biggest audit finding is confirmed as the field's #1 methodological rule.**
   Bolger & Laurenceau's *Intensive Longitudinal Methods* (the standard text for exactly
   our data type — daily diary/journal series) is explicit: associations must be computed
   **within-person, on deviations from the person's own mean/trend**. Pooled raw scores
   confound stable between-person differences with within-person processes. Our mood
   correlations currently run on raw pooled sentiment — the confound we demonstrated
   empirically (5 false claims, p ≤ 1e-6) is precisely the textbook failure. Fixing it is
   not a tweak; it is conforming to the field's core standard.

2. **The strongest-evidence patterns we could detect (meta-analytic support):**
   within-person **sleep → next-day mood** (lag-1; Konjarski et al. 2018,
   *Sleep Medicine Reviews* 42, meta-analysis of experience-sampling studies),
   **day-of-week and time-of-day rhythms** (Golder & Macy 2011, Science;
   Mappiness), **mood inertia** (autocorrelation; Houben et al. 2015 meta-analysis), and
   **EWMA control charts over daily mood with a personal baseline** — which we already
   implement, correctly citing Snippe et al. 2024. We are right about EWMA and wrong
   about almost everything downstream of sentiment.

3. **Our deterministic, no-fake-insights philosophy is validated and differentiated —
   and now an APA position.** The APA's Nov-2025 health advisory on AI wellness apps:
   no diagnose/treat/cure claims, grounding in psychological science, in-app crisis
   safeguards, AI disclosure. Daylio — the most successful *non-AI* tracker — wins trust
   by labeling correlation confidence rather than overclaiming. We lost the competition
   on analysis quality, not on philosophy; the fix is more (and better-grounded) science,
   not LLM marketing.

4. **Industry table stakes we are missing:** mood charts (line/heatmap/"Year in
   Pixels"), streaks, weekly/monthly reports, **crisis resources reachable in 1–2 taps**
   (only ~35% of apps provide them — being in the 65% is a real liability), immediate
   first-value on day one, and wearable/HealthKit correlation. MindDoc deliberately
   gates assessment behind 14 days *and explains why* — precedent for our 30-day gate,
   but they show structured value during the wait; we show a countdown.

5. **Sentiment NLP: our hand-rolled 120-word lexicon should be replaced by standard,
   still-deterministic instruments.** VADER (MIT license) adds graded valence,
   intensifiers ("very" ×1.5), graded negation, punctuation/emphasis rules — all
   deterministic and rule-based. AFINN-111 (~2,477 words, open) provides −5..+5 valence.
   NRC EmoLex (8 emotions + 2 sentiments, ~13,900 words, free for research/commercial
   license available) enables **emotion granularity** — a validated wellbeing construct
   no competitor surfaces from journal text.

6. **Language markers with clinical evidence** (computable deterministically):
   absolutist words ("always", "never", "must" — elevated ~50% in depression/anxiety
   forums, ~80% in suicidal-ideation forums; Al-Mosaiwi & Johnstone 2018), first-person
   singular pronoun density (weak individual signal — feature, not trigger), repetitive
   negative thinking / rumination (transdiagnostic; Ehring & Watkins 2008) — our
   near-duplicate phrase clustering is 80% of a rumination detector already.

7. **Regulatory line to hold (FDA general-wellness):** "observes patterns in your
   journal" = wellness; "predicts/foresees depression relapse" = device claim. Our own
   README currently leans on "foreseeing depressive recurrence" adjacent language when
   justifying the EWMA chart — the *implementation* is fine (we surface "your entries
   have read lower lately"), but marketing/README phrasing must stay on the wellness
   side. FTC precedent (BetterHelp $7.8M, Cerebral ~$7M, GoodRx, Monument) makes
   privacy-marketing-vs-practice consistency an enforcement target; our opt-in LLM path
   needs named-provider, retention, and no-training disclosure, and crisis-safe behavior.

---

## 1. Industry landscape — what competitors ship

### 1.1 Insight features per app (2025–2026 state)

| App | Insights | Time-to-first-insight | Engine |
|---|---|---|---|
| **Daylio** | Mood line charts, Year in Pixels, weekday occurrence bars, activity↔mood correlations **with Low/Med/High confidence labels**, previous/same/next-day mood comparisons, longest streaks with/without activity | Immediate (frequency stats) | Deterministic statistics — no ML |
| **How We Feel** | Emotion check-ins on a granularity wheel (Yale/Brackett), pattern charts, HealthKit sleep/exercise trends | Immediate check-in value | Rules/science-based, free |
| **Reflectly** | Daily/weekly/monthly overviews, mood graphs, adaptive prompts | After first entry; deeper insights paid | AI/NLP |
| **Stoic** | Mood/emotion/sleep trends, morning/evening prompts, export, "AI-Powered Journal" | Immediate | Hybrid |
| **Moodnotes** | Mood-over-time charts, trigger identification, **cognitive-distortion ("thinking trap") prompts after negative entries** | Immediate | CBT rules (ustwo + clinicians) |
| **MindDoc** | 3×/day questions × 14 days → **biweekly validated screening-based assessment**, symptom/progress reports, CBT courses | **14 days by design, explained to the user** | Validated instruments (PHQ/GAD-style) |
| **Youper** (shutting down Sept 2026) | Chat check-ins, "Emotional Health Insights" over time; RCT-adjacent evidence (anxiety d=0.57, depression d=0.46 in 2 weeks) | Immediate (conversational) | AI chatbot + CBT scripts |
| **Wysa** | Chat mood check-ins, journaling, **SOS crisis detection** (claims 82% of crisis users detected); NHS-approved; NYC 988 companion | Immediate | AI + scripted CBT/DBT |
| **Bearable** | Custom symptom/mood/habit tracking, weekly reports, correlation insights | ~1 week | Deterministic statistics |
| **eMoods** | Daily mood highs/lows, sleep/meds/anxiety charts, **printable PDF reports for clinicians** | Immediate | Rules |
| **Rosebud / Mindsera** (AI-journaling wave 2024–26) | Weekly progress reports, recurring-topic overviews, natural-language search over journal history | Immediate | LLM |

### 1.2 The pattern that separates winners

- **Immediate activation value + accumulating depth.** Daylio shows frequency stats day
  one and correlation confidence grows with data. MindDoc gates its *assessment* behind
  14 days but shows daily questions throughout and *explains the wait*. Nobody credible
  shows a blank screen for a month. A common AI-journaling rule of thumb: meaningful
  patterns need 2–4 weeks of entries — apps that show *something* sooner win activation.
- **Confidence framing beats certainty.** Daylio's Low/Medium/High confidence labels on
  correlations are the industry's trust mechanism — exactly our lifecycle states
  (emerging/confirmed/fading), which we already compute but render weakly.
- **The moat question.** The AI-journaling category is crowded (Rosebud, Mindsera,
  Reflectly, Stoic); on-device AI (Apple Foundation Models, iOS 26) is making "private
  AI" a commodity. Our differentiators that survive 2026: client-side encryption,
  deterministic explainable statistics, and *clinically-cited* pattern kinds nobody else
  ships (within-person lagged links, mood inertia, emotion granularity from journal text).

### 1.3 App-evaluation standards (what judges/raters score)

- **APA App Evaluation Model** (5 hierarchical levels): access/background → privacy &
  security → evidence → ease of use → interoperability. Being updated for AI apps.
- **One Mind PsyberGuide**: Credibility / UX / **Transparency** scores (peer-reviewed
  methodology, Neary et al. 2021).
- **ORCHA** (UK): Data & Security (GDPR, ISO 27001), Professional Assurance, UX.
- **NICE ESF (UK, 2022)**: functional tiers A–E by risk; a pattern-observation app maps
  to **Tier B** ("understanding behavior") — staying out of Tier C ("treat/diagnose")
  requires avoiding treatment/diagnosis claims.
- **DTAC (UK NHS)**: clinical safety, data protection, technical security,
  interoperability, usability — pass/fail gates.
- **DiGa (Germany)**: CE-marked device + positive-effect evidence; most listed DiGAs are
  mental-health.
- **FDA general-wellness guidance**: stress-management/relaxation framing stays
  unregulated; disease claims (diagnose/treat/predict relapse) cross into device
  territory. Apple requires a regulated-medical-device declaration in App Store Connect;
  Google Play requires the health-app declaration + privacy policy covering third-party
  health-data sharing.

---

## 2. Clinical evidence base — what psychology validates for personalized detection

Evidence grades: **[S]trong** (meta-analytic or large-scale replication), **[M]oderate**
(prospective studies, consistent), **[E]merging** (plausible, partial replications),
**[C]aution** (group-level only, or replication concerns).

### 2.1 Methodology (how to compute — governs everything else)

| Standard | Source | Implication for the brain |
|---|---|---|
| **[S] Within-person centering** — associations on deviations from the person's own mean, never pooled raw scores | Bolger & Laurenceau 2013, *Intensive Longitudinal Methods*; Shiffman, Stone & Hufford 2008 (EMA canonical design) | Replace raw mood-correlation input with per-user detrended residuals (e.g., subtract a rolling personal baseline). This kills our demonstrated false-positive mode. |
| **[S] Idiographic > nomothetic** — group-level structures often don't describe the individual (non-ergodicity); personalized models required | Fisher, Medaglia & Jeronimus 2018, *PNAS* 115(27) (non-ergodicity); Wright & Woods 2020, *Annu Rev Clin Psychol* 16:49–74 (personalized models of psychopathology); Fried et al. 2023 WARN-D protocol | Our per-user engine is architecturally right; frame it as "idiographic, within-person" — that language is the accepted standard. |
| **[S] Momentary vs retrospective are different measures** | Stone & Shiffman 2002 | Tag entries as momentary ("right now") vs end-of-day; don't mix streams silently. |

### 2.2 Mood dynamics (what to detect)

| Signal | Evidence | Notes for the brain |
|---|---|---|
| **EWMA control chart, personal baseline** | **[S]** Snippe et al. 2024, *J Psychopathol Clin Sci* (foresaw recurrence in patients tapering antidepressants); Smit, Schat & Ceulemans 2023, *Assessment* (methods paper: λ ≈ 0.05–0.25 on day-averaged EMA, person-specific limits) | Already implemented. Note: their λ is much smaller than our 0.3 → smoother, fewer false alarms. Restlessness was the idiographic prodrome — multi-signal EWMA (per-theme mood, not just global) is the validated extension. |
| **Mood inertia (lag-1 autocorrelation)** | **[S]** Kuppens, Allen & Sheeber 2010; Koval et al. 2012; Houben et al. 2015 meta-analysis (*Psychological Bulletin*): inertia/instability ↔ lower wellbeing, prospective prediction of onset | New detector, trivially computable on daily sentiment series: "your mood has been carrying over day-to-day more than usual." |
| **Affective instability (variance/switch frequency)** | **[M]** Henry 2012; Stange 2016; Taylor 2021 (bipolar prospective) | Surface as *observation* ("bigger swings than your usual"), never "bipolar flag" — individual cutoffs unvalidated, diagnosis language crosses FDA line. |
| **Critical slowing down (rising autocorr + variance before transition)** | **[C]** van de Leemput et al. 2014, *PNAS*; mixed replications (2024 *Clinical Psychological Science* replication: ~33% of participants; Wichers 2016 N-of-1 success; Helmich 2024 methodological critique) | Use only as a *supporting* signal bundled with EWMA, or skip. Never as a standalone claim. |
| **Personal early-warning signs (prodromes)** | **[M]** Birchwood et al. 2000 (EWS paradigm); Morriss et al. 2018 Cochrane (EWS + action plan reduces relapse); individualized signs appear weeks ahead | Product feature more than algorithm: let users mark "this feels like the start of a dip for me" and monitor *their* marked pattern specifically. Pairs detection with an action plan — the evidence-based wrapper. |

### 2.3 Temporal rhythms (what to detect)

| Signal | Evidence | Notes |
|---|---|---|
| **Day-of-week mood variation** | **[S]** Golder & Macy 2011, *Science* (509M tweets, 84 countries); Bryson & MacKerron 2017 Mappiness (*Economic Journal*) | Validates our temporal detector's premise; also mandates **removing weekly/daily cycles before computing other associations** (they're confounders, like the trend). |
| **Time-of-day (diurnal) mood variation** | **[S]** Golder & Macy 2011 (positive affect peaks morning, shifts later weekends); classic diurnal-variation depression literature (worse on waking) | Requires client to send time-of-day (audit finding #4). Morning-worse/evening-worse asymmetry is a clinically meaningful signature — phrased as observation only. |
| **Routine regularity (Social Rhythm Metric)** | **[M]** Monk et al. 1990 (SRM); Frank et al. 1997 (*Biological Psychiatry*): IPSRT (regularizing routines) reduced recurrence in bipolar; SRM-5 short form | Regularity of *journaling itself* + mentioned anchor events (wake/bed/meals) is computable from our data. "Your writing times have drifted later over the past two weeks" is an SRM-flavored observation. |
| **Seasonality** | **[M]** Rosenthal 1984 (SAD); Golder & Macy 2011 (daylength effect at scale) | Month-of-year as a detrend covariate; a gentle seasonal note only for users with clear year-over-year data (we won't have 12 months for a long time — fine). |

### 2.4 Lagged daily associations (the links nobody else ships)

| Signal | Evidence | Notes |
|---|---|---|
| **Sleep → next-day mood (stronger than reverse)** | **[S]** Konjarski et al. 2018, *Sleep Medicine Reviews* 42 (meta-analysis of experience-sampling/daily-diary studies); Triantafillou et al. 2019; Difrancesco et al. 2021 | Lag-1/lag-2 within-person cross-correlation between theme-days and next-day mood. Our audit's recommendation #3, now meta-analytically grounded. Phrasing: "the day after 'sleep' comes up, your entries read lower" — observation, causality never claimed. |
| **Stress spillover / slow recovery** | **[S]** Bolger, DeLongis, Kessler & Wethington 1989 (classic 42-day diary); daily-stress literature | Stressor-theme day → mood not recovered next day = "slow recovery" link. |
| **Physical activity → same/next-day affect** | **[S]** Liao, Shonkoff & Dunton 2015 review | Our 'health' theme partially proxies activity; with wearable data (later) this strengthens. |

### 2.5 Language markers (journal-text features)

| Feature | Evidence | Notes |
|---|---|---|
| **Absolutist words** ("always", "never", "completely", "must") | **[M]** Al-Mosaiwi & Johnstone 2018, *Clinical Psychological Science*: ~50% elevated in anxiety/depression forums, ~80% in suicidal-ideation forums; still elevated in recovery forums | Easy deterministic density metric; show as a *self-reflection* observation ("your writing has leaned on 'always/never' words more this month"), never a risk score. **Safety interplay:** sustained spikes should soften crisis-resource visibility, not diagnose (see §4). |
| **First-person singular pronouns ("I" density)** | **[M]** Edwards & Holtzman 2017 meta-analysis (small-moderate group effect) | Weak individually; one feature among many, never surfaced alone. |
| **Repetitive negative thinking / rumination** | **[S] construct; [E] text-detection** Ehring & Watkins 2008 (transdiagnostic RNT); Rosenkranz et al. 2020 (EMA assessment) | Our MinHash/LSH near-duplicate clustering is already a rumination detector in disguise: cluster negative-valence recurring phrases → "the same worry has returned N times across M weeks." Framing it with RNT science turns a gimmick into the clinically-richest pattern kind we have. |
| **Emotion differentiation/granularity** | **[M]** Kashdan, Barrett & McKnight 2015; Kalokerinos 2019; Erbas et al. 2022 (momentary ED validated in EMA) | With NRC EmoLex: per-entry emotion distribution → granularity index (negative-emotion differentiation). "You described this week's low feelings with four different words; earlier weeks used one" — no competitor does this from free text. |
| **LIWC categories** | Standard in psych research (Pennebaker et al. 2007/2015) | LIWC is commercial; NRC EmoLex + VADER cover the same ground open-licensed for our use. |

### 2.6 Journaling itself (product-level evidence)

- **Expressive writing**: Pennebaker & Beall 1986; Frattaroli 2006 meta-analysis (146
  studies, r ≈ .075 — real but small; more sessions & spacing → larger effects). Niles
  et al. 2013/2016: benefits not limited to high-expressives; brief distress during
  writing is common and transient — evidence-aligned copy for our onboarding.
- **Gratitude journaling**: Emmons & McCullough 2003 (modest, contested but widely
  adopted). Defensible as an *occasional* prompt variant.
- **Positive-affect journaling**: Smyth et al. 2018 RCT (*JMIR Mental Health*) — reduced
  stress/anxiety/depressive symptoms in medical patients.
- **Question quality**: our question engine's "one reflective question/day" maps to
  meaning-making/narrative prompts (the active ingredient per Niles/Pennebaker);
  evidence supports referencing the user's actual patterns (personalization), which we
  do — expanding template pools and anchoring questions in observed dates is aligned.

### 2.7 Measurement standards

- **PANAS** (Watson, Clark & Tellegen 1988) is the affect standard; **circumplex**
  (Russell 1980; Posner et al. 2005): valence × arousal — two sliders capture affect
  economically. Single-item mood measures are psychometrically defensible (Verster 2021;
  Allen 2022; Song 2023). What v1 actually ships: a daily mood score DERIVED from entry
  text (the deterministic graded lexicon), with an optional client-computed sentiment
  tag honored when present — no self-report slider exists yet; adding one (and a second
  "energy" slider for the circumplex) is planned work that would give EWMA a second
  validated channel.
- **PHQ-9** thresholds 5/10/15/20 (Kroenke et al. 2001); MCID ≈ 4–5 points (Löwe 2006;
  Bauer-Staeb 2021). We don't administer screeners (and shouldn't, wellness-framed) —
  but our *internal* "is this shift meaningful" bar should borrow the MCID mindset:
  define a minimum meaningful within-person shift, not just statistical significance.
- **EMA phrasing**: 0–10 or 7-point sliders with concrete anchors; momentary ("right
  now") vs "today overall" are distinct streams (Stone & Shiffman 2002).

---

## 3. Sentiment/emotion NLP standards (deterministic path)

| Instrument | What it gives us | License | Fit |
|---|---|---|---|
| **VADER** (Hutto & Gilbert 2014) | ~7,500-word graded lexicon + deterministic rules: intensifiers (×0.95–×1.5), graded negation (damped flip, ±3-token window), punctuation/caps/emoji emphasis; compound score −1..1 | MIT | Drop-in replacement for our 120-word hand lexicon; same determinism guarantees; validated on informal text (journal register). |
| **AFINN-111** (Nielsen 2011) | 2,477 words with integer valence −5..+5 | Open (ODbL-ish, cite paper) | Simplest upgrade; no rules — combine with VADER-style rule layer. |
| **NRC EmoLex** (Mohammad & Turney 2010/2013) | ~13,900 words → 8 emotions + 2 sentiments | Free for research; commercial license from NRC | Enables emotion-granularity features and per-emotion EWMA channels. Check license before shipping commercially. |
| **NRC VAD / Emotion Intensity** | Valence-arousal-dominance; per-emotion intensity | Same terms | Arousal channel for circumplex alignment without asking a second slider. |

Recommendation: **VADER as the sentiment engine** (deterministic, tested, MIT), theme
lexicon kept as-is (it's a *topic* model, not sentiment), **NRC EmoLex layered for
emotion granularity** once licensing is confirmed.

---

## 4. Safety, ethics & regulatory (the table stakes we currently miss)

### 4.1 Where we stand vs. the 2026 checklist

| Requirement | Standard/source | Us today |
|---|---|---|
| Crisis resources reachable in 1–2 taps from anywhere; 988 call/text/chat + Crisis Text Line 741741 + 911 guidance; offline-cached | 2026 Frontiers framework; APA advisory; only ~35% of apps comply | **Missing entirely** |
| Safe-messaging-compliant response to self-harm/suicidal content; route to humans, never AI reassurance | #chatsafe (Orygen/JED); Illinois WOPR Act (2025) mandates escalation for behavioral-health AI; character.ai litigation ongoing | Missing (our LLM path returns `[]` on any failure — silent) |
| Persistent "not a medical device / not an emergency service" disclaimer | Apple 1.4.1; Youper pattern; FDA boundary | Partial (footnote in Insights screen) |
| No diagnosis/treatment/relapse-*prediction* claims | FDA general-wellness line; AMA; APA; NICE ESF Tier B posture | Mostly good — but README phrasing ("foreseeing depressive recurrence") flirts with the line; keep the citation, soften the claim to "detects sustained shifts" |
| Granular, withdrawable opt-in per processing purpose (pattern analysis vs LLM), never bundled | GDPR Art. 9 explicit consent; Washington MHMDA opt-in; FTC orders | Good (re-auth for LLM enable) — add named-provider/retention/no-training disclosure at the consent screen |
| No "anonymous" claims unless defensible | FTC skepticism (BetterHelp $7.8M; Cerebral ~$7M; GoodRx $1.5M; Monument) | Fine |
| Deletion extends to third parties users consented to | FTC Cerebral/Monument orders (direct third-party deletion) | Documented gap in README (LLM provider retention "out of our hands") — needs a provider with contractual deletion/Zero-Data-Retention |
| AI disclosure ("AI, not human") at first use + store listing | Illinois WOPR; emerging norm | N/A (we're not conversational) but the LLM analyzer consent copy should carry it |

### 4.2 The privacy paradox to manage

Our marketing is "client-side encryption, server blind to content" — with a documented
deliberate exception (single-use processing session) and an opt-in LLM exception. The
BetterHelp precedent says the enforcement risk is *the gap between marketing and
practice*, not the practice itself. Our consent flow must make the exception loud.
Longer term, on-device analysis (the README already names it as the path) is both the
industry direction (Apple Foundation Models, iOS 26) and the clean end-state; the
deterministic brain ports to the client unchanged — it's pure functions over JSON.

### 4.3 Crisis design decision (needed before v3 ships)

Standard-pattern stepped model for a journaling app: (1) crisis resources always
reachable from Settings + Insights; (2) if the *deterministic* analyzer (never the LLM)
notices sustained severe-negative language, gently surface the resources card — never a
diagnosis, never an alarm, never a push notification about crisis content. This is the
"5 types of crisis support" ladder Wysa is credited with; even implementing rungs 1–2
moves us from the non-compliant 65% to the compliant 35%, and it is the single most
judge-visible safety upgrade.

### 4.4 Self-harm/ED adjacency — the two-tier suppression philosophy

The crisis-language contract (shared/crisis_phrases.json) runs two deliberately
asymmetric tiers. The **dialog tier** (client-side, pre-encryption, fires the support
dialog) stays conservative: a false positive there costs one gentle dialog, so it is
phrase-anchored and mostly first-person ("cutting myself", "want to die"). The
**suppress tier** (dialog + `suppress_extra`; server-side card sensitivity + question
filter, client-side non-quoting belt) is deliberately broader, because a false positive
there only means a pattern is not *quoted back* — the card still surfaces, in the
gentle non-quoting variant.

Bare topic words ("cutting", "self-loathing") and eating-disorder phrasing ("starve
myself", "make/made myself throw up") belong to the suppress tier only. The 2026
re-audit showed why: a corpus whose last month read "the urge for cutting was loud"
produced a *quoted* "'cutting' has been taking up more space…" topic card and quoted
engagement questions — mirroring crisis-adjacent wording back as an invitation to
engage. For a user journaling recovery from anorexia or self-harm, the right artifact
is the non-quoting card that acknowledges a difficult thought and points at humans —
never an algorithmically mirrored prompt to sit with it.

The honest residual: single-word suppression over-triggers on benign topics ("cutting
back on sugar", "a cutting board", "I burned myself on the stove"). Those patterns
render as the soft non-quoting card — a missed quote, not a dialog, not an alarm. We
accept that asymmetry on purpose: the cost of a false positive is a slightly vaguer
card; the cost of a false negative is quoting self-harm ideation back to the person
who wrote it.

---

## 5. Mapping: evidence → v3 mini-brain changes

Prioritized by (evidence strength × impact on insight quality × implementation cost):

| # | Change | Evidence anchor | Cost |
|---|---|---|---|
| 1 | **Within-person detrending before all mood associations** (rolling personal baseline; also detrend weekly cycles) | Bolger & Laurenceau 2013; Golder & Macy 2011 | S — fixes the false-positive class we demonstrated |
| 2 | **VADER sentiment engine** replacing the hand lexicon | Hutto & Gilbert 2014; industry NLP standard | S |
| 3 | **Lagged link detector** ("the day after X, your entries read Y"; lag-1/lag-2, within-person) | Konjarski et al. 2018 meta; Bolger et al. 1989 | M — new pattern kind `link` |
| 4 | **Mood-inertia + instability metrics** (rolling autocorrelation/variance of daily sentiment) | Houben et al. 2015 meta; Kuppens et al. 2010 | S — new pattern kind `inertia` |
| 5 | **Rumination framing for phrase clusters** (negative-valence recurring near-duplicates → RNT observation with distinct copy + question templates) | Ehring & Watkins 2008; Al-Mosaiwi 2018 (absolutist density inside clusters) | S — mostly copy + one metric |
| 6 | **Time-of-day capture + diurnal pattern kind** (client sends local time bucket; morning/evening asymmetry detection) | Golder & Macy 2011; diurnal-variation literature | M — touches client payload (v2 payload already versioned) |
| 7 | **Emotion granularity** (NRC EmoLex; negative-ED index over time) | Kashdan et al. 2015; Erbas 2022 | M — license check first |
| 8 | **Routine-regularity observation** (journaling-time drift, anchor-event regularity) | Monk 1990 SRM; Frank 1997 | S |
| 9 | **EWMA tuning**: λ 0.3 → ~0.15–0.2, per-theme channels, baseline = stabilized running estimate not oldest-third | Smit, Schat & Ceulemans 2023 methods paper | S |
| 10 | **Temporal test selection-bias fix** (all-7-weekdays into BH family) | Standard multiple-testing practice | S |
| 11 | **Crisis resources + stepped safe-messaging design** | §4.3; APA/Wysa/#chatsafe | M |
| 12 | **Pre-threshold value**: mood sparkline + streaks + top-words (client-side, no decryption — keeps threshold honesty) | §1.2 activation norm; MindDoc precedent | M |
| 13 | **Confidence framing in UI** (render lifecycle as Daylio-style evidence labels; "based on your last N weeks") | Daylio pattern; APA transparency | S |
| 14 | **Question engine expansion** (pattern-anchored, date-referencing, occasional gratitude/meaning prompts referencing Pennebaker/Emmons mechanisms) | Smyth 2018; Emmons 2003; Niles 2013 | S |

Explicitly **not** doing (evidence/regulatory): critical slowing down as a standalone
claim (mixed replications), bipolar language of any kind, relapse-*prediction* claims
(FDA line), PHQ-style screeners (Tier C drift), passive sensing (privacy posture is our
moat), LLM-generated insight claims without the deterministic core underneath.

---

## 6. Bibliography (by section)

**§1 Industry:** daylio.net (+ /faq/activity-and-mood-statistics); howwefeel.org;
reflectlyapp.com; getstoic.com; minddoc.com/us/en/faq; youper.ai/emergency; wysa.com;
bearable.app; emoodtracker.com/features; reflection.app/blog/ai-journaling-apps-compared;
mindsera.com; psychiatry.org/psychiatrists/practice/mental-health-apps/the-app-evaluation-model;
onemindpsyberguide.org; appfinder.orcha.co.uk/about;
nice.org.uk/.../evidence-standards-framework-esf-for-digital-health-technologies;
bfarm.de (DiGa); fda.gov general-wellness guidance;
apple.com/newsroom/2025/09/apples-foundation-models-framework...;
pmc.ncbi.nlm.nih.gov/articles/PMC8558599/ (PsyberGuide methodology);
pmc.ncbi.nlm.nih.gov/articles/PMC10632923/ (MindDoc).

**§2 Clinical:** Shiffman, Stone & Hufford 2008 (*Annu Rev Clin Psychol*);
Stone & Shiffman 2002 (*Ann Behav Med*); Bolger & Laurenceau 2013 (*Intensive
Longitudinal Methods*, Guilford); Fisher, Medaglia & Jeronimus 2018 (*PNAS*
115(27)); Wright & Woods 2020 (*Annu Rev Clin Psychol* 16:49–74, personalized
models); Fried et al. 2023 WARN-D (*Clin Psychol Sci*); Snippe et al. 2024 (*J
Psychopathol Clin Sci*); Smit, Schat & Ceulemans 2023 (*Assessment* 30(5)); Schreuder et al. 2024;
van de Leemput et al. 2014 (*PNAS* 111(1)) + 2014 critique letter + Wichers 2016
(*Psychosom Psychother*) + 2024 replication (*Clin Psychol Sci*); Kuppens, Allen &
Sheeber 2010 (*Psychol Sci* 21(7)); Koval et al. 2012 (*Cogn Emot*); Houben et al.
2015 (*Psychol Bull* 141(4):901–930); Birchwood, Spencer & McGovern 2000 (*Adv Psychiatr
Treat*); Morriss et al. 2018 (Cochrane); Golder & Macy 2011 (*Science* 333);
Bryson & MacKerron 2017 (*Econ J*, Mappiness); Monk et al. 1990 (SRM); Frank et al.
1997 (*Biol Psychiatry*); Rosenthal et al. 1984 (*Arch Gen Psychiatry*);
Konjarski et al. 2018 (*Sleep Med Rev* 42, meta-analysis); Triantafillou et al. 2019
(*JMIR Ment Health*); Difrancesco et al. 2021 (*J Affect Disord*); Liao, Shonkoff &
Dunton 2015 (*Front Psychol*);
Al-Mosaiwi & Johnstone 2018 (*Clin Psychol Sci* 6(2)); Edwards & Holtzman 2017
(*J Res Pers*); Kashdan, Barrett & McKnight 2015 (*Curr Dir Psychol Sci*); Erbas et al.
2022 (*Assessment*); Ehring & Watkins 2008 (*Int J Cogn Ther*); Rosenkranz et al. 2020;
Pennebaker & Beall 1986 (*J Abnorm Psychol*); Frattaroli 2006 (*Psychol Bull* 132);
Niles et al. 2013/2016; Emmons & McCullough 2003 (*JPSP* 84(2)); Smyth et al. 2018
(*JMIR Ment Health* 5(4)); Watson, Clark & Tellegen 1988 (*JPSP* — PANAS); Russell
1980 (*JPSP*); Posner, Russell & Peterson 2005; Kroenke, Spitzer & Williams 2001
(*J Gen Intern Med*); Löwe et al. 2006; Bauer-Staeb et al. 2021 (*J Clin Epidemiol*);
Verster et al. 2021; Allen et al. 2022; Song et al. 2023 (*Assessment*).

**§3 NLP:** github.com/cjhutto/vadersentiment; nltk.org/_modules/nltk/sentiment/vader.html;
Hutto & Gilbert 2014 (ICWSM); Nielsen 2011 (arxiv.org/abs/1103.2903, AFINN);
saifmohammad.com/WebPages/NRC-Emotion-Lexicon.htm; nrc.canada.ca (lexicon licensing);
Mohammad & Turney 2010/2013.

**§4 Safety/regulatory:** fda.gov general-wellness guidance + 2026 draft update;
FTC: BetterHelp (2023, $7.8M), GoodRx (2023, $1.5M), Cerebral (2024, ~$7M), Monument
(2024); ftc.gov/business-guidance/resources/mobile-health-apps-interactive-tool;
gdpr-info.eu/art-9-gdpr; Washington MHMDA (RCW 19.373, eff. 2024); California CMIA
(AB 2089/352); developer.apple.com/app-store/review/guidelines/ (1.4.1);
support.google.com (Play health declaration); who.int 2021 AI guidance + 2024 LMM
guidance; apa.org Nov-2025 health advisory on AI chatbots/wellness apps;
ama-assn.org AI-chatbot positions; Illinois WOPR Act (HB 1806, PA 104-0054, 2025);
Utah HB 452; character.ai litigation (ongoing; Fortune/JURIST coverage); Orygen #chatsafe
(+ PMC10395901); Wysa crisis-support research (blogs.wysa.io; PMC6286427);
mental.jmir.org/2024/1/e52763 (safety planning); Frontiers 2026 crisis-UX framework
(fdgth.2026.1814547); openai.com/enterprise-privacy (+ ZDR); nice.org.uk ESF tiers;
dimesociety.org/access-resources/v3/; nature.com/articles/s41746-024-01322-2.
