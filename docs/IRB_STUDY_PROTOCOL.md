# IRB-reviewed usability study protocol (Phase 3, 2026-09-21)

Purpose: convert the PsyberGuide self-assessment (docs/
PSYBERGUIDE_SELF_ASSESSMENT.md) into publishable, IRB-reviewed evidence.
This document is the protocol draft an IRB reviews; it is written for a
minimal-risk, no-PHI behavioral study of the app AS SHIPPED.

## 1. Design

- **Type**: single-arm, mixed-methods usability + acceptability study,
  4 weeks of naturalistic app use + 3 structured sessions (baseline,
  week 2, week 4).
- **N**: 30 adult journal users (18+), balanced for Spanish/English
  locale; powered for thematic saturation on the qualitative strand,
  descriptive statistics only on the quantitative strand.
- **Arms**: none (single-arm). Optional extension: masked review of the
  pattern-card comprehension task by 2 clinicians for content-validity
  ratings only.
- **Setting**: remote; participants use their own devices and their own
  accounts. No study server, no data collection beyond the instruments
  below — the app is zero-knowledge and STAYS that way: the study never
  requests journal content, and no decryption capability is extended to
  investigators.

## 2. Inclusion / exclusion

- Inclusion: 18+, owns a smartphone, willing to journal ≥3×/week for 4
  weeks, fluent in English or Spanish.
- Exclusion: current suicidal ideation requiring active treatment
  (screened at baseline with the same self-report gate the app itself
  uses; positive screens receive the same crisis-resource referral
  PLUS a documented referral out of the study), or participation in
  concurrent psychotherapy research.

## 3. Measures (all participant-reported, outside the app)

| Construct | Instrument | When |
|---|---|---|
| System usability | SUS (10-item) | week 4 |
| Acceptability of the 30-day threshold | ad-hoc 5-item (clarity, burden, trust; piloted, Cronbach reported) | week 2 + 4 |
| Perceived utility of pattern cards | ad-hoc comprehension task: interpret 3 sample cards | week 4 |
| Engagement (objective, privacy-preserving) | self-reported frequency; NO app telemetry exists to harvest — the app collects none | all sessions |
| Qualitative experience | semi-structured interview (~30 min) | week 4 |

## 4. Data handling consistent with the product's claims

- The study collects NO journal content and NO app-derived data. Every
  measure is a standard instrument administered outside the app.
- The zero-knowledge architecture is itself a study material: the
  informed-consent form states that investigators CANNOT read journal
  content and that deleting the account deletes the data.
- Interviews are recorded with consent, transcribed, de-identified;
  retention 7 years per institutional policy.

## 5. Analysis plan

- Descriptive statistics (median, IQR) for SUS and acceptability;
  pre-registered benchmark: SUS ≥ 68 (above-average usability).
- Comprehension task: % of participants who correctly describe what a
  card does and does NOT claim ("observed pattern", not diagnosis);
  benchmark ≥ 80% — this is the published-claims gate for "honest
  cards".
- Thematic analysis (Braun & Clarke) of interviews; two coders, κ
  reported.

## 6. Ethics

- Minimal risk classification; no deception; withdraw-anytime; the
  crisis resources are one tap away at all times (and the screen is
  offline static content).
- The app never interprets scores or gives advice — the protocol does
  not change that; comprehension materials must not either.
- IRB of record: the investigators' institution; this draft is the
  submission base. ClinicalTrials.gov registration is NOT expected
  (not a clinical intervention), but OSF pre-registration of the
  analysis plan is.

## 7. Conversion path to published claims

Passing the benchmarks licenses claims of exactly this shape: "In a
4-week single-arm usability study (N=30), participants rated the app
X (SUS) and Y% correctly described the app's pattern cards as
observations rather than diagnoses." No efficacy claims, no clinical
outcome claims, no wellness-outcome claims beyond self-reported
acceptability.
