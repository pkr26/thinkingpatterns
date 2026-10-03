# Draft usability study protocol for institutional review

Status as of October 3, 2026: proposed protocol; no institutional approval,
registration, recruitment, clinical review or completed study is recorded.
Risk classification, screening/referral procedures, investigator roles,
retention, consent and recruitment require the reviewing institution's
determination before study execution. The engineering validation plan is
in [VALIDATION_TO_90.md](VALIDATION_TO_90.md).

Purpose: convert the PsyberGuide self-assessment (docs/
PSYBERGUIDE_SELF_ASSESSMENT.md) into publishable, IRB-reviewed evidence.
This document is a submission draft. Its proposed privacy controls do not
establish a minimal-risk classification or a legal no-PHI determination.

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
- Exclusion: current suicidal ideation requiring active treatment.
  Screened at baseline with validated instruments per standard
  behavioral-research practice — **PHQ-9 item 9 endorsement (score ≥1)**
  (Kroenke et al. 2001) **AND** the **Columbia-Suicide Severity Rating
  Scale (C-SSRS) screener version** (Posner et al. 2011) — NOT the app's
  own crisis-language phrase gate (which is a conservative client-side
  suppression heuristic, not a validated screening instrument, and
  cannot serve as an eligibility gate). Either positive screen refers
  the participant out of the study with the same crisis-resource
  referral PLUS a documented clinical referral; the C-SSRS
  ideation-behavior severity items govern the referral path (passive
  ideation → resources + study-team clinical consultant same-day
  review; active ideation or any behavior → immediate referral and
  exclusion). Re-screen at week 2 and week 4 sessions with the same
  instruments; new positives keep the participant's data but trigger
  the referral path and a safety-protocol review. Participation in
  concurrent psychotherapy research is also exclusionary.

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

If approved and completed, the measured results could support a bounded
description of exactly this shape: "In a
4-week single-arm usability study (N=30), participants rated the app
X (SUS) and Y% correctly described the app's pattern cards as
observations rather than diagnoses." No efficacy claims, no clinical
outcome claims, no wellness-outcome claims beyond self-reported
acceptability.
