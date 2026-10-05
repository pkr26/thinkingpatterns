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
- **Evaluated scope**: onboarding, journaling, threshold explanations and
  comprehension of investigator-supplied sample cards. A new account needs
  30 distinct active journaling days before personal analysis unlocks. Four
  weeks cannot meet that threshold even with daily writing; the suggested
  three-times-weekly cadence is also insufficient. This protocol therefore
  does not evaluate participants' own generated observations or post-unlock
  workflows. Those endpoints require a separately reviewed longer protocol
  with enough active days and subsequent experience; the app's production
  threshold remains unchanged.
- **N**: 30 adult journal users (18+), balanced for Spanish/English
  locale; proposed qualitative sample, with thematic sufficiency assessed
  and reported rather than assumed. Quantitative statistics are descriptive only.
- **Arms**: none (single-arm). Optional extension: masked review of the
  pattern-card comprehension task by 2 clinicians for content-validity
  ratings only.
- **Setting**: remote; participants use their own devices and their own
  accounts. There is no study server and no study collection beyond the
  instruments below. Investigators never request journal content or receive
  an app decryption key. The app encrypts content on the client for storage
  and sync. Requested server analysis is a disclosed processing exception:
  the app sends its data key to a single-use session lasting at most five
  minutes, and the server decrypts and analyzes content in process. This is
  not hardware-enclave protection. Separately consented voice transcription
  and translation can send recordings/text to configured providers. Study
  staff access, server processing and provider processing are distinct; the
  consent materials must explain them using the deployed configuration.

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
| Acceptability of the 30-active-day threshold explanation | ad-hoc 5-item (clarity, expected burden, trust; pilot and report reliability); does not measure completed threshold experience | week 2 + 4 |
| Sample-card comprehension | ad-hoc comprehension task: interpret 3 investigator-supplied sample cards; no participant's generated observations | week 4 |
| Engagement (self-reported, privacy-preserving) | self-reported frequency; NO app telemetry exists to harvest — the app collects none | all sessions |
| Qualitative experience | semi-structured interview (~30 min) | week 4 |

## 4. Data handling consistent with the product's claims

- The study collects NO journal content and NO app-derived data. Measures
  are administered outside the app and include SUS, study-specific items,
  sample-card tasks and interviews; the study-specific items are not presented
  as standardized instruments.
- Informed-consent materials state that investigators cannot read journal
  content through the study, and describe the client encryption and optional
  server/provider processing boundaries above. Deleting an account removes
  live account content; earlier encrypted backups and access-audit metadata
  follow the deployed retention schedule. Do not promise immediate removal
  from every backup or provider. Review the [retention schedule](DATA_RETENTION_SCHEDULE.md)
  and configured provider disclosures before recruitment.
- Interviews are recorded with consent, transcribed, de-identified;
  retention 7 years per institutional policy.

## 5. Analysis plan

- Descriptive statistics (median, IQR) for SUS and acceptability;
  proposed benchmark for future pre-registration: SUS ≥ 68. No completed
  pre-registration is claimed by this draft.
- Sample-card comprehension task: % of participants who correctly describe
  what the supplied cards claim (observations, not diagnoses); proposed
  benchmark ≥ 80%. This endpoint measures comprehension of those materials,
  not validity or usefulness of personal generated observations.
- Thematic analysis (Braun & Clarke) of interviews; two coders, κ
  reported.

## 6. Ethics

- Risk classification remains for the reviewing institution to determine;
  proposed safeguards include no deception and withdrawal at any time. The
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
X (SUS) and Y% correctly described three supplied sample cards as
observations rather than diagnoses." These results do not establish
post-unlock personal-pattern usability or longitudinal usefulness.
No efficacy claims, no clinical
outcome claims, no wellness-outcome claims beyond self-reported
acceptability.
