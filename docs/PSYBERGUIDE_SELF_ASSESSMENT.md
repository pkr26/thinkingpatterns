# One Mind PsyberGuide self-assessment — Fathom

PsyberGuide's three criteria: **credibility, user experience, data
security** (expert scores do not track star ratings — Neary et al. 2021:
161 reviewed apps averaged 2.51/5 on credibility). This document is a
working self-assessment, not an independent PsyberGuide review. Real-device,
usability and clinical evaluation remain separate evidence requirements;
see the October 3 audit and remediation plan at the project root.

## Credibility

- **No therapeutic claims**: the product boundary is observational —
  pattern observations with evidence panels (n, effect size, corrected
  p-value, plain-language method), no advice, no diagnosis, no
  prediction. Enforced by tests (question templates must be questions;
  the word "should" is banned from the pool; crisis content never
  surfaces as prompts).
- **Methods cited**: every detector maps to literature in docs/research.md
  (within-person centering per Bolger & Laurenceau 2013 with per-weekday
  deconfounding; sleep→affect per Bourke et al. 2026 meta-analysis and
  Konjarski et al. 2018 systematic review; EWMA charts per Snippe et
  al. 2023 with the Smit/Schat/Ceulemans 2023 methods tutorial, control
  limit Monte-Carlo-calibrated to a ≤5% false-alarm probability;
  rumination clustering per Ehring & Watkins 2008...). These references
  motivate methods; they do not validate this app. True-parameter chart
  calibration is distinct from the deployed estimated-parameter detector.
  The October 3 detector-only diagnostic observed nominal p≤.05 rates
  from 0.4% to 6.7% across nine specified AR(1) cells (1,000 runs each),
  so a universal ≤5% guarantee is unsupported.
- **Honest statistics**: Benjamini–Hochberg correction across every
  simultaneous claim, replication gating, effect-size floors, and a
  ground-truth probe — CI-gated implementation checks. The historical
  60-day noise-control report (`reports/simulation60/`) uses a deterministic
  seed but its original results have not been re-established for the current
  engine. CI does not run that full replay. Smaller detector/noise regressions
  do not establish end-to-end user-level false-discovery control, independent
  replication on overlapping windows or clinical benefit.

## User experience

- Calm-tone design: no streak-shaming, no loss-framed notifications
  (opt-in local-only daily reminders, shipped — a stable notification
  id so a refreshed reminder replaces rather than stacks), 
  lapse-tolerant framing, crisis help one tap from every screen.
- Transparency UX: "Why am I seeing this?" panels; the 30-day threshold
  explained at the moment of waiting; consent flows that say what the
  LLM path means before asking for a password re-auth.
- Accessibility: WCAG-AA contrast test-pinned, VoiceOver labels, 44pt
  targets; dynamic type still partial (documented gap).

## Data security

- Client-side AES-256-GCM with AAD binding; keys derived on device
  (PBKDF2 600k; v2 accounts hold a random data key in a
  password-wrapped envelope); server stores scrypt(verifier) only
  (N=2¹⁷).
- Zero-knowledge therapist sharing (ECDH→HKDF wrap, out-of-band SAS
  verification of the pairing); read-only by endpoint absence; full
  access audit log with a per-patient forward hash chain.
- Cross-platform crypto pinned byte-for-byte FOUR ways (backend ⇄
  mobile ⇄ portal ⇄ web, incl. edge-case AAD vectors and
  cross-client interop fixtures, both in CI: the
  `web-contract-vectors` and `contract-gates` jobs).
- Known, documented residuals: plaintext during the processing window;
  metadata visibility. (The former AsyncStorage device-key residual is
  remediated: the session-token key is held only by iOS Keychain /
  Android Keystore with no AsyncStorage fallback, and sign-in fails
  closed if that native secure-storage seam is unavailable.)

## Submission checklist

Re-verified against the current tree in the 2026-09-26 documentation
pass; submission itself remains an operator step, so the boxes stay
open until the operator completes them.

- [ ] Privacy policy URL (a plain-language template mapped to the actual
      data flows ships at `docs/PRIVACY_POLICY_TEMPLATE.md` — complete
      its LEGAL-REVIEW placeholders and publish; the in-app offline copy
      is the source)
- [ ] App store privacy nutrition labels reconciled to the complete inventory:
      linked identifier, health/user/audio content, access/action and consent
      history (**Product Interaction**), and age-attestation/account metadata
      (**Other Data Types**, or the operator's documented current-taxonomy
      mapping); no tracking or third-party analytics SDKs. Retain dated
      Store Connect/Play Console evidence for the candidate build.
- [x] Research summary = docs/research.md *(exists; citations re-verified
      2026-09-26 and cross-checked against the shipped engine constants
      in `backend/app/services/brain.py`)*
- [ ] Point of contact for the expert review. The tagged web release generates
      `security.txt` only from validated operator variables and fails closed
      when they are absent; `docs/security.txt.example` remains a template for
      any additional served origin.
