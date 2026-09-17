# One Mind PsyberGuide self-assessment — MindPattern

PsyberGuide's three criteria: **credibility, user experience, data
security** (expert scores do not track star ratings — Neary et al. 2021:
161 reviewed apps averaged 2.51/5 on credibility). This document is the
submission-ready self-assessment; every claim is testable in this repo.

## Credibility

- **No therapeutic claims**: the product boundary is observational —
  pattern observations with evidence panels (n, effect size, corrected
  p-value, plain-language method), no advice, no diagnosis, no
  prediction. Enforced by tests (question templates must be questions;
  the word "should" is banned from the pool; crisis content never
  surfaces as prompts).
- **Methods cited**: every detector maps to literature in RESEARCH.md
  (within-person centering per Bolger & Laurenceau; sleep→affect per
  Konjarski 2018; EWMA charts per Smit/Schat/Ceulemans 2023; rumination
  clustering per Ehring & Watkins 2008...).
- **Honest statistics**: Benjamini–Hochberg correction across every
  simultaneous claim, replication gating, effect-size floors, a
  ground-truth probe (9/9) and a 60-day noise-control simulation (zero
  false cards) — all CI-gated.

## User experience

- Calm-tone design: no streak-shaming, no loss-framed notifications
  (reminders land only when the native module ships, opt-in, local-only),
  lapse-tolerant framing, crisis help one tap from every screen.
- Transparency UX: "Why am I seeing this?" panels; the 30-day threshold
  explained at the moment of waiting; consent flows that say what the
  LLM path means before asking for a password re-auth.
- Accessibility: WCAG-AA contrast test-pinned, VoiceOver labels, 44pt
  targets; dynamic type still partial (documented gap).

## Data security

- Client-side AES-256-GCM with AAD binding; keys derived on device
  (PBKDF2 600k); server stores scrypt(verifier) only.
- Zero-knowledge therapist sharing (ECDH→HKDF wrap); read-only by
  endpoint absence; full access audit log.
- Cross-platform crypto pinned byte-for-byte (backend ⇄ mobile ⇄ portal,
  incl. edge-case AAD vectors in CI).
- Known, documented residuals: AsyncStorage device-key custody pending
  Keychain; plaintext during the processing window; metadata visibility.

## Submission checklist

- [ ] Privacy policy URL (the in-app offline copy is the source)
- [ ] App store privacy nutrition labels (data: journal text, entered by
      user, encrypted; no tracking, no third-party SDKs)
- [ ] Research summary = RESEARCH.md
- [ ] Point of contact for the expert review
