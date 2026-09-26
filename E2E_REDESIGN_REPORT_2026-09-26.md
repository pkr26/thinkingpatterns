# UI/UX Redesign — Verification Report (2026-09-26)

Warm & calming redesign of both web frontends, per the approved plan:
hand-crafted zero-dependency CSS token system, patient app light/dark
themes, portal re-tokenized onto the same architecture.

## What changed (patient app, `web/`)

- **Design system** — `public/app.css` grew from 31 lines to the full token
  layer (color/type/spacing/radius/elevation/motion) with `[data-theme="dark"]`;
  `src/tokens.ts` mirrors the palette for JS-drawn SVG charts (pinned to the
  CSS by `tests/designTokens.test.ts`, which also enforces WCAG ≥ 4.5:1
  contrast floors for every text role, both themes).
- **Typography** — self-hosted Nunito (4 latin weights, ~16 KB each,
  `font-src 'self'`, zero external requests), 1.6 line-height body.
- **Navigation** — desktop tabs + More menu; mobile bottom tab bar with
  safe-area padding; Sign-out lives in More. State-machine routing unchanged.
- **Today** — time-aware greeting, date, streak chip; the check-in is a
  visible one-tap card (5 faces for mood, 3 for energy, dots for sleep,
  chips for activities) — no longer hidden behind "Show details".
  Selection is aria-pressed sage + check icon, NEVER the danger color
  (the old red-selection bug is gone app-wide).
- **History** — calendar with weekday headers, legend, month count,
  tap-a-day filtering; entries as cards with mood rail; two-step delete;
  side-by-side conflict blocks.
- **Patterns / Measures** — SVG trend charts (dates, titles, last-score
  highlight), progress track for baseline and questionnaire completion,
  segmented instrument control.
- **Login** — brand panel, real `<form>` (Enter submits), password-strength
  meter fed by the existing policy checker, full-width primary action.
- **Crisis** — accessible overlay Dialog (focus-trapped, Esc close) instead
  of a view swap; the user's place survives. Copy unchanged (safety).
- **Settings** — sectioned (Appearance with Light/Dark/System switch,
  Privacy & data, Access log timeline, Account, red Danger zone).
- **Toasts/skeletons** replace the inline saved-notes; every new string
  went through the en/es catalogs.

## What changed (portal, `portal/`)

- `public/portal.css` token layer (dark clinical identity kept, refreshed
  palette); the previously MISSING `warn` token fixed (warn notes were
  rendering blue); ui kit class-based; App banners unified; caseload
  toolbar's raw input/select and PatientView's hand-styled
  inputs/textareas/template buttons moved to token classes; Account
  security panel sectioned; first-ever responsive rules.

## Verification

- **Web**: 465 tests passed (incl. jest-axe a11y suites, token-sync +
  contrast tests); `npm run build` green with SRI stamping.
- **Portal**: 342 tests passed; build green.
- **E2E browser campaign** (screenshots in `gui-test-screenshots/redesign_*.png`):
  full journey against the real backend — register (policy + strength meter),
  3-step onboarding, one-tap check-in + encrypted save with toast, calendar
  + entry, baseline patterns, question, PHQ-9 completion + trend chart,
  More menu, Share **end-to-end pairing with a live therapist portal
  account** (fingerprint verification, both attestations, grant card),
  Settings theme switch (light → dark verified live), crisis dialog
  open/close over intact content, 390px mobile viewport with bottom nav.
  Three findings found during the campaign were fixed and re-verified:
  login card width/centering + placeholders, header CTA hierarchy, and the
  redundant mobile "More" pill.

## Not changed (by design)

Functionality, zero-knowledge crypto, state-machine routing (no URLs),
CSP/SRI pipeline, EN/ES catalog mechanism, "Get help" one-tap-from-anywhere,
and the non-quoting sensitive-pattern contract.
