# Independent latest-commit audit evidence

This directory records the independent audit of commit `ad797b060ac5de986e2eac6a044da8d6439a1c03` and the resulting fixes included in this follow-up commit. The findings, current verification and limits are in [the audit report](../../docs/archive/audits/AUDIT_LAST_COMMIT_2026-10-03.md).

- `backend/`: authentic original-HEAD negative controls, focused dual-dialect regressions, full-suite verification and source checks. Any pre-follow-up full run is explicitly labeled; it must be paired with the later focused checks.
- `mobile/`: owner/session, biometric, audio, native-wrapper and signed-summary regressions; final clean-install suite and actual native/bundle evidence.
- `web/` and `portal/`: regressions, final coverage suites, typechecks and built-artifact results. The web build log retains the correctly failing real-contact placeholder gate.
- `browser/`: real Chrome against HTTPS built artifacts and synthetic local fixtures, including password/custody changes and separate chart-history drafts.
- `operations/`: real PostgreSQL upgrade/encrypted backup restore, pinned monitoring/tooling/red-team and source/secret checks, plus owned-resource cleanup.

A `before-fix`, `red` or `original-head` log is deliberately failing negative-control evidence. Only completed current-scope checks support passing claims. Synthetic seed credentials, database URLs, local databases and private keys are excluded. Original remediation evidence remains in its original directory.
