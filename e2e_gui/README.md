# Manual browser drill fixtures

These scripts create synthetic accounts in a disposable local development
instance. They use the real client cryptography and also modify database
timestamps directly to exercise threshold and history views.

| Script | Purpose |
| --- | --- |
| `seed_patients.py` | Baseline and insight-phase patients for browser walkthroughs |
| `seed_caseload.py` | Therapist caseload, sharing states, measures, and note history |
| `seed_sensitive_caseload.py` | Additional sensitive-pattern patient and varied timestamps; run after the caseload seed |

Run with the backend virtual environment, for example:

```sh
backend/.venv/bin/python e2e_gui/seed_patients.py --help
```

Each script documents its arguments and synthetic credentials. Existing accounts
are generally skipped; use a fresh database to repeat a clean drill. The
[dated GUI report](GUI_DRILL_REPORT_2026-09-28.md) records the original scenarios.
These are manual fixture tools, not the automated regression suite, and may need
scenario updates when authentication or consent workflows change.

The caseload scripts were previously named `audit_seed.py` and `audit_seed2.py`.
