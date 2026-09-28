# Historical artifact — script not preserved

`run.log` (2026-09-16) records a 148-check live E2E campaign whose script
was never committed; only this log remains, so the "148/148 passed" claim
is not reproducible from the repo. It also predates most of the current
API surface (processing sessions, envelope v2, TOTP, notes, measures).

Superseded by `reports/simulation1y/` (2026-09-28): 245/245 checks over
all 52 mounted endpoints, script + log + results + timelines preserved
together and re-runnable.
