# Fathom web client (patient)

The patient-facing web app — the mobile app's journaling experience in
the browser, against the same FastAPI backend, with the same
zero-knowledge contract (keys derived in the client; the server only
ever stores opaque blobs). Built phase by phase per [`../WEB_PLAN.md`](../WEB_PLAN.md).

## Status

Shipped — see WEB_PLAN.md's status dashboard (all ten phases done
2026-09-25; P7/P10 independently E2E-verified by the black-box browser
pass of 2026-09-26). This package mirrors the therapist portal's stack and
discipline: React 19 + Vite + TypeScript strict, Vitest with coverage
thresholds, security headers pinned in three aligned places
(`index.html` meta, `public/_headers`, the nginx template) by test.

## Commands

```bash
npm ci
npm run dev        # :5173 with /api proxied to localhost:8000
npm test           # vitest + coverage thresholds
npm run typecheck  # tsc --noEmit
npm run build      # typecheck gates the production bundle
```

`WEB_API_PROXY` overrides the vite dev proxy target (default
`http://localhost:8000` — see `vite.config.ts`) for machines where the
backend port is taken.

The backend for local dev: see the root README's "Running" section
(`MINDPATTERN_ENV=development uvicorn app.main:app --port 8000`).
