# MindPattern web client (patient)

The patient-facing web app — the mobile app's journaling experience in
the browser, against the same FastAPI backend, with the same
zero-knowledge contract (keys derived in the client; the server only
ever stores opaque blobs). Built phase by phase per [`../WEB_PLAN.md`](../WEB_PLAN.md).

## Status

Phase 1 (scaffold & security baseline) — see WEB_PLAN.md's dashboard for
the current phase. This package mirrors the therapist portal's stack and
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

The backend for local dev: see the root README's "Running" section
(`MINDPATTERN_ENV=development uvicorn app.main:app --port 8000`).
