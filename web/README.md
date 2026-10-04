# Fathom patient web client

React 19, Vite, and strict TypeScript client for the FastAPI backend.
Journal entries and local drafts are encrypted in the browser. Unlocked
keys remain in session memory; pattern processing requires an explicit
user action. See the [architecture guide](../docs/architecture.md) for the security model
and backend setup.

## Development

```bash
npm ci
npm run dev        # http://localhost:5173
npm run typecheck  # strict checking, including unused declarations
npm test           # unit and regression suites with coverage gates
npm run build      # typecheck, production bundle, and integrity hashes
npm run preview    # serve the production bundle locally
```

The app calls its own `/api` origin. Vite proxies development requests to
`http://localhost:8000`; set `WEB_API_PROXY` to change the local backend
target. Production must serve the app and API through one HTTPS origin.

## Structure

- `src/views/`: patient-facing workflows.
- `src/api/` and `src/crypto/`: authenticated transport and encryption.
- `src/kvstore.ts`, `src/ownerStorage.ts`: durable storage and account ownership.
- `src/localRotation.ts`, `src/localErasure.ts`: resumable account operations.
- `src/locales/`: English and Spanish copy.
- `tests/`: regression, accessibility, cryptographic, and integration checks.

Live backend drills and fixture generation are opt-in and skipped by the
normal test command; their files document the required environment variables.

## Release

`npm run build:release` also generates `.well-known/security.txt` from
`SECURITY_TXT_CONTACT`, `SECURITY_TXT_CANONICAL`, and `SECURITY_TXT_EXPIRES`.
Supply the real deployment values; placeholders fail validation.

Configure the static host with `public/_headers`. The fallback CSP in
`index.html` does not replace HTTP response headers. Security configuration
tests keep the client and deployment policies aligned.
