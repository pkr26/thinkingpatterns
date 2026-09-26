import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

// The patient web client talks only to its own origin (`/api` is proxied
// locally in dev, by nginx in production — WEB_PLAN D-5), so a
// credential-bearing page never needs broad HTTPS egress. Keep the CSP
// aligned with the immutable same-origin API boundary, and with
// index.html's meta fallback + public/_headers (pinned by
// tests/securityConfig.test.ts).
const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
};

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "node",
    include: ["tests/**/*.test.{ts,tsx}"],
    setupFiles: ["tests/helpers/setup.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**"],
      // main.tsx is the DOM-only entry point (react-dom render); it has no
      // testable logic and no node-runnable renderer.
      exclude: ["src/main.tsx"],
      // A global gate is deliberate (same decision as the portal): the app
      // has thin presentation components alongside crypto/network/sync
      // code; security-sensitive behavior has targeted tests, and this
      // gate keeps the whole product from regressing below that baseline.
      thresholds: { statements: 85, branches: 75, functions: 85, lines: 90 },
    },
  },
  server: {
    // Dev proxy: same-origin /api against the local backend — no CORS
    // configuration needed during development.
    proxy: {
      "/api": "http://localhost:8000",
    },
    headers: securityHeaders,
  },
  preview: {
    headers: securityHeaders,
  },
});
