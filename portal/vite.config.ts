import { createHash } from "node:crypto";
import { defineConfig, type Plugin } from "vitest/config";
import react from "@vitejs/plugin-react";

// The portal talks only to its own origin (`/api` is proxied locally in dev),
// so a credential-bearing page never needs broad HTTPS egress. Keep the CSP
// aligned with LoginView's immutable same-origin API boundary.
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

/** Dev-only repair for the CSP-vs-fast-refresh conflict (E2E 2026-09-26,
 * finding F1 — same fix as the patient web client): @vitejs/plugin-react
 * boots HMR with an INLINE module script (the react-refresh preamble)
 * that `script-src 'self'` blocks, blanking `npm run dev`. Instead of
 * widening script-src, hash the inline module scripts actually served
 * and append those hashes to the meta CSP. Production configs are
 * untouched; applies only to `vite dev`, where the CSP header is
 * dropped so the hashed meta policy governs. */
function devInlineScriptHashes(): Plugin {
  return {
    name: "dev-inline-script-hashes",
    apply: "serve",
    transformIndexHtml: {
      order: "post",
      handler(html) {
        const hashes = new Set<string>();
        const rewritten = html.replace(
          /<script((?![^>]*\bsrc=)[^>]*)>([\s\S]*?)<\/script>/g,
          (full: string, attrs: string, code: string) => {
            if (attrs.includes('type="module"') && code.trim() !== "") {
              hashes.add(`'sha256-${createHash("sha256").update(code).digest("base64")}'`);
            }
            return full;
          },
        );
        if (hashes.size === 0) return rewritten;
        const directive = "script-src 'self'";
        const at = rewritten.indexOf(directive);
        if (at === -1) return rewritten;
        return (
          rewritten.slice(0, at + directive.length)
          + " " + [...hashes].join(" ")
          + rewritten.slice(at + directive.length)
        );
      },
    },
  };
}

export default defineConfig({
  plugins: [react(), devInlineScriptHashes()],
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
      // A global gate is deliberate.  The portal has thin presentation
      // components alongside crypto/network code; a blanket per-file rule
      // made CI red even while the exercised aggregate was high and drove
      // test authors toward cosmetic coverage.  Security-sensitive request,
      // crypto, session, and pagination behavior has targeted tests; this
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
    // No CSP header in dev: the served meta policy — rewritten with
    // inline-script hashes by devInlineScriptHashes() — governs (a
    // hash-less header copy would re-block the react-refresh preamble).
    headers: Object.fromEntries(
      Object.entries(securityHeaders).filter(([name]) => name !== "Content-Security-Policy"),
    ),
  },
  preview: {
    headers: securityHeaders,
  },
});
