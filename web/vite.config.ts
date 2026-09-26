import { createHash } from "node:crypto";
import { defineConfig, type Plugin } from "vitest/config";
import react from "@vitejs/plugin-react";

// The patient web client talks only to its own origin (`/api` is proxied
// locally in dev, by nginx in production — WEB_PLAN D-5), so a
// credential-bearing page never needs broad HTTPS egress. Keep the CSP
// aligned with the immutable same-origin API boundary, and with
// index.html's meta fallback + public/_headers (pinned by
// tests/securityConfig.test.ts). No 'unsafe-inline' even here: dev serves
// the same external /app.css, and React's CSSOM inline styles are outside
// style-src's reach. HSTS stays a production-only header (it is
// meaningless on plain-HTTP loopback dev servers).
const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-src 'none'; upgrade-insecure-requests",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Cache-Control": "no-store",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), accelerometer=(), gyroscope=(), magnetometer=(), display-capture=(), idle-detection=(), browsing-topics=(), serial=(), bluetooth=()",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
  "X-Robots-Tag": "noindex, nofollow",
};

/** Dev-only repair for the CSP-vs-fast-refresh conflict (E2E 2026-09-26,
 * finding F1): @vitejs/plugin-react boots HMR by injecting an INLINE
 * module script (the react-refresh preamble) into index.html, which
 * `script-src 'self'` — enforced by BOTH the meta tag and the dev
 * server's header copy — blocks, leaving `npm run dev` a permanently
 * blank page. The fix refuses 'unsafe-inline' (banned by
 * tests/securityConfig.test.ts, rightly): it hashes whatever inline
 * module scripts the dev server actually serves and appends those
 * hashes to the meta CSP. The production triple (index.html file,
 * public/_headers, nginx) is untouched — this plugin applies only to
 * `vite dev`, and the dev server drops its CSP header so the hashed
 * meta policy is the one that governs. */
function devInlineScriptHashes(): Plugin {
  return {
    name: "dev-inline-script-hashes",
    apply: "serve",
    transformIndexHtml: {
      order: "post",
      handler(html) {
        const hashes = new Set<string>();
        // Inline module scripts only: external ones (src=) are already
        // covered by script-src 'self'.
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
    // No CSP header in dev: the served index.html's meta policy —
    // rewritten with inline-script hashes by devInlineScriptHashes() —
    // is the governing CSP (two policies intersect, so a hash-less
    // header copy would re-block the react-refresh preamble and blank
    // the page again). Every other header keeps the production posture.
    headers: Object.fromEntries(
      Object.entries(securityHeaders).filter(([name]) => name !== "Content-Security-Policy"),
    ),
  },
  preview: {
    headers: securityHeaders,
  },
});
