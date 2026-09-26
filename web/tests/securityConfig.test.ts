/** Static-host defenses are easy to accidentally drop during a deployment
 *  refactor, so pin the security policy files as part of the web suite
 *  (WEB_PLAN P1.4: the aligned triple — index.html meta fallback,
 *  public/_headers, and the nginx template's patient-app block). */
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const webRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// The nginx template lives OUTSIDE the web package (../deploy/...), so a
// Stryker mutation sandbox — a web-only copy — cannot see it. Skip there
// rather than fail; the full checkout (CI `npm test`) always runs this.
const nginxPath = resolve(webRoot, "../deploy/nginx/mindpattern.conf.example");

describe("static-host security policy", () => {
  it.skipIf(!existsSync(nginxPath))(
    "ships CSP and privacy headers as a page fallback, static-host config, and an aligned nginx block",
    async () => {
      const [html, headers, nginx] = await Promise.all([
        readFile(resolve(webRoot, "index.html"), "utf8"),
        readFile(resolve(webRoot, "public/_headers"), "utf8"),
        readFile(nginxPath, "utf8"),
      ]);
      for (const source of [html, headers]) {
        expect(source).toContain("Content-Security-Policy");
        expect(source).toContain("default-src 'self'");
        expect(source).toContain("frame-ancestors 'none'");
        expect(source).toContain("connect-src 'self';");
      }
      expect(html).toContain('name="referrer" content="no-referrer"');
      expect(headers).toContain("Referrer-Policy: no-referrer");
      expect(headers).toContain("X-Content-Type-Options: nosniff");
      expect(headers).toContain("Cache-Control: no-store");
      expect(headers).toContain("Permissions-Policy:");
      expect(headers).toContain("Cross-Origin-Opener-Policy: same-origin");
      expect(headers).toContain("Cross-Origin-Resource-Policy: same-origin");
      // `_headers` is the production static-host contract (not Vite's local
      // HTTP dev server), so its HSTS policy must match the TLS nginx
      // template.
      expect(headers).toContain("Strict-Transport-Security: max-age=31536000; includeSubDomains");
      // The dev/preview server must carry the same policy as the shipped
      // configs, or development quietly diverges from production.
      const viteConfig = await readFile(resolve(webRoot, "vite.config.ts"), "utf8");
      expect(viteConfig).toContain("default-src 'self'");
      expect(viteConfig).toContain("Cross-Origin-Opener-Policy");
      // The nginx template ships the patient web app's block (a marked
      // placeholder until WEB_PLAN P10 turns it live). It must name the
      // static root, its own subdomain, and carry the SAME CSP literal so
      // the three configs cannot drift apart.
      expect(nginx).toContain("Patient web client (web/)");
      expect(nginx).toContain("app.example.com");
      expect(nginx).toContain("/srv/mindpattern/web/dist");
      expect(nginx).toContain(
        "add_header Content-Security-Policy \"default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'\"",
      );
      // The patient app's block must also keep the no-store posture.
      expect(nginx).toContain('add_header Cache-Control "no-store" always;');
    },
  );
});
