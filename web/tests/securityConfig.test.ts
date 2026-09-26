/** Static-host defenses are easy to accidentally drop during a deployment
 *  refactor, so pin the security policy files as part of the web suite
 *  (WEB_PLAN P1.4: the aligned triple — index.html meta fallback,
 *  public/_headers, and the nginx template's patient-app block). The
 *  2026-09-26 hardening pass tightened the pinned contract: no
 *  'unsafe-inline' anywhere (the stylesheet is the same-origin /app.css;
 *  React's CSSOM inline styles are outside style-src), no framing, no
 *  form submission, COEP isolation, HSTS ready for preload submission,
 *  and noindex on a mental-health app that must stay out of search
 *  indexes and referrer graphs. */
import { createHash } from "node:crypto";
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

const CSP =
  "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; frame-src 'none'; upgrade-insecure-requests";

describe("static-host security policy", () => {
  it.skipIf(!existsSync(nginxPath))(
    "ships CSP and privacy headers as a page fallback, static-host config, and an aligned nginx block",
    async () => {
      const [html, headers, nginx, viteConfig] = await Promise.all([
        readFile(resolve(webRoot, "index.html"), "utf8"),
        readFile(resolve(webRoot, "public/_headers"), "utf8"),
        readFile(nginxPath, "utf8"),
        readFile(resolve(webRoot, "vite.config.ts"), "utf8"),
      ]);
      const patientBlock = nginx.slice(nginx.indexOf("Patient web client (web/)"));

      // The ONE CSP literal, identical across the meta fallback, the
      // static-host header file, the dev server, and nginx. Any drift
      // between them is the exact bug this suite exists to catch. The
      // unsafe-inline ban is checked on COMMENT-STRIPPED text — the
      // configs legitimately explain, in comments, why it is absent.
      const stripComments = (text: string): string =>
        text
          .replace(/<!--[\s\S]*?-->/g, "")
          .replace(/\/\*[\s\S]*?\*\//g, "")
          .replace(/(^|\s)\/\/[^\n]*/g, "$1")
          .replace(/(^|\n)\s*#[^\n]*/g, "$1");
      for (const source of [html, headers, viteConfig, patientBlock]) {
        expect(source).toContain(CSP);
        expect(stripComments(source)).not.toContain("unsafe-inline");
      }

      expect(html).toContain('name="referrer" content="no-referrer"');
      expect(html).toContain('name="robots" content="noindex, nofollow"');
      expect(headers).toContain("Referrer-Policy: no-referrer");
      expect(headers).toContain("X-Content-Type-Options: nosniff");
      expect(headers).toContain("Cache-Control: no-store");
      expect(headers).toContain("Permissions-Policy:");
      expect(headers).toContain("Cross-Origin-Opener-Policy: same-origin");
      expect(headers).toContain("Cross-Origin-Resource-Policy: same-origin");

      // Cross-origin isolation: every subresource is same-origin with CORP
      // same-origin set, so require-corp closes the Spectre-adjacent
      // cross-origin embedding surface without breaking anything.
      expect(headers).toContain("Cross-Origin-Embedder-Policy: require-corp");
      expect(patientBlock).toContain('add_header Cross-Origin-Embedder-Policy "require-corp" always;');

      // A mental-health journal must never be indexed or leak via referer.
      expect(headers).toContain("X-Robots-Tag: noindex, nofollow");
      expect(patientBlock).toContain('add_header X-Robots-Tag "noindex, nofollow" always;');

      // `_headers` is the production static-host contract (not Vite's local
      // HTTP dev server), so its HSTS policy must match the TLS nginx
      // template — preload-ready; submitting to hstspreload.org is the
      // operator step (deploy/README.md).
      const hsts = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload";
      expect(headers).toContain(hsts);
      expect(patientBlock).toContain(
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;',
      );
      // Exactly ONE HSTS directive in the patient block: two conflicting
      // add_header lines would both ship.
      expect((patientBlock.match(/Strict-Transport-Security/g) ?? []).length).toBe(1);

      // The shell stylesheet is external and same-origin — that is what
      // lets style-src ship without 'unsafe-inline'. No <style> blocks in
      // the shipped HTML, and the file it links exists.
      expect(html).not.toContain("<style");
      expect(html).toContain('<link rel="stylesheet" href="/app.css" />');
      expect(existsSync(resolve(webRoot, "public/app.css"))).toBe(true);
      const appCss = await readFile(resolve(webRoot, "public/app.css"), "utf8");
      expect(appCss).not.toContain("@import");
      expect(appCss).not.toContain("url(http");

      // The nginx template ships the patient web app's block. It must name
      // the static root, its own subdomain, and carry the SAME CSP literal
      // so the configs cannot drift apart.
      expect(patientBlock).toContain("app.example.com");
      expect(patientBlock).toContain("/srv/mindpattern/web/dist");
      // The patient app's block must also keep the no-store posture.
      expect(patientBlock).toContain('add_header Cache-Control "no-store" always;');

      // RFC 9116 disclosure channel (operators replace the contact).
      const securityTxt = await readFile(resolve(webRoot, "public/.well-known/security.txt"), "utf8");
      expect(securityTxt).toMatch(/^Contact: /m);
      expect(securityTxt).toMatch(/^Expires: /m);
    },
  );

  it.skipIf(!existsSync(resolve(webRoot, "dist/index.html")))(
    "the built shell carries subresource integrity for every local subresource",
    async () => {
      const distIndex = resolve(webRoot, "dist/index.html");
      const html = await readFile(distIndex, "utf8");
      const stamped = [...html.matchAll(/<(script|link)\b[^>]*>/g)].filter((m) =>
        /\b(src|href)="\/[^"]*"/.test(m[0]),
      );
      expect(stamped.length).toBeGreaterThanOrEqual(2);
      for (const match of stamped) {
        const tag = match[0];
        const integrity = tag.match(/\bintegrity="(sha384-[^"]+)"/)?.[1];
        expect(integrity, `${tag} must carry an SRI hash`).toBeDefined();
        const publicPath = tag.match(/\b(?:src|href)="(\/[^"]+)"/)?.[1];
        const digest = createHash("sha384")
          .update(await readFile(resolve(webRoot, "dist", publicPath!.replace(/^\//, ""))))
          .digest("base64");
        expect(integrity).toBe(`sha384-${digest}`);
      }
    },
  );
});
