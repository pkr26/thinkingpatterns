/** Static-host defenses are easy to accidentally drop during a deployment
 * refactor, so pin the security policy files as part of the portal suite. */
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const portalRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
// The nginx template lives OUTSIDE the portal package (../deploy/...), so a
// Stryker mutation sandbox — a portal-only copy — cannot see it. Skip there
// rather than fail; the full checkout (CI `npm test`) always runs this.
const nginxPath = resolve(portalRoot, "../deploy/nginx/mindpattern.conf.example");

describe("static-host security policy", () => {
  it.skipIf(!existsSync(nginxPath))(
    "ships CSP and privacy headers both as a page fallback and static-host config",
    async () => {
      const [html, headers, nginx, viteConfig] = await Promise.all([
        readFile(resolve(portalRoot, "index.html"), "utf8"),
        readFile(resolve(portalRoot, "public/_headers"), "utf8"),
        readFile(nginxPath, "utf8"),
        readFile(resolve(portalRoot, "vite.config.ts"), "utf8"),
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
    // HTTP dev server), so its HSTS policy must match the TLS nginx template.
    expect(headers).toContain("Strict-Transport-Security: max-age=31536000; includeSubDomains");
    // 2026-09-26 CSP hardening (audit L): the portal's OWN three policy
    // surfaces — the meta fallback, the static-host header, and Vite's
    // preview/dev-server header — all drop style-src 'unsafe-inline'. The
    // views' former inline style objects are portal.css classes and the
    // print rules live in public/print.css, so no <style> tag or style=
    // attribute ships anywhere. The trailing ';' keeps the pin exact: the
    // old loosened form read "style-src 'self' 'unsafe-inline';".
    for (const source of [html, headers, viteConfig]) {
      expect(source).toContain("style-src 'self';");
      expect(source).not.toContain("'unsafe-inline'");
    }
    expect(html).toContain('<link rel="stylesheet" href="/print.css" media="print" />');
    // FE-2 (pentest 2026-09-29): the deploy template's portal block is
    // synced to the pinned header set. It had kept style-src
    // 'unsafe-inline' (with a stale justifying comment about an inline
    // style theme the portal no longer ships) for three days after every
    // pinned portal copy dropped it, so an operator deploying from the
    // template silently got a LOOSER CSP than any tested copy. Slice to
    // the portal block — the patient-web block below the marker carries
    // its own literal, pinned by the web suite.
    const portalBlock = nginx.slice(0, nginx.indexOf("Patient web client (web/)"));
    expect(portalBlock).toContain("style-src 'self';");
    // The ban is checked on COMMENT-STRIPPED text — the template
    // legitimately explains, in comments, why 'unsafe-inline' is absent
    // (same rule as the web suite's nginx pin).
    const stripNginxComments = (text: string): string => text.replace(/(^|\n)\s*#[^\n]*/g, "$1");
    expect(stripNginxComments(portalBlock)).not.toContain("unsafe-inline");
    // The clinician portal is as unindexable as the patient app: the same
    // noindex header the web block ships.
    expect(portalBlock).toContain('add_header X-Robots-Tag "noindex, nofollow" always;');
    expect(nginx).toContain("connect-src 'self'");
    expect(nginx).toContain('add_header Cache-Control "no-store" always;');
    expect(nginx).toContain('add_header Cross-Origin-Resource-Policy "same-origin" always;');
    expect(nginx).toContain(
      'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
    );
    expect(nginx).toContain("client_body_timeout 30s;");
    expect(nginx).toContain("proxy_set_header Host portal.example.com;");
    expect(nginx).not.toContain("https://$host");
    // Edge flood armor and the streamed-export read budget (2026-09-18
    // audit): the proxy template must keep shedding load before app
    // concurrency slots, and must not cut a large export at nginx's 60s
    // default upstream read timeout.
    expect(nginx).toContain("limit_req_zone $binary_remote_addr zone=edge_api:");
    expect(nginx).toContain("limit_req zone=edge_api burst=");
    expect(nginx).toContain("proxy_read_timeout 300s;");
    // The deprecated `listen … ssl http2` form warns on nginx >= 1.25.1.
    expect(nginx).toContain("http2 on;");
    expect(nginx).not.toContain("listen 443 ssl http2");
  });

  it.skipIf(!existsSync(resolve(portalRoot, "dist/index.html")))(
    "the built shell carries subresource integrity for every local subresource",
    async () => {
      // FE-3 (pentest 2026-09-29): the portal build gained the web
      // client's post-build SRI stamp (tools/add-sri.mjs, wired after
      // `vite build` in package.json) — the same dist pin the web suite
      // runs. dist/ is gitignored, so this self-skips in a checkout
      // without a local build and fires wherever a build has run.
      const distIndex = resolve(portalRoot, "dist/index.html");
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
          .update(await readFile(resolve(portalRoot, "dist", publicPath!.replace(/^\//, ""))))
          .digest("base64");
        expect(integrity).toBe(`sha384-${digest}`);
      }
    },
  );
});
