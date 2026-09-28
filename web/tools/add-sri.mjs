/**
 * Post-build SRI stamp (industrial hardening, 2026-09-26).
 *
 * vite emits `<script type="module" crossorigin src="/assets/…">` and the
 * shell links the external `/app.css`; this step recomputes sha384 over
 * each referenced local asset and injects `integrity` attributes into
 * dist/index.html. A tampered or substituted bundle then fails to
 * execute/load in the browser even if an attacker can write to the static
 * host — same-origin SRI is cheap insurance for a static app with no
 * server-side rendering.
 *
 * Stamped surfaces: <script src>, <link rel="stylesheet">,
 * <link rel="modulepreload"> and <link rel="preload" as="script|style">
 * (2026-09-28 audit: the modulepreload/preload links vite emits were
 * silently unstamped before). KNOWN LIMITATION, stated honestly: fonts and
 * other assets referenced from INSIDE CSS (url() in @font-face and the
 * like) cannot carry integrity attributes — they are fetched by the CSS
 * engine, not by an HTML tag — so their integrity is only covered
 * transitively by the stylesheet's own hash. Cross-origin (non
 * root-relative) references are skipped with a warning, never silently.
 *
 * Fail-closed: a build whose index.html references a local asset that is
 * missing, or that cannot be stamped, exits nonzero so CI never ships an
 * unstamped shell. Run automatically by `npm run build`.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import { assertNoSecurityTxtPlaceholders } from "./securityTxt.mjs";

const dist = join(import.meta.dirname, "..", "dist");
const indexPath = join(dist, "index.html");

if (!existsSync(indexPath)) {
  console.error("add-sri: dist/index.html not found — run `vite build` first.");
  process.exit(1);
}

// security.txt placeholder gate (audit 2026-09-28, INFO): the file under
// public/ is what vite copies into dist/ verbatim, so gate on the SOURCE.
// The build fails while the RFC 9116 template still carries its example
// contact/URL — a placeholder contact is worse than none because it looks
// like a channel nobody reads. The check itself is unit-pinned
// (tests/securityTxt.test.ts).
try {
  assertNoSecurityTxtPlaceholders(readFileSync(join(import.meta.dirname, "..", "public", ".well-known", "security.txt"), "utf8"));
} catch (err) {
  console.error(`add-sri: ${(err instanceof Error ? err.message : String(err))}`);
  process.exit(1);
}

let html = readFileSync(indexPath, "utf8");

/** sha384-<base64> SRI expression for a file inside dist/. */
function sriFor(publicPath) {
  if (!publicPath.startsWith("/")) {
    throw new Error(`add-sri: only root-relative asset URLs can be stamped, got ${publicPath}`);
  }
  const file = join(dist, publicPath);
  if (!existsSync(file)) {
    throw new Error(`add-sri: ${publicPath} referenced by index.html is missing from dist/`);
  }
  const digest = createHash("sha384").update(readFileSync(file)).digest("base64");
  return `sha384-${digest}`;
}

let stamped = 0;
// Every <script src=…>, stylesheet/modulepreload/preload link pointing at
// a LOCAL asset gets an integrity attribute (idempotent: existing ones are
// recomputed, so a rebuilt bundle never keeps a stale hash). Non
// root-relative references cannot be stamped — they are skipped with a
// WARNING so a CDN-relative or protocol-relative slip is visible, not
// silently unprotected (2026-09-28 audit).
html = html.replace(/<script\b[^>]*\bsrc="([^"]+)"[^>]*>/g, (tag, src) => {
  if (!src.startsWith("/")) {
    console.warn(`add-sri: SKIPPED non-root-relative script src="${src}" — it carries no integrity; verify it is intentionally external`);
    return tag;
  }
  const integrity = sriFor(src);
  stamped += 1;
  const withoutIntegrity = tag.replace(/\s+integrity="[^"]*"/, "");
  return withoutIntegrity.replace(/<script\b/, `<script integrity="${integrity}"`);
});
html = html.replace(/<link\b[^>]*>/g, (tag) => {
  const rel = (tag.match(/\brel="([^"]+)"/)?.[1] ?? "").split(/\s+/);
  const as = tag.match(/\bas="([^"]+)"/)?.[1] ?? "";
  const href = tag.match(/\bhref="([^"]+)"/)?.[1];
  // 2026-09-28 audit: vite's <link rel="modulepreload" …> and
  // <link rel="preload" as="script|style" …> emissions were never matched
  // by the old stylesheet-only regex — the module graph's subresource
  // integrity silently did not exist. Attribute order is deliberately
  // re-parsed per tag instead of assumed.
  const stampable = rel.includes("stylesheet") || rel.includes("modulepreload")
    || (rel.includes("preload") && (as === "script" || as === "style"));
  if (!stampable) return tag;
  if (!href || !href.startsWith("/")) {
    console.warn(`add-sri: SKIPPED non-root-relative link href="${href ?? "(none)"}" (rel="${rel.join(" ")}") — it carries no integrity; verify it is intentionally external`);
    return tag;
  }
  const integrity = sriFor(href);
  stamped += 1;
  const withoutIntegrity = tag.replace(/\s+integrity="[^"]*"/, "");
  return withoutIntegrity.replace(/<link\b/, `<link integrity="${integrity}"`);
});

if (stamped === 0) {
  console.error("add-sri: no local script/stylesheet references found in dist/index.html — nothing to stamp.");
  process.exit(1);
}

writeFileSync(indexPath, html);
console.log(`add-sri: stamped ${stamped} subresource integrity attribute(s) into dist/index.html`);
