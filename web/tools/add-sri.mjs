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
 * Fail-closed: a build whose index.html references a local asset that is
 * missing, or that cannot be stamped, exits nonzero so CI never ships an
 * unstamped shell. Run automatically by `npm run build`.
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const dist = join(import.meta.dirname, "..", "dist");
const indexPath = join(dist, "index.html");

if (!existsSync(indexPath)) {
  console.error("add-sri: dist/index.html not found — run `vite build` first.");
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
// Every <script src=…> and stylesheet <link href=…> pointing at a local
// asset gets an integrity attribute (idempotent: existing ones are
// recomputed, so a rebuilt bundle never keeps a stale hash).
html = html.replace(/<script\b[^>]*\bsrc="([^"]+)"[^>]*>/g, (tag, src) => {
  if (!src.startsWith("/")) return tag;
  const integrity = sriFor(src);
  stamped += 1;
  const withoutIntegrity = tag.replace(/\s+integrity="[^"]*"/, "");
  return withoutIntegrity.replace(/<script\b/, `<script integrity="${integrity}"`);
});
html = html.replace(/<link\b[^>]*rel="stylesheet"[^>]*>/g, (tag) => {
  const href = tag.match(/\bhref="([^"]+)"/)?.[1];
  if (!href || !href.startsWith("/")) return tag;
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
