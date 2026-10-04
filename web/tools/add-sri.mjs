/**
 * Stamp local scripts, stylesheets, and script/style preload links with SHA-384 SRI.
 * Recomputing hashes on every build avoids stale integrity attributes.
 * Missing referenced assets fail the build; external URLs are reported and skipped.
 *
 * SRI authenticates the referenced asset, not resources fetched from inside CSS.
 * It also assumes the delivered HTML and its integrity attributes are trusted.
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
// Every <script src=…>, stylesheet/modulepreload/preload link pointing at
// a LOCAL asset gets an integrity attribute (idempotent: existing ones are
// recomputed, so a rebuilt bundle never keeps a stale hash). Non
// root-relative references cannot be stamped — they are skipped with a
// WARNING so a CDN-relative or protocol-relative slip is visible, not
// silently unprotected.
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
  // Include preload links as well as stylesheets; attribute order is arbitrary.
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
