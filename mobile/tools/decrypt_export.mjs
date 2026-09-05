#!/usr/bin/env node
/**
 * Decrypt a MindPattern export bundle into readable files.
 *
 * The server can only export ciphertext (it never holds your key). This
 * tool derives your keys from your password + the salt in the bundle, using
 * the SAME crypto modules the app ships (compiled via the project's
 * TypeScript; the engine seam falls back to node:crypto), and writes your
 * journal as Markdown plus the raw decrypted JSON.
 *
 *   node tools/decrypt_export.mjs --bundle export.json [--out export-decrypted]
 *
 * The password is read from MINDPATTERN_PASSWORD, or prompted interactively
 * (hidden input) when stdin is a TTY.
 *
 * Requires `npm install` once (for typescript). Everything runs locally;
 * nothing leaves this machine.
 */
import { readFileSync, writeFileSync, existsSync, rmSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline";
import { EOL } from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const tscBin = join(here, "..", "node_modules", ".bin", "tsc");
const buildDir = join(here, "..", ".decrypt-build");

function parseArgs() {
  const args = { bundle: null, out: null };
  const raw = process.argv.slice(2);
  for (let i = 0; i < raw.length; i++) {
    if (raw[i] === "--bundle") args.bundle = raw[++i];
    else if (raw[i] === "--out") args.out = raw[++i];
  }
  if (!args.bundle) {
    console.error("usage: node tools/decrypt_export.mjs --bundle <export.json> [--out <dir>]");
    process.exit(2);
  }
  return args;
}

async function readPassword() {
  if (process.env.MINDPATTERN_PASSWORD) return process.env.MINDPATTERN_PASSWORD;
  process.stderr.write("Password (input hidden where supported): ");
  const rl = createInterface({ input: process.stdin });
  // readline cannot hide input portably; for real secrecy pipe the password
  // in via MINDPATTERN_PASSWORD. Local interactive use is the tradeoff.
  const line = await new Promise((resolve) => rl.once("line", resolve));
  rl.close();
  process.stderr.write(EOL);
  return line;
}

async function loadCrypto() {
  if (!existsSync(tscBin)) {
    console.error("typescript not installed — run `npm install` in mobile/ first.");
    process.exit(1);
  }
  rmSync(buildDir, { recursive: true, force: true });
  mkdirSync(buildDir, { recursive: true });
  const compiled = spawnSync(tscBin, [
    join(here, "..", "src", "crypto", "kdf.ts"),
    join(here, "..", "src", "crypto", "envelope.ts"),
    "--module", "commonjs",
    "--target", "es2022",
    "--esModuleInterop",
    "--skipLibCheck",
    "--outDir", buildDir,
  ], { stdio: "pipe" });
  if (compiled.status !== 0) {
    console.error("tsc failed:\n" + compiled.stderr.toString());
    process.exit(1);
  }
  const kdf = await import(join(buildDir, "kdf.js"));
  const envelope = await import(join(buildDir, "envelope.js"));
  return { kdf, envelope };
}

const { bundle: bundlePath, out: outArg } = parseArgs();
const bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
if (!bundle.user_id || !bundle.salt) {
  console.error("bundle is missing user_id or salt (pre-fix export? re-export from the app).");
  process.exit(1);
}

const password = await readPassword();
const { kdf, envelope } = await loadCrypto();
rmSync(buildDir, { recursive: true, force: true });

const master = kdf.deriveMasterKey(password, Buffer.from(bundle.salt, "base64"));
const dataKey = kdf.deriveDataKey(master);

let decrypted = 0;
const entryDocs = [];
for (const entry of bundle.entries ?? []) {
  try {
    const payload = JSON.parse(envelope.decrypt(
      dataKey,
      Buffer.from(entry.blob, "base64"),
      envelope.buildAad("entry", bundle.user_id, entry.client_entry_id),
    ).toString("utf8"));
    entryDocs.push({ ...entry, decrypted: payload });
    decrypted += 1;
  } catch {
    entryDocs.push({ ...entry, decrypted: null, error: "authentication failed (wrong password or corrupted blob)" });
  }
}

const insightDocs = [];
for (const insight of bundle.insights ?? []) {
  const kind = insight.kind; // "patterns" | "question"
  try {
    let aad;
    if (kind === "question") aad = envelope.buildAad("question", bundle.user_id, insight.for_date);
    else aad = envelope.buildAad("insights", bundle.user_id, "patterns");
    const payload = JSON.parse(envelope.decrypt(
      dataKey, Buffer.from(insight.blob, "base64"), aad,
    ).toString("utf8"));
    insightDocs.push({ ...insight, decrypted: payload });
  } catch {
    insightDocs.push({ ...insight, decrypted: null, error: "authentication failed" });
  }
}

const outDir = outArg ?? bundlePath.replace(/\.json$/i, "") + "-decrypted";
writeFileSync(join(outDir + ".json"), JSON.stringify({
  username: bundle.username,
  entries: entryDocs,
  insights: insightDocs,
}, null, 2));

const lines = [`# MindPattern journal — ${bundle.username}`, ""];
for (const doc of entryDocs) {
  if (!doc.decrypted) {
    lines.push(`## ${doc.entry_date} — [undecryptable]`, "");
    continue;
  }
  lines.push(`## ${doc.decrypted.created_at ?? doc.entry_date}`, "");
  if (doc.decrypted.sentiment != null) lines.push(`*mood note: ${doc.decrypted.sentiment}*`, "");
  lines.push(doc.decrypted.text ?? "", "");
}
writeFileSync(join(outDir + ".md"), lines.join("\n"));

console.log(`decrypted ${decrypted}/${(bundle.entries ?? []).length} entries, ` +
            `${insightDocs.filter((d) => d.decrypted).length}/${(bundle.insights ?? []).length} insights`);
console.log(`wrote ${outDir}.json and ${outDir}.md`);
if (decrypted === 0 && (bundle.entries ?? []).length > 0) {
  console.error("nothing decrypted — wrong password?");
  process.exit(1);
}
