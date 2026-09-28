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
  // The compiled modules are CommonJS, but mobile/package.json says
  // "type": "module" — mark the build dir so node loads them as CJS
  // (without this, modern node refuses the .js output as an ES module).
  writeFileSync(join(buildDir, "package.json"), '{"type":"commonjs"}');
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
// 2026-09-28 audit: a truncated/garbled export file used to surface as an
// unhandled JSON.parse stack trace — wrap it in the tool's own error voice.
let bundle;
try {
  bundle = JSON.parse(readFileSync(bundlePath, "utf8"));
} catch (err) {
  console.error(`bundle is not valid JSON (${bundlePath}): ${err.message}`);
  process.exit(1);
}
if (!bundle.user_id || !bundle.salt) {
  console.error("bundle is missing user_id or salt (pre-fix export? re-export from the app).");
  process.exit(1);
}

const password = await readPassword();
const { kdf, envelope } = await loadCrypto();
rmSync(buildDir, { recursive: true, force: true });

// 2026-09-28 audit: the bundle may carry the account's versioned kdf_params
// (ExportBundle.kdf_params). Honor the declared PBKDF2 iteration count —
// a client that adopted different (e.g. higher) params would otherwise get
// a silently WRONG key and every row would read as corrupted. Any other
// algorithm is a loud failure, never a guess.
let iterations = kdf.KDF_ITERATIONS;
if (bundle.kdf_params != null) {
  const algo = bundle.kdf_params.algorithm;
  if (algo !== "pbkdf2-sha256") {
    console.error(
      `unsupported kdf algorithm in bundle.kdf_params: ${JSON.stringify(algo)} ` +
      `(iterations=${JSON.stringify(bundle.kdf_params.iterations)}) — this tool ` +
      `implements pbkdf2-sha256 only; re-export or extend the tool`,
    );
    process.exit(1);
  }
  const declared = bundle.kdf_params.iterations;
  if (!Number.isSafeInteger(declared) || declared < kdf.MIN_ITERATIONS) {
    console.error(
      `bundle.kdf_params.iterations is not a usable integer ` +
      `(got ${JSON.stringify(declared)}; the library floor is ${kdf.MIN_ITERATIONS})`,
    );
    process.exit(1);
  }
  iterations = declared;
}

const master = kdf.deriveMasterKey(password, Buffer.from(bundle.salt, "base64"), iterations);
const dataKey = kdf.deriveDataKey(master);

// Per-blob decode cap (2026-09-28 audit hygiene): a corrupted/hostile bundle
// field must not turn into a >64 MiB allocation. The size is estimated from
// the base64 length BEFORE Buffer.from allocates.
const MAX_BLOB_BYTES = 64 * 1024 * 1024;
function decodeBounded(b64, what) {
  if (typeof b64 !== "string" || b64.length === 0) {
    throw new Error(`${what}: blob field is empty`);
  }
  const approxBytes = Math.floor((b64.length * 3) / 4);
  if (approxBytes > MAX_BLOB_BYTES) {
    throw new Error(`${what}: blob is ~${approxBytes} bytes, over the ${MAX_BLOB_BYTES}-byte decode cap`);
  }
  return Buffer.from(b64, "base64");
}

let decrypted = 0;
const entryDocs = [];
for (const entry of bundle.entries ?? []) {
  try {
    // AAD ladder (2026-09-28 audit, mirroring MindPatternCrypto.decryptEntry
    // and the server's crypto.entry_aad_candidates): a row last written by a
    // v2 client binds its content generation into the AAD —
    // ("entry", user, id, String(content_version)) — while legacy-written
    // rows (including any row a LEGACY client later edited, whose stored
    // version still advanced server-side) keep the 3-part binding. The v2
    // form is tried first when the export row carries content_version, the
    // 3-part form is the fallback; without a version only the legacy form
    // is tried. Without this ladder every edited entry decrypted as
    // "authentication failed".
    const open = (aad) => JSON.parse(envelope.decrypt(
      dataKey, decodeBounded(entry.blob, "entry"), aad,
    ).toString("utf8"));
    let payload;
    if (entry.content_version != null) {
      try {
        payload = open(envelope.buildAad(
          "entry", bundle.user_id, entry.client_entry_id, String(entry.content_version)));
      } catch {
        payload = open(envelope.buildAad("entry", bundle.user_id, entry.client_entry_id));
      }
    } else {
      payload = open(envelope.buildAad("entry", bundle.user_id, entry.client_entry_id));
    }
    entryDocs.push({ ...entry, decrypted: payload });
    decrypted += 1;
  } catch {
    entryDocs.push({ ...entry, decrypted: null, error: "authentication failed (wrong password or corrupted blob)" });
  }
}

const insightDocs = [];
for (const insight of bundle.insights ?? []) {
  const kind = insight.kind; // "patterns" | "question" | "brain"
  try {
    let aad;
    if (kind === "question") aad = envelope.buildAad("question", bundle.user_id, insight.for_date);
    // 2026-09-20 audit M-31: brain-state rows are AAD-bound to the "brain"
    // channel (insights.py binds build_aad("insights", user, "brain")) —
    // the old patterns-only branch could never authenticate them and
    // reported healthy rows as corrupted.
    else if (kind === "brain") aad = envelope.buildAad("insights", bundle.user_id, "brain");
    else aad = envelope.buildAad("insights", bundle.user_id, "patterns");
    const payload = JSON.parse(envelope.decrypt(
      dataKey, decodeBounded(insight.blob, "insight"), aad,
    ).toString("utf8"));
    insightDocs.push({ ...insight, decrypted: payload });
  } catch {
    insightDocs.push({ ...insight, decrypted: null, error: "authentication failed" });
  }
}

// Wellbeing measures (PHQ-9/MBC — audit H-3, 2026-09-20): the export now
// streams every stored measure row. Each blob is AAD-bound exactly like
// the app's create path: ("measure", user_id, client_measure_id); the
// payload is the client's own JSON ({"v":1,"measure":"phq9","score":N,
// "completed_at":...}). Old bundles without a measures key decrypt
// unchanged.
const measureDocs = [];
for (const measure of bundle.measures ?? []) {
  try {
    const payload = JSON.parse(envelope.decrypt(
      dataKey,
      decodeBounded(measure.blob, "measure"),
      envelope.buildAad("measure", bundle.user_id, measure.client_measure_id),
    ).toString("utf8"));
    measureDocs.push({ ...measure, decrypted: payload });
  } catch {
    measureDocs.push({ ...measure, decrypted: null, error: "authentication failed" });
  }
}

const outDir = outArg ?? bundlePath.replace(/\.json$/i, "") + "-decrypted";
// 2026-09-20 audit L-95: the bundle carries user_id (username was removed
// from the export); rendering `undefined` helped nobody.
writeFileSync(join(outDir + ".json"), JSON.stringify({
  user_id: bundle.user_id,
  entries: entryDocs,
  insights: insightDocs,
  measures: measureDocs,
}, null, 2));

const lines = [`# MindPattern journal — ${bundle.user_id}`, ""];
for (const doc of entryDocs) {
  if (!doc.decrypted) {
    lines.push(`## ${doc.entry_date} — [undecryptable]`, "");
    continue;
  }
  lines.push(`## ${doc.decrypted.created_at ?? doc.entry_date}`, "");
  if (doc.decrypted.sentiment != null) lines.push(`*mood note: ${doc.decrypted.sentiment}*`, "");
  lines.push(doc.decrypted.text ?? "", "");
}
if (measureDocs.length > 0) {
  lines.push("## Wellbeing measures (PHQ-9)", "");
  for (const doc of measureDocs) {
    if (!doc.decrypted) {
      lines.push(`- ${doc.measure_date}: [undecryptable]`);
      continue;
    }
    lines.push(`- ${doc.decrypted.completed_at ?? doc.measure_date}: ` +
               `${doc.decrypted.measure ?? "questionnaire"} score ${doc.decrypted.score}`);
  }
  lines.push("");
}
writeFileSync(join(outDir + ".md"), lines.join("\n"));

console.log(`decrypted ${decrypted}/${(bundle.entries ?? []).length} entries, ` +
            `${insightDocs.filter((d) => d.decrypted).length}/${(bundle.insights ?? []).length} insights, ` +
            `${measureDocs.filter((d) => d.decrypted).length}/${(bundle.measures ?? []).length} measures`);
console.log(`wrote ${outDir}.json and ${outDir}.md`);
// Wrong-password fence (2026-09-28 audit): zero rows decrypted of ANY kind
// (entries + insights + measures) means the derived key authenticated
// nothing — with a correct password at least one AEAD open succeeds unless
// every single blob is corrupted. Exit non-zero so scripts wrapping this
// tool do not mistake a wrong-password run for success.
const totalRows = (bundle.entries ?? []).length + (bundle.insights ?? []).length
                + (bundle.measures ?? []).length;
const totalOpened = decrypted + insightDocs.filter((d) => d.decrypted).length
                  + measureDocs.filter((d) => d.decrypted).length;
if (totalRows > 0 && totalOpened === 0) {
  console.error("nothing decrypted of any kind (entries/insights/measures) — wrong password?");
  process.exit(1);
}
