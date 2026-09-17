#!/usr/bin/env node
/**
 * Cross-platform crypto verification — over the REAL shipping modules.
 *
 * Compiles mobile/src/crypto with the project's TypeScript and runs the
 * emitted modules (their engine seam falls back to node:crypto) against
 * every vector in shared/vectors.json. This is the check that would have
 * caught the ensure_ascii AAD divergence before it shipped.
 *
 *   node tools/verify_vectors.mjs
 *
 * If node_modules/typescript is not installed, falls back to a webcrypto
 * REFERENCE check and says so loudly (that variant cannot detect bugs in
 * the app's own crypto code — run `npm install && npm test` for that).
 */
import { readFileSync, rmSync, mkdirSync } from "node:fs";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { webcrypto } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const tscBin = join(here, "..", "node_modules", ".bin", "tsc");
const buildDir = join(here, "..", ".verify-build");

const vectorsJson = JSON.parse(readFileSync(vectorsPath, "utf8"));
const { vectors, encrypt_vectors: encryptVectors } = vectorsJson;
// Fail CLOSED: a renamed/dropped key must not read as "0 vectors verified".
if (!Array.isArray(vectors) || vectors.length < 4) {
  console.error(`vectors.json: "vectors" key missing or has ${vectors?.length ?? "no"} entries (expected >= 4)`);
  process.exit(1);
}
if (!Array.isArray(encryptVectors) || encryptVectors.length < 2) {
  console.error(`vectors.json: "encrypt_vectors" key missing or has ${encryptVectors?.length ?? "no"} entries (expected >= 2)`);
  process.exit(1);
}

function b64(buf) {
  return Buffer.from(buf).toString("base64");
}

async function loadRealModules() {
  if (!existsSync(tscBin)) return null;
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
    console.error("tsc failed to compile src/crypto:\n" + compiled.stderr.toString());
    process.exit(1);
  }
  // engine.js's conditional require: quick-crypto fails under node -> node:crypto.
  const kdf = await import(join(buildDir, "kdf.js"));
  const envelope = await import(join(buildDir, "envelope.js"));
  return { kdf, envelope, mode: "REAL MODULES" };
}

async function loadReferenceFallback() {
  const { subtle } = webcrypto;
  return {
    mode: "webcrypto REFERENCE (cannot catch app-crypto bugs — run `npm install && npm test`)",
    kdf: {
      deriveMasterKey: async (password, salt, iterations) => {
        const key = await subtle.importKey("raw", Buffer.from(password, "utf8"), "PBKDF2", false, ["deriveBits"]);
        return Buffer.from(await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256));
      },
      deriveAuthKey: async (master) => hkdf(master, "mindpattern/auth/v1"),
      deriveDataKey: async (master) => hkdf(master, "mindpattern/data/v1"),
    },
    envelope: {
      buildAad: async (...parts) => referenceBuildAad(...parts),
      decrypt: async (key, blob, aad) => {
        const nonce = blob.subarray(0, 12);
        const ck = await subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
        // GCM with empty AAD is byte-identical to GCM with no AAD.
        return Buffer.from(await subtle.decrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad ?? Buffer.alloc(0), tagLength: 128 }, ck, blob.subarray(12)));
      },
      encrypt: async (key, plaintext, aad, nonce) => {
        const ck = await subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
        const ct = Buffer.from(await subtle.encrypt(
          { name: "AES-GCM", iv: nonce, additionalData: aad ?? Buffer.alloc(0), tagLength: 128 }, ck, plaintext));
        return Buffer.concat([nonce, ct]);
      },
    },
  };
}

async function hkdf(ikm, info) {
  const { subtle } = webcrypto;
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return Buffer.from(await subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: Buffer.alloc(32), info: Buffer.from(info, "utf8") }, key, 256));
}

// Reference copy of the ensure_ascii AAD canonicalization for the webcrypto
// fallback ONLY — in REAL MODULES mode the shipping envelope.buildAad is used.
function referenceBuildAad(...parts) {
  const json = JSON.stringify(parts);
  let out = "";
  for (let i = 0; i < json.length; i++) {
    const code = json.charCodeAt(i);
    out += code >= 0x7f ? "\\u" + code.toString(16).padStart(4, "0") : json[i];
  }
  return Buffer.from(out, "utf8");
}

const impl = (await loadRealModules()) ?? (await loadReferenceFallback());
console.log(`verifying ${vectors.length} vectors with: ${impl.mode}`);

let failures = 0;
for (const [i, v] of vectors.entries()) {
  const salt = Buffer.from(v.salt, "base64");
  const master = await impl.kdf.deriveMasterKey(v.password, salt, v.iterations);
  const authKey = await impl.kdf.deriveAuthKey(master);
  const dataKey = await impl.kdf.deriveDataKey(master);

  for (const [name, got, want] of [
    ["master_key", master, v.master_key],
    ["auth_key", authKey, v.auth_key],
    ["data_key", dataKey, v.data_key],
  ]) {
    if (b64(got) !== want) {
      console.error(`vector ${i}: ${name} MISMATCH\n  got:  ${b64(got)}\n  want: ${want}`);
      failures += 1;
    }
  }

  const aad = Buffer.from(v.aad, "base64");
  const blob = Buffer.from(v.blob, "base64");
  try {
    const plaintext = await impl.envelope.decrypt(dataKey, blob, aad);
    if (b64(plaintext) !== v.plaintext) {
      console.error(`vector ${i}: plaintext MISMATCH`);
      failures += 1;
    }
  } catch (err) {
    console.error(`vector ${i}: AES-GCM decrypt failed: ${err.message}`);
    failures += 1;
  }
}

for (const [i, v] of encryptVectors.entries()) {
  const salt = Buffer.from(v.salt, "base64");
  const master = await impl.kdf.deriveMasterKey(v.password, salt, v.iterations);
  const dataKey = await impl.kdf.deriveDataKey(master);
  if (b64(dataKey) !== v.data_key) {
    console.error(`encrypt vector ${i}: data_key MISMATCH`);
    failures += 1;
    continue;
  }
  const aad = v.aad_parts ? await impl.envelope.buildAad(...v.aad_parts) : undefined;
  const nonce = Buffer.from(v.nonce, "base64");
  const plaintext = Buffer.from(v.plaintext, "base64");
  try {
    const blob = await impl.envelope.encryptWithFixedNonce(dataKey, plaintext, aad, nonce);
    if (b64(blob) !== v.blob) {
      console.error(`encrypt vector ${i}: fixed-nonce encrypt blob MISMATCH`);
      failures += 1;
    }
    const back = await impl.envelope.decrypt(dataKey, Buffer.from(v.blob, "base64"), aad);
    if (b64(back) !== v.plaintext) {
      console.error(`encrypt vector ${i}: pinned blob decrypt MISMATCH`);
      failures += 1;
    }
  } catch (err) {
    console.error(`encrypt vector ${i}: AES-GCM failed: ${err.message}`);
    failures += 1;
  }
}

// AAD edge-case corpus (promoted 2026-09-17 from redteam/a_crypto.py A6):
// surrogates, DEL/control chars, CJK, RTL, combining marks, empty parts.
const edgeCases = vectorsJson.aad_edge_cases ?? [];
for (const c of edgeCases) {
  const got = await impl.envelope.buildAad(...c.parts);
  const want = Buffer.from(c.aad_b64, "base64");
  if (Buffer.compare(Buffer.from(got), want) !== 0) {
    console.error(`aad edge case ${c.name}: MISMATCH (${got}) != (${want})`);
    failures += 1;
  }
}

if (impl.mode.startsWith("REAL")) rmSync(buildDir, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log(`all ${vectors.length} vectors + ${encryptVectors.length} encrypt vectors + ${edgeCases.length} AAD edge cases verified`);
