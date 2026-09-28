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
import { readFileSync, rmSync, mkdirSync, writeFileSync } from "node:fs";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { webcrypto, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from "node:crypto";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsPath = join(here, "..", "..", "shared", "vectors.json");
const tscBin = join(here, "..", "node_modules", ".bin", "tsc");
const buildDir = join(here, "..", ".verify-build");

const vectorsJson = JSON.parse(readFileSync(vectorsPath, "utf8"));
const {
  vectors,
  encrypt_vectors: encryptVectors,
  wrap_vectors: wrapVectors,
  aad_edge_cases: edgeCases,
  envelope_vectors: envelopeVectors,
} = vectorsJson;
// Fail CLOSED on EVERY section: a renamed/dropped/gutted key must not read
// as "0 vectors verified" and exit 0. wrap_vectors and aad_edge_cases have
// no generator — they are hand-maintained, so a generator that overwrites
// the file wholesale is exactly the drift this gate must catch.
if (!Array.isArray(vectors) || vectors.length < 4) {
  console.error(`vectors.json: "vectors" key missing or has ${vectors?.length ?? "no"} entries (expected >= 4)`);
  process.exit(1);
}
if (!Array.isArray(encryptVectors) || encryptVectors.length < 2) {
  console.error(`vectors.json: "encrypt_vectors" key missing or has ${encryptVectors?.length ?? "no"} entries (expected >= 2)`);
  process.exit(1);
}
if (!Array.isArray(wrapVectors) || wrapVectors.length < 3) {
  console.error(`vectors.json: "wrap_vectors" key missing or has ${wrapVectors?.length ?? "no"} entries (expected >= 3, hand-maintained section with no generator)`);
  process.exit(1);
}
if (!Array.isArray(edgeCases) || edgeCases.length < 1) {
  console.error(`vectors.json: "aad_edge_cases" key missing or has ${edgeCases?.length ?? "no"} entries (expected >= 1, hand-maintained section with no generator)`);
  process.exit(1);
}
// envelope_vectors (2026-09-28 audit): the v2 entry AAD (4-part
// content_version binding) and the v2 key-envelope wrap were pinned in
// shared/vectors.json but this verifier never read the section — a
// regression in either construction would have sailed through. Same
// fail-closed shape as the other sections.
if (!Array.isArray(envelopeVectors) || envelopeVectors.length < 4) {
  console.error(`vectors.json: "envelope_vectors" key missing or has ${envelopeVectors?.length ?? "no"} entries (expected >= 4: entry-aad-v2 +/- tamper, key-envelope-wrap +/- tamper)`);
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
    join(here, "..", "src", "crypto", "sharing.ts"),
    join(here, "..", "src", "crypto", "keyEnvelope.ts"),
    "--module", "commonjs",
    "--target", "es2022",
    "--esModuleInterop",
    "--skipLibCheck",
    "--outDir", buildDir,
  ], { stdio: "pipe", cwd: join(here, "..") });
  if (compiled.status !== 0) {
    console.error("tsc failed to compile src/crypto:\n" + compiled.stderr.toString());
    process.exit(1);
  }
  // The mobile package is ESM so Vitest's config can use the native loader,
  // but this verifier deliberately emits CommonJS: engine.ts then exercises
  // its `require("node:crypto")` fallback. Scope that module format to the
  // disposable output directory instead of changing the shipping package.
  writeFileSync(join(buildDir, "package.json"), '{"type":"commonjs"}\n');
  // engine.js's conditional require: quick-crypto fails under node -> node:crypto.
  const kdf = await import(join(buildDir, "kdf.js"));
  const envelope = await import(join(buildDir, "envelope.js"));
  const sharing = await import(join(buildDir, "sharing.js"));
  const keyEnvelope = await import(join(buildDir, "keyEnvelope.js"));
  return { kdf, envelope, sharing, keyEnvelope, mode: "REAL MODULES" };
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
    // Reference copy of sharing.ts's KEK derivation (HKDF-SHA256, salt =
    // ephemeral_spki || therapist_spki, info "mindpattern/wrap/v1") for the
    // webcrypto fallback ONLY — in REAL MODULES mode the shipping
    // sharing.deriveWrapKek is used. ECDH itself is node:crypto in both
    // modes (webcrypto has no raw ECDH-secret export usable here).
    sharing: {
      WRAP_CONTEXT: "consent-wrap",
      deriveWrapKek: (shared, ephemeralSpki, therapistSpki) => Buffer.from(
        hkdfSync(
          "sha256", shared, Buffer.concat([ephemeralSpki, therapistSpki]),
          Buffer.from("mindpattern/wrap/v1", "utf8"), 32)),
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

// Therapist-sharing wrap vectors (hand-maintained section, no generator):
// reproduce the pinned wrap bytes through the SHIPPING sharing.ts
// construction, then prove the therapist side unwraps them back to the
// data key. Both directions together also pin that the vector's pub/priv
// keypairs are consistent (a mismatched pair yields a different ECDH
// secret and GCM auth failure).
for (const [i, v] of wrapVectors.entries()) {
  const ephemeralSpki = Buffer.from(v.ephemeral_pub_spki, "base64");
  const therapistSpki = Buffer.from(v.therapist_pub_spki, "base64");
  const dataKey = Buffer.from(v.data_key, "base64");
  const nonce = Buffer.from(v.nonce, "base64");
  const wrapped = Buffer.from(v.wrapped, "base64");
  const aad = await impl.envelope.buildAad(impl.sharing.WRAP_CONTEXT, v.user_id, v.therapist_id);
  try {
    // Patient side with the vector's fixed keys — the exact construction
    // wrapDataKeyForTherapist runs on device:
    //   ECDH(ephemeral_priv, therapist_pub) -> deriveWrapKek ->
    //   buildAad("consent-wrap", userId, therapistId) -> AES-256-GCM.
    const shared = diffieHellman({
      privateKey: createPrivateKey({
        key: Buffer.from(v.ephemeral_priv_pkcs8, "base64"), format: "der", type: "pkcs8",
      }),
      publicKey: createPublicKey({ key: therapistSpki, format: "der", type: "spki" }),
    });
    const kek = impl.sharing.deriveWrapKek(shared, ephemeralSpki, therapistSpki);
    const blob = await impl.envelope.encryptWithFixedNonce(kek, dataKey, aad, nonce);
    if (b64(blob) !== v.wrapped) {
      console.error(`wrap vector ${i}: pinned wrap bytes MISMATCH`);
      failures += 1;
    }
    // Therapist side: the vector's therapist private key must unwrap the
    // pinned blob back to the data key.
    const sharedT = diffieHellman({
      privateKey: createPrivateKey({
        key: Buffer.from(v.therapist_priv_pkcs8, "base64"), format: "der", type: "pkcs8",
      }),
      publicKey: createPublicKey({ key: ephemeralSpki, format: "der", type: "spki" }),
    });
    const kekT = impl.sharing.deriveWrapKek(sharedT, ephemeralSpki, therapistSpki);
    const back = await impl.envelope.decrypt(kekT, wrapped, aad);
    if (b64(back) !== v.data_key) {
      console.error(`wrap vector ${i}: therapist-side unwrap MISMATCH`);
      failures += 1;
    }
  } catch (err) {
    console.error(`wrap vector ${i}: wrap verification failed: ${err.message}`);
    failures += 1;
  }
}

// A fresh on-device wrap through the shipping wrapDataKeyForTherapist must
// unwrap on the therapist side with a fresh ephemeral key (REAL MODULES
// only — the webcrypto fallback has no copy of the app's wrap code).
if (impl.mode.startsWith("REAL")) {
  const v = wrapVectors[0];
  const dataKey = Buffer.from(v.data_key, "base64");
  const therapistSpki = Buffer.from(v.therapist_pub_spki, "base64");
  try {
    const wrap = impl.sharing.wrapDataKeyForTherapist(dataKey, v.therapist_pub_spki, v.user_id, v.therapist_id);
    if (wrap.ephemeralPubB64 === v.ephemeral_pub_spki) {
      console.error("wrap round-trip: fresh wrap reused the vector's ephemeral key");
      failures += 1;
    }
    const ephemeralSpki = Buffer.from(wrap.ephemeralPubB64, "base64");
    const sharedT = diffieHellman({
      privateKey: createPrivateKey({
        key: Buffer.from(v.therapist_priv_pkcs8, "base64"), format: "der", type: "pkcs8",
      }),
      publicKey: createPublicKey({ key: ephemeralSpki, format: "der", type: "spki" }),
    });
    const kekT = impl.sharing.deriveWrapKek(sharedT, ephemeralSpki, therapistSpki);
    const aad = await impl.envelope.buildAad(impl.sharing.WRAP_CONTEXT, v.user_id, v.therapist_id);
    const back = await impl.envelope.decrypt(kekT, Buffer.from(wrap.wrappedKeyB64, "base64"), aad);
    if (b64(back) !== v.data_key) {
      console.error("wrap round-trip: fresh wrap did not unwrap to the data key");
      failures += 1;
    }
  } catch (err) {
    console.error(`wrap round-trip failed: ${err.message}`);
    failures += 1;
  }
} else {
  console.log("note: webcrypto fallback cannot exercise wrapDataKeyForTherapist (fresh-wrap round-trip skipped) — run `npm install && npm test` for that");
}

// AAD edge-case corpus (promoted 2026-09-17 from redteam/a_crypto.py A6):
// surrogates, DEL/control chars, CJK, RTL, combining marks, empty parts.
for (const c of edgeCases) {
  const got = await impl.envelope.buildAad(...c.parts);
  const want = Buffer.from(c.aad_b64, "base64");
  if (Buffer.compare(Buffer.from(got), want) !== 0) {
    console.error(`aad edge case ${c.name}: MISMATCH (${got}) != (${want})`);
    failures += 1;
  }
}

// envelope_vectors (2026-09-28 audit): the v2 entry AAD (content_version
// bound as the 4th part) and the v2 key-envelope wrap, replayed through the
// same compiled modules as every other section. Entry vectors run in BOTH
// modes (the fallback implements derive/buildAad/decrypt); the key-envelope
// vectors exercise keyEnvelope.ts and are REAL MODULES only.
for (const [i, v] of envelopeVectors.entries()) {
  const salt = Buffer.from(v.salt, "base64");
  if (v.kind === "entry-aad-v2" || v.kind === "entry-aad-v2-tampered") {
    try {
      const master = await impl.kdf.deriveMasterKey(v.password, salt, v.iterations);
      const dataKey = await impl.kdf.deriveDataKey(master);
      if (b64(dataKey) !== v.data_key) {
        console.error(`envelope vector ${i} (${v.kind}): data_key MISMATCH`);
        failures += 1;
        continue;
      }
      const aad = await impl.envelope.buildAad(...v.aad_parts);
      const blob = Buffer.from(v.blob, "base64");
      if (v.expect === "tamper") {
        try {
          await impl.envelope.decrypt(dataKey, blob, aad);
          console.error(`envelope vector ${i} (${v.kind}): tampered blob DECRYPTED — must fail closed`);
          failures += 1;
        } catch {
          // expected: GCM authentication failure
        }
      } else {
        const plaintext = await impl.envelope.decrypt(dataKey, blob, aad);
        if (b64(plaintext) !== v.plaintext) {
          console.error(`envelope vector ${i} (${v.kind}): plaintext MISMATCH`);
          failures += 1;
        }
        // Re-encrypt with the pinned nonce: the blob must reproduce exactly,
        // pinning the 4-part AAD on the ENCRYPT side too.
        const nonce = Buffer.from(v.nonce, "base64");
        const reBlob = await impl.envelope.encryptWithFixedNonce(dataKey, plaintext, aad, nonce);
        if (b64(reBlob) !== v.blob) {
          console.error(`envelope vector ${i} (${v.kind}): fixed-nonce re-encrypt blob MISMATCH`);
          failures += 1;
        }
      }
    } catch (err) {
      console.error(`envelope vector ${i} (${v.kind}): ${err.message}`);
      failures += 1;
    }
  } else if (v.kind === "key-envelope-wrap" || v.kind === "key-envelope-wrap-tampered") {
    if (!impl.keyEnvelope) {
      console.log(`note: webcrypto fallback cannot exercise ${v.kind} (keyEnvelope.ts is app code) — run \`npm install && node tools/verify_vectors.mjs\` for that`);
      continue;
    }
    try {
      const master = await impl.kdf.deriveMasterKey(v.password, salt, v.iterations);
      if (b64(master) !== v.master_key) {
        console.error(`envelope vector ${i} (${v.kind}): master_key MISMATCH`);
        failures += 1;
      }
      // KEK = HKDF(master, salt, "mindpattern/envelope/v2") through the
      // SHIPPING envelopeKek, then the OBJECT-shaped AAD through the
      // shipping envelopeAad under the vector's kdf_params.
      const kek = impl.keyEnvelope.envelopeKek(master, salt);
      if (b64(kek) !== v.kek) {
        console.error(`envelope vector ${i} (${v.kind}): kek MISMATCH`);
        failures += 1;
      }
      const params = impl.keyEnvelope.validateKdfParams(v.kdf_params);
      if (params == null) {
        console.error(`envelope vector ${i} (${v.kind}): vector kdf_params rejected by validateKdfParams`);
        failures += 1;
        continue;
      }
      const aad = impl.keyEnvelope.envelopeAad(v.username, params);
      if (b64(aad) !== v.aad) {
        console.error(`envelope vector ${i} (${v.kind}): envelope AAD MISMATCH`);
        failures += 1;
      }
      const wrapped = Buffer.from(v.wrapped, "base64");
      if (v.expect === "tamper") {
        try {
          impl.keyEnvelope.unwrapDataKey(wrapped, kek, v.username, params);
          console.error(`envelope vector ${i} (${v.kind}): tampered wrap UNWRAPPED — must fail closed`);
          failures += 1;
        } catch (err) {
          if (!(err instanceof impl.keyEnvelope.TamperError) && !/auth/i.test(String(err))) {
            console.error(`envelope vector ${i} (${v.kind}): unexpected failure shape: ${err.message}`);
            failures += 1;
          }
        }
      } else {
        // Reproduce the pinned wrap bytes (fixed-nonce form), then unwrap
        // them back to the data key through the shipping construction.
        const nonce = Buffer.from(v.nonce, "base64");
        const dataKey = Buffer.from(v.data_key, "base64");
        const reWrapped = impl.keyEnvelope.wrapDataKeyWithFixedNonce(
          dataKey, kek, v.username, params, nonce);
        if (b64(reWrapped) !== v.wrapped) {
          console.error(`envelope vector ${i} (${v.kind}): fixed-nonce re-wrap MISMATCH`);
          failures += 1;
        }
        const back = impl.keyEnvelope.unwrapDataKey(wrapped, kek, v.username, params);
        if (b64(back) !== v.data_key) {
          console.error(`envelope vector ${i} (${v.kind}): unwrap did not return the data key`);
          failures += 1;
        }
      }
    } catch (err) {
      console.error(`envelope vector ${i} (${v.kind}): ${err.message}`);
      failures += 1;
    }
  } else {
    console.error(`envelope vector ${i}: unknown kind ${JSON.stringify(v.kind)}`);
    failures += 1;
  }
}

if (impl.mode.startsWith("REAL")) rmSync(buildDir, { recursive: true, force: true });

if (failures > 0) {
  console.error(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
console.log(
  `all ${vectors.length} vectors + ${encryptVectors.length} encrypt vectors + ` +
  `${wrapVectors.length} wrap vectors + ${edgeCases.length} AAD edge cases + ` +
  `${envelopeVectors.length} envelope vectors verified`);
