/**
 * Interop-fixture GENERATOR (run with GEN_INTEROP=1; skipped otherwise).
 * Encrypts canonical blobs with the REAL web crypto modules and writes the
 * `web_generated` section of shared/interop_fixtures.json. The mobile
 * suite generates the symmetric `mobile_generated` section the same way;
 * BOTH suites' pin tests then decrypt BOTH sections with their own real
 * modules — cross-platform byte interop in both directions (WEB_PLAN
 * P5.6, D-2).
 *
 *   cd web && GEN_INTEROP=1 npx vitest run tests/interop.generate.test.ts
 *   cd mobile && GEN_INTEROP=1 npx vitest run tests/interop.generate.test.ts
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildAad } from "../src/crypto/aad";
import { encryptWithFixedNonce, toBase64, type Bytes } from "../src/crypto/core";
import { decryptInsights, decryptQuestion, encryptEntry } from "../src/crypto/patient";
import { deriveWrapKek, keyFingerprint } from "../src/crypto/sharing";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(here, "..", "..", "shared", "interop_fixtures.json");

const generate = process.env.GEN_INTEROP === "1";
const DATA_KEY_SEED = "mindpattern-interop-fixture-key!!"; // first 32 bytes

describe.skipIf(!generate)("interop fixture generator (web)", () => {
  it("writes the web_generated section", async () => {
    const dataKey = new Uint8Array(new ArrayBuffer(32));
    for (let i = 0; i < 32; i += 1) dataKey[i] = DATA_KEY_SEED.charCodeAt(i) & 0xff;
    const userId = "interop-user-1";
    const nonce = (n: number): Bytes => {
      const out = new Uint8Array(new ArrayBuffer(12));
      out[10] = n;
      return out;
    };

    // Entries use the SHIPPING encryptEntry (production-shaped, random
    // nonce) — pins verify by decryption, so only the fixed-nonce
    // constructions below need determinism.
    const entryV1 = await encryptEntry(dataKey, userId, "interop-entry-v1", "Legacy-bound interop entry.", "2026-09-25T10:00:00Z", 0.25);
    const entryV2 = await encryptEntry(dataKey, userId, "interop-entry-v2", "Structured interop entry.", "2026-09-25T11:00:00Z", -0.25, { energy: 1, sleep: 3, tags: ["work", "rest"], tod: "morning" }, 2);

    const insightsPayload = JSON.stringify({ v: 2, stats: { patterns: [] }, state_seq: 9 });
    const insightsBlob = await encryptWithFixedNonce(dataKey, new TextEncoder().encode(insightsPayload), nonce(1), buildAad("insights", userId, "patterns"));
    const questionPayload = JSON.stringify({ for_date: "2026-09-25", question: "What took up space today?", pattern_pid: "temporal:work" });
    const questionBlob = await encryptWithFixedNonce(dataKey, new TextEncoder().encode(questionPayload), nonce(2), buildAad("question", userId, "2026-09-25"));

    // The wrap construction with fixture-held keys, fixed nonce.
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const ephPair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const therapistSpki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
    const ephSpki = new Uint8Array(await crypto.subtle.exportKey("spki", ephPair.publicKey));
    const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: pair.publicKey }, ephPair.privateKey, 256);
    const kek = await deriveWrapKek(new Uint8Array(sharedBits), ephSpki, therapistSpki);
    const wrapped = await encryptWithFixedNonce(kek, dataKey, nonce(3), buildAad("consent-wrap", userId, "interop-therapist"));

    const section = {
      data_key: toBase64(dataKey),
      user_id: userId,
      entry_v1: {
        client_entry_id: "interop-entry-v1",
        blob: entryV1.blobB64,
        payload: JSON.stringify({ v: 1, text: "Legacy-bound interop entry.", sentiment: 0.25, created_at: "2026-09-25T10:00:00Z" }),
      },
      entry_v2: {
        client_entry_id: "interop-entry-v2",
        content_version: 2,
        blob: entryV2.blobB64,
        payload: JSON.stringify({ v: 2, text: "Structured interop entry.", sentiment: -0.25, created_at: "2026-09-25T11:00:00Z", energy: 1, sleep: 3, tags: ["work", "rest"], tod: "morning" }),
      },
      insights: { blob: toBase64(insightsBlob), payload: insightsPayload },
      question: { for_date: "2026-09-25", blob: toBase64(questionBlob), payload: questionPayload },
      wrap: {
        therapist_priv_pkcs8: toBase64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey))),
        therapist_pub_spki: toBase64(therapistSpki),
        ephemeral_priv_pkcs8: toBase64(new Uint8Array(await crypto.subtle.exportKey("pkcs8", ephPair.privateKey))),
        ephemeral_pub_spki: toBase64(ephSpki),
        therapist_id: "interop-therapist",
        wrapped: toBase64(wrapped),
      },
      fingerprint: await keyFingerprint(toBase64(therapistSpki)),
    };

    const doc = existsSync(fixturesPath)
      ? (JSON.parse(readFileSync(fixturesPath, "utf8")) as Record<string, unknown>)
      : { v: 1 };
    doc.v = 1;
    doc.web_generated = section;
    writeFileSync(fixturesPath, `${JSON.stringify(doc, null, 2)}\n`);
    console.log("[interop] web_generated section written");

    // Self-check through the shipping decrypt paths before committing.
    expect((await decryptInsights(dataKey, userId, toBase64(insightsBlob))).state_seq).toBe(9);
    expect((await decryptQuestion(dataKey, userId, "2026-09-25", toBase64(questionBlob))).pattern_pid).toBe("temporal:work");
  });
});
