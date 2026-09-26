/**
 * Interop-fixture GENERATOR (mobile side; run with GEN_INTEROP=1). Writes
 * the `mobile_generated` section of shared/interop_fixtures.json using the
 * REAL mobile crypto modules (node engine behind the same seam the device
 * uses). The web suite generated the `web_generated` section the same way;
 * both suites' pin tests decrypt BOTH sections with their own real
 * modules — cross-platform byte interop in both directions (WEB_PLAN
 * P5.6).
 *
 *   cd mobile && GEN_INTEROP=1 npx vitest run tests/interop.generate.test.ts
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildAad, encryptWithFixedNonce } from "../src/crypto/envelope";
import { decryptEntry, encryptEntry } from "../src/crypto/MindPatternCrypto";
import { deriveWrapKek, therapistKeyFingerprint } from "../src/crypto/sharing";
import { engine } from "../src/crypto/engine";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(here, "..", "..", "shared", "interop_fixtures.json");

const generate = process.env.GEN_INTEROP === "1";
const DATA_KEY_SEED = "mindpattern-interop-fixture-key!!";

describe.skipIf(!generate)("interop fixture generator (mobile)", () => {
  it("writes the mobile_generated section", async () => {
    const dataKey = Buffer.alloc(32);
    for (let i = 0; i < 32; i += 1) dataKey[i] = DATA_KEY_SEED.charCodeAt(i) & 0xff;
    const userId = "interop-user-1";
    const nonce = (n: number): Buffer => {
      const out = Buffer.alloc(12);
      out[10] = n;
      return out;
    };

    const entryV1 = encryptEntry({ dataKey }, userId, "interop-entry-v1", "Legacy-bound interop entry.", "2026-09-25T10:00:00Z", 0.25);
    const entryV2 = encryptEntry({ dataKey }, userId, "interop-entry-v2", "Structured interop entry.", "2026-09-25T11:00:00Z", -0.25, { energy: 1, sleep: 3, tags: ["work", "rest"], tod: "morning" }, 2);

    const insightsPayload = JSON.stringify({ v: 2, stats: { patterns: [] }, state_seq: 9 });
    const insightsBlob = encryptWithFixedNonce(dataKey, Buffer.from(insightsPayload, "utf8"), buildAad("insights", userId, "patterns"), nonce(1));
    const questionPayload = JSON.stringify({ for_date: "2026-09-25", question: "What took up space today?", pattern_pid: "temporal:work" });
    const questionBlob = encryptWithFixedNonce(dataKey, Buffer.from(questionPayload, "utf8"), buildAad("question", userId, "2026-09-25"), nonce(2));

    const pair = engine.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const ephPair = engine.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const therapistSpki = pair.publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const ephSpki = ephPair.publicKey.export({ format: "der", type: "spki" }) as Buffer;
    const shared = engine.diffieHellman({ privateKey: ephPair.privateKey, publicKey: pair.publicKey });
    const kek = deriveWrapKek(shared, ephSpki, therapistSpki);
    const wrapped = encryptWithFixedNonce(kek, dataKey, buildAad("consent-wrap", userId, "interop-therapist"), nonce(3));

    const section = {
      data_key: dataKey.toString("base64"),
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
      insights: { blob: insightsBlob.toString("base64"), payload: insightsPayload },
      question: { for_date: "2026-09-25", blob: questionBlob.toString("base64"), payload: questionPayload },
      wrap: {
        therapist_priv_pkcs8: (pair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64"),
        therapist_pub_spki: therapistSpki.toString("base64"),
        ephemeral_priv_pkcs8: (ephPair.privateKey.export({ format: "der", type: "pkcs8" }) as Buffer).toString("base64"),
        ephemeral_pub_spki: ephSpki.toString("base64"),
        therapist_id: "interop-therapist",
        wrapped: wrapped.toString("base64"),
      },
      fingerprint: therapistKeyFingerprint(therapistSpki.toString("base64")),
    };

    const doc = existsSync(fixturesPath)
      ? (JSON.parse(readFileSync(fixturesPath, "utf8")) as Record<string, unknown>)
      : { v: 1 };
    doc.v = 1;
    doc.mobile_generated = section;
    writeFileSync(fixturesPath, `${JSON.stringify(doc, null, 2)}\n`);
    console.log("[interop] mobile_generated section written");

    // Self-check through the shipping decrypt path.
    expect(decryptEntry({ dataKey }, userId, "interop-entry-v2", entryV2.blobB64, 2).sleep).toBe(3);
  });
});
