/**
 * Cross-client interop pins (WEB_PLAN P5.6): decrypt BOTH fixture sections
 * — the one this web client generated and the one the MOBILE client
 * generated with its real modules — with the REAL web crypto. If either
 * platform drifts, these pins fail. Also pins the shared fingerprint
 * format (P5.7).
 */
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { decrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { decryptEntry, decryptInsights, decryptQuestion } from "../src/crypto/patient";
import { deriveWrapKek, keyFingerprint } from "../src/crypto/sharing";
import { buildAad } from "../src/crypto/aad";

const here = dirname(fileURLToPath(import.meta.url));
const fixturesPath = join(here, "..", "..", "shared", "interop_fixtures.json");

interface Section {
  data_key: string;
  user_id: string;
  entry_v1: { client_entry_id: string; blob: string; payload: string };
  entry_v2: { client_entry_id: string; content_version: number; blob: string; payload: string };
  insights: { blob: string; payload: string };
  question: { for_date: string; blob: string; payload: string };
  wrap: {
    therapist_priv_pkcs8: string;
    therapist_pub_spki: string;
    ephemeral_priv_pkcs8: string;
    ephemeral_pub_spki: string;
    therapist_id: string;
    wrapped: string;
  };
  fingerprint: string;
}

const fixtures = existsSync(fixturesPath)
  ? (JSON.parse(readFileSync(fixturesPath, "utf8")) as { v: number; web_generated?: Section; mobile_generated?: Section })
  : { v: 1 };

for (const [name, section] of [["web_generated", fixtures.web_generated], ["mobile_generated", fixtures.mobile_generated]] as const) {
  describe.skipIf(section === undefined)(`interop pins: ${name}`, () => {
    const s = section!;
    const dataKey = fromBase64(s.data_key);

    it("decrypts the v1 (legacy-binding) entry to the canonical payload", async () => {
      const payload = await decryptEntry(dataKey, s.user_id, s.entry_v1.client_entry_id, s.entry_v1.blob);
      expect(JSON.stringify({ ...payload, created_at: payload.created_at })).toBeDefined();
      expect(payload.text).toBe((JSON.parse(s.entry_v1.payload) as { text: string }).text);
      expect(payload.v).toBe(1);
    });

    it("decrypts the version-bound v2 entry with its structured channels", async () => {
      const payload = await decryptEntry(dataKey, s.user_id, s.entry_v2.client_entry_id, s.entry_v2.blob, s.entry_v2.content_version);
      expect(payload.v).toBe(2);
      expect(payload.sleep).toBe(3);
      expect(payload.tags).toEqual(["work", "rest"]);
      expect(payload.text).toBe((JSON.parse(s.entry_v2.payload) as { text: string }).text);
    });

    it("decrypts the insights and question blobs byte-identically", async () => {
      const insights = await decryptInsights(dataKey, s.user_id, s.insights.blob);
      expect(insights.state_seq).toBe(9);
      const question = await decryptQuestion(dataKey, s.user_id, s.question.for_date, s.question.blob);
      expect(question.pattern_pid).toBe("temporal:work");
    });

    it("opens the data-key wrap with the fixture's therapist private key", async () => {
      const priv = await crypto.subtle.importKey("pkcs8", fromBase64(s.wrap.therapist_priv_pkcs8), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
      const ephPub = await crypto.subtle.importKey("spki", fromBase64(s.wrap.ephemeral_pub_spki), { name: "ECDH", namedCurve: "P-256" }, false, []);
      const sharedBits = await crypto.subtle.deriveBits({ name: "ECDH", public: ephPub }, priv, 256);
      const kek = await deriveWrapKek(new Uint8Array(sharedBits), fromBase64(s.wrap.ephemeral_pub_spki), fromBase64(s.wrap.therapist_pub_spki));
      const opened = await decrypt(kek, fromBase64(s.wrap.wrapped), buildAad("consent-wrap", s.user_id, s.wrap.therapist_id));
      expect(toBase64(opened)).toBe(s.data_key);
    });

    it("derives the identical pairing fingerprint", async () => {
      expect(await keyFingerprint(s.wrap.therapist_pub_spki)).toBe(s.fingerprint);
    });
  });
}

it("both sections exist once generation has run on both platforms", () => {
  // Audit 2026-09-25: this guard used to assert only `v === 1` while the
  // pin describes above used skipIf — deleting either section from the
  // committed fixtures left both suites silently green. The committed file
  // carries BOTH platforms' sections; a degraded file must FAIL here, not
  // skip to green.
  expect(fixtures.v).toBe(1);
  expect(fixtures.web_generated).toBeDefined();
  expect(fixtures.mobile_generated).toBeDefined();
});
