/**
 * Cross-client interop pins (mobile side, WEB_PLAN P5.6): decrypt BOTH
 * fixture sections — mobile's own and the WEB client's — with the REAL
 * mobile crypto (node engine behind the same seam the device uses). If
 * either platform drifts, these pins fail. Also pins the shared
 * fingerprint format (P5.7) against the web-computed value.
 */
import { existsSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildAad, decrypt } from "../src/crypto/envelope";
import { decryptEntry, decryptInsights, decryptQuestion } from "../src/crypto/MindPatternCrypto";
import { deriveWrapKek, therapistKeyFingerprint } from "../src/crypto/sharing";
import { engine } from "../src/crypto/engine";

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
    const dataKey = Buffer.from(s.data_key, "base64");

    it("decrypts the v1 (legacy-binding) entry", () => {
      const payload = decryptEntry({ dataKey }, s.user_id, s.entry_v1.client_entry_id, s.entry_v1.blob);
      expect(payload.v).toBe(1);
      expect(payload.text).toBe((JSON.parse(s.entry_v1.payload) as { text: string }).text);
    });

    it("decrypts the version-bound v2 entry with its structured channels", () => {
      const payload = decryptEntry({ dataKey }, s.user_id, s.entry_v2.client_entry_id, s.entry_v2.blob, s.entry_v2.content_version);
      expect(payload.v).toBe(2);
      expect(payload.sleep).toBe(3);
      expect(payload.tags).toEqual(["work", "rest"]);
    });

    it("decrypts the insights and question blobs", () => {
      const insights = decryptInsights({ dataKey }, s.user_id, s.insights.blob);
      expect(insights.state_seq).toBe(9);
      const question = decryptQuestion({ dataKey }, s.user_id, s.question.for_date, s.question.blob);
      expect(question.pattern_pid).toBe("temporal:work");
    });

    it("opens the data-key wrap with the fixture's therapist private key", () => {
      const priv = engine.createPrivateKey({ key: Buffer.from(s.wrap.therapist_priv_pkcs8, "base64"), format: "der", type: "pkcs8" });
      const ephPub = engine.createPublicKey({ key: Buffer.from(s.wrap.ephemeral_pub_spki, "base64"), format: "der", type: "spki" });
      const shared = engine.diffieHellman({ privateKey: priv, publicKey: ephPub });
      const kek = deriveWrapKek(shared, Buffer.from(s.wrap.ephemeral_pub_spki, "base64"), Buffer.from(s.wrap.therapist_pub_spki, "base64"));
      const opened = decrypt(kek, Buffer.from(s.wrap.wrapped, "base64"), buildAad("consent-wrap", s.user_id, s.wrap.therapist_id));
      expect(opened.toString("base64")).toBe(s.data_key);
    });

    it("derives the identical pairing fingerprint (format parity with web + portal)", () => {
      expect(therapistKeyFingerprint(s.wrap.therapist_pub_spki)).toBe(s.fingerprint);
    });
  });
}

it("both sections exist once generation has run on both platforms", () => {
  // Audit 2026-09-25: assert BOTH sections, not just the version — a
  // degraded fixtures file must fail here rather than skip to green.
  expect(fixtures.v).toBe(1);
  expect(fixtures.web_generated).toBeDefined();
  expect(fixtures.mobile_generated).toBeDefined();
});
