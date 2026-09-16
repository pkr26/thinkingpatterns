/**
 * Regression pins for the 2026-09-16 red-team remediation wave
 * (reports/redteam_audit_2026-09-16.md), mobile side. The obfuscation
 * corpus for crisis detection is pinned cross-engine by the shared JSON
 * fixtures (crisisPhrases.test.ts replays them); these tests cover the
 * fixes that are mobile-only behavior.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import AsyncStorage from "@react-native-async-storage/async-storage";

import { normalizeCrisisText } from "../src/crisisDetect";
import { KDF_ITERATIONS, MIN_ITERATIONS, deriveMasterKey, deriveMasterKeyAsync } from "../src/crypto/kdf";
import { encrypt } from "../src/crypto/envelope";
import { detailToMessage, api } from "../src/api/client";

beforeEach(() => {
  (AsyncStorage as unknown as { __reset(): void }).__reset();
});

describe("A4: KDF iteration floor (client side)", () => {
  it("refuses to derive below MIN_ITERATIONS", () => {
    const salt = Buffer.alloc(16, 7);
    expect(() => deriveMasterKey("pw", salt, 1)).toThrow(/iterations must be at least/);
    expect(() => deriveMasterKey("pw", salt, MIN_ITERATIONS - 1)).toThrow(/iterations must be at least/);
  });

  it("still derives at the floor and at the production default", async () => {
    const salt = Buffer.alloc(16, 7);
    expect(deriveMasterKey("pw", salt, MIN_ITERATIONS).length).toBe(32);
    expect((await deriveMasterKeyAsync("pw", salt, MIN_ITERATIONS)).length).toBe(32);
    expect(KDF_ITERATIONS).toBe(600_000);
    expect(MIN_ITERATIONS).toBeGreaterThanOrEqual(100_000);
  });
});

describe("A5: production encrypt() has no nonce parameter", () => {
  it("always randomizes (two calls differ)", () => {
    const key = Buffer.alloc(32, 3);
    expect(encrypt(key, Buffer.from("x"))).not.toEqual(encrypt(key, Buffer.from("x")));
  });
});

describe("E1: crisis normalization engine (mobile side)", () => {
  it("folds leetspeak, homoglyphs, invisible chars and separators", () => {
    expect(normalizeCrisisText("Ѕuіϲіde​ thoughts…")).toBe("suicide thoughts");
    expect(normalizeCrisisText("s.u.i.c.i.d.e")).toBe("suicide");
    expect(normalizeCrisisText("s u i c i d e")).toBe("suicide");
    expect(normalizeCrisisText("k1ll myself")).toBe("kill myself");
    expect(normalizeCrisisText("su­icide")).toBe("suicide");
    expect(normalizeCrisisText("1 want to d1e so bad")).toBe("1 want to die so bad");
  });

  it("does not eat ordinary prose", () => {
    expect(normalizeCrisisText("i am so sad today")).toBe("i am so sad today");
    expect(normalizeCrisisText("to be or not to be that is the question")).toBe(
      "to be or not to be that is the question",
    );
    expect(normalizeCrisisText("u s a won gold")).toBe("u s a won gold");
  });

  it("is idempotent", () => {
    const once = normalizeCrisisText("Ѕuіϲіde​ thoughts…");
    expect(normalizeCrisisText(once)).toBe(once);
  });

  it("passes unmapped characters in the homoglyph ranges through untouched", () => {
    // б г д ж ц ш щ have no Latin lookalike mapping — they must survive
    // (only the confusable subset folds).
    expect(normalizeCrisisText("бгдж цшщ")).toBe("бгдж цшщ");
  });

  it("keeps non-latin single-letter tokens unjoined", () => {
    // Digits and CJK singles never enter the latin join rule.
    expect(normalizeCrisisText("5 五 x ray")).toBe("5 五 x ray");
  });

  it("folds chained leet digits through repeated passes", () => {
    expect(normalizeCrisisText("un4l1ve myself")).toBe("unalive myself");
    expect(normalizeCrisisText("no leet here at all")).toBe("no leet here at all");
  });
});

describe("F2: error-dialog sanitizer (scheme-less domains, phone digits)", () => {
  it("strips bare domains and phone-like digit runs", () => {
    expect(detailToMessage("go to evil.com/support for help", 400)).not.toContain("evil.com");
    expect(detailToMessage("call 555-0134 now", 400)).not.toContain("555");
    expect(detailToMessage("see https://evil.example/x", 400)).not.toContain("evil");
    expect(detailToMessage("open mindpattern-support://x", 400)).not.toContain("://");
  });

  it("keeps ordinary messages readable", () => {
    const out = detailToMessage("username is taken; try another in 5 minutes", 409);
    expect(out).toContain("username is taken");
    expect(out).toContain("5 minutes");
  });
});

describe("F2: the data key never rides plain HTTP", () => {
  it("openProcessingSession refuses a consented insecure URL before any fetch", async () => {
    await AsyncStorage.setItem("@mindpattern/base_url", "http://attacker.example");
    await AsyncStorage.setItem("@mindpattern/insecure_http_ok", "http://attacker.example");
    const spy = vi.fn();
    vi.stubGlobal("fetch", spy);
    try {
      await expect(
        api.openProcessingSession(Buffer.alloc(32, 9).toString("base64")),
      ).rejects.toThrow(/HTTPS/);
      expect(spy).not.toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("allows loopback http (local development servers)", async () => {
    await AsyncStorage.setItem("@mindpattern/base_url", "http://localhost:8000");
    const spy = vi.fn(async () => ({
      ok: true,
      status: 201,
      url: "http://localhost:8000/api/v1/processing/sessions",
      headers: new Headers({ "Content-Type": "application/json" }),
      json: async () => ({ session_token: "st", expires_in: 300 }),
    }));
    vi.stubGlobal("fetch", spy);
    try {
      const out = await api.openProcessingSession(Buffer.alloc(32, 9).toString("base64"));
      expect(out.session_token).toBe("st");
      expect(spy).toHaveBeenCalled();
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
