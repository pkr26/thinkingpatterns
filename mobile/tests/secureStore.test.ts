/**
 * H3: session material is encrypted at rest. A device backup must not
 * contain a greppable bearer token or username.
 */
import { beforeEach, describe, expect, it } from "vitest";
import storage from "./helpers/storageMock";
import { secureStore } from "../src/secureStore";

beforeEach(() => {
  storage.__reset();
});

describe("secureStore", () => {
  it("round-trips values", async () => {
    await secureStore.setItem("@mindpattern/token", "tok-abc");
    expect(await secureStore.getItem("@mindpattern/token")).toBe("tok-abc");
    await secureStore.removeItem("@mindpattern/token");
    expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  });

  it("never persists the plaintext value", async () => {
    await secureStore.setItem("@mindpattern/token", "tok-secret-value");
    const raw = await storage.getItem("@mindpattern/token");
    expect(raw).not.toBeNull();
    expect(raw).not.toBe("tok-secret-value");
    expect(raw).not.toContain("tok-secret-value");
    // And nothing else in the store holds it either.
    for (const [key, value] of (storage as unknown as { __entries?: [string, string][] }).__entries ?? []) {
      expect(value).not.toContain("tok-secret-value");
    }
  });

  it("corrupt ciphertext reads as absent instead of throwing", async () => {
    await secureStore.setItem("k", "v");
    await storage.setItem("k", "garbage-not-ciphertext");
    expect(await secureStore.getItem("k")).toBeNull();
  });

  it("different values encrypt to different ciphertexts (random nonces)", async () => {
    await secureStore.setItem("a", "same");
    await secureStore.setItem("b", "same");
    expect(await storage.getItem("a")).not.toBe(await storage.getItem("b"));
  });
});
