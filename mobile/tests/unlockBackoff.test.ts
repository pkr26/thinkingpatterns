import { runTestControl } from "./helpers/testControl";
/**
 * S-5 (pentest 2026-09-26): the escalating offline-unlock failure pad.
 * Pins the delay curve (first failure pays the historical 500 ms, doubling
 * to the 30 s cap, saturating), the durable per-account counter under the
 * encrypted secure-store envelope, corrupt-reads-as-zero, and the
 * success-clears contract.
 */
import { beforeEach, describe, expect, it } from "vitest";
import storage from "./helpers/storageMock";
import * as Keychain from "react-native-keychain";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import {
  BASE_UNLOCK_FAIL_DELAY_MS,
  MAX_TRACKED_UNLOCK_FAILURES,
  MAX_UNLOCK_FAIL_DELAY_MS,
  clearUnlockFailures,
  recordUnlockFailure,
  unlockFailureCount,
  unlockFailureDelayMs,
} from "../src/unlockBackoff";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { api } from "../src/api/client";

const USER = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

beforeEach(async () => {
  storage.__reset();
  (Keychain as unknown as { __reset: () => void }).__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(setSecureStoreBackend, null);
  await api.setSession("token", USER, "alice");
});

describe("unlockFailureDelayMs (the curve)", () => {
  it("first failure pays exactly the historical 500 ms constant", () => {
    expect(unlockFailureDelayMs(1)).toBe(BASE_UNLOCK_FAIL_DELAY_MS);
    expect(BASE_UNLOCK_FAIL_DELAY_MS).toBe(500);
  });

  it("doubles per consecutive failure and caps at 30 s", () => {
    expect(unlockFailureDelayMs(2)).toBe(1_000);
    expect(unlockFailureDelayMs(3)).toBe(2_000);
    expect(unlockFailureDelayMs(4)).toBe(4_000);
    expect(unlockFailureDelayMs(5)).toBe(8_000);
    expect(unlockFailureDelayMs(6)).toBe(16_000);
    expect(unlockFailureDelayMs(7)).toBe(MAX_UNLOCK_FAIL_DELAY_MS);
    expect(unlockFailureDelayMs(99)).toBe(MAX_UNLOCK_FAIL_DELAY_MS);
    expect(MAX_UNLOCK_FAIL_DELAY_MS).toBe(30_000);
  });

  it("treats degenerate counts as the first failure, never zero or negative", () => {
    expect(unlockFailureDelayMs(0)).toBe(BASE_UNLOCK_FAIL_DELAY_MS);
    expect(unlockFailureDelayMs(-5)).toBe(BASE_UNLOCK_FAIL_DELAY_MS);
  });
});

describe("the durable per-account counter", () => {
  it("records, saturates, persists encrypted, and clears on success", async () => {
    expect(await unlockFailureCount("alice")).toBe(0);

    for (let i = 1; i <= MAX_TRACKED_UNLOCK_FAILURES + 5; i += 1) {
      const n = await recordUnlockFailure("alice", USER);
      expect(n).toBe(Math.min(i, MAX_TRACKED_UNLOCK_FAILURES));
    }
    expect(await unlockFailureCount("alice")).toBe(MAX_TRACKED_UNLOCK_FAILURES);

    // The stored value is inside the encrypted envelope — no plaintext
    // counter in AsyncStorage, and no device key there either.
    const raw = await storage.getItem("mindpattern.unlockFail.alice");
    expect(raw).not.toBeNull();
    expect(raw).not.toContain(String(MAX_TRACKED_UNLOCK_FAILURES));
    expect(await storage.getItem("@mindpattern/device_k")).toBeNull();

    await clearUnlockFailures("alice", USER);
    expect(await unlockFailureCount("alice")).toBe(0);
    expect(await storage.getItem("mindpattern.unlockFail.alice")).toBeNull();
  });

  it("counts are per-account and corrupt reads are zero (never a brick)", async () => {
    await recordUnlockFailure("alice", USER);
    expect(await unlockFailureCount("bob")).toBe(0);
    await storage.setItem("mindpattern.unlockFail.carol", "not-an-envelope");
    expect(await unlockFailureCount("carol")).toBe(0);
    await storage.setItem("mindpattern.unlockFail.dan", "9999");
    expect(await secureStore.getItem("mindpattern.unlockFail.dan")).toBeNull(); // corrupt -> absent
    expect(await unlockFailureCount("dan")).toBe(0);
  });
});
