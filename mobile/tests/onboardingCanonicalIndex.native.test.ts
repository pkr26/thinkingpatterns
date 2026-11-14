import AsyncStorage from "@react-native-async-storage/async-storage";
import { beforeEach, expect, it, vi } from "vitest";
import { accountStorageKey } from "../src/accountStorage";
import { loadOnboardingPanel } from "../src/onboarding";
import storage from "./helpers/storageMock";

beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); });

it.each(["-0", "-000"])("normalizes the stored signed-zero panel %s to the canonical first-panel index", async stored => {
  const owner = "a".repeat(32);
  await AsyncStorage.setItem(accountStorageKey.onboardingPanel(owner), stored);
  const index = await loadOnboardingPanel(3, owner);
  // This is the exported numeric result, including its sign, rather than
  // an internal parser state or a storage-call count.
  expect(index).toBe(0);
});

it("starts a fresh application module without a pending registration invitation", async () => {
  vi.resetModules();
  const { takePendingOnboarding } = await import("../src/onboarding");
  expect(takePendingOnboarding()).toBe(false);
});
