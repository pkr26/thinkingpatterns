import { randomUUID } from "node:crypto";
import { expect, it, vi } from "vitest";

it("clearing an account retires its item-nine process stamp while native preference reads remain unavailable", async () => {
  vi.resetModules();
  const storage = (await import("./helpers/storageMock")).default;
  const keychain = await import("./helpers/keychainMock");
  const { api } = await import("../src/api/client");
  const { accountStorageKey } = await import("../src/accountStorage");
  const { recordCrisisDialogShown, crisisDialogShownOn, clearCrisisDialogStamp } = await import("../src/crisisDialog");
  const owner = randomUUID().replace(/-/g, "");
  const day = new Date().toISOString().slice(0, 10);
  const slot = accountStorageKey.crisisItem9(owner);
  storage.__reset();
  keychain.__reset();
  await api.setSession("owned crisis stamp session", owner, "owned-stamp-account");
  const get = storage.getItem.bind(storage);
  const set = storage.setItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    if (key === slot) throw new Error("native preference read unavailable");
    return get(key);
  });
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === slot) throw new Error("native preference write unavailable");
    return set(key, value);
  });
  try {
    await recordCrisisDialogShown(owner, day, "phq9-item9");
    expect(await crisisDialogShownOn(owner, day, "phq9-item9")).toBe(true);
    await clearCrisisDialogStamp(owner);
    expect(await crisisDialogShownOn(owner, day, "phq9-item9")).toBe(false);
  } finally {
    vi.restoreAllMocks();
    await clearCrisisDialogStamp(owner);
    await api.clearSession();
    vi.resetModules();
  }
});

it("reads registered encrypted item-nine stamps and publishes the default journal stamp in its registered slot", async () => {
  vi.resetModules();
  const storage = (await import("./helpers/storageMock")).default;
  const keychain = await import("./helpers/keychainMock");
  const { api } = await import("../src/api/client");
  const { secureStore } = await import("../src/secureStore");
  const { accountStorageKey } = await import("../src/accountStorage");
  const { recordCrisisDialogShown, crisisDialogShownOn, clearCrisisDialogStamp } = await import("../src/crisisDialog");
  const owner = randomUUID().replace(/-/g, "");
  const day = new Date().toISOString().slice(0, 10);
  storage.__reset();
  keychain.__reset();
  await api.setSession("owned interoperable stamp session", owner, "owned-stamp-account");
  try {
    await secureStore.setItem(accountStorageKey.crisisItem9(owner), day);
    expect(await crisisDialogShownOn(owner, day, "phq9-item9")).toBe(true);
    expect(await crisisDialogShownOn(owner, day, "journal")).toBe(false);
    await clearCrisisDialogStamp(owner);
    await recordCrisisDialogShown(owner, day);
    expect(await crisisDialogShownOn(owner, day, "journal")).toBe(true);
    expect(await secureStore.getItem(accountStorageKey.crisisJournal(owner))).toBe(day);
    expect(await crisisDialogShownOn(owner, day, "phq9-item9")).toBe(false);
  } finally {
    vi.restoreAllMocks();
    await clearCrisisDialogStamp(owner);
    await api.clearSession();
    vi.resetModules();
  }
});
