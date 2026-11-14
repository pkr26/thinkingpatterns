import { expect, it, vi } from "vitest";
import { advanceLocalWriteScope, localWriteScopeEpoch, subscribeLocalWriteScope } from "../src/localWriteGuard";

it("scope retirement survives throwing and reentrant subscribers and unsubscription", async () => {
  const start = localWriteScopeEpoch();
  let reentered = false;
  const throwing = vi.fn(() => { throw new Error("subscriber failed"); });
  const observer = vi.fn(() => {
    if (!reentered) { reentered = true; advanceLocalWriteScope(); }
  });
  const stopThrowing = subscribeLocalWriteScope(throwing), stopObserver = subscribeLocalWriteScope(observer);
  try {
    expect(advanceLocalWriteScope()).toBe(start + 1);
    expect(localWriteScopeEpoch()).toBe(start + 1);
    await vi.waitFor(() => expect(observer).toHaveBeenCalledTimes(2));
    expect(localWriteScopeEpoch()).toBe(start + 2);
    expect(throwing).toHaveBeenCalledTimes(2);
  } finally { stopThrowing(); stopObserver(); }
  advanceLocalWriteScope();
  expect(observer).toHaveBeenCalledTimes(2);
});

it("a newer reentrant server selection retires the older selection", async () => {
  const { setBaseUrl, getBaseUrl } = await import("../src/api/client");
  const storage = (await import("./helpers/storageMock")).default;
  const keychain = await import("./helpers/keychainMock");
  const { setSecureStoreBackend } = await import("../src/secureStore");
  const { runTestControl } = await import("./helpers/testControl");
  storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  expect(await setBaseUrl("http://localhost:8000")).toBeNull();
  let triggered = false, newer: Promise<string | null> | undefined;
  const stop = subscribeLocalWriteScope(() => {
    if (!triggered) { triggered = true; newer = setBaseUrl("http://localhost:8000/new"); }
  });
  try {
    const older = setBaseUrl("http://localhost:9000");
    const olderOutcome = older.then(value => ({ status: "fulfilled" as const, value }), error => ({ status: "rejected" as const, error }));
    await vi.waitFor(() => expect(newer).toBeDefined());
    expect(await newer!).toBeNull();
    expect((await olderOutcome).status).toBe("rejected");
    expect(await getBaseUrl()).toBe("http://localhost:8000/new");
  } finally { stop(); runTestControl(setSecureStoreBackend, null); }
});

it("a reentrant clear during real session adoption retires the older adoption", async () => {
  const { api, setBaseUrl } = await import("../src/api/client");
  const storage = (await import("./helpers/storageMock")).default;
  const keychain = await import("./helpers/keychainMock");
  const { setSecureStoreBackend } = await import("../src/secureStore");
  const { runTestControl } = await import("./helpers/testControl");
  storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  expect(await setBaseUrl("http://localhost:8000")).toBeNull();
  let newer: Promise<void> | undefined;
  const stop = subscribeLocalWriteScope(() => { if (!newer) newer = api.clearSession(); });
  try {
    const older = api.setSession("old-token", "a".repeat(32), "alice");
    const oldResult = older.then(() => "fulfilled", () => "rejected");
    await vi.waitFor(() => expect(newer).toBeDefined()); await newer!;
    expect(await oldResult).toBe("rejected"); expect(await api.getUserId()).toBeNull(); expect(await api.isLoggedIn()).toBe(false);
  } finally { stop(); runTestControl(setSecureStoreBackend, null); }
});

it("a newer server transition started after origin retirement wins", async () => {
  const { setBaseUrl, getBaseUrl } = await import("../src/api/client");
  const { localWriteOriginEpoch } = await import("../src/localWriteGuard");
  const storage = (await import("./helpers/storageMock")).default;
  const keychain = await import("./helpers/keychainMock");
  const { setSecureStoreBackend } = await import("../src/secureStore");
  const { runTestControl } = await import("./helpers/testControl");
  storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  expect(await setBaseUrl("http://localhost:8000")).toBeNull();
  const origin = localWriteOriginEpoch(); let newer: Promise<string | null> | undefined;
  const stop = subscribeLocalWriteScope(() => { if (!newer && localWriteOriginEpoch() !== origin) newer = setBaseUrl("http://localhost:9100"); });
  try {
    const older = setBaseUrl("http://localhost:9000"); const oldResult = older.then(() => "fulfilled", () => "rejected");
    await vi.waitFor(() => expect(newer).toBeDefined()); expect(await newer!).toBeNull();
    expect(await oldResult).toBe("rejected"); expect(await getBaseUrl()).toBe("http://localhost:9100");
  } finally { stop(); runTestControl(setSecureStoreBackend, null); }
});

it("a session started by a cleanup notification is not erased by older cleanup", async () => {
  const { api, setBaseUrl } = await import("../src/api/client");
  const storage = (await import("./helpers/storageMock")).default;
  const keychain = await import("./helpers/keychainMock");
  const { setSecureStoreBackend } = await import("../src/secureStore");
  const { runTestControl } = await import("./helpers/testControl");
  storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  expect(await setBaseUrl("http://localhost:8000")).toBeNull();
  const originalWrite = storage.setItem.bind(storage); let failed = false, newer: Promise<void> | undefined;
  const write = vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === "@mindpattern/username" && !failed) { failed = true; throw new Error("injected old username write failure"); }
    await originalWrite(key, value);
  });
  const stop = subscribeLocalWriteScope(() => { if (failed && !newer) newer = api.setSession("new-token", "b".repeat(32), "bob"); });
  try {
    const older = api.setSession("old-token", "a".repeat(32), "alice"); const oldResult = older.then(() => "fulfilled", () => "rejected");
    await vi.waitFor(() => expect(newer).toBeDefined()); await newer!;
    expect(await oldResult).toBe("rejected"); expect(await api.getUserId()).toBe("b".repeat(32)); expect(await api.isLoggedIn()).toBe(true);
  } finally { stop(); write.mockRestore(); runTestControl(setSecureStoreBackend, null); }
});

it("coalesces consecutive synchronous scope retirements into one deferred notice", async () => {
  await Promise.resolve();
  const observer = vi.fn();
  const stop = subscribeLocalWriteScope(observer);
  try {
    advanceLocalWriteScope();
    advanceLocalWriteScope();
    expect(observer).not.toHaveBeenCalled();
    await Promise.resolve();
    expect(observer).toHaveBeenCalledTimes(1);
  } finally { stop(); }
});

it("does not notify an unsubscribed listener after the notice is delivered", async () => {
  await Promise.resolve();
  const observer = vi.fn();
  const stop = subscribeLocalWriteScope(observer);
  stop();
  advanceLocalWriteScope();
  await Promise.resolve();
  expect(observer).not.toHaveBeenCalled();
});
