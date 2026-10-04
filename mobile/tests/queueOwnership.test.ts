import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import * as fs from "./helpers/expoFsMock";
import { api } from "../src/api/client";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { enqueue, flushQueue, queueLength } from "../src/offlineQueue";
import { enqueueAudio, flushAudioQueue, audioQueueCount } from "../src/audioQueue";
import { encryptAudio } from "../src/crypto/MindPatternCrypto";
import { buildAad, encrypt } from "../src/crypto/envelope";
const USER = "11111111111111111111111111111111", OTHER = "22222222222222222222222222222222", KEY = Buffer.alloc(32, 5);
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); fs.__resetFiles(); __resetLocalKeyLifecycleForTests(); setSecureStoreBackend(null);
  await api.setSession("old-account-token", USER, "alice");
  vi.stubGlobal("fetch", vi.fn(async () => new Response("{}", { status: 201, headers: { "Content-Type": "application/json" } })));
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("an explicit old-account text flush never uploads its ciphertext with a replacement account's bearer", async () => {
  const blobB64 = encrypt(KEY, Buffer.from(JSON.stringify({ text: "old-account private writing" })), buildAad("entry", USER, "saved", "1")).toString("base64");
  await enqueue({ userId: USER, clientEntryId: "saved", blobB64, entryDate: "2026-10-03" });
  await api.setSession("replacement-account-token", OTHER, "bob");
  await flushQueue(USER).catch(() => {});
  expect(fetch).not.toHaveBeenCalled(); expect(await queueLength(USER)).toBe(1);
});

it("an interrupted replacement login cannot leave an old owner paired with the replacement bearer after restart", async () => {
  await enqueue({ userId: USER, clientEntryId: "saved", blobB64: "old-account retained ciphertext", entryDate: "2026-10-03" });
  const original = secureStore.setItem.bind(secureStore);
  const failing = vi.spyOn(secureStore, "setItem").mockImplementation((slot, value) => slot === "@mindpattern/user_id"
    ? Promise.reject(new Error("simulated durable credential interruption")) : original(slot, value));
  await expect(api.setSession("replacement-account-token", OTHER, "bob")).rejects.toThrow("credential interruption");
  failing.mockRestore(); __resetLocalKeyLifecycleForTests();
  await flushQueue(USER).catch(() => {});
  expect(fetch).not.toHaveBeenCalled(); expect(await queueLength(USER)).toBe(1);
  expect(await api.isLoggedIn()).toBe(false);
});

it.each(["@mindpattern/user_id", "@mindpattern/username", "@mindpattern/token"])("a cold restart during native publication of %s cannot pair an old outbox with a replacement bearer", async (boundary) => {
  await enqueue({ userId: USER, clientEntryId: "saved", blobB64: "old-account retained ciphertext", entryDate: "2026-10-03" });
  const original = secureStore.setItem.bind(secureStore), started = deferred(), release = deferred();
  vi.spyOn(secureStore, "setItem").mockImplementation(async (slot, value) => {
    if (slot === boundary) { started.resolve(); await release.promise; }
    return original(slot, value);
  });
  const replacement = api.setSession("replacement-account-token", OTHER, "bob").catch(e => e);
  await started.promise;
  // Observe the durable state before any catch/rollback can run. Clearing
  // process-local epochs models a newly started client reading those bytes.
  expect(await secureStore.getItem("@mindpattern/token")).toBeNull();
  __resetLocalKeyLifecycleForTests(); await flushQueue(USER).catch(() => {});
  expect(fetch).not.toHaveBeenCalled(); expect(await queueLength(USER)).toBe(1);
  release.resolve(); expect(await replacement).toMatchObject({ code: "stale_operation" });
});

it("a cold restart after the final native token write sees a complete replacement identity", async () => {
  await enqueue({ userId: USER, clientEntryId: "saved", blobB64: "old-account retained ciphertext", entryDate: "2026-10-03" });
  const original = secureStore.setItem.bind(secureStore), started = deferred(), release = deferred();
  vi.spyOn(secureStore, "setItem").mockImplementation(async (slot, value) => {
    await original(slot, value);
    if (slot === "@mindpattern/token") { started.resolve(); await release.promise; }
  });
  const replacement = api.setSession("replacement-account-token", OTHER, "bob").catch(e => e); await started.promise;
  __resetLocalKeyLifecycleForTests();
  expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBe("bob"); expect(await api.isLoggedIn()).toBe(true);
  await flushQueue(USER).catch(() => {}); expect(fetch).not.toHaveBeenCalled();
  await enqueue({ userId: OTHER, clientEntryId: "new-saved", blobB64: "replacement-account ciphertext", entryDate: "2026-10-03" });
  expect(await flushQueue(OTHER)).toBe(1);
  expect(fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer replacement-account-token" }) }));
  release.resolve(); expect(await replacement).toMatchObject({ code: "stale_operation" });
});

it("an owner-changing token refresh with no username clears the previous account's username", async () => {
  await api.setSession("replacement-account-token", OTHER);
  expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBeNull();
  expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement-account-token");
});

it("a same-owner token refresh with no username retains that owner's username", async () => {
  await api.setSession("refreshed-account-token", USER);
  expect(await api.getUsername()).toBe("alice"); expect(await api.isLoggedIn()).toBe(true);
});

it("same-account re-login retires a text flush suspended in its durable queue read", async () => {
  await enqueue({ userId: USER, clientEntryId: "saved", blobB64: "retained ciphertext", entryDate: "2026-10-03" });
  const original = storage.getItem, started = deferred(), release = deferred(); let once = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await original(slot);
    if (slot.startsWith("@mindpattern/queue.v2.items.") && once) { once = false; started.resolve(); await release.promise; }
    return value;
  });
  const flushing = flushQueue(USER).catch(e => e); await started.promise;
  await api.setSession("replacement-token-for-same-account", USER, "alice"); release.resolve(); await flushing;
  expect(fetch).not.toHaveBeenCalled(); expect(await queueLength(USER)).toBe(1);
});

it("a captured owner permits a legitimate cold-start locked-vault outbox upload", async () => {
  await enqueue({ userId: USER, clientEntryId: "saved", blobB64: "retained ciphertext", entryDate: "2026-10-03" });
  expect(await flushQueue(USER)).toBe(1);
  expect(fetch).toHaveBeenCalledWith(expect.any(String), expect.objectContaining({ headers: expect.objectContaining({ Authorization: "Bearer old-account-token" }) }));
  expect(await queueLength(USER)).toBe(0);
});

it("a last audio origin await cannot let old-account ciphertext adopt the replacement bearer", async () => {
  await enqueueAudio({ userId: USER, clientEntryId: "saved", ...encryptAudio({ dataKey: KEY }, USER, "saved", Buffer.from("old-account private voice")), mime: "audio/m4a", durationSeconds: 4 });
  const read = fs.readAsStringAsync.getMockImplementation()!, original = storage.getItem, started = deferred(), release = deferred();
  let arm = false, once = true;
  fs.readAsStringAsync.mockImplementationOnce(async (...args) => { const value = await read(...args); arm = true; return value; });
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await original(slot);
    if (slot === "@mindpattern/base_url" && arm && once) { once = false; started.resolve(); await release.promise; }
    return value;
  });
  const flushing = flushAudioQueue(); await started.promise;
  await api.setSession("replacement-account-token", OTHER, "bob"); release.resolve(); await flushing;
  expect(fetch).not.toHaveBeenCalled(); expect(await audioQueueCount(USER)).toBe(1);
});
