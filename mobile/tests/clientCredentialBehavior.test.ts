import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, ApiError, DEFAULT_BASE_URL, setBaseUrl } from "../src/api/client";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { captureLocalWritePermit, changeLocalSessionOwner } from "../src/localWriteGuard";

const USER = "dddddddddddddddddddddddddddddddd", OTHER = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 };
const ENVELOPE = { scheme: "v2" as const, saltB64: "cached-salt", wrappedB64: "wrapped-key", kdfParams: PARAMS };
// Historical installed-client cache records are inputs to the public reader.
// Expectations below observe cache behavior, rather than private encoding.
const SALT_SLOT = "@mindpattern/salt_YWxpY2U", ENVELOPE_SLOT = "@mindpattern/keyenvelope_YWxpY2U";
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); runTestControl(setSecureStoreBackend, null); });
afterEach(() => vi.restoreAllMocks());

it.each([1, 2, 4])("never publishes usable credentials after native adoption write %s fails", async failure => {
  const original = secureStore.setItem; let count = 0;
  vi.spyOn(secureStore, "setItem").mockImplementation(async (key, value) => {
    if (++count === failure) throw new Error("native credential storage failed");
    return original(key, value);
  });
  await expect(api.setSession("new-token", USER, "alice")).rejects.toThrow("native credential storage failed");
  expect(await api.isLoggedIn()).toBe(false); expect(await api.getUserId()).toBeNull(); expect(await api.getUsername()).toBeNull();
});

it("adopts usable credentials when only the optional first-origin pin cannot be stored", async () => {
  const original = secureStore.setItem; let count = 0;
  vi.spyOn(secureStore, "setItem").mockImplementation(async (key, value) => {
    if (++count === 3) throw new Error("native origin pin unavailable");
    return original(key, value);
  });
  await api.setSession("new-token", USER, "alice");
  expect(await api.isLoggedIn()).toBe(true); expect(await api.getUserId()).toBe(USER); expect(await api.getUsername()).toBe("alice");
  expect(await api.pinnedOrigin()).toBeNull(); expect(await api.originPinChanged()).toBe(false);
});

it.each([1, 2, 3, 4])("retires a cancelled authentication continuation after native adoption write %s", async boundary => {
  const original = secureStore.setItem; let count = 0, current = true;
  vi.spyOn(secureStore, "setItem").mockImplementation(async (key, value) => {
    await original(key, value); if (++count === boundary) current = false;
  });
  const failure = await api.setSession("retired-token", USER, "alice", { stillCurrent: () => current }).catch((error: unknown) => error);
  expect(failure).toBeInstanceOf(ApiError); expect(failure).toMatchObject({ code: "stale_operation", message: "This authentication attempt was retired" });
  expect(await api.isLoggedIn()).toBe(false); expect(await api.getUserId()).toBeNull(); expect(await api.getUsername()).toBeNull();
});

it("preserves username only when adopting the same owner and clears it for a replacement owner", async () => {
  await api.setSession("first", USER, "alice"); await api.setSession("refresh", USER);
  expect(await api.getUsername()).toBe("alice"); expect(await api.getUserId()).toBe(USER);
  await api.setSession("replacement", OTHER);
  expect(await api.getUsername()).toBeNull(); expect(await api.getUserId()).toBe(OTHER); expect(await api.isLoggedIn()).toBe(true);
});

it("refuses a retired attempt before publishing any identity and keeps another active tuple", async () => {
  await api.setSession("existing", OTHER, "bob");
  await expect(api.setSession("retired", USER, "alice", { stillCurrent: () => false })).rejects.toMatchObject({ code: "stale_operation", message: "This authentication attempt was retired" });
  expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBe("bob"); expect(await api.isLoggedIn()).toBe(true);
});

it("retains the first installed-client origin pin after authenticating at a replacement origin", async () => {
  await secureStore.setItem("@mindpattern/pinned_origin", "https://first-trusted.example");
  await api.setSession("first-token", USER, "alice");
  expect(await api.pinnedOrigin()).toBe("https://first-trusted.example");
  await setBaseUrl("https://replacement.example"); await api.setSession("replacement-token", USER, "alice");
  expect(await api.pinnedOrigin()).toBe("https://first-trusted.example"); expect(await api.originPinChanged()).toBe(true);
});

it.each([
  [null, USER], ["token", null], [null, null], ["token", `x${USER}`], ["token", `${USER}x`], ["token", USER.toUpperCase()], ["token", "wrong-owner"],
] as Array<[string | null, string | null]>)("refuses an unusable installed credential tuple (%s, %s)", async (token, owner) => {
  if (token !== null) await secureStore.setItem("@mindpattern/token", token);
  if (owner !== null) await secureStore.setItem("@mindpattern/user_id", owner);
  expect(await api.isLoggedIn()).toBe(false);
});

it("native session clearing immediately fences old account producers", async () => {
  await api.setSession("old-token", USER, "alice"); expect(() => captureLocalWritePermit(USER, Buffer.alloc(32, 7))).not.toThrow();
  await api.clearSession();
  expect(() => captureLocalWritePermit(USER, Buffer.alloc(32, 7))).toThrow();
  expect(await api.isLoggedIn()).toBe(false); expect(await api.getUserId()).toBeNull(); expect(await api.getUsername()).toBeNull();
});
it.each(["sign-out", "replacement login"])("does not hydrate a retired native credential tuple after %s", async transition => {
  await api.setSession("old-token", USER, "alice");
  const read=secureStore.getItem;let release:()=>void=()=>{},ready!:()=>void,held=false;const entered=new Promise<void>(resolve=>{ready=resolve;});
  vi.spyOn(secureStore,"getItem").mockImplementation(async key=>{const value=await read(key);if(key==="@mindpattern/token"&&!held){held=true;ready();await new Promise<void>(resolve=>{release=resolve;});}return value;});
  const hydration=api.isLoggedIn();await entered;
  if(transition==="sign-out")await api.clearSession();else await api.setSession("new-token",OTHER,"bob");
  release();expect(await hydration).toBe(false);
  if(transition==="sign-out")expect(()=>captureLocalWritePermit(USER,Buffer.alloc(32,7))).toThrow();
  else{expect(await api.getUserId()).toBe(OTHER);expect(()=>captureLocalWritePermit(OTHER,Buffer.alloc(32,7))).not.toThrow();}
});

it("a failed adoption fences producers before the caller checks stored login state", async () => {
  vi.spyOn(secureStore, "setItem").mockRejectedValueOnce(new Error("native write refused"));
  await expect(api.setSession("failed-token", USER, "alice")).rejects.toThrow("native write refused");
  expect(() => captureLocalWritePermit(USER, Buffer.alloc(32, 7))).toThrow();
});

it("retires a deleted owner's complete native tuple and fences its producers", async () => {
  await api.setSession("deleted-token", USER, "alice"); await api.retireDeletedSession(USER);
  expect(() => captureLocalWritePermit(USER, Buffer.alloc(32, 7))).toThrow();
  expect(await api.isLoggedIn()).toBe(false); expect(await api.getUserId()).toBeNull(); expect(await api.getUsername()).toBeNull();
});

it("refuses a deletion continuation for a replacement owner and preserves that owner's tuple", async () => {
  await api.setSession("replacement-token", OTHER, "bob");
  await expect(api.retireDeletedSession(USER)).rejects.toMatchObject({ code: "stale_operation", message: "A replacement account owns this session" });
  expect(await api.isLoggedIn()).toBe(true); expect(await api.getUserId()).toBe(OTHER); expect(await api.getUsername()).toBe("bob");
});

it("retires a partial deleted session when its native owner slot is already missing", async () => {
  await secureStore.setItem("@mindpattern/token", "orphaned-token"); await secureStore.setItem("@mindpattern/username", "alice");
  await api.retireDeletedSession(USER);
  expect(await api.isLoggedIn()).toBe(false); expect(await api.getUsername()).toBeNull();
});

it.each([1, 2, 3])("attempts every native tuple delete when retirement removal %s rejects", async failure => {
  await api.setSession("deleted-token", USER, "alice"); const original = secureStore.removeItem;
  const refused = new Error(`native deletion ${failure} refused`); let count = 0;
  vi.spyOn(secureStore, "removeItem").mockImplementation(async slot => { if (++count === failure) throw refused; return original(slot); });
  await expect(api.retireDeletedSession(USER)).rejects.toBe(refused);
  expect(await api.isLoggedIn()).toBe(false);
  expect(await api.getUserId()).toBe(failure === 2 ? USER : null);
  expect(await api.getUsername()).toBe(failure === 3 ? "alice" : null);
});

it("reports the first native tuple removal failure after attempting the other slots", async () => {
  await api.setSession("deleted-token", USER, "alice");
  const first = new Error("first native deletion refused"), second = new Error("later native deletion refused");
  vi.spyOn(secureStore, "removeItem").mockRejectedValueOnce(first).mockRejectedValueOnce(second);
  await expect(api.retireDeletedSession(USER)).rejects.toBe(first);
  expect(await api.getUsername()).toBeNull();
});

it.each(["salt", "envelope"])("never publishes a retired %s cache after a held origin lookup", async kind => {
  const original = storage.getItem; let release: (() => void) | undefined;
  const entered = new Promise<void>(resolve => {
    vi.spyOn(storage, "getItem").mockImplementationOnce(async key => { resolve(); await new Promise<void>(done => { release = done; }); return original(key); });
  });
  const operation = kind === "salt" ? api.cacheSalt("alice", "retired-salt") : api.cacheKeyEnvelope("alice", ENVELOPE);
  const completion = operation.then(() => ({ accepted: true }), (error: unknown) => ({ error }));
  await Promise.race([entered, completion.then(() => { throw new Error("Cache publication skipped its origin lookup"); })]);
  try { changeLocalSessionOwner(OTHER); } finally { release?.(); }
  expect(await completion).toMatchObject({ error: { code: "stale_operation", message: "A newer account/server transition superseded this operation" } });
  expect(kind === "salt" ? await api.getCachedSalt("alice") : await api.getCachedKeyEnvelope("alice")).toBeNull();
});

it.each(["salt", "envelope"])("retains a historical %s twin when native clearing spans a retired scope", async kind => {
  if (kind === "salt") await api.cacheSalt("alice", "newer-salt"); else await api.cacheKeyEnvelope("alice", ENVELOPE);
  await storage.setItem(kind === "salt" ? "@mindpattern/salt_alice" : "@mindpattern/keyenvelope_alice", JSON.stringify(kind === "salt" ? { v: 1, o: DEFAULT_BASE_URL, s: "historical-salt" } : { v: 1, o: DEFAULT_BASE_URL, ...ENVELOPE }));
  const original = storage.removeItem; let release: (() => void) | undefined;
  const entered = new Promise<void>(resolve => {
    vi.spyOn(storage, "removeItem").mockImplementationOnce(async key => { await original(key); resolve(); await new Promise<void>(done => { release = done; }); });
  });
  const operation = kind === "salt" ? api.clearCachedSalt("alice") : api.clearCachedKeyEnvelope("alice");
  const completion = operation.then(() => ({ accepted: true }), (error: unknown) => ({ error }));
  await Promise.race([entered, completion.then(() => { throw new Error("Cache clearing skipped its native removal"); })]);
  try { changeLocalSessionOwner(OTHER); } finally { release?.(); }
  expect(await completion).toMatchObject({ error: { code: "stale_operation" } });
  expect(kind === "salt" ? await api.getCachedSalt("alice") : await api.getCachedKeyEnvelope("alice")).toEqual(kind === "salt" ? "historical-salt" : ENVELOPE);
});

it("keeps origin trust if persistence is readable and degrades visibly when its read fails", async () => {
  expect(await api.pinnedOrigin()).toBeNull(); expect(await api.originPinChanged()).toBe(false);
  await api.confirmCurrentOrigin(); expect(await api.pinnedOrigin()).toBe("http://127.0.0.1:8000");
  await setBaseUrl("https://new-server.example"); expect(await api.originPinChanged()).toBe(true);
  await api.confirmCurrentOrigin(); expect(await api.pinnedOrigin()).toBe("https://new-server.example"); expect(await api.originPinChanged()).toBe(false);
  vi.spyOn(secureStore, "getItem").mockRejectedValue(new Error("native secure storage unavailable"));
  expect(await api.pinnedOrigin()).toBeNull(); expect(await api.originPinChanged()).toBe(false);
});

it("keeps independent cached material for Unicode usernames and clears each namespace through its public API", async () => {
  for (const name of ["alice", "alice/记录", "alice:separate", "ålice"]) {
    await api.cacheSalt(name, `salt:${name}`); await api.cacheKeyEnvelope(name, { ...ENVELOPE, saltB64: `envelope:${name}` });
  }
  for (const name of ["alice", "alice/记录", "alice:separate", "ålice"]) {
    expect(await api.getCachedSalt(name)).toBe(`salt:${name}`); expect(await api.getCachedKeyEnvelope(name)).toEqual({ ...ENVELOPE, saltB64: `envelope:${name}` });
    await api.clearCachedSalt(name); await api.clearCachedKeyEnvelope(name);
    expect(await api.getCachedSalt(name)).toBeNull(); expect(await api.getCachedKeyEnvelope(name)).toBeNull();
  }
});

const malformedSalt: unknown[] = [null, false, [], "record", {}, { v: 2, o: DEFAULT_BASE_URL, s: "salt" }, { v: 1, o: null, s: "salt" }, { v: 1, o: DEFAULT_BASE_URL, s: null }, { v: 1, o: "https://other.example", s: "salt" }];
it.each(malformedSalt.map((record, i) => [i, record] as const))("refuses malformed historical salt cache %s", async (_i, record) => {
  await storage.setItem(SALT_SLOT, JSON.stringify(record)); expect(await api.getCachedSalt("alice")).toBeNull();
});

const envelope = { v: 1, o: DEFAULT_BASE_URL, ...ENVELOPE };
const malformedEnvelope: unknown[] = [null, false, [], "record", {}, { ...envelope, v: 2 }, { ...envelope, o: null }, { ...envelope, o: "https://other.example" }, { ...envelope, scheme: "v3" }, { ...envelope, scheme: null }, { ...envelope, saltB64: null }, { ...envelope, wrappedB64: null }, { ...envelope, wrappedB64: 42 }, { ...envelope, kdfParams: undefined }];
it.each(malformedEnvelope.map((record, i) => [i, record] as const))("refuses malformed historical envelope cache %s", async (_i, record) => {
  await storage.setItem(ENVELOPE_SLOT, JSON.stringify(record)); expect(await api.getCachedKeyEnvelope("alice")).toBeNull();
});

it("uses a newer cache over a legacy twin and preserves a usable legacy cache when migration writes fail", async () => {
  await storage.setItem("@mindpattern/salt_alice", JSON.stringify({ o: DEFAULT_BASE_URL, s: "legacy-salt" }));
  await api.cacheSalt("alice", "newer-salt"); expect(await api.getCachedSalt("alice")).toBe("newer-salt");
  await api.clearCachedSalt("alice"); expect(await api.getCachedSalt("alice")).toBeNull();
  await storage.setItem("@mindpattern/salt_alice", JSON.stringify({ o: DEFAULT_BASE_URL, s: "retry-salt" }));
  const original = storage.setItem;
  const failure = vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { if (key === SALT_SLOT) throw new Error("disk full"); return original(key, value); });
  expect(await api.getCachedSalt("alice")).toBe("retry-salt"); failure.mockRestore();
  expect(await api.getCachedSalt("alice")).toBe("retry-salt");
  expect(await storage.getItem("@mindpattern/salt_alice")).toBeNull();
});
