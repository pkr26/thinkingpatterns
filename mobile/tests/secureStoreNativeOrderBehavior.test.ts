import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv } from "node:crypto";
import * as Keychain from "react-native-keychain";
import * as native from "./helpers/keychainMock";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { engine } from "./helpers/nodeEngine";

const SLOT = "@mindpattern/user_id", OTHER = "@mindpattern/username";
const key = Buffer.alloc(32, 21);
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
function gate() { let opened = false, resolve!: () => void; const pending = new Promise<void>(done => { resolve = done; }); return { pending, release: () => { opened = true; resolve(); }, get opened() { return opened; } }; }
const arrived = async (event: ReturnType<typeof gate>) => { await vi.waitFor(() => expect(event.opened).toBe(true), { timeout: 400, interval: 5 }); };
function nativeDelivery(turns: number, callback: () => void): void { if (turns === 0) callback(); else queueMicrotask(() => nativeDelivery(turns - 1, callback)); }
async function installedLegacy(value: string) {
  const nonce = Buffer.alloc(12, 4), cipher = createCipheriv("aes-256-gcm", key, nonce);
  const blob = Buffer.concat([nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]).toString("base64");
  await Keychain.setGenericPassword("mindpattern-device-key", key.toString("base64"), { service: "com.mindpattern.session-device-key.v1" });
  await storage.setItem(SLOT, blob);
}
beforeEach(() => { vi.restoreAllMocks(); native.__reset(); storage.__reset(); runTestControl(setSecureStoreBackend, null); });
afterEach(async () => { await turn(); vi.restoreAllMocks(); });

it.each(["replace", "remove"])("a held legacy native read cannot rewrite a credential after a public %s", async mode => {
  await installedLegacy("retired-account");
  const held = gate(), entered = gate(), get = storage.getItem; let captured = false;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await get(slot);
    if (slot === SLOT && !captured) { captured = true; entered.release(); await held.pending; }
    return value;
  });
  const reading = secureStore.getItem(SLOT);
  await arrived(entered);
  try {
    if (mode === "replace") await secureStore.setItem(SLOT, "replacement-account");
    else await secureStore.removeItem(SLOT);
  } finally { held.release(); }
  expect(await reading).toBe("retired-account");
  runTestControl(setSecureStoreBackend, null);
  expect(await secureStore.getItem(SLOT)).toBe(mode === "replace" ? "replacement-account" : null);
});

it.each(["replace", "remove"])("an admitted legacy native rewrite drains before a later public %s", async mode => {
  await installedLegacy("retired-account");
  const held = gate(), entered = gate(), set = storage.setItem; let admitted = false;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    if (slot === SLOT && !admitted) { admitted = true; entered.release(); await held.pending; }
    return set(slot, value);
  });
  const reading = secureStore.getItem(SLOT); await arrived(entered);
  const replacement = mode === "replace" ? secureStore.setItem(SLOT, "replacement-account") : secureStore.removeItem(SLOT);
  // Native completion is independent of whether the later operation is queued.
  setTimeout(held.release, 25);
  await Promise.all([reading, replacement]);
  runTestControl(setSecureStoreBackend, null);
  expect(await secureStore.getItem(SLOT)).toBe(mode === "replace" ? "replacement-account" : null);
});

it("a completed earlier write cannot release a slot that still has another native write pending", async () => {
  await installedLegacy("initial-account");
  const first = gate(), second = gate(), firstEntered = gate(), secondEntered = gate(), set = storage.setItem; let phase = 0;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    if (slot === SLOT) {
      const step = phase++;
      if (step === 0) { firstEntered.release(); await first.pending; }
      if (step === 1) { secondEntered.release(); await second.pending; }
    }
    return set(slot, value);
  });
  const writingFirst = secureStore.setItem(SLOT, "first-account"); await arrived(firstEntered);
  const writingSecond = secureStore.setItem(SLOT, "second-account"); first.release(); await arrived(secondEntered);
  const writingLast = secureStore.setItem(SLOT, "last-account");
  setTimeout(second.release, 25);
  await Promise.all([writingFirst, writingSecond, writingLast]);
  runTestControl(setSecureStoreBackend, null);
  expect(await secureStore.getItem(SLOT)).toBe("last-account");
});

it("a failed native write refuses its caller without poisoning the queued replacement credential", async () => {
  await installedLegacy("initial-account");
  const held = gate(), entered = gate(), set = storage.setItem; let refused = false;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    if (slot === SLOT && !refused) { refused = true; entered.release(); await held.pending; throw new Error("Native slot write refused"); }
    return set(slot, value);
  });
  const writing = secureStore.setItem(SLOT, "refused-account"); const rejection = expect(writing).rejects.toThrow("Native slot write refused");
  await arrived(entered); const replacement = secureStore.setItem(SLOT, "replacement-account"); held.release();
  await rejection; await replacement; runTestControl(setSecureStoreBackend, null);
  expect(await secureStore.getItem(SLOT)).toBe("replacement-account");
});

it("a held credential write does not block another encrypted native slot", async () => {
  await installedLegacy("initial-account");
  const held = gate(), entered = gate(), set = storage.setItem;
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => { if (slot === SLOT) { entered.release(); await held.pending; } return set(slot, value); });
  const writing = secureStore.setItem(SLOT, "replacement-account"); await arrived(entered);
  try {
    const other = secureStore.setItem(OTHER, "replacement-name");
    expect(await Promise.race([other.then(() => "stored"), new Promise<string>(resolve => setTimeout(() => resolve("blocked"), 100))])).toBe("stored");
    expect(await secureStore.getItem(OTHER)).toBe("replacement-name");
  } finally { held.release(); await writing; }
});

it("the public removal promise completes only after native ciphertext custody is gone", async () => {
  await installedLegacy("initial-account");
  const held = gate(), entered = gate(), remove = storage.removeItem;
  vi.spyOn(storage, "removeItem").mockImplementation(async slot => { if (slot === SLOT) { entered.release(); await held.pending; } return remove(slot); });
  let settled = false; const removing = secureStore.removeItem(SLOT).then(() => { settled = true; }); await arrived(entered); await turn();
  try { expect(settled).toBe(false); expect(await storage.getItem(SLOT)).not.toBeNull(); }
  finally { held.release(); await removing; }
  expect(await storage.getItem(SLOT)).toBeNull();
});

it.each([false, true])("the native encryption input is erased after slot write refusal=%s", async refused => {
  await installedLegacy("initial-account");
  const secret = "fresh private Native bearer UTF8 é", held: Buffer[] = [], create = engine.createCipheriv;
  vi.spyOn(engine, "createCipheriv").mockImplementation((...args) => {
    const cipher = create(...args), update = cipher.update.bind(cipher);
    cipher.update = ((input: Buffer) => { if (Buffer.isBuffer(input) && input.toString("utf8") === secret) held.push(input); return update(input); }) as typeof cipher.update;
    return cipher;
  });
  if (refused) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native credential write refused"));
  if (refused) await expect(secureStore.setItem(SLOT, secret)).rejects.toThrow("Native credential write refused");
  else await secureStore.setItem(SLOT, secret);
  expect(held.length).toBeGreaterThan(0); expect(held.every(buffer => buffer.every(byte => byte === 0))).toBe(true);
});

it.each(["versioned", "legacy"])("the returned %s Native credential leaves no retained decrypted conversion bytes", async format => {
  const secret = "retained Native plaintext conversion é";
  await installedLegacy(secret);
  if (format === "versioned") await secureStore.getItem(SLOT);
  const held: Buffer[] = [], convert = Buffer.prototype.toString;
  vi.spyOn(Buffer.prototype, "toString").mockImplementation(function(this: Buffer, ...args) {
    const value = convert.apply(this, args); if (value === secret) held.push(this); return value;
  });
  expect(await secureStore.getItem(SLOT)).toBe(secret);
  expect(held.length).toBeGreaterThan(0); expect(held.every(buffer => buffer.every(byte => byte === 0))).toBe(true);
});

it.each(Array.from({ length: 9 }, (_, phase) => phase))("a native key receipt delivery phase %s preserves physical slot custody through the next write outage", async phase => {
  const writeKey = Keychain.setGenericPassword, set = storage.setItem, entered = gate();
  let secondary: Promise<PromiseSettledResult<void>> | undefined, durableValue: string | undefined;
  vi.spyOn(Keychain, "setGenericPassword").mockImplementation(async (...args) => {
    const answer = await writeKey(...args);
    return new Promise(resolve => { setImmediate(() => { resolve(answer); nativeDelivery(phase, () => {
      secondary = secureStore.setItem(OTHER, "secondary private slot").then(() => ({ status: "fulfilled", value: undefined }), reason => ({ status: "rejected", reason })); entered.release();
    }); }); });
  });
  vi.spyOn(storage, "setItem").mockImplementation(async (slot, value) => {
    if (durableValue !== undefined) throw new Error("Native slot service unavailable after its durable receipt");
    durableValue = slot; return set(slot, value);
  });
  const primary = secureStore.setItem(SLOT, "primary private slot").then(() => ({ status: "fulfilled", value: undefined }), reason => ({ status: "rejected", reason }));
  await arrived(entered); const outcomes = await Promise.all([primary, secondary!]);
  // Phase 2 delivers the second caller after the durable key publication
  // and before the first caller's shared initialization promise resumes.
  // Its actual native write succeeds before the finite provider outage.
  expect(outcomes.map(result => result.status)).toEqual(phase === 2 ? ["rejected", "fulfilled"] : ["fulfilled", "rejected"]);
  runTestControl(setSecureStoreBackend, null);
  expect(await secureStore.getItem(SLOT)).toBe(phase === 2 ? null : "primary private slot");
  expect(await secureStore.getItem(OTHER)).toBe(phase === 2 ? "secondary private slot" : null);
});
