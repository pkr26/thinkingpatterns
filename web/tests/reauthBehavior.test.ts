import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, auth, clearSession } from "../src/api/client";
import { freshStepUp, verifyPasswordForVault } from "../src/reauth";
import { derivePatientKeys } from "../src/crypto/keys";
import { vault } from "../src/vault";
import { installSession, resetTestState } from "./helpers/api";

const owner = "reauth-behavior-owner", password = "fresh typed password café", salt = new Uint8Array(16).fill(24);
const expectedMaster = pbkdf2Sync(password, salt, 100_000, 32, "sha256");
const expectedAuth = new Uint8Array(hkdfSync("sha256", expectedMaster, new Uint8Array(32), Buffer.from("mindpattern/auth/v1"), 32));
const baseEnvelope = { key_scheme: "v2" as const, kdf_params: { algorithm: "pbkdf2-sha256" as const, version: 1, iterations: 100_000 }, salt: Buffer.from(salt).toString("base64"), wrapped_data_key: null };
const realTimeout = globalThis.setTimeout;
beforeEach(() => {
  resetTestState(); installSession(owner, "alice"); unlock();
  vi.spyOn(auth, "saltFor").mockResolvedValue({ salt: Buffer.from(salt).toString("base64") });
  vi.spyOn(api, "keyEnvelope").mockResolvedValue(baseEnvelope);
  vi.spyOn(api, "stepUp").mockResolvedValue({ proof: "single-use-proof", action: "account_delete", expires_in: 120 });
});
afterEach(() => { vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks(); vault.lock(); });
function unlock() { vault.unlock({ authKey: expectedAuth.slice(), dataKey: new Uint8Array(32).fill(16) }, owner); }
function heldDerivations() {
  const held: Uint8Array[] = [], realDerive = crypto.subtle.deriveBits.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => { const result = await realDerive(...args); held.push(new Uint8Array(result)); return result; });
  return held;
}
function erased(held: Uint8Array[]) { held.forEach(value => expect(value).toEqual(new Uint8Array(value.length))); }

it("verifies a v2 password against the independent key schedule, sends an action-bound proof request and releases actual derived key buffers", async () => {
  const held = heldDerivations();
  await expect(freshStepUp(password, "account_delete")).resolves.toEqual({ ok: true, proof: "single-use-proof" });
  expect(api.stepUp).toHaveBeenCalledExactlyOnceWith(Buffer.from(expectedAuth).toString("base64"), "account_delete");
  expect(auth.saltFor).toHaveBeenCalledWith("alice"); expect(held).toHaveLength(3); erased(held);
  expect(vault.get().authKey).toEqual(expectedAuth); expect(vault.get().dataKey).toEqual(new Uint8Array(32).fill(16));
});
it.each(["empty password", "locked", "unverified owner", "missing account"])("rejects verification before contacting the server for %s", async condition => {
  if (condition === "locked") vault.lock();
  if (condition === "unverified owner") vault.unlock({ authKey: expectedAuth.slice(), dataKey: new Uint8Array(32) });
  if (condition === "missing account") clearSession();
  const reason = condition === "empty password" ? "wrong-password" : condition === "missing account" ? "no-account" : "locked";
  expect(await verifyPasswordForVault(condition === "empty password" ? "" : password)).toEqual({ ok: false, reason });
  expect(auth.saltFor).not.toHaveBeenCalled(); expect(api.keyEnvelope).not.toHaveBeenCalled(); expect(api.stepUp).not.toHaveBeenCalled();
});
it.each([null, { algorithm: "pbkdf2-sha256", version: 1, iterations: 99_999 }, { algorithm: "unsupported", version: 1, iterations: 100_000 }])("declines missing or invalid v2 KDF parameters without attempting a proof: %j", async params => {
  vi.mocked(api.keyEnvelope).mockResolvedValue({ ...baseEnvelope, kdf_params: params } as Awaited<ReturnType<typeof api.keyEnvelope>>);
  expect(await freshStepUp(password, "account_delete")).toEqual({ ok: false, reason: "offline" }); expect(api.stepUp).not.toHaveBeenCalled();
});
it.each(["offline", "locked", "owner", "owner reusing keys", "account", "auth key", "data key"])("rejects a response from an obsolete verification when %s changes during retrieval", async change => {
  let respond!: (value: { salt: string }) => void;
  vi.mocked(auth.saltFor).mockImplementation(() => new Promise(resolve => { respond = resolve; }));
  const operation = verifyPasswordForVault(password);
  if (change === "offline") vi.mocked(api.keyEnvelope).mockRejectedValue(new Error("offline"));
  if (change === "locked") vault.lock();
  if (change === "owner") vault.unlock({ authKey: expectedAuth.slice(), dataKey: new Uint8Array(32) }, "different owner");
  if (change === "owner reusing keys") vault.unlock(vault.get(), "different owner");
  if (change === "account") installSession(owner, "another account");
  if (change === "auth key" || change === "data key") {
    const original = vault.get();
    vi.spyOn(vault, "get").mockReturnValue({ authKey: change === "auth key" ? original.authKey.slice() : original.authKey, dataKey: change === "data key" ? original.dataKey.slice() : original.dataKey });
  }
  if (change === "offline") { respond({ salt: "not base64" }); await expect(operation).resolves.toEqual({ ok: false, reason: "offline" }); }
  else { respond({ salt: Buffer.from(salt).toString("base64") }); await expect(operation).resolves.toEqual({ ok: false, reason: "locked" }); }
  expect(api.stepUp).not.toHaveBeenCalled();
});
it("rechecks the account and key references after real password derivation, clearing all obsolete outputs", async () => {
  const realDerive = crypto.subtle.deriveBits.bind(crypto.subtle), held: Uint8Array[] = [];
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => {
    const result = await realDerive(...args); held.push(new Uint8Array(result));
    if (held.length === 3) vault.lock(); return result;
  });
  expect(await freshStepUp(password, "account_delete")).toEqual({ ok: false, reason: "locked" });
  expect(api.stepUp).not.toHaveBeenCalled(); expect(held).toHaveLength(3); erased(held);
});
it.each([false, true])("holds a local mismatch for the full anti-guessing delay and rechecks lock state before returning: lock=%s", async lock => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  const held = heldDerivations(); let result: Awaited<ReturnType<typeof verifyPasswordForVault>> | undefined;
  void verifyPasswordForVault("wrong password").then(value => { result = value; });
  for (let n = 0; n < 200 && !vi.getTimerCount() && !result; n++) await new Promise(resolve => realTimeout(resolve, 1));
  await vi.advanceTimersByTimeAsync(499); expect(result).toBeUndefined(); if (lock) vault.lock();
  await vi.advanceTimersByTimeAsync(1); expect(result).toEqual({ ok: false, reason: lock ? "locked" : "wrong-password" });
  expect(api.stepUp).not.toHaveBeenCalled(); erased(held);
});
it("declines an authentication-key length mismatch and a cryptographic failure without requesting a proof", async () => {
  const longerAuth = new Uint8Array(33); longerAuth.set(expectedAuth); vault.unlock({ authKey: longerAuth, dataKey: new Uint8Array(32) }, owner);
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] }); let result: Awaited<ReturnType<typeof verifyPasswordForVault>> | undefined;
  void verifyPasswordForVault(password).then(value => { result = value; });
  for (let n = 0; n < 200 && !vi.getTimerCount() && !result; n++) await new Promise(resolve => realTimeout(resolve, 1));
  await vi.advanceTimersByTimeAsync(500); expect(result).toEqual({ ok: false, reason: "wrong-password" });
  vi.useRealTimers(); vi.spyOn(crypto.subtle, "deriveBits").mockRejectedValue(new Error("hardware unavailable"));
  expect(await verifyPasswordForVault(password)).toEqual({ ok: false, reason: "offline" }); expect(api.stepUp).not.toHaveBeenCalled();
});
it("returns a post-derivation lock immediately without entering the live-password mismatch delay", async () => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  const realDerive = crypto.subtle.deriveBits.bind(crypto.subtle); let count = 0, derived!: () => void;
  const ready = new Promise<void>(resolve => { derived = resolve; });
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => {
    const result = await realDerive(...args); if (++count === 3) { vault.lock(); derived(); } return result;
  });
  let result: Awaited<ReturnType<typeof verifyPasswordForVault>> | undefined;
  const operation = verifyPasswordForVault(password).then(value => { result = value; });
  await ready; await new Promise(resolve => realTimeout(resolve, 10));
  try { expect(result).toEqual({ ok: false, reason: "locked" }); }
  finally { await vi.advanceTimersByTimeAsync(500); await operation; }
  expect(api.stepUp).not.toHaveBeenCalled();
});
it("normalizes cryptographic failure to locked if the requesting vault ends during the failed derivation", async () => {
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async () => { vault.lock(); throw new Error("device crypto failure"); });
  expect(await verifyPasswordForVault(password)).toEqual({ ok: false, reason: "locked" }); expect(api.stepUp).not.toHaveBeenCalled();
});
it.each([1, 2])("erases the actual master and successful sibling subkey when WebCrypto derivation %s fails", async failureAt => {
  const realDerive = crypto.subtle.deriveBits.bind(crypto.subtle), held: Uint8Array[] = [], pending: Promise<unknown>[] = [];
  let hkdfCalls = 0;
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => {
    if ((args[0] as Algorithm).name === "HKDF" && ++hkdfCalls === failureAt) throw new Error("subkey hardware failed");
    const operation = realDerive(...args).then(result => { held.push(new Uint8Array(result)); return result; }); pending.push(operation); return operation;
  });
  expect(await verifyPasswordForVault(password)).toEqual({ ok: false, reason: "offline" }); await Promise.all(pending);
  expect(held).toHaveLength(2); erased(held); expect(api.stepUp).not.toHaveBeenCalled();
});
it.each([1, 2, "both"])("the public key schedule releases transferred master and partial subkeys and preserves the original cryptographic failure: %s", async failureAt => {
  const master = new Uint8Array(expectedMaster), realDerive = crypto.subtle.deriveBits.bind(crypto.subtle), held: Uint8Array[] = [];
  const failure = new Error("key schedule hardware failure");
  let count = 0;
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => {
    count++; if (failureAt === "both" || count === failureAt) throw failure;
    const result = await realDerive(...args); held.push(new Uint8Array(result)); return result;
  });
  await expect(derivePatientKeys(master)).rejects.toBe(failure);
  expect(master).toEqual(new Uint8Array(32)); expect(held).toHaveLength(failureAt === "both" ? 0 : 1); erased(held);
});
it.each([false, true])("reports an unavailable credential service after checking whether the requesting vault was locked: %s", async lock => {
  let reject!: (error: Error) => void; vi.mocked(auth.saltFor).mockImplementation(() => new Promise((_resolve, fail) => { reject = fail; }));
  const operation = verifyPasswordForVault(password); if (lock) vault.lock(); reject(new Error("credential service unavailable"));
  expect(await operation).toEqual({ ok: false, reason: lock ? "locked" : "offline" }); expect(api.stepUp).not.toHaveBeenCalled();
});
it.each(["locked", "replacement keys"])("refuses a proof whose original vault%s changes after actual password verification", async retirement => {
  let reply!: (value: Awaited<ReturnType<typeof api.stepUp>>) => void, started!: () => void; const requested = new Promise<void>(resolve => { started = resolve; });
  vi.mocked(api.stepUp).mockImplementation(() => { started(); return new Promise(resolve => { reply = resolve; }); });
  const operation = freshStepUp(password, "account_delete"); await requested; expect(api.stepUp).toHaveBeenCalledExactlyOnceWith(Buffer.from(expectedAuth).toString("base64"), "account_delete");
  if (retirement === "locked") vault.lock(); else unlock(); reply({ proof: "retired-vault-proof", action: "account_delete", expires_in: 120 }); await expect(operation).resolves.toEqual({ ok: false, reason: "locked" });
});
it.each(["locked", "authentication key", "data key", "owner reusing buffers", "same account new login"])("rejects an actual WebCrypto completion retired in the native verification-to-request promise window: %s", async retirement => {
  const realDerive = crypto.subtle.deriveBits.bind(crypto.subtle), held: Uint8Array[] = []; let count = 0;
  vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(async (...args) => {
    const result = await realDerive(...args); held.push(new Uint8Array(result));
    if (++count === 3) {
      // Native promise reactions leave a real window between the verifier's
      // return and its caller's continuation. Retire the public account/vault
      // there while preserving the real PBKDF2/HKDF execution and output.
      const later = (remaining: number): void => { queueMicrotask(() => {
        if (remaining > 1) { later(remaining - 1); return; }
        const keys = vault.get();
        if (retirement === "locked") vault.lock();
        else if (retirement === "same account new login") installSession(owner, "alice");
        else vault.unlock({ authKey: retirement === "authentication key" ? expectedAuth.slice() : keys.authKey, dataKey: retirement === "data key" ? new Uint8Array(32).fill(16) : keys.dataKey }, retirement === "owner reusing buffers" ? "replacement owner" : owner);
      }); }; later(6);
    }
    return result;
  });
  expect(await freshStepUp(password, "account_delete")).toEqual({ ok: false, reason: "locked" }); expect(api.stepUp).not.toHaveBeenCalled(); expect(held.length).toBeGreaterThan(0); erased(held);
});
