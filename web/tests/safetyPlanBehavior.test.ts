import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { buildAad } from "../src/crypto/aad";
import { decrypt, encrypt, toBase64 } from "../src/crypto/core";
import { kv, setKvBackendForTests, StorageReadError } from "../src/kvstore";
import { clearSafetyPlan, EMPTY_SAFETY_PLAN, loadSafetyPlan, preserveSafetyPlan, registerSafetyPlanSource, rewrapSafetyPlan, saveSafetyPlan, type SafetyPlan } from "../src/safetyPlan";
import { vault } from "../src/vault";
import { observeSecretCopies } from "./helpers/secretCustody";

vi.mock("../src/crypto/core", async original => {
  const actual = await original<typeof import("../src/crypto/core")>();
  return { ...actual, encrypt: vi.fn(actual.encrypt), decrypt: vi.fn(actual.decrypt) };
});
const owner = "plan-behavior-owner", slot = `mindpattern.safetyPlan.${owner}`;
const valid: SafetyPlan = { warningSigns: "My early signs", coping: "Things that help", peoplePlaces: "A calm place", helpers: "Trusted people", professionals: "Professional contacts", saferEnvironment: "Ways to be safer" };
let key: Uint8Array<ArrayBuffer>, records: Map<string, string>;
beforeEach(() => {
  records = new Map(); key = new Uint8Array(32).fill(19);
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); }, keys: async () => [...records.keys()] });
  vault.unlock({ dataKey: key, authKey: new Uint8Array(32).fill(20) }, owner);
  registerSafetyPlanSource(() => null)(); vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
});
afterEach(() => { registerSafetyPlanSource(() => null)(); vault.lock(); setKvBackendForTests(null); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
async function seed(value: unknown) {
  const encrypted = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(value)), buildAad("safety-plan", owner)));
  records.set(slot, encrypted); vi.mocked(encrypt).mockClear(); return encrypted;
}
async function consumerBuffersCleared() {
  for (const [secret, plaintext] of vi.mocked(encrypt).mock.calls) {
    expect(plaintext).toEqual(new Uint8Array(plaintext.length));
    if (secret !== key) expect(secret).toEqual(new Uint8Array(secret.length));
  }
  for (const result of vi.mocked(decrypt).mock.results) {
    const plaintext = await Promise.resolve(result.value).catch(() => null) as Uint8Array | null;
    if (plaintext) expect(plaintext).toEqual(new Uint8Array(plaintext.length));
  }
}

it.each([null, 1, true, "not a plan", [], {}, ...Object.keys(valid).flatMap(field => [
  { ...valid, [field]: undefined }, { ...valid, [field]: null }, { ...valid, [field]: 42 }, { ...valid, [field]: "a".repeat(4001) },
])])("retains authenticated malformed safety-plan writing for recovery without returning invalid editor values: #%#", async value => {
  const original = await seed(value);
  await expect(loadSafetyPlan(key, owner)).rejects.toBeInstanceOf(StorageReadError);
  expect(records.get(slot)).toBe(original); await consumerBuffersCleared();
});
it.each(Object.keys(valid) as (keyof SafetyPlan)[])("retains field %s at the maximum text boundary, ignoring unrelated authenticated metadata", async field => {
  const expected = { ...valid, [field]: "a".repeat(4000) };
  await seed({ ...expected, future: "authenticated extra field" });
  expect(await loadSafetyPlan(key, owner)).toEqual(expected); await consumerBuffersCleared();
});
it("validates all fields before changing durable writing and reports the input limit", async () => {
  await saveSafetyPlan(key, owner, valid); const original = records.get(slot);
  await expect(saveSafetyPlan(key, owner, { ...valid, coping: "a".repeat(4001) })).rejects.toThrow("Each safety-plan field must be text of at most 4000 characters.");
  expect(records.get(slot)).toBe(original); await consumerBuffersCleared();
});
it("clears an intentionally blank or whitespace-only plan and leaves an absent rotation slot absent", async () => {
  await saveSafetyPlan(key, owner, valid); await consumerBuffersCleared();
  await saveSafetyPlan(key, owner, Object.fromEntries(Object.keys(valid).map(field => [field, " \t\n "])) as unknown as SafetyPlan);
  expect(await loadSafetyPlan(key, owner)).toBeNull();
  await rewrapSafetyPlan(key, new Uint8Array(32).fill(22), owner); expect(records.size).toBe(0);
  await clearSafetyPlan(owner); expect(records.size).toBe(0);
});
it.each(Object.keys(valid) as (keyof SafetyPlan)[])("keeps a plan when only %s has writing", async field => {
  const plan = { ...EMPTY_SAFETY_PLAN, [field]: "One remaining written field" };
  await saveSafetyPlan(key, owner, plan); expect(await loadSafetyPlan(key, owner)).toEqual(plan); await consumerBuffersCleared();
});
it("retains an authenticated malformed JSON record and provides a restoration error as the recovery cause", async () => {
  const ciphertext = toBase64(await encrypt(key, new TextEncoder().encode("{"), buildAad("safety-plan", owner)));
  records.set(slot, ciphertext); vi.mocked(encrypt).mockClear();
  try { await loadSafetyPlan(key, owner); throw new Error("expected restoration failure"); }
  catch (error) { expect(error).toBeInstanceOf(StorageReadError); expect((error as StorageReadError).cause).toMatchObject({ message: "Stored safety-plan shape is invalid." }); }
  expect(records.get(slot)).toBe(ciphertext); await consumerBuffersCleared();
});
it("captures the latest live editor and prevents an older unmount from unregistering its replacement", async () => {
  const unmountOld = registerSafetyPlanSource(() => ({ ...valid, coping: "old editor" }));
  let current = "latest editor"; const unmountCurrent = registerSafetyPlanSource(() => ({ ...valid, coping: current }));
  unmountOld(); current = "writing at navigation time"; await preserveSafetyPlan();
  expect((await loadSafetyPlan(key, owner))?.coping).toBe(current); await consumerBuffersCleared();
  unmountCurrent(); current = "retired editor"; await preserveSafetyPlan();
  expect((await loadSafetyPlan(key, owner))?.coping).toBe("writing at navigation time");
});
it("takes custody of a live key synchronously so an immediately following vault lock cannot destroy the parked plan", async () => {
  const recoveryKey = key.slice(); registerSafetyPlanSource(() => valid);
  const parked = preserveSafetyPlan(); vault.lock(); await parked;
  expect(await loadSafetyPlan(recoveryKey, owner)).toEqual(valid); await consumerBuffersCleared();
});
it.each(["no source", "undefined source", "locked", "unverified owner"])("does not replace existing writing without a verified live editor: %s", async condition => {
  await saveSafetyPlan(key, owner, valid); const original = records.get(slot);
  registerSafetyPlanSource(() => condition === "undefined source" ? undefined : null);
  if (condition === "locked") { registerSafetyPlanSource(() => ({ ...valid, coping: "locked writing" })); vault.lock(); }
  if (condition === "unverified owner") { registerSafetyPlanSource(() => ({ ...valid, coping: "unverified writing" })); vault.unlock({ dataKey: key.slice(), authKey: new Uint8Array(32) }); }
  await preserveSafetyPlan(); expect(records.get(slot)).toBe(original);
});
it("propagates explicit save failure, while parking failure settles and retains the previous recoverable record", async () => {
  await saveSafetyPlan(key, owner, valid); const original = records.get(slot);
  vi.spyOn(kv, "setItem").mockRejectedValue(new Error("storage quota"));
  await expect(saveSafetyPlan(key, owner, { ...valid, coping: "new writing" })).rejects.toThrow("storage quota");
  registerSafetyPlanSource(() => ({ ...valid, coping: "new live writing" }));
  await expect(preserveSafetyPlan()).resolves.toBeUndefined(); expect(records.get(slot)).toBe(original); await consumerBuffersCleared();
});
it("exposes the restoration cause through the public storage error without clearing the original ciphertext", async () => {
  const original = await seed({ ...EMPTY_SAFETY_PLAN, coping: 2 });
  try { await loadSafetyPlan(key, owner); throw new Error("expected restoration failure"); }
  catch (error) { expect(error).toBeInstanceOf(StorageReadError); expect((error as StorageReadError).cause).toMatchObject({ message: "Stored safety-plan shape is invalid." }); }
  expect(records.get(slot)).toBe(original);
});
it.each([false, true])("releases every owned physical copy of the live caller secret when parking a plan settles: failure=%s", async fail => {
  const originalKey = key.slice(); await saveSafetyPlan(key, owner, valid); const previous = records.get(slot);
  registerSafetyPlanSource(() => ({ ...valid, coping: "Writing at lock time" }));
  if (fail) vi.spyOn(kv, "setItem").mockRejectedValue(new Error("quota"));
  const { copies } = await observeSecretCopies(key, () => preserveSafetyPlan());
  expect(copies.length).toBeGreaterThan(0);
  copies.forEach(secret => expect(secret).toEqual(new Uint8Array(secret.length)));
  expect(key).toEqual(originalKey);
  if (fail) expect(records.get(slot)).toBe(previous);
  else expect((await loadSafetyPlan(key, owner))?.coping).toBe("Writing at lock time");
});
