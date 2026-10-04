import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { setSecureStoreBackend } from "../src/secureStore";
import { prepareLocalRekey, resumeLocalRekey, pendingLocalRekey, clearLocalRekey, assertLocalWritesAllowed, markLocalRekeyPhase } from "../src/localRekey";
import { emptySafetyPlan, saveSafetyPlan, loadSafetyPlan } from "../src/safetyPlan";
import { savePendingMeasure, loadPendingMeasure } from "../src/pendingMeasure";
import { isV2Bound, noteV2Bound, resetEntryVersionMirrors } from "../src/entryVersions";
import { encryptAudio, decryptAudio } from "../src/crypto/journalCrypto";
import { enqueueAudio } from "../src/audioQueue";
import * as fs from "./helpers/expoFsMock";
const user = "local-rekey-owner";
const oldKey = Buffer.alloc(32, 5), newKey = Buffer.alloc(32, 9);
beforeEach(async () => {
  await clearLocalRekey(user).catch(() => {});
  storage.__reset(); fs.__resetFiles(); setSecureStoreBackend(null); resetEntryVersionMirrors();
});
describe("durable registered local rekey", () => {
  it("a prepared proof alone cannot apply local replacements before credential commit", async () => {
    await saveSafetyPlan(oldKey, user, emptySafetyPlan());
    await prepareLocalRekey(user, oldKey, newKey);
    await expect(resumeLocalRekey(user, newKey)).rejects.toThrow("confirmed online");
    expect(await loadSafetyPlan(oldKey, user)).toEqual(emptySafetyPlan());
    await resumeLocalRekey(user, newKey, { credentialConfirmed: true });
    expect(await loadSafetyPlan(newKey, user)).toEqual(emptySafetyPlan());
  });
  it("preserves the safety plan, completed measure, rollback binding and recording through a data-key change", async () => {
    const plan = { ...emptySafetyPlan(), warningSigns: "My own warning signs" };
    await saveSafetyPlan(oldKey, user, plan);
    const measure = { kind: "phq9" as const, clientMeasureId: "pending-one", picks: Array(9).fill(1), date: "2026-10-03" };
    await savePendingMeasure(oldKey, user, measure);
    await noteV2Bound(user, oldKey, "entry:one");
    const plaintext = Buffer.from("voice bytes");
    await enqueueAudio({ userId: user, clientEntryId: "entry:one", ...encryptAudio({ dataKey: oldKey }, user, "entry:one", plaintext), mime: "audio/m4a", durationSeconds: 5 });
    await prepareLocalRekey(user, oldKey, newKey);
    expect(await loadSafetyPlan(oldKey, user)).toEqual(plan);
    expect(() => assertLocalWritesAllowed(user)).toThrow("paused");
    expect(await pendingLocalRekey(user)).toBe(true);
    await markLocalRekeyPhase(user, "credential");
    await resumeLocalRekey(user, newKey);
    expect(await loadSafetyPlan(newKey, user)).toEqual(plan);
    expect(await loadPendingMeasure(newKey, user)).toEqual(measure);
    resetEntryVersionMirrors(); expect(await isV2Bound(user, newKey, "entry:one")).toBe(true);
    const descriptorKey = (await storage.getAllKeys()).find(k => k.startsWith("@mindpattern/audioqueue.v1:"))!;
    const descriptor = JSON.parse((await storage.getItem(descriptorKey))!);
    const ciphertext = await fs.readAsStringAsync(descriptor.uri);
    expect(decryptAudio({ dataKey: newKey }, user, "entry:one", ciphertext)).toEqual(plaintext);
    expect(await pendingLocalRekey(user)).toBe(false);
    expect(() => assertLocalWritesAllowed(user)).not.toThrow();
    const allStored = JSON.stringify(await Promise.all((await storage.getAllKeys()).map(k => storage.getItem(k))));
    expect(allStored).not.toContain("My own warning signs");
    expect(allStored).not.toContain(oldKey.toString("base64"));
    expect(allStored).not.toContain(newKey.toString("base64"));
  });
  it("resumes after an interrupted local commit and never overwrites an independently changed record", async () => {
    const plan = { ...emptySafetyPlan(), copingStrategies: "A walk" };
    await saveSafetyPlan(oldKey, user, plan);
    await savePendingMeasure(oldKey, user, { kind: "phq9", clientMeasureId: "one", picks: Array(9).fill(0), date: "2026-10-03" });
    await prepareLocalRekey(user, oldKey, newKey);
    await markLocalRekeyPhase(user, "credential");
    const original = storage.setItem;
    const spy = vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === `@mindpattern/pending_measure_${user}`) throw new Error("disk temporarily unavailable");
      return original(key, value);
    });
    await expect(resumeLocalRekey(user, newKey)).rejects.toThrow("disk");
    spy.mockRestore();
    setSecureStoreBackend(null); // process restart reopens the same device key
    expect(await pendingLocalRekey(user)).toBe(true);
    await markLocalRekeyPhase(user, "credential");
    await resumeLocalRekey(user, newKey);
    expect(await loadSafetyPlan(newKey, user)).toEqual(plan);
    expect(await loadPendingMeasure(newKey, user)).not.toBeNull();
    expect(await pendingLocalRekey(user)).toBe(false);
  });
  it("a wrong retry target password cannot replace a prepared key generation", async () => {
    await saveSafetyPlan(oldKey, user, emptySafetyPlan());
    await prepareLocalRekey(user, oldKey, newKey);
    await expect(prepareLocalRekey(user, oldKey, Buffer.alloc(32, 11))).rejects.toThrow();
    expect(await loadSafetyPlan(oldKey, user)).toEqual(emptySafetyPlan());
    expect(await pendingLocalRekey(user)).toBe(true);
  });
});
