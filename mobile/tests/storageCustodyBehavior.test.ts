import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv,createDecipheriv } from "node:crypto";
import storage from "./helpers/storageMock";
import { engine } from "./helpers/nodeEngine";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { buildFeedbackBlob, recordFeedbackTap } from "../src/questionFeedback";
import { loadPendingMeasure, savePendingMeasure } from "../src/pendingMeasure";

const owner = "11111111111111111111111111111111", key = Buffer.alloc(32, 11);
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); runTestControl(setSecureStoreBackend, null); });
afterEach(() => { vi.restoreAllMocks(); runTestControl(setSecureStoreBackend, null); });
function heldPlaintext(expectedReads: string[] = []) {
  const written: Buffer[] = [], read: Buffer[] = [], keys: Buffer[] = [], create = engine.createCipheriv.bind(engine), decipher = engine.createDecipheriv.bind(engine), toString = Buffer.prototype.toString;
  vi.spyOn(engine, "createCipheriv").mockImplementation((algorithm, cipherKey, nonce) => {
    keys.push(cipherKey as Buffer);
    const cipher = create(algorithm, cipherKey, nonce), update = cipher.update.bind(cipher);
    vi.spyOn(cipher, "update").mockImplementation((plain: Buffer) => { written.push(plain); return update(plain); }); return cipher;
  });
  vi.spyOn(engine, "createDecipheriv").mockImplementation((algorithm, cipherKey, nonce) => { keys.push(cipherKey as Buffer); return decipher(algorithm, cipherKey, nonce); });
  vi.spyOn(Buffer.prototype, "toString").mockImplementation(function(this: Buffer, ...args: any[]) {
    const value = toString.apply(this, args as [BufferEncoding?, number?, number?]); if (expectedReads.includes(value)) read.push(this); return value;
  });
  return { written, read, keys };
}
function erased(buffers: Buffer[]) { expect(buffers.length).toBeGreaterThan(0); for (const buffer of buffers) expect(buffer.every(byte => byte === 0)).toBe(true); }
function nativeBackend() {
  let deviceKey: string | null = key.toString("base64");
  return { readDeviceKey: async () => deviceKey, writeDeviceKey: async (value: string) => { deviceKey = value; }, getItem: storage.getItem, setItem: storage.setItem, removeItem: storage.removeItem };
}
function seal(value: string): string {
  const nonce = Buffer.alloc(12, 3), cipher = createCipheriv("aes-256-gcm", key, nonce);
  return Buffer.concat([nonce, cipher.update(value), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

it.each([false, true])("erases the feedback append plaintext after native commit failure=%s", async failure => {
  const held = heldPlaintext(); if (failure) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Feedback native commit failed"));
  const operation = recordFeedbackTap(key, owner, "private-pattern", true);
  if (failure) await expect(operation).rejects.toThrow("Feedback native commit failed"); else await expect(operation).resolves.toBeUndefined();
  erased(held.written); erased(held.keys); expect(key).toEqual(Buffer.alloc(32, 11));
});

it("erases feedback read and processing-body plaintext after creating the real recompute blob", async () => {
  await recordFeedbackTap(key, owner, "private-pattern", true);
  // Read the actual Native receipt independently: append now adds an
  // internal event identity which must remain outside the server payload.
  const wire=Buffer.from((await storage.getItem(`@mindpattern/question_feedback.${owner}`))!,"base64"),decipher=createDecipheriv("aes-256-gcm",key,wire.subarray(0,12));decipher.setAAD(Buffer.from(JSON.stringify(["feedback-local",owner])));decipher.setAuthTag(wire.subarray(-16));const plain=Buffer.concat([decipher.update(wire.subarray(12,-16)),decipher.final()]);let input:string;try{input=plain.toString("utf8");expect(JSON.parse(input)).toMatchObject([{pid:"private-pattern",resonated:true}]);}finally{plain.fill(0);}const held = heldPlaintext([input]);
  expect(await buildFeedbackBlob(key, owner)).toEqual(expect.any(String)); erased(held.read); erased(held.written); erased(held.keys);
});

it("erases malformed authenticated feedback plaintext before treating the optional queue as absent", async () => {
  const nonce = Buffer.alloc(12, 3), cipher = createCipheriv("aes-256-gcm", key, nonce); cipher.setAAD(Buffer.from(JSON.stringify(["feedback-local", owner])));
  const input = "malformed private feedback", blob = Buffer.concat([nonce, cipher.update(input), cipher.final(), cipher.getAuthTag()]);
  await storage.setItem(`@mindpattern/question_feedback.${owner}`, blob.toString("base64"));
  const held = heldPlaintext([input]); expect(await buildFeedbackBlob(key, owner)).toBeNull(); erased(held.read);
});

it.each([false, true])("erases credential plaintext after encrypted native commit failure=%s", async failure => {
  runTestControl(setSecureStoreBackend, nativeBackend()); const held = heldPlaintext();
  if (failure) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native credential commit failed"));
  // Preserve the native backend method dynamically so its rejection is real.
  runTestControl(setSecureStoreBackend, { ...nativeBackend(), setItem: (...args) => storage.setItem(...args) });
  const operation = secureStore.setItem("installed-session-record", "private bearer material");
  if (failure) await expect(operation).rejects.toThrow("Native credential commit failed"); else await expect(operation).resolves.toBeUndefined();
  erased(held.written);
});

it.each(["v1", "legacy"])("erases plaintext returned by native decryption of an installed %s record", async format => {
  const value = "private installed bearer", ciphertext = seal(value); runTestControl(setSecureStoreBackend, nativeBackend());
  await storage.setItem("installed-session-record", format === "v1" ? JSON.stringify({ v: 1, c: ciphertext }) : ciphertext);
  const held = heldPlaintext([value]); expect(await secureStore.getItem("installed-session-record")).toBe(value); erased(held.read);
  if (format === "legacy") erased(held.written);
});

it.each([false, true])("erases the pending questionnaire key and plaintext after commit failure=%s", async failure => {
  const value = { kind: "phq2" as const, picks: [1, 3], clientMeasureId: "pending-native-custody", date: "2026-10-05" }, held = heldPlaintext();
  if (failure) vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Pending native commit failed"));
  const operation = savePendingMeasure(key, owner, value);
  if (failure) await expect(operation).rejects.toThrow("Pending native commit failed"); else await expect(operation).resolves.toBeUndefined();
  erased(held.written); erased(held.keys); expect(key).toEqual(Buffer.alloc(32, 11));
});

it("erases the key and parsed plaintext consumed by pending questionnaire restoration", async () => {
  const value = { kind: "phq2" as const, picks: [1, 3], clientMeasureId: "pending-native-custody", date: "2026-10-05" };
  await savePendingMeasure(key, owner, value); const held = heldPlaintext([JSON.stringify(value)]);
  expect(await loadPendingMeasure(key, owner)).toEqual(value); erased(held.read); erased(held.keys); expect(key).toEqual(Buffer.alloc(32, 11));
});
