/** custody policy. Observe genuine provider handles while
 * returning each original importKey Promise unchanged. The shipping notes
 * consumers perform all encryption/decryption; native export is the oracle.
 * Copy into a disposable portal/tests lane before running. */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";


import { afterEach, expect, it, vi } from "vitest";
import { decryptNote, encryptNote, type Bytes } from "../src/crypto";

const OWNER = "synthetic-export-policy-therapist";
const PATIENT = "synthetic-export-policy-patient";
const ID = "synthetic-export-policy-note";
const TEXT = "A synthetic clinical note remains authenticated.";
const KEY = new Uint8Array(Array.from({ length: 32 }, (_, index) => index + 1)) as Bytes;
type Case = "encrypt-note-native-handle" | "decrypt-note-native-handle";
type Witness = { case: Case; stage: string; checks: { name: string; passed: boolean }[]; controls?: unknown; observations: unknown[]; error?: string };
let witness: Witness | undefined;

async function completed<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`ExecutionError: native provider completion timed out: ${label}`)), 12_000);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}

async function exportObservation(subtle: SubtleCrypto, handle: CryptoKey): Promise<{ outcome: string; bytes?: number }> {
  try {
    const exported = new Uint8Array(await completed(subtle.exportKey("raw", handle), "export policy"));
    const bytes = exported.length;
    exported.fill(0);
    return { outcome: "exported", bytes };
  } catch (error) {
    if (error instanceof Error && error.name === "InvalidAccessError") return { outcome: "InvalidAccessError" };
    // Node22 uses this native DOMException name for the same denied raw export.
    // Require the genuine DOMException and an actually nonextractable handle.
    if (error instanceof DOMException && error.name === "InvalidAccessException" && handle.extractable === false) return { outcome: "InvalidAccessError" };
    if (error instanceof Error && /ExecutionError/.test(error.message)) throw error;
    throw new Error(`SetupError: native export provider failed outside policy refusal: ${String(error)}`);
  }
}

async function providerControl(subtle: SubtleCrypto): Promise<void> {
  try {
    const denied = await completed(subtle.importKey("raw", KEY, "AES-GCM", false, ["encrypt", "decrypt"]), "nonextractable control");
    const allowed = await completed(subtle.importKey("raw", KEY, "AES-GCM", true, ["encrypt", "decrypt"]), "extractable control");
    const deniedResult = await exportObservation(subtle, denied);
    const allowedBytes = new Uint8Array(await completed(subtle.exportKey("raw", allowed), "positive export control"));
    const sameBytes = allowedBytes.length === KEY.length && allowedBytes.every((byte, index) => byte === KEY[index]);

    allowedBytes.fill(0);
    if (deniedResult.outcome !== "InvalidAccessError" || !sameBytes) throw new Error("native controls did not distinguish denied and authenticated raw export");

    witness!.stage = "provider-controls-complete";
  } catch (error) {
    if (error instanceof Error && /ExecutionError/.test(error.message)) throw error;
    throw new Error(`SetupError: native AES export controls failed: ${String(error)}`);
  }
}

function observeNativeAesImports(subtle: SubtleCrypto): { handles: CryptoKey[]; restore: () => void } {
  const original = subtle.importKey;
  const handles: CryptoKey[] = [];
  const forwarding = ((...args: unknown[]) => {
    const promise = Reflect.apply(original, subtle, args) as Promise<CryptoKey>;
    // Observers never substitute a fake key, Promise or provider result.
    promise.then(handle => { if (handle.algorithm.name === "AES-GCM" && handle.type === "secret") handles.push(handle); }, () => undefined);
    return promise;
  }) as SubtleCrypto["importKey"];
  const spy = vi.spyOn(subtle, "importKey").mockImplementation(forwarding);
  return { handles, restore: () => spy.mockRestore() };
}

function sealedByIndependentNode(): string {
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", KEY, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["note", OWNER, PATIENT, ID]), "utf8"));
  return Buffer.concat([nonce, cipher.update(JSON.stringify({ v: 1, text: TEXT }), "utf8"), cipher.final(), cipher.getAuthTag()]).toString("base64");
}

function independentlyOpen(blobB64: string): string {
  const bytes = Buffer.from(blobB64, "base64"), decipher = createDecipheriv("aes-256-gcm", KEY, bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["note", OWNER, PATIENT, ID]), "utf8"));
  decipher.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
  try { return (JSON.parse(plain.toString("utf8")) as { text: string }).text; }
  finally { plain.fill(0); }
}



afterEach(() => {
  vi.restoreAllMocks();


  witness = undefined;
});

it.each(["encrypt-note-native-handle", "decrypt-note-native-handle"] as const)("retains nonextractable AES provider custody after actual %s", async (scenario) => {
    witness = { case: scenario, stage: "setup", checks: [], observations: [] };
    const subtle = globalThis.crypto?.subtle;
    if (!subtle) throw new Error("SetupError: genuine native WebCrypto provider is unavailable");
    try {
      await providerControl(subtle);
      const observation = observeNativeAesImports(subtle);
      let text: string;
      try {
        if (scenario === "encrypt-note-native-handle") {
          const sealed = await completed(encryptNote(KEY, OWNER, PATIENT, ID, TEXT), "shipping encryptNote");
          text = independentlyOpen(sealed.blobB64);

        } else {
          const sealed = sealedByIndependentNode();
          if (independentlyOpen(sealed) !== TEXT) throw new Error("SetupError: independent authenticated note fixture failed its positive control");
          text = await completed(decryptNote(KEY, OWNER, PATIENT, ID, sealed), "shipping decryptNote");

        }
      } finally { observation.restore(); }
      // Let the fulfilled original import Promise's forwarding observer finish.
      await Promise.resolve();
      if (observation.handles.length !== 1) throw new Error(`SetupError: expected exactly one genuine shipping AES handle, observed ${observation.handles.length}`);
      const handle = observation.handles[0]!;
      witness.stage = "behavior-oracle";
      {
const name = "authenticated clinical note has independently authored plaintext";
const passed = text === TEXT;


  expect(passed, name).toBe(true);

}
      const exported = await exportObservation(subtle, handle);

      {
const name = "native AES handle denies raw export after consumer completion";
const passed = exported.outcome === "InvalidAccessError";


  expect(passed, name).toBe(true);

}
      {
const name = "caller-owned synthetic key remains intact";
const passed = KEY.every((byte, index) => byte === index + 1);


  expect(passed, name).toBe(true);

}
      witness.stage = "passed";
    } catch (error) {

      if (witness.stage !== "behavior-oracle" && !/SetupError|ExecutionError/.test(String(error))) {
        throw new Error(`ExecutionError: shipping native consumer or fixture did not complete: ${String(error)}`);
      }
      throw error;
    }
  });
