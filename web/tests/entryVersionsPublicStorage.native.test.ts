/** SOURCE-ONLY DRAFT: not imported, compiled, materialized or executed.
 * Future web/tests placement only after root review and snapshot promotion.
 * Scope: shipping kvstore over an owned fake-indexeddb factory, shipping crypto,
 * exported version/binding APIs and real local erasure/rotation consumers.
 * One declared target-key native put fault; no browser/device certification,
 * timer oracle, write-arrival gate or account transition from a provider call.
 */
import { expect, it, vi } from "vitest";
import { IDBFactory, IDBObjectStore } from "fake-indexeddb";
import { kv, resetKvConnectionForTests, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { decrypt, fromBase64, toBase64, zeroize } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { entryV2Bindings, forgetAllEntryVersions, forgetEntryVersion, knownEntryVersion, noteV2BoundBatch, observeEntryVersions } from "../src/entryVersions";
import { confirmLocalErasure, stageLocalErasure } from "../src/localErasure";
import { hasLocalRotation, resumeLocalRotation, stageLocalRotation } from "../src/localRotation";

it("persists authenticated version receipts, completes deletion with a failing put provider, and clears process protections through actual erasure and rotation", async () => {
  const namespace = `versions-public-storage-${crypto.randomUUID()}`;
  const owners = ["persist", "forget", "erasure", "rotation"].map(label => `${namespace}-${label}`);
  const [persistOwner, forgetOwner, erasedOwner, rotatedOwner] = owners as [string, string, string, string];
  const oldKey = new Uint8Array(new ArrayBuffer(32)).fill(61);
  const newKey = new Uint8Array(new ArrayBuffer(32)).fill(65);
  const entry = "saved-entry";
  const versionSlot = (owner: string) => `mindpattern.entryVersions.${owner}`;
  const boundSlot = (owner: string) => `mindpattern.entryV2Bound.${owner}`;
  const unrelated = `fixture-unrelated.${namespace}`;
  const factory = new IDBFactory();
  const connections = new Set<IDBDatabase>();
  const open = factory.open.bind(factory);
  const opening = vi.spyOn(factory, "open").mockImplementation((name, version) => {
    const request = open(name, version);
    request.addEventListener("success", () => { connections.add(request.result); });
    return request;
  });
  setKvBackendForTests(null);
  resetKvConnectionForTests();
  vi.stubGlobal("indexedDB", factory);
  // One sequential actor; this provider does not claim lock contention/fairness.
  vi.stubGlobal("navigator", { locks: { request: async (_name: string, run: () => Promise<unknown>) => run() } });

  let bodyFailed = false;
  let bodyError: unknown;
  try {
    await kv.setItem(unrelated, "retained unrelated ciphertext");

    // The returned operation owns completion; durable ciphertext is a separate
    // public storage observation, not a write-count or receipt-arrival witness.
    expect(await observeEntryVersions(persistOwner, oldKey, [{ clientEntryId: entry, contentVersion: 7 }]))
      .toEqual({ advanced: true, rolledBack: [] });
    const persisted = await kv.getItem(versionSlot(persistOwner));
    expect(persisted).not.toBeNull();
    const plaintext = await decrypt(oldKey, fromBase64(persisted!), buildAad("entry-versions", persistOwner));
    try { expect(JSON.parse(new TextDecoder().decode(plaintext))).toEqual({ "saved-entry": 7 }); }
    finally { zeroize(plaintext); }

    // Native put may fail while native deletion remains usable. The shipping
    // KV transaction/permit implementation is retained, including tx abort.
    await observeEntryVersions(forgetOwner, oldKey, [{ clientEntryId: entry, contentVersion: 1 }]);
    const put = IDBObjectStore.prototype.put;
    const unavailablePut = vi.spyOn(IDBObjectStore.prototype, "put").mockImplementation(function (
      this: IDBObjectStore, ...args: Parameters<IDBObjectStore["put"]>
    ) {
      if (this.name === "kv" && args[1] === versionSlot(forgetOwner))
        throw new DOMException("The injected native put provider has no capacity.", "QuotaExceededError");
      return put.apply(this, args);
    });
    try {
      await expect(forgetEntryVersion(forgetOwner, oldKey, entry)).resolves.toBeUndefined();
      expect(await kv.getItem(versionSlot(forgetOwner))).toBeNull();
      expect(await knownEntryVersion(forgetOwner, oldKey, entry)).toBeNull();
      expect(await kv.getItem(unrelated)).toBe("retained unrelated ciphertext");
    } finally { unavailablePut.mockRestore(); }

    // No reset helper is called in setup or the observer. Actual erasure must
    // remove both durable records and the already established process memory.
    await observeEntryVersions(erasedOwner, oldKey, [{ clientEntryId: entry, contentVersion: 7 }]);
    await noteV2BoundBatch(erasedOwner, oldKey, new Set([entry]));
    expect(await knownEntryVersion(erasedOwner, oldKey, entry)).toBe(7);
    expect(await entryV2Bindings(erasedOwner, oldKey)).toEqual(new Set([entry]));
    await stageLocalErasure(erasedOwner);
    await confirmLocalErasure(erasedOwner);
    expect(await kv.getItem(versionSlot(erasedOwner))).toBeNull();
    expect(await kv.getItem(boundSlot(erasedOwner))).toBeNull();
    expect(await knownEntryVersion(erasedOwner, oldKey, entry)).toBeNull();
    expect(await entryV2Bindings(erasedOwner, oldKey)).toEqual(new Set());
    expect(await kv.getItem(unrelated)).toBe("retained unrelated ciphertext");

    // Missing durable metadata is supported: the process still remembers the
    // old key's version/binding before staging. Only production migration reset
    // may clear that memory; a test-only reset is never substituted or shielded.
    await observeEntryVersions(rotatedOwner, oldKey, [{ clientEntryId: entry, contentVersion: 7 }]);
    await noteV2BoundBatch(rotatedOwner, oldKey, new Set([entry]));
    await kv.removeItem(versionSlot(rotatedOwner));
    await kv.removeItem(boundSlot(rotatedOwner));
    expect(await knownEntryVersion(rotatedOwner, oldKey, entry)).toBe(7);
    expect(await entryV2Bindings(rotatedOwner, oldKey)).toEqual(new Set([entry]));
    const credential = {
      operation_id: crypto.randomUUID(),
      new_salt: toBase64(new Uint8Array(new ArrayBuffer(16)).fill(67)),
      new_verifier: toBase64(newKey),
    };
    await stageLocalRotation(rotatedOwner, oldKey, newKey, credential);
    await resumeLocalRotation(rotatedOwner, newKey, credential.new_salt);
    expect(await hasLocalRotation(rotatedOwner)).toBe(false);
    expect(await knownEntryVersion(rotatedOwner, newKey, entry)).toBeNull();
    expect(await entryV2Bindings(rotatedOwner, newKey)).toEqual(new Set());
    expect(await kv.getItem(unrelated)).toBe("retained unrelated ciphertext");
  } catch (error) {
    bodyFailed = true;
    bodyError = error;
  }

  // All operations above are awaited, including rejected transactions. Clean
  // only this actor's factory/owners after observations. Removing fixture-only
  // generation fences here permits the public forget-all cleanup of mirrors;
  // no erased generation is changed before its public outcome is inspected.
  const cleanupErrors: unknown[] = [];
  for (const owner of owners) {
    try { await kv.removeItem(writeGenerationKey(owner)); await forgetAllEntryVersions(owner); }
    catch (error) { cleanupErrors.push(error); }
  }
  zeroize(oldKey, newKey);
  for (const db of connections) {
    try { db.close(); } catch (error) { cleanupErrors.push(error); }
  }
  resetKvConnectionForTests();
  try {
    await new Promise<void>((resolve, reject) => {
      const request = factory.deleteDatabase("mindpattern");
      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error ?? new Error("Owned fixture database cleanup failed."));
      request.onblocked = () => {
        cleanupErrors.push(new Error("An owned fixture database connection remained open."));
        for (const db of connections) db.close();
        // Keep owning the delete request through its eventual success/error;
        // a blocked notification alone must not leave pending cleanup behind.
      };
    });
  } catch (error) { cleanupErrors.push(error); }
  opening.mockRestore();
  setKvBackendForTests(null);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  // Preserve the actual first body error; cleanup must never replace it with a
  // later unrelated assertion or admission failure.
  if (bodyFailed) throw bodyError;
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Owned fixture cleanup did not finish.");
});
