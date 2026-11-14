import crypto from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";
import {
  __resetLocalKeyLifecycleForTests,
  changeLocalSessionOwner,
  installLocalDataKey,
  waitLocalWriteCommits,
} from "../src/localWriteGuard";
import {
  forgetAllEntryVersions,
  observeEntryVersions,
  rebindEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";
import { vault } from "../src/vault";

let ownedKeys: Buffer[] = [];
function ownedKey(byte: number): Buffer {
  const key = Buffer.alloc(32, byte);
  ownedKeys.push(key);
  return key;
}
function ownedCopy(key: Buffer): Buffer {
  const copy = Buffer.from(key);
  ownedKeys.push(copy);
  return copy;
}

// Independent native AES-GCM reader for the registered account version slot.
// This never uses an application decrypt helper or the process version mirror.
function nativeVersions(raw: string, key: Buffer, user: string): unknown {
  const bytes = Buffer.from(raw, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["entry-versions", user])));
  decipher.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
  try { return JSON.parse(plain.toString("utf8")); }
  finally { plain.fill(0); }
}

beforeEach(() => {
  vi.restoreAllMocks();
  vault.lock();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
  ownedKeys = [];
});
afterEach(async () => {
  await waitLocalWriteCommits();
  vi.restoreAllMocks();
  vault.lock();
  runTestControl(resetEntryVersionMirrors);
  runTestControl(__resetLocalKeyLifecycleForTests);
  for (const key of ownedKeys) key.fill(0);
  ownedKeys = [];
});

it("a reset-retired rebind preserves fresh authenticated version bytes when its borrowed vault key locks", async () => {
  // This is the exported reset/rebind API domain, not a shipped rotation caller.
  const user = crypto.randomBytes(16).toString("hex"), slot = "mindpattern.entryVersions." + user;
  const oldKey = ownedKey(79), dataKey = ownedKey(83);
  changeLocalSessionOwner(user);
  installLocalDataKey(user, oldKey);
  expect(await observeEntryVersions(user, oldKey, [{ clientEntryId: "before-reset", contentVersion: 8 }]))
    .toEqual({ rolledBack: [], advanced: true });
  expect(nativeVersions((await storage.getItem(slot))!, oldKey, user)).toEqual({ "before-reset": 8 });

  vault.unlock({ masterKey: ownedKey(89), authKey: ownedKey(97), dataKey }, user);
  const borrowedNewKey = vault.get().dataKey;
  const stableNewKey = ownedCopy(borrowedNewKey);
  installLocalDataKey(user, borrowedNewKey);
  expect(vault.isUnlocked()).toBe(true);

  const nativeRead = storage.getItem.bind(storage), nativeRemove = storage.removeItem.bind(storage);
  let releaseReset!: () => void, resetAdmitted!: () => void, heldReset = false;
  const resetGate = new Promise<void>(resolve => { releaseReset = resolve; });
  const resetEntered = new Promise<void>(resolve => { resetAdmitted = resolve; });
  const remove = vi.spyOn(storage, "removeItem").mockImplementation(async name => {
    if (name === slot && !heldReset) { heldReset = true; resetAdmitted(); await resetGate; }
    await nativeRemove(name);
  });
  let releaseRead!: () => void, readAdmitted!: () => void, heldRead = false;
  const readGate = new Promise<void>(resolve => { releaseRead = resolve; });
  const readEntered = new Promise<void>(resolve => { readAdmitted = resolve; });
  const read = vi.spyOn(storage, "getItem").mockImplementation(async name => {
    const snapshot = await nativeRead(name);
    // Forward the actual read first; only its acknowledgement is delayed.
    if (name === slot && !heldRead) { heldRead = true; readAdmitted(); await readGate; }
    return snapshot;
  });
  let firstReset: Promise<void> | undefined, secondReset: Promise<void> | undefined;
  let rebinding: Promise<void> | undefined, observing: ReturnType<typeof observeEntryVersions> | undefined;
  try {
    firstReset = forgetAllEntryVersions(user);
    void firstReset.catch(() => {});
    await Promise.race([resetEntered, firstReset]);
    // Rebind captures the first reset generation and waits for physical erasure.
    rebinding = rebindEntryVersions(user, oldKey, borrowedNewKey);
    void rebinding.catch(() => {});
    secondReset = forgetAllEntryVersions(user);
    void secondReset.catch(() => {});
    releaseReset();
    await Promise.all([firstReset, secondReset]);
    await Promise.race([readEntered, rebinding]);

    // A real fresh observation owns the replacement generation. Its literal
    // version and independently authenticated physical record are the positives.
    observing = observeEntryVersions(user, stableNewKey, [{ clientEntryId: "fresh-entry", contentVersion: 9 }]);
    expect(await observing).toEqual({ rolledBack: [], advanced: true });
    const fresh = await nativeRead(slot);
    expect(fresh).not.toBeNull();
    expect(nativeVersions(fresh!, stableNewKey, user)).toEqual({ "fresh-entry": 9 });

    // lock() really zeroizes the shared dataKey buffer borrowed before the await.
    // Its local owner/permit state is separate; no fake crypto/key mutation seam.
    vault.lock();
    expect(vault.isUnlocked()).toBe(false);
    releaseRead();
    await rebinding;
    await waitLocalWriteCommits(user);

    // Native authentication failure here is an invalid durable record, not a
    // nonce/count difference. The verifier's pre-lock copy remains independent.
    const durable = await nativeRead(slot);
    expect(durable).not.toBeNull();
    expect(nativeVersions(durable!, stableNewKey, user)).toEqual({ "fresh-entry": 9 });
  } finally {
    releaseReset();
    releaseRead();
    await Promise.allSettled([firstReset, secondReset, rebinding, observing]);
    await waitLocalWriteCommits(user);
    read.mockRestore();
    remove.mockRestore();
  }
});
