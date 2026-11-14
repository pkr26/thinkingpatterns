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
  isV2Bound,
  noteV2Bound,
  observeEntryVersions,
  rebindEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";

let key: Buffer;

// Genuine independent native ciphertext for a post-delete storage publication.
// This is valid binding JSON, using the account wire's nonce12/tag16 and AAD.
function nativeBinding(ids: string[], user: string): string {
  const plaintext = Buffer.from(JSON.stringify(ids), "utf8");
  try {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify(["entry-v2-bound", user])));
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString("base64");
  } finally { plaintext.fill(0); }
}

beforeEach(() => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
  key = Buffer.alloc(32, 53);
});

afterEach(async () => {
  await waitLocalWriteCommits();
  vi.restoreAllMocks();
  runTestControl(resetEntryVersionMirrors);
  runTestControl(__resetLocalKeyLifecycleForTests);
  key.fill(0);
});

it("a reset-retired rebind does not remember a later binding whose storage disappears", async () => {
  const user = crypto.randomBytes(16).toString("hex");
  changeLocalSessionOwner(user);
  installLocalDataKey(user, key);
  const previous = "pre-reset-bound-entry", replacement = "post-delete-published-binding";
  const versionsSlot = "mindpattern.entryVersions." + user;
  const bindingSlot = "mindpattern.entryV2Bound." + user;
  expect(await observeEntryVersions(user, key, [{ clientEntryId: previous, contentVersion: 8 }]))
    .toEqual({ rolledBack: [], advanced: true });
  await noteV2Bound(user, key, previous);
  expect(await isV2Bound(user, key, previous)).toBe(true);

  const nativeWrite = storage.setItem.bind(storage);
  const nativeRemove = storage.removeItem.bind(storage);
  let releaseWrite!: () => void, writeAdmitted!: () => void;
  let releaseEraseAck!: () => void, physicallyDeleted!: () => void;
  const writeGate = new Promise<void>(resolve => { releaseWrite = resolve; });
  const admittedWrite = new Promise<void>(resolve => { writeAdmitted = resolve; });
  const eraseAckGate = new Promise<void>(resolve => { releaseEraseAck = resolve; });
  const bindingDeleted = new Promise<void>(resolve => { physicallyDeleted = resolve; });
  let heldWrite = false, heldEraseAck = false;
  const write = vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => {
    if (name === versionsSlot && !heldWrite) {
      heldWrite = true;
      writeAdmitted();
      await writeGate;
    }
    await nativeWrite(name, value);
  });
  const remove = vi.spyOn(storage, "removeItem").mockImplementation(async name => {
    await nativeRemove(name);
    if (name === bindingSlot && !heldEraseAck) {
      heldEraseAck = true;
      // The real native Map deletion is already complete. Only its acknowledgement
      // is delayed, in both ordinary source and the candidate mutation.
      physicallyDeleted();
      await eraseAckGate;
    }
  });
  let rebinding: Promise<void> | undefined, erasing: Promise<void> | undefined;
  try {
    rebinding = rebindEntryVersions(user, key, key);
    await admittedWrite;
    erasing = forgetAllEntryVersions(user);
    releaseWrite();
    await bindingDeleted;

    // A fresh authenticated storage record is published after the physical
    // deletion, before its acknowledgement. It is never observed through an
    // entry API here. Both providers retain their real native Map behavior.
    await storage.setItem(bindingSlot, nativeBinding([replacement], user));
    releaseEraseAck();
    await Promise.all([erasing, rebinding]);
    await waitLocalWriteCommits(user);

    // The module promises process observations survive disappearing storage.
    // A retired old rebind must not have observed this replacement-generation ID.
    await storage.removeItem(bindingSlot);
    expect(await storage.getItem(bindingSlot)).toBeNull();
    expect(await isV2Bound(user, key, replacement)).toBe(false);
  } finally {
    releaseWrite();
    releaseEraseAck();
    await Promise.allSettled([rebinding, erasing]);
    await waitLocalWriteCommits(user);
    write.mockRestore();
    remove.mockRestore();
  }
});
