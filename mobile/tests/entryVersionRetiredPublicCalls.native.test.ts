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
  forgetEntryVersion,
  isV2Bound,
  noteV2Bound,
  observeEntryVersions,
  rebindEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";

type SettledCall = { status: "fulfilled"; value: void } | { status: "rejected"; reason: unknown };
let ownedKeys: Buffer[] = [];
function ownedKey(byte: number): Buffer {
  const key = Buffer.alloc(32, byte);
  ownedKeys.push(key);
  return key;
}
function openOwner(key: Buffer): string {
  const user = crypto.randomBytes(16).toString("hex");
  changeLocalSessionOwner(user);
  installLocalDataKey(user, key);
  return user;
}
function settle(operation: Promise<void>): Promise<SettledCall> {
  // Attach both outcomes immediately; observe the actual settled public CALL,
  // without polling a completed flag, checking an error copy, or counting turns.
  return operation.then<SettledCall, SettledCall>(
    value => ({ status: "fulfilled", value }),
    reason => ({ status: "rejected", reason }),
  );
}

beforeEach(() => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
  ownedKeys = [];
});
afterEach(async () => {
  await waitLocalWriteCommits();
  vi.restoreAllMocks();
  runTestControl(resetEntryVersionMirrors);
  runTestControl(__resetLocalKeyLifecycleForTests);
  for (const key of ownedKeys) key.fill(0);
  ownedKeys = [];
});

it("an admitted entry deletion acknowledges the reset that retires its remaining binding work", async () => {
  const key = ownedKey(67), user = openOwner(key), entry = "retired-forget-entry";
  expect(await observeEntryVersions(user, key, [{ clientEntryId: entry, contentVersion: 8 }]))
    .toEqual({ rolledBack: [], advanced: true });
  await noteV2Bound(user, key, entry);
  expect(await isV2Bound(user, key, entry)).toBe(true);

  const slot = "mindpattern.entryVersions." + user;
  const nativeRemove = storage.removeItem.bind(storage);
  let release!: () => void, admitted!: () => void, held = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  const remove = vi.spyOn(storage, "removeItem").mockImplementation(async name => {
    if (name === slot && !held) { held = true; admitted(); await gate; }
    await nativeRemove(name);
  });
  let deleting: Promise<void> | undefined, erasing: Promise<void> | undefined;
  try {
    deleting = forgetEntryVersion(user, key, entry);
    const outcome = settle(deleting);
    // This is the real remove admitted after the initial permit/generation
    // checks. Holding the initial read would retire at an earlier permit check.
    await Promise.race([entered, deleting]);
    changeLocalSessionOwner(null);
    erasing = forgetAllEntryVersions(user);
    // The reset is queued behind the admitted removal, so release before awaiting it.
    release();
    await erasing;
    const settled = await outcome;
    await waitLocalWriteCommits(user);
    expect(settled).toEqual({ status: "fulfilled", value: undefined });
  } finally {
    release();
    await Promise.allSettled([deleting, erasing]);
    await waitLocalWriteCommits(user);
    remove.mockRestore();
  }
});

it("a rebind whose initial read crosses owner retirement rejects after the completed entry reset", async () => {
  const oldKey = ownedKey(71), newKey = ownedKey(73), user = openOwner(oldKey);
  expect(await observeEntryVersions(user, oldKey, [{ clientEntryId: "retired-rebind-entry", contentVersion: 8 }]))
    .toEqual({ rolledBack: [], advanced: true });
  installLocalDataKey(user, newKey);

  const slot = "mindpattern.entryVersions." + user;
  const nativeRead = storage.getItem.bind(storage);
  let release!: () => void, admitted!: () => void, held = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  const read = vi.spyOn(storage, "getItem").mockImplementation(async name => {
    const snapshot = await nativeRead(name);
    if (name === slot && !held) { held = true; admitted(); await gate; }
    return snapshot;
  });
  let rebinding: Promise<void> | undefined, erasing: Promise<void> | undefined;
  try {
    rebinding = rebindEntryVersions(user, oldKey, newKey);
    const outcome = settle(rebinding);
    // Both source and the targeted removed check reach this genuine initial read.
    await Promise.race([entered, rebinding]);
    changeLocalSessionOwner(null);
    erasing = forgetAllEntryVersions(user);
    // No write was admitted by rebind yet, so physical erasure can finish while
    // its old native read snapshot is held. All key buffers remain owned/stable.
    await erasing;
    release();
    const settled = await outcome;
    await waitLocalWriteCommits(user);
    expect(settled.status).toBe("rejected");
  } finally {
    release();
    await Promise.allSettled([rebinding, erasing]);
    await waitLocalWriteCommits(user);
    read.mockRestore();
  }
});
