import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { engine } from "./helpers/nodeEngine";
import { runTestControl } from "./helpers/testControl";
import { accountStorageKey } from "../src/accountStorage";
import {
  __resetLocalKeyLifecycleForTests, changeLocalSessionOwner, installLocalDataKey, markAccountDeleted,
} from "../src/localWriteGuard";
import {
  forgetAllEntryVersions, forgetEntryVersion, noteV2Bound, observeEntryVersions, rebindEntryVersions, resetEntryVersionMirrors,
} from "../src/entryVersions";

const USER = "b".repeat(32), KEY = Buffer.alloc(32, 19);
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
beforeEach(() => {
  storage.__reset(); runTestControl(resetEntryVersionMirrors); runTestControl(__resetLocalKeyLifecycleForTests);
  changeLocalSessionOwner(USER); installLocalDataKey(USER, KEY);
});

it("quietly retires a rebind whose AAD-binding read completes after account deletion and reset", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "retired-entry", contentVersion: 8 }]);
  await noteV2Bound(USER, KEY, "retired-entry");
  const slot = accountStorageKey.entryV2Bound(USER);
  const read = storage.getItem.bind(storage);
  let release!: () => void, admitted!: () => void, held = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async name => {
    const snapshot = await read(name);
    if (name === slot && !held) { held = true; admitted(); await gate; }
    return snapshot;
  });
  const completing = rebindEntryVersions(USER, KEY, KEY).then(
    () => ({ status: "completed" }),
    error => ({ status: "failed", message: error instanceof Error ? error.message : String(error) }),
  );
  let erasing: Promise<void> | undefined;
  try {
    await Promise.race([entered, completing]);
    expect(held).toBe(true);
    markAccountDeleted(USER);
    erasing = forgetAllEntryVersions(USER);
    await erasing;
    release();
    expect(await completing).toEqual({ status: "completed" });
    expect(await read(accountStorageKey.entryVersions(USER))).toBeNull();
    expect(await read(slot)).toBeNull();
  } finally {
    release();
    await Promise.allSettled([completing, erasing]);
  }
});
afterEach(() => { vi.restoreAllMocks(); runTestControl(resetEntryVersionMirrors); });

it("keeps a replacement reset barrier when an earlier reset tolerates a native deletion failure", async () => {
  const row = [{ clientEntryId: "recreated-entry", contentVersion: 1 }];
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "recreated-entry", contentVersion: 8 }]);
  const slot = accountStorageKey.entryVersions(USER);
  expect(await storage.getItem(slot)).not.toBeNull();
  const remove = storage.removeItem.bind(storage);
  let release!: () => void, admitted!: () => void, deletions = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  vi.spyOn(storage, "removeItem").mockImplementation(async name => {
    if (name === slot) {
      const deletion = ++deletions;
      if (deletion === 1) throw new Error("Native deletion temporarily unavailable");
      if (deletion === 2) { admitted(); await gate; }
    }
    await remove(name);
  });
  // Both calls publish their barriers synchronously, before either native
  // deletion settles. Completion of the first must preserve the second.
  const first = forgetAllEntryVersions(USER);
  const second = forgetAllEntryVersions(USER);
  let observing: ReturnType<typeof observeEntryVersions> | undefined;
  try {
    await first;
    await Promise.race([entered, second]);
    expect(deletions).toBe(2);
    observing = observeEntryVersions(USER, KEY, row);
    await turn();
    release(); await second;
    expect(await observing).toEqual({ rolledBack: [], advanced: true });
  } finally {
    release();
    await Promise.allSettled([first, second, observing]);
  }
});

it.each(["rebind", "forget version", "forget binding"] as const)(
  "retires %s before an unavailable native cipher can reject detached guard work",
  async operation => {
    await observeEntryVersions(USER, KEY, [
      { clientEntryId: "retired-entry", contentVersion: 8 },
      { clientEntryId: "other-entry", contentVersion: 3 },
    ]);
    await noteV2Bound(USER, KEY, "retired-entry");
    const slot = operation === "forget binding"
      ? accountStorageKey.entryV2Bound(USER)
      : accountStorageKey.entryVersions(USER);
    const read = storage.getItem.bind(storage);
    let release!: () => void, admitted!: () => void, held = false;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const entered = new Promise<void>(resolve => { admitted = resolve; });
    vi.spyOn(storage, "getItem").mockImplementation(async name => {
      const snapshot = await read(name);
      if (name === slot && !held) { held = true; admitted(); await gate; }
      return snapshot;
    });
    const pending = operation === "rebind"
      ? rebindEntryVersions(USER, KEY, KEY)
      : forgetEntryVersion(USER, KEY, "retired-entry");
    const completing = pending.then(
      () => ({ status: "completed" }),
      error => ({ status: "failed", message: error instanceof Error ? error.message : String(error) }),
    );
    let erasing: Promise<void> | undefined;
    try {
      await Promise.race([entered, completing]);
      expect(held).toBe(true);
      erasing = forgetAllEntryVersions(USER);
      await erasing;
      // The account permit remains current. Only the reset retired this
      // read; obsolete work must finish quietly during a native outage.
      vi.spyOn(engine, "createCipheriv").mockImplementation(() => {
        throw new Error("Native cipher temporarily unavailable");
      });
      release();
      expect(await completing).toEqual({ status: "completed" });
      expect(await read(accountStorageKey.entryVersions(USER))).toBeNull();
      expect(await read(accountStorageKey.entryV2Bound(USER))).toBeNull();
    } finally {
      release();
      await Promise.allSettled([completing, erasing]);
    }
  },
);
