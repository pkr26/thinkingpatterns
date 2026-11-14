import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";
import { accountStorageKey } from "../src/accountStorage";
import {
  __resetLocalKeyLifecycleForTests, captureLocalWritePermit, changeLocalSessionOwner,
  commitLocalWrite, installLocalDataKey, waitLocalWriteCommits,
} from "../src/localWriteGuard";
import {
  forgetAllEntryVersions, isV2Bound, knownEntryVersion, observeEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";

const USER = "b".repeat(32), KEY = Buffer.alloc(32, 19);
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
beforeEach(() => {
  storage.__reset(); runTestControl(resetEntryVersionMirrors); runTestControl(__resetLocalKeyLifecycleForTests);
  changeLocalSessionOwner(USER); installLocalDataKey(USER, KEY);
});
afterEach(() => { vi.restoreAllMocks(); runTestControl(resetEntryVersionMirrors); });

it("rejects zero and negative first observations without inventing rollback history", async () => {
  expect(await observeEntryVersions(USER, KEY, [
    { clientEntryId: "never-zero", contentVersion: 0 },
    { clientEntryId: "never-negative", contentVersion: -1 },
    { clientEntryId: "first-positive", contentVersion: 1 },
  ])).toEqual({ rolledBack: [], advanced: true });
  expect(await knownEntryVersion(USER, KEY, "never-zero")).toBeNull();
  expect(await knownEntryVersion(USER, KEY, "never-negative")).toBeNull();
  expect(await knownEntryVersion(USER, KEY, "first-positive")).toBe(1);
});

it("orders account erasure after an admitted version write and releases settled queue ownership", async () => {
  const nativeSet = Map.prototype.set, receivers: Map<unknown, unknown>[] = [];
  vi.spyOn(Map.prototype, "set").mockImplementation(function (this: Map<unknown, unknown>, owner: unknown, value: unknown) {
    const result = nativeSet.call(this, owner, value);
    if (owner === USER && value instanceof Promise && !receivers.includes(this)) receivers.push(this);
    return result;
  });
  let release!: () => void, admitted!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  const write = storage.setItem.bind(storage);
  vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => {
    if (name === accountStorageKey.entryVersions(USER)) { admitted(); await held; }
    await write(name, value);
  });
  const observing = observeEntryVersions(USER, KEY, [{ clientEntryId: "erased-entry", contentVersion: 8 }]);
  let forgetting: Promise<void> | undefined;
  try {
    await Promise.race([entered, observing]);
    let erased = false;
    forgetting = forgetAllEntryVersions(USER).then(() => { erased = true; });
    await turn(); expect(erased).toBe(false);
    release(); await observing; await forgetting;
    expect(await storage.getItem(accountStorageKey.entryVersions(USER))).toBeNull();
    expect(await storage.getItem(accountStorageKey.entryV2Bound(USER))).toBeNull();
    expect(receivers.length).toBeGreaterThan(0);
    for (const receiver of receivers) expect(receiver.has(USER), "settled write/reset metadata retains its account").toBe(false);
  } finally { release(); await Promise.allSettled([observing, forgetting]); }
});

it("reads both empty rollback stores after erasure within a finite account lookup budget", async () => {
  await forgetAllEntryVersions(USER);
  const nativeHas = Map.prototype.has;
  let lookups = 0;
  const observer = vi.spyOn(Map.prototype, "has").mockImplementation(function (this: Map<unknown, unknown>, key: unknown) {
    if (key === USER && ++lookups > 64) throw new Error("finite erased-account lookup stopped making progress");
    return nativeHas.call(this, key);
  });
  try {
    expect(await knownEntryVersion(USER, KEY, "forgotten-entry")).toBeNull();
    expect(await isV2Bound(USER, KEY, "forgotten-entry")).toBe(false);
  } finally { observer.mockRestore(); }
});

it.each([undefined, USER] as const)("drains settled physical commits for owner %s within a finite settlement budget", async owner => {
  await commitLocalWrite(captureLocalWritePermit(USER, KEY), async () => "durable receipt");
  const nativeAllSettled = Promise.allSettled.bind(Promise);
  let settlements = 0;
  const observer = vi.spyOn(Promise, "allSettled").mockImplementation((values: Iterable<unknown>) => {
    if (++settlements > 16) throw new Error("finite native commit drain stopped making progress");
    return nativeAllSettled(values);
  });
  try { await expect(waitLocalWriteCommits(owner)).resolves.toBeUndefined(); }
  finally { observer.mockRestore(); }
});

it("keeps a second version write ordered when a third write arrives after the first settles", async () => {
  const write = storage.setItem.bind(storage);
  let releaseFirst!: () => void, releaseSecond!: () => void, enteredFirst!: () => void, enteredSecond!: () => void;
  const firstGate = new Promise<void>(resolve => { releaseFirst = resolve; });
  const secondGate = new Promise<void>(resolve => { releaseSecond = resolve; });
  const firstEntered = new Promise<void>(resolve => { enteredFirst = resolve; });
  const secondEntered = new Promise<void>(resolve => { enteredSecond = resolve; });
  let admissions = 0;
  vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => {
    if (name === accountStorageKey.entryVersions(USER)) {
      const admission = ++admissions;
      if (admission === 1) { enteredFirst(); await firstGate; }
      if (admission === 2) { enteredSecond(); await secondGate; }
    }
    await write(name, value);
  });
  const row = (version: number) => [{ clientEntryId: "ordered-entry", contentVersion: version }];
  const first = observeEntryVersions(USER, KEY, row(1));
  let second: ReturnType<typeof observeEntryVersions> | undefined, third: typeof second;
  try {
    await Promise.race([firstEntered, first]);
    second = observeEntryVersions(USER, KEY, row(2));
    releaseFirst(); await first; await Promise.race([secondEntered, second]);
    third = observeEntryVersions(USER, KEY, row(3));
    await turn(); expect(admissions, "third write overtook an admitted durable version write").toBe(2);
    releaseSecond(); await second; await third;
    runTestControl(resetEntryVersionMirrors);
    expect(await knownEntryVersion(USER, KEY, "ordered-entry")).toBe(3);
  } finally { releaseFirst(); releaseSecond(); await Promise.allSettled([first, second, third]); }
});

it("waits for ordered erasure before reading either replacement rollback store", async () => {
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "prior-entry", contentVersion: 8 }]);
  const { noteV2Bound } = await import("../src/entryVersions");
  await noteV2Bound(USER, KEY, "prior-entry");
  const remove = storage.removeItem.bind(storage);
  let release!: () => void, admitted!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  vi.spyOn(storage, "removeItem").mockImplementation(async name => {
    if (name === accountStorageKey.entryVersions(USER)) { admitted(); await gate; }
    await remove(name);
  });
  const erasing = forgetAllEntryVersions(USER);
  let known: Promise<number | null> | undefined, bound: Promise<boolean> | undefined;
  try {
    await Promise.race([entered, erasing]);
    let knownFinished = false, boundFinished = false;
    known = knownEntryVersion(USER, KEY, "prior-entry").then(value => { knownFinished = true; return value; });
    bound = isV2Bound(USER, KEY, "prior-entry").then(value => { boundFinished = true; return value; });
    await turn();
    expect(knownFinished, "rollback read passed an unfinished account erasure").toBe(false);
    expect(boundFinished, "AAD binding read passed an unfinished account erasure").toBe(false);
    release(); await erasing;
    expect(await known).toBeNull(); expect(await bound).toBe(false);
  } finally { release(); await Promise.allSettled([erasing, known, bound]); }
});

it("drains a host-delivered physical receipt within a finite global settlement budget", async () => {
  let release!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const committing = commitLocalWrite(captureLocalWritePermit(USER, KEY), () => held);
  const nativeAllSettled = Promise.allSettled.bind(Promise);
  let settlements = 0;
  const observer = vi.spyOn(Promise, "allSettled").mockImplementation((values: Iterable<unknown>) => {
    if (++settlements > 16) throw new Error("finite held-receipt drain stopped making progress");
    return nativeAllSettled(values);
  });
  const delivery = setImmediate(release);
  try { await expect(waitLocalWriteCommits()).resolves.toBeUndefined(); }
  finally { clearImmediate(delivery); observer.mockRestore(); release(); await committing; }
});

it.each(["account reset", "owner retirement"] as const)("does not admit a queued version write after %s", async retirement => {
  const write = storage.setItem.bind(storage);
  let release!: () => void, admitted!: () => void, admissions = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => {
    if (name === accountStorageKey.entryVersions(USER)) {
      admissions++;
      if (admissions === 1) { admitted(); await gate; }
    }
    await write(name, value);
  });
  const first = observeEntryVersions(USER, KEY, [{ clientEntryId: "retiring-entry", contentVersion: 1 }]);
  let second: typeof first | undefined, erasing: Promise<void> | undefined;
  try {
    await Promise.race([entered, first]);
    second = observeEntryVersions(USER, KEY, [{ clientEntryId: "retiring-entry", contentVersion: 2 }]);
    await turn();
    if (retirement === "account reset") erasing = forgetAllEntryVersions(USER);
    else changeLocalSessionOwner("c".repeat(32));
    release(); await first; await second; await erasing;
    expect(admissions, "a queued retired snapshot reached native persistence").toBe(1);
    if (retirement === "account reset") expect(await storage.getItem(accountStorageKey.entryVersions(USER))).toBeNull();
  } finally { release(); await Promise.allSettled([first, second, erasing]); }
});

it.each(["forget", "rebind"] as const)("a reset retires %s completion before it reads replacement AAD bindings", async operation => {
  const { noteV2Bound, forgetEntryVersion, rebindEntryVersions } = await import("../src/entryVersions");
  await observeEntryVersions(USER, KEY, [{ clientEntryId: "retiring-entry", contentVersion: 8 }]);
  await noteV2Bound(USER, KEY, "retiring-entry");
  const remove = storage.removeItem.bind(storage), write = storage.setItem.bind(storage), read = storage.getItem.bind(storage);
  let release!: () => void, admitted!: () => void, releaseReplacement!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  const replacementGate = new Promise<void>(resolve => { releaseReplacement = resolve; });
  let held = false, replacementRead = false;
  const boundary = async (name: string) => {
    if (!held && name === accountStorageKey.entryVersions(USER)) { held = true; admitted(); await gate; }
  };
  vi.spyOn(storage, "removeItem").mockImplementation(async name => { if (operation === "forget") await boundary(name); await remove(name); });
  vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => { if (operation === "rebind") await boundary(name); await write(name, value); });
  const completing = operation === "forget" ? forgetEntryVersion(USER, KEY, "retiring-entry") : rebindEntryVersions(USER, KEY, KEY);
  let erasing: Promise<void> | undefined;
  try {
    await Promise.race([entered, completing]);
    erasing = forgetAllEntryVersions(USER);
    vi.spyOn(storage, "getItem").mockImplementation(async name => {
      if (name === accountStorageKey.entryV2Bound(USER)) { replacementRead = true; await replacementGate; }
      return read(name);
    });
    let completed = false;
    const completion = completing.then(() => { completed = true; });
    release(); await erasing; await turn();
    expect(replacementRead, "retired work read replacement account bindings").toBe(false);
    expect(completed, "retired work waited for replacement storage").toBe(true);
    await completion;
  } finally { release(); releaseReplacement(); await Promise.allSettled([completing, erasing]); }
});
