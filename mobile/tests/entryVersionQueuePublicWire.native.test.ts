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
import { isV2Bound, noteV2Bound, resetEntryVersionMirrors } from "../src/entryVersions";

let key: Buffer;
function openOwner(): string {
  const user = crypto.randomBytes(16).toString("hex");
  changeLocalSessionOwner(user);
  installLocalDataKey(user, key);
  return user;
}
function nativeJson(raw: string, user: string): unknown {
  const bytes = Buffer.from(raw, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["entry-v2-bound", user])));
  decipher.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
  try { return JSON.parse(plain.toString("utf8")); }
  finally { plain.fill(0); }
}
async function storedBindings(user: string): Promise<unknown> {
  const raw = await storage.getItem("mindpattern.entryV2Bound." + user);
  expect(raw).not.toBeNull();
  return nativeJson(raw!, user);
}

beforeEach(() => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
  key = Buffer.alloc(32, 59);
});
afterEach(async () => {
  await waitLocalWriteCommits();
  vi.restoreAllMocks();
  runTestControl(resetEntryVersionMirrors);
  runTestControl(__resetLocalKeyLifecycleForTests);
  key.fill(0);
});

// All arguments are independent literal IDs supplied by the cases below.
// Gates delay real native sets BEFORE forwarding. No getItem is intercepted.
async function twoBindings(user: string, firstId: string, secondId: string): Promise<unknown> {
  const slot = "mindpattern.entryV2Bound." + user;
  const nativeWrite = storage.setItem.bind(storage);
  let release!: () => void, admitted!: () => void, held = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { admitted = resolve; });
  const write = vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => {
    if (name === slot && !held) { held = true; admitted(); await gate; }
    await nativeWrite(name, value);
  });
  const operations: Promise<void>[] = [];
  const track = (operation: Promise<void>) => {
    operations.push(operation);
    void operation.catch(() => {}); // Observe rejection immediately; original CALL is preserved.
    return operation;
  };
  try {
    const first = track(noteV2Bound(user, key, firstId));
    // An early public completion releases this schedule too; no gate flag is an oracle.
    await Promise.race([entered, first]);
    track(noteV2Bound(user, key, secondId));
    expect(await isV2Bound(user, key, secondId)).toBe(true);
    release();
    await Promise.all(operations);
    await waitLocalWriteCommits(user);
    return await storedBindings(user);
  } finally {
    release();
    await Promise.allSettled(operations);
    await waitLocalWriteCommits(user);
    write.mockRestore();
  }
}

async function threeBindings(user: string, firstId: string, secondId: string, thirdId: string): Promise<unknown> {
  const slot = "mindpattern.entryV2Bound." + user;
  const nativeWrite = storage.setItem.bind(storage);
  let releaseFirst!: () => void, admittedFirst!: () => void;
  let releaseSecond!: () => void, admittedSecond!: () => void;
  const firstGate = new Promise<void>(resolve => { releaseFirst = resolve; });
  const firstEntered = new Promise<void>(resolve => { admittedFirst = resolve; });
  const secondGate = new Promise<void>(resolve => { releaseSecond = resolve; });
  const secondEntered = new Promise<void>(resolve => { admittedSecond = resolve; });
  let heldFirst = false, heldSecond = false;
  const write = vi.spyOn(storage, "setItem").mockImplementation(async (name, value) => {
    if (name === slot && !heldFirst) {
      heldFirst = true; admittedFirst(); await firstGate;
    } else if (name === slot && !heldSecond) {
      heldSecond = true; admittedSecond(); await secondGate;
    }
    await nativeWrite(name, value);
  });
  const operations: Promise<void>[] = [];
  const track = (operation: Promise<void>) => {
    operations.push(operation);
    void operation.catch(() => {});
    return operation;
  };
  try {
    const first = track(noteV2Bound(user, key, firstId));
    await Promise.race([firstEntered, first]);
    const second = track(noteV2Bound(user, key, secondId));
    expect(await isV2Bound(user, key, secondId)).toBe(true);
    releaseFirst();
    await first;
    await Promise.race([secondEntered, second]);
    track(noteV2Bound(user, key, thirdId));
    expect(await isV2Bound(user, key, thirdId)).toBe(true);
    releaseSecond();
    await Promise.all(operations);
    await waitLocalWriteCommits(user);
    return await storedBindings(user);
  } finally {
    releaseFirst(); releaseSecond();
    await Promise.allSettled(operations);
    await waitLocalWriteCommits(user);
    write.mockRestore();
  }
}

it("completed overlapping bindings retain both identifiers in authenticated storage", async () => {
  const user = openOwner();
  const actual = await twoBindings(user, "overlap-first", "overlap-second");
  expect(actual).toEqual(["overlap-first", "overlap-second"]);
});

it("a third binding remains durable when a prior write completes ahead of the pending write", async () => {
  const user = openOwner();
  const actual = await threeBindings(user, "chain-first", "chain-second", "chain-third");
  expect(actual).toEqual(["chain-first", "chain-second", "chain-third"]);
});

it("an existing authenticated binding and three overlapping additions all remain durable", async () => {
  const user = openOwner();
  await noteV2Bound(user, key, "already-durable");
  expect(await storedBindings(user)).toEqual(["already-durable"]);
  const actual = await threeBindings(user, "warm-first", "warm-second", "warm-third");
  expect(actual).toEqual(["already-durable", "warm-first", "warm-second", "warm-third"]);
});
