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
  knownEntryVersion,
  noteV2Bound,
  observeEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";

const KEY = Buffer.alloc(32, 23);

// A fresh native identifier keeps every invocation independent of previous
// completed resets, including a runner that reuses its module instance.
function openOwner(): string {
  const user = crypto.randomBytes(16).toString("hex");
  changeLocalSessionOwner(user);
  installLocalDataKey(user, KEY);
  return user;
}

// Independent decoder for the persisted nonce12/ciphertext/tag16 wire format.
// The expected JSON and AAD contexts below are literal account-store contracts.
function nativeJson(raw: string, context: string, user: string): unknown {
  const bytes = Buffer.from(raw, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", KEY, bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify([context, user])));
  decipher.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
  try { return JSON.parse(plain.toString("utf8")); }
  finally { plain.fill(0); }
}

beforeEach(() => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
});

afterEach(async () => {
  await waitLocalWriteCommits();
  vi.restoreAllMocks();
  runTestControl(resetEntryVersionMirrors);
});

it("a completed entry reset permits a new observation and remembers its version", async () => {
  const user = openOwner(), entry = "fresh-after-completed-reset";
  expect(await observeEntryVersions(user, KEY, [{ clientEntryId: entry, contentVersion: 5 }]))
    .toEqual({ rolledBack: [], advanced: true });
  expect(await knownEntryVersion(user, KEY, entry)).toBe(5);

  await forgetAllEntryVersions(user);

  expect(await observeEntryVersions(user, KEY, [{ clientEntryId: entry, contentVersion: 9 }]))
    .toEqual({ rolledBack: [], advanced: true });
  expect(await knownEntryVersion(user, KEY, entry)).toBe(9);
  const raw = await storage.getItem("mindpattern.entryVersions." + user);
  expect(raw).not.toBeNull();
  expect(nativeJson(raw!, "entry-versions", user)).toEqual({ [entry]: 9 });
});

it("lookups begun during an admitted erasure reflect the completed reset", async () => {
  const user = openOwner(), entry = "erased-version-and-binding";
  const versionsSlot = "mindpattern.entryVersions." + user;
  const bindingSlot = "mindpattern.entryV2Bound." + user;
  expect(await observeEntryVersions(user, KEY, [{ clientEntryId: entry, contentVersion: 8 }]))
    .toEqual({ rolledBack: [], advanced: true });
  await noteV2Bound(user, KEY, entry);
  expect(await knownEntryVersion(user, KEY, entry)).toBe(8);
  expect(await isV2Bound(user, KEY, entry)).toBe(true);
  expect(nativeJson((await storage.getItem(versionsSlot))!, "entry-versions", user)).toEqual({ [entry]: 8 });
  expect(nativeJson((await storage.getItem(bindingSlot))!, "entry-v2-bound", user)).toEqual([entry]);

  const nativeRemove = storage.removeItem.bind(storage);
  let release!: () => void, acquired!: () => void, held = false;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const admitted = new Promise<void>(resolve => { acquired = resolve; });
  const remove = vi.spyOn(storage, "removeItem").mockImplementation(async name => {
    if (name === versionsSlot && !held) { held = true; acquired(); await gate; }
    await nativeRemove(name);
  });
  let erasing: Promise<void> | undefined;
  let known: Promise<number | null> | undefined, bound: Promise<boolean> | undefined;
  try {
    erasing = forgetAllEntryVersions(user);
    // This promise schedules the honest native latency; it is never an oracle.
    await admitted;
    known = knownEntryVersion(user, KEY, entry);
    bound = isV2Bound(user, KEY, entry);
    // getItem snapshots its native Map value at invocation. Release in this
    // same stack, without a timer, turn-count probe or completion-flag assertion.
    release();
    const [knownAfter, boundAfter] = await Promise.all([known, bound]);
    await erasing;
    await waitLocalWriteCommits(user);
    expect(knownAfter).toBeNull();
    expect(boundAfter).toBe(false);
    expect(await storage.getItem(versionsSlot)).toBeNull();
    expect(await storage.getItem(bindingSlot)).toBeNull();
  } finally {
    release();
    await Promise.allSettled([erasing, known, bound]);
    await waitLocalWriteCommits(user);
    remove.mockRestore();
  }
});
