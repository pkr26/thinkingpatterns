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
  forgetEntryVersion,
  isV2Bound,
  noteV2Bound,
  observeEntryVersions,
  rebindEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";

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

// Independent AES-GCM wire readers/writers use the native provider directly.
// The account slot, AAD context, nonce12/tag16 framing, and JSON are contracts;
// no application crypto or key factory computes the expected observations.
function nativeJson(raw: string, key: Buffer, user: string): unknown {
  const bytes = Buffer.from(raw, "base64");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["entry-v2-bound", user])));
  decipher.setAuthTag(bytes.subarray(-16));
  const plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
  try { return JSON.parse(plain.toString("utf8")); }
  finally { plain.fill(0); }
}
function nativeSeal(value: unknown, key: Buffer, user: string): string {
  const plain = Buffer.from(JSON.stringify(value), "utf8");
  try {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify(["entry-v2-bound", user])));
    const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
    return Buffer.concat([nonce, ciphertext, cipher.getAuthTag()]).toString("base64");
  } finally { plain.fill(0); }
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

it("forgetting a completed entry removes its public required-v2 binding", async () => {
  const key = ownedKey(37), user = openOwner(key), entry = "deleted-bound-entry";
  expect(await observeEntryVersions(user, key, [{ clientEntryId: entry, contentVersion: 8 }]))
    .toEqual({ rolledBack: [], advanced: true });
  await noteV2Bound(user, key, entry);
  expect(await isV2Bound(user, key, entry)).toBe(true);

  await forgetEntryVersion(user, key, entry);

  expect(await isV2Bound(user, key, entry)).toBe(false);
});

it("a real entry rebind authenticates its registered binding ciphertext with the new key", async () => {
  const oldKey = ownedKey(41), newKey = ownedKey(43);
  const user = openOwner(oldKey), entry = "retained-bound-entry";
  const slot = "mindpattern.entryV2Bound." + user;
  expect(await observeEntryVersions(user, oldKey, [{ clientEntryId: entry, contentVersion: 6 }]))
    .toEqual({ rolledBack: [], advanced: true });
  await noteV2Bound(user, oldKey, entry);
  const before = await storage.getItem(slot);
  expect(before).not.toBeNull();
  expect(nativeJson(before!, oldKey, user)).toEqual([entry]);

  installLocalDataKey(user, newKey);
  await rebindEntryVersions(user, oldKey, newKey);

  const rebound = await storage.getItem(slot);
  expect(rebound).not.toBeNull();
  expect(nativeJson(rebound!, newKey, user)).toEqual([entry]);
});

it("rewriting authenticated mixed binding records persists only string entry identifiers", async () => {
  const key = ownedKey(47), user = openOwner(key);
  const slot = "mindpattern.entryV2Bound." + user;
  // The loader deliberately treats authenticated JSON as unknown and filters
  // individual identifiers. This fixture contains valid and invalid members.
  await storage.setItem(slot, nativeSeal([7, "kept"], key, user));
  expect(nativeJson((await storage.getItem(slot))!, key, user)).toEqual([7, "kept"]);

  await noteV2Bound(user, key, "new");

  const rewritten = await storage.getItem(slot);
  expect(rewritten).not.toBeNull();
  expect(nativeJson(rewritten!, key, user)).toEqual(["kept", "new"]);
});
