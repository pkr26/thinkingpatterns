import { beforeEach, expect, it } from "vitest";
import { runTestControl } from "./helpers/testControl";
import { __resetLocalKeyLifecycleForTests, advanceLocalWriteScope, assertLocalTransitionScope, assertLocalWritePermit, captureLocalWritePermit, captureOpaqueLocalWritePermit, changeLocalOrigin, changeLocalSessionOwner, clearLocalKeyState, commitActiveAccountWrite, commitLocalErasureWrite, commitLocalTransitionWrite, commitLocalWrite, commitOriginErasureWrite, freezeLocalKeyWrites, hydrateLocalSessionOwner, installLocalDataKey, localKeyGeneration, localWriteScopeEpoch, markAccountDeleted, waitLocalWriteCommits } from "../src/localWriteGuard";
const user = "11111111111111111111111111111111", other = "22222222222222222222222222222222", key = Buffer.alloc(32, 5), nextKey = Buffer.alloc(32, 6);
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
beforeEach(() => { runTestControl(__resetLocalKeyLifecycleForTests); });

it("hydrates a newly authenticated owner and preserves permits on a repeat read of the same owner", async () => {
  const before = captureLocalWritePermit(user, key); hydrateLocalSessionOwner(user);
  expect(() => assertLocalWritePermit(before)).toThrow("retired");
  const current = captureLocalWritePermit(user, key); hydrateLocalSessionOwner(user);
  await expect(commitLocalWrite(current, async () => "same-owner commit")).resolves.toBe("same-owner commit");
  hydrateLocalSessionOwner(other); expect(() => captureLocalWritePermit(user, key)).toThrow("account/session changed");
  expect(() => captureLocalWritePermit(other, key)).not.toThrow();
});

it("retires a captured write when the public scope advances", () => {
  const permit = captureLocalWritePermit(user, key); advanceLocalWriteScope(); expect(() => assertLocalWritePermit(permit)).toThrow("retired");
});

it("never revives a retained permit when an owner replacement is followed by another scope advance", () => {
  changeLocalSessionOwner(user); const permit = captureLocalWritePermit(user, key);
  changeLocalSessionOwner(user); advanceLocalWriteScope(); expect(() => assertLocalWritePermit(permit)).toThrow("retired");
});

it("never revives a retained permit when cold-start hydration and a fresh owner publication alternate", () => {
  changeLocalSessionOwner(user); const permit = captureLocalWritePermit(user, key);
  hydrateLocalSessionOwner(other); changeLocalSessionOwner(user); expect(() => assertLocalWritePermit(permit)).toThrow("retired");
});

it.each([0, 31, 33])("refuses a %s-byte producer key before issuing an opaque write permit", size => {
  expect(() => captureLocalWritePermit(user, Buffer.alloc(size))).toThrow("Invalid local data key");
});

it("checks both the account and key ownership of an opaque ciphertext producer", () => {
  const keyed = captureLocalWritePermit(user, key), otherOwner = captureLocalWritePermit(other, key), unkeyed = captureLocalWritePermit(user);
  expect(captureOpaqueLocalWritePermit(user, keyed)).toBe(keyed);
  expect(() => captureOpaqueLocalWritePermit(user, otherOwner)).toThrow("Invalid ciphertext producer ownership");
  expect(() => captureOpaqueLocalWritePermit(user, unkeyed)).toThrow("Invalid ciphertext producer ownership");
  changeLocalSessionOwner(user); expect(() => captureOpaqueLocalWritePermit(user, keyed)).toThrow("retired");
});

it("requires a producer permit once a verified key has been installed", () => {
  installLocalDataKey(user, key);
  expect(() => captureOpaqueLocalWritePermit(user)).toThrow("key-bound ciphertext producer permit");
  expect(() => captureOpaqueLocalWritePermit(user, captureLocalWritePermit(user, key))).not.toThrow();
});

it("permits an authenticated legacy producer before any verified key binding has been installed", async () => {
  changeLocalSessionOwner(user); const permit = captureOpaqueLocalWritePermit(user);
  await expect(commitLocalWrite(permit, async () => "legacy ciphertext commit")).resolves.toBe("legacy ciphertext commit");
});

it("rejects old-key and unkeyed callbacks after a different verified key is installed", () => {
  installLocalDataKey(user, key); const keyed = captureLocalWritePermit(user, key), unkeyed = captureLocalWritePermit(user);
  installLocalDataKey(user, nextKey);
  expect(() => assertLocalWritePermit(keyed)).toThrow("retired"); expect(() => assertLocalWritePermit(unkeyed)).toThrow("retired");
  expect(() => captureLocalWritePermit(user, key)).toThrow("generation changed"); expect(() => captureLocalWritePermit(user, nextKey)).not.toThrow();
});

it("keeps a verified same-key installation idempotent while a freeze permanently retires earlier callbacks", () => {
  installLocalDataKey(user, key); const permit = captureLocalWritePermit(user, key);
  installLocalDataKey(user, Buffer.from(key)); expect(() => assertLocalWritePermit(permit)).not.toThrow();
  freezeLocalKeyWrites(user); expect(() => captureLocalWritePermit(user, key)).toThrow("paused");
  installLocalDataKey(user, key); expect(() => assertLocalWritePermit(permit)).toThrow("retired");
  expect(() => captureLocalWritePermit(user, key)).not.toThrow();
});

it("keeps an old-origin verified key retired after the same account authenticates again", () => {
  installLocalDataKey(user, key); const permit = captureLocalWritePermit(user, key);
  changeLocalOrigin(); changeLocalSessionOwner(user);
  expect(() => assertLocalWritePermit(permit)).toThrow("retired"); expect(() => captureLocalWritePermit(user, key)).toThrow("generation changed");
  installLocalDataKey(user, key); expect(() => captureLocalWritePermit(user, key)).not.toThrow();
});

it("retires an in-flight transition when an old-origin key is verified in the new origin", () => {
  installLocalDataKey(user, key); changeLocalOrigin(); changeLocalSessionOwner(user); freezeLocalKeyWrites(user);
  const epoch = localWriteScopeEpoch(), generation = localKeyGeneration(user); installLocalDataKey(user, key);
  expect(() => assertLocalTransitionScope(user, epoch, generation)).toThrow("retired generation");
});

it("clears key bindings and a freeze while keeping previously captured callbacks retired", () => {
  installLocalDataKey(user, key); const permit = captureLocalWritePermit(user);
  freezeLocalKeyWrites(user); clearLocalKeyState(user);
  expect(() => captureLocalWritePermit(user, nextKey)).not.toThrow(); expect(() => assertLocalWritePermit(permit)).toThrow("retired");
});

it("clears a key generation even when there was no freeze", () => {
  const permit = captureLocalWritePermit(user); clearLocalKeyState(user); expect(() => assertLocalWritePermit(permit)).toThrow("retired");
});

it("does not revive a deleted owner when a key is cleared or installed", () => {
  markAccountDeleted(user); clearLocalKeyState(user);
  expect(() => captureLocalWritePermit(user, key)).toThrow("deleted"); expect(() => freezeLocalKeyWrites(user)).toThrow("deleted");
  expect(() => installLocalDataKey(user, key)).toThrow("deleted");
});

it("checks transition owner, epoch, and generation before invoking a native checkpoint write", () => {
  changeLocalSessionOwner(user); const epoch = localWriteScopeEpoch(), generation = localKeyGeneration(user); let wrote = false;
  expect(() => assertLocalTransitionScope(other, epoch)).toThrow("account/server");
  freezeLocalKeyWrites(user); expect(() => assertLocalTransitionScope(user, epoch, generation)).toThrow("retired generation");
  expect(() => commitLocalTransitionWrite(user, epoch, async () => { wrote = true; }, generation)).toThrow("retired generation"); expect(wrote).toBe(false);
  changeLocalSessionOwner(null); expect(() => assertLocalTransitionScope(user, localWriteScopeEpoch())).toThrow("account/server");
  changeLocalSessionOwner(user); expect(() => assertLocalTransitionScope(user, epoch)).toThrow("account/server");
});

it("runs a current account metadata write and rejects a retired owner before native admission", async () => {
  changeLocalSessionOwner(user); await expect(commitActiveAccountWrite(user, async () => "metadata")).resolves.toBe("metadata");
  changeLocalSessionOwner(other); let wrote = false;
  expect(() => commitActiveAccountWrite(user, async () => { wrote = true; })).toThrow("account/session"); expect(wrote).toBe(false);
});

it.each(["account", "origin"] as const)("allows %s erasure for tombstones but rejects a retired epoch before native deletion", async kind => {
  const epoch = localWriteScopeEpoch(); markAccountDeleted(user);
  const commit = (write: () => Promise<string>) => kind === "account" ? commitLocalErasureWrite(user, epoch, write) : commitOriginErasureWrite(epoch, write);
  await expect(commit(async () => "deleted native records")).resolves.toBe("deleted native records");
  changeLocalSessionOwner(other); let wrote = false;
  expect(() => commit(async () => { wrote = true; return "stale deletion"; })).toThrow("changed during"); expect(wrote).toBe(false);
});

it("drains all owner and unattributable origin commits before reporting administrative completion", async () => {
  const ownerGate = deferred(), otherGate = deferred(), originGate = deferred(), epoch = localWriteScopeEpoch();
  const first = commitLocalWrite(captureLocalWritePermit(user, key), () => ownerGate.promise);
  const second = commitLocalWrite(captureLocalWritePermit(other, key), () => otherGate.promise);
  const third = commitOriginErasureWrite(epoch, () => originGate.promise);
  let drained = false; const drain = waitLocalWriteCommits().then(() => { drained = true; });
  await turn(); expect(drained).toBe(false); ownerGate.resolve(); await first; await turn(); expect(drained).toBe(false);
  otherGate.resolve(); await second; await turn(); expect(drained).toBe(false); originGate.resolve(); await third; await drain; expect(drained).toBe(true);
});

it("an account-specific drain does not wait for another owner's held native commit", async () => {
  const gate = deferred(), commit = commitLocalWrite(captureLocalWritePermit(other, key), () => gate.promise);
  let drained = false; const drain = waitLocalWriteCommits(user).then(() => { drained = true; });
  await turn(); expect(drained).toBe(true); gate.resolve(); await commit; await drain;
});

it("keeps second and newly admitted third writes tracked after the first write settles", async () => {
  const gates = [deferred(), deferred(), deferred()], permit = captureLocalWritePermit(user, key);
  const first = commitLocalWrite(permit, () => gates[0]!.promise), second = commitLocalWrite(permit, () => gates[1]!.promise);
  gates[0]!.resolve(); await first;
  const third = commitLocalWrite(permit, () => gates[2]!.promise);
  let drained = false; const drain = waitLocalWriteCommits(user).then(() => { drained = true; });
  await turn(); expect(drained).toBe(false); gates[1]!.resolve(); await second; await turn(); expect(drained).toBe(false);
  gates[2]!.resolve(); await third; await drain;
});

it("a failed native write is surfaced while allowing the remaining administrative drain to finish", async () => {
  const error = new Error("Native commit rejected"), permit = captureLocalWritePermit(user, key);
  await expect(commitLocalWrite(permit, async () => { throw error; })).rejects.toBe(error);
  await expect(waitLocalWriteCommits(user)).resolves.toBeUndefined();
});
