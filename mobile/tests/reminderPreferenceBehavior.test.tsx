import React from "react";
import TestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it } from "vitest";
import { runTestControl } from "./helpers/testControl";
import { vault } from "../src/vault";
import { __resetLocalKeyLifecycleForTests, changeLocalSessionOwner, waitLocalWriteCommits } from "../src/localWriteGuard";
import { commitReminderPreferenceWrite, useReminderPreferenceIntent } from "../src/reminderPreferences";
const user = "11111111111111111111111111111111", other = "22222222222222222222222222222222";
let root: TestRenderer.ReactTestRenderer | undefined, begin!: ReturnType<typeof useReminderPreferenceIntent>;
(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const deferred = () => { let resolve!: () => void; const promise = new Promise<void>(done => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
function unlock(owner = user) { vault.unlock({ masterKey: Buffer.alloc(32, 1), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 3) }, owner); }
async function mount() { function Consumer() { begin = useReminderPreferenceIntent(); return null; } await act(async () => { root = TestRenderer.create(<Consumer />); }); }
beforeEach(() => { runTestControl(__resetLocalKeyLifecycleForTests); vault.lock(); changeLocalSessionOwner(user); });
afterEach(async () => { await act(async () => { root?.unmount(); }); root = undefined; vault.lock(); });

it("keeps only the latest intent for each independent reminder control", async () => {
  unlock(); await mount(); const first = begin("daily-enabled")!, measure = begin("measure-enabled")!;
  expect(first.owner).toBe(user); expect(first.current()).toBe(true); expect(measure.current()).toBe(true);
  const replacement = begin("daily-enabled")!; expect(first.current()).toBe(false); expect(replacement.current()).toBe(true); expect(measure.current()).toBe(true);
});
it("retires the reader's retained intent and its callback after unmount", async () => {
  unlock(); await mount(); const intent = begin("daily-enabled")!; await act(async () => { root!.unmount(); }); root = undefined;
  expect(intent.current()).toBe(false); expect(begin("daily-enabled")).toBeNull();
});
it("does not admit an intent without a known account and refuses another owner", async () => {
  await mount(); expect(begin("daily-enabled")).toBeNull(); expect(begin("daily-enabled", other)).toBeNull();
});
it("admits non-sensitive onboarding preferences for an explicit authenticated owner while the vault is locked", async () => {
  await mount(); const intent = begin("daily-enabled", user)!; expect(intent.owner).toBe(user); expect(intent.current()).toBe(true);
  changeLocalSessionOwner(other); expect(intent.current()).toBe(false);
});
it.each(["lock", "different-account", "same-account-new-key"] as const)("retires an unlocked reminder intent after %s", async transition => {
  unlock(); await mount(); const intent = begin("daily-enabled")!;
  if (transition === "lock") vault.lock(); else unlock(transition === "different-account" ? other : user);
  expect(intent.current()).toBe(false);
});
it("retires a same-account intent when the authenticated scope changes", async () => {
  unlock(); await mount(); const intent = begin("daily-enabled")!; changeLocalSessionOwner(user); expect(intent.current()).toBe(false);
});
it("refuses a replacement vault owner even when an unlock caller reuses the held key buffer", async () => {
  unlock(); await mount(); const intent = begin("daily-enabled")!, held = vault.get().dataKey;
  vault.unlock({ masterKey: Buffer.alloc(32, 4), authKey: Buffer.alloc(32, 5), dataKey: held }, other);
  expect(intent.current()).toBe(false);
});
it("retries a serialized preference operation after a previous native failure", async () => {
  const failure = new Error("Preference write rejected");
  await expect(commitReminderPreferenceWrite(user, async () => { throw failure; })).rejects.toBe(failure);
  let wrote = false; await commitReminderPreferenceWrite(user, async () => { wrote = true; }); expect(wrote).toBe(true);
});
it("does not let queued preference work adopt a replacement account", async () => {
  const gate = deferred(), entered = deferred();
  const first = commitReminderPreferenceWrite(user, async () => { entered.resolve(); await gate.promise; }), firstResult = first.catch(error => error);
  await Promise.race([entered.promise, firstResult.then(() => { throw new Error("Preference write skipped its run callback"); })]);
  let wrote = false; const queued = commitReminderPreferenceWrite(user, async () => { wrote = true; }).catch(error => error);
  changeLocalSessionOwner(other); gate.resolve(); expect(await firstResult).toBeInstanceOf(Error); expect(await queued).toBeInstanceOf(Error); expect(wrote).toBe(false);
});
it("registers queued preference work in the physical administrative drain immediately", async () => {
  const gate = deferred(), entered = deferred(), first = commitReminderPreferenceWrite(user, async () => { entered.resolve(); await gate.promise; });
  await Promise.race([entered.promise, first.then(() => { throw new Error("Preference write skipped its run callback"); })]);
  const queued = commitReminderPreferenceWrite(user, async () => { await turn(); });
  let drained = false; const drain = waitLocalWriteCommits(user).then(() => { drained = true; }); await turn(); expect(drained).toBe(false);
  gate.resolve(); await first; await queued; await drain; expect(drained).toBe(true);
});
