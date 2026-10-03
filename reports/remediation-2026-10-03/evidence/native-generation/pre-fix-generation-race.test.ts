import { beforeEach, expect, it, vi } from "/Users/pradeepreddy/Desktop/mental_health_application/mobile/node_modules/vitest/dist/index.js";
import storage from "/Users/pradeepreddy/Desktop/mental_health_application/mobile/tests/helpers/storageMock";
import { setSecureStoreBackend } from "/Users/pradeepreddy/Desktop/mental_health_application/mobile/src/secureStore";
import { prepareLocalRekey, resumeLocalRekey, pendingLocalRekey, markLocalRekeyPhase, __resetLocalKeyLifecycleForTests } from "/Users/pradeepreddy/Desktop/mental_health_application/mobile/src/localRekey";
import { recordMood } from "/Users/pradeepreddy/Desktop/mental_health_application/mobile/src/moodLog";
import { buildAad, decrypt } from "/Users/pradeepreddy/Desktop/mental_health_application/mobile/src/crypto/envelope";
const user = "generation-race-scratch", oldKey = Buffer.alloc(32, 5), newKey = Buffer.alloc(32, 9);
const slot = `mindpattern.moodlog.${user}`;
const open = (key: Buffer, raw: string) => JSON.parse(decrypt(key, Buffer.from(raw, "base64"), buildAad("moodlog", user)).toString());
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); setSecureStoreBackend(null); __resetLocalKeyLifecycleForTests(); });
it("old mood read resumed after complete rotation overwrites new generation", async () => {
  await recordMood(oldKey, user, "2026-10-01", 0.2);
  const original = storage.getItem;
  let release!: () => void, entered!: () => void, pause = true;
  const gate = new Promise<void>(r => { release = r; });
  const started = new Promise<void>(r => { entered = r; });
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const snapshot = await original(key);
    if (key === slot && pause) { pause = false; entered(); await gate; }
    return snapshot;
  });
  const oldCallerKey = Buffer.from(oldKey);
  const delayedWrite = recordMood(oldCallerKey, user, "2026-10-02", 0.7);
  oldCallerKey.fill(0); // vault lock does not wipe recordMood's private snapshot
  await started;
  await prepareLocalRekey(user, oldKey, newKey);
  await markLocalRekeyPhase(user, "credential");
  await resumeLocalRekey(user, newKey);
  expect(await pendingLocalRekey(user)).toBe(false);
  expect(open(newKey, (await original(slot))!)).toEqual([{ date: "2026-10-01", value: 0.2 }]);
  release(); await delayedWrite;
  const replaced = (await original(slot))!;
  expect(() => open(newKey, replaced)).toThrow();
  expect(open(oldKey, replaced)).toEqual([{ date: "2026-10-01", value: 0.2 }, { date: "2026-10-02", value: 0.7 }]);
});
it("queued old-key mood callbacks survive native-FIFO storage ordering and rotation", async () => {
  await recordMood(oldKey, user, "2026-10-01", 0.2);
  let nativeQueue: Promise<unknown> = Promise.resolve();
  const ordered = <T>(task: () => Promise<T>): Promise<T> => {
    const work = nativeQueue.then(async () => { await new Promise<void>(r => setImmediate(r)); return task(); });
    nativeQueue = work.catch(() => {}); return work;
  };
  for (const method of ["getItem", "setItem", "getAllKeys", "multiRemove"] as const) {
    const original = storage[method].bind(storage) as (...args: any[]) => Promise<any>;
    vi.spyOn(storage, method).mockImplementation((...args: any[]) => ordered(() => original(...args)) as any);
  }
  const pending = Array.from({ length: 200 }, (_, i) => recordMood(oldKey, user, "2026-10-02", i / 200).catch(e => e));
  await new Promise<void>(r => setImmediate(r));
  await prepareLocalRekey(user, oldKey, newKey);
  await markLocalRekeyPhase(user, "credential");
  await resumeLocalRekey(user, newKey);
  const outcomes = await Promise.all(pending);
  const replaced = (await storage.getItem(slot))!;
  expect(outcomes.some(x => x instanceof Error)).toBe(true); // callbacks during freeze are refused
  expect(() => open(newKey, replaced)).toThrow(); // later callbacks are incorrectly admitted
  expect(open(oldKey, replaced).at(-1)).toEqual({ date: "2026-10-02", value: 199 / 200 });
});
