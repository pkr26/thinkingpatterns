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
  resetEntryVersionMirrors,
} from "../src/entryVersions";

let key: Buffer;
type SettledCall = { status: "fulfilled"; value: void } | { status: "rejected"; reason: unknown };

beforeEach(() => {
  vi.restoreAllMocks();
  storage.__reset();
  runTestControl(__resetLocalKeyLifecycleForTests);
  runTestControl(resetEntryVersionMirrors);
  key = Buffer.alloc(32, 61);
});
afterEach(async () => {
  await waitLocalWriteCommits();
  vi.restoreAllMocks();
  runTestControl(resetEntryVersionMirrors);
  runTestControl(__resetLocalKeyLifecycleForTests);
  key.fill(0);
});

// An ordinary provider latency holds the first write before the actual native
// set. The queued second public binding is positively visible in the process
// before retirement; its eventual CALL status is observed only after all gates
// are released. There is no private queue/count or time-based completion oracle.
async function retireQueuedBinding(resetEntries: boolean): Promise<SettledCall> {
  const user = crypto.randomBytes(16).toString("hex");
  changeLocalSessionOwner(user);
  installLocalDataKey(user, key);
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
    void operation.catch(() => {});
    return operation;
  };
  let erasing: Promise<void> | undefined;
  try {
    const first = track(noteV2Bound(user, key, "admitted-before-retirement"));
    // Also proceed if a changed public implementation finishes without issuing
    // a native write. The gate observation is never asserted as correctness.
    await Promise.race([entered, first]);
    const second = track(noteV2Bound(user, key, "queued-before-retirement"));
    const secondOutcome: Promise<SettledCall> = second.then<SettledCall, SettledCall>(
      value => ({ status: "fulfilled", value }),
      reason => ({ status: "rejected", reason }),
    );
    expect(await isV2Bound(user, key, "queued-before-retirement")).toBe(true);

    changeLocalSessionOwner(null);
    // Administrative entry erasure is admitted under the new current scope.
    // Without this reset, the original queued continuation must reject its
    // retired permit instead of acknowledging a generation-retired no-op.
    if (resetEntries) erasing = track(forgetAllEntryVersions(user));
    release();
    await first;
    await erasing;
    const outcome = await secondOutcome;
    await waitLocalWriteCommits(user);
    return outcome;
  } finally {
    release();
    await Promise.allSettled(operations);
    await waitLocalWriteCommits(user);
    write.mockRestore();
  }
}

it("a reset-retired queued binding acknowledges the completed erasure", async () => {
  const outcome = await retireQueuedBinding(true);
  expect(outcome).toEqual({ status: "fulfilled", value: undefined });
});

it("an owner-retired queued binding rejects when no entry reset retired its continuation", async () => {
  const outcome = await retireQueuedBinding(false);
  expect(outcome.status).toBe("rejected");
});
