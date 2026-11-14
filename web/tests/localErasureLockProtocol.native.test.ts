/** Unexecuted public LockManager protocol draft. Exclusive request/query subset;
 * no claim of a native browser implementation or support for unused options. */
import { afterEach, beforeEach, expect, it } from "vitest";
import { kv } from "../src/kvstore";
import {
  stageLocalErasure, confirmRemoteLocalErasure, confirmLocalErasure,
  pendingLocalErasures, resumeConfirmedErasures,
} from "../src/localErasure";
import { resetTestState } from "./helpers/api";

type Info = { name: string; mode: "exclusive"; clientId: string };
type Waiting = {
  info: Info;
  run: (lock: Readonly<{ name: string; mode: "exclusive" }>) => unknown;
  yes: (value: unknown) => void;
  no: (reason: unknown) => void;
};

/** Honest FIFO same-name exclusive scheduler with actual Promise custody.
 * query() reports its real held/pending state through the standard public API.
 * Tests never inspect the queues, held map, task count or callback invocations. */
class ExclusiveLockManager {
  private held = new Map<string, Waiting>();
  private queues = new Map<string, Waiting[]>();
  private tasks: Promise<unknown> = Promise.resolve();

  private task<T>(run: () => T | PromiseLike<T>): Promise<T> {
    const result = this.tasks.then(run);
    this.tasks = result.then(() => undefined, () => undefined);
    return result;
  }

  request<T>(name: string, run: (lock: Readonly<{ name: string; mode: "exclusive" }>) => T | PromiseLike<T>): Promise<T> {
    return new Promise<T>((yes, no) => {
      const item: Waiting = {
        info: { name, mode: "exclusive", clientId: "local-erasure-protocol-context" },
        run, yes: value => yes(value as T), no,
      };
      const queue = this.queues.get(name) ?? [];
      queue.push(item);
      this.queues.set(name, queue);
      void this.task(() => { this.grant(name); });
    });
  }

  private grant(name: string): void {
    if (this.held.has(name)) return;
    const queue = this.queues.get(name);
    const item = queue?.shift();
    if (!item) return;
    this.held.set(name, item);
    const waiting = Promise.resolve().then(() => item.run(Object.freeze({ name, mode: "exclusive" as const })));
    void waiting.then(
      value => this.task(() => { this.held.delete(name); item.yes(value); this.grant(name); }),
      reason => this.task(() => { this.held.delete(name); item.no(reason); this.grant(name); }),
    );
  }

  query(): Promise<{ held: Info[]; pending: Info[] }> {
    return this.task(() => ({
      held: [...this.held.values()].map(item => ({ ...item.info })),
      pending: [...this.queues.values()].flatMap(queue => queue.map(item => ({ ...item.info }))),
    }));
  }
}

let manager: ExclusiveLockManager;
let priorLocks: PropertyDescriptor | undefined;
beforeEach(() => {
  resetTestState();
  priorLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
  manager = new ExclusiveLockManager();
  Object.defineProperty(navigator, "locks", { configurable: true, value: manager });
});
afterEach(() => {
  if (priorLocks) Object.defineProperty(navigator, "locks", priorLocks);
  else Reflect.deleteProperty(navigator, "locks");
  resetTestState();
});

async function heldPublicLock(): Promise<{ release: () => void; completion: Promise<void> }> {
  let release!: () => void;
  let granted!: () => void;
  const gate = new Promise<void>(yes => { release = yes; });
  const ready = new Promise<void>(yes => { granted = yes; });
  const completion = manager.request("account-erasure", async () => { granted(); await gate; });
  await ready; // Standard public request grant, not a producer/private admission signal.
  return { release, completion };
}

it.each(["stage", "remote", "confirm", "resume"] as const)("queues public %s cleanup behind the existing account-erasure resource", async kind => {
  const owner = "lock-protocol-owner";
  const own = "mindpattern.safetyPlan.lock-protocol-owner";
  const checkpoint = "mindpattern.erase.lock-protocol-owner";
  await kv.setItem(own, "opaque account writing");
  if (kind === "confirm" || kind === "resume") {
    await kv.setItem(checkpoint, JSON.stringify({ v: 1, owner, remoteConfirmed: kind === "resume", keys: [own] }));
  }
  const held = await heldPublicLock();
  let operation: Promise<unknown> | undefined;
  try {
    operation = kind === "stage" ? stageLocalErasure(owner)
      : kind === "remote" ? confirmRemoteLocalErasure(owner)
      : kind === "confirm" ? confirmLocalErasure(owner)
      : resumeConfirmedErasures();
    void operation.catch(() => undefined);
    // Later genuine read-only public receipt follows the initial resume enumeration
    // on the honest resolved default KV backend. No private read/call counter is tested.
    await pendingLocalErasures();
    const snapshot = await manager.query();
    // First assertion is standard public LockManagerSnapshot resource identity/mode.
    expect(snapshot.pending.map(({ name, mode }) => ({ name, mode }))).toEqual([
      { name: "account-erasure", mode: "exclusive" },
    ]);
  } finally {
    held.release();
    await Promise.allSettled([held.completion, ...(operation ? [operation] : [])]);
  }
});

it("returns an unconfirmed pending receipt without queueing behind an unrelated ongoing erasure", async () => {
  const owner = "unconfirmed-lock-owner";
  const checkpoint = { v: 1, owner, remoteConfirmed: false, keys: [] };
  await kv.setItem("mindpattern.erase.unconfirmed-lock-owner", JSON.stringify(checkpoint));
  const held = await heldPublicLock();
  let operation: ReturnType<typeof resumeConfirmedErasures> | undefined;
  try {
    operation = resumeConfirmedErasures();
    void operation.catch(() => undefined);
    await pendingLocalErasures();
    const snapshot = await manager.query();
    // First assertion is public state: no extra competing erasure request exists.
    expect(snapshot.pending).toEqual([]);
  } finally {
    held.release();
    await Promise.allSettled([held.completion, ...(operation ? [operation] : [])]);
  }
  // This returned public receipt is supplemental; no deadline/timer liveness oracle.
  expect(await operation).toEqual([checkpoint]);
});
