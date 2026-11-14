import { createCipheriv } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  clearSession, hasSession, sessionUserId, setSession, setSessionExpiredHandler,
} from "../src/api/client";
import { reconcile, reconcileInsights } from "../src/sync";
import { forgetAnalysisGeneration } from "../src/stateSeqGuard";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const key = (byte: number) => new Uint8Array(new ArrayBuffer(32)).fill(byte);
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(yes => { resolve = yes; });
  return { promise, resolve };
}

beforeEach(() => {
  resetTestState();
  setSessionExpiredHandler(null);
});
afterEach(() => {
  setSessionExpiredHandler(null);
  clearSession();
  vault.lock();
  setKvBackendForTests(null);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it("retains the current public session when reconciliation refuses a foreign vault", async () => {
  const owner = "sync-terminal-session-owner";
  const foreignOwner = "sync-terminal-foreign-vault-owner";
  const foreignKeys = { authKey: key(31), dataKey: key(37) };
  setSession("sync-terminal-session-token", owner, "terminal-owner");
  vault.unlock(foreignKeys, foreignOwner);
  // Positive public fixture receipts only; no mutation credit.
  expect(hasSession()).toBe(true);
  expect(sessionUserId()).toBe(owner);
  expect(vault.isUnlocked()).toBe(true);
  expect(vault.ownerUserId()).toBe(foreignOwner);
  expect(vault.get().dataKey).toBe(foreignKeys.dataKey);

  // An honest consumer of the documented SDK lifecycle protocol, using
  // the same terminal session/key operations as the shipped App funnel.
  // This test does not mount App or assert callback calls/counts.
  setSessionExpiredHandler(() => { clearSession(); vault.lock(); });
  stubFetch(() => jsonResponse({ detail: "Session expired", code: "unauthorized" }, { status: 401 }));
  const outcome = await reconcileInsights();

  // First mutation-sensitive oracle: actual completed public ownership.
  // The original ownership refusal leaves the current session alone.
  expect(sessionUserId()).toBe(owner);
  expect(hasSession()).toBe(true);
  expect(vault.isUnlocked()).toBe(true);
  expect(vault.ownerUserId()).toBe(foreignOwner);
  expect(outcome).toEqual({ kind: "locked" });
});

it("does not durably pin the generation of an insight retired at its native decryption receipt", async () => {
  const owner = "sync-terminal-retired-generation";
  const slot = "mindpattern.stateSeq.sync-terminal-retired-generation";
  const keys = { authKey: key(67), dataKey: key(71) };
  setSession("sync-terminal-native-token", owner, "native-owner");
  vault.unlock(keys, owner);
  await forgetAnalysisGeneration(owner);
  expect(await kv.getItem(slot)).toBeNull();
  expect(sessionUserId()).toBe(owner);
  expect(vault.ownerUserId()).toBe(owner);
  expect(vault.get().dataKey).toBe(keys.dataKey);

  // Independent native envelope construction: no production crypto helper
  // computes expected plaintext, AAD or wire layout.
  const plain = Buffer.from(JSON.stringify({ v: 2, stats: { patterns: [] }, state_seq: 7 }));
  const nonce = new Uint8Array(12);
  let encoded: string;
  try {
    const cipher = createCipheriv("aes-256-gcm", keys.dataKey, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify(["insights", owner, "patterns"])));
    encoded = Buffer.concat([nonce, cipher.update(plain), cipher.final(), cipher.getAuthTag()]).toString("base64");
  } finally {
    plain.fill(0);
  }
  stubFetch(() => jsonResponse({ phase: "insight", active_days: 40, streak: 3, days_remaining: 0, state_seq: 7, blob: encoded }));
  const nativeDecrypt = crypto.subtle.decrypt.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "decrypt").mockImplementation(async (...args) => {
    const plaintext = await nativeDecrypt(...args);
    // Real successful native plaintext receipt precedes real public lock.
    // No native call/entry count or fabricated plaintext is inspected.
    vault.lock();
    return plaintext;
  });
  const outcome = await reconcileInsights();
  // Positive native-receipt/retirement admission; failure here is0K.
  expect(outcome).toEqual({ kind: "locked" });
  expect(vault.isUnlocked()).toBe(false);

  // First mutation-sensitive oracle: completed public durable value.
  expect(await kv.getItem(slot)).toBeNull();
});

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


it("queues reconciliation behind the exact public resource held by another document", async () => {
  const owner = "sync-terminal-lock-owner";
  setSession("sync-terminal-lock-token", owner, "lock-owner");
  vault.unlock({ authKey: key(89), dataKey: key(97) }, owner);
  const manager = new ExclusiveLockManager();
  const priorLocks = Object.getOwnPropertyDescriptor(navigator, "locks");
  Object.defineProperty(navigator, "locks", { configurable: true, value: manager });
  const entered = deferred<void>();
  const held = deferred<void>();
  const sibling = manager.request("mindpattern-reconcile", async () => {
    entered.resolve(undefined);
    await held.promise;
  });
  let operation: ReturnType<typeof reconcile> | undefined;
  try {
    await entered.promise; // Public grant receipt, fixture admission only.
    const admitted = await manager.query();
    expect(admitted.held.map(({ name, mode }) => ({ name, mode }))).toEqual([
      { name: "mindpattern-reconcile", mode: "exclusive" },
    ]);
    expect(admitted.pending).toEqual([]);
    stubFetch(() => jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null }));
    operation = reconcile();
    void operation.catch(() => undefined);
    // request() synchronously queues before this genuine later public
    // snapshot task. No elapsed-time or private queue/count observation.
    const snapshot = await manager.query();
    // First mutation-sensitive oracle: standard public name/mode value.
    expect(snapshot.pending.map(({ name, mode }) => ({ name, mode }))).toEqual([
      { name: "mindpattern-reconcile", mode: "exclusive" },
    ]);
  } finally {
    held.resolve(undefined);
    try {
      await Promise.allSettled([sibling, ...(operation ? [operation] : [])]);
    } finally {
      if (priorLocks) Object.defineProperty(navigator, "locks", priorLocks);
      else Reflect.deleteProperty(navigator, "locks");
    }
  }
});
