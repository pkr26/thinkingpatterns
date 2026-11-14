import { afterEach, beforeEach, expect, it, vi } from "vitest";
import {
  clearSession,
  hasSession,
  sessionAbortSignal,
  sessionUserId,
  setSession,
} from "../src/api/client";
import { reconcileInsights, type ReconcileOutcome } from "../src/sync";
import { vault } from "../src/vault";
import { setKvBackendForTests } from "../src/kvstore";
import { resetTestState, stubFetch } from "./helpers/api";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const key = (value: number) => new Uint8Array(new ArrayBuffer(32)).fill(value);

beforeEach(() => { resetTestState(); });
afterEach(() => {
  clearSession();
  vault.lock();
  setKvBackendForTests(null);
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

it("preserves a reentrant successor session and its in-flight reconciliation", async () => {
  setSession("reentrancy-token-A", "reentrancy-owner-A", "owner-a");
  vault.unlock({ authKey: key(31), dataKey: key(37) }, "reentrancy-owner-A");
  const signalA = sessionAbortSignal();
  expect(signalA).toBeInstanceOf(AbortSignal);
  expect(signalA!.aborted).toBe(false);

  const summary = { phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null };
  const response = new Response(JSON.stringify(summary), { status: 200, headers: { "Content-Type": "application/json" } });
  const transport = deferred<Response>();
  const http = deferred<{
    url: string;
    method: string | undefined;
    authorization: string | null;
    signal: AbortSignal | null;
  }>();
  // Return the exact held native Promise, without an async wrapper. All
  // request construction, cancellation and session checks remain real.
  stubFetch((url, init) => {
    http.resolve({
      url,
      method: init.method,
      authorization: new Headers(init.headers).get("Authorization"),
      signal: init.signal ?? null,
    });
    return transport.promise;
  });

  const keysB = { authKey: key(73), dataKey: key(79) };
  const listenerFinished = deferred<void>();
  let listenerError: unknown;
  let operation: Promise<ReconcileOutcome> | undefined;
  let adopted: {
    signedIn: boolean;
    userId: string | null;
    signal: AbortSignal | null;
    vaultOwner: string | null;
    dataKey: Uint8Array<ArrayBuffer>;
  } | undefined;
  const onAbortA = () => {
    try {
      // The native AbortController dispatch is synchronous. Its already
      // aborted signal does not redispatch when nested setSession clears A.
      setSession("reentrancy-token-B", "reentrancy-owner-B", "owner-b");
      vault.unlock(keysB, "reentrancy-owner-B");
      adopted = {
        signedIn: hasSession(),
        userId: sessionUserId(),
        signal: sessionAbortSignal(),
        vaultOwner: vault.ownerUserId(),
        dataKey: vault.get().dataKey,
      };
      operation = reconcileInsights();
      // Own an unexpected rejection immediately while retaining the exact
      // public operation Promise for the eventual completed-outcome oracle.
      void operation.catch(() => undefined);
    } catch (error) {
      listenerError = error;
    } finally {
      listenerFinished.resolve(undefined);
    }
  };
  signalA!.addEventListener("abort", onAbortA, { once: true });

  try {
    clearSession();
    await listenerFinished.promise;

    // These are positive public setup receipts, independent of current().
    expect(listenerError).toBeUndefined();
    expect(adopted).toBeDefined();
    expect(adopted!.signedIn).toBe(true);
    expect(adopted!.userId).toBe("reentrancy-owner-B");
    expect(adopted!.vaultOwner).toBe("reentrancy-owner-B");
    expect(adopted!.dataKey).toBe(keysB.dataKey);
    expect(adopted!.signal).toBeInstanceOf(AbortSignal);
    expect(operation).toBeDefined();

    const request = await http.promise;
    expect(new URL(request.url).pathname).toBe("/api/v1/insights");
    expect(request.method).toBe("GET");
    expect(request.authorization).toBe("Bearer reentrancy-token-B");
    expect(request.signal).toBeInstanceOf(AbortSignal);

    // The outer clear retires A only. The reentrant B session and vault
    // remain paired, and B's in-flight request is still current.
    expect(hasSession()).toBe(true);
    expect(sessionUserId()).toBe("reentrancy-owner-B");
    expect(sessionAbortSignal()).toBe(adopted!.signal);
    expect(adopted!.signal!.aborted).toBe(false);
    expect(request.signal!.aborted).toBe(false);
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("reentrancy-owner-B");
    expect(vault.get().dataKey).toBe(keysB.dataKey);

    // Complete B's real HTTP request with a valid baseline payload; it must
    // finish under B rather than becoming locked by A's outer clear.
    expect(response.status).toBe(200);
    transport.resolve(response);
    expect(await transport.promise).toBe(response);

    // First mutation-sensitive oracle: the completed public category.
    // No fetch count, private session slot, elapsed-time or Error copy.
    expect(await operation!).toEqual({ kind: "ok", phase: "baseline", stateSeq: null, summary, payload: null });
  } finally {
    signalA!.removeEventListener("abort", onAbortA);
    transport.resolve(response);
    await transport.promise;
    if (operation) await Promise.allSettled([operation]);
    clearSession();
    vault.lock();
  }
});
