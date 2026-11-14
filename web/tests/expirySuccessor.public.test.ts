import { afterEach, expect, it, vi } from "vitest";
import { clearSession, hasSession, sessionUserId, setSession, setSessionExpiredHandler } from "../src/api/client";
afterEach(() => { clearSession(); setSessionExpiredHandler(null); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });
it("preserves a successor installed synchronously by the prior expiry handler and retains its expiry", async () => {
  vi.useFakeTimers();
  const expired: string[] = [];
  setSessionExpiredHandler((_error, context) => {
    expired.push(context.userId);
    if (context.userId === "owner-a") setSession("token-b", "owner-b", "user-b", 120);
  });
  setSession("token-a", "owner-a", "user-a", 60);
  await vi.advanceTimersByTimeAsync(0);
  expect(expired).toEqual(["owner-a"]);
  expect(sessionUserId()).toBe("owner-b");
  await vi.advanceTimersByTimeAsync(59999);
  expect(sessionUserId()).toBe("owner-b");
  await vi.advanceTimersByTimeAsync(1);
  expect(expired).toEqual(["owner-a", "owner-b"]);
  expect(hasSession()).toBe(false);
});

it("does not notify old export 401 twice when its handler installs a successor", async () => {
  const expired: string[] = [];
  setSessionExpiredHandler((_error, context) => {
    expired.push(context.userId);
    if (context.userId === "owner-a" && expired.length === 1) setSession("token-b", "owner-b", "user-b");
  });
  setSession("token-a", "owner-a", "user-a");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ code: "unauthorized" }), { status: 401 })));
  const { api } = await import("../src/api/client");
  await expect(api.exportAccountRaw()).rejects.toMatchObject({ status: 401 });
  expect(expired).toEqual(["owner-a"]);
  expect(sessionUserId()).toBe("owner-b");
  await expect(api.meta()).rejects.toMatchObject({ status: 401 });
  expect(expired).toEqual(["owner-a", "owner-b"]);
});

it("does not deliver an old export 410 account-deletion notification after a successor session starts", async () => {
  const { api } = await import("../src/api/client");
  const stale: number[] = [];
  for (let turn = 0; turn < 20; turn++) {
    clearSession();
    const notices: { reported: string; current: string | null }[] = [];
    setSessionExpiredHandler((_error, context) => notices.push({ reported: context.userId, current: sessionUserId() }));
    setSession("token-a", "owner-a", "user-a");
    let deliver!: (text: string) => void;
    let entered!: () => void;
    const enteredBody = new Promise<void>(resolve => { entered = resolve; });
    const body = new Promise<string>(resolve => { deliver = resolve; });
    const response = { status: 410, ok: false, body: null, headers: new Headers(), text: () => { entered(); return body; } };
    vi.stubGlobal("fetch", vi.fn(async () => response));
    const pending = api.exportAccountRaw().catch(() => undefined);
    await enteredBody;
    deliver(JSON.stringify({ code: "account_deleted" }));
    let scheduled = Promise.resolve();
    for (let i = 0; i < turn; i++) scheduled = scheduled.then(() => undefined);
    await scheduled.then(() => setSession("token-b", "owner-b", "user-b"));
    await pending;
    if (notices.some(row => row.reported === "owner-a" && row.current === "owner-b")) stale.push(turn);
  }
  expect(stale).toEqual([]);
});

it("ignores an old queued expiry callback after a new session owns the timer", async () => {
  vi.useFakeTimers();
  const nativeSetTimeout = globalThis.setTimeout;
  const callbacks: Array<() => void> = [];
  const observer = vi.spyOn(globalThis, "setTimeout").mockImplementation(((fn: TimerHandler, delay?: number, ...args: unknown[]) => {
    if (typeof fn === "function") callbacks.push(() => fn(...args));
    return nativeSetTimeout(fn, delay, ...args);
  }) as typeof setTimeout);
  const expired: string[] = [];
  setSessionExpiredHandler((_error, context) => expired.push(context.userId));
  setSession("token-a", "owner-a", "user-a", 90);
  const queuedOld = callbacks.at(-1)!;
  setSession("token-b", "owner-b", "user-b", 120);
  queuedOld(); // Emulate an A callback already queued when clearTimeout ran.
  expect(sessionUserId()).toBe("owner-b");
  expect(expired).toEqual([]);
  await vi.advanceTimersByTimeAsync(60000);
  expect(expired).toEqual(["owner-b"]);
  expect(hasSession()).toBe(false);
  observer.mockRestore();
});
