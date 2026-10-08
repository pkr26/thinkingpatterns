import { runTestControl } from "./helpers/testControl";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { getEventListeners } from "node:events";
import storage from "./helpers/storageMock";
import { api, setUnauthorizedHandler } from "../src/api/client";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";

const origin = "http://localhost:8000";
const json = (value: unknown) => new Response(JSON.stringify(value));
const settle = async () => { for (let index = 0; index < 60; index++) await Promise.resolve(); };
function observe<T>(request: Promise<T>) {
  const result: { settled: boolean; value?: T; error?: unknown } = { settled: false };
  void request.then(value => { result.value = value; result.settled = true; }, error => { result.error = error; result.settled = true; });
  return result;
}
beforeEach(async () => {
  storage.__reset(); runTestControl(__resetLocalKeyLifecycleForTests); setUnauthorizedHandler(null);
  await api.setSession("transport-token", "a".repeat(32), "alice");
});
afterEach(async () => { await api.clearSession(); setUnauthorizedHandler(null); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });

it("cleans the headers and body deadlines when a native response completes", async () => {
  vi.useFakeTimers(); let signal!: AbortSignal;
  vi.stubGlobal("fetch", vi.fn(async (_url, init) => { signal = init!.signal!; return json({ complete: true }); }));
  const result=observe(api.meta());
  try {
    await settle();await vi.advanceTimersByTimeAsync(0);await settle();
    expect(result).toMatchObject({settled:true,value:{complete:true}});expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(15000);expect(signal.aborted).toBe(false);
  } finally {await api.clearSession();await settle();}
});

it("releases the native response body's abort subscription after completion",async()=>{
  let signal!:AbortSignal;
  vi.stubGlobal("fetch",vi.fn(async(_url,init)=>{signal=init!.signal!;return json({complete:true});}));
  expect(await api.meta()).toEqual({complete:true});await settle();
  expect(getEventListeners(signal,"abort")).toHaveLength(0);
});

it("reports exactly the fifteen-second headers deadline without leaving the request pending", async () => {
  vi.useFakeTimers(); let release!: (value: Response) => void;
  vi.stubGlobal("fetch", vi.fn((_url, init) => new Promise<Response>((resolve, reject) => {
    release = resolve;
    init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  })));
  const result = observe(api.meta());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(14999); await settle(); expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "request timed out after 15s" } });
    expect(vi.getTimerCount()).toBe(0);
  } finally { release(json({ complete: true })); await settle(); }
});

it.each(["alternate", "native"])("bounds a hung %s response body even when its implementation ignores the fetch signal", async kind => {
  vi.useFakeTimers(); let release!: () => void;
  vi.stubGlobal("fetch", vi.fn(async () => {
    if (kind === "alternate") return { status: 200, ok: true, url: origin + "/api/v1/meta", json: () => new Promise(resolve => { release = () => resolve({ complete: true }); }) } as Response;
    return new Response(new ReadableStream<Uint8Array>({ start(target) { release = () => { target.enqueue(new TextEncoder().encode('{"complete":true}')); target.close(); }; } }));
  }));
  const result = observe(api.meta());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(14999); await settle(); expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "request timed out after 15s" } });
    expect(vi.getTimerCount()).toBe(0);
  } finally { release(); await settle(); }
});

it("keeps failed fetch cleanup on the typed network-error surface", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network down"); }));
  await expect(api.meta()).rejects.toMatchObject({ name: "ApiError", status: 0, message: "server unreachable — check the server URL or your connection" });
  expect(vi.getTimerCount()).toBe(0);
});

it("reports a native body connection failure instead of returning a success envelope", async () => {
  vi.useFakeTimers(); let source!: ReadableStreamDefaultController<Uint8Array>;
  vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ start(controller) { source = controller; } }))));
  const result = observe(api.meta());
  try {
    await settle(); source.error(new Error("connection lost during response")); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "server unreachable — check the server URL or your connection" } });
    expect(vi.getTimerCount()).toBe(0);
  } finally { try { source.close(); } catch { /* already failed */ } await settle(); }
});

it("refuses a late headers response that ignored an already expired fetch signal", async () => {
  vi.useFakeTimers(); let release!: (value: Response) => void;
  vi.stubGlobal("fetch", vi.fn(() => new Promise<Response>(resolve => { release = resolve; })));
  const result = observe(api.meta());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(15000); release(json({ secret: "late response" })); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "request timed out after 15s" } });
    expect(result.value).toBeUndefined(); expect(vi.getTimerCount()).toBe(0);
  } finally { release(json({})); await settle(); }
});

it("retires old-account content when ownership changes during an alternate response body", async () => {
  let release!: (value: unknown) => void;
  vi.stubGlobal("fetch", vi.fn(async () => ({ status: 200, ok: true, url: "", json: () => new Promise(resolve => { release = resolve; }) }) as Response));
  const result = observe(api.meta());
  try {
    await settle(); await api.setSession("next-token", "b".repeat(32), "bob");
    release({ secret: "old account" }); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, code: "stale_operation",message:"The account or key generation changed. This request may already have committed; confirm its outcome before retrying." } });
    expect(result.value).toBeUndefined();
  } finally { release({}); await settle(); }
});

it("allows safe response-origin verification and rejects malformed final URLs", async () => {
  for (const url of ["not a URL", "https://different.example.com/api/v1/meta"]) {
    const response = json({ secret: true }); Object.defineProperty(response, "url", { value: url });
    vi.stubGlobal("fetch", vi.fn(async () => response));
    await expect(api.meta()).rejects.toMatchObject({ status: 0, message: "server redirected the request off the configured origin — check your server URL" });
  }
});
