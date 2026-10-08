import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, apiBaseUrl, auth, clearSession, detailToMessage, normalizeApiBaseUrl, parseRetryAfter, sessionAbortSignal, sessionUserId, setSession, setSessionExpiredHandler } from "../src/api/client";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

beforeEach(() => { resetTestState(); installSession(); });
afterEach(() => { clearSession(); setSessionExpiredHandler(null); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });
const settle = async () => { for (let index = 0; index < 40; index++) await Promise.resolve(); };
function observe<T>(request: Promise<T>) {
  const result: { settled: boolean; value?: T; error?: unknown } = { settled: false };
  void request.then(value => { result.value = value; result.settled = true; }, error => { result.error = error; result.settled = true; });
  return result;
}

it.each([[false, "production", false], [false, "test", true], [true, "development", true]] as const)("applies the build's loopback transport policy (DEV=%s MODE=%s)", (dev, mode, allowed) => {
  vi.stubEnv("DEV", dev); vi.stubEnv("MODE", mode);
  for (const candidate of ["http://localhost:5173", "http://127.0.0.1:8000", "http://[::1]:5173"]) expect(normalizeApiBaseUrl(candidate)).toBe(allowed ? candidate : "");
  expect(normalizeApiBaseUrl("https://clinic.example.com/prefix///")).toBe("https://clinic.example.com/prefix");
  expect(normalizeApiBaseUrl("  https://clinic.example.com/prefix///  ")).toBe("https://clinic.example.com/prefix");
  expect(normalizeApiBaseUrl("http://remote.example.com")).toBe("");
});

it("preserves path separators while trimming only trailing base slashes", () => {
  expect(normalizeApiBaseUrl("https://clinic.example.com/a//b///")).toBe("https://clinic.example.com/a//b");
  expect(normalizeApiBaseUrl(" ")).toBe("");
});

it("rejects a loopback address carried by an unsupported protocol", () => {
  vi.stubEnv("DEV", true);
  for (const url of ["ftp://localhost:21", "ws://localhost:5173", "file://localhost/api"]) expect(normalizeApiBaseUrl(url)).toBe("");
});

it("sanitizes untrusted error text while keeping readable word boundaries", () => {
  const cases: [unknown,string][] = [
    ["keep\u0000word", "keep word"],
    ["keep\u007fword", "keep word"],
    ["  keep clean copy  ", "keep clean copy"],
    ["look sub.api.evil.example:9999/path/tail end", "look end"],
    ["look evil.example:9999/path/tail end", "look end"],
    ["look evil.example:9999 end", "look end"],
    ["keep 12345 words", "keep words"],
    ["keep 1 2 3 4 words", "keep words"],
    ["keep 123a words", "keep 123a words"],
    ["keep a123 words", "keep a123 words"],
    ["keep1-234word", "keep word"],
    [[null, 1, "x", {}, { msg: 5 }, { msg: "safe" }], "invalid field; invalid field; invalid field; invalid field; invalid field; safe"],
  ];
  for (const [input,expected] of cases) expect(detailToMessage(input,422)).toBe(expected);
});

it("parses numeric and dated retry headers without accepting nonfinite or negative seconds", () => {
  vi.useFakeTimers(); vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
  for (const [input,expected] of [["0e0",0],["0",0],["1.25",1250],["-1",0],["Infinity",undefined],["not a date",undefined],["Mon, 05 Oct 2026 12:00:01 GMT",1000],["Mon, 05 Oct 2026 11:59:59 GMT",0]] as const) expect(parseRetryAfter(input)).toBe(expected);
});

it.each(["authenticated","public"])("preserves the %s response retry hint only for a retryable status", async flow => {
  for (const status of [400,429,503]) {
    stubFetch(async () => jsonResponse({ detail:"busy",code:"service_unavailable" },{status,headers:{"Retry-After":"2"}}));
    await expect(flow === "public" ? auth.meta() : api.meta()).rejects.toMatchObject({status,code:"service_unavailable",retryAfterMs:status === 400 ? undefined : 2000});
  }
});

it("refuses a missing or unsafe page origin before replacing an established session", () => {
  const active = sessionAbortSignal();
  vi.stubGlobal("window", { location: { origin: "http://remote.example.com" } });
  expect(() => apiBaseUrl()).toThrow("this app must be served over HTTPS (or a local development server)");
  expect(() => setSession("next", "next-user", "next")).toThrow("this app must be served over HTTPS (or a local development server)");
  expect(sessionAbortSignal()).toBe(active); expect(active?.aborted).toBe(false);
  vi.stubGlobal("window", undefined); expect(() => apiBaseUrl()).toThrow("this app must be served over HTTPS (or a local development server)");
});

it("exposes the active account and cancellation signal, then retires both on logout", () => {
  expect(sessionUserId()).toBe("user-1"); const signal = sessionAbortSignal(); expect(signal).toBeInstanceOf(AbortSignal); expect(signal?.aborted).toBe(false);
  setSession("replacement", "next-user", "bob"); expect(signal?.aborted).toBe(true); expect(sessionUserId()).toBe("next-user");
  const next = sessionAbortSignal(); clearSession(); expect(next?.aborted).toBe(true); expect(sessionAbortSignal()).toBeNull(); expect(sessionUserId()).toBeNull();
});

it.each([59, 60, 3600, 1e300])("fires a bounded expiry notice with the correct identity for a lifetime of %s seconds", async lifetime => {
  vi.useFakeTimers(); const handler = vi.fn(); setSessionExpiredHandler(handler); setSession("expiry-token", "expiry-user", "alice", lifetime);
  const signal = sessionAbortSignal(); const delay = Math.min(Math.max(lifetime * 1000 - 60000, 0), 2147483647);
  if (delay > 0) { await vi.advanceTimersByTimeAsync(delay - 1); expect(handler).not.toHaveBeenCalled(); await vi.advanceTimersByTimeAsync(1); }
  else await vi.advanceTimersByTimeAsync(0);
  expect(handler).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({ name: "ApiError", status: 401, message: "session token expired", code: "unauthorized" }), { userId: "expiry-user", origin: "http://localhost:5173", accountDeleted: false });
  expect(signal?.aborted).toBe(true); expect(sessionUserId()).toBeNull(); expect(vi.getTimerCount()).toBe(0);
});

it.each([0, -1, NaN, Infinity])("avoids expiry timers for unusable lifetime %s", lifetime => {
  vi.useFakeTimers(); setSession("expiry-token", "expiry-user", "alice", lifetime); expect(vi.getTimerCount()).toBe(0);
});

it("expires without a registered notification callback", async () => {
  vi.useFakeTimers(); setSessionExpiredHandler(null); setSession("expiry-token", "expiry-user", "alice", 60);
  await vi.advanceTimersByTimeAsync(0); expect(sessionUserId()).toBeNull();
});

it("uses safe fallback copy for an empty or entirely hostile validation list", () => {
  expect(detailToMessage([], 422)).toBe("request failed (422)");
  expect(detailToMessage([{ msg: "https://evil.example.com" }], 422)).toBe("request failed (422)");
});

it.each(["authenticated", "public", "logout"])("cleans a failed %s connection and reports helpful copy", async flow => {
  vi.useFakeTimers(); stubFetch(async () => { throw new TypeError("network down"); });
  await expect(flow === "public" ? auth.meta() : flow === "logout" ? api.logout() : api.meta()).rejects.toMatchObject({ name: "ApiError", status: 0, message: "server unreachable — check your connection" });
  expect(vi.getTimerCount()).toBe(0);
});

it("releases both the request timer and session cancellation link after a complete response", async () => {
  vi.useFakeTimers(); let signal!: AbortSignal;
  stubFetch(async (_url, init) => { signal = init.signal!; return jsonResponse({ complete: true }); });
  await expect(api.meta()).resolves.toEqual({ complete: true }); expect(vi.getTimerCount()).toBe(0);
  clearSession(); expect(signal.aborted).toBe(false);
});

it("cleans an empty native response while retaining its typed failure", async () => {
  vi.useFakeTimers(); stubFetch(async () => new Response(null, { status: 403 }));
  await expect(api.meta()).rejects.toMatchObject({ status: 403, message: "request failed (403)" }); expect(vi.getTimerCount()).toBe(0);
});

it.each([
  ["ordinary", () => api.meta(), 15000],
  ["voice", () => api.transcribeAudio("audio", "audio/mp4", 5), 180000],
  ["translation", () => api.translateText("hello", "en"), 15000],
  ["export", () => api.exportAccountRaw(), 120000],
] as const)("uses the public %s request's exact deadline", async (_name, invoke, deadline) => {
  vi.useFakeTimers(); let release!: (value: Response) => void;
  stubFetch((_url, init) => new Promise<Response>((resolve, reject) => {
    release = resolve;
    init.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  }));
  const result = observe<unknown>(invoke());
  try {
    await vi.advanceTimersByTimeAsync(deadline - 1); await settle(); expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: `request timed out after ${deadline / 1000}s` } });
    expect(vi.getTimerCount()).toBe(0);
  } finally { release(jsonResponse({})); await settle(); }
});

it.each(["deadline", "signout"])("settles an alternate response body after %s even when the body ignores abort", async event => {
  vi.useFakeTimers(); let release!: (value: string) => void;
  stubFetch(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", text: () => new Promise(resolve => { release = resolve; }) }) as unknown as Response);
  const result = observe(api.meta());
  try {
    await settle();
    if (event === "deadline") { await vi.advanceTimersByTimeAsync(14999); expect(result.settled).toBe(false); await vi.advanceTimersByTimeAsync(1); }
    else clearSession();
    await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: event === "deadline" ? "request timed out while reading response" : "session ended" } });
    expect(vi.getTimerCount()).toBe(0);
  } finally { release("{}"); await settle(); }
});

it("rejects an alternate body that replaces the active account before completing", async () => {
  stubFetch(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", text: async () => { setSession("new-token", "new-user", "next"); return '{"secret":"old-account"}'; } }) as unknown as Response);
  await expect(api.meta()).rejects.toMatchObject({ status: 0, message: "session ended" });
});

it("reports malformed final origins using the origin-specific failure", async () => {
  const response = jsonResponse({}); Object.defineProperty(response, "url", { value: "not a URL" }); stubFetch(async () => response);
  await expect(api.meta()).rejects.toMatchObject({ status: 0, message: "server returned an invalid response origin" });
});

it.each(["text", "json", "arrayBuffer", "blob", "formData"] as const)("keeps the raw export's %s consumer cancellable and clears its deadline", async method => {
  vi.useFakeTimers(); let release!: (value: unknown) => void;
  const expected = { opaque: "polyfill result" };
  stubFetch(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", [method]: () => new Promise(resolve => { release = resolve; }) }) as unknown as Response);
  const response = await api.exportAccountRaw();
  const result = observe(response[method]());
  try {
    await settle(); clearSession(); await settle();
    expect(result).toMatchObject({ settled: true, error: { status: 0, message: "session ended" } }); expect(vi.getTimerCount()).toBe(0);
  } finally { release(expected); await settle(); }
});

it("refuses consumption when a returned raw response was already retired", async () => {
  const consume = vi.fn(async () => "old account");
  stubFetch(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", text: consume }) as unknown as Response);
  const response = await api.exportAccountRaw(); clearSession();
  await expect(response.text()).rejects.toMatchObject({ status: 0, message: "session ended" }); expect(consume).not.toHaveBeenCalled();
});

it("rejects a body whose own consumer aborts the request while resolving", async () => {
  stubFetch(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", text: async () => { clearSession(); return "{}"; } }) as unknown as Response);
  await expect(api.meta()).rejects.toMatchObject({ status: 0, message: "session ended" });
});

it.each(["complete", "read-failure", "oversized"])("settles a native response's %s path without relying on a test watchdog", async outcome => {
  vi.useFakeTimers(); const failure = new Error("source disconnected"); const cancelled = vi.fn(); let source!: ReadableStreamDefaultController<Uint8Array>;
  stubFetch(async () => new Response(new ReadableStream<Uint8Array>({ start(target) { source = target; }, cancel: cancelled })));
  const result = observe(api.meta());
  try {
    await settle();
    if (outcome === "complete") { source.enqueue(new TextEncoder().encode('{"complete":true}')); source.close(); }
    else if (outcome === "read-failure") source.error(failure);
    else source.enqueue(new Uint8Array(16 * 1024 * 1024 + 1));
    await vi.advanceTimersByTimeAsync(0); await settle();
    expect(result.settled).toBe(true);
    if (outcome === "complete") expect(result.value).toEqual({ complete: true });
    else if (outcome === "read-failure") expect(result.error).toBe(failure);
    else { expect(result.error).toMatchObject({ name: "ApiError", status: 0, message: "Server response exceeded this client's safe size limit." }); expect(cancelled).toHaveBeenCalledOnce(); }
    expect(vi.getTimerCount()).toBe(0);
  } finally { try { source.close(); } catch { /* source already settled */ } clearSession(); await vi.advanceTimersByTimeAsync(0); await settle(); }
});

it("cancels a native response already retired while its headers were arriving", async () => {
  const cancelled = vi.fn();
  stubFetch(async () => { clearSession(); return new Response(new ReadableStream<Uint8Array>({ cancel: cancelled })); });
  await expect(api.meta()).rejects.toMatchObject({ status: 0, message: "session ended" }); expect(cancelled).toHaveBeenCalledOnce();
});

it("settles a held native body at the deadline and cancels its source", async () => {
  vi.useFakeTimers(); const cancelled = vi.fn(); let source!: ReadableStreamDefaultController<Uint8Array>;
  stubFetch(async () => new Response(new ReadableStream<Uint8Array>({ start(target) { source = target; }, cancel: cancelled })));
  const result = observe(api.meta());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(15000); await settle();
    expect(result).toMatchObject({ settled: true, error: { status: 0, message: "request timed out while reading response" } });
    expect(cancelled).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
  } finally { try { source.close(); } catch { /* source already cancelled */ } clearSession(); await settle(); }
});

it("reports a public authentication body's deadline as a transport failure", async () => {
  vi.useFakeTimers(); let release!: (value:unknown) => void;
  stubFetch(async () => ({status:200,ok:true,headers:new Headers(),url:"",json:()=>new Promise(resolve=>{release=resolve;})}) as unknown as Response);
  const result=observe(auth.meta());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(15000); await settle();
    expect(result).toMatchObject({settled:true,error:{name:"ApiError",status:0,message:"request timed out while reading response"}});
    expect(vi.getTimerCount()).toBe(0);
  } finally { release({}); await settle(); }
});
