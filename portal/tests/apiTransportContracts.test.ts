import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { getEventListeners } from "node:events";
import { api, auth, clearSession, hasSession, normalizeApiBaseUrl, setSession, setUnauthorizedHandler } from "../src/api";
const base = "https://clinic.example.com";
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
beforeEach(() => { clearSession(); setUnauthorizedHandler(null); setSession("transport-bearer", base); });
afterEach(() => { clearSession(); setUnauthorizedHandler(null); vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.useRealTimers(); });
const settle = async () => { for (let index = 0; index < 30; index++) await Promise.resolve(); };
function observe<T>(request: Promise<T>) {
  const result: { settled: boolean; value?: T; error?: unknown } = { settled: false };
  void request.then(value => { result.value = value; result.settled = true; }, error => { result.error = error; result.settled = true; });
  return result;
}

it.each([null, 7, true, "error"])("maps an incomplete error envelope %s to a recognizable safe API failure", async body => {
  for (const invoke of [() => api.me(), () => auth.login(base, "drportal", "proof"), () => api.logout()]) {
    vi.stubGlobal("fetch", vi.fn(async () => json(body, 403)));
    await expect(invoke()).rejects.toMatchObject({ name: "ApiError", status: 403, code: undefined, message: "request failed (403)" });
  }
});
it("rejects an empty or whitespace-only bearer with specific copy before altering a current session", () => {
  for (const token of ["", "   "]) expect(() => setSession(token, base)).toThrow("invalid empty session token");
  expect(hasSession()).toBe(true);
});
it("returns the normalized base's canonical origin/path while preserving deployment prefixes", () => {
  expect(normalizeApiBaseUrl("  https://clinic.example.com/path///  ")).toBe(base + "/path");
  for (const candidate of [base + "/", " " + base, ""]) expect(() => setSession("bearer", candidate)).toThrow("use an HTTPS server URL (or an explicit local development server)");
});
it("accepts explicit development IPv6 loopback without permitting a lookalike", () => {
  expect(normalizeApiBaseUrl("http://[::1]:5173/")).toBe("http://[::1]:5173");
  expect(normalizeApiBaseUrl("http://[::2]:5173/")).toBe("");
});
it.each(["ftp://localhost:5173","ws://localhost:5173","file://localhost/","custom://127.0.0.1:5173"])("refuses unsupported local-development protocol %s",candidate=>{
  expect(normalizeApiBaseUrl(candidate)).toBe("");
});

it("retires the earlier provider-held request signal when installing a replacement session",async()=>{
  let signal!:AbortSignal;let release!:(response:Response)=>void;
  vi.stubGlobal("fetch",vi.fn(async(_url,init)=>{signal=init!.signal!;return await new Promise<Response>(resolve=>{release=resolve;});}));
  const request=api.me();await settle();
  try{setSession("replacement",base);expect(signal.aborted).toBe(true);}finally{release(json({}));await request.catch(()=>{});}
});

it("drops fetch-failure deadlines and links even when the host rejects before response headers",async()=>{
  vi.useFakeTimers();let signal!:AbortSignal;
  vi.stubGlobal("fetch",vi.fn(async(_url,init)=>{signal=init!.signal!;throw new Error("offline");}));
  await expect(api.me()).rejects.toMatchObject({status:0,message:"server unreachable — check your connection"});
  expect(vi.getTimerCount()).toBe(0);clearSession();expect(signal.aborted).toBe(false);
});

it("rejects body consumption immediately when a late response arrives after its deadline",async()=>{
  vi.useFakeTimers();let releaseFetch!:(response:Response)=>void;let releaseBody!:(body:unknown)=>void;
  const body=new Promise<unknown>(resolve=>{releaseBody=resolve;});
  vi.stubGlobal("fetch",vi.fn(async()=>await new Promise<Response>(resolve=>{releaseFetch=resolve;})));
  const request=api.me();const result=observe(request);await settle();
  try{
    vi.advanceTimersByTime(15_000);await settle();
    releaseFetch({status:200,ok:true,headers:new Headers(),url:"",json:async()=>await body} as Response);
    await settle();expect(result.settled).toBe(true);expect(result.error).toMatchObject({status:0,message:"request timed out while reading response"});
  }finally{releaseBody({});await request.catch(()=>{});}
});

it("cleans a retired request's deadline immediately even while its host fetch is still pending",async()=>{
  vi.useFakeTimers();let release!:(response:Response)=>void;
  vi.stubGlobal("fetch",vi.fn(async()=>await new Promise<Response>(resolve=>{release=resolve;})));
  const request=api.me();await settle();
  try{clearSession();expect(vi.getTimerCount()).toBe(0);}finally{release(json({}));await request.catch(()=>{});}
});

it("consumes a successful JSON logout acknowledgement with its HTTP content type",async()=>{
  vi.stubGlobal("fetch",vi.fn(async(_url,init)=>{
    expect(new Headers(init?.headers).get("content-type")).toBe("application/json");
    return json({acknowledged:true});
  }));
  await expect(api.logout()).resolves.toBeNull();
});
it("preserves the client's API error class name rather than exposing a generic Error", async () => {
  clearSession();
  await expect(api.me()).rejects.toMatchObject({ name: "ApiError", status: 0, message: "not signed in" });
  await expect(api.logout()).rejects.toMatchObject({ name: "ApiError", status: 0, message: "not signed in" });
});
it.each(["authenticated", "login", "logout"])("maps an unavailable %s connection to helpful copy", async flow => {
  vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network down"); }));
  const request = flow === "login" ? auth.login(base, "drportal", "proof") : flow === "logout" ? api.logout() : api.me();
  await expect(request).rejects.toMatchObject({ name: "ApiError", status: 0, message: "server unreachable — check your connection" });
});
it("rejects an invalid returned origin without treating it as a network outage", async () => {
  const response = json({}); Object.defineProperty(response, "url", { value: "not an origin" });
  vi.stubGlobal("fetch", vi.fn(async () => response));
  await expect(api.me()).rejects.toMatchObject({ status: 0, message: "server returned an invalid response origin" });
});
it("rejects protected content when its fetch implementation resolves after session replacement", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => { setSession("replacement", base); return json({ secret: "old-account" }); }));
  await expect(api.me()).rejects.toMatchObject({ status: 0, message: "session ended" });
});
it("rejects protected content when its body replaces the session before finishing", async () => {
  vi.stubGlobal("fetch", vi.fn(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", json: async () => { setSession("replacement", base); return { secret: "old-account" }; } }) as Response));
  await expect(api.me()).rejects.toMatchObject({ status: 0, message: "session ended" });
});
it("allows the unauthorized callback to be cleared and still rejects a later 401", async () => {
  const handler = vi.fn(); setUnauthorizedHandler(handler); setUnauthorizedHandler(null);
  vi.stubGlobal("fetch", vi.fn(async () => json({ detail: "expired" }, 401)));
  await expect(api.me()).rejects.toMatchObject({ status: 401, message: "expired" });
  expect(handler).not.toHaveBeenCalled();
});
it("keeps per-device logout alive while the caller immediately retires its local session", async () => {
  vi.stubGlobal("fetch", vi.fn(async (_url, init) => { clearSession(); expect(init?.signal?.aborted).toBe(false); return new Response(null, { status: 204 }); }));
  await expect(api.logout()).resolves.toBeNull();
  expect(vi.mocked(fetch).mock.calls[0]![1]).toMatchObject({ keepalive: true });
});
it("cleans the deadline and session cancellation link after successful response consumption", async () => {
  vi.useFakeTimers(); let signal!: AbortSignal;
  vi.stubGlobal("fetch", vi.fn(async (_url, init) => { signal = init!.signal!; return json({ complete: true }); }));
  await expect(api.me()).resolves.toEqual({ complete: true });
  expect(vi.getTimerCount()).toBe(0);
  clearSession(); expect(signal.aborted).toBe(false);
});
it.each(["success", "parse failure"])("releases pending-body callbacks and deadlines for an alternate body after %s", async outcome => {
  vi.useFakeTimers(); let signal!: AbortSignal;
  const failure = new Error("alternate body failed");
  vi.stubGlobal("fetch", vi.fn(async (_url, init) => {
    signal = init!.signal!;
    return { status: 200, ok: true, headers: new Headers(), url: "", json: async () => {
      if (outcome === "parse failure") throw failure;
      return { complete: true };
    } } as Response;
  }));
  if (outcome === "success") await expect(api.me()).resolves.toEqual({ complete: true });
  else await expect(api.me()).rejects.toBe(failure);
  await settle();
  expect(vi.getTimerCount()).toBe(0);
  expect(getEventListeners(signal, "abort")).toHaveLength(0);
  clearSession(); expect(signal.aborted).toBe(false);
});

it.each(["empty acknowledged", "JSON acknowledged", "malformed JSON"])("fully releases best-effort bearer revocation after %s", async outcome => {
  vi.useFakeTimers();
  vi.stubGlobal("fetch", vi.fn(async () => outcome === "empty acknowledged" ? new Response(null,{status:204}) : outcome === "JSON acknowledged" ? json({ complete: true }) : new Response("not JSON")));
  await expect(auth.logoutBearer(base,"rejected-bearer")).resolves.toBeNull();
  expect(vi.getTimerCount()).toBe(0);
});

it("propagates a bearer-revocation source fault after releasing its deadline", async () => {
  vi.useFakeTimers(); const failure = new Error("revocation source failed");
  vi.stubGlobal("fetch",vi.fn(async () => ({ status:200,ok:true,headers:new Headers(),url:"",json:async () => {throw failure;} }) as unknown as Response));
  await expect(auth.logoutBearer(base,"rejected-bearer")).rejects.toBe(failure);
  expect(vi.getTimerCount()).toBe(0);
});
it("cleans the deadline for a native empty error response", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 403 })));
  await expect(api.me()).rejects.toMatchObject({ status: 403, message: "request failed (403)" });
  expect(vi.getTimerCount()).toBe(0);
});
it("preserves a helpful timeout at exactly fifteen seconds before response headers arrive", async () => {
  vi.useFakeTimers(); let release!: (value: Response) => void;
  vi.stubGlobal("fetch", vi.fn((_url, init) => new Promise<Response>((resolve, reject) => {
    release = resolve;
    init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
  })));
  const result = observe(api.me());
  try {
    await vi.advanceTimersByTimeAsync(14999); await settle(); expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "request timed out after 15s" } });
    expect(vi.getTimerCount()).toBe(0);
  } finally { release(json({ complete: true })); await settle(); }
});
it("stops a hung alternate response body at the deadline even when the fetch implementation ignores its signal", async () => {
  vi.useFakeTimers(); let release!: (value: unknown) => void;
  vi.stubGlobal("fetch", vi.fn(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", json: () => new Promise(resolve => { release = resolve; }) }) as Response));
  const result = observe(api.me());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(14999); await settle(); expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "request timed out while reading response" } });
  } finally { release({ complete: true }); await settle(); }
});
it("interrupts a hung alternate body immediately when the clinician signs out", async () => {
  let release!: (value: unknown) => void;
  vi.stubGlobal("fetch", vi.fn(async () => ({ status: 200, ok: true, headers: new Headers(), url: "", json: () => new Promise(resolve => { release = resolve; }) }) as Response));
  const result = observe(api.me());
  try {
    await settle(); clearSession(); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "session ended" } });
  } finally { release({ complete: true }); await settle(); }
});
it("cancels and cleans a native source when response reading hits the deadline", async () => {
  vi.useFakeTimers(); let source!: ReadableStreamDefaultController<Uint8Array>;
  const cancelled = vi.fn();
  vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ start(target) { source = target; }, cancel: cancelled }))));
  const result = observe(api.me());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(15000); await settle();
    expect(result).toMatchObject({ settled: true, error: { name: "ApiError", status: 0, message: "request timed out while reading response" } });
    expect(cancelled).toHaveBeenCalledOnce(); expect(vi.getTimerCount()).toBe(0);
  } finally { try { source.close(); } catch { /* already cancelled */ } await settle(); }
});
it("accepts exactly the native sixteen-MiB budget and rejects one extra byte", async () => {
  const size = 16 * 1024 * 1024;
  vi.stubGlobal("fetch", vi.fn(async () => new Response('"' + "x".repeat(size - 2) + '"')));
  await expect(api.me()).resolves.toHaveLength(size - 2);
  const cancelled = vi.fn(); let sent = false;
  vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream<Uint8Array>({ pull(target) { if (!sent) { sent = true; target.enqueue(new Uint8Array(size + 1)); } }, cancel: cancelled }))));
  await expect(api.me()).rejects.toMatchObject({ status: 0, message: "Server response exceeded this client's safe size limit." });
  expect(cancelled).toHaveBeenCalledOnce();
});
it("propagates a native source read failure while releasing the request deadline", async () => {
  vi.useFakeTimers(); const failure = new Error("source disconnected");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream({ start(target) { target.error(failure); } }))));
  await expect(api.me()).rejects.toBe(failure); expect(vi.getTimerCount()).toBe(0);
});

it("keeps a hung native JSON body unsettled until its fifteen-second deadline, then fails promptly", async () => {
  vi.useFakeTimers(); let source!: ReadableStreamDefaultController<Uint8Array>;
  vi.stubGlobal("fetch",vi.fn(async () => new Response(new ReadableStream<Uint8Array>({start(target){source=target;}}))));
  const result=observe(api.me());
  try {
    await settle(); await vi.advanceTimersByTimeAsync(14999); await settle(); expect(result.settled).toBe(false);
    await vi.advanceTimersByTimeAsync(1); await settle();
    expect(result).toMatchObject({settled:true,error:{name:"ApiError",status:0,message:"request timed out while reading response"}});
  } finally {try{source.close();}catch{/* source already cancelled */} await settle();}
});
it.each([undefined, "", "   ", " enrollment-token "])("sends an optional enrollment token only when meaningful: %s", async token => {
  vi.stubGlobal("fetch", vi.fn(async () => json({ token: "issued" })));
  await auth.registerTherapist(base, { username: "drportal", salt: "salt", verifier: "proof", display_name: "Dr. Portal", wrap_pub_key: "public", wrap_key_blob: "sealed", age_attestation: "minimum_age_confirmed_v1" }, token);
  const headers = new Headers(vi.mocked(fetch).mock.calls[0]![1]!.headers);
  expect(headers.get("X-Therapist-Enrollment-Token")).toBe(token?.trim() || null);
});
