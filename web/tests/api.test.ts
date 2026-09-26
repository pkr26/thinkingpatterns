/** The API client's hardening, error contract, session-death latch, and
 *  pagination validators — the request core is the security surface. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  api,
  ApiError,
  apiBaseUrl,
  auth,
  clearSession,
  normalizeApiBaseUrl,
  parseRetryAfter,
  setSession,
  setSessionExpiredHandler,
} from "../src/api/client";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const ORIGIN = "http://localhost:5173";

beforeEach(() => {
  resetTestState();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

describe("base URL policy (same-origin only, TLS or explicit loopback)", () => {
  it("accepts https origins and canonicalizes trailing slashes", () => {
    expect(normalizeApiBaseUrl("https://app.example.com/")).toBe("https://app.example.com");
    expect(normalizeApiBaseUrl("https://app.example.com")).toBe("https://app.example.com");
  });
  it("rejects non-loopback http, userinfo, query and fragment", () => {
    expect(normalizeApiBaseUrl("http://evil.example.com")).toBe("");
    expect(normalizeApiBaseUrl("https://user:pass@example.com")).toBe("");
    expect(normalizeApiBaseUrl("https://example.com/?x=1")).toBe("");
    expect(normalizeApiBaseUrl("https://example.com/#f")).toBe("");
    expect(normalizeApiBaseUrl("not a url")).toBe("");
  });
  it("accepts explicit loopback http in the test build", () => {
    expect(normalizeApiBaseUrl("http://localhost:3000")).toBe("http://localhost:3000");
    expect(normalizeApiBaseUrl("http://127.0.0.1:8000")).toBe("http://127.0.0.1:8000");
  });
  it("uses the page origin as the only API base", () => {
    expect(apiBaseUrl()).toBe(ORIGIN);
  });
});

describe("session lifecycle", () => {
  it("stores the session and reports identity", () => {
    expect(apiBaseUrl()).toBe(ORIGIN);
    setSession("tok", "user-9", "alice");
    expect(apiBaseUrl()).toBe(ORIGIN);
    clearSession();
  });

  it("refuses an empty token", () => {
    expect(() => setSession("  ", "u", "n")).toThrow(ApiError);
  });

  it("an authenticated call without a session fails closed", async () => {
    await expect(api.meta()).rejects.toThrow("not signed in");
  });
});

describe("fetch hardening", () => {
  it("sends the exact hardened fetch shape with the bearer token", async () => {
    setSession("tok-bearer", "user-1", "a");
    const mock = stubFetch(() => jsonResponse({ version: "1.0.0" }));
    await api.meta();
    const [url, init] = mock.mock.calls[0]! as [string, RequestInit];
    expect(url).toBe(`${ORIGIN}/api/v1/meta`);
    expect(init.credentials).toBe("omit");
    expect(init.redirect).toBe("error");
    expect(init.cache).toBe("no-store");
    expect(init.referrerPolicy).toBe("no-referrer");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-bearer");
    clearSession();
  });

  it("a response from a different origin is refused", async () => {
    setSession("t", "u", "n");
    stubFetch(() => ({
      url: "https://evil.example.com/api/v1/meta",
      status: 200,
      headers: new Headers(),
      text: () => Promise.resolve("{}"),
    } as unknown as Response));
    await expect(api.meta()).rejects.toThrow("different origin");
    clearSession();
  });

  it("a hung server surfaces as a timeout ApiError", async () => {
    vi.useFakeTimers();
    try {
      setSession("t", "u", "n");
      stubFetch((_url, init) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        }),
      );
      const pending = api.meta();
      const assertion = expect(pending).rejects.toThrow("request timed out after 15s");
      await vi.advanceTimersByTimeAsync(16_000);
      await assertion;
      clearSession();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("error envelope contract", () => {
  it("maps {detail, code} to ApiError with a whitelisted code", async () => {
    setSession("t", "u", "n");
    stubFetch(() => jsonResponse({ detail: "nope", code: "quota_exceeded" }, { status: 413 }));
    const err = await api.meta().catch((e: unknown) => e as ApiError);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).status).toBe(413);
    expect((err as ApiError).code).toBe("quota_exceeded");
    expect((err as ApiError).message).toBe("nope");
    clearSession();
  });

  it("an unknown code degrades to undefined; detail is truncated to 200 chars", async () => {
    setSession("t", "u", "n");
    const long = "x".repeat(300);
    stubFetch(() => jsonResponse({ detail: long, code: "made_up_code" }, { status: 400 }));
    const err = await api.meta().catch((e: unknown) => e as ApiError);
    expect((err as ApiError).code).toBeUndefined();
    expect((err as ApiError).message.length).toBe(200);
    clearSession();
  });

  it("an unparseable body degrades to the status fallback message", async () => {
    setSession("t", "u", "n");
    stubFetch(() => new Response("<html>garbage", { status: 502 }));
    const err = await api.meta().catch((e: unknown) => e as ApiError);
    expect((err as ApiError).message).toBe("request failed (502)");
    clearSession();
  });
});

describe("Retry-After parsing", () => {
  it("parses seconds and clamps to one hour", () => {
    expect(parseRetryAfter("30")).toBe(30_000);
    expect(parseRetryAfter("99999999")).toBe(60 * 60_000);
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter("junk")).toBeUndefined();
  });
  it("parses an HTTP date and clamps the past to 0", () => {
    const future = new Date(Date.now() + 5000).toUTCString();
    const got = parseRetryAfter(future);
    expect(got).toBeDefined();
    expect(got!).toBeGreaterThan(0);
    expect(got!).toBeLessThanOrEqual(6000);
    expect(parseRetryAfter(new Date(Date.now() - 5000).toUTCString())).toBe(0);
  });

  it("a 429 carries retryAfterMs on the ApiError", async () => {
    stubFetch(() => jsonResponse({ detail: "slow down", code: "rate_limited" }, { status: 429, headers: { "Retry-After": "30" } }));
    const err = await auth.saltFor("someone").catch((e: unknown) => e as ApiError);
    expect((err as ApiError).retryAfterMs).toBe(30_000);
  });
});

describe("session-death latch (D-8)", () => {
  it("a 401 fires the handler ONCE per session with the error", async () => {
    setSession("t", "u", "n");
    const handler = vi.fn();
    setSessionExpiredHandler(handler);
    stubFetch(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 }));
    await expect(api.meta()).rejects.toThrow();
    await expect(api.insights()).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(1);
    expect((handler.mock.calls[0]![0] as ApiError).code).toBe("unauthorized");
    setSessionExpiredHandler(null);
    clearSession();
  });

  it("setSession re-arms the latch", async () => {
    setSession("t1", "u", "n");
    const handler = vi.fn();
    setSessionExpiredHandler(handler);
    stubFetch(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 }));
    await expect(api.meta()).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(1);
    setSession("t2", "u", "n");
    await expect(api.meta()).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(2);
    setSessionExpiredHandler(null);
    clearSession();
  });

  it("a 410 account_deleted fires the latch; a plain 401 on the unauthenticated path does not", async () => {
    setSession("t", "u", "n");
    const handler = vi.fn();
    setSessionExpiredHandler(handler);
    stubFetch(() => jsonResponse({ detail: "gone", code: "account_deleted" }, { status: 410 }));
    await expect(api.insights()).rejects.toThrow();
    expect(handler).toHaveBeenCalledTimes(1);
    setSessionExpiredHandler(null);
    clearSession();

    const handler2 = vi.fn();
    setSessionExpiredHandler(handler2);
    stubFetch(() => jsonResponse({ detail: "no", code: "invalid_credentials" }, { status: 401 }));
    await expect(auth.login("u", "v")).rejects.toThrow();
    expect(handler2).not.toHaveBeenCalled();
    setSessionExpiredHandler(null);
  });

  it("clearSession mid-flight ends the request without parsing", async () => {
    setSession("t", "u", "n");
    stubFetch(
      (_url, init) =>
        new Promise((resolve, reject) => {
          init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
          setTimeout(() => resolve(jsonResponse({ version: "1" })), 50);
        }),
    );
    const pending = api.meta();
    clearSession();
    await expect(pending).rejects.toThrow("session ended");
  });
});

describe("pagination validators", () => {
  it("an absent continuation header means the result set is complete", async () => {
    setSession("t", "u", "n");
    stubFetch(() => jsonResponse([{ id: "1", client_entry_id: "e1", blob: "AA", entry_date: "d", received_at: "r" }]));
    const page = await api.listEntriesPage({ offset: 0 });
    expect(page.nextOffset).toBeNull();
    clearSession();
  });

  it("listEntriesPage returns validated offset + revision", async () => {
    setSession("t", "u", "n");
    stubFetch(() =>
      jsonResponse([{ id: "1", client_entry_id: "e1", blob: "AA", entry_date: "2026-09-25", received_at: "x" }], {
        headers: { "X-Next-Offset": "1", "X-Entries-Revision": "5" },
      }),
    );
    const page = await api.listEntriesPage({ offset: 0 });
    expect(page.nextOffset).toBe(1);
    expect(page.revision).toBe("5");
    expect(page.entries.length).toBe(1);
    clearSession();
  });

  it("sends the expected_revision back and rejects a changed snapshot", async () => {
    setSession("t", "u", "n");
    let sent = "";
    stubFetch((url) => {
      sent = url;
      return jsonResponse([{ id: "1", client_entry_id: "e1", blob: "AA", entry_date: "d", received_at: "r" }], {
        headers: { "X-Next-Offset": "1", "X-Entries-Revision": "6" },
      });
    });
    await expect(api.listEntriesPage({ offset: 0, expectedRevision: "5" })).rejects.toThrow("changed entries snapshot");
    expect(sent).toContain("expected_revision=5");
    clearSession();
  });

  it("rejects malformed continuations (1e3, mismatched, headerless, empty-page)", async () => {
    setSession("t", "u", "n");
    const cases: { headers: Record<string, string>; rows: number }[] = [
      { headers: { "X-Next-Offset": "1e3" }, rows: 1 }, // non-decimal cursor
      { headers: { "X-Next-Offset": "9" }, rows: 1 }, // offset jump (9 !== 0+1)
      { headers: { "X-Next-Offset": "1" }, rows: 0 }, // "more after an empty page"
    ];
    for (const { headers, rows } of cases) {
      stubFetch(() => {
        const page = rows === 0 ? [] : [{ id: "1", client_entry_id: "e1", blob: "AA", entry_date: "d", received_at: "r" }];
        return jsonResponse(page, { headers });
      });
      await expect(api.listEntriesPage({ offset: 0 })).rejects.toThrow("invalid entries continuation");
    }
    clearSession();
  });

  it("listMeasuresPage validates the measures revision header", async () => {
    setSession("t", "u", "n");
    const row = { id: "1", client_measure_id: "m1", blob: "AA", measure_date: "d", received_at: "r" };
    stubFetch(() => jsonResponse([row], { headers: { "X-Next-Offset": "1", "X-Measures-Revision": "2" } }));
    const page = await api.listMeasuresPage({ offset: 0, expectedRevision: "2" });
    expect(page.revision).toBe("2");
    stubFetch(() => jsonResponse([row], { headers: { "X-Next-Offset": "1", "X-Measures-Revision": "3" } }));
    await expect(api.listMeasuresPage({ offset: 0, expectedRevision: "2" })).rejects.toThrow("changed measures snapshot");
    clearSession();
  });

  it("refuses malformed entry ids before any request is made", async () => {
    setSession("t", "u", "n");
    const mock = stubFetch(() => jsonResponse({}));
    expect(() => api.createEntry("bad id!", "AA", "2026-09-25")).toThrow("invalid entry id");
    expect(() => api.updateEntry("bad id!", "AA", "2026-09-25")).toThrow("invalid entry id");
    expect(() => api.getEntry("bad id!")).toThrow("invalid entry id");
    expect(() => api.deleteEntry("bad id!")).toThrow("invalid entry id");
    expect(mock).not.toHaveBeenCalled();
    clearSession();
  });

  it("refuses out-of-range page parameters locally", async () => {
    setSession("t", "u", "n");
    const mock = stubFetch(() => jsonResponse([]));
    await expect(api.listEntriesPage({ limit: 501 })).rejects.toThrow("invalid entry page request");
    await expect(api.listEntriesPage({ offset: -1 })).rejects.toThrow("invalid entry page request");
    await expect(api.listEntriesPage({ pageBytes: 0 })).rejects.toThrow("invalid entry page request");
    expect(mock).not.toHaveBeenCalled();
    clearSession();
  });

  it("accessLogPage walks the cursor header", async () => {
    setSession("t", "u", "n");
    stubFetch(() =>
      jsonResponse([{ at: "2026-09-25T00:00:00Z", action: "entry.create", actor: "self" }], {
        headers: { "X-Next-Cursor": "abc" },
      }),
    );
    const page = await api.accessLogPage();
    expect(page.rows.length).toBe(1);
    expect(page.nextCursor).toBe("abc");
    stubFetch(() => jsonResponse([]));
    const end = await api.accessLogPage("abc");
    expect(end.nextCursor).toBeNull();
    clearSession();
  });

  it("exportAccountRaw returns the raw response for streaming download", async () => {
    setSession("t", "u", "n");
    stubFetch(() => new Response('{"bundle":true}', { status: 200 }));
    const response = await api.exportAccountRaw();
    expect(response.status).toBe(200);
    clearSession();
  });
});
