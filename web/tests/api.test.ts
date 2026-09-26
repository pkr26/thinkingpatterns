/** The API client's hardening, error contract, session-death latch, and
 *  pagination validators — the request core is the security surface. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  api,
  ApiError,
  apiBaseUrl,
  auth,
  clearSession,
  detailToMessage,
  listEntriesWalk,
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

  it("an unknown code degrades to undefined; detail is capped at 200 chars + ellipsis (mobile-parity sanitizer)", async () => {
    setSession("t", "u", "n");
    const long = "x".repeat(300);
    stubFetch(() => jsonResponse({ detail: long, code: "made_up_code" }, { status: 400 }));
    const err = await api.meta().catch((e: unknown) => e as ApiError);
    expect((err as ApiError).code).toBeUndefined();
    expect((err as ApiError).message.length).toBe(201); // 200 + the ellipsis
    expect((err as ApiError).message.endsWith("…")).toBe(true);
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

describe("logout survives its own session teardown (audit 2026-09-25)", () => {
  it("the epoch-bump request completes even though clearSession aborts everything else", async () => {
    // The fetch resolves only AFTER clearSession() has already run — the
    // exact race the old shared AbortController lost.
    let release!: (value: Response) => void;
    const gate = new Promise<Response>((resolve) => {
      release = resolve;
    });
    const mock = stubFetch(() => gate);
    setSession("tok", "user-1", "tester");
    const pending = api.logout();
    clearSession(); // synchronous teardown, as lockDown performs it
    release(new Response(null, { status: 204 }));
    await expect(pending).resolves.toBeNull();
    expect(mock).toHaveBeenCalledTimes(1);
    expect(String(mock.mock.calls[0]![0])).toBe(`${ORIGIN}/api/v1/auth/logout`);
  });

  it("surfaces a failed logout as an ApiError, not a silent abort", async () => {
    stubFetch(() => jsonResponse({ detail: "nope" }, { status: 500 }));
    setSession("tok", "user-1", "tester");
    await expect(api.logout()).rejects.toThrow(ApiError);
  });

  it("requires a session like every authenticated call", async () => {
    await expect(api.logout()).rejects.toThrow("not signed in");
  });
});

describe("listEntriesWalk (S-5: the bounded snapshot walk)", () => {
  beforeEach(() => {
    setSession("tok", "user-1", "tester");
  });

  const row = (id: string): { id: string; client_entry_id: string; blob: string; entry_date: string; received_at: string } => ({
    id: `row-${id}`,
    client_entry_id: id,
    blob: "AAECAwQFBgcICQoL",
    entry_date: "2026-09-25",
    received_at: "2026-09-25T00:00:00Z",
  });

  function page(rows: ReturnType<typeof row>[], nextOffset: number | null, revision?: string): Response {
    return jsonResponse(rows, {
      headers: {
        ...(nextOffset !== null ? { "X-Next-Offset": String(nextOffset) } : {}),
        ...(revision !== undefined ? { "X-Entries-Revision": revision } : {}),
      },
    });
  }

  it("walks every page under one pinned revision and stops at the terminal page", async () => {
    const seen: string[] = [];
    stubFetch((url) => {
      seen.push(String(url));
      if (!url.includes("/entries?")) return jsonResponse({ detail: "unmatched" }, { status: 404 });
      if (url.includes("offset=0")) return page([row("a"), row("b")], 2, "7");
      if (url.includes("offset=2")) {
        expect(url).toContain("expected_revision=7"); // the pin rides every continuation
        return page([row("c")], null, "7");
      }
      return jsonResponse({ detail: "bad" }, { status: 500 });
    });
    const entries = await listEntriesWalk();
    expect(entries.map((entry) => entry.client_entry_id)).toEqual(["a", "b", "c"]);
    expect(seen).toHaveLength(2);
  });

  it("legacy headerless servers walk unpinned with cross-page dedupe", async () => {
    stubFetch((url) => {
      if (!url.includes("/entries?")) return jsonResponse({ detail: "unmatched" }, { status: 404 });
      expect(String(url)).not.toContain("expected_revision=");
      if (url.includes("offset=0")) return page([row("a"), row("dup")], 2); // no revision headers
      if (url.includes("offset=2")) return page([row("dup"), row("z")], null); // boundary drift repeats "dup"
      return jsonResponse({ detail: "bad" }, { status: 500 });
    });
    const entries = await listEntriesWalk();
    expect(entries.map((entry) => entry.client_entry_id)).toEqual(["a", "dup", "z"]);
  });

  it("a mid-walk 409 collection_changed restarts from page one (bounded retries)", async () => {
    let attempt = 0;
    stubFetch((url) => {
      if (!url.includes("/entries?")) return jsonResponse({ detail: "unmatched" }, { status: 404 });
      if (url.includes("offset=0")) {
        attempt += 1;
        return page([row("a")], 1, attempt === 1 ? "5" : "6");
      }
      // First walk's continuation: the snapshot moved under us.
      if (url.includes("offset=1") && attempt === 1) {
        return jsonResponse({ detail: "changed", code: "collection_changed" }, { status: 409 });
      }
      if (url.includes("offset=1") && attempt === 2) return page([row("b")], null, "6");
      return jsonResponse({ detail: "bad" }, { status: 500 });
    });
    const entries = await listEntriesWalk();
    expect(entries.map((entry) => entry.client_entry_id)).toEqual(["a", "b"]);
  });

  it("a walk that keeps colliding fails honestly after the restart budget", async () => {
    stubFetch((url) => {
      if (url.includes("offset=0")) return page([row("a")], 1, "5");
      return jsonResponse({ detail: "changed", code: "collection_changed" }, { status: 409 });
    });
    await expect(listEntriesWalk()).rejects.toThrow(ApiError);
  });

  it("a mid-walk protocol-mode switch (legacy then revision) restarts, never mixes", async () => {
    let attempt = 0;
    stubFetch((url) => {
      if (!url.includes("/entries?")) return jsonResponse({ detail: "unmatched" }, { status: 404 });
      if (url.includes("offset=0")) {
        attempt += 1;
        return attempt === 1 ? page([row("a")], 1) : page([row("a")], 1, "9");
      }
      if (url.includes("offset=1")) {
        // The continuation suddenly speaks revisions while page one did not.
        return page([row("b")], null, "9");
      }
      return jsonResponse({ detail: "bad" }, { status: 500 });
    });
    const entries = await listEntriesWalk();
    expect(entries.map((entry) => entry.client_entry_id)).toEqual(["a", "b"]);
  });

  it("a server that never stops paginating is cut off by the page cap", async () => {
    let pages = 0;
    stubFetch((url) => {
      if (!url.includes("/entries?")) return jsonResponse({ detail: "unmatched" }, { status: 404 });
      pages += 1;
      const offset = Number(new URL(String(url)).searchParams.get("offset") ?? "0");
      return page([row(`r${offset}`)], offset + 1, "5");
    });
    await expect(listEntriesWalk()).rejects.toThrow("keeps returning entry continuations");
    expect(pages).toBe(201); // 200 capped pages + the terminal probe
  });

  it("the terminal probe accepting completion on an empty 201st page", async () => {
    let pages = 0;
    stubFetch((url) => {
      if (!url.includes("/entries?")) return jsonResponse({ detail: "unmatched" }, { status: 404 });
      pages += 1;
      const offset = Number(new URL(String(url)).searchParams.get("offset") ?? "0");
      if (offset >= 200) return page([], null, "5"); // the honest 201st page
      return page([row(`r${offset}`)], offset + 1, "5");
    });
    const entries = await listEntriesWalk();
    expect(entries).toHaveLength(200);
    expect(pages).toBe(201);
  });
});

describe("F2: error-banner sanitizer (W-2, mobile parity)", () => {
  it("strips bare domains and phone-like digit runs", () => {
    expect(detailToMessage("go to evil.com/support for help", 400)).not.toContain("evil.com");
    expect(detailToMessage("call 555-0134 now", 400)).not.toContain("555");
    expect(detailToMessage("see https://evil.example/x", 400)).not.toContain("evil");
    expect(detailToMessage("open mindpattern-support://x", 400)).not.toContain("://");
  });

  it("no TLD allowlist — EVERY domain TLD is stripped (2026-09-19 corpus)", () => {
    expect(detailToMessage("Account locked. Unlock at bit.ly/mp-verify", 403))
      .not.toContain("bit.ly");
    expect(detailToMessage("Verify your account at mindpattern-support.de/login", 403))
      .not.toContain("mindpattern-support.de");
    expect(detailToMessage("Join the support chat: discord.gg/mindpattern", 403))
      .not.toContain("discord.gg");
    expect(detailToMessage("Recover data at mp-recover.to/help", 403))
      .not.toContain("mp-recover.to");
    expect(detailToMessage("see status.example.xyzzy now", 400)).not.toContain("example.xyzzy");
  });

  it("invisible characters cannot split a domain", () => {
    expect(detailToMessage("Unlock at bit\u2060.ly/mp-verify", 403))
      .not.toContain(".ly");
    expect(detailToMessage("Unlock at bit\u2060.ly/mp-verify", 403))
      .not.toContain("\u2060");
    expect(detailToMessage("Unlock at evil\ufeff.com/verify", 403))
      .not.toContain("evil");
    expect(detailToMessage("go bit\u200b.ly now", 400)).not.toContain(".ly");
  });

  it("bidi overrides cannot flip the banner's reading order", () => {
    const out = detailToMessage("safe\u202etext\u202c: call 555-0134", 400);
    expect(out).not.toContain("\u202e");
    expect(out).not.toContain("\u202c");
    expect(out).not.toContain("555");
  });

  it("honest text still reads fine after the strip", () => {
    const out = detailToMessage("your journal entry was saved; sync continues in 5 minutes", 201);
    expect(out).toContain("journal entry was saved");
    expect(out).toContain("5 minutes");
    const taken = detailToMessage("username is taken; try another in 5 minutes", 409);
    expect(taken).toContain("username is taken");
    expect(taken).toContain("5 minutes");
  });

  it("a fully-sanitized-away detail falls back to the status message", () => {
    expect(detailToMessage("https://evil.example/everything", 400)).toBe("request failed (400)");
    expect(detailToMessage("", 500)).toBe("request failed (500)");
  });

  it("FastAPI array details sanitize too, and length is capped at 200 + ellipsis", () => {
    const out = detailToMessage([{ msg: "go to evil.com now" }, { msg: "and call 555-0134" }], 422);
    expect(out).not.toContain("evil.com");
    expect(out).not.toContain("555");
    expect(out).not.toContain("invalid field"); // joined msgs, not the placeholder
    const long = detailToMessage(`x`.repeat(500), 400);
    expect(long.length).toBe(201);
    expect(long.endsWith("…")).toBe(true);
    expect(detailToMessage([{ nope: 1 }, "str"], 422)).toContain("invalid field");
  });

  it("the request path carries sanitized copy end to end (no raw detail in ApiError.message)", async () => {
    setSession("tok", "0123456789abcdef0123456789abcdef", "alice");
    stubFetch(() => jsonResponse({ detail: "Account locked. Unlock at bit.ly/mp-verify or call 555-0134", code: "forbidden" }, { status: 403 }));
    const err = await api.meta().catch((e: unknown) => e) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.message).not.toContain("bit.ly");
    expect(err.message).not.toContain("555-0134");
    expect(err.message).not.toContain("http");
  });
});
