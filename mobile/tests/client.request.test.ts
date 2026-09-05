/**
 * The real api client (no module mock): fetch is stubbed at the global so
 * every request() branch runs — headers, 204, error mapping, timeout,
 * unreachable, malformed JSON — plus the stored-URL policy and the
 * listEntries pagination loop.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import storage from "./helpers/storageMock";
import {
  api,
  ApiError,
  DEFAULT_BASE_URL,
  detailToMessage,
  getBaseUrl,
  isInsecureHttpAllowed,
  setBaseUrl,
} from "../src/api/client";

// The real client validates the FINAL url of every response (redirect
// hardening); node Response objects carry url === "" so the mock pins a
// same-origin url on every stubbed response by default.
const jsonResponse = (body: unknown, status = 200, url = DEFAULT_BASE_URL): Response => {
  const response = new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  Object.defineProperty(response, "url", { value: url });
  return response;
};

beforeEach(() => {
  storage.__reset();
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("stored base URL policy", () => {
  it("defaults to the local dev server", async () => {
    expect(await getBaseUrl()).toBe(DEFAULT_BASE_URL);
    expect(DEFAULT_BASE_URL).toBe("http://localhost:8000");
  });

  it("persists valid https URLs and clears the insecure flag", async () => {
    expect(await setBaseUrl("https://api.example.com:8443/v1/")).toBeNull();
    expect(await getBaseUrl()).toBe("https://api.example.com:8443/v1");
    expect(await isInsecureHttpAllowed()).toBe(false);
  });

  it("rejects malformed URLs with actionable guidance", async () => {
    expect(await setBaseUrl("not a url")).toMatch(/full URL like https/);
    expect(await setBaseUrl("ftp://example.com")).toMatch(/full URL like https/);
    expect(await getBaseUrl()).toBe(DEFAULT_BASE_URL);
  });

  it("refuses plain-HTTP remote servers without explicit consent", async () => {
    const error = await setBaseUrl("http://nas.lan:8000");
    expect(error).toMatch(/plain HTTP/i);
    expect(await getBaseUrl()).toBe(DEFAULT_BASE_URL);
  });

  it("saves an insecure server only when explicitly allowed, and remembers the consent", async () => {
    expect(await setBaseUrl("http://nas.lan:8000", { allowInsecure: true })).toBeNull();
    expect(await getBaseUrl()).toBe("http://nas.lan:8000");
    expect(await isInsecureHttpAllowed()).toBe(true);
    // Consent is scoped to the exact URL: any OTHER cleartext server is
    // still refused until separately consented to.
    expect(await isInsecureHttpAllowed("http://nas.lan:8000")).toBe(true);
    expect(await isInsecureHttpAllowed("http://other.lan:8000")).toBe(false);
    const error = await setBaseUrl("http://other.lan:8000");
    expect(error).toMatch(/plain HTTP/i);
  });

  it("clears a previous consent when a different URL is saved (no sticky downgrade)", async () => {
    await setBaseUrl("http://nas.lan:8000", { allowInsecure: true });
    expect(await isInsecureHttpAllowed()).toBe(true);
    await setBaseUrl("http://other.lan:8000", { allowInsecure: true });
    // Saving OTHER consented URL replaced the old one — nas.lan's consent is gone.
    expect(await isInsecureHttpAllowed("http://nas.lan:8000")).toBe(false);
    expect(await isInsecureHttpAllowed("http://other.lan:8000")).toBe(true);
  });

  it("allows loopback http without consent and records it as not-allowed", async () => {
    expect(await setBaseUrl("http://127.0.0.1:9000")).toBeNull();
    expect(await getBaseUrl()).toBe("http://127.0.0.1:9000");
    expect(await isInsecureHttpAllowed()).toBe(false);
  });

  // M1: a live session token must never travel to a newly configured origin.
  it("clears the stored session when the base URL changes origin", async () => {
    await setBaseUrl("https://old.example.com");
    await api.setSession("tok-secret", "user-1", "alice");
    await api.cacheSalt("alice", "c2FsdA==");
    await storage.setItem("@mindpattern/last_recompute_user-1", "2026-09-04");
    await storage.setItem("@mindpattern/unlockproof_user-1", "cHJvb2Y=");
    await storage.setItem("mindpattern.moodlog.user-1", "blob");
    expect(await api.isLoggedIn()).toBe(true);

    expect(await setBaseUrl("https://evil.example.com")).toBeNull();
    expect(await api.isLoggedIn()).toBe(false);
    expect(await api.getUserId()).toBeNull();
    expect(await api.getUsername()).toBeNull();
    // Origin-bound local state is wiped too: another server's salt/proof/
    // stamp/mood-log must never leak into the new origin's account.
    expect(await storage.getItem("@mindpattern/salt_alice")).toBeNull();
    expect(await storage.getItem("@mindpattern/last_recompute_user-1")).toBeNull();
    expect(await storage.getItem("@mindpattern/unlockproof_user-1")).toBeNull();
    expect(await storage.getItem("mindpattern.moodlog.user-1")).toBeNull();

    // The very next request carries NO Authorization header to the new origin.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true }, 200, "https://evil.example.com/api/meta")));
    await api.meta();
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("keeps the session when the saved URL is unchanged", async () => {
    await setBaseUrl("https://same.example.com");
    await api.setSession("tok-secret", "user-1", "alice");
    expect(await setBaseUrl("https://same.example.com")).toBeNull();
    expect(await api.isLoggedIn()).toBe(true);
  });
});

describe("request plumbing", () => {
  it("sends JSON with the bearer token when a session exists", async () => {
    await api.setSession("tok-1", "user-1", "alice");
    await api.meta();
    const [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/meta`);
    expect(init.method).toBe("GET");
    expect(init.headers).toMatchObject({ "Content-Type": "application/json", Authorization: "Bearer tok-1" });
  });

  it("omits Authorization when not logged in", async () => {
    await api.meta();
    const [, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("returns parsed JSON bodies", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ phase: "insight" }));
    expect(await api.insights()).toEqual({ phase: "insight" });
  });

  it("returns null for 204 and never parses a body", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response(null, { status: 204 }));
    expect(await api.logout()).toBeNull();
  });

  it("maps error details to ApiError (string, validation list, absent)", async () => {
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: "nope" }, 403));
    await expect(api.insights()).rejects.toMatchObject({ status: 403, message: "nope" });

    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: [{ msg: "field required" }] }, 422));
    await expect(api.createEntry("e", "b", "2026-01-01")).rejects.toMatchObject({ status: 422, message: "field required" });

    vi.mocked(fetch).mockResolvedValue(jsonResponse({ odd: true }, 500));
    await expect(api.insights()).rejects.toMatchObject({ status: 500, message: "request failed (500)" });

    // Malformed JSON on an error status falls back to the status message.
    vi.mocked(fetch).mockResolvedValue(new Response("<html>", { status: 502 }));
    await expect(api.insights()).rejects.toMatchObject({ status: 502, message: "request failed (502)" });
  });

  it("treats a response body that is not JSON as empty on success", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("not json", { status: 200 }));
    await expect(api.meta()).resolves.toEqual({});
  });

  it("reports request timeouts distinctly from unreachable servers", async () => {
    const messageOf = async (): Promise<string> => {
      const error = await api.meta().catch((e) => e);
      expect(error.status).toBe(0);
      return error.message as string;
    };

    const aborted = Object.assign(new Error("The operation was aborted"), { name: "AbortError" });
    vi.mocked(fetch).mockRejectedValue(aborted);
    expect(await messageOf()).toBe("request timed out after 15s");

    // An Error that is NOT an AbortError must land on unreachable, not timeout.
    vi.mocked(fetch).mockRejectedValue(new TypeError("fetch failed"));
    expect(await messageOf()).toBe("server unreachable — check the server URL or your connection");

    // Non-Error rejections land on the same unreachable path.
    vi.mocked(fetch).mockRejectedValue("boom" as never);
    expect(await messageOf()).toBe("server unreachable — check the server URL or your connection");

    // A non-Error carrying an AbortError name still lacks instanceof Error.
    vi.mocked(fetch).mockRejectedValue({ name: "AbortError" } as never);
    expect(await messageOf()).toBe("server unreachable — check the server URL or your connection");
  });

  it("clears the timeout timer once the request settles", async () => {
    vi.useFakeTimers();
    try {
      let capturedSignal: AbortSignal | undefined;
      vi.mocked(fetch).mockImplementation(
        ((_url: unknown, init?: RequestInit) => {
          capturedSignal = init?.signal as AbortSignal;
          return Promise.resolve(jsonResponse({ ok: true }));
        }) as never,
      );
      await api.meta();
      // Long past the 15s timeout: the completed request's signal must never
      // be aborted — the timer was cleared in the finally block.
      await vi.advanceTimersByTimeAsync(60_000);
      expect(capturedSignal?.aborted).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("aborts stalled requests through the 15s timeout controller", async () => {
    vi.useFakeTimers();
    try {
      vi.mocked(fetch).mockImplementation(
        ((_url: unknown, init?: RequestInit) =>
          new Promise((_resolve, reject) => {
            init?.signal?.addEventListener("abort", () =>
              reject(Object.assign(new Error("The operation was aborted"), { name: "AbortError" })),
            );
          })) as never,
      );
      const pending = api.meta();
      const error = await (async () => {
        const result = pending.catch((e) => e);
        await vi.advanceTimersByTimeAsync(15_000);
        return result;
      })();
      expect(error.status).toBe(0);
      expect(error.message).toBe("request timed out after 15s");
    } finally {
      vi.useRealTimers();
    }
  });

  it("ApiError carries status and name", () => {
    const err = new ApiError(418, "teapot");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("ApiError");
    expect(err.status).toBe(418);
  });
});

describe("session storage helpers", () => {
  it("stores and clears token, user id and username", async () => {
    expect(await api.isLoggedIn()).toBe(false);
    await api.setSession("tok", "u1");
    expect(await api.getUserId()).toBe("u1");
    expect(await api.getUsername()).toBeNull();

    await api.setSession("tok", "u1", "alice");
    expect(await api.getUsername()).toBe("alice");
    expect(await api.isLoggedIn()).toBe(true);

    await api.clearSession();
    expect(await api.isLoggedIn()).toBe(false);
    expect(await api.getUserId()).toBeNull();
    expect(await api.getUsername()).toBeNull();
  });
});

describe("listEntries pagination", () => {
  it("keeps fetching pages of 500 until a short page arrives", async () => {
    const fullPage = Array.from({ length: 500 }, (_, i) => ({ client_entry_id: `e-${i}` }));
    const shortPage = [{ client_entry_id: "last" }];
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(fullPage))
      .mockResolvedValueOnce(jsonResponse(shortPage));

    const entries = await api.listEntries();

    expect(entries).toHaveLength(501);
    const urls = vi.mocked(fetch).mock.calls.map(([u]) => u as string);
    expect(urls[0]).toContain("limit=500&offset=0");
    expect(urls[1]).toContain("limit=500&offset=500");
    expect(urls).toHaveLength(2);
  });

  it("stops immediately on a short first page and forwards since", async () => {
    vi.mocked(fetch).mockResolvedValueOnce(jsonResponse([{ id: 1 }]));
    await api.listEntries("2026-01-01");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/entries?limit=500&offset=0&since=2026-01-01`);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(1);
  });

  it("handles a full page followed by an empty one", async () => {
    const fullPage = Array.from({ length: 500 }, (_, i) => ({ client_entry_id: `e-${i}` }));
    vi.mocked(fetch)
      .mockResolvedValueOnce(jsonResponse(fullPage))
      .mockResolvedValueOnce(jsonResponse([]));
    const entries = await api.listEntries();
    expect(entries).toHaveLength(500);
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2);
    // The wire path carries ONLY the pagination params — a spurious
    // `since=undefined` would break incremental sync.
    expect((vi.mocked(fetch).mock.calls[0] as [string])[0]).toBe(
      `${DEFAULT_BASE_URL}/api/entries?limit=500&offset=0`,
    );
    expect((vi.mocked(fetch).mock.calls[1] as [string])[0]).toBe(
      `${DEFAULT_BASE_URL}/api/entries?limit=500&offset=500`,
    );
  });
});

describe("endpoint wiring", () => {
  it("posts credentials in bodies, never in URLs", async () => {
    await api.saltFor("alice");
    let [url, init] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/auth/salt`);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ username: "alice" }));

    await api.register("alice", "c2FsdA==", "dmVyaWZpZXI=");
    [url, init] = vi.mocked(fetch).mock.calls[1] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/auth/register`);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ username: "alice", salt: "c2FsdA==", verifier: "dmVyaWZpZXI=" }));

    await api.login("alice", "dmVyaWZpZXI=");
    [url, init] = vi.mocked(fetch).mock.calls[2] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/auth/login`);
    expect(init.method).toBe("POST");
    expect(init.body).toBe(JSON.stringify({ username: "alice", verifier: "dmVyaWZpZXI=" }));
  });

  it("pins method, path and body for every remaining endpoint", async () => {
    const expectCall = async (
      index: number,
      method: string,
      path: string,
      body: unknown,
      headers?: Record<string, string>,
    ) => {
      const [calledUrl, init] = vi.mocked(fetch).mock.calls[index] as [string, RequestInit];
      expect(calledUrl).toBe(`${DEFAULT_BASE_URL}${path}`);
      expect(init.method).toBe(method);
      if (body === undefined) {
        expect(init.body).toBeUndefined();
      } else {
        expect(JSON.parse(init.body as string)).toEqual(body);
      }
      if (headers) expect(init.headers).toMatchObject(headers);
    };

    await api.createEntry("e-1", "YmxvYg==", "2026-09-03");
    await expectCall(0, "POST", "/api/entries", {
      client_entry_id: "e-1",
      blob: "YmxvYg==",
      entry_date: "2026-09-03",
    });

    await api.deleteEntry("e-1");
    await expectCall(1, "DELETE", "/api/entries/e-1", undefined);

    await api.openProcessingSession("a2V5");
    await expectCall(2, "POST", "/api/processing/sessions", { data_key: "a2V5" });

    await api.recompute("ptok");
    await expectCall(3, "POST", "/api/insights/recompute", undefined, { "X-Processing-Token": "ptok" });

    await api.insights();
    await expectCall(4, "GET", "/api/insights", undefined);

    await api.questionToday();
    await expectCall(5, "GET", "/api/questions/today", undefined);

    await api.exportAccount();
    await expectCall(6, "GET", "/api/account/export", undefined);

    await api.deleteAccount("dmVyaWY=");
    await expectCall(7, "DELETE", "/api/account", { verifier: "dmVyaWY=" });

    await api.getLlmConsent();
    await expectCall(8, "GET", "/api/account/llm-consent", undefined);

    await api.setLlmConsent(false, "dmVyaWY=");
    await expectCall(9, "PUT", "/api/account/llm-consent", { enabled: false, verifier: "dmVyaWY=" });

    await api.logout();
    await expectCall(10, "POST", "/api/auth/logout", undefined);

    await api.meta();
    await expectCall(11, "GET", "/api/meta", undefined);
  });
});

describe("persisted storage keys", () => {
  // H3: session material must be ENCRYPTED at rest — a device backup must
  // not contain a greppable bearer token.
  it("never stores the token, user id or username in plaintext", async () => {
    await api.setSession("tok-2", "u-2", "bob");
    expect(await storage.getItem("@mindpattern/token")).not.toBe("tok-2");
    expect(await storage.getItem("@mindpattern/token")).not.toContain("tok-2");
    expect(await storage.getItem("@mindpattern/user_id")).not.toBe("u-2");
    expect(await storage.getItem("@mindpattern/username")).not.toBe("bob");
    // But the session still round-trips through the encrypted wrapper.
    expect(await api.getUserId()).toBe("u-2");
    expect(await api.getUsername()).toBe("bob");
    expect(await api.isLoggedIn()).toBe(true);

    await setBaseUrl("https://api.example.com");
    expect(await storage.getItem("@mindpattern/base_url")).toBe("https://api.example.com");
    // Secure server -> insecure consent explicitly cleared.
    expect(await storage.getItem("@mindpattern/insecure_http_ok")).toBe("0");

    await setBaseUrl("http://nas.lan:8000", { allowInsecure: true });
    // Consent is recorded as the exact URL, not a global "1".
    expect(await storage.getItem("@mindpattern/insecure_http_ok")).toBe("http://nas.lan:8000");

    await api.clearSession();
    expect(await api.isLoggedIn()).toBe(false);
    expect(await api.getUserId()).toBeNull();
    expect(await api.getUsername()).toBeNull();
  });

  it("caches the KDF salt per username, bound to the origin it came from", async () => {
    await api.cacheSalt("alice", "c2FsdA==");
    expect(await storage.getItem("@mindpattern/salt_alice")).not.toBe("c2FsdA=="); // origin-bound record
    expect(await api.getCachedSalt("alice")).toBe("c2FsdA==");
    expect(await api.getCachedSalt("bob")).toBeNull(); // per-username

    // A different origin (server switch): the old origin's salt is REFUSED —
    // cross-origin KDF poisoning must not survive a base-URL change.
    await setBaseUrl("https://api.example.com");
    expect(await api.getCachedSalt("alice")).toBeNull();

    await api.clearCachedSalt("alice");
    expect(await api.getCachedSalt("alice")).toBeNull();
  });

  it("refuses legacy/corrupt salt records rather than guessing", async () => {
    await storage.setItem("@mindpattern/salt_alice", "not json");
    expect(await api.getCachedSalt("alice")).toBeNull();
    await storage.setItem("@mindpattern/salt_bob", JSON.stringify({ o: "http://x" }));
    expect(await api.getCachedSalt("bob")).toBeNull();
  });
});

describe("error-detail sanitization", () => {
  // M12: invisible bidi / zero-width characters must not survive sanitizing.
  it("strips bidi overrides and zero-width characters (RLO/RTO attack)", async () => {
    const detail = "\u202Eev\u2066il\u2069.example.com \u200Bkeep\u200Dme";
    // The invisible marks are gone; visible text survives.
    expect(detailToMessage(detail, 403)).toBe("evil.example.com keepme");
    // And none of the invisible codepoints remain anywhere in the output.
    expect(detailToMessage(detail, 403)).not.toMatch(/[\u200b-\u200f\u202a-\u202e\u2066-\u2069]/);
  });

  it("keeps normal text untouched", async () => {
    expect(detailToMessage("rate limited", 429)).toBe("rate limited");
  });
});

describe("redirect origin validation", () => {
  // M13: RN fetch follows redirects and re-sends headers — a redirect to a
  // foreign origin must surface as an error instead of a trusted response.
  const redirectedResponse = (url: string): unknown => ({
    ok: true,
    status: 200,
    url,
    json: async () => ({ evil: true }),
  });

  it("refuses responses that landed on a foreign origin", async () => {
    vi.mocked(fetch).mockResolvedValue(redirectedResponse("https://evil.example/api/meta") as never);
    await expect(api.meta()).rejects.toMatchObject({
      status: 0,
      message: expect.stringContaining("redirected"),
    });
  });

  it("accepts same-origin redirects (path-only)", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => redirectedResponse("https://api.example.com/v1/api/meta")));
    try {
      await setBaseUrl("https://api.example.com/v1");
      await expect(api.meta()).resolves.toEqual({ evil: true });
    } finally {
      vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));
    }
  });
});

describe("sensitive-request redirect hardening", () => {
  // H1: requests that ship a verifier or the data key must never accept a
  // response whose final URL cannot be verified (some network stacks leave
  // response.url empty) — that silence is exactly where a redirect hides.
  const unverifiable = (): unknown => ({ ok: true, status: 200, url: "", json: async () => ({}) });

  it("refuses sensitive requests when the final URL is unverifiable", async () => {
    vi.mocked(fetch).mockResolvedValue(unverifiable() as never);
    await expect(api.login("alice", "dmVyaWZpZXI=")).rejects.toMatchObject({
      status: 0,
      message: expect.stringContaining("could not verify"),
    });
    await expect(api.openProcessingSession("a2V5")).rejects.toMatchObject({ status: 0 });
    await expect(api.register("a", "c2FsdA==", "dg==")).rejects.toMatchObject({ status: 0 });
    await expect(api.deleteAccount("dg==")).rejects.toMatchObject({ status: 0 });
    await expect(api.setLlmConsent(true, "dg==")).rejects.toMatchObject({ status: 0 });
  });

  it("still allows non-sensitive requests with an unverifiable URL", async () => {
    vi.mocked(fetch).mockResolvedValue(unverifiable() as never);
    await expect(api.meta()).resolves.toEqual({});
  });

  it("refuses sensitive requests that landed on a foreign origin", async () => {
    const response = jsonResponse({ token: "x" }, 200, "https://evil.example/api/auth/login");
    vi.mocked(fetch).mockResolvedValue(response as never);
    await expect(api.login("alice", "dmVyaWZpZXI=")).rejects.toMatchObject({
      message: expect.stringContaining("redirected"),
    });
  });
});

describe("listEntries hostile-server cap", () => {
  // M1: a server that always returns a full page must not loop the client
  // forever (unbounded memory + battery drain).
  it("aborts loudly after the page cap instead of looping forever", async () => {
    const fullPage = Array.from({ length: 500 }, (_, i) => ({ client_entry_id: `e-${i}` }));
    vi.mocked(fetch).mockImplementation(async () => jsonResponse(fullPage));
    await expect(api.listEntries()).rejects.toMatchObject({
      status: 0,
      message: expect.stringContaining("full entry pages"),
    });
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(100);
  });
});

describe("deleteEntry path validation", () => {
  // L1: the entry id is interpolated into the URL path — at-rest tampering
  // must never steer the authenticated DELETE at another endpoint.
  it("refuses ids outside the generated shape", async () => {
    for (const bad of ["../../api/account", "x?verbose=", "a b", "", "e/" + "x".repeat(200)]) {
      await expect(api.deleteEntry(bad)).rejects.toMatchObject({
        status: 0,
        message: expect.stringContaining("invalid entry id"),
      });
    }
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("percent-encodes legitimate ids into the path", async () => {
    await api.deleteEntry("e-2026-09-04-abc_def");
    const [url] = vi.mocked(fetch).mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/entries/e-2026-09-04-abc_def`);
  });
});

describe("sanitizer: non-http schemes", () => {
  // L3: phishing is not limited to http(s) — app-deep-link and other
  // scheme URLs are stripped too.
  it("strips custom scheme URLs from server-provided detail", async () => {
    expect(detailToMessage("open evilapp://pay now", 400)).toBe("open now");
    expect(detailToMessage("go ftp://files.evil.example/x now", 400)).toBe("go now");
  });
});
