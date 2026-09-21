/**
 * Deep-mutation pins for the API client (2026-09-15 Stryker campaign).
 *
 * Each block kills specific surviving mutants (see /tmp/surv_api__client.ts.txt):
 *  - the exact AsyncStorage key names session material lives under,
 *  - queue_quarantine/queue_rejected being origin-bound on a server switch,
 *  - the first-save (previous === null) case keeping the session,
 *  - insecure-HTTP consent recorded only for insecure servers (&& not ||),
 *  - sanitizeDetail regex vectors: scheme URLs at string start, "xhttp://",
 *    and a URL-like fragment after "https://" whitespace,
 *  - parseRetryAfter boundaries: negative, Infinity, and the exact-0 vector
 *    whose Date.parse fallback differs ("0e0" parses as NaN, "0" as year 2000),
 *  - the 401 hook firing ONLY on 401s that carried a token,
 *  - Retry-After read ONLY on 429 and only through a real headers object,
 *  - getCachedSalt refusing a non-string s, and clearCachedSalt really wiping.
 */
// @ts-nocheck

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import storage from "./helpers/storageMock";
import {
  api,
  DEFAULT_BASE_URL,
  detailToMessage,
  getInsecureConsentUrl,
  isInsecureHttpAllowed,
  parseRetryAfter,
  setBaseUrl,
  setUnauthorizedHandler,
} from "../src/api/client";

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
  setUnauthorizedHandler(null);
});

describe("client pins: session storage key names", () => {
  it("user id and username land under their exact AsyncStorage keys (encrypted wrappers)", async () => {
    await api.setSession("tok", "abababababababababababababababab", "kim");
    // secureStore wraps the values, but they must exist under the canonical
    // keys — an emptied key constant would store them under "" instead.
    expect(await storage.getItem("@mindpattern/user_id")).not.toBeNull();
    expect(await storage.getItem("@mindpattern/username")).not.toBeNull();
  });
});

describe("client pins: origin-bound local state on server switch", () => {
  it("old unscoped queue bytes are preserved for safe migration; unrelated keys survive", async () => {
    await setBaseUrl("https://old.example.com");
    await storage.setItem("@mindpattern/queue_quarantine", "q");
    await storage.setItem("@mindpattern/queue_rejected", "r");
    await storage.setItem("@mindpattern/unrelated", "keep-me");

    expect(await setBaseUrl("https://new.example.com")).toBeNull();

    // Queue v2 owns scoped keys itself. Old global bytes are deliberately
    // retained until its migration can quarantine them rather than guessing
    // they belong to this new server.
    expect(await storage.getItem("@mindpattern/queue_quarantine")).toBe("q");
    expect(await storage.getItem("@mindpattern/queue_rejected")).toBe("r");
    expect(await storage.getItem("@mindpattern/unrelated")).toBe("keep-me");
  });

  it("pending question feedback is wiped with the origin too", async () => {
    await setBaseUrl("https://old.example.com");
    await storage.setItem("@mindpattern/question_feedback.user-1", "enc-blob");

    expect(await setBaseUrl("https://new.example.com")).toBeNull();

    // Feedback taps are AAD-bound to the account of the origin that ranked
    // the questions — one server's taps must not train another's ranking.
    expect(await storage.getItem("@mindpattern/question_feedback.user-1")).toBeNull();
  });
});

describe("client pins: first URL save", () => {
  it("treats the implicit localhost default as a real origin and wipes its session before a first remote URL save", async () => {
    await api.setSession("tok-keep", "abababababababababababababababab", "alice");
    expect(await api.isLoggedIn()).toBe(true);
    // `previous === null` means the active origin was DEFAULT_BASE_URL. A
    // first save to a remote host is therefore a real origin change; keeping
    // the localhost token created a bearer leak window in older clients.
    expect(await setBaseUrl("https://first.example.com")).toBeNull();
    expect(await api.isLoggedIn()).toBe(false);
    expect(await api.getUserId()).toBeNull();
  });
});

describe("client pins: insecure consent records only insecure servers", () => {
  it("a SECURE url saved with allowInsecure records NO consent", async () => {
    expect(await setBaseUrl("https://secure.example.com", { allowInsecure: true })).toBeNull();
    // Consent is the exact insecure URL or the literal "0" — never a secure
    // URL (the && must not degrade to ||, which would bless any save).
    expect(await storage.getItem("@mindpattern/insecure_http_ok")).toBe("0");
    expect(await isInsecureHttpAllowed()).toBe(false);
    expect(await getInsecureConsentUrl()).toBeNull();
  });
});

describe("client pins: sanitizeDetail regex vectors", () => {
  it("a URL fragment after scheme-whitespace is NOT stripped (the \\S is load-bearing)", () => {
    // "https://" followed by whitespace matches neither the http nor the
    // generic scheme regex (both require \\S+ right after "://") — replacing
    // \\S with \\s here would swallow the "https://" and change the message.
    // The bare "evil.example" domain IS stripped (2026-09-19: every alpha
    // TLD now, not an allowlist), so the surviving scheme text is the
    // observable pin; a \\s regression would yield "see now".
    expect(detailToMessage("see https:// evil.example now", 400)).toBe("see https:// now");
  });

  it("an 'xhttp://' URL loses only its http:// part — the 'x' prefix survives", () => {
    // The http(s) regex matches mid-token, so "x" is left behind; only the
    // later generic-scheme pass could eat the whole token (https-only mutant).
    expect(detailToMessage("go xhttp://a now", 400)).toBe("go x now");
  });

  it("a scheme URL at the very start of the message is stripped", () => {
    // With no preceding character, [^a-z]-style mutations cannot ride an
    // earlier non-letter and the strip must still happen.
    expect(detailToMessage("mywallet://transfer?to=evil now", 400)).toBe("now");
  });
});

describe("client pins: parseRetryAfter boundaries", () => {
  it("negative seconds clamp to 0 via the date fallback — never a negative retryAfterMs", () => {
    // "-5" fails seconds >= 0, and V8's Date.parse("-5") is a past date that
    // clamps to 0; a || / >=0→true mutant would return -5000 instead.
    expect(parseRetryAfter("-5")).toBe(0);
    // Infinity is not finite and not a date: undefined, never the ceiling.
    expect(parseRetryAfter("Infinity")).toBeUndefined();
  });

  it("an exact zero delays by exactly 0ms (>= is strict at the boundary)", () => {
    // "0e0" numeric-parses to 0 but is NOT an HTTP-date (NaN), unlike "0"
    // (which V8 reads as year 2000 and clamps back to 0) — so only the
    // seconds branch can produce 0 here.
    expect(parseRetryAfter("0e0")).toBe(0);
  });
});

describe("client pins: 401 hook gating", () => {
  it("a non-401 error that carried a token does NOT fire the session-death hook", async () => {
    const handler = vi.fn();
    setUnauthorizedHandler(handler);
    await api.setSession("tok-1", "abababababababababababababababab", "alice");
    vi.mocked(fetch).mockResolvedValue(jsonResponse({ detail: "boom" }, 500));
    await expect(api.insights()).rejects.toMatchObject({ status: 500 });
    expect(handler).not.toHaveBeenCalled();
  });
});

describe("client pins: Retry-After is read only on 429 with a real headers object", () => {
  it("a non-429 error with a Retry-After header carries no retryAfterMs", async () => {
    const response = jsonResponse({ detail: "slow down" }, 500);
    response.headers.set("retry-after", "30");
    vi.mocked(fetch).mockResolvedValue(response);
    await expect(api.meta()).rejects.toMatchObject({ status: 500, retryAfterMs: undefined });
  });

  it("a 429 without any headers object still maps to a 429 ApiError (no TypeError)", async () => {
    vi.mocked(fetch).mockResolvedValue({ ok: false, status: 429, url: DEFAULT_BASE_URL, json: async () => ({}) } as never);
    await expect(api.meta()).rejects.toMatchObject({ status: 429, retryAfterMs: undefined });
  });
});

describe("client pins: salt cache record shape", () => {
  it("a v1 record with a non-string s is refused (never returned raw)", async () => {
    await storage.setItem("@mindpattern/salt_nonstring", JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, s: 5 }));
    expect(await api.getCachedSalt("nonstring")).toBeNull();
  });

  it("clearCachedSalt really removes the cached record", async () => {
    await api.cacheSalt("kim", "c2FsdA==");
    expect(await api.getCachedSalt("kim")).toBe("c2FsdA==");
    await api.clearCachedSalt("kim");
    expect(await api.getCachedSalt("kim")).toBeNull();
  });
});
