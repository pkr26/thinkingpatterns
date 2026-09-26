/**
 * The portal API client: URL handling, wire shapes, error envelope
 * mapping, and the not-signed-in / unreachable branches.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, ApiError, auth, clearSession, setSession } from "../src/api";
import { normalizeBaseUrl } from "../src/views/LoginView";

const jsonResponse = (body: unknown, status = 200, headers: HeadersInit = {}): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });

beforeEach(() => {
  clearSession();
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

describe("normalizeBaseUrl", () => {
  it("trims trailing slashes and keeps paths", () => {
    expect(normalizeBaseUrl("https://api.example.com/")).toBe("https://api.example.com");
    expect(normalizeBaseUrl("https://api.example.com/mindpattern//")).toBe("https://api.example.com/mindpattern");
    expect(normalizeBaseUrl("  http://localhost:8000 ")).toBe("http://localhost:8000");
  });
  it("returns empty for garbage", () => {
    expect(normalizeBaseUrl("not a url")).toBe("");
    expect(normalizeBaseUrl("")).toBe("");
  });

  it("rejects insecure remote URLs, URL spoofing components, and non-web schemes", () => {
    expect(normalizeBaseUrl("http://api.example.com")).toBe("");
    expect(normalizeBaseUrl("https://user:password@api.example.com")).toBe("");
    expect(normalizeBaseUrl("https://api.example.com/path?token=nope")).toBe("");
    expect(normalizeBaseUrl("https://api.example.com/#fragment")).toBe("");
    expect(normalizeBaseUrl("file:///tmp/api")).toBe("");
  });
});

describe("authenticated requests", () => {
  it("refuses to run without a session", async () => {
    await expect(api.patients()).rejects.toMatchObject({ status: 0, message: "not signed in" });
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("sends the bearer token to the configured base under /api/v1", async () => {
    setSession("tok-1", "https://api.example.com");
    await api.patients();
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/therapist/patients");
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
    expect(init.redirect).toBe("error");
    expect(init.credentials).toBe("omit");
    expect(init.cache).toBe("no-store");
    expect(init.referrerPolicy).toBe("no-referrer");
  });

  it("rejects an unsafe session base before a bearer request can be made", () => {
    expect(() => setSession("tok-1", "http://api.example.com")).toThrow(/HTTPS server URL/);
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("rejects a cross-origin response even if a non-browser fetch implementation follows a redirect", async () => {
    setSession("tok-1", "https://api.example.com");
    const redirected = jsonResponse({ ok: true });
    Object.defineProperty(redirected, "url", { value: "https://evil.example/api/v1/therapist/patients" });
    vi.stubGlobal("fetch", vi.fn(async () => redirected));
    await expect(api.patients()).rejects.toMatchObject({
      status: 0,
      message: "server redirected the request to a different origin",
    });
  });

  it("aborts an in-flight authenticated request when the session is cleared", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn((_url: string, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener("abort", () => {
        const abort = new Error("aborted");
        abort.name = "AbortError";
        reject(abort);
      });
    })));
    const pending = api.patients();
    clearSession();
    await expect(pending).rejects.toMatchObject({ status: 0, message: "session ended" });
  });

  it("builds bounded entry queries with since/until/limit/offset", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse([])));
    await api.patientEntries("u1", { since: "2026-09-01", until: "2026-09-10", offset: 100 });
    const [url] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toContain("/therapist/patients/u1/entries?");
    expect(url).toContain("since=2026-09-01");
    expect(url).toContain("until=2026-09-10");
    expect(url).toContain("offset=100");
    expect(url).toContain("limit=25");
    expect(url).toContain("page_bytes=2097152");
  });

  it("returns an evidence page with a validated server continuation", async () => {
    setSession("tok-1", "https://api.example.com");
    const rows = Array.from({ length: 25 }, (_, index) => ({
      id: `row-${index}`,
      client_entry_id: `client-${index}`,
      blob: "B==",
      entry_date: "2026-09-01",
      received_at: "2026-09-01T00:00:00Z",
    }));
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(rows, 200, { "X-Next-Offset": "125" })));
    await expect(api.patientEntries("u1", { offset: 100 })).resolves.toEqual({
      entries: rows,
      nextOffset: 125,
    });
  });

  it("binds evidence continuations to one validated signed-64-bit snapshot revision", async () => {
    setSession("tok-1", "https://api.example.com");
    const firstRows = Array.from({ length: 25 }, (_, index) => ({
      id: `row-${index}`,
      client_entry_id: `client-${index}`,
      blob: "B==",
      entry_date: "2026-09-01",
      received_at: "2026-09-01T00:00:00Z",
    }));
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResponse(firstRows, 200, {
          "X-Next-Offset": "25",
          "X-Entries-Revision": "9223372036854775807",
        }))
        .mockResolvedValueOnce(jsonResponse([], 200, { "X-Entries-Revision": "9223372036854775807" })),
    );

    const first = await api.patientEntries("u1");
    expect(first).toMatchObject({ nextOffset: 25, revision: "9223372036854775807" });
    await expect(api.patientEntries("u1", { offset: 25, expectedRevision: first.revision })).resolves.toMatchObject({
      nextOffset: null,
      revision: "9223372036854775807",
    });
    const [url] = vi.mocked(fetch).mock.calls[1]! as [string, RequestInit];
    expect(url).toContain("offset=25");
    expect(url).toContain("expected_revision=9223372036854775807");
  });

  it("falls back only for headerless full pages from an older backend", async () => {
    setSession("tok-1", "https://api.example.com");
    const entries = Array.from({ length: 25 }, (_, index) => ({
      id: `row-${index}`,
      client_entry_id: `client-${index}`,
      blob: "B==",
      entry_date: "2026-09-01",
      received_at: "2026-09-01T00:00:00Z",
    }));
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(entries)));
    await expect(api.patientEntries("u1")).resolves.toMatchObject({
      entries,
      nextOffset: 25,
      revision: undefined,
    });

    // A headerless short page is still the terminal response contract.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(entries.slice(0, 24))));
    await expect(api.patientEntries("u1")).resolves.toMatchObject({
      nextOffset: null,
    });

    const notes = Array.from({ length: 100 }, (_, index) => ({
      id: `note-${index}`,
      client_note_id: `client-note-${index}`,
      pattern_pid: null,
      blob: "B==",
      created_at: "2026-09-01T00:00:00Z",
      updated_at: "2026-09-01T00:00:00Z",
    }));
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(notes)));
    await expect(api.notes("u1")).resolves.toMatchObject({
      notes,
      nextOffset: 100,
    });
  });

  it("rejects malformed, non-progressing, or oversized evidence page metadata", async () => {
    setSession("tok-1", "https://api.example.com");
    const oneRow = [{
      id: "row-1", client_entry_id: "client-1", blob: "B==",
      entry_date: "2026-09-01", received_at: "2026-09-01T00:00:00Z",
    }];
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(oneRow, 200, { "X-Next-Offset": "not-a-number" })));
    await expect(api.patientEntries("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid evidence continuation",
    });

    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(oneRow, 200, { "X-Next-Offset": "25" })));
    await expect(api.patientEntries("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid evidence continuation",
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(Array.from({ length: 26 }, () => oneRow[0]))),
    );
    await expect(api.patientEntries("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid evidence page",
    });
  });

  it("rejects invalid or changed snapshot revisions before they can steer a continuation", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse([], 200, { "X-Entries-Revision": "01" })),
    );
    await expect(api.patientEntries("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid evidence snapshot revision",
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse([], 200, { "X-Entries-Revision": "8" })),
    );
    await expect(api.patientEntries("u1", { expectedRevision: "7" })).rejects.toMatchObject({
      status: 0,
      message: "server returned a changed evidence snapshot revision",
    });

    await expect(api.patientEntries("u1", { expectedRevision: "01" })).rejects.toMatchObject({
      status: 0,
      message: "invalid evidence snapshot revision",
    });

    await expect(api.patientEntries("u1", { expectedRevision: "9223372036854775808" })).rejects.toMatchObject({
      status: 0,
      message: "invalid evidence snapshot revision",
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse([], 200, { "X-Entries-Revision": "9223372036854775808" })),
    );
    await expect(api.patientEntries("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid evidence snapshot revision",
    });
  });

  it("builds bounded notes pages and encodes opaque path identifiers", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse([])));
    await api.notes("user / one", { offset: 200 });
    const [url] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toContain("/therapist/patients/user%20%2F%20one/notes?");
    expect(url).toContain("limit=100");
    expect(url).toContain("page_bytes=2097152");
    expect(url).toContain("offset=200");
  });

  it("builds bounded measures pages on the snapshot-revision contract (2026-09-26 audit L)", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse([], 200, { "X-Measures-Revision": "9" })));
    await api.patientMeasures("u1", { offset: 200, expectedRevision: "9" });
    let [url] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe(
      "https://api.example.com/api/v1/therapist/patients/u1/measures?limit=100&page_bytes=2097152&offset=200&expected_revision=9",
    );
    // Offset zero is the server's default: no query parameter for it.
    await api.patientMeasures("u1");
    [url] = vi.mocked(fetch).mock.calls[1]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/therapist/patients/u1/measures?limit=100&page_bytes=2097152");
    // Caller-controlled paging state is validated like every continuation.
    await expect(api.patientMeasures("u1", { offset: -1 })).rejects.toMatchObject({
      status: 0,
      message: "invalid measure page offset",
    });
    await expect(api.patientMeasures("u1", { expectedRevision: "01" })).rejects.toMatchObject({
      status: 0,
      message: "invalid measures snapshot revision",
    });
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ nope: true })));
    await expect(api.patientMeasures("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid measures page",
    });
  });

  it("returns a measures page with a validated continuation and revision", async () => {
    setSession("tok-1", "https://api.example.com");
    const rows = Array.from({ length: 100 }, (_, index) => ({
      id: `row-${index}`,
      client_measure_id: `client-${index}`,
      blob: "B==",
      measure_date: "2026-09-01",
      received_at: "2026-09-01T00:00:00Z",
    }));
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse(rows, 200, { "X-Next-Offset": "100", "X-Measures-Revision": "4" })),
    );
    await expect(api.patientMeasures("u1", { expectedRevision: "4" })).resolves.toEqual({
      measures: rows,
      nextOffset: 100,
      revision: "4",
    });
  });

  it("rejects a malformed or changed measures continuation/revision before it can steer a page", async () => {
    setSession("tok-1", "https://api.example.com");
    const oneRow = [{
      id: "row-1", client_measure_id: "client-1", blob: "B==",
      measure_date: "2026-09-01", received_at: "2026-09-01T00:00:00Z",
    }];
    // A cursor that does not advance exactly past the materialized rows.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(oneRow, 200, { "X-Next-Offset": "25" })));
    await expect(api.patientMeasures("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid measures continuation",
    });
    // A snapshot that moved under a pinned continuation.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse([], 200, { "X-Measures-Revision": "8" })));
    await expect(api.patientMeasures("u1", { expectedRevision: "7" })).rejects.toMatchObject({
      status: 0,
      message: "server returned a changed measures snapshot revision",
    });
  });

  it("patientInsights surfaces the echoed state_seq sentinel, validated as a canonical integer (2026-09-26 audit L)", async () => {
    setSession("tok-1", "https://api.example.com");
    const summary = {
      phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "B==",
    };
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ...summary, state_seq: 12 })));
    await expect(api.patientInsights("u1")).resolves.toMatchObject({ state_seq: 12 });
    // Baseline accounts echo 0 — a valid generation with nothing to guard.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ...summary, blob: null, state_seq: 0 })));
    await expect(api.patientInsights("u1")).resolves.toMatchObject({ state_seq: 0 });
    // The rollback-replay sentinel must never be a value an equality check
    // could silently pass: floats, strings, negatives, NaN/null all refuse.
    for (const bad of [-1, 1.5, "12", null]) {
      vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ...summary, state_seq: bad })));
      await expect(api.patientInsights("u1")).rejects.toMatchObject({
        status: 0,
        message: "server returned an invalid insights state sequence",
      });
    }
    // A missing echo is just as invalid: the field is part of the response
    // contract (backend schemas.InsightsResponse), not an optional extra.
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(summary)));
    await expect(api.patientInsights("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid insights state sequence",
    });
  });

  it("M-P1: logout POSTs /auth/logout with the bearer and resolves on 204", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(api.logout()).resolves.toBeNull();
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/auth/logout");
    expect(init.method).toBe("POST");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
    expect(init.credentials).toBe("omit");
    // 2026-09-26 follow-up (portal N-2): the audit doc's keepalive — a
    // logout fired at sign-out survives the tab closing mid-fetch.
    expect(init.keepalive).toBe(true);
  });

  it("M-P1: logout does NOT ride the session abort controller — clearSession cannot kill it", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      await new Promise((resolve) => setTimeout(resolve, 10));
      // A logout wired to the session's signal would be aborted by the
      // clearSession() below long before this line runs; the epoch bump
      // is exactly the request that must survive the local teardown.
      if (init?.signal?.aborted) {
        const abort = new Error("aborted");
        abort.name = "AbortError";
        throw abort;
      }
      return new Response(null, { status: 204 });
    }));
    const pending = api.logout();
    clearSession();
    await expect(pending).resolves.toBeNull();
  });

  it("M-P1: logout without a session fails fast; failures map to ApiError", async () => {
    await expect(api.logout()).rejects.toMatchObject({ status: 0, message: "not signed in" });
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("offline"))));
    await expect(api.logout()).rejects.toMatchObject({
      status: 0,
      message: "server unreachable — check the server URL or your connection",
    });
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ detail: "rate limited" }, 429)));
    await expect(api.logout()).rejects.toMatchObject({ status: 429, message: "rate limited" });
  });

  it("returns a note page with a validated continuation header", async () => {
    setSession("tok-1", "https://api.example.com");
    const notes = [{
      id: "note-1", client_note_id: "client-note-1", pattern_pid: null, blob: "B==",
      created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z",
    }];
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(notes, 200, { "X-Next-Offset": "201" })));
    await expect(api.notes("u1", { offset: 200 })).resolves.toEqual({
      notes,
      nextOffset: 201,
    });
  });

  it("sends and validates the note snapshot revision on continuation", async () => {
    setSession("tok-1", "https://api.example.com");
    const notes = [{
      id: "note-1", client_note_id: "client-note-1", pattern_pid: null, blob: "B==",
      created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z",
    }];
    vi.stubGlobal(
      "fetch",
      vi.fn()
        .mockResolvedValueOnce(jsonResponse(notes, 200, {
          "X-Next-Offset": "1",
          "X-Notes-Revision": "0",
        }))
        .mockResolvedValueOnce(jsonResponse([], 200, { "X-Notes-Revision": "0" })),
    );
    const first = await api.notes("u1");
    expect(first).toMatchObject({ nextOffset: 1, revision: "0" });
    await api.notes("u1", { offset: 1, expectedRevision: first.revision });
    const [url] = vi.mocked(fetch).mock.calls[1]! as [string, RequestInit];
    expect(url).toContain("expected_revision=0");
  });

  it("rejects a malformed or mismatched note continuation", async () => {
    setSession("tok-1", "https://api.example.com");
    const notes = [{
      id: "note-1", client_note_id: "client-note-1", pattern_pid: null, blob: "B==",
      created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z",
    }];
    vi.stubGlobal("fetch", vi.fn(async () => jsonResponse(notes, 200, { "X-Next-Offset": "999" })));
    await expect(api.notes("u1")).rejects.toMatchObject({
      status: 0,
      message: "server returned an invalid note continuation",
    });
  });

  it("maps the unified error envelope to ApiError with the code", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ detail: "patient not found", code: "not_found" }, 404)),
    );
    await expect(api.patientInsights("u1")).rejects.toMatchObject({
      status: 404,
      code: "not_found",
      message: "patient not found",
    });
  });

  it("NEW-3/F.4: PUTs the credential rotation with the current verifier and fresh material", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(api.rotateCredential("CUR-V==", "NEW-SALT==", "NEW-V==")).resolves.toBeNull();
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/account/credential");
    expect(init.method).toBe("PUT");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
    // Exactly the register payload's shape: current proof + 16-byte salt +
    // 32-byte verifier, all base64.
    expect(JSON.parse(init.body as string)).toEqual({
      verifier: "CUR-V==",
      new_salt: "NEW-SALT==",
      new_verifier: "NEW-V==",
    });
  });

  it("NEW-3/F.4: PUTs the wrap-key rotation behind the X-Account-Verifier header", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(api.rotateWrapKey("CUR-V==", "PUB==", "BLOB==")).resolves.toBeNull();
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/therapist/wrap-key");
    expect(init.method).toBe("PUT");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok-1");
    expect((init.headers as Record<string, string>)["X-Account-Verifier"]).toBe("CUR-V==");
    // The body is the register payload's shape; the password proof rides
    // the header, never the body.
    expect(JSON.parse(init.body as string)).toEqual({ wrap_pub_key: "PUB==", wrap_key_blob: "BLOB==" });
  });

  it("handles 204 No Content and network failure", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(null, { status: 204 })));
    await expect(api.deleteNote("n1")).resolves.toBeNull();
    vi.stubGlobal("fetch", vi.fn(async () => Promise.reject(new TypeError("offline"))));
    await expect(api.notes("u1")).rejects.toMatchObject({
      status: 0,
      message: "server unreachable — check the server URL or your connection",
    });
  });
});

describe("auth requests (no token)", () => {
  it("does not send credentials to an insecure remote auth origin", async () => {
    await expect(auth.login("http://api.example.com", "drx", "verif")).rejects.toMatchObject({ status: 0 });
    expect(vi.mocked(fetch)).not.toHaveBeenCalled();
  });

  it("posts salt and login bodies without an Authorization header", async () => {
    await auth.saltFor("https://api.example.com", "drx");
    let [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/auth/salt");
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();

    await auth.login("https://api.example.com", "drx", "verif");
    [url, init] = vi.mocked(fetch).mock.calls[1]! as [string, RequestInit];
    expect(JSON.parse(init.body as string)).toEqual({ username: "drx", verifier: "verif" });
  });

  it("registers a therapist with the full key material payload", async () => {
    await auth.registerTherapist("https://api.example.com", {
      username: "drx",
      salt: "AA==",
      verifier: "BB==",
      display_name: "Dr. X",
      wrap_pub_key: "C".repeat(124),
      wrap_key_blob: "DD==",
    }, "organization-issued-token");
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/therapist/register");
    expect(JSON.parse(init.body as string)).toMatchObject({ username: "drx", display_name: "Dr. X" });
    expect((init.headers as Record<string, string>)["X-Therapist-Enrollment-Token"]).toBe("organization-issued-token");
  });

  it("reads public server enrollment policy without an authorization header", async () => {
    await auth.meta("https://api.example.com");
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/meta");
    expect((init.headers as Record<string, string>).Authorization).toBeUndefined();
  });

  it("covers the note write paths and session predicates", async () => {
    setSession("tok-1", "https://api.example.com");
    expect((await import("../src/api")).hasSession()).toBe(true);
    await api.me();
    await api.createNote("u1", { client_note_id: "n1", pattern_pid: "temporal:work", blob: "B==" });
    await api.updateNote("n1", "B2==");
    let [url, init] = vi.mocked(fetch).mock.calls[1]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/therapist/patients/u1/notes");
    expect(JSON.parse((init as { body: string }).body)).toMatchObject({ pattern_pid: "temporal:work" });
    [url, init] = vi.mocked(fetch).mock.calls[2]! as [string, RequestInit];
    expect(init.method).toBe("PATCH");
    expect(url).toBe("https://api.example.com/api/v1/therapist/notes/n1");
    clearSession();
    expect((await import("../src/api")).hasSession()).toBe(false);
  });

  it("falls back to a status message when the error body is not JSON", async () => {
    setSession("tok-1", "https://api.example.com");
    vi.stubGlobal("fetch", vi.fn(async () => new Response("<html>500</html>", { status: 500 })));
    await expect(api.patients()).rejects.toMatchObject({
      status: 500,
      message: "request failed (500)",
    });
  });

  it("surfaces ApiError instances (not raw strings)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ detail: "username already taken", code: "conflict" }, 409)),
    );
    const err = await auth.login("https://api.example.com", "drx", "v").catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
  });
});

describe("session-expiry hook (2026-09-17)", () => {
  it("a 401 fires the unauthorized handler exactly once (latched)", async () => {
    const { setSession, clearSession, setUnauthorizedHandler, api, ApiError } = await import("../src/api");
    setSession("tok", "http://localhost:5173");
    const fired: number[] = [];
    setUnauthorizedHandler(() => fired.push(1));
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ detail: "unauthorized", code: "unauthorized" }), { status: 401 })));
    for (let i = 0; i < 2; i++) {
      await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    }
    setUnauthorizedHandler(null);
    clearSession();
    expect(fired).toHaveLength(1);
  });

  it("a new session re-arms the latch: one fire per sign-in, still latched within it", async () => {
    const { setSession, clearSession, setUnauthorizedHandler, api, ApiError } = await import("../src/api");
    const fired: number[] = [];
    setUnauthorizedHandler(() => fired.push(1));
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ detail: "unauthorized", code: "unauthorized" }), { status: 401 })));
    // The handler is registered once (App never re-registers); only the
    // session changes between expiries, exactly like a same-tab re-login.
    setSession("tok-1", "http://localhost:5173");
    for (let i = 0; i < 2; i++) {
      await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    }
    expect(fired).toHaveLength(1);
    setSession("tok-2", "http://localhost:5173");
    for (let i = 0; i < 2; i++) {
      await expect(api.me()).rejects.toBeInstanceOf(ApiError);
    }
    setUnauthorizedHandler(null);
    clearSession();
    expect(fired).toHaveLength(2);
  });

  it("non-401 errors never fire the handler", async () => {
    const { setSession, clearSession, setUnauthorizedHandler, api } = await import("../src/api");
    setSession("tok", "http://localhost:5173");
    const fired: number[] = [];
    setUnauthorizedHandler(() => fired.push(1));
    vi.stubGlobal("fetch", vi.fn(async () =>
      new Response(JSON.stringify({ detail: "boom", code: "internal_error" }), { status: 500 })));
    await expect(api.me()).rejects.toThrow();
    setUnauthorizedHandler(null);
    clearSession();
    expect(fired).toHaveLength(0);
  });
});
