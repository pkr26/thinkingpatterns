/**
 * The portal API client: URL handling, wire shapes, error envelope
 * mapping, and the not-signed-in / unreachable branches.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { api, ApiError, auth, clearSession, setSession } from "../src/api";
import { normalizeBaseUrl } from "../src/views/LoginView";

const jsonResponse = (body: unknown, status = 200): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

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
  });

  it("builds entry queries with since/until/limit/offset", async () => {
    setSession("tok-1", "https://api.example.com");
    await api.patientEntries("u1", { since: "2026-09-01", until: "2026-09-10", offset: 100 });
    const [url] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toContain("/therapist/patients/u1/entries?");
    expect(url).toContain("since=2026-09-01");
    expect(url).toContain("until=2026-09-10");
    expect(url).toContain("offset=100");
    expect(url).toContain("limit=500");
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
    });
    const [url, init] = vi.mocked(fetch).mock.calls[0]! as [string, RequestInit];
    expect(url).toBe("https://api.example.com/api/v1/therapist/register");
    expect(JSON.parse(init.body as string)).toMatchObject({ username: "drx", display_name: "Dr. X" });
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
