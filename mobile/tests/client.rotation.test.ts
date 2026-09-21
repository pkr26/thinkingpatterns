/**
 * Real api client (no module mock): the 2026-09-20 audit-fix surfaces —
 * L-7 account-id validation on setSession, the M-3 first-origin pin, the
 * M-5 single-entry fetch (URL shape + origin pin), and the H-1 rotation
 * endpoints' request shapes.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import storage from "./helpers/storageMock";
import { api, DEFAULT_BASE_URL } from "../src/api/client";

const jsonResponse = (
  body: unknown,
  status = 200,
  url = DEFAULT_BASE_URL,
  headers: Record<string, string> = {},
): Response => {
  const response = new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
  Object.defineProperty(response, "url", { value: url });
  return response;
};

const HEX = "ab".repeat(16);

beforeEach(() => {
  storage.__reset();
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("L-7: account-id shape", () => {
  it("setSession adopts only the backend's 32-hex id shape", async () => {
    await expect(api.setSession("tok", "user-1", "alice")).rejects.toThrow(/invalid account id/);
    await expect(api.setSession("tok", "U".repeat(32))).rejects.toThrow();
    await expect(api.setSession("tok", HEX, "alice")).resolves.toBeUndefined();
    expect(await api.getUserId()).toBe(HEX);
  });
});

describe("M-3: first-origin pin", () => {
  it("pins on first authentication and warns only on a real change", async () => {
    const { setBaseUrl } = await import("../src/api/client");
    await setBaseUrl("https://real.example.test");
    await api.setSession("tok", HEX, "alice");
    expect(await api.originPinChanged()).toBe(false);
    expect(await api.pinnedOrigin()).toBe("https://real.example.test");

    await setBaseUrl("https://phish.example.test");
    expect(await api.originPinChanged()).toBe(true);

    await api.confirmCurrentOrigin();
    expect(await api.originPinChanged()).toBe(false);
    expect(await api.pinnedOrigin()).toBe("https://phish.example.test");
  });

  it("loopback alias spellings are the same canonical origin", async () => {
    const { setBaseUrl } = await import("../src/api/client");
    await setBaseUrl("http://localhost:8000");
    await api.setSession("tok", HEX);
    await setBaseUrl("http://127.0.0.1:8000");
    expect(await api.originPinChanged()).toBe(false);
  });
});

describe("M-5: single-entry fetch", () => {
  it("GETs the exact path and forwards the origin pin", async () => {
    const fetchMock = vi.mocked(fetch);
    await api.getEntry("e_abc-1", "http://127.0.0.1:8000");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    // The pin canonicalizes loopback aliases, so the pinned 127.0.0.1 passes
    // while the request itself goes to the currently-selected spelling.
    expect(url).toBe("http://localhost:8000/api/v1/entries/e_abc-1");
    expect(init.method).toBe("GET");
    await expect(api.getEntry("bad id with spaces")).rejects.toThrow(/invalid entry id/);
  });
});

describe("H-1: rotation endpoint request shapes", () => {
  it("rekey sends two tokens plus the verifier as headers, no body", async () => {
    const fetchMock = vi.mocked(fetch);
    await api.rekeyStoredData("old-tok", "new-tok", "verif");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith("/api/v1/processing/rekey")).toBe(true);
    expect(init.method).toBe("POST");
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Processing-Token"]).toBe("old-tok");
    expect(headers["X-New-Processing-Token"]).toBe("new-tok");
    expect(headers["X-Account-Verifier"]).toBe("verif");
  });

  it("rotateCredential PUTs the new salt and verifier in the body", async () => {
    const fetchMock = vi.mocked(fetch);
    await api.rotateCredential("old", "c2FsdA==", "dmVyaWZpZXI=");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith("/api/v1/account/credential")).toBe(true);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(String(init.body))).toEqual({
      verifier: "old",
      new_salt: "c2FsdA==",
      new_verifier: "dmVyaWZpZXI=",
    });
  });

  it("rewrapConsent PUTs to the consent path and refuses foreign id shapes", async () => {
    const fetchMock = vi.mocked(fetch);
    await api.rewrapConsent("c".repeat(32), "eph", "wrap", "verif");
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url.endsWith(`/api/v1/consents/${"c".repeat(32)}/rewrap`)).toBe(true);
    expect(init.method).toBe("PUT");
    expect((init.headers as Record<string, string>)["X-Account-Verifier"]).toBe("verif");
    // The id check throws synchronously (before any promise exists).
    expect(() => api.rewrapConsent("not-hex", "eph", "wrap", "verif")).toThrow(/invalid consent id/);
  });
});
