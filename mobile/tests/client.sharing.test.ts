/**
 * The sharing methods of the real api client (fetch stubbed globally, per
 * client.request.test.ts): wire shapes, verifier transport, and the
 * consent-id URL-path guard.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import storage from "./helpers/storageMock";
import { api, ApiError, DEFAULT_BASE_URL, SHARING_DISCLOSURE_VERSION } from "../src/api/client";

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

describe("sharing client methods", () => {
  it("pairingLookup posts the code (never in the URL path)", async () => {
    await api.pairingLookup("ab2c4d6f");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents/pairing/lookup`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ code: "ab2c4d6f" });
  });

  it("grantConsent ships the wrap + disclosure with the verifier header", async () => {
    await api.grantConsent("AB2C4D6F", "EPH", "WRAPPED", "verifier-b64");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents`);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({ "X-Account-Verifier": "verifier-b64" });
    expect(JSON.parse(init.body as string)).toEqual({
      code: "AB2C4D6F",
      ephemeral_pub: "EPH",
      wrapped_key: "WRAPPED",
      disclosure: SHARING_DISCLOSURE_VERSION,
    });
    // v2 (2026-09-20 audit H-14): the disclosure names measures and
    // caseload summaries — kept in lockstep with the server's constant.
    expect(SHARING_DISCLOSURE_VERSION).toBe("v2");
  });

  it("listConsents GETs the consent list", async () => {
    await api.listConsents();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents`);
    expect(init.method).toBe("GET");
  });

  it("revokeConsent DELETEs with the verifier header", async () => {
    const id = "a".repeat(32);
    await api.revokeConsent(id, "verifier-b64");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents/${id}`);
    expect(init.method).toBe("DELETE");
    expect(init.headers).toMatchObject({ "X-Account-Verifier": "verifier-b64" });
  });

  it("refuses a tampered consent id before any request ships", async () => {
    await expect(api.revokeConsent("../../account", "v")).rejects.toMatchObject({
      status: 0,
      name: "ApiError",
    });
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(0);
    // The refusal is a local ApiError, not a thrown string.
    await api.revokeConsent("short").catch((err: unknown) => {
      expect(err).toBeInstanceOf(ApiError);
    });
  });

  it("surfaces a revoked-patient 404 as a not-found ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ detail: "consent not found", code: "not_found" }, 404)),
    );
    await expect(api.revokeConsent("b".repeat(32), "v")).rejects.toMatchObject({
      status: 404,
      code: "not_found",
    });
  });
});
