/**
 * The sharing methods of the real api client (fetch stubbed globally, per
 * client.request.test.ts): wire shapes, verifier transport, and the
 * consent-id URL-path guard.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import storage from "./helpers/storageMock";
import {
  api,
  ApiError,
  DEFAULT_BASE_URL,
  SHARING_DISCLOSURE_VERSION,
} from "../src/api/client";

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

beforeEach(() => {
  storage.__reset();
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => jsonResponse({ ok: true })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("sharing client methods", () => {
  it("pairingLookup posts the code (never in the URL path)", async () => {
    await api.pairingLookup("ab2c4d6f");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents/pairing/lookup`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toEqual({ code: "ab2c4d6f" });
  });

  it("grantConsent ships the wrap + disclosure with the verifier header", async () => {
    await api.grantConsent("AB2C4D6F", "EPH", "WRAPPED", "verifier-b64");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents`);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      "X-Account-Verifier": "verifier-b64",
    });
    expect(JSON.parse(init.body as string)).toEqual({
      code: "AB2C4D6F",
      ephemeral_pub: "EPH",
      wrapped_key: "WRAPPED",
      disclosure: SHARING_DISCLOSURE_VERSION,
    });
    // v3: the disclosure names every supported measure and
    // caseload summaries — kept in lockstep with the server's constant.
    expect(SHARING_DISCLOSURE_VERSION).toBe("v3");
  });

  it("listConsents GETs the consent list", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse([], 200, DEFAULT_BASE_URL, {
          "X-Consents-Revision": "4",
        }),
      ),
    );
    await api.listConsents();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents?limit=200&offset=0`);
    expect(init.method).toBe("GET");
  });

  it("walks beyond 200 revoked relationships to expose a displaced active grant", async () => {
    const row = (id: string, status = "revoked") => ({
      id,
      therapist_id: `therapist-${id}`,
      display_name: `Clinician ${id}`,
      username: `clinician-${id}`,
      status,
      granted_at: "2026-01-01T00:00:00Z",
      revoked_at: status === "active" ? null : "2026-02-01T00:00:00Z",
    });
    const revoked = Array.from({ length: 200 }, (_, index) =>
      row(`revoked-${index}`),
    );
    const active = row("active-grant", "active");
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);
        if (url.includes("offset=0")) {
          return jsonResponse(revoked, 200, DEFAULT_BASE_URL, {
            "X-Next-Offset": "200",
            "X-Consents-Revision": "77",
          });
        }
        expect(url).toContain("offset=200");
        expect(url).toContain("expected_revision=77");
        return jsonResponse([active], 200, DEFAULT_BASE_URL, {
          "X-Consents-Revision": "77",
        });
      }),
    );

    const consents = await api.listConsents();
    expect(consents).toHaveLength(201);
    expect(consents.find((consent) => consent.status === "active")?.id).toBe(
      "active-grant",
    );
  });

  it("restarts a changed consent snapshot from page zero and deduplicates boundary rows", async () => {
    const row = (id: string) => ({
      id,
      therapist_id: id,
      display_name: id,
      username: id,
      status: "revoked",
      granted_at: "2026-01-01T00:00:00Z",
      revoked_at: "2026-02-01T00:00:00Z",
    });
    let walk = 0;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: string | URL | Request) => {
        const url = String(input);
        if (url.includes("offset=0")) {
          walk += 1;
          return jsonResponse([row("a")], 200, DEFAULT_BASE_URL, {
            "X-Next-Offset": "1",
            "X-Consents-Revision": String(walk),
          });
        }
        if (walk === 1) {
          return jsonResponse(
            { detail: "changed", code: "collection_changed" },
            409,
            DEFAULT_BASE_URL,
          );
        }
        return jsonResponse([row("a"), row("b")], 200, DEFAULT_BASE_URL, {
          "X-Consents-Revision": "2",
        });
      }),
    );
    await expect(api.listConsents()).resolves.toEqual([row("a"), row("b")]);
    expect(walk).toBe(2);
  });

  it("revokeConsent DELETEs with the verifier header", async () => {
    const id = "a".repeat(32);
    await api.revokeConsent(id, "verifier-b64");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock
      .calls[0] as [string, RequestInit];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/consents/${id}`);
    expect(init.method).toBe("DELETE");
    expect(init.headers).toMatchObject({
      "X-Account-Verifier": "verifier-b64",
    });
  });

  it("refuses a tampered consent id before any request ships", async () => {
    await expect(api.revokeConsent("../../account", "v")).rejects.toMatchObject(
      {
        status: 0,
        name: "ApiError",
      },
    );
    expect(
      (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls,
    ).toHaveLength(0);
    // The refusal is a local ApiError, not a thrown string.
    await api.revokeConsent("short").catch((err: unknown) => {
      expect(err).toBeInstanceOf(ApiError);
    });
  });

  it("surfaces a revoked-patient 404 as a not-found ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        jsonResponse({ detail: "consent not found", code: "not_found" }, 404),
      ),
    );
    await expect(api.revokeConsent("b".repeat(32), "v")).rejects.toMatchObject({
      status: 404,
      code: "not_found",
    });
  });
});
