/** The authenticated endpoint surface: every method hits the documented
 *  path with the documented payload/headers (the shapes P5–P7 screens and
 *  the interop harness lean on). */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api, SHARING_DISCLOSURE_VERSION } from "../src/api/client";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const ORIGIN = "http://localhost:5173";

beforeEach(() => {
  resetTestState();
  installSession();
});
afterEach(() => {
  vi.unstubAllGlobals();
});

function lastCall(mock: ReturnType<typeof stubFetch>): [string, RequestInit] {
  return mock.mock.calls[mock.mock.calls.length - 1]! as [string, RequestInit];
}

describe("endpoint surface", () => {
  it("insights + question carry the bearer", async () => {
    const mock = stubFetch(() => jsonResponse({ phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null }));
    await api.insights();
    let [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/insights`);
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token-123");

    mock.mockClear();
    mock.mockImplementation(() => jsonResponse({ for_date: "2026-09-25", blob: "AA" }));
    await api.questionToday();
    [url] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/questions/today`);
  });

  it("the processing session/recompute pair carries the single-use token", async () => {
    const mock = stubFetch(() => jsonResponse({ session_token: "pst", expires_in: 300 }));
    await api.openProcessingSession("a2V5");
    let [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/processing/sessions`);
    expect(JSON.parse(String(init.body))).toEqual({ data_key: "a2V5" });

    mock.mockImplementation(() => jsonResponse({ phase: "baseline" }));
    await api.recompute("pst", "ZmVlZGJhY2s=");
    [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/insights/recompute`);
    expect((init.headers as Record<string, string>)["X-Processing-Token"]).toBe("pst");
    expect(JSON.parse(String(init.body))).toEqual({ feedback_blob: "ZmVlZGJhY2s=" });

    mock.mockImplementation(() => new Response(null, { status: 204 }));
    await api.recompute("pst");
    [, init] = lastCall(mock);
    expect(init.body).toBeUndefined();
  });

  it("rekey carries both processing tokens plus the account verifier", async () => {
    const mock = stubFetch(() => new Response(null, { status: 204 }));
    await api.rekeyStoredData("old", "new", "ver");
    const [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/processing/rekey`);
    const headers = init.headers as Record<string, string>;
    expect(headers["X-Processing-Token"]).toBe("old");
    expect(headers["X-New-Processing-Token"]).toBe("new");
    expect(headers["X-Account-Verifier"]).toBe("ver");
  });

  it("account lifecycle: llm-consent, delete (verifier in the header), credential rotation", async () => {
    const mock = stubFetch(() => jsonResponse({ enabled: false }));
    await api.getLlmConsent();
    let [url] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/account/llm-consent`);

    mock.mockImplementation(() => jsonResponse({ enabled: true }));
    await api.setLlmConsent(true, "ver");
    let [, init] = lastCall(mock);
    expect(JSON.parse(String(init.body))).toEqual({ enabled: true, verifier: "ver" });

    mock.mockImplementation(() => new Response(null, { status: 204 }));
    await api.deleteAccount("ver");
    [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/account`);
    expect(init.method).toBe("DELETE");
    expect((init.headers as Record<string, string>)["X-Account-Verifier"]).toBe("ver");

    await api.rotateCredential("old", "salt", "new");
    [, init] = lastCall(mock);
    expect(JSON.parse(String(init.body))).toEqual({ verifier: "old", new_salt: "salt", new_verifier: "new" });
  });

  it("consents: pairing lookup, grant (disclosure version), rewrap, revoke", async () => {
    const mock = stubFetch(() => jsonResponse({ therapist_id: "t1", display_name: "Dr. River", wrap_pub_key: "k" }));
    await api.pairingLookup("ABC123");
    let [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/consents/pairing/lookup`);
    expect(JSON.parse(String(init.body))).toEqual({ code: "ABC123" });

    mock.mockImplementation(() => jsonResponse({ id: "c".repeat(32) }));
    await api.grantConsent("ABC123", "eph", "wrap", "ver");
    [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/consents`);
    expect(JSON.parse(String(init.body))).toEqual({
      code: "ABC123",
      ephemeral_pub: "eph",
      wrapped_key: "wrap",
      disclosure: SHARING_DISCLOSURE_VERSION,
    });
    expect((init.headers as Record<string, string>)["X-Account-Verifier"]).toBe("ver");

    mock.mockImplementation(() => jsonResponse([]));
    await api.listConsents();
    let [, ] = lastCall(mock);

    mock.mockImplementation(() => new Response(null, { status: 204 }));
    const consentId = "a".repeat(32);
    await api.rewrapConsent(consentId, "eph2", "wrap2", "ver");
    [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/consents/${consentId}/rewrap`);

    await api.revokeConsent(consentId, "ver");
    [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/consents/${consentId}`);
    expect(init.method).toBe("DELETE");

    // Malformed consent ids are refused locally.
    expect(() => api.rewrapConsent("bad", "e", "w", "v")).toThrow("invalid consent id");
    expect(() => api.revokeConsent("bad", "v")).toThrow("invalid consent id");
  });

  it("measures: create + validated page", async () => {
    const mock = stubFetch(() => jsonResponse({ id: "m" }, { status: 201 }));
    await api.createMeasure("m-1", "AA", "2026-09-25");
    let [url, init] = lastCall(mock);
    expect(url).toBe(`${ORIGIN}/api/v1/measures`);
    expect(JSON.parse(String(init.body))).toEqual({ client_measure_id: "m-1", blob: "AA", measure_date: "2026-09-25" });

    mock.mockImplementation(() =>
      jsonResponse([{ id: "1", client_measure_id: "m-1", blob: "AA", measure_date: "d", received_at: "r" }], {
        headers: { "X-Next-Offset": "1", "X-Measures-Revision": "4" },
      }),
    );
    const page = await api.listMeasuresPage({ offset: 0 });
    expect(page.revision).toBe("4");
    expect(page.nextOffset).toBe(1);
  });
});
