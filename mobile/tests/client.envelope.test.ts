/**
 * The v2 key-scheme surface of the REAL api client (fetch stubbed globally,
 * per client.rotation.test.ts): registration's both-or-neither pair, the
 * key-envelope GET, the v2 password change, the v1→v2 upgrade's two-proof
 * headers, the new sanitized error codes, opaque-token tolerance for the
 * richer login/register responses, and the origin-bound envelope cache.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import storage from "./helpers/storageMock";
import { api, ApiError, DEFAULT_BASE_URL } from "../src/api/client";

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
const PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 600000 };
const WRAPPED_60_B64 = Buffer.alloc(60, 9).toString("base64");

beforeEach(() => {
  storage.__reset();
  vi.stubGlobal("fetch", vi.fn(async () => jsonResponse({ ok: true })));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("v2 registration wire shape", () => {
  it("sends kdf_params + wrapped_data_key as a pair when both are supplied", async () => {
    await api.register("alice", "c2FsdA==", "dmVyaWZpZXI=", PARAMS, WRAPPED_60_B64);
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/auth/register`);
    expect(JSON.parse(init.body as string)).toEqual({
      username: "alice",
      salt: "c2FsdA==",
      verifier: "dmVyaWZpZXI=",
      kdf_params: PARAMS,
      wrapped_data_key: WRAPPED_60_B64,
    });
  });

  it("v1 registration sends NEITHER field (the historical body, byte-for-byte)", async () => {
    await api.register("alice", "c2FsdA==", "dmVyaWZpZXI=");
    const [, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(JSON.parse(init.body as string)).toEqual({
      username: "alice",
      salt: "c2FsdA==",
      verifier: "dmVyaWZpZXI=",
    });
  });

  it("refuses a half pair locally — the server's 422 never needs to happen", async () => {
    // The pair check throws SYNCHRONOUSLY (the rewrapConsent id-check
    // idiom): no promise exists for .rejects to await.
    expect(() => api.register("alice", "c2FsdA==", "dmVyaWZpZXI=", PARAMS)).toThrow(/together/);
    expect(() => api.register("alice", "c2FsdA==", "dmVyaWZpZXI=", undefined, WRAPPED_60_B64)).toThrow(
      /together/,
    );
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});

describe("key-envelope endpoint and cache", () => {
  it("GETs /auth/key-envelope with the bearer and returns the body untouched", async () => {
    await secureSession();
    await api.keyEnvelope();
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/auth/key-envelope`);
    expect(init.method).toBe("GET");
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
  });

  it("the envelope cache round-trips a v2 record and refuses foreign origins", async () => {
    const record = { scheme: "v2" as const, saltB64: "c2FsdA==", kdfParams: PARAMS, wrappedB64: WRAPPED_60_B64 };
    await api.cacheKeyEnvelope("alice", record);
    expect(await api.getCachedKeyEnvelope("alice")).toEqual(record);

    // Origin-bound like the salt cache: a different selected server must
    // never hand back this server's envelope.
    const { setBaseUrl } = await import("../src/api/client");
    await setBaseUrl("https://other.example.test");
    expect(await api.getCachedKeyEnvelope("alice")).toBeNull();
  });

  it("a v1 marker round-trips; a corrupt or half-v2 record refuses", async () => {
    await api.cacheKeyEnvelope("alice", { scheme: "v1", saltB64: "c2FsdA==", kdfParams: null, wrappedB64: null });
    expect(await api.getCachedKeyEnvelope("alice")).toEqual({
      scheme: "v1",
      saltB64: "c2FsdA==",
      kdfParams: null,
      wrappedB64: null,
    });
    await api.clearCachedKeyEnvelope("alice");
    expect(await api.getCachedKeyEnvelope("alice")).toBeNull();

    storage.setItem("@mindpattern/keyenvelope_alice", JSON.stringify({ v: 1, o: DEFAULT_BASE_URL, scheme: "v2", saltB64: "c2FsdA==" }));
    expect(await api.getCachedKeyEnvelope("alice")).toBeNull(); // no wrapped key: refuse
  });

  it("an origin switch wipes cached envelopes with the other origin-bound state", async () => {
    await secureSession();
    const { setBaseUrl } = await import("../src/api/client");
    await setBaseUrl("https://real.example.test");
    await api.cacheKeyEnvelope("alice", { scheme: "v2", saltB64: "c2FsdA==", kdfParams: PARAMS, wrappedB64: WRAPPED_60_B64 });
    await setBaseUrl("https://phish.example.test");
    expect(await storage.getItem("@mindpattern/keyenvelope_alice")).toBeNull();
  });
});

describe("v2 password change and upgrade wire shapes", () => {
  it("changePassword PUTs the one-transaction payload", async () => {
    await api.changePassword("old", "c2FsdA==", "dmVyaWZpZXI=", WRAPPED_60_B64);
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/account/password`);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toEqual({
      verifier: "old",
      new_salt: "c2FsdA==",
      new_verifier: "dmVyaWZpZXI=",
      wrapped_data_key: WRAPPED_60_B64,
    });
  });

  it("changePassword carries new_kdf_params only when supplied", async () => {
    await api.changePassword("old", "c2FsdA==", "dmVyaWZpZXI=", WRAPPED_60_B64, PARAMS);
    const body = JSON.parse(
      ((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit])[1].body as string,
    );
    expect(body.new_kdf_params).toEqual(PARAMS);
  });

  it("upgradeKeyEnvelope ships the blob with BOTH proofs as headers", async () => {
    await api.upgradeKeyEnvelope(PARAMS, WRAPPED_60_B64, "proc-tok", "verifier-b64");
    const [url, init] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe(`${DEFAULT_BASE_URL}/api/v1/account/key-envelope/upgrade`);
    expect(init.method).toBe("POST");
    expect(init.headers).toMatchObject({
      "X-Processing-Token": "proc-tok",
      "X-Account-Verifier": "verifier-b64",
    });
    expect(JSON.parse(init.body as string)).toEqual({ kdf_params: PARAMS, wrapped_data_key: WRAPPED_60_B64 });
  });
});

describe("new error codes and token-shape tolerance", () => {
  it("key_scheme_conflict and envelope_key_mismatch survive sanitization for branch logic", async () => {
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "this account uses the v2 key envelope", code: "key_scheme_conflict" }, 409),
    );
    const err409 = await api.rotateCredential("v", "s", "n").catch((e: unknown) => e);
    expect(err409).toBeInstanceOf(ApiError);
    expect((err409 as ApiError).code).toBe("key_scheme_conflict");

    fetchMock.mockResolvedValueOnce(
      jsonResponse({ detail: "wrong key", code: "envelope_key_mismatch" }, 403),
    );
    const err403 = await api.upgradeKeyEnvelope(PARAMS, WRAPPED_60_B64, "t", "v").catch((e: unknown) => e);
    expect((err403 as ApiError).code).toBe("envelope_key_mismatch");
  });

  it("login/register responses with the NEWER token fields stay opaque and usable", async () => {
    // The bearer is an opaque string; jti/purpose/ksv live INSIDE it, and
    // key_scheme/role/expires_in ride the RESPONSE. The client must adopt
    // the token verbatim and ignore the extras without breaking.
    const tokenWithNewClaims =
      "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhYmFidCIsImp0aSI6IjFkZiIsInB1cnBvc2UiOiJwYXRpZW50Iiwia3N2IjoxLCJleHAiOjk5OTk5OTk5OTl9.sig";
    const fetchMock = vi.mocked(globalThis.fetch);
    fetchMock.mockResolvedValueOnce(
      jsonResponse({
        token: tokenWithNewClaims,
        user_id: HEX,
        expires_in: 900,
        role: "patient",
        key_scheme: "v2",
      }),
    );
    const body = await api.login("alice", "dmVyaWZpZXI=");
    expect(body.token).toBe(tokenWithNewClaims);
    await api.setSession(body.token, body.user_id, "alice");
    expect(await api.isLoggedIn()).toBe(true);
  });
});

/** Put a session on the secure store so keyEnvelope's bearer attaches. */
async function secureSession(): Promise<void> {
  await api.setSession("tok", HEX, "alice");
  const fetchMock = vi.mocked(globalThis.fetch);
  fetchMock.mockClear();
}

// --- sanitizeEnvelopeResponse (keyScheme.ts): the fail-closed gate ----------
// Every screen decision keys off this pure sanitizer; it must refuse
// everything this app cannot act on EXACTLY, never degrade to guessing.
const { sanitizeEnvelopeResponse } = await import("../src/keyScheme");

describe("sanitizeEnvelopeResponse", () => {
  it("accepts the exact v1 and v2 shapes", () => {
    expect(sanitizeEnvelopeResponse({ key_scheme: "v1", salt: "c2FsdHNhbHRzYWx0c2FsdA==", kdf_params: null, wrapped_data_key: null })).toEqual({
      scheme: "v1",
      saltB64: "c2FsdHNhbHRzYWx0c2FsdA==",
      kdfParams: null,
      wrappedB64: null,
    });
    expect(
      sanitizeEnvelopeResponse({ key_scheme: "v2", salt: "c2FsdHNhbHRzYWx0c2FsdA==", kdf_params: PARAMS, wrapped_data_key: WRAPPED_60_B64 }),
    ).toEqual({ scheme: "v2", saltB64: "c2FsdHNhbHRzYWx0c2FsdA==", kdfParams: PARAMS, wrappedB64: WRAPPED_60_B64 });
  });

  it("refuses a future scheme instead of degrading to v1 (wrong-key writes)", () => {
    expect(sanitizeEnvelopeResponse({ key_scheme: "v3", salt: "c2FsdHNhbHRzYWx0c2FsdA==" })).toBeNull();
    expect(sanitizeEnvelopeResponse({ salt: "c2FsdHNhbHRzYWx0c2FsdA==" })).toBeNull(); // absent scheme
  });

  it("refuses v2 answers with an unusable blob or params", () => {
    // Argon2id params (a profile no shipped mobile client can derive).
    expect(
      sanitizeEnvelopeResponse({
        key_scheme: "v2",
        salt: "c2FsdHNhbHRzYWx0c2FsdA==",
        kdf_params: { algorithm: "argon2id", version: 1, iterations: 3, memory_kib: 65536, parallelism: 1 },
        wrapped_data_key: WRAPPED_60_B64,
      }),
    ).toBeNull();
    // Wrong-size wrap (the server's own 422 shape).
    expect(
      sanitizeEnvelopeResponse({ key_scheme: "v2", salt: "c2FsdHNhbHRzYWx0c2FsdA==", kdf_params: PARAMS, wrapped_data_key: Buffer.alloc(59).toString("base64") }),
    ).toBeNull();
    // Unknown params fields ("the bytes you sent are the bytes that bind").
    expect(
      sanitizeEnvelopeResponse({ key_scheme: "v2", salt: "c2FsdHNhbHRzYWx0c2FsdA==", kdf_params: { ...PARAMS, extra: 1 }, wrapped_data_key: WRAPPED_60_B64 }),
    ).toBeNull();
    // Bounds: below the shared floor, above the ceiling.
    expect(
      sanitizeEnvelopeResponse({ key_scheme: "v2", salt: "c2FsdHNhbHRzYWx0c2FsdA==", kdf_params: { ...PARAMS, iterations: 99_999 }, wrapped_data_key: WRAPPED_60_B64 }),
    ).toBeNull();
    expect(
      sanitizeEnvelopeResponse({ key_scheme: "v2", salt: "c2FsdHNhbHRzYWx0c2FsdA==", kdf_params: { ...PARAMS, iterations: 10_000_001 }, wrapped_data_key: WRAPPED_60_B64 }),
    ).toBeNull();
  });
});
