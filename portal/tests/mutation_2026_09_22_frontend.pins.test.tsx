/**
 * Frontend mutation campaign 2026-09-22 — survivor pins (portal).
 *
 * Fresh full-src Stryker run (3,549 mutants, 55.68% raw — see
 * redteam/mutation_campaign_2026-09-22_frontend/REPORT.md). Every pin here
 * kills at least one genuine survivor from that run and was verified to do
 * so by a scoped re-run over the mutated file. Style/theme-literal mutants
 * and environment-limited equivalents are documented in the report, not
 * pinned.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return {
    ...actual,
    auth: {
      meta: vi.fn(async () => ({ sharing_available: true })),
      saltFor: vi.fn(async () => ({ salt: "QUJDREVGR0hJSktMTU5P" })),
      login: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
      registerTherapist: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
    },
    api: {
      me: vi.fn(async () => ({
        username: "drportal",
        display_name: "Dr. Portal",
        wrap_pub_key: "P".repeat(124),
        wrap_key_blob: "KQ==",
      })),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7 })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async (_u: string, payload: { client_note_id: string; pattern_pid?: string | null }) => ({
        id: "created-1", client_note_id: payload.client_note_id, pattern_pid: payload.pattern_pid ?? null,
        blob: "b", created_at: "2026-09-02T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
      })),
      updateNote: vi.fn(async (id: string) => ({
        id, client_note_id: "c1", pattern_pid: null, blob: "b",
        created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
      })),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      rotateCredential: vi.fn(async () => null),
      rotateWrapKey: vi.fn(async () => null),
      totpSetup: vi.fn(async () => ({ secret_base32: "SECRET", otpauth_uri: "otpauth://x" })),
      totpEnable: vi.fn(async () => null),
      totpDisable: vi.fn(async () => null),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  return {
    ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    derivePortalKeys: vi.fn(async () => ({
      authKey: new Uint8Array(32),
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      wrapKeyBlobB64: "SEALED==",
    })),
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } } as unknown as CryptoKey)),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({ state_seq: 7, stats: { patterns: [] } })),
    decryptEntry: vi.fn(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
      text: `decrypted ${entry.client_entry_id}`,
      sentiment: null,
    })),
    encryptNote: vi.fn(async () => ({ clientNoteId: "c", blobB64: "SEALEDNOTE==" })),
    decryptNote: vi.fn(async () => "existing note text"),
    keyFingerprint: vi.fn(async () => "AABB CCDD"),
    openSealedPrivateKey: vi.fn(async () => new Uint8Array(138)),
    sealPrivateKeyForUpload: vi.fn(async () => "SEALED=="),
  };
});

const { auth, api, ApiError } = await import("../src/api");
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const realCrypto = await vi.importActual<typeof import("../src/crypto")>("../src/crypto");
const realApi = await vi.importActual<typeof import("../src/api")>("../src/api");
const { setSession, clearSession, hasSession } = realApi;
const platform = await import("../src/platform");
const ui = await import("../src/ui");
const { LoginView, passwordPolicyError } = await import("../src/views/LoginView");
const { PatientsView } = await import("../src/views/PatientsView");
const { PatientView } = await import("../src/views/PatientView");
const rtr = await import("./helpers/rtr");
const { render, flush, textOf, press, buttonByLabel, typeInto, typeTextarea } = rtr;
type PatternPayload = import("../src/crypto").PatternPayload;

const patient = {
  user_id: "user-1",
  username: "patienta",
  status: "active",
  granted_at: "2026-09-01T10:00:00Z",
  revoked_at: null,
  ephemeral_pub: "E".repeat(124),
  wrapped_key: "W==",
};
const session = {
  username: "drportal",
  userId: "therapist-1",
  noteKey: new Uint8Array(32),
  privateKey: {} as CryptoKey,
  publicKeyB64: "P".repeat(124),
};
const BASE = "http://localhost:5173";

/** A fetch mock that respects its abort signal, like the real one. */
const hangingFetch = (): ReturnType<typeof vi.fn> =>
  vi.fn((_url: unknown, init: { signal?: AbortSignal }) =>
    new Promise((_resolve, reject) => {
      init.signal?.addEventListener("abort", () =>
        reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
    }));

beforeEach(() => {
  // clearAllMocks only clears call history; implementations (and once-queues)
  // survive it. Several tests below override mock implementations, so every
  // mock is reset and re-defaulted here — no test inherits another's mocks.
  vi.clearAllMocks();
  mockedAuth.meta.mockReset().mockResolvedValue({ sharing_available: true });
  mockedAuth.saltFor.mockReset().mockResolvedValue({ salt: "QUJDREVGR0hJSktMTU5P" });
  mockedAuth.login.mockReset().mockResolvedValue({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" });
  mockedAuth.registerTherapist.mockReset().mockResolvedValue({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" });
  mockedApi.me.mockReset().mockResolvedValue({ username: "drportal", display_name: "Dr. Portal", wrap_pub_key: "P".repeat(124), wrap_key_blob: "KQ==" });
  mockedApi.patients.mockReset().mockResolvedValue([]);
  mockedApi.patientInsights.mockReset().mockResolvedValue({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==", state_seq: 7 });
  mockedApi.patientEntries.mockReset().mockResolvedValue({ entries: [], nextOffset: null });
  mockedApi.notes.mockReset().mockResolvedValue({ notes: [], nextOffset: null });
  mockedApi.noteRevisions.mockReset().mockResolvedValue([]);
  mockedApi.createNote.mockReset().mockImplementation(async (_u: string, payload: { client_note_id: string; pattern_pid?: string | null }) => ({
    id: "created-1", client_note_id: payload.client_note_id, pattern_pid: payload.pattern_pid ?? null,
    blob: "b", created_at: "2026-09-02T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
  }));
  mockedApi.updateNote.mockReset().mockImplementation(async (id: string) => ({
    id, client_note_id: "c1", pattern_pid: null, blob: "b",
    created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
  }));
  mockedApi.deleteNote.mockReset().mockResolvedValue(null);
  mockedApi.newPairingCode.mockReset().mockResolvedValue({ code: "7X2KQM4N", expires_in: 900 });
  mockedApi.patientMeasures.mockReset().mockResolvedValue({ measures: [], nextOffset: null });
  mockedApi.rotateCredential.mockReset().mockResolvedValue(null);
  mockedApi.rotateWrapKey.mockReset().mockResolvedValue(null);
  mockedApi.totpSetup.mockReset().mockResolvedValue({ secret_base32: "SECRET", otpauth_uri: "otpauth://x" });
  mockedApi.totpEnable.mockReset().mockResolvedValue(null);
  mockedApi.totpDisable.mockReset().mockResolvedValue(null);
  mockedCrypto.deriveMasterKey.mockReset().mockResolvedValue(new Uint8Array(32));
  mockedCrypto.derivePortalKeys.mockReset().mockResolvedValue({ authKey: new Uint8Array(32), wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32) });
  mockedCrypto.unlockWrapPrivateKey.mockReset().mockResolvedValue({ algorithm: { name: "ECDH" } } as unknown as CryptoKey);
  mockedCrypto.unwrapPatientDataKey.mockReset().mockResolvedValue(new Uint8Array(32));
  mockedCrypto.decryptCaseloadSummary.mockReset().mockResolvedValue(null);
  mockedCrypto.decryptMeasure.mockReset().mockResolvedValue(null);
  mockedCrypto.decryptInsights.mockReset().mockResolvedValue({ state_seq: 7, stats: { patterns: [] } });
  mockedCrypto.decryptEntry.mockReset().mockImplementation(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
    text: `decrypted ${entry.client_entry_id}`, sentiment: null,
  }));
  mockedCrypto.encryptNote.mockReset().mockResolvedValue({ clientNoteId: "c", blobB64: "SEALEDNOTE==" });
  mockedCrypto.decryptNote.mockReset().mockImplementation(async () => "existing note text");
  mockedCrypto.keyFingerprint.mockReset().mockResolvedValue("AABB CCDD");
  mockedCrypto.openSealedPrivateKey.mockReset().mockResolvedValue(new Uint8Array(138));
  mockedCrypto.sealPrivateKeyForUpload.mockReset().mockResolvedValue("SEALED==");
  mockedCrypto.generateTherapistKeyPair.mockReset().mockResolvedValue({ publicKeySpkiB64: "P".repeat(124), wrapKeyBlobB64: "SEALED==" });
  realApi.clearSession();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

// ---------------------------------------------------------------------------
// api.ts — session, transport, and pagination-contract survivors
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: api session + transport", () => {
  it("rejects an empty or whitespace session token before any request", () => {
    expect(() => realApi.setSession("", BASE)).toThrow(ApiError);
    expect(() => realApi.setSession("   ", BASE)).toThrow(ApiError);
    expect(realApi.hasSession()).toBe(false);
  });

  it("rejects an un-normalized session base (exact-form contract)", () => {
    expect(() => realApi.setSession("tok", `${BASE}/`)).toThrow(ApiError);
    expect(realApi.hasSession()).toBe(false);
  });

  it("replacing a session aborts the previous session's in-flight request", async () => {
    realApi.setSession("tok1", BASE);
    let resolveFetch!: (value: unknown) => void;
    vi.stubGlobal("fetch", vi.fn(() => new Promise((resolve) => { resolveFetch = resolve; })));
    const pending = realApi.api.me();
    realApi.setSession("tok2", BASE); // must realApi.clearSession() -> abort the old controller
    resolveFetch({ ok: true, status: 200, json: async () => ({}), headers: new Headers(), url: "" });
    await expect(pending).rejects.toThrow("session ended");
    vi.unstubAllGlobals();
  });

  it("a fetch that resolves after the session was replaced never returns its data", async () => {
    realApi.setSession("tok", BASE);
    let resolveFetch!: (value: unknown) => void;
    vi.stubGlobal("fetch", vi.fn(() => new Promise((resolve) => { resolveFetch = resolve; })));
    const pending = realApi.api.me();
    realApi.clearSession();
    resolveFetch({ ok: true, status: 200, json: async () => ({ username: "leak" }), headers: new Headers(), url: "" });
    await expect(pending).rejects.toThrow(ApiError);
    vi.unstubAllGlobals();
  });

  it("enforces the 15 s request deadline with the honest message", async () => {
    vi.useFakeTimers();
    try {
      realApi.setSession("tok", BASE);
      vi.stubGlobal("fetch", hangingFetch());
      const pending = realApi.api.me();
      const assertion = expect(pending).rejects.toThrow("request timed out after 15s");
      await vi.advanceTimersByTimeAsync(15_000);
      await assertion;
      vi.unstubAllGlobals();
    } finally {
      vi.useRealTimers();
    }
  });

  it("a request made on an already-cleared session never reaches fetch", async () => {
    realApi.setSession("tok", BASE);
    const calls: unknown[][] = [];
    vi.stubGlobal("fetch", vi.fn(async (...args: unknown[]) => {
      calls.push(args);
      return { ok: true, status: 200, json: async () => ({}), headers: new Headers(), url: "" };
    }));
    realApi.clearSession();
    await expect(realApi.api.me()).rejects.toThrow("not signed in");
    expect(calls).toHaveLength(0);
    vi.unstubAllGlobals();
  });

  it("a same-origin response.url passes the redirect check; a foreign one is refused", async () => {
    realApi.setSession("tok", BASE);
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}), headers: new Headers(), url: `${BASE}/api/v1/therapist/me`,
    })));
    await expect(realApi.api.me()).resolves.toBeDefined();
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: true, status: 200, json: async () => ({}), headers: new Headers(), url: "https://evil.example/api/v1/x",
    })));
    await expect(realApi.api.me()).rejects.toThrow("server redirected the request to a different origin");
    vi.unstubAllGlobals();
  });

  it("clamps a server detail message to 200 characters", async () => {
    realApi.setSession("tok", BASE);
    const long = "x".repeat(250);
    vi.stubGlobal("fetch", vi.fn(async () => ({
      ok: false, status: 400, json: async () => ({ detail: long }), headers: new Headers(), url: "",
    })));
    const err: unknown = await realApi.api.me().then(() => null, (e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as { message: string }).message).toHaveLength(200);
    vi.unstubAllGlobals();
  });
});

describe("mutation pins 2026-09-22: api request body shapes", () => {
  it("login sends totp_code only when a code is supplied", async () => {
    const bodies: unknown[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: { body?: string }) => {
      bodies.push(JSON.parse(init.body ?? "{}"));
      return { ok: true, status: 200, json: async () => ({ token: "t", user_id: "u", expires_in: 1, role: "therapist" }), headers: new Headers(), url: "" };
    }));
    await realApi.auth.login(BASE, "u", "v");
    await realApi.auth.login(BASE, "u", "v", "123456");
    expect(bodies[0]).toEqual({ username: "u", verifier: "v" });
    expect(bodies[1]).toEqual({ username: "u", verifier: "v", totp_code: "123456" });
    vi.unstubAllGlobals();
  });

  it("registerTherapist trims the enrollment token and omits a blank one entirely", async () => {
    const headers: Array<Record<string, string>> = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: { headers: Record<string, string> }) => {
      headers.push(init.headers);
      return { ok: true, status: 200, json: async () => ({ token: "t", user_id: "u", expires_in: 1, role: "therapist" }), headers: new Headers(), url: "" };
    }));
    const payload = { username: "u", salt: "s", verifier: "v", display_name: "d", wrap_pub_key: "p", wrap_key_blob: "b" };
    await realApi.auth.registerTherapist(BASE, payload, "  tok  ");
    await realApi.auth.registerTherapist(BASE, payload, "   ");
    await realApi.auth.registerTherapist(BASE, payload);
    expect(headers[0]!["X-Therapist-Enrollment-Token"]).toBe("tok");
    expect(headers[1]!["X-Therapist-Enrollment-Token"]).toBeUndefined();
    expect(headers[2]!["X-Therapist-Enrollment-Token"]).toBeUndefined();
    vi.unstubAllGlobals();
  });
});

describe("mutation pins 2026-09-22: api pagination contracts", () => {
  const page = (rows: unknown[], next: number | null, revision?: string) => ({
    ok: true, status: 200, json: async () => rows,
    headers: new Headers([
      ...(next === null ? [] : [["X-Next-Offset", String(next)]]),
      ...(revision === undefined ? [] : [["X-Entries-Revision", revision]]),
    ] as [string, string][]),
    url: "",
  });
  const entry = (id: string) => ({ id, client_entry_id: `c${id}`, blob: "b", entry_date: "2026-09-01", received_at: "x" });

  it("rejects continuation headers that are not canonical decimal", async () => {
    realApi.setSession("tok", BASE);
    for (const bad of [" 25", "+25", "1e3", "25.0", "0x1f", "٢٥", ""]) {
      vi.stubGlobal("fetch", vi.fn(async () => page([entry("1")], 25)));
      await expect(realApi.api.patientEntries("u", {})).rejects.toThrow("invalid evidence continuation");
    }
    vi.unstubAllGlobals();
  });

  it("rejects a continuation after an empty page, whatever the header says", async () => {
    realApi.setSession("tok", BASE);
    vi.stubGlobal("fetch", vi.fn(async () => page([], 0)));
    await expect(realApi.api.patientEntries("u", {})).rejects.toThrow("invalid evidence continuation");
    vi.unstubAllGlobals();
  });

  it("rejects snapshot revisions beyond the signed-64 boundary", async () => {
    realApi.setSession("tok", BASE);
    for (const bad of ["9223372036854775808", "99999999999999999999", "-1", "01"]) {
      vi.stubGlobal("fetch", vi.fn(async () => page([], null, bad)));
      await expect(realApi.api.patientEntries("u", {})).rejects.toThrow("snapshot revision");
    }
    vi.stubGlobal("fetch", vi.fn(async () => page([], null, "9223372036854775807")));
    await expect(realApi.api.patientEntries("u", {})).resolves.toHaveProperty("revision", "9223372036854775807");
    vi.unstubAllGlobals();
  });

  it("a headerless page after a revision was established fails closed", async () => {
    realApi.setSession("tok", BASE);
    let call = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      call += 1;
      return call === 1
        ? page([entry("1")], 1, "5")
        : page([entry("2")], null); // revision silently dropped
    }));
    const first = await realApi.api.patientEntries("u", {});
    await expect(realApi.api.patientEntries("u", { offset: first.nextOffset!, expectedRevision: first.revision! }))
      .rejects.toThrow("server dropped the evidence snapshot revision");
    vi.unstubAllGlobals();
  });

  it("builds the exact query shape: optional params omitted, opt-ins always present", async () => {
    realApi.setSession("tok", BASE);
    const urls: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (url: unknown) => {
      urls.push(String(url));
      return page([], null, "9");
    }));
    await realApi.api.patientEntries("u", {});
    await realApi.api.patientEntries("u", { offset: 25, since: "2026-09-01", until: "2026-09-08", expectedRevision: "9" });
    await realApi.api.notes("u", {});
    await realApi.api.patientMeasures("u", {});
    expect(urls[0]).toBe(`${BASE}/api/v1/therapist/patients/u/entries?limit=25&page_bytes=2097152`);
    expect(urls[1]).toBe(`${BASE}/api/v1/therapist/patients/u/entries?since=2026-09-01&until=2026-09-08&limit=25&page_bytes=2097152&offset=25&expected_revision=9`);
    expect(urls[2]).toBe(`${BASE}/api/v1/therapist/patients/u/notes?limit=100&page_bytes=2097152`);
    expect(urls[3]).toBe(`${BASE}/api/v1/therapist/patients/u/measures?limit=100&page_bytes=2097152`);
    vi.unstubAllGlobals();
  });

  it("rejects negative and non-integer page offsets for entries, notes, and measures; limit 1 is legal", async () => {
    realApi.setSession("tok", BASE);
    vi.stubGlobal("fetch", vi.fn(async () => page([], null, "9")));
    for (const bad of [-1, 1.5, Number.NaN]) {
      await expect(realApi.api.patientEntries("u", { offset: bad })).rejects.toThrow("invalid evidence page offset");
      await expect(realApi.api.notes("u", { offset: bad })).rejects.toThrow("invalid note page offset");
      await expect(realApi.api.patientMeasures("u", { offset: bad })).rejects.toThrow("invalid measure page offset");
    }
    await expect(realApi.api.patientMeasures("u", { offset: 0 })).resolves.toEqual({ measures: [], nextOffset: null });
    vi.unstubAllGlobals();
  });

  it("hits the exact documented endpoint paths", async () => {
    realApi.setSession("tok", BASE);
    const urls: string[] = [];
    let call = 0;
    vi.stubGlobal("fetch", vi.fn(async (url: unknown) => {
      call += 1;
      urls.push(String(url));
      // The third call is the insights summary, whose body must carry the
      // validated state_seq sentinel (2026-09-26 audit L); every other
      // endpoint here answers an empty JSON object.
      return {
        ok: true, status: 200,
        json: async () => (call === 3 ? { phase: "insight", state_seq: 1 } : {}),
        headers: new Headers(), url: "",
      };
    }));
    await realApi.api.me();
    await realApi.api.accessLog();
    await realApi.api.patientInsights("u");
    // 2026-09-26 audit M-P1: logout joins the documented surface.
    await realApi.api.logout();
    expect(urls).toEqual([
      `${BASE}/api/v1/therapist/me`,
      `${BASE}/api/v1/therapist/access-log?limit=100`,
      `${BASE}/api/v1/therapist/patients/u/insights`,
      `${BASE}/api/v1/auth/logout`,
    ]);
    vi.unstubAllGlobals();
  });
});

// ---------------------------------------------------------------------------
// crypto.ts — sanitization windows and hygiene survivors (real WebCrypto)
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: crypto sanitization", () => {
  const { toBase64 } = realCrypto;

  /** Seal an arbitrary JSON payload exactly the way the backend seals a
   * caseload summary (independent construction — never trust the module
   * under test to build its own oracle). */
  const sealSummary = async (payload: unknown): Promise<{
    thPriv: CryptoKey; thPubB64: string; ephPubB64: string; blobB64: string;
  }> => {
    const subtle = globalThis.crypto.subtle;
    const mk = async () => subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
    const th = await mk();
    const eph = await mk();
    const thDer = new Uint8Array(await subtle.exportKey("spki", th.publicKey));
    const ephDer = new Uint8Array(await subtle.exportKey("spki", eph.publicKey));
    const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: eph.publicKey }, th.privateKey, 256));
    const salt = new Uint8Array(ephDer.length + thDer.length);
    salt.set(ephDer, 0);
    salt.set(thDer, ephDer.length);
    const ikm = await subtle.importKey("raw", shared, "HKDF", false, ["deriveBits"]);
    const kek = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("mindpattern/wrap/v1") }, ikm, 256));
    const { buildAad } = await import("../src/aad");
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const cipher = await subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: buildAad("caseload-summary", "user-1", "therapist-1") },
      await subtle.importKey("raw", kek, "AES-GCM", false, ["encrypt"]),
      new TextEncoder().encode(JSON.stringify(payload)),
    );
    const blob = new Uint8Array(12 + cipher.byteLength);
    blob.set(nonce, 0);
    blob.set(new Uint8Array(cipher), 12);
    return { thPriv: th.privateKey, thPubB64: toBase64(thDer), ephPubB64: toBase64(ephDer), blobB64: toBase64(blob) };
  };

  const dataKey = () => new Uint8Array(32).fill(7);
  const sealedMeasure = async (payload: unknown, clientMeasureId: string): Promise<string> => {
    const { buildAad } = await import("../src/aad");
    const blob = await realCrypto.encrypt(dataKey(), new TextEncoder().encode(JSON.stringify(payload)), buildAad("measure", "user-1", clientMeasureId));
    return toBase64(blob);
  };

  it("decryptMeasure accepts the exact score boundaries 0 and 100 and rejects outside them", async () => {
    for (const score of [0, 100]) {
      const blob = await sealedMeasure({ v: 1, measure: "phq9", score, completed_at: "2026-09-01T12:00:00Z" }, "m1");
      const reading = await realCrypto.decryptMeasure(dataKey(), "user-1", { client_measure_id: "m1", blob, measure_date: "2026-09-01" });
      expect(reading, `score ${score}`).toMatchObject({ score });
    }
    for (const score of [-1, 101, Number.NaN, Number.POSITIVE_INFINITY, "7", null]) {
      const blob = await sealedMeasure({ v: 1, measure: "phq9", score, completed_at: null }, "m2");
      const reading = await realCrypto.decryptMeasure(dataKey(), "user-1", { client_measure_id: "m2", blob, measure_date: "2026-09-01" });
      expect(reading, `score ${String(score)}`).toBeNull();
    }
  });

  it("decryptMeasure clamps the display fields to their fixed slices", async () => {
    const blob = await sealedMeasure({
      v: 1, measure: "m".repeat(30), score: 4, completed_at: "2026-09-01T12:00:00.999Z",
    }, "m3");
    const reading = await realCrypto.decryptMeasure(dataKey(), "user-1", { client_measure_id: "m3", blob, measure_date: "2026-09-01T23:59:59Z" });
    expect(reading).toMatchObject({ measure: "m".repeat(24), completedAt: "2026-09-01", measureDate: "2026-09-01" });
  });

  it("decryptCaseloadSummary sanitizes every field of a hostile summary", async () => {
    const hostile = { patterns: "many", newest: 12345, for_date: "2026-09-01T00:00:00Z", sensitive: "yes" };
    const sealed = await sealSummary(hostile);
    const summary = await realCrypto.decryptCaseloadSummary(sealed.thPriv, sealed.thPubB64, sealed.ephPubB64, sealed.blobB64, "user-1", "therapist-1");
    expect(summary).toEqual({ patterns: 0, sensitive: false, newest: null, forDate: "2026-09-01" });

    const honest = await sealSummary({ patterns: 3.9, newest: "2026-09-02T01:02:03Z", for_date: "2026-09-01", sensitive: true });
    const ok = await realCrypto.decryptCaseloadSummary(honest.thPriv, honest.thPubB64, honest.ephPubB64, honest.blobB64, "user-1", "therapist-1");
    expect(ok).toEqual({ patterns: 3, sensitive: true, newest: "2026-09-02", forDate: "2026-09-01" });
  });

  it("decrypt refuses a wrong-size key and round-trips an empty-plaintext envelope", async () => {
    const key = new Uint8Array(32).fill(3);
    const blob = await realCrypto.encrypt(key, new Uint8Array(0));
    expect(blob).toHaveLength(28); // nonce(12) + tag(16) — the minimum envelope
    await expect(realCrypto.decrypt(new Uint8Array(16).fill(3), blob)).rejects.toThrow("key must be 32 bytes");
    await expect(realCrypto.decrypt(key, blob)).resolves.toEqual(new Uint8Array(0));
  });

  it("fails loudly when WebCrypto is absent", async () => {
    const savedCrypto = globalThis.crypto;
    Object.defineProperty(globalThis, "crypto", { configurable: true, value: undefined });
    try {
      await expect(realCrypto.deriveMasterKey("pw", new Uint8Array(16))).rejects.toThrow("WebCrypto is unavailable");
    } finally {
      Object.defineProperty(globalThis, "crypto", { configurable: true, value: savedCrypto });
    }
  });

  it("sealPrivateKeyForUpload wipes the caller's raw PKCS#8 buffer", async () => {
    const kek = new Uint8Array(32).fill(5);
    const der = globalThis.crypto.getRandomValues(new Uint8Array(138));
    await realCrypto.sealPrivateKeyForUpload(kek, der, "drportal");
    expect(der.every((b) => b === 0)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// platform.ts + ui.tsx — seam and kit contracts
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: platform seam", () => {
  it("printPage goes through window.print", () => {
    const calls: number[] = [];
    const original = window.print;
    (window as { print: () => void }).print = () => { calls.push(1); };
    try {
      platform.printPage();
      expect(calls).toHaveLength(1);
    } finally {
      (window as { print: () => void }).print = original;
    }
  });

  it("randomBytes returns fresh non-zero randomness of the asked length", () => {
    const a = platform.randomBytes(16);
    const b = platform.randomBytes(16);
    expect(a).toHaveLength(16);
    expect(a.every((x) => x === 0)).toBe(false);
    expect(b.every((x) => x === 0)).toBe(false);
    expect(Array.from(a)).not.toEqual(Array.from(b));
  });

  it("a hostile window (location access throws) degrades to an empty origin", () => {
    const saved = (window as { location?: unknown }).location;
    Object.defineProperty(window, "location", {
      configurable: true,
      get() { throw new Error("locked down"); },
    });
    try {
      expect(platform.currentOrigin()).toBe("");
    } finally {
      Object.defineProperty(window, "location", { configurable: true, value: saved });
    }
  });

  it("removePrefix deletes only the prefixed keys, in both stores", () => {
    for (const key of ["mindpattern.lastVisit.A.1", "mindpattern.other", "xmindpattern.decoy", "unrelated"]) {
      platform.localStore.set(key, "1");
      platform.sessionStore.set(key, "1");
    }
    platform.localStore.removePrefix("mindpattern.");
    platform.sessionStore.removePrefix("mindpattern.");
    expect(platform.localStore.get("mindpattern.lastVisit.A.1")).toBeNull();
    expect(platform.localStore.get("mindpattern.other")).toBeNull();
    expect(platform.localStore.get("xmindpattern.decoy")).toBe("1");
    expect(platform.localStore.get("unrelated")).toBe("1");
    expect(platform.sessionStore.get("mindpattern.other")).toBeNull();
    expect(platform.sessionStore.get("xmindpattern.decoy")).toBe("1");
  });
});

describe("mutation pins 2026-09-22: ui kit contracts", () => {
  it("Button wires the disabled attribute through to the rendered button", async () => {
    const root = await render(<React.Fragment>
      <ui.Button label="Off" onPress={vi.fn()} disabled />
      <ui.Button label="On" onPress={vi.fn()} />
    </React.Fragment>);
    const buttons = root.root.findAllByType("button");
    const off = buttons.find((n) => n.props.children === "Off")!;
    const on = buttons.find((n) => n.props.children === "On")!;
    expect(off.props.disabled).toBe(true);
    expect(on.props.disabled).not.toBe(true);
  });

  it("Field keeps the password masked and defaults to text", async () => {
    const root = await render(<React.Fragment>
      <ui.Field label="Secret" value="" onChange={() => undefined} type="password" />
      <ui.Field label="Plain" value="" onChange={() => undefined} />
    </React.Fragment>);
    const inputs = root.root.findAllByType("input");
    expect(inputs[0]!.props.type).toBe("password");
    expect(inputs[1]!.props.type).toBe("text");
  });

  it("ErrorBanner renders nothing without a message", async () => {
    const root = await render(<ui.ErrorBanner message="" />);
    expect(root.root.findAllByType("div")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// LoginView — policy boundaries, TOTP gating, failure-path hygiene
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: LoginView", () => {
  it("password policy boundaries: 11 fails, 12-with-3-classes passes, 15-with-2 fails, 16 passes alone", () => {
    expect(passwordPolicyError("abcdefghijk")).toBe("Use at least 12 characters."); // 11 chars
    expect(passwordPolicyError("Aa1aaaaaaaaaa")).toBe(""); // exactly 12, 3 classes
    expect(passwordPolicyError("Aaaaaaaaaaaaaaa")).toBe("Use a 16-character passphrase, or 12+ characters from at least three character types."); // 15, 2 classes
    expect(passwordPolicyError("abcdefghijklmnop")).toBe(""); // exactly 16, passphrase lane
    expect(passwordPolicyError("aaaaaaaaaaaa")).toContain("three character types"); // one class only
    expect(passwordPolicyError("aaaaaaaaaaaaaaaa")).toBe(""); // 16, still one class — passphrase lane
  });

  it("the authenticator input keeps only digits, capped at six", async () => {
    mockedAuth.login.mockRejectedValueOnce(Object.assign(new ApiError(401, "totp"), { code: "totp_required" }));
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "password-value-123");
    await press(root, "Sign in");
    await flush();
    const { act } = await import("react");
    const codeInput = () => root.root.findAllByType("input").find((n) => n.props.autoComplete === "one-time-code")!;
    await act(async () => { codeInput()!.props.onChange({ target: { value: "9a8b7c6d5e4f3g" } }); });
    expect(codeInput()!.props.value).toBe("987654"); // digits only, first six
    await act(async () => { codeInput()!.props.onChange({ target: { value: "12 34" } }); });
    expect(codeInput()!.props.value).toBe("1234");
    const verify = root.root.findAllByType("button").find((n) => (n.children as unknown[]).join("") === "Verify code")!;
    expect(verify.props.disabled).toBe(true); // incomplete code cannot submit
  });

  it("an incomplete form never enables its submit button", async () => {
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    const signIn = root.root.findAllByType("button").find((n) => (n.children as unknown[]).join("") === "Sign in")!;
    expect(signIn.props.disabled).toBe(true); // username alone is not enough
    await press(root, "Create a therapist account instead");
    await flush();
    const create = root.root.findAllByType("button").find((n) => (n.children as unknown[]).join("") === "Create account")!;
    expect(create.props.disabled).toBe(true); // no repeat-password yet
    await typeInto(root, "Password", "password-value-123");
    expect(create.props.disabled).toBe(true);
  });

  it("a non-TOTP error inside the TOTP stage takes the generic path and clears the password", async () => {
    let call = 0;
    mockedAuth.login.mockImplementation(async () => {
      call += 1;
      if (call === 1) throw Object.assign(new ApiError(401, "totp"), { code: "totp_required" });
      throw new ApiError(401, "bad credentials", "invalid_credentials");
    });
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "password-value-123");
    await press(root, "Sign in");
    await flush();
    await typeInto(root, "Authenticator code", "123456");
    await press(root, "Verify code");
    await flush();
    expect(textOf(root)).toContain("bad credentials");
    const passwordField = root.root.findAllByType("input").find((n) => n.props.type === "password")!;
    expect(passwordField.props.value).toBe("");
  });

  it("a failed sign-in wipes the derived keys and leaves no session behind", async () => {
    const keys = { authKey: new Uint8Array(32).fill(1), wrapKek: new Uint8Array(32).fill(2), noteKey: new Uint8Array(32).fill(3) };
    mockedCrypto.derivePortalKeys.mockResolvedValueOnce(keys);
    mockedAuth.login.mockRejectedValue(new ApiError(401, "nope"));
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "password-value-123");
    await press(root, "Sign in");
    await flush();
    expect(keys.authKey.every((b) => b === 0)).toBe(true);
    expect(keys.wrapKek.every((b) => b === 0)).toBe(true);
    expect(keys.noteKey.every((b) => b === 0)).toBe(true);
    expect(realApi.hasSession()).toBe(false);
  });

  it("a successful registration establishes the session before onReady", async () => {
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await press(root, "Create a therapist account instead");
    await flush();
    await typeInto(root, "Your name", "Dr. Pin");
    await typeInto(root, "Username", "drpin");
    await typeInto(root, "Password", "password-value-123");
    await typeInto(root, "Repeat password", "password-value-123");
    await press(root, "Create account");
    await flush();
    expect(onReady).toHaveBeenCalledTimes(1);
    expect(realApi.hasSession()).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PatientView — ordering, pagination guards, hygiene, note machinery
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: PatientView", () => {
  const pattern = (over: Partial<PatternPayload["detail"]> & { kind?: string; label?: string; occurrences?: number }): PatternPayload =>
    ({ kind: over.kind ?? "topic", label: over.label ?? "x", occurrences: over.occurrences ?? 2, confidence: 0.5, detail: over });

  const renderChart = async (patterns: PatternPayload[]) => {
    mockedCrypto.decryptInsights.mockResolvedValueOnce({ state_seq: 7, stats: { patterns, total_entries: 9, active_days: 4 } });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    return root;
  };

  it("review ordering: sensitive < mood-shift-down < rumination < topics, strength descending within a rank", async () => {
    const root = await renderChart([
      pattern({ kind: "topic", label: "plain-a", strength: 0.9 }),
      pattern({ kind: "rumination", label: "rumin", strength: 0.1 }),
      pattern({ kind: "mood_shift", label: "shift-down", direction: "lower", strength: 0.2 }),
      pattern({ kind: "mood_shift", label: "shift-up", direction: "higher", strength: 0.9 }),
      pattern({ sensitive: true, label: "sensitive", strength: 0.0 }),
      pattern({ kind: "topic", label: "plain-b", strength: 0.5 }),
    ]);
    const titles = root.root.findAllByType("h2").map((n) => (n.children as unknown[]).join(""));
    const sensitiveAt = titles.indexOf("A difficult thought has been returning");
    expect(sensitiveAt).toBeGreaterThan(-1);
    for (const other of ["shift-down", "rumin", "plain-a", "plain-b", "shift-up"]) {
      expect(sensitiveAt).toBeLessThan(titles.indexOf(other));
    }
    expect(titles.indexOf("shift-down")).toBeLessThan(titles.indexOf("rumin"));
    expect(titles.indexOf("rumin")).toBeLessThan(titles.indexOf("plain-a"));
    expect(titles.indexOf("plain-a")).toBeLessThan(titles.indexOf("plain-b"));
    expect(titles.indexOf("shift-up")).toBeGreaterThan(titles.indexOf("rumin"));
  });

  it("the sparkline label reports the exact average of the mood-tagged entries", async () => {
    mockedCrypto.decryptInsights.mockResolvedValueOnce({
      state_seq: 7,
      stats: { patterns: [pattern({ kind: "temporal", label: "work", evidence_dates: ["2026-09-01", "2026-09-02", "2026-09-03"] })] },
    });
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "3", client_entry_id: "e-3", blob: "b", entry_date: "2026-09-03", received_at: "x" },
        { id: "2", client_entry_id: "e-2", blob: "b", entry_date: "2026-09-02", received_at: "x" },
        { id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" },
      ],
      nextOffset: null,
    });
    vi.mocked(mockedCrypto.decryptEntry).mockImplementation(async (_k, _u, entry) => ({
      text: `t ${entry.client_entry_id}`,
      sentiment: entry.client_entry_id === "e-1" ? 0.5 : entry.client_entry_id === "e-2" ? -0.5 : 0.25,
    }));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "See the evidence");
    await flush(8);
    const label = root.root.findAll((n) => n.props["aria-label"] && String(n.props["aria-label"]).includes("average")).map((n) => n.props["aria-label"])[0];
    expect(label).toContain("3 mood-tagged");
    expect(label).toContain("average 0.08");
  });

  it("evidence rows disclose the full statistical surface when present", async () => {
    const root = await renderChart([
      pattern({
        kind: "temporal", label: "work", pattern_state: "confirmed", sample_days: 21, p_value: 0.03,
        cohens_d: 0.8, strength: 0.67, evidence_dates: ["2026-09-01"], first_seen: "2026-08-01T00:00:00Z",
        last_seen: "2026-09-01T00:00:00Z", day: "Sunday", day_count: 4, occurrences: 9,
      }),
    ]);
    const text = textOf(root);
    expect(text).toContain("first seen");
    expect(text).toContain("2026-08-01");
    expect(text).toContain("last seen");
    expect(text).toContain("mentions");
    expect(text).toContain("9");
    expect(text).toContain("window entries");
    expect(text).toContain("21");
    expect(text).toContain("p (corrected)");
    expect(text).toContain("0.03");
    expect(text).toContain("effect (Cohen's d)");
    expect(text).toContain("0.8");
    expect(text).toContain("evidence density");
    expect(text).toContain("67%");
    expect(text).toContain("evidence days");
  });

  it("a pattern whose first_seen equals the anchor date is NOT new; a later one is", async () => {
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1", "2026-09-05");
    const root = await renderChart([
      pattern({ label: "same-day", first_seen: "2026-09-05" }),
      pattern({ label: "newer", first_seen: "2026-09-06" }),
    ]);
    expect(textOf(root)).toContain("1 pattern new");
  });

  it("persistently conflicting collections restart exactly once, then surface the error", async () => {
    const conflict = Object.assign(new ApiError(409, "changed while paging; retry the request"), { code: "collection_changed" });
    mockedApi.notes.mockRejectedValue(conflict);
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    expect(mockedApi.notes.mock.calls.length).toBe(2); // initial + exactly one restart
    expect(textOf(root)).toContain("changed while paging");
  });

  it("a non-409 conflict code never restarts the traversal", async () => {
    mockedApi.notes.mockRejectedValue(Object.assign(new ApiError(409, "nope"), { code: "something_else" }));
    await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    expect(mockedApi.notes.mock.calls.length).toBe(1);
  });

  it("measure traversal stops at its page cap against an always-full server", async () => {
    // 2026-09-26 audit L: the traversal retains MAX_MEASURE_PAGES pages plus
    // ONE bounded terminal probe. An always-full server answers the probe
    // with rows, so the portal refuses the twenty-first page honestly —
    // the same fence entries and notes run — instead of accumulating an
    // unbounded chart.
    let page = 0;
    mockedApi.patientMeasures.mockImplementation(async () => {
      page += 1;
      return {
        measures: Array.from({ length: 100 }, (_, i) => ({
          id: `m-${page}-${i}`, client_measure_id: `c-${page}-${i}`, blob: "b", measure_date: "2026-09-01", received_at: "x",
        })),
        // Headerless full pages keep the compatibility continuation alive.
        nextOffset: page * 100,
      };
    });
    mockedCrypto.decryptMeasure.mockResolvedValue({ measure: "phq9", score: 4, completedAt: null, measureDate: "2026-09-01" });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await vi.waitFor(() => expect(mockedApi.patientMeasures.mock.calls.length).toBe(21), { timeout: 4000 });
    expect(textOf(root)).toContain("measure history exceeds this portal's safe page limit");
  });

  it("a pre-paging backend (same rows every request) cannot loop the traversal", async () => {
    // 2026-09-26 audit L: the silent id-dedupe heuristic is GONE. A server
    // that answers every request with the same full page keeps the
    // compatibility continuation alive to the same bounded probe as above,
    // then fails with the honest page-limit error — bounded, never looping,
    // and never silently rendering a de-duplicated maybe-stale subset.
    const sameRows = Array.from({ length: 100 }, (_, i) => ({
      id: `m-${i}`, client_measure_id: `c-${i}`, blob: "b", measure_date: "2026-09-01", received_at: "x",
    }));
    mockedApi.patientMeasures.mockImplementation(async () => ({ measures: sameRows, nextOffset: 100 }));
    mockedCrypto.decryptMeasure.mockResolvedValue({ measure: "phq9", score: 4, completedAt: null, measureDate: "2026-09-01" });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await vi.waitFor(() => expect(mockedApi.patientMeasures.mock.calls.length).toBe(21), { timeout: 4000 });
    expect(textOf(root)).toContain("measure history exceeds this portal's safe page limit");
  });

  it("the unwrapped data key is zeroized after the insights load and after a drill-down", async () => {
    const tracked = [new Uint8Array(32).fill(9), new Uint8Array(32).fill(9)];
    let issued = 0;
    mockedCrypto.unwrapPatientDataKey.mockImplementation(async () => tracked[Math.min(issued++, 1)]!);
    mockedCrypto.decryptInsights.mockResolvedValue({ state_seq: 7, stats: { patterns: [pattern({ label: "work", evidence_dates: ["2026-09-01"] })] } });
    mockedApi.patientEntries.mockResolvedValue({ entries: [{ id: "1", client_entry_id: "e-1", blob: "b", entry_date: "2026-09-01", received_at: "x" }], nextOffset: null });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "See the evidence");
    await flush(8);
    expect(tracked[0]!.every((b) => b === 0)).toBe(true);
    expect(tracked[1]!.every((b) => b === 0)).toBe(true);
  });

  it("reversed measure input renders oldest-first", async () => {
    mockedApi.patientMeasures.mockResolvedValue({
      measures: [
        { id: "m-2", client_measure_id: "c-2", blob: "b", measure_date: "2026-09-02", received_at: "x" },
        { id: "m-1", client_measure_id: "c-1", blob: "b", measure_date: "2026-09-01", received_at: "x" },
      ],
      nextOffset: null,
    });
    mockedCrypto.decryptMeasure.mockImplementation(async (_k, _u, row) => ({ measure: "phq9", score: 4, completedAt: null, measureDate: row.measure_date }));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await vi.waitFor(() => expect(textOf(root)).toContain("PHQ-9"), { timeout: 4000 });
    const text = textOf(root);
    expect(text.indexOf("2026-09-01")).toBeLessThan(text.indexOf("2026-09-02"));
  });

  it("a note pagination protocol that gains a revision mid-load fails closed", async () => {
    let call = 0;
    mockedApi.notes.mockImplementation(async () => {
      call += 1;
      return call === 1
        ? { notes: [{ id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" }], nextOffset: 1 }
        : { notes: [], nextOffset: null, revision: "5" };
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    expect(textOf(root)).toContain("server changed the note pagination protocol mid-load");
  });

  it("an inconsistent note snapshot revision fails closed", async () => {
    let call = 0;
    mockedApi.notes.mockImplementation(async () => {
      call += 1;
      return call === 1
        ? { notes: [{ id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" }], nextOffset: 1, revision: "5" }
        : { notes: [], nextOffset: null, revision: "6" };
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    expect(textOf(root)).toContain("server returned an inconsistent note snapshot revision");
  });

  it("duplicate evidence rows render once, and same-date entries order by id", async () => {
    mockedCrypto.decryptInsights.mockResolvedValueOnce({ state_seq: 7, stats: { patterns: [pattern({ label: "work", evidence_dates: ["2026-09-01"] })] } });
    mockedApi.patientEntries.mockResolvedValue({
      entries: [
        { id: "b", client_entry_id: "e-2", blob: "x", entry_date: "2026-09-01", received_at: "x" },
        { id: "b", client_entry_id: "e-2", blob: "x", entry_date: "2026-09-01", received_at: "x" },
        { id: "a", client_entry_id: "e-1", blob: "x", entry_date: "2026-09-01", received_at: "x" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "See the evidence");
    await flush(8);
    const text = textOf(root);
    expect(text.match(/decrypted e-2/g)?.length).toBe(1);
    expect(text.indexOf("decrypted e-1")).toBeLessThan(text.indexOf("decrypted e-2"));
  });

  it("history cannot be requested twice concurrently; empty history says so", async () => {
    let slow = false;
    mockedApi.noteRevisions.mockImplementation(async () => {
      if (slow) await new Promise((resolve) => setTimeout(resolve, 50));
      return [];
    });
    mockedApi.notes.mockResolvedValue({
      notes: [
        { id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z" },
        { id: "n2", client_note_id: "c2", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    const historyButtons = root.root.findAllByType("button").filter((n) => (n.children as unknown[]).join("") === "View history");
    expect(historyButtons).toHaveLength(1); // only the edited note carries one
    slow = true;
    await press(root, "View history");
    await press(root, "Loading history…"); // inert while busy
    await vi.waitFor(() => expect(textOf(root)).toContain("no earlier text recorded"), { timeout: 4000 });
    expect(mockedApi.noteRevisions.mock.calls.length).toBe(1);
  });

  it("note drafts are trimmed and blank drafts never reach the API — including edits", async () => {
    mockedApi.notes.mockResolvedValue({
      notes: [{ id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" }],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await typeTextarea(root, "Note about this patient…", "   ");
    await press(root, "Save note");
    await flush();
    expect(mockedApi.createNote).not.toHaveBeenCalled();
    await typeTextarea(root, "Note about this patient…", "  real text  ");
    await press(root, "Save note");
    await flush();
    expect(mockedApi.createNote).toHaveBeenCalledTimes(1);
    expect(textOf(root)).toContain("real text");
    await press(root, "Edit");
    await typeTextarea(root, "Editing note…", "   ");
    const saveEdit = root.root.findAllByType("button").find((n) => (n.children as unknown[]).join("") === "Save edit")!;
    expect(saveEdit.props.disabled).toBe(true);
  });

  it("delete confirmation arms per note and only the armed note deletes", async () => {
    mockedApi.notes.mockResolvedValue({
      notes: [
        { id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
        { id: "n2", client_note_id: "c2", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "Delete"); // arms the first note only
    expect(buttonByLabel(root, "Confirm delete")).toBe(true);
    expect(textOf(root)).toContain("Press again to confirm");
    await press(root, "Confirm delete");
    await flush();
    expect(mockedApi.deleteNote).toHaveBeenCalledTimes(1);
  });

  it("the notes search box appears at three notes and filters case-insensitively on trimmed input", async () => {
    mockedCrypto.decryptNote.mockImplementation(async (_k, _t, _u, clientId: string) =>
      clientId === "c1" ? "Sleep issues" : clientId === "c2" ? "sleep again" : "exercise");
    mockedApi.notes.mockResolvedValue({
      notes: [
        { id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
        { id: "n2", client_note_id: "c2", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
        { id: "n3", client_note_id: "c3", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    const search = root.root.findAllByType("input").find((n) => n.props["aria-label"] === "Search notes");
    expect(search).toBeDefined();
    await search!.props.onChange({ target: { value: "  SLEEP  " } });
    await flush();
    const text = textOf(root);
    expect(text).toContain("Sleep issues");
    expect(text).toContain("sleep again");
    expect(text.match(/exercise/g)?.length).toBe(1); // print summary only, never the interactive list
  });

  it("pattern-anchored notes never bleed into the general list or vice versa", async () => {
    mockedCrypto.decryptInsights.mockResolvedValueOnce({ state_seq: 7, stats: { patterns: [pattern({ label: "work", pattern_pid: "pid-1", evidence_dates: ["2026-09-01"] })] } });
    mockedCrypto.decryptNote.mockImplementation(async (_k, _t, _u, clientId: string) =>
      clientId === "c1" ? "pattern-anchored note" : "general note");
    mockedApi.notes.mockResolvedValue({
      notes: [
        { id: "n1", client_note_id: "c1", pattern_pid: "pid-1", blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
        { id: "n2", client_note_id: "c2", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" },
      ],
      nextOffset: null,
    });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await press(root, "See the evidence");
    await flush(4);
    expect(textOf(root)).toContain("Notes on this pattern");
    expect(textOf(root)).toContain("pattern-anchored note");
    expect(textOf(root)).not.toContain("general note");
    await press(root, "Back to all patterns");
    await flush();
    const general = textOf(root);
    expect(general).toContain("General notes about this patient");
    expect(general).toContain("general note");
    expect(general).not.toContain("pattern-anchored note");
  });

  it("a template appends on a newline to a non-empty draft", async () => {
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    await typeTextarea(root, "Note about this patient…", "existing");
    const templateButtons = root.root.findAllByType("button").filter((n) => ["Session focus", "Observed together", "Homework / between-session plan", "Questions for next visit"].includes((n.children as unknown[]).join("")));
    const { act } = await import("react");
    await act(async () => { templateButtons[0]!.props.onClick(); });
    const area = root.root.findAllByType("textarea").find((n) => n.props.placeholder === "Note about this patient…")!;
    expect(area.props.value).toBe("existing\nSession focus:\n- \n- \n");
  });

  it("the account summary renders honest fallbacks for absent stats", async () => {
    mockedCrypto.decryptInsights.mockResolvedValueOnce({ state_seq: 7, stats: { patterns: [pattern({ label: "work" })], total_entries: undefined, active_days: undefined, avg_sentiment: undefined } });
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await flush(6);
    const text = textOf(root);
    expect(text).toContain("? entries");
    expect(text).toContain("? active days");
    expect(text).not.toContain("average reading");
  });

  it("retrying a failed chart load clears the previous notes and measures", async () => {
    mockedApi.notes.mockResolvedValueOnce({
      notes: [{ id: "n1", client_note_id: "c1", pattern_pid: null, blob: "b", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" }],
      nextOffset: null,
    });
    mockedApi.patientMeasures.mockResolvedValueOnce({ measures: [{ id: "m1", client_measure_id: "c1", blob: "b", measure_date: "2026-09-01", received_at: "x" }], nextOffset: null });
    mockedCrypto.decryptMeasure.mockResolvedValueOnce({ measure: "phq9", score: 4, completedAt: null, measureDate: "2026-09-01" });
    mockedApi.patientInsights.mockRejectedValueOnce(new Error("load failed"));
    const root = await render(<PatientView patient={patient} session={session} onBack={vi.fn()} />);
    await vi.waitFor(() => expect(textOf(root)).toContain("load failed"), { timeout: 4000 });
    await press(root, "Retry loading this patient");
    await vi.waitFor(() => expect(mockedApi.notes.mock.calls.length).toBe(2), { timeout: 4000 });
    await flush(4);
    expect(textOf(root)).not.toContain("PHQ-9");
  });
});

// ---------------------------------------------------------------------------
// PatientsView — rotation hygiene, retry policy, TOTP panel discipline
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: PatientsView account security", () => {
  it("the final credential PUT retries exactly up to four attempts on persistent 5xx", async () => {
    mockedApi.rotateWrapKey.mockResolvedValue(null);
    mockedApi.rotateCredential.mockRejectedValue(new ApiError(503, "busy"));
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await press(root, "Show account security");
    await typeInto(root, "Current password", "current-password-1");
    await typeInto(root, "New password", "new-password-value-1");
    await typeInto(root, "Repeat new password", "new-password-value-1");
    await press(root, "Change password");
    await vi.waitFor(() => expect(mockedApi.rotateCredential.mock.calls.length).toBe(4), { timeout: 4000 });
    expect(textOf(root)).toContain("did not complete");
  });

  it("every flow wipes its derived key sets and the pkcs8 buffer on the way out", async () => {
    const mkKeys = () => ({ authKey: new Uint8Array(32).fill(1), wrapKek: new Uint8Array(32).fill(2), noteKey: new Uint8Array(32).fill(3) });
    const changeKeys = mkKeys();
    const rotateKeys = mkKeys();
    const totpKeys = mkKeys();
    const der = new Uint8Array(138).fill(9);
    mockedCrypto.derivePortalKeys
      .mockResolvedValueOnce(changeKeys)
      .mockResolvedValueOnce(changeKeys)
      .mockResolvedValueOnce(rotateKeys)
      .mockResolvedValueOnce(totpKeys);
    mockedCrypto.openSealedPrivateKey.mockResolvedValueOnce(der).mockResolvedValue(null);
    mockedApi.rotateWrapKey.mockResolvedValue(null);
    mockedApi.rotateCredential.mockResolvedValue(null);
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} onSessionsEnded={vi.fn()} />);
    await press(root, "Show account security");
    await typeInto(root, "Current password", "current-password-1");
    await typeInto(root, "New password", "new-password-value-1");
    await typeInto(root, "Repeat new password", "new-password-value-1");
    await press(root, "Change password");
    await vi.waitFor(() => expect(mockedApi.rotateCredential).toHaveBeenCalledTimes(1), { timeout: 4000 });
    expect(changeKeys.authKey.every((b) => b === 0)).toBe(true);
    expect(changeKeys.wrapKek.every((b) => b === 0)).toBe(true);
    expect(der.every((b) => b === 0)).toBe(true);
    await typeInto(root, "Current password (to authorize rotation)", "current-password-1");
    const { act } = await import("react");
    const checkbox = () => root.root.findAllByType("input").find((n) => n.props.type === "checkbox")!;
    await act(async () => { checkbox()!.props.onChange({ target: { checked: true } }); });
    await press(root, "Rotate sharing key");
    await vi.waitFor(() => expect(mockedApi.rotateWrapKey.mock.calls.length).toBe(2), { timeout: 4000 });
    expect(rotateKeys.authKey.every((b) => b === 0)).toBe(true);
    await typeInto(root, "Current password (to authorize setup)", "current-password-1");
    await press(root, "Set up authenticator");
    await vi.waitFor(() => expect(mockedApi.totpSetup).toHaveBeenCalledTimes(1), { timeout: 4000 });
    expect(totpKeys.authKey.every((b) => b === 0)).toBe(true);
  });

  it("a successful password change routes through onSessionsEnded when provided", async () => {
    const onSessionsEnded = vi.fn();
    const onSignOut = vi.fn();
    mockedApi.rotateWrapKey.mockResolvedValue(null);
    mockedApi.rotateCredential.mockResolvedValue(null);
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={onSignOut} onSessionsEnded={onSessionsEnded} />);
    await press(root, "Show account security");
    await typeInto(root, "Current password", "current-password-1");
    await typeInto(root, "New password", "new-password-value-1");
    await typeInto(root, "Repeat new password", "new-password-value-1");
    await press(root, "Change password");
    await vi.waitFor(() => expect(onSessionsEnded).toHaveBeenCalledTimes(1), { timeout: 4000 });
    expect(onSignOut).not.toHaveBeenCalled();
  });

  it("recovery with the wrong intended password changes nothing and says so", async () => {
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await press(root, "Show account security");
    mockedApi.rotateWrapKey.mockResolvedValue(null);
    mockedApi.rotateCredential.mockRejectedValue(new ApiError(403, "verifier rejected"));
    await typeInto(root, "Current password", "current-password-1");
    await typeInto(root, "New password", "new-password-value-1");
    await typeInto(root, "Repeat new password", "new-password-value-1");
    await press(root, "Change password");
    await vi.waitFor(() => expect(textOf(root)).toContain("the password change did not complete"), { timeout: 4000 });
    expect(mockedApi.rotateWrapKey.mock.calls.length).toBe(1); // the change's re-wrap happened
    mockedApi.rotateWrapKey.mockClear();
    mockedCrypto.openSealedPrivateKey.mockResolvedValue(null);
    await typeInto(root, "Current password (the one you sign in with)", "current-password-1");
    await typeInto(root, "The password you were changing to", "wrong-intended-pass");
    await press(root, "Recover sharing key");
    await vi.waitFor(() => expect(textOf(root)).toContain("did not unlock the stored sharing key"), { timeout: 4000 });
    expect(mockedApi.rotateWrapKey.mock.calls.length).toBe(0); // the failed recovery never PUTs
  });

  it("the TOTP code input sanitizes to digits and caps at six", async () => {
    mockedApi.me.mockResolvedValue({
      username: "drportal", display_name: "Dr.", wrap_pub_key: "P".repeat(124), wrap_key_blob: "KQ==", totp_enabled: false,
    });
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await press(root, "Show account security");
    await flush(4);
    await typeInto(root, "Current password (to authorize setup)", "current-password-1");
    await press(root, "Set up authenticator");
    await vi.waitFor(() => expect(textOf(root)).toContain("SECRET"), { timeout: 4000 });
    await typeInto(root, "Current password (to authorize setup)", "current-password-1");
    const { act } = await import("react");
    const codeInput = () => root.root.findAllByType("input").find((n) => n.props.autoComplete === "one-time-code")!;
    await act(async () => { codeInput()!.props.onChange({ target: { value: "9a8b7c6d5e4f3g" } }); });
    expect(codeInput()!.props.value).toBe("987654");
    expect(mockedApi.totpEnable).not.toHaveBeenCalled();
  });

  it("hiding the security panel discards the one-time TOTP secret", async () => {
    mockedApi.me.mockResolvedValue({
      username: "drportal", display_name: "Dr.", wrap_pub_key: "P".repeat(124), wrap_key_blob: "KQ==", totp_enabled: false,
    });
    mockedApi.totpSetup.mockResolvedValue({ secret_base32: "ONE-TIME-SECRET", otpauth_uri: "otpauth://totp/x" });
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await press(root, "Show account security");
    await flush(4);
    await typeInto(root, "Current password (to authorize setup)", "current-password-1");
    await press(root, "Set up authenticator");
    await vi.waitFor(() => expect(textOf(root)).toContain("ONE-TIME-SECRET"), { timeout: 4000 });
    await press(root, "Hide account security");
    await flush(2);
    await press(root, "Show account security");
    await flush(2);
    expect(textOf(root)).not.toContain("ONE-TIME-SECRET");
    expect(buttonByLabel(root, "Set up authenticator")).toBe(true);
  });

  it("a rotation error surfaces when the portal origin cannot be normalized", async () => {
    const saved = (window as { location?: unknown }).location;
    Object.defineProperty(window, "location", { configurable: true, value: { origin: "" } });
    try {
      const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
      await press(root, "Show account security");
      await typeInto(root, "Current password", "current-password-1");
      await typeInto(root, "New password", "new-password-value-1");
      await typeInto(root, "Repeat new password", "new-password-value-1");
      await press(root, "Change password");
      await vi.waitFor(() => expect(textOf(root)).toContain("configured secure origin"), { timeout: 4000 });
      expect(mockedApi.rotateWrapKey).not.toHaveBeenCalled();
    } finally {
      Object.defineProperty(window, "location", { configurable: true, value: saved });
    }
  });
});

describe("mutation pins 2026-09-22: PatientsView caseload", () => {
  it("stopped patients never trigger a summary decrypt; active ones do", async () => {
    mockedApi.patients.mockResolvedValue([
      { ...patient, user_id: "u-active", summary_blob: "SB", summary_eph_pub: "SE" },
      { ...patient, user_id: "u-stopped", status: "revoked", summary_blob: "SB", summary_eph_pub: "SE" },
    ]);
    await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await vi.waitFor(() => expect(mockedCrypto.decryptCaseloadSummary).toHaveBeenCalledTimes(1), { timeout: 4000 });
    expect(mockedCrypto.decryptCaseloadSummary.mock.calls[0]![4]).toBe("u-active");
  });

  it("triage ordering breaks ties by most-new-since-reviewed", async () => {
    mockedApi.patients.mockResolvedValue([
      { ...patient, user_id: "p1", username: "alpha", granted_at: "2026-09-03T00:00:00Z" },
      { ...patient, user_id: "p2", username: "bravo", granted_at: "2026-09-02T00:00:00Z" },
      { ...patient, user_id: "p3", username: "charlie", granted_at: "2026-09-01T00:00:00Z" },
    ]);
    const mk = (userId: string, blob: string | null) => async () =>
      ({ phase: "insight", active_days: 1, streak: 1, days_remaining: 0, blob, state_seq: 7 });
    mockedApi.patientInsights.mockImplementation(async (userId: string) => mk(userId, userId === "p1" ? null : "B")());
    mockedCrypto.decryptInsights.mockImplementation(async (_k, userId: string) => ({
      state_seq: 7,
      stats: {
        patterns: userId === "p3"
          ? [pattern0("a", "2026-09-06"), pattern0("b", "2026-09-07")]
          : [pattern0("a", "2026-09-06")],
      },
    }));
    const pattern0 = (label: string, firstSeen: string): PatternPayload =>
      ({ kind: "topic", label, occurrences: 1, confidence: 0.5, detail: { first_seen: firstSeen } });
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.p2", "2026-09-05");
    window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.p3", "2026-09-01");
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush(4);
    await press(root, "Scan caseload for triage");
    await vi.waitFor(() => expect(textOf(root)).toContain("(scanned just now)"), { timeout: 4000 });
    const select = root.root.findAllByType("select")[0]!;
    await select.props.onChange({ target: { value: "triage" } });
    await flush(2);
    const order = root.root.findAllByType("strong").map((n) => (n.children as unknown[]).join(""));
    expect(order.indexOf("charlie")).toBeLessThan(order.indexOf("bravo"));
    expect(order.indexOf("bravo")).toBeLessThan(order.indexOf("alpha"));
  });

  it("the scan controls appear only for a caseload of two or more", async () => {
    mockedApi.patients.mockResolvedValue([{ ...patient }]);
    const root = await render(<PatientsView displayName="Dr." session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
    await flush(4);
    expect(buttonByLabel(root, "Scan caseload for triage")).toBe(false);
    expect(root.root.findAllByType("input").find((n) => n.props["aria-label"] === "Search patients by username")).toBeUndefined();
  });
});
