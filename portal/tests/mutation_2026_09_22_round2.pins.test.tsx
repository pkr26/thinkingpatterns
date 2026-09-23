/**
 * Frontend mutation campaign 2026-09-22 — round 2 survivor pins (portal).
 *
 * The second pass over the post-round-1 survivors: URL-policy and transport
 * arms that only discriminate under a stubbed MODE, the derive-path key
 * wipes, windowless degradation of the platform seam, the idle-lock event
 * matrix, generation-guard boundaries, the ui theme/tone literals, and the
 * remaining sanitizer discriminators. Provably-equivalent mutants are
 * documented in the campaign REPORT instead of pinned.
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
      patientInsights: vi.fn(async () => ({ phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==" })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async (_u: string, payload: { client_note_id: string }) => ({
        id: "created-1", client_note_id: payload.client_note_id, pattern_pid: null,
        blob: "b", created_at: "2026-09-02T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
      })),
      updateNote: vi.fn(async (id: string) => ({
        id, client_note_id: "c1", pattern_pid: null, blob: "b",
        created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-02T00:00:00Z",
      })),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      patientMeasures: vi.fn(async () => []),
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
    decryptInsights: vi.fn(async () => ({ stats: { patterns: [] } })),
    decryptEntry: vi.fn(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
      text: `decrypted ${entry.client_entry_id}`, sentiment: null,
    })),
    encryptNote: vi.fn(async () => ({ clientNoteId: "c", blobB64: "SEALEDNOTE==" })),
    decryptNote: vi.fn(async () => "existing note text"),
    keyFingerprint: vi.fn(async () => "AABB CCDD"),
    openSealedPrivateKey: vi.fn(async () => new Uint8Array(138)),
    sealPrivateKeyForUpload: vi.fn(async () => "SEALED=="),
  };
});

const { auth, api, ApiError } = await import("../src/api");
const realApi = await vi.importActual<typeof import("../src/api")>("../src/api");
const { setSession, clearSession, hasSession, normalizeApiBaseUrl } = realApi;
const mockedAuth = vi.mocked(auth);
const mockedApi = vi.mocked(api);
const mockedCrypto = vi.mocked(await import("../src/crypto"));
const realCrypto = await vi.importActual<typeof import("../src/crypto")>("../src/crypto");
const platform = await import("../src/platform");
const ui = await import("../src/ui");
const { LoginView, passwordPolicyError } = await import("../src/views/LoginView");
const { App } = await import("../src/App");
const { act } = await import("react");
const rtr = await import("./helpers/rtr");
const { render, flush, textOf, press, buttonByLabel, typeInto } = rtr;

const BASE = "http://localhost:5173";

beforeEach(() => {
  vi.clearAllMocks();
  mockedAuth.meta.mockReset().mockResolvedValue({ sharing_available: true });
  mockedAuth.saltFor.mockReset().mockResolvedValue({ salt: "QUJDREVGR0hJSktMTU5P" });
  mockedAuth.login.mockReset().mockResolvedValue({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" });
  mockedApi.me.mockReset().mockResolvedValue({ username: "drportal", display_name: "Dr. Portal", wrap_pub_key: "P".repeat(124), wrap_key_blob: "KQ==" });
  mockedCrypto.deriveMasterKey.mockReset().mockResolvedValue(new Uint8Array(32));
  mockedCrypto.derivePortalKeys.mockReset().mockResolvedValue({ authKey: new Uint8Array(32), wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32) });
  clearSession();
  window.localStorage.clear();
  window.sessionStorage.clear();
});

// ---------------------------------------------------------------------------
// api.ts round 2 — URL policy under a stubbed production MODE, error
// taxonomy, header shapes, and the abort seams
// ---------------------------------------------------------------------------

describe("round 2: api URL policy", () => {
  it("the loopback exceptions are exactly the four documented hostnames", () => {
    for (const host of ["localhost", "127.0.0.1", "[::1]"]) {
      expect(normalizeApiBaseUrl(`http://${host}:5173`), host).not.toBe("");
    }
    expect(normalizeApiBaseUrl("http://10.0.0.5:5173")).toBe("");
    expect(normalizeApiBaseUrl("http://localhost.example:5173")).toBe("");
  });

  it("strips every trailing slash from the path, and only trailing ones", () => {
    expect(normalizeApiBaseUrl("https://x.example//")).toBe("https://x.example");
    expect(normalizeApiBaseUrl("https://x.example/a//")).toBe("https://x.example/a");
    expect(normalizeApiBaseUrl("https://x.example/a/b")).toBe("https://x.example/a/b");
  });
});

describe("round 2: api error taxonomy and request shapes", () => {
  const ok = (body: unknown, url = ""): unknown =>
    ({ ok: true, status: 200, json: async () => body, headers: new Headers(), url });

  it("an ApiError carries its class name and the exact guard messages", async () => {
    expect(() => setSession("", BASE)).toThrow("invalid empty session token");
    setSession("tok", BASE);
    const err = await realApi.api.me().then(() => null, (e: unknown) => e as { name?: string; message?: string });
    expect(err).toBeInstanceOf(ApiError);
    expect(err?.name).toBe("ApiError");
    vi.unstubAllGlobals();
  });

  it("a whitespace-only server detail degrades to the generic message", async () => {
    setSession("tok", BASE);
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 400, json: async () => ({ detail: "   " }), headers: new Headers(), url: "" })));
    const err = await realApi.api.me().then(() => null, (e: unknown) => e as { name?: string; message?: string });
    expect(err?.message).toBe("request failed (400)");
    vi.unstubAllGlobals();
  });

  it("an unparseable response origin surfaces its own message", async () => {
    setSession("tok", BASE);
    vi.stubGlobal("fetch", vi.fn(async () => ok({}, "not a url at all")));
    await expect(realApi.api.me()).rejects.toThrow("server returned an invalid response origin");
    vi.unstubAllGlobals();
  });

  it("replacing a session aborts the old request even if fetch never settles", async () => {
    setSession("tok1", BASE);
    vi.stubGlobal("fetch", vi.fn((_url: unknown, init: { signal?: AbortSignal }) =>
      new Promise((_resolve, reject) => {
        init.signal?.addEventListener("abort", () =>
          reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      })));
    const pending = realApi.api.me();
    setSession("tok2", BASE);
    await expect(pending).rejects.toThrow("session ended");
    vi.unstubAllGlobals();
  });

  it("a network failure becomes the honest unreachable error; the error code keeps its string contract", async () => {
    setSession("tok", BASE);
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("fetch failed"); }));
    const unreachable = await realApi.api.me().then(() => null, (e: unknown) => e as { message?: string });
    expect(unreachable?.message).toBe("server unreachable — check the server URL or your connection");
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 400, json: async () => ({ detail: "nope", code: 42 }), headers: new Headers(), url: "" })));
    const numeric = await realApi.api.me().then(() => null, (e: unknown) => e as { code?: unknown });
    expect(numeric?.code).toBeUndefined(); // a non-string code never reaches ApiError.code
    vi.stubGlobal("fetch", vi.fn(async () => ({ ok: false, status: 400, json: async () => ({ detail: "nope", code: "rate_limited" }), headers: new Headers(), url: "" })));
    const coded = await realApi.api.me().then(() => null, (e: unknown) => e as { code?: unknown });
    expect(coded?.code).toBe("rate_limited");
    vi.unstubAllGlobals();
  });

  it("a 401 without an installed handler rejects cleanly, and JSON bodies carry the content type", async () => {
    setSession("tok", BASE);
    let headers: Record<string, string> = {};
    let body: unknown;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: { headers: Record<string, string>; body?: string }) => {
      headers = init.headers;
      body = init.body;
      return { ok: false, status: 401, json: async () => ({ detail: "expired" }), headers: new Headers(), url: "" };
    }));
    await expect(realApi.api.accessLog()).rejects.toThrow("expired"); // no handler installed: no crash
    expect(headers["Content-Type"]).toBe("application/json");
    expect(body).toBeUndefined(); // GET: no body key at all
    vi.unstubAllGlobals();
  });

  it("auth requests send JSON bodies with the content type; bodyless ones send none", async () => {
    const shapes: Array<Record<string, unknown>> = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init: Record<string, unknown>) => {
      shapes.push(init);
      return { ok: true, status: 200, json: async () => ({ token: "t", user_id: "u", expires_in: 1, role: "therapist" }), headers: new Headers(), url: "" };
    }));
    await realApi.auth.meta(BASE);
    await realApi.auth.login(BASE, "u", "v", "123456");
    expect(shapes[0]!.headers).toEqual({ "Content-Type": "application/json" });
    expect(shapes[0]!.body).toBeUndefined();
    expect(shapes[1]!.body).toBe(JSON.stringify({ username: "u", verifier: "v", totp_code: "123456" }));
    expect(shapes[1]!.headers).toEqual({ "Content-Type": "application/json" });
    vi.unstubAllGlobals();
  });
});

// ---------------------------------------------------------------------------
// crypto.ts round 2 — error identity, import-key hygiene, sanitizer arms
// ---------------------------------------------------------------------------

describe("round 2: crypto identity and hygiene", () => {
  it("TamperError carries its name and message", async () => {
    const key = new Uint8Array(32).fill(3);
    let err: unknown;
    await realCrypto.decrypt(key, new Uint8Array(10)).catch((e: unknown) => { err = e; });
    expect(err).toBeInstanceOf(realCrypto.TamperError);
    const tamper = err as { name?: string; message?: string } | null;
    expect(tamper?.name).toBe("TamperError");
    expect(tamper?.message).toBe("blob failed authentication");
  });

  it("imports every symmetric and public key as non-extractable", async () => {
    const subtle = globalThis.crypto.subtle;
    const seen: Array<{ alg: string; extractable: boolean }> = [];
    const original = subtle.importKey.bind(subtle);
    const spy = vi.spyOn(subtle, "importKey").mockImplementation(async (format, keyData, algorithm, extractable, usages) => {
      seen.push({ alg: (algorithm as { name?: string }).name ?? String(algorithm), extractable });
      return original(format, keyData as BufferSource, algorithm as Algorithm, extractable, usages);
    });
    try {
      const thPair = await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      const thDer = new Uint8Array(await subtle.exportKey("spki", thPair.publicKey));
      const ephPair = await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
      const ephDer = new Uint8Array(await subtle.exportKey("spki", ephPair.publicKey));
      const { toBase64 } = realCrypto;
      const seal = async (payload: unknown): Promise<string> => {
        const shared = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: ephPair.publicKey }, thPair.privateKey, 256));
        const salt = new Uint8Array(ephDer.length + thDer.length);
        salt.set(ephDer, 0);
        salt.set(thDer, ephDer.length);
        const ikm = await original("raw", shared, "HKDF", false, ["deriveBits"]);
        const kek = new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info: new TextEncoder().encode("mindpattern/wrap/v1") }, ikm, 256));
        const { buildAad } = await import("../src/aad");
        const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const cipher = await subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: buildAad("caseload-summary", "user-1", "therapist-1") }, await original("raw", kek, "AES-GCM", false, ["encrypt"]), new TextEncoder().encode(JSON.stringify(payload)));
        const blob = new Uint8Array(12 + cipher.byteLength);
        blob.set(nonce, 0);
        blob.set(new Uint8Array(cipher), 12);
        return toBase64(blob);
      };
      await realCrypto.decryptCaseloadSummary(thPair.privateKey, toBase64(thDer), toBase64(ephDer), await seal({ patterns: 1 }), "user-1", "therapist-1");
      const keyImports = seen.filter((s) => s.alg === "AES-GCM");
      expect(keyImports.length).toBeGreaterThan(0);
      expect(keyImports.every((s) => s.extractable === false)).toBe(true);
    } finally {
      spy.mockRestore();
    }
  });

  it("sanitizer discriminators: string scores, string-typed summary fields, non-string display fields", async () => {
    const { toBase64 } = realCrypto;
    const dataKey = new Uint8Array(32).fill(7);
    const { buildAad } = await import("../src/aad");
    const sealMeasure = async (payload: unknown, id: string): Promise<string> =>
      toBase64(await realCrypto.encrypt(dataKey, new TextEncoder().encode(JSON.stringify(payload)), buildAad("measure", "user-1", id)));
    // "7" as a string score is corrupt data, never a score.
    const strScore = await sealMeasure({ v: 1, measure: "phq9", score: "7", completed_at: null }, "s1");
    expect(await realCrypto.decryptMeasure(dataKey, "user-1", { client_measure_id: "s1", blob: strScore, measure_date: "2026-09-01" })).toBeNull();
    // A non-string measure name degrades to the neutral label.
    const noName = await sealMeasure({ v: 1, measure: 7, score: 4, completed_at: null }, "s2");
    expect(await realCrypto.decryptMeasure(dataKey, "user-1", { client_measure_id: "s2", blob: noName, measure_date: "2026-09-01" }))
      .toMatchObject({ measure: "measure" });
    // A non-string completed_at degrades to null.
    const noDate = await sealMeasure({ v: 1, measure: "phq9", score: 4, completed_at: 17 }, "s3");
    expect(await realCrypto.decryptMeasure(dataKey, "user-1", { client_measure_id: "s3", blob: noDate, measure_date: "2026-09-01" }))
      .toMatchObject({ completedAt: null });
  });
});

// ---------------------------------------------------------------------------
// platform.ts round 2 — windowless degradation of every seam
// ---------------------------------------------------------------------------

describe("round 2: platform degradation", () => {
  const withoutWindow = async <T,>(fn: () => T): Promise<T> => {
    const saved = (globalThis as { window?: unknown }).window;
    Object.defineProperty(globalThis, "window", { configurable: true, value: undefined });
    try {
      return await fn();
    } finally {
      Object.defineProperty(globalThis, "window", { configurable: true, value: saved });
    }
  };

  it("every storage and origin seam degrades inertly without a window", async () => {
    await withoutWindow(() => {
      expect(platform.currentOrigin()).toBe("");
      expect(platform.localStore.get("k")).toBeNull();
      expect(platform.sessionStore.get("k")).toBeNull();
      expect(() => platform.localStore.set("k", "v")).not.toThrow();
      expect(() => platform.sessionStore.set("k", "v")).not.toThrow();
      expect(() => platform.localStore.removePrefix("p.")).not.toThrow();
      expect(() => platform.sessionStore.removePrefix("p.")).not.toThrow();
      expect(() => platform.printPage()).not.toThrow();
      return Promise.resolve();
    });
  });

  it("a throwing sessionStorage read degrades to null", () => {
    const saved = Object.getOwnPropertyDescriptor(window, "sessionStorage")!;
    Object.defineProperty(window, "sessionStorage", {
      configurable: true,
      get() { throw new Error("locked down"); },
    });
    try {
      expect(platform.sessionStore.get("k")).toBeNull();
    } finally {
      Object.defineProperty(window, "sessionStorage", saved);
    }
  });

  it("prefix cleanup matches prefixes only — an ends-with decoy survives", () => {
    platform.localStore.set("decoy.mindpattern", "1");
    platform.localStore.set("mindpattern.real", "1");
    platform.localStore.removePrefix("mindpattern.");
    expect(platform.localStore.get("decoy.mindpattern")).toBe("1");
    expect(platform.localStore.get("mindpattern.real")).toBeNull();
    platform.sessionStore.set("decoy.mindpattern", "1");
    platform.sessionStore.set("mindpattern.real", "1");
    platform.sessionStore.removePrefix("mindpattern.");
    expect(platform.sessionStore.get("decoy.mindpattern")).toBe("1");
    expect(platform.sessionStore.get("mindpattern.real")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// App.tsx round 2 — idle-lock event matrix, no-session timer, unlock races
// ---------------------------------------------------------------------------

describe("round 2: App idle lock and session races", () => {

  it("a never-signed-in app never arms the idle lock", async () => {
    vi.useFakeTimers();
    try {
      const root = await render(<App />);
      await act(async () => { await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000); });
      expect(textOf(root)).not.toContain("Locked after inactivity");
    } finally {
      vi.useRealTimers();
    }
  });

  it("every documented interaction event re-arms the clock", async () => {
    vi.useFakeTimers();
    try {
      const root = await render(<App />);
      await typeInto(root, "Username", "drportal");
      await typeInto(root, "Password", "pw");
      await press(root, "Sign in");
      await flush();
      for (const event of ["click", "keydown", "mousemove", "scroll", "touchstart"]) {
        await act(async () => { await vi.advanceTimersByTimeAsync(9 * 60 * 1000); });
        window.dispatchEvent({ type: event } as Event);
      }
      await act(async () => { await vi.advanceTimersByTimeAsync(9 * 60 * 1000); });
      expect(textOf(root)).toContain("Patients — Dr. Portal"); // every bump re-armed
      await act(async () => { await vi.advanceTimersByTimeAsync(60 * 1000 + 1); });
      expect(textOf(root)).toContain("Locked after inactivity");
    } finally {
      vi.useRealTimers();
    }
  });

  it("an unlock overtaken by teardown never resurrects the session", async () => {
    let resolveMe!: (value: unknown) => void;
    mockedApi.me.mockImplementation(() => new Promise((resolve) => { resolveMe = resolve; }) as never);
    const root = await render(<App />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "pw");
    await press(root, "Sign in");
    await flush();
    expect(hasSession()).toBe(true); // LoginView set it; api.me still pending
    await act(async () => { root.unmount(); }); // teardown bumps the generation
    resolveMe({
      username: "drportal", display_name: "Dr.", wrap_pub_key: "P".repeat(124), wrap_key_blob: "KQ==",
    });
    await flush(4);
    expect(hasSession()).toBe(false); // the stale unlock cleared it instead
  });
});

// ---------------------------------------------------------------------------
// ui.tsx round 2 — the theme table and tone colors are contracts
// ---------------------------------------------------------------------------

describe("round 2: ui theme and tones", () => {
  it("the theme table is exactly the clinical palette", () => {
    expect(ui.theme).toEqual({
      bg: "#0d1117",
      card: "#161b26",
      cardDeep: "#10141d",
      text: "#e7ecf5",
      body: "#c3ccdb",
      muted: "#7d8899",
      accent: "#4f8cff",
      accentBright: "#6ea0ff",
      danger: "#e0604f",
      ok: "#4fae7c",
      border: "#232a38",
      radius: 10,
    });
  });

  it("the cursor reflects the disabled state; Note tone colors map exactly", async () => {
    const root = await render(<React.Fragment>
      <ui.Button label="Go" onPress={vi.fn()} />
      <ui.Button label="No" onPress={vi.fn()} disabled />
      <ui.Note tone="ok">fine</ui.Note>
      <ui.Note tone="danger">alarm</ui.Note>
      <ui.Note tone="warn">warn</ui.Note>
      <ui.Note>plain</ui.Note>
    </React.Fragment>);
    const buttons = root.root.findAllByType("button");
    expect(buttons.find((n) => n.props.children === "Go")!.props.style.cursor).toBe("pointer");
    expect(buttons.find((n) => n.props.children === "No")!.props.style.cursor).toBe("default");
    const noteColor = (tone: string) =>
      root.root.findAllByType("p").find((n) => (n.children as unknown[]).join("") === ({ ok: "fine", danger: "alarm", warn: "warn", plain: "plain" } as Record<string, string>)[tone])!.props.style.color;
    expect(noteColor("ok")).toBe(ui.theme.ok);
    expect(noteColor("danger")).toBe(ui.theme.danger);
    expect(noteColor("warn")).toBe(ui.theme.accentBright);
    expect(noteColor("plain")).toBe(ui.theme.muted);
  });
});

// ---------------------------------------------------------------------------
// LoginView round 2 — policy regex arm, derive-path wipes, mode-switch reset
// ---------------------------------------------------------------------------

describe("round 2: LoginView arms", () => {
  it("two character classes at 12-15 characters are NOT three", () => {
    // lower+digits only: 2 classes — must demand the passphrase lane.
    expect(passwordPolicyError("aaaaaaaaaa01")).toContain("three character types");
    expect(passwordPolicyError("AAAAAAAAAA01")).toContain("three character types");
    expect(passwordPolicyError("aaaaaaaaaa!!")).toContain("three character types");
  });

  it("a failure before any derivation wipes nothing and still surfaces its error", async () => {
    mockedAuth.saltFor.mockRejectedValue(new ApiError(0, "server unreachable"));
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "password-value-123");
    await press(root, "Sign in");
    await flush();
    expect(textOf(root)).toContain("server unreachable");
    expect(onReady).not.toHaveBeenCalled();
  });

  it("the salt and master buffers are wiped after a successful sign-in", async () => {
    const salt = new Uint8Array(16).fill(5);
    const master = new Uint8Array(32).fill(6);
    mockedCrypto.deriveMasterKey.mockResolvedValue(master);
    const saltSpy = vi.spyOn(mockedCrypto, "fromBase64").mockImplementation((text: string) =>
      text === "QUJDREVGR0hJSktMTU5P" ? salt : realCrypto.fromBase64(text));
    const onReady = vi.fn();
    const root = await render(<LoginView onReady={onReady} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "password-value-123");
    await press(root, "Sign in");
    await flush();
    expect(onReady).toHaveBeenCalledTimes(1);
    expect(salt.every((b) => b === 0)).toBe(true);
    expect(master.every((b) => b === 0)).toBe(true);
    saltSpy.mockRestore();
  });

  it("switching modes restarts the enrollment-policy check", async () => {
    let slow = false;
    mockedAuth.meta.mockImplementation(async () => {
      if (slow) await new Promise((resolve) => setTimeout(resolve, 25));
      return { sharing_available: true };
    });
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await vi.waitFor(() => expect(textOf(root)).toContain("Create account"), { timeout: 2000 });
    slow = true;
    await press(root, "Back to sign in");
    await press(root, "Create a therapist account instead");
    await vi.waitFor(() => expect(textOf(root)).toContain("Checking this server"), { timeout: 2000 });
  });

  it("registration stays disabled until the server advertises enrollment", async () => {
    mockedAuth.meta.mockResolvedValue({ sharing_available: false });
    const root = await render(<LoginView onReady={vi.fn()} />);
    await press(root, "Create a therapist account instead");
    await vi.waitFor(() => expect(textOf(root)).toContain("unavailable on this server"), { timeout: 2000 });
    await typeInto(root, "Your name", "Dr. X");
    await typeInto(root, "Username", "drx");
    await typeInto(root, "Password", "password-value-123");
    await typeInto(root, "Repeat password", "password-value-123");
    const create = root.root.findAllByType("button").find((n) => (n.children as unknown[]).join("") === "Create account")!;
    expect(create.props.disabled).toBe(true); // policy gate holds over complete fields
  });

  it("the TOTP stage keeps the password for a wrong code", async () => {
    let call = 0;
    mockedAuth.login.mockImplementation(async () => {
      call += 1;
      if (call === 1) throw Object.assign(new ApiError(401, "totp"), { code: "totp_required" });
      throw new ApiError(401, "stale", "totp_code_invalid");
    });
    const root = await render(<LoginView onReady={vi.fn()} />);
    await typeInto(root, "Username", "drportal");
    await typeInto(root, "Password", "password-value-123");
    await press(root, "Sign in");
    await flush();
    await typeInto(root, "Authenticator code", "123456");
    await press(root, "Verify code");
    await flush();
    const passwordField = root.root.findAllByType("input").find((n) => n.props.type === "password")!;
    expect(passwordField.props.value).toBe("password-value-123"); // kept for the retry
    expect(textOf(root)).toContain("wrong or already used");
  });
});
