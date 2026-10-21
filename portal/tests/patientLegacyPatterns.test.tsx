/** real App/Login/API/P-256/WebCrypto chart with
 * an independently authenticated additive older insights payload. No view,
 * session, crypto operation or private state is replaced by a test model. */
import { createCipheriv, createDecipheriv, diffieHellman, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import * as cryptography from "../src/crypto";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const USERNAME = "synthetic_legacy_chart";
const PASSWORD = "correct horse battery staple";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const OWNER = "0123456789abcdef0123456789abcdef";
const PATIENT = "fedcba9876543210fedcba9876543210";
const TOKEN = "synthetic-legacy-chart-token";
type Scenario = "older-authenticated-stats-without-patterns" | "authenticated-empty-patterns-positive-control";
type Witness = { stage: string };

/** Node implements the documented wire independently; production AAD,
 * derivation, wrapping and decryption helpers supply no fixture bytes. */
function sealed(key: Buffer, aad: string[], plain: Buffer): string {
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", key, nonce);
  const associated = Buffer.from(JSON.stringify(aad), "utf8"); cipher.setAAD(associated);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]), tag = cipher.getAuthTag();
  const open = createDecipheriv("aes-256-gcm", key, nonce); open.setAAD(associated); open.setAuthTag(tag);
  const verified = Buffer.concat([open.update(ciphertext), open.final()]);
  if (!verified.equals(plain)) throw new Error("SetupError: independent wire authentication failed");
  verified.fill(0);
  return Buffer.concat([nonce, ciphertext, tag]).toString("base64");
}

function fixture(scenario: Scenario) {
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/portal-wrap/v1"), 32));
  const identity = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const ephemeral = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const identityPrivate = identity.privateKey.export({ format: "der", type: "pkcs8" });
  const identityPublic = identity.publicKey.export({ format: "der", type: "spki" });
  const ephemeralPublic = ephemeral.publicKey.export({ format: "der", type: "spki" });
  const shared = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: identity.publicKey });
  const consentKek = Buffer.from(hkdfSync("sha256", shared, Buffer.concat([ephemeralPublic, identityPublic]), Buffer.from("mindpattern/wrap/v1"), 32));
  const dataKey = randomBytes(32);
  const stats = scenario === "older-authenticated-stats-without-patterns" ? { avg_sentiment: 0, total_entries: 4, active_days: 4 } : { avg_sentiment: 0, total_entries: 4, active_days: 4, patterns: [] };
  const payload = { v: 2, state_seq: 7, stats };
  try {
    return { verifier: auth.toString("base64"), publicKeyB64: identityPublic.toString("base64"),
      privateEnvelope: sealed(wrap, ["therapist-key", USERNAME], identityPrivate),
      patient: { user_id: PATIENT, username: "Synthetic older analysis", status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null,
        ephemeral_pub: ephemeralPublic.toString("base64"), wrapped_key: sealed(consentKek, ["consent-wrap", PATIENT, OWNER], dataKey), share_voice: false },
      insights: { phase: "insight", active_days: 4, streak: 1, days_remaining: 0, state_seq: 7, blob: sealed(dataKey, ["insights", PATIENT, "patterns"], Buffer.from(JSON.stringify(payload))) },
      expectedOlderFieldAbsent: !Object.prototype.hasOwnProperty.call(stats, "patterns") };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); shared.fill(0); consentKek.fill(0); dataKey.fill(0); identityPrivate.fill(0); }
}

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), { status, headers: { "Content-Type": "application/json" } });
}

async function complete(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  await flush();
}

async function settle<T>(label: string, promise: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([promise, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error(`ExecutionError: original producer promise timed out: ${label}`)), 15_000);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}

function check(assertion: () => void): void {
  { assertion();  }
}

let root: ReactTestRenderer | undefined;
beforeEach(() => { vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = ""; });
afterEach(async () => {
  await act(async () => { root?.unmount(); }); root = undefined;
  clearSession(); vi.restoreAllMocks(); vi.unstubAllGlobals();
});

for (const scenario of ["older-authenticated-stats-without-patterns", "authenticated-empty-patterns-positive-control"] as const) {
  it(`actual authenticated patient chart completes ${scenario} without inventing a pattern or crashing`, async () => {
    const witness: Witness = { stage: "setup" };
    let originalDecrypt: ReturnType<typeof cryptography.decryptInsights> | undefined;
    try {
      const account = fixture(scenario); let logins = 0; let profileReads = 0; let insightsReads = 0;
      const realDecrypt = cryptography.decryptInsights;
      vi.spyOn(cryptography, "decryptInsights").mockImplementation((...args) => {
        const original = realDecrypt(...args); originalDecrypt = original;

        return original;
      });
      vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
        const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
        const path = url.pathname, body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};

        if (String(init?.body ?? "").includes(PASSWORD)) throw new Error("SetupError: plaintext password crossed the server seam");
        if (path === "/api/v1/meta") return response({ sharing_available: true });
        if (path === "/api/v1/auth/salt") return response({ salt: SALT });
        if (path === "/api/v1/auth/login") {
          logins += 1;
          if (body.username !== USERNAME || body.verifier !== account.verifier) throw new Error("SetupError: actual 600k Login verifier mismatches independent account");
          if (body.totp_code === undefined) return response({ detail: "MFA is required", code: "totp_required" }, 401);
          if (body.totp_code !== "123456") throw new Error("SetupError: public MFA code not owned by this scenario");
          return response({ token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86_400, mfa_enrollment_required: false });
        }
        if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
        if (new Headers(init?.headers).get("Authorization") !== `Bearer ${TOKEN}`) throw new Error("SetupError: protected request lacks current therapist bearer");
        if (path === "/api/v1/therapist/me") {
          profileReads += 1;
          return response({ username: USERNAME, display_name: "Dr. Legacy Chart", wrap_pub_key: account.publicKeyB64, wrap_key_blob: account.privateEnvelope, totp_enabled: true });
        }
        if (path === "/api/v1/therapist/patients") return response([account.patient]);
        if (path === `/api/v1/therapist/patients/${PATIENT}/insights`) { insightsReads += 1; return response(account.insights); }
        if (path === `/api/v1/therapist/patients/${PATIENT}/notes` || path === `/api/v1/therapist/patients/${PATIENT}/measures`) return response([]);
        throw new Error(`SetupError: unexpected server producer ${path}`);
      });
      root = await render(<App />);
      await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD); await press(root, "Sign in");
      await complete("password-only response into MFA", () => root!.root.findAllByType("button").some(button => textOfNode(button) === "Verify code"));
      check(() => { expect(profileReads).toBe(0); expect(hasSession()).toBe(false); });
      await typeInto(root, "Authenticator code (or recovery code)", "123456"); await press(root, "Verify code");
      await complete("actual App caseload admission", () => textOf(root!).includes("Synthetic older analysis") && root!.root.findAllByType("button").some(button => textOfNode(button) === "Open patterns"));
      await press(root, "Open patterns");
      await complete("actual chart invokes native authenticated insights decrypt", () => originalDecrypt !== undefined);
      // Await the unchanged production Promise rather than a mutant-specific
      // UI expectation. App's await continuation runs before this observer's
      // later await; act then flushes the completed chart/boundary render.
      let opened!: Awaited<ReturnType<typeof cryptography.decryptInsights>>;
      await act(async () => { opened = await settle("native insights decrypt", originalDecrypt!); }); await flush(8);
      witness.stage = "behavior-oracle";

      check(() => {
        expect(opened.state_seq).toBe(7); expect(opened.stats.avg_sentiment).toBe(0);
        expect(!Object.prototype.hasOwnProperty.call(opened.stats, "patterns")).toBe(scenario === "older-authenticated-stats-without-patterns");
        expect(account.expectedOlderFieldAbsent).toBe(scenario === "older-authenticated-stats-without-patterns");
      });
      // Direct body assertions retain actual source-phase attribution after
      // promotion into the complete affected-source behavioral corpus.
      expect(textOf(root!)).toContain("No recurring pattern has enough evidence yet.");
      expect(textOf(root!)).toContain("General notes about this patient");
      expect(textOf(root!)).not.toContain("Something went wrong");
      expect(textOf(root!)).not.toContain("Stryker was here");
      expect(root!.root.findAll(node => node.props.role === "alert")).toHaveLength(0);

      check(() => {
        expect(hasSession()).toBe(true); expect(logins).toBe(2); expect(profileReads).toBe(1); expect(insightsReads).toBe(1);
        expect(root!.root.findAllByType("button").some(button => textOfNode(button) === "Sign out")).toBe(true);
      });
      witness.stage = "passed";
    }
    finally {
      if (originalDecrypt) await settle("cleanup original insights decrypt", originalDecrypt).catch(error => { if (witness.stage === "passed") throw error; });


    }
  });
}
