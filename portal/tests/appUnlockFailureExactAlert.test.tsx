/** pristine regression draft. The real App, LoginView, API,
 * PBKDF2-600k, HKDF, WebCrypto and UI own every state transition. Only the
 * server transport and the project's existing Node storage/event seams are
 * synthetic. Copy into a disposable portal/tests lane before running.
 */
import { createCipheriv, createDecipheriv, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const USERNAME = "synthetic_portal_failure";
const PASSWORD = "correct horse battery staple";
const SALT = "AAECAwQFBgcICQoLDA0ODw==";
const OWNER = "0123456789abcdef0123456789abcdef";
const TOKEN = "synthetic-portal-failure-token";
const AUTHORED_PROFILE_ERROR = "server is busy — try again";
const AUTHORED_TAMPER_ERROR = "your stored sharing key could not be unlocked with this password — sign in with the account's password";


type Trace = { phase: string; path?: string; method?: string; code?: string; verifierMatched?: boolean; bearerMatched?: boolean };
type Witness = { trace: Trace[] };

/** Independent Node implementation of the backend's password schedule and
 * therapist-key envelope. No production source, derivation helper, AAD
 * constructor or expected-output table supplies this fixture's oracle.
 */
function accountFixture(): { verifier: string; publicKeyB64: string; sealed: string; tampered: string; envelopeBytes: number } {
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/portal-wrap/v1"), 32));
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
  const nonce = randomBytes(12);
  // This ASCII identity needs no Unicode escapes. The independent wire
  // encoding is the backend's compact JSON array, rather than buildAad().
  const aad = Buffer.from(JSON.stringify(["therapist-key", USERNAME]), "utf8");
  try {
    const cipher = createCipheriv("aes-256-gcm", wrap, nonce);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([cipher.update(privateDer), cipher.final()]);
    const tag = cipher.getAuthTag();
    const sealed = Buffer.concat([nonce, encrypted, tag]);
    const open = createDecipheriv("aes-256-gcm", wrap, nonce);
    open.setAAD(aad); open.setAuthTag(tag);
    const opened = Buffer.concat([open.update(encrypted), open.final()]);
    if (!opened.equals(privateDer)) throw new Error("SetupError: independent therapist envelope failed authentication");
    opened.fill(0);
    const tampered = Buffer.from(sealed);
    tampered[20]! ^= 1;
    return { verifier: auth.toString("base64"), publicKeyB64: publicKey.export({ format: "der", type: "spki" }).toString("base64"), sealed: sealed.toString("base64"), tampered: tampered.toString("base64"), envelopeBytes: sealed.length };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); privateDer.fill(0); }
}

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } });
}

/** Completion is witnessed by the real form leaving busy after it awaited
 * App's onReady. An absent completion is an execution error, never an
 * assertion failure or a mutation kill. The form's void onSubmit return is
 * deliberately not used as a completion promise.
 */
async function producerCompletion(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>((resolve) => setTimeout(resolve, 10)); });
  }
  await flush();
}

function buttons(root: ReactTestRenderer, label: string) {
  return root.root.findAllByType("button").filter(node => textOfNode(node) === label);
}

async function submitEnabledForm(root: ReactTestRenderer, label: string): Promise<void> {
  const button = buttons(root, label)[0];
  if (!button || button.props.disabled === true) throw new Error(`SetupError: expected enabled public ${label} submission`);
  let prevented = false;
  await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() { prevented = true; } }); });
  if (!prevented) throw new Error("SetupError: real form did not prevent navigation");
}

function check(assertion: () => void): void {
  { assertion();  }
}

beforeEach(() => { vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = ""; });
afterEach(() => { clearSession(); vi.unstubAllGlobals(); });

it.each(["profile-503-after-MFA", "authenticated-wrap-tamper-after-MFA", "valid-wrap-positive-control", "profile-503-after-required-enrollment"] as const)("real App handles %s with the exact public surface after Login completion", async (scenario) => {
    const witness: Witness = { trace: [] };
    try {
      const fixture = accountFixture();
      let loginRequests = 0; let profileRequests = 0; let logoutRequests = 0;
      const enrollment = scenario === "profile-503-after-required-enrollment";
      vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
        const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
        const path = new URL(url).pathname;
        const method = init?.method ?? "GET";
        const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
        const headers = new Headers(init?.headers);
        if (String(init?.body ?? "").includes(PASSWORD)) throw new Error("SetupError: password crossed the server seam");
        witness.trace.push({ phase: "actual-fetch", path, method });
        if (path === "/api/v1/meta") return jsonResponse({ sharing_available: true });
        if (path === "/api/v1/auth/salt") return jsonResponse({ salt: SALT });
        if (path === "/api/v1/auth/login") {
          loginRequests += 1;
          witness.trace.push({ phase: "real-derived-verifier", code: typeof body.totp_code === "string" ? body.totp_code : "absent", verifierMatched: body.verifier === fixture.verifier });
          if (body.username !== USERNAME || body.verifier !== fixture.verifier) throw new Error("SetupError: real Login verifier did not match the independent 600k fixture");
          if (!enrollment && body.totp_code === undefined) return jsonResponse({ detail: "MFA is required", code: "totp_required" }, 401);
          if (!enrollment && body.totp_code !== "123456") throw new Error("SetupError: expected the publicly entered second-factor code");
          return jsonResponse({ token: TOKEN, user_id: OWNER, role: "therapist", expires_in: 86_400, mfa_enrollment_required: enrollment });
        }
        if (path === "/api/v1/account/totp/setup") {
          if (!enrollment || body.verifier !== fixture.verifier) throw new Error("SetupError: invalid required enrollment producer");
          return jsonResponse({ secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:synthetic?secret=JBSWY3DPEHPK3PXP" });
        }
        if (path === "/api/v1/account/totp/enable") {
          if (!enrollment || body.verifier !== fixture.verifier || body.code !== "123456") throw new Error("SetupError: invalid public MFA enrollment code");
          return jsonResponse({ backup_codes: ["ABCDE12345", "FGHIJ67890"] });
        }
        if (path === "/api/v1/therapist/me") {
          profileRequests += 1;
          const bearerMatched = headers.get("Authorization") === `Bearer ${TOKEN}`;
          witness.trace.push({ phase: "authenticated-profile", bearerMatched });
          if (!bearerMatched) throw new Error("SetupError: profile was not owned by the accepted therapist token");
          if (scenario.startsWith("profile-503")) return jsonResponse({ detail: "synthetic maintenance refusal", code: "service_unavailable" }, 503);
          return jsonResponse({ username: USERNAME, display_name: "Dr. Synthetic", wrap_pub_key: fixture.publicKeyB64, wrap_key_blob: scenario === "authenticated-wrap-tamper-after-MFA" ? fixture.tampered : fixture.sealed, totp_enabled: true });
        }
        if (path === "/api/v1/auth/logout") { logoutRequests += 1; return new Response(null, { status: 204 }); }
        if (path === "/api/v1/therapist/patients") return jsonResponse([]);
        throw new Error(`SetupError: unexpected actual server request ${method} ${path}`);
      });
      const root = await render(<App />);
      await typeInto(root, "Username", USERNAME);
      await typeInto(root, "Password", PASSWORD);
      await submitEnabledForm(root, "Sign in");
      if (enrollment) {
        await producerCompletion("required MFA setup completed", () => textOf(root).includes("Set up two-factor authentication to continue") && buttons(root, "Enable two-factor authentication").length === 1);
        check(() => { expect(profileRequests).toBe(0); });
        await typeInto(root, "Authenticator code", "123456");
        await press(root, "Enable two-factor authentication");
        await producerCompletion("required MFA enrollment completed", () => buttons(root, "I saved the codes — continue").length === 1);
        check(() => { expect(profileRequests).toBe(0); });
        await press(root, "I saved the codes — continue");
      } else {
        await producerCompletion("password response completed into public MFA challenge", () => buttons(root, "Verify code").length === 1);
        check(() => { expect(profileRequests).toBe(0); expect(hasSession()).toBe(false); });
        await typeInto(root, "Authenticator code (or recovery code)", "123456");
        await submitEnabledForm(root, "Verify code");
      }
      if (scenario === "valid-wrap-positive-control") {
        await producerCompletion("real App adopts the independent valid identity envelope", () => textOf(root).includes("Patients — Dr. Synthetic"));
      } else {
        // For MFA finish the two possible completed public branches are
        // ordinary sign-in or explicit handoff refusal. Either is a real
        // completion; the subsequent exact-surface assertion distinguishes
        // them without turning mutant completion into a watchdog failure.
        await producerCompletion("real Login completes the actual App handoff", () => enrollment
          ? buttons(root, "Sign in").length === 1 || buttons(root, "I saved the codes — return to sign in").length === 1
          : buttons(root, "Verify code").length === 1);
      }
      await flush(8);

      const alerts = root.root.findAll(node => node.type === "div" && node.props.role === "alert").map(textOfNode);

      check(() => {
        expect(profileRequests).toBe(1); expect(loginRequests).toBe(enrollment ? 1 : 2);
        expect(witness.trace.filter(row => row.phase === "real-derived-verifier").every(row => row.verifierMatched)).toBe(true);
        expect(witness.trace.find(row => row.phase === "authenticated-profile")?.bearerMatched).toBe(true);
      });
      {

{
 for (const label of ["Signing in…", "Opening portal…", "Enabling…"]) expect(buttons(root, label)).toHaveLength(0);

}
}
      if (scenario === "valid-wrap-positive-control") {
        {

{

          expect(alerts).toEqual([]); expect(hasSession()).toBe(true); (() => { expect(logoutRequests).toBe(0); })();
          expect(textOf(root)).toContain("Patients — Dr. Synthetic"); expect(textOf(root)).toContain("No patients are sharing with you yet");


}
}
      } else {
        {

{

          expect(alerts).toEqual([scenario.startsWith("profile-503") ? AUTHORED_PROFILE_ERROR : AUTHORED_TAMPER_ERROR]);


}
}
        {

{

          expect(hasSession()).toBe(false); (() => { expect(logoutRequests).toBe(1); })();
          expect(buttons(root, enrollment ? "Sign in" : "Verify code")).toHaveLength(1);
          expect(textOf(root)).not.toContain("Patients — Dr. Synthetic");
          expect(textOf(root)).not.toContain("Two-factor authentication is enabled, but the portal could not finish opening");


}
}
      }

    }
    finally {


    }
  });
