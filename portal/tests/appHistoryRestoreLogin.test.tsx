/** Public restoration regressions.
 * Simulated same-task public restore events are a bounded producer schedule;
 * physical BFCache ordering remains unproved. Original input files are untouched.
 */
import { createCipheriv, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { clearSession, hasSession } from "../src/api";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const NAME = "synthetic_history_therapist", PASSWORD = "correct horse battery staple";
const SALT = "AAECAwQFBgcICQoLDA0ODw==", TOKEN = "synthetic-history-therapist-token";

function check(assertion: () => void): void {
  { assertion();  }
}
async function completed(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= deadline) throw new Error(`ExecutionError: producer completion timed out: ${label}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  await flush();
}
const buttons = (root: ReactTestRenderer, label: string) => root.root.findAllByType("button").filter(node => textOfNode(node) === label);
async function submit(root: ReactTestRenderer, label: string): Promise<void> {
  const button = buttons(root, label)[0];
  if (!button || button.props.disabled === true) throw new Error(`SetupError: public ${label} is unavailable or disabled`);
  await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
}
/** Independent backend-compatible account fixture; never App source/state. */
function fixture(): { verifier: string; publicKey: string; blob: string } {
  const master = pbkdf2Sync(PASSWORD, Buffer.from(SALT, "base64"), 600000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/portal-wrap/v1"), 32));
  const keys = generateKeyPairSync("ec", { namedCurve: "prime256v1" }), der = keys.privateKey.export({ format: "der", type: "pkcs8" });
  try {
    const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", wrap, nonce);
    cipher.setAAD(Buffer.from(JSON.stringify(["therapist-key", NAME])));
    return { verifier: auth.toString("base64"), publicKey: keys.publicKey.export({ format: "der", type: "spki" }).toString("base64"), blob: Buffer.concat([nonce, cipher.update(der), cipher.final(), cipher.getAuthTag()]).toString("base64") };
  } finally { master.fill(0); auth.fill(0); wrap.fill(0); der.fill(0); }
}
async function authenticatedApp(): Promise<ReactTestRenderer> {
  const account = fixture();
  const response = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status, headers: { "content-type": "application/json" } });
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url).pathname;
    const body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};

    if (String(init?.body ?? "").includes(PASSWORD)) throw new Error("SetupError: password crossed the owned server seam");
    if (path === "/api/v1/auth/salt") return response({ salt: SALT });
    if (path === "/api/v1/auth/login") {
      if (body.username !== NAME || body.verifier !== account.verifier) throw new Error("SetupError: actual 600k verifier mismatch");
      if (body.totp_code === undefined) return response({ detail: "MFA required", code: "totp_required" }, 401);
      if (body.totp_code !== "123456") throw new Error("SetupError: expected publicly submitted second factor");
      return response({ token: TOKEN, user_id: "0123456789abcdef0123456789abcdef", role: "therapist", expires_in: 86400, mfa_enrollment_required: false });
    }
    if (new Headers(init?.headers).get("Authorization") !== `Bearer ${TOKEN}`) throw new Error("SetupError: actual accepted therapist bearer was required");
    if (path === "/api/v1/therapist/me") return response({ username: NAME, display_name: "Dr. History Synthetic", wrap_pub_key: account.publicKey, wrap_key_blob: account.blob, totp_enabled: true });
    if (path === "/api/v1/therapist/patients") return response([]);
    if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
    throw new Error(`SetupError: unexpected actual request ${path}`);
  });
  const root = await render(<App />);
  await typeInto(root, "Username", NAME); await typeInto(root, "Password", PASSWORD);
  await submit(root, "Sign in");
  await completed("real Login password→MFA challenge", () => buttons(root, "Verify code").length === 1);
  await typeInto(root, "Authenticator code (or recovery code)", "123456");
  await submit(root, "Verify code");
  await completed("actual App authenticated identity adoption", () => textOf(root).includes("Patients — Dr. History Synthetic"));
  await flush(8);
  check(() => { expect(hasSession()).toBe(true); expect(buttons(root, "Sign out")).toHaveLength(1); expect(textOf(root)).toContain("No patients are sharing with you yet"); });
  return root;
}

beforeEach(() => { vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); window.location.hash = ""; });
afterEach(() => { clearSession(); vi.unstubAllGlobals(); });

it("actual explicit Sign out positive control restores one clean public sign-in form", async () => {

  {
    const root = await authenticatedApp();
    await press(root, "Sign out"); await flush(8);

    expect(hasSession()).toBe(false);
    expect(buttons(root, "Sign in")).toHaveLength(1);
    expect(root.root.findAllByType("form")).toHaveLength(1);
    expect(textOf(root)).not.toContain("Unlocking…");


  }
});

it("same-task simulated persisted pageshow and caseload popstate must restore the public Login after lock", async () => {

  {
    const root = await authenticatedApp();
    // The shipped no-chart route is already active. Two public window event
    // dispatches in one task exercise installed listeners; no private App
    // callback, state setter, sessionRef or lifecycle counter is touched.
    const restore = new Event("pageshow"); Object.defineProperty(restore, "persisted", { value: true });
    await act(async () => { window.dispatchEvent(restore); window.dispatchEvent(new Event("popstate")); });
    await flush(8);


    expect(hasSession()).toBe(false);
    expect(buttons(root, "Sign in")).toHaveLength(1);
    expect(root.root.findAllByType("form")).toHaveLength(1);
    expect(textOf(root)).not.toContain("Unlocking…");
    expect(textOf(root)).not.toContain("Patients — Dr. History Synthetic");


  }
});
