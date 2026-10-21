/** Real App/Login/Settings/WebCrypto,
 * native loopback HTTP/fetch/Responses; Node/RTR storage and public UI seam.
 * Authentication600k and declared envelope wrapping100k are separate costs.
 */
import { createCipheriv, createDecipheriv, hkdfSync, pbkdf2Sync } from "node:crypto";

import { createServer, type Server } from "node:http";

import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { hasSession, sessionUserId } from "../src/api/client";
import * as reauth from "../src/reauth";
import { applyLanguagePref } from "../src/strings";
import { vault } from "../src/vault";
import { resetTestState } from "./helpers/api";
import { buttonByLabel, flush, isDisabled, press, pressSwitch, render, textOf, typeInto } from "./helpers/rtr";

const OWNER = "0123456789abcdef0123456789abcdef";
const USERNAME = "synthetic_reauth_cost_patient";
const PASSWORD = "correct horse battery staple";
const TOKEN = "synthetic-action-bound-reauth-cost-token";
const nativeFetch = globalThis.fetch;
type Scenario = "different-wrap-cost" | "same-wrap-cost-control" | "wrong-password-control";
type Witness = { scenario: Scenario; nativeFetchCreated: number; nativeFetchSettled: number; nativeCryptoCreated: number; nativeCryptoSettled: number; originalPublicPromiseObserved: boolean; publicFlowSettled: boolean; result?: reauth.FreshStepUpResult; loginAuth600kVerified: boolean; vaultRandomDataVerified: boolean; independentEnvelopeAuthenticated: boolean; wireStepUpVerifier?: string; wireAction?: string; wireConsentProof?: string; faults: string[] };
type Owned = {
  server: Server; root?: ReactTestRenderer; witness: Witness; promises: Promise<unknown>[];
  settlement?: Promise<reauth.FreshStepUpResult>; restoreCrypto: () => void; originDescriptor?: PropertyDescriptor;
};
let owned: Owned | undefined;

function fault(message: string): Error { return new Error("SetupError: reauth cost producer: " + message); }
async function finite<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer!: ReturnType<typeof setTimeout>;
  try { return await Promise.race([promise, new Promise<T>((_, reject) => { timer = setTimeout(() => reject(fault(label + " completion deadline")), 15000); })]); }
  finally { clearTimeout(timer); }
}
async function until(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15000;
  while (!ready()) {
    if (Date.now() >= deadline) throw fault(label + " public completion deadline");
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  await flush();
}

async function drain(current: Owned): Promise<void> {
  let count = -1;
  while (count !== current.promises.length) {
    count = current.promises.length;
    const outcomes = await finite(Promise.allSettled(current.promises), "original native promises");
    for (const outcome of outcomes) if (outcome.status === "rejected") throw fault("original native promise rejected: " + String(outcome.reason));
  }
  if (current.witness.faults.length) throw fault(current.witness.faults.join("; "));
}
async function retire(current: Owned): Promise<void> {
  let error: unknown;
  try {
    if (current.settlement) await finite(current.settlement, "original public step-up");
    await drain(current);
  } catch (caught) { error = caught; }
  finally {
    if (current.root) await act(async () => { current.root!.unmount(); });

    resetTestState(); current.restoreCrypto(); vi.restoreAllMocks(); vi.unstubAllGlobals();
    if (current.originDescriptor) Object.defineProperty(window.location, "origin", current.originDescriptor);

    current.server.closeAllConnections();
    await finite(new Promise<void>((resolve, reject) => current.server.close(caught => caught ? reject(fault("owned server close: " + String(caught))) : resolve())), "owned server retirement");
     if (owned === current) owned = undefined;
  }
  if (error !== undefined) throw error;
}

beforeEach(() => { vi.useRealTimers(); resetTestState(); applyLanguagePref("en"); });
afterEach(async () => {
  const current = owned;
  if (current) await retire(current);
  resetTestState(); vi.restoreAllMocks(); vi.unstubAllGlobals();
});

it.each(["different-wrap-cost", "same-wrap-cost-control", "wrong-password-control"] as const)(
  "actual Login and Settings fresh-password action uses authentication cost independently: %s", async scenario => {
    const w: Witness = { scenario, nativeFetchCreated: 0, nativeFetchSettled: 0, nativeCryptoCreated: 0, nativeCryptoSettled: 0, originalPublicPromiseObserved: false, publicFlowSettled: false, loginAuth600kVerified: false, vaultRandomDataVerified: false, independentEnvelopeAuthenticated: false, faults: [] };
    const iterations = scenario === "same-wrap-cost-control" ? 600000 : 100000;
    const salt = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
    const params = { algorithm: "pbkdf2-sha256", version: 1, iterations };
    const authMaster = pbkdf2Sync(PASSWORD, salt, 600000, 32, "sha256");
    const auth = Buffer.from(hkdfSync("sha256", authMaster, Buffer.alloc(32), "mindpattern/auth/v1", 32)); authMaster.fill(0);
    const wrapMaster = pbkdf2Sync(PASSWORD, salt, iterations, 32, "sha256");
    const kek = Buffer.from(hkdfSync("sha256", wrapMaster, salt, "mindpattern/envelope/v2", 32)); wrapMaster.fill(0);
    const data = Buffer.from("4f934c7143c31fdf26d9ed3e715e0a76eaa07832dbd901dc15cba497f44b62d0", "hex");
    const nonce = Buffer.from("202122232425262728292a2b", "hex"), aad = Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username: USERNAME }));
    const seal = createCipheriv("aes-256-gcm", kek, nonce); seal.setAAD(aad); const ciphertext = Buffer.concat([seal.update(data), seal.final()]), tag = seal.getAuthTag();
    const wrapped = Buffer.concat([nonce, ciphertext, tag]).toString("base64");
    const open = createDecipheriv("aes-256-gcm", kek, nonce); open.setAAD(aad); open.setAuthTag(tag); const independent = Buffer.concat([open.update(ciphertext), open.final()]);
    if (!independent.equals(data)) throw fault("independent authenticated envelope positive control"); independent.fill(0); kek.fill(0); w.independentEnvelopeAuthenticated = true;
    let origin = "", voiceEnabled = false;
    const server = createServer((request, response) => {
      const chunks: Buffer[] = []; request.on("data", chunk => chunks.push(Buffer.from(chunk)));
      request.on("error", error => { w.faults.push("request stream: " + String(error)); });
      request.on("end", () => {
        const url = new URL(request.url ?? "", origin); const path = url.pathname; const method = request.method ?? "";

        let body: Record<string, unknown> = {}, status = 200, value: unknown;
        try { if (chunks.length) body = JSON.parse(Buffer.concat(chunks).toString()); }
        catch (error) { w.faults.push("body parse: " + String(error)); status = 500; }
        if (path === "/api/v1/auth/salt" && method === "POST" && body.username === USERNAME) value = { salt: salt.toString("base64") };
        else if (path === "/api/v1/auth/login" && method === "POST" && body.username === USERNAME && body.verifier === auth.toString("base64")) {
          w.loginAuth600kVerified = true; value = { token: TOKEN, user_id: OWNER, expires_in: 86400, role: "user", key_scheme: "v2" };
        } else if (path === "/api/v1/meta" && method === "GET") value = { version: "synthetic-native", api_version: "v1", unlock_ttl_minutes: 30, sharing_enabled: true, llm_available: false, audio_available: true, stt_provider_name: "Synthetic native witness", stt_data_retention: "none", stt_policy_fingerprint: "synthetic-policy" };
        else if (request.headers.authorization !== "Bearer " + TOKEN) { w.faults.push("unexpected unauthenticated route: " + method + " " + path); status = 500; value = { detail: "fixture admission failed", code: "witness_setup_fault" }; }
        else if (path === "/api/v1/auth/key-envelope" && method === "GET") value = { key_scheme: "v2", salt: salt.toString("base64"), kdf_params: params, wrapped_data_key: wrapped };
        else if (path === "/api/v1/account/llm-consent" && method === "GET") value = { enabled: false, active_for_current_policy: false };
        else if (path === "/api/v1/account/voice-consent" && method === "GET") value = { enabled: voiceEnabled, active_for_current_policy: voiceEnabled };
        else if (path === "/api/v1/account/access-log" && method === "GET") value = [];
        else if (path === "/api/v1/account/step-up" && method === "POST" && body.verifier === auth.toString("base64") && body.action === "voice_consent") {
          w.wireStepUpVerifier = String(body.verifier); w.wireAction = String(body.action); value = { proof: "synthetic-voice-one-use-proof", action: "voice_consent", expires_in: 60 };
        } else if (path === "/api/v1/account/voice-consent" && method === "PUT" && body.enabled === true && request.headers["x-step-up-proof"] === "synthetic-voice-one-use-proof") {
          w.wireConsentProof = String(request.headers["x-step-up-proof"]); voiceEnabled = true; value = { enabled: true, active_for_current_policy: true };
        } else { w.faults.push("unknown native receiver route/body: " + method + " " + path); status = 500; value = { detail: "fixture admission failed", code: "witness_setup_fault" }; }
        response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(value));
      });
    });
    server.on("error", error => { w.faults.push("owned server: " + String(error)); });
    await finite(new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); }), "owned server startup");
    const address = server.address(); if (!address || typeof address === "string") throw fault("owned server address"); origin = `http://127.0.0.1:${address.port}`;
    const current: Owned = { server, witness: w, promises: [], restoreCrypto: () => undefined, originDescriptor: Object.getOwnPropertyDescriptor(window.location, "origin") }; owned = current;
    Object.defineProperty(window.location, "origin", { configurable: true, value: origin });
    const subtle = globalThis.crypto.subtle, originalDerive = subtle.deriveBits, descriptor = Object.getOwnPropertyDescriptor(subtle, "deriveBits");
    Object.defineProperty(subtle, "deriveBits", { configurable: true, writable: true, value: (...args: Parameters<SubtleCrypto["deriveBits"]>): ReturnType<SubtleCrypto["deriveBits"]> => {
      const original = originalDerive.apply(subtle, args); current.promises.push(original); w.nativeCryptoCreated += 1;
      void original.then(() => { w.nativeCryptoSettled += 1; }, error => { w.faults.push("native deriveBits: " + String(error)); }); return original;
    } });
    current.restoreCrypto = () => { if (descriptor) Object.defineProperty(subtle, "deriveBits", descriptor); else Reflect.deleteProperty(subtle, "deriveBits"); };
    vi.stubGlobal("fetch", (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
      const target = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
      if (target.origin !== origin || !target.pathname.startsWith("/api/v1/") || !init?.signal || init.signal.aborted) throw fault("unowned fetch input");
      const original = nativeFetch(target, init); current.promises.push(original); w.nativeFetchCreated += 1;
      void original.then(() => { w.nativeFetchSettled += 1; }, error => { w.faults.push("native fetch: " + String(error)); }); return original;
    });
    const originalStepUp = reauth.freshStepUp;
    vi.spyOn(reauth, "freshStepUp").mockImplementation((password, action) => {
      if (current.settlement) throw fault("multiple unprepared public step-up requests");
      const original = originalStepUp(password, action); current.settlement = original; w.originalPublicPromiseObserved = true; return original;
    });
    try {
      current.root = await render(<App />); const root = current.root;
      await until("real App Sign in", () => buttonByLabel(root, "Sign in"));
      await typeInto(root, "Username", USERNAME); await typeInto(root, "Password", PASSWORD);
      if (isDisabled(root, "Sign in")) throw fault("public Login is disabled");
      await act(async () => { root.root.findByType("form").props.onSubmit({ preventDefault() {} }); });
      await until("actual Login adoption", () => textOf(root).includes("Step 1 of 3"));
      if (!w.loginAuth600kVerified || !vault.isUnlocked() || vault.ownerUserId() !== OWNER || !hasSession() || sessionUserId() !== OWNER
        || !Buffer.from(vault.get().authKey).equals(auth) || !Buffer.from(vault.get().dataKey).equals(data)) throw fault("real Login authenticated owner/data key differs from independent fixture");
      w.vaultRandomDataVerified = true;
      await press(root, "Next"); await press(root, "Next"); await press(root, "Start journaling");
      await until("actual journal chunk", () => textOf(root).includes("Today's entry"));
      await press(root, "More"); await press(root, "Settings");
      await until("actual Settings Voice control", () => root.root.findAllByProps({ role: "switch", "aria-label": "Voice journaling off" }).length === 1);
      await drain(current); await pressSwitch(root, "Voice journaling off");
      await typeInto(root, "Current password", scenario === "wrong-password-control" ? "a genuine incorrect password" : PASSWORD);
      if (isDisabled(root, "Verify and continue")) throw fault("public reauthentication action is disabled");
      await press(root, "Verify and continue");
      if (!current.settlement) throw fault("real Settings did not invoke public fresh step-up");
      let result: reauth.FreshStepUpResult;
      try { result = await finite(current.settlement, "public fresh step-up"); }
      catch (error) { throw fault("unexpected public step-up rejection: " + String(error)); }
      w.result = result; w.publicFlowSettled = true;
      if (!result.ok && result.reason !== "wrong-password") throw fault("unprepared completed refusal: " + result.reason);
      await until("actual Settings finally retires busy", () => textOf(root).includes("Voice journaling is on.") || buttonByLabel(root, "Verify and continue") && !buttonByLabel(root, "Working…"));
      await drain(current);
      if (scenario === "wrong-password-control") {
        expect(result).toEqual({ ok: false, reason: "wrong-password" });
        expect(root.root.findAllByProps({ role: "alert" }).map(node => String(node.children.join("")))).toEqual(["Wrong password."]);
        expect(root.root.findAllByProps({ role: "switch", "aria-label": "Voice journaling off" })).toHaveLength(1);
        expect(w.wireStepUpVerifier).toBeUndefined(); expect(w.wireConsentProof).toBeUndefined();
        expect(isDisabled(root, "Verify and continue")).toBe(true);
      } else {
        expect(result).toEqual({ ok: true, proof: "synthetic-voice-one-use-proof" });
        expect(root.root.findAllByProps({ role: "alert" })).toHaveLength(0);
        expect(root.root.findAllByProps({ role: "switch", "aria-label": "Voice journaling on" })).toHaveLength(1);
        expect(textOf(root)).toContain("Voice journaling is on.");
        expect(w.wireStepUpVerifier).toBe(auth.toString("base64")); expect(w.wireAction).toBe("voice_consent");
        expect(w.wireConsentProof).toBe("synthetic-voice-one-use-proof");
      }
      expect(vault.ownerUserId()).toBe(OWNER); expect(sessionUserId()).toBe(OWNER);
      expect(Buffer.from(vault.get().authKey)).toEqual(auth); expect(Buffer.from(vault.get().dataKey)).toEqual(data);
      expect(w.nativeFetchCreated).toBe(w.nativeFetchSettled); expect(w.nativeCryptoCreated).toBe(w.nativeCryptoSettled);

    }
    finally { await retire(current); auth.fill(0); data.fill(0); salt.fill(0);  }
  },
);
