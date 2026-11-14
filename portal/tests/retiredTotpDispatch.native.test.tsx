/** Synthetic native HTTP/WebCrypto retirement control; the mutant may send a synthetic verifier to the owned local receiver. */
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { createServer } from "node:http";
import { act, useState } from "react";
import { expect, it, vi } from "vitest";
import { api, clearSession, hasSession, setSession } from "../src/api";
import * as provider from "../src/crypto";
import { PatientsView } from "../src/views/PatientsView";
import type { PortalSession } from "../src/views/PatientView";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

async function checkRetiredDispatch(action: "TOTP setup" | "TOTP enable" | "TOTP disable"): Promise<void> {
  const username = "native-retirement-clinician", owner = "0123456789abcdef0123456789abcdef", password = "correct horse battery staple", salt = "AAECAwQFBgcICQoLDA0ODw==";
  const master = pbkdf2Sync(password, Buffer.from(salt, "base64"), 600000, 32, "sha256");
  const expectedAuth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32)); master.fill(0);
  const wrapKey = new Uint8Array(32).fill(41), generated = await provider.generateTherapistKeyPair(wrapKey, username);
  const unlocked = await provider.unlockWrapPrivateKeyWithNotesKey(wrapKey, generated.wrapKeyBlobB64, username);
  const session: PortalSession = { username, userId: owner, privateKey: unlocked.privateKey, publicKeyB64: generated.publicKeySpkiB64, noteKey: new Uint8Array(32).fill(42), noteKeyV2: unlocked.noteKeyV2 };
  const patient = { user_id: "fedcba0987654321fedcba0987654321", username: "Current patient", status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null, wrapped_key: null, ephemeral_pub: null };
  const handlers: Promise<void>[] = [], faults: string[] = []; let setupRequests = 0, enableRequests = 0, disableRequests = 0;
  const server = createServer((req, res) => {
    const handling = (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1"); let body: Record<string, unknown> = {};
        if (req.method === "POST") { const chunks: Buffer[] = []; for await (const c of req) chunks.push(Buffer.from(c)); body = JSON.parse(Buffer.concat(chunks).toString()); }
        let value: unknown;
        if (url.pathname === "/api/v1/auth/salt") { if (body.username !== username) throw new Error("salt owner mismatch"); value = { salt }; }
        else {
          if (req.headers.authorization !== "Bearer synthetic-retired-verifier") throw new Error("bearer mismatch");
          if (url.pathname === "/api/v1/therapist/patients") value = [patient];
          else if (url.pathname === "/api/v1/therapist/me") value = { username, display_name: "Native clinician", wrap_pub_key: generated.publicKeySpkiB64, wrap_key_blob: generated.wrapKeyBlobB64, totp_enabled: action === "TOTP disable" };
          else if (url.pathname === "/api/v1/account/totp/setup") { if (body.verifier !== expectedAuth.toString("base64")) throw new Error("setup verifier mismatch"); setupRequests++; value = { secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:native?secret=JBSWY3DPEHPK3PXP" }; }
          else if (url.pathname === "/api/v1/account/totp/enable") { if (setupRequests !== 1 || body.verifier !== expectedAuth.toString("base64") || body.code !== "123456") throw new Error("enable proof mismatch"); enableRequests++; value = { backup_codes: ["A2B3C4D5E6", "F7G8H9J2K3"] }; }
          else if (url.pathname === "/api/v1/account/totp/disable") { if (body.verifier !== expectedAuth.toString("base64") || body.code !== "123456") throw new Error("disable proof mismatch"); disableRequests++; value = {}; }
          else throw new Error(`unexpected native route ${url.pathname}`);
        }
        res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(value));
      } catch (error) { faults.push(String(error)); res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ detail: "native fixture fault" })); }
    })(); handlers.push(handling);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: local server address unavailable");
  const origin = `http://127.0.0.1:${address.port}`, oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin");
  Object.defineProperty(window.location, "origin", { configurable: true, value: origin }); setSession("synthetic-retired-verifier", origin);
  let release!: () => void, retired = false, reached = false, retiredVerifierEncodings = 0, activeControlEncodings = 0, derivations = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const nativeDerive = provider.derivePortalKeys, nativeEncode = provider.toBase64;
  let delivered: Awaited<ReturnType<typeof provider.derivePortalKeys>> | undefined, pending: Promise<Awaited<ReturnType<typeof provider.derivePortalKeys>>> | undefined;
  const derivation = vi.spyOn(provider, "derivePortalKeys").mockImplementation((...args) => {
    derivations++;
    const original = nativeDerive(...args);
    if (action === "TOTP enable" && derivations === 1) return original;
    pending = original.then(async keys => { delivered = keys; reached = true; await gate; return keys; });
    return pending;
  });
  const encoding = vi.spyOn(provider, "toBase64").mockImplementation(bytes => {
    if (Buffer.from(bytes).equals(expectedAuth)) { if (retired) retiredVerifierEncodings++; else activeControlEncodings++; }
    return nativeEncode(bytes);
  });
  const nativeSetup = api.totpSetup;
  const setupObservation: { retiredAdmissions: number; pending?: ReturnType<typeof api.totpSetup> } = { retiredAdmissions: 0 };
  const setupSpy = vi.spyOn(api, "totpSetup").mockImplementation((...args) => {
    if (retired) setupObservation.retiredAdmissions++;
    const original = nativeSetup(...args); setupObservation.pending = original; return original;
  });
  const nativeEnable = api.totpEnable;
  const enableObservation: { retiredAdmissions: number; pending?: ReturnType<typeof api.totpEnable> } = { retiredAdmissions: 0 };
  const enableSpy = vi.spyOn(api, "totpEnable").mockImplementation((...args) => {
    if (retired) enableObservation.retiredAdmissions++;
    const original = nativeEnable(...args); enableObservation.pending = original; return original;
  });
  const nativeDisable = api.totpDisable;
  const disableObservation: { retiredAdmissions: number; pending?: ReturnType<typeof api.totpDisable> } = { retiredAdmissions: 0 };
  const disableSpy = vi.spyOn(api, "totpDisable").mockImplementation((...args) => {
    if (retired) disableObservation.retiredAdmissions++;
    const original = nativeDisable(...args); disableObservation.pending = original; return original;
  });
  function Routes() { const [chart, setChart] = useState(false); return chart ? <p>Current patient chart</p> : <PatientsView displayName="Native clinician" session={session} onOpen={() => setChart(true)} onSignOut={() => {}} />; }
  let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    root = await render(<Routes />);
    await vi.waitFor(() => expect(textOf(root!)).toContain("Current patient"));
    await press(root, "Show account security");
    if (action === "TOTP disable") {
      await vi.waitFor(() => expect(textOf(root!)).toContain("Disable two-factor"));
      await typeInto(root, "Current password (to disable two-factor)", password);
      await typeInto(root, "6-digit code (to disable two-factor)", "123456"); await press(root, "Disable two-factor");
    } else {
      await vi.waitFor(() => expect(textOf(root!)).toContain("Set up authenticator"));
      await typeInto(root, "Current password (to authorize setup)", password); await press(root, "Set up authenticator");
    }
    if (action === "TOTP enable") {
      await vi.waitFor(() => expect(textOf(root!)).toContain("6-digit code from the app"), { timeout: 10_000 });
      expect(setupRequests).toBe(1);
      await typeInto(root, "Current password (to authorize setup)", password);
      await typeInto(root, "6-digit code from the app", "123456"); await press(root, "Enable two-factor");
    }
    await vi.waitFor(() => expect(reached).toBe(true), { timeout: 10_000 });
    if (!delivered || !pending) throw new Error("SetupError: genuine key derivation did not reach the owned gate");
    const activeBeforeControl = activeControlEncodings, setupRequestsBeforeRetirement = setupRequests;
    expect(provider.toBase64(delivered.authKey)).toBe(expectedAuth.toString("base64"));
    expect(activeControlEncodings).toBe(activeBeforeControl + 1);
    const open = root.root.findAllByType("button").find(button => textOfNode(button) === "Open patterns");
    if (!open) throw new Error("SetupError: public patient navigation button missing");
    const navigation = pending.then(() => new Promise<void>((resolve, reject) => queueMicrotask(() => {
      try { act(() => { open.props.onClick(); }); retired = true; resolve(); } catch (error) { reject(error); }
    })));
    release(); await navigation; await flush(12);
    if (setupObservation.pending) await Promise.allSettled([setupObservation.pending]);
    if (enableObservation.pending) await Promise.allSettled([enableObservation.pending]);
    if (disableObservation.pending) await Promise.allSettled([disableObservation.pending]);
    await Promise.all(handlers);
    expect(textOf(root)).toContain("Current patient chart"); expect(hasSession()).toBe(true);
    expect(activeControlEncodings, "genuine verifier encoding completed before navigation").toBe(activeBeforeControl + 2);
    expect(retiredVerifierEncodings).toBe(0);
    expect(delivered.authKey.every(byte => byte === 0)).toBe(true);
    expect(faults).toEqual([]);
    expect(setupRequests - setupRequestsBeforeRetirement, "every retired setup admission reached the owned receiver").toBe(setupObservation.retiredAdmissions);
    expect(enableRequests, "every retired enable admission reached the owned receiver").toBe(enableObservation.retiredAdmissions);
    expect(disableRequests, "every retired disable admission reached the owned receiver").toBe(disableObservation.retiredAdmissions);
    expect(setupObservation.retiredAdmissions, "retired view must not dispatch TOTP setup").toBe(0);
    expect(enableObservation.retiredAdmissions, "retired view must not dispatch TOTP enable").toBe(0);
    expect(disableObservation.retiredAdmissions, "retired view must not dispatch TOTP disable").toBe(0);
  } finally {
    release(); if (pending) await Promise.allSettled([pending]); if (root) await act(async () => root!.unmount());
    derivation.mockRestore(); encoding.mockRestore(); setupSpy.mockRestore(); enableSpy.mockRestore(); disableSpy.mockRestore(); clearSession(); if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin); else Reflect.deleteProperty(window.location, "origin");
    wrapKey.fill(0); session.noteKey.fill(0); session.noteKeyV2.fill(0); expectedAuth.fill(0);
    await Promise.allSettled(handlers); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

it("does not send TOTP setup after a queued navigation retires the view", async () => {
  await checkRetiredDispatch("TOTP setup");
}, 60_000);

it("does not send TOTP enable after a queued navigation retires the view", async () => {
  await checkRetiredDispatch("TOTP enable");
}, 60_000);

it("does not send TOTP disable after a queued navigation retires the view", async () => {
  await checkRetiredDispatch("TOTP disable");
}, 60_000);
