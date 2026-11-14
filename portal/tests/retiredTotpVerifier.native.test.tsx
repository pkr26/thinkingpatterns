/** Synthetic native HTTP/WebCrypto retirement control; no credential is sent after retirement. */
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { createServer } from "node:http";
import { act, useState } from "react";
import { expect, it, vi } from "vitest";
import { clearSession, hasSession, setSession } from "../src/api";
import * as provider from "../src/crypto";
import { PatientsView } from "../src/views/PatientsView";
import type { PortalSession } from "../src/views/PatientView";
import { flush, press, render, textOf, typeInto } from "./helpers/rtr";

async function checkRetiredVerifier(action: "TOTP setup" | "sharing-key rotation" | "password change"): Promise<void> {
  const username = "native-retirement-clinician", owner = "0123456789abcdef0123456789abcdef", password = "correct horse battery staple", salt = "AAECAwQFBgcICQoLDA0ODw==";
  const master = pbkdf2Sync(password, Buffer.from(salt, "base64"), 600000, 32, "sha256");
  const expectedAuth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32)); master.fill(0);
  const wrapKey = new Uint8Array(32).fill(41), generated = await provider.generateTherapistKeyPair(wrapKey, username);
  const unlocked = await provider.unlockWrapPrivateKeyWithNotesKey(wrapKey, generated.wrapKeyBlobB64, username);
  const session: PortalSession = { username, userId: owner, privateKey: unlocked.privateKey, publicKeyB64: generated.publicKeySpkiB64, noteKey: new Uint8Array(32).fill(42), noteKeyV2: unlocked.noteKeyV2 };
  const patient = { user_id: "fedcba0987654321fedcba0987654321", username: "Current patient", status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null, wrapped_key: null, ephemeral_pub: null };
  const handlers: Promise<void>[] = [], faults: string[] = []; let setupRequests = 0, profileRequests = 0;
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
          else if (url.pathname === "/api/v1/therapist/me") { profileRequests++; value = { username, display_name: "Native clinician", wrap_pub_key: generated.publicKeySpkiB64, wrap_key_blob: generated.wrapKeyBlobB64, totp_enabled: false }; }
          else if (url.pathname === "/api/v1/account/totp/setup") { setupRequests++; value = { secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:native?secret=JBSWY3DPEHPK3PXP" }; }
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
    if (action === "password change" && derivations === 1) return original;
    pending = original.then(async keys => { delivered = keys; reached = true; await gate; return keys; });
    return pending;
  });
  const encoding = vi.spyOn(provider, "toBase64").mockImplementation(bytes => {
    if (action === "password change" ? bytes === delivered?.authKey : Buffer.from(bytes).equals(expectedAuth)) { if (retired) retiredVerifierEncodings++; else activeControlEncodings++; }
    return nativeEncode(bytes);
  });
  function Routes() { const [chart, setChart] = useState(false); return chart ? <p>Current patient chart</p> : <PatientsView displayName="Native clinician" session={session} onOpen={() => setChart(true)} onSignOut={() => {}} />; }
  let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    root = await render(<Routes />);
    await vi.waitFor(() => expect(textOf(root!)).toContain("Current patient"));
    await press(root, "Show account security"); await vi.waitFor(() => expect(textOf(root!)).toContain("Set up authenticator"));
    if (action === "TOTP setup") {
      await typeInto(root, "Current password (to authorize setup)", password); await press(root, "Set up authenticator");
    } else if (action === "password change") {
      await typeInto(root, "Current password", password);
      await typeInto(root, "New password", "a wholly separate strong phrase 42!");
      await typeInto(root, "Repeat new password", "a wholly separate strong phrase 42!");
      await press(root, "Change password");
    } else {
      await typeInto(root, "Current password (to authorize rotation)", password);
      const confirmation = root.root.findAllByType("input").find(node => node.props["aria-label"] === "Confirm sharing-key rotation")!;
      await act(async () => confirmation.props.onChange({ target: { checked: true } }));
      await press(root, "Rotate sharing key");
    }
    await vi.waitFor(() => expect(reached).toBe(true), { timeout: 10_000 });
    if (!delivered || !pending) throw new Error("SetupError: genuine key derivation did not reach the owned gate");
    if (action === "password change") {
      expect(derivations).toBe(2);
      expect(Buffer.from(delivered.authKey).equals(expectedAuth)).toBe(false);
      expect(provider.toBase64(delivered.authKey)).toBe(nativeEncode(delivered.authKey));
    } else expect(provider.toBase64(delivered.authKey)).toBe(expectedAuth.toString("base64"));
    expect(activeControlEncodings).toBe(1);
    const profileRequestsBeforeRetirement = profileRequests;
    await press(root, "Open patterns"); expect(textOf(root)).toContain("Current patient chart"); expect(hasSession()).toBe(true); retired = true;
    await act(async () => { release(); await pending; }); await flush(12); await Promise.all(handlers);
    expect(faults).toEqual([]); expect(setupRequests).toBe(0); expect(profileRequests).toBe(profileRequestsBeforeRetirement); expect(hasSession()).toBe(true);
    expect(delivered.authKey.every(byte => byte === 0)).toBe(true);
    expect(retiredVerifierEncodings, "a retired view must not create another immutable verifier string").toBe(0);
  } finally {
    release(); if (pending) await Promise.allSettled([pending]); if (root) await act(async () => root!.unmount());
    derivation.mockRestore(); encoding.mockRestore(); clearSession(); if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin); else Reflect.deleteProperty(window.location, "origin");
    wrapKey.fill(0); session.noteKey.fill(0); session.noteKeyV2.fill(0); expectedAuth.fill(0);
    await Promise.allSettled(handlers); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

it("does not encode a retired TOTP verifier after its native key derivation completes", async () => {
  await checkRetiredVerifier("TOTP setup");
}, 60_000);

it("does not encode a retired sharing-key rotation verifier after its native key derivation completes", async () => {
  await checkRetiredVerifier("sharing-key rotation");
}, 60_000);

it("does not encode a retired new-password verifier after its native key derivation completes", async () => {
  await checkRetiredVerifier("password change");
}, 60_000);
