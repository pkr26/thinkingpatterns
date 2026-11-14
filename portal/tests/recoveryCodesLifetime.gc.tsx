/** Public controls, genuine local HTTP/fetch/Response/WebCrypto, and Node/V8 weak-reference lifetime.
 * Synthetic account and credentials; this is not a browser or production-backend heap claim. */
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { createServer } from "node:http";
import { act } from "react";
import { expect, it } from "vitest";
import { api, clearSession, setSession } from "../src/api";
import { generateTherapistKeyPair, unlockWrapPrivateKeyWithNotesKey } from "../src/crypto";
import { PatientsView } from "../src/views/PatientsView";
import type { PortalSession } from "../src/views/PatientView";
import { press, render, textOf, typeInto } from "./helpers/rtr";

it("releases native received recovery codes after disabling two-factor", async () => {
  const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
  if (!gc) throw new Error("SetupError: requires a Node worker with --expose-gc");
  const turn = () => new Promise<void>(resolve => setImmediate(resolve));
  const released = () => new WeakRef(["negative one", "negative two"]);
  const positive = ["positive one", "positive two"], positiveRef = new WeakRef(positive), negativeRef = released();
  async function collected(ref: WeakRef<string[]>) {
    for (let i = 0; i < 20; i++) { await turn(); gc!(); await turn(); if (ref.deref() === undefined) return true; }
    return false;
  }
  expect(await collected(negativeRef), "released same-shape GC control").toBe(true);
  expect(positiveRef.deref(), "retained same-shape GC control").toBe(positive);
  const username = "native-retention-clinician", owner = "0123456789abcdef0123456789abcdef", password = "correct horse battery staple", salt = "AAECAwQFBgcICQoLDA0ODw==";
  const master = pbkdf2Sync(password, Buffer.from(salt, "base64"), 600000, 32, "sha256");
  const expectedVerifier = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32)).toString("base64"); master.fill(0);
  const wrapKey = new Uint8Array(32).fill(41), generated = await generateTherapistKeyPair(wrapKey, username);
  const unlocked = await unlockWrapPrivateKeyWithNotesKey(wrapKey, generated.wrapKeyBlobB64, username);
  const session: PortalSession = { username, userId: owner, privateKey: unlocked.privateKey, publicKeyB64: generated.publicKeySpkiB64, noteKey: new Uint8Array(32).fill(42), noteKeyV2: unlocked.noteKeyV2 };
  const handlers: Promise<void>[] = [], faults: string[] = []; let enabled = false, setups = 0, enables = 0, disables = 0;
  const server = createServer((req, res) => {
    const handling = (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1"); let body: Record<string, unknown> = {};
        if (req.method === "POST") { const chunks: Buffer[] = []; for await (const c of req) chunks.push(Buffer.from(c)); body = JSON.parse(Buffer.concat(chunks).toString()); }
        let status = 200, value: unknown;
        if (url.pathname === "/api/v1/auth/salt") { if (body.username !== username) throw new Error("salt owner mismatch"); value = { salt }; }
        else {
          if (req.headers.authorization !== "Bearer synthetic-retention-bearer") throw new Error("bearer mismatch");
          if (url.pathname === "/api/v1/therapist/patients") value = [];
          else if (url.pathname === "/api/v1/therapist/me") value = { username, display_name: "Native clinician", wrap_pub_key: generated.publicKeySpkiB64, wrap_key_blob: generated.wrapKeyBlobB64, totp_enabled: enabled };
          else if (url.pathname === "/api/v1/account/totp/setup") { if (body.verifier !== expectedVerifier || enabled) throw new Error("setup proof mismatch"); setups++; value = { secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:native?secret=JBSWY3DPEHPK3PXP" }; }
          else if (url.pathname === "/api/v1/account/totp/enable") { if (body.verifier !== expectedVerifier || body.code !== "123456" || enabled) throw new Error("enable proof mismatch"); enables++; enabled = true; value = { backup_codes: ["A2B3C4D5E6", "F7G8H9J2K3"] }; }
          else if (url.pathname === "/api/v1/account/totp/disable") { if (body.verifier !== expectedVerifier || body.code !== "123456" || !enabled) throw new Error("disable proof mismatch"); disables++; enabled = false; status = 204; value = null; }
          else throw new Error(`unexpected native route ${url.pathname}`);
        }
        res.writeHead(status, { "Content-Type": "application/json" }); res.end(status === 204 ? undefined : JSON.stringify(value));
      } catch (error) { faults.push(String(error)); res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ detail: "native fixture fault" })); }
    })(); handlers.push(handling);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: local server address unavailable");
  const origin = `http://127.0.0.1:${address.port}`, oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin"), originalEnable = api.totpEnable, descriptor = Object.getOwnPropertyDescriptor(api, "totpEnable");
  let observed: WeakRef<string[]> | undefined;
  Object.defineProperty(window.location, "origin", { configurable: true, value: origin });
  Object.defineProperty(api, "totpEnable", { ...descriptor, value: (...args: Parameters<typeof api.totpEnable>) => originalEnable(...args).then(result => { observed = new WeakRef(result.backup_codes); return result; }) });
  setSession("synthetic-retention-bearer", origin); let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    root = await render(<PatientsView displayName="Native clinician" session={session} onOpen={() => {}} onSignOut={() => {}} />);
    await press(root, "Show account security");
    await viWait(() => textOf(root!).includes("Set up authenticator"));
    await typeInto(root, "Current password (to authorize setup)", password); await press(root, "Set up authenticator");
    await viWait(() => textOf(root!).includes("6-digit code from the app"));
    await typeInto(root, "Current password (to authorize setup)", password); await typeInto(root, "6-digit code from the app", "123456"); await press(root, "Enable two-factor");
    await viWait(() => observed !== undefined && textOf(root!).includes("A2B3C4D5E6"));
    expect(setups).toBe(1); expect(enables).toBe(1); expect(observed?.deref()).toHaveLength(2);
    await typeInto(root, "Current password (to disable two-factor)", password); await typeInto(root, "6-digit code (to disable two-factor)", "123456"); await press(root, "Disable two-factor");
    await viWait(() => textOf(root!).includes("Two-factor authentication is off.")); expect(disables).toBe(1);
    for (const text of ["current one", "current two", "current three"]) await typeInto(root, "Current password (to authorize setup)", text);
    await Promise.all(handlers); expect(faults).toEqual([]); expect(positiveRef.deref()).toBe(positive);
    expect(await collected(observed!), "native received recovery-code array is released after disable").toBe(true);
  } finally {
    if (root) await act(async () => root!.unmount());
    clearSession(); if (descriptor) Object.defineProperty(api, "totpEnable", descriptor);
    if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin);
    wrapKey.fill(0); session.noteKey.fill(0); session.noteKeyV2.fill(0);
    await Promise.allSettled(handlers); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
}, 60_000);

async function viWait(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 500; i++) { if (predicate()) return; await new Promise(resolve => setTimeout(resolve, 10)); }
  throw new Error("SetupError: public native account action did not reach its expected completion");
}
