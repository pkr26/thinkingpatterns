/** Synthetic native HTTP/WebCrypto retirement control for in-memory notes custody. */
import { hkdfSync, pbkdf2Sync } from "node:crypto";
import { createServer } from "node:http";
import { act, useState } from "react";
import { expect, it, vi } from "vitest";
import { clearSession, hasSession, setSession } from "../src/api";
import * as provider from "../src/crypto";
import { PatientsView } from "../src/views/PatientsView";
import type { PortalSession } from "../src/views/PatientView";
import { flush, press, render, textOf, typeInto } from "./helpers/rtr";

async function checkRetiredKeyring(action: "sharing-key rotation" | "password change" | "interrupted recovery"): Promise<void> {
  const username = "native-custody-clinician", owner = "0123456789abcdef0123456789abcdef", password = "correct horse battery staple", salt = "AAECAwQFBgcICQoLDA0ODw==";
  const master = pbkdf2Sync(password, Buffer.from(salt, "base64"), 600000, 32, "sha256");
  const wrapKey = new Uint8Array(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/portal-wrap/v1", 32)); master.fill(0);
  const generated = await provider.generateTherapistKeyPair(wrapKey, username);
  const unlocked = await provider.unlockWrapPrivateKeyWithNotesKey(wrapKey, generated.wrapKeyBlobB64, username);
  const intendedPassword = "a wholly separate strong phrase 42!", intendedSalt = "EBESExQVFhcYGRobHB0eHw==";
  const checkpointKey = `mindpattern.interruptedRotateSalt.${owner}`;
  const previousCheckpoint = window.sessionStorage.getItem(checkpointKey);
  let fixtureWrapBlob = generated.wrapKeyBlobB64;
  if (action === "interrupted recovery") {
    const intendedMaster = pbkdf2Sync(intendedPassword, Buffer.from(intendedSalt, "base64"), 600000, 32, "sha256");
    const intendedWrap = new Uint8Array(hkdfSync("sha256", intendedMaster, Buffer.alloc(32), "mindpattern/portal-wrap/v1", 32)); intendedMaster.fill(0);
    const identity = await provider.openSealedPrivateKey(wrapKey, generated.wrapKeyBlobB64, username);
    if (!identity) throw new Error("SetupError: original fixture identity did not open");
    try { fixtureWrapBlob = await provider.sealPrivateKeyForUpload(intendedWrap, identity, username); }
    finally { identity.fill(0); intendedWrap.fill(0); }
  }
  const session: PortalSession = { username, userId: owner, privateKey: unlocked.privateKey, publicKeyB64: generated.publicKeySpkiB64, noteKey: new Uint8Array(32).fill(42), noteKeyV2: unlocked.noteKeyV2 };
  const seedRing = provider.createNotesKeyring(new Uint8Array(32).fill(61), new Uint8Array(32).fill(62));
  const ringBlob = await provider.sealNotesKeyring(wrapKey, owner, seedRing); provider.wipeNotesKeyring(seedRing);
  const patient = { user_id: "fedcba0987654321fedcba0987654321", username: "Current patient", status: "active", granted_at: "2026-10-01T00:00:00Z", revoked_at: null, wrapped_key: null, ephemeral_pub: null };
  const handlers: Promise<void>[] = [], faults: string[] = []; let patientRequests = 0;
  const server = createServer((req, res) => {
    const handling = (async () => {
      try {
        const url = new URL(req.url ?? "/", "http://127.0.0.1"); let body: Record<string, unknown> = {};
        if (req.method === "POST") { const chunks: Buffer[] = []; for await (const c of req) chunks.push(Buffer.from(c)); body = JSON.parse(Buffer.concat(chunks).toString()); }
        let value: unknown;
        if (url.pathname === "/api/v1/auth/salt") { if (body.username !== username) throw new Error("salt owner mismatch"); value = { salt }; }
        else {
          if (req.headers.authorization !== "Bearer synthetic-retired-keyring") throw new Error("bearer mismatch");
          if (url.pathname === "/api/v1/therapist/patients") { patientRequests++; value = [patient]; }
          else if (url.pathname === "/api/v1/therapist/me") value = { username, display_name: "Native clinician", wrap_pub_key: generated.publicKeySpkiB64, wrap_key_blob: fixtureWrapBlob, notes_keyring_blob: ringBlob, custody_version: 1, totp_enabled: false };
          else throw new Error(`unexpected native route ${url.pathname}`);
        }
        res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify(value));
      } catch (error) { faults.push(String(error)); res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ detail: "native fixture fault" })); }
    })(); handlers.push(handling);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: local server address unavailable");
  const origin = `http://127.0.0.1:${address.port}`, oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin");
  Object.defineProperty(window.location, "origin", { configurable: true, value: origin }); setSession("synthetic-retired-keyring", origin);
  let release!: () => void, retired = false, reached = false, retiredCopies = 0, activeControlCopies = 0;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const nativeOpen = provider.openNotesKeyring, nativeInclude = provider.includeNotesCustodyKey;
  let opened: provider.NotesKeyring | undefined, pending: Promise<provider.NotesKeyring> | undefined;
  const opening = vi.spyOn(provider, "openNotesKeyring").mockImplementation((...args) => {
    pending = nativeOpen(...args).then(async ring => { opened = ring; reached = true; await gate; return ring; });
    return pending;
  });
  const inclusion = vi.spyOn(provider, "includeNotesCustodyKey").mockImplementation((ring, key) => {
    const before = ring.historical.length; nativeInclude(ring, key); const added = ring.historical.length - before;
    if (retired) retiredCopies += added; else activeControlCopies += added;
  });
  function Routes() { const [chart, setChart] = useState(false); return chart ? <p>Current patient chart</p> : <PatientsView displayName="Native clinician" session={session} onOpen={() => setChart(true)} onSignOut={() => {}} />; }
  let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    if (action === "interrupted recovery") window.sessionStorage.setItem(checkpointKey, intendedSalt);
    root = await render(<Routes />); await vi.waitFor(() => expect(textOf(root!)).toContain("Current patient"));
    await press(root, "Show account security"); await vi.waitFor(() => expect(textOf(root!)).toContain("Set up authenticator"));
    if (action === "sharing-key rotation") {
      await typeInto(root, "Current password (to authorize rotation)", password);
      const confirmation = root.root.findAllByType("input").find(node => node.props["aria-label"] === "Confirm sharing-key rotation")!;
      await act(async () => confirmation.props.onChange({ target: { checked: true } })); await press(root, "Rotate sharing key");
    } else if (action === "password change") {
      await typeInto(root, "Current password", password);
      await typeInto(root, "New password", intendedPassword);
      await typeInto(root, "Repeat new password", intendedPassword);
      await press(root, "Change password");
    } else {
      expect(textOf(root)).toContain("An interrupted change from this browser session is repairable right now");
      await typeInto(root, "Current password (the one you sign in with)", password);
      await typeInto(root, "The password you were changing to", intendedPassword);
      await press(root, "Recover sharing key");
    }
    await vi.waitFor(() => expect(reached).toBe(true), { timeout: 10_000 });
    if (!opened || !pending) throw new Error("SetupError: genuine keyring open did not reach the owned gate");
    const controlRing = provider.createNotesKeyring(new Uint8Array(32).fill(71), new Uint8Array(32).fill(72));
    provider.includeNotesCustodyKey(controlRing, new Uint8Array(32).fill(73)); expect(activeControlCopies).toBe(1); provider.wipeNotesKeyring(controlRing);
    const patientRequestsBeforeRetirement = patientRequests;
    await press(root, "Open patterns"); expect(textOf(root)).toContain("Current patient chart"); expect(hasSession()).toBe(true); retired = true;
    await act(async () => { release(); await pending; }); await flush(12); await Promise.all(handlers);
    expect(faults).toEqual([]); expect(patientRequests).toBe(patientRequestsBeforeRetirement); expect(hasSession()).toBe(true);
    expect(opened.active.every(byte => byte === 0)).toBe(true);
    expect(opened.historical.every(key => key.every(byte => byte === 0))).toBe(true);
    expect(retiredCopies, "a retired view must not make fresh copies of notes-custody keys").toBe(0);
  } finally {
    release(); if (pending) await Promise.allSettled([pending]); if (root) await act(async () => root!.unmount());
    opening.mockRestore(); inclusion.mockRestore(); clearSession(); if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin); else Reflect.deleteProperty(window.location, "origin");
    wrapKey.fill(0); session.noteKey.fill(0); session.noteKeyV2.fill(0);
    if (previousCheckpoint === null) window.sessionStorage.removeItem(checkpointKey); else window.sessionStorage.setItem(checkpointKey, previousCheckpoint);
    await Promise.allSettled(handlers); server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
}

it("does not copy notes-custody keys after a retired keyring open completes", async () => {
  await checkRetiredKeyring("sharing-key rotation");
}, 60_000);

it("does not copy notes-custody keys after a retired password-change keyring open completes", async () => {
  await checkRetiredKeyring("password change");
}, 60_000);

it("does not copy notes-custody keys after a retired interrupted-recovery keyring open completes", async () => {
  await checkRetiredKeyring("interrupted recovery");
}, 60_000);
