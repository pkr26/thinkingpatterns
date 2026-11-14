import { createDecipheriv } from "node:crypto";
import { createServer } from "node:http";
import { IDBFactory } from "fake-indexeddb";
import { act, useState } from "react";
import { expect, it, vi } from "vitest";
import { api, clearSession, hasSession, setSession } from "../src/api";
import * as portalCrypto from "../src/crypto";
import { resetKvConnectionForTests, setKvBackendForTests, kv } from "../src/kvstore";
import * as drafts from "../src/noteDrafts";
import { PatientView, type PortalSession } from "../src/views/PatientView";
import { press, render, textOf, typeTextarea } from "./helpers/rtr";

const OWNER = "1234567890abcdef1234567890abcdef", PATIENT = "fedcba0987654321fedcba0987654321";
const CLIENT = "native-retirement-client", ORIGINAL = "Authenticated saved clinician note", WRITING = "Authenticated clinician writing awaiting completion";
const patient = { user_id: PATIENT, username: "Native retirement patient", status: "revoked", granted_at: "2026-10-01T00:00:00Z", revoked_at: "2026-10-02T00:00:00Z", ephemeral_pub: null, wrapped_key: null };

function independentlyOpen(key: Uint8Array, id: string, blob: string): string {
  const wire = Buffer.from(blob, "base64"), decipher = createDecipheriv("aes-256-gcm", key, wire.subarray(0, 12));
  decipher.setAAD(Buffer.from(JSON.stringify(["note", OWNER, PATIENT, id]))); decipher.setAuthTag(wire.subarray(-16));
  const plain = Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]);
  try { return (JSON.parse(plain.toString()) as { text: string }).text; } finally { plain.fill(0); }
}

it.each([
  { action: "create", retire: false }, { action: "create", retire: true },
  { action: "edit", retire: false }, { action: "edit", retire: true },
])("a completed native $action producer keeps its public route custody when retired=$retire", async ({ action, retire }) => {
  const wrapKey = new Uint8Array(32).fill(41), generated = await portalCrypto.generateTherapistKeyPair(wrapKey, "native-clinician");
  const unlocked = await portalCrypto.unlockWrapPrivateKeyWithNotesKey(wrapKey, generated.wrapKeyBlobB64, "native-clinician");
  const session: PortalSession = { userId: OWNER, username: "native-clinician", noteKey: new Uint8Array(32).fill(42), noteKeyV2: unlocked.noteKeyV2, privateKey: unlocked.privateKey, publicKeyB64: generated.publicKeySpkiB64 };
  const sealed = await portalCrypto.encryptNote(session.noteKeyV2, OWNER, PATIENT, CLIENT, ORIGINAL);
  expect(independentlyOpen(session.noteKeyV2, CLIENT, sealed.blobB64)).toBe(ORIGINAL);
  const note = { id: "native-retirement-note", client_note_id: CLIENT, blob: sealed.blobB64, pattern_pid: null, version: 1, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" };
  const writes: Array<{ method: string; authorization: string; plaintext: string }> = [], faults: unknown[] = [], handlers: Promise<void>[] = [];
  const server = createServer((request, response) => {
    const handling = (async () => {
      try {
        const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
        let value: unknown, status = 200;
        if (request.method === "GET" && path.endsWith(`/patients/${PATIENT}/notes`)) {
          value = action === "edit" ? [note] : []; response.setHeader("X-Notes-Revision", "1");
        } else if (request.method === "POST" && path.endsWith(`/patients/${PATIENT}/notes`) || request.method === "PATCH" && path.endsWith(`/notes/${note.id}`)) {
          const parts: Buffer[] = []; for await (const part of request) parts.push(Buffer.from(part));
          const body = JSON.parse(Buffer.concat(parts).toString()) as { blob: string; client_note_id?: string };
          const id = action === "create" ? body.client_note_id! : CLIENT;
          const plaintext = independentlyOpen(session.noteKeyV2, id, body.blob);
          writes.push({ method: request.method!, authorization: String(request.headers.authorization), plaintext });
          value = { ...note, client_note_id: id, blob: body.blob, version: 2 }; status = request.method === "POST" ? 201 : 200;
        } else { status = 404; value = { detail: "unknown native note route" }; }
        response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(value));
      } catch (error) { faults.push(error); response.writeHead(500, { "Content-Type": "application/json" }); response.end(JSON.stringify({ detail: "native fixture failed" })); }
    })(); handlers.push(handling);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: owned native note server has no address");
  const origin = `http://127.0.0.1:${address.port}`, oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin"), oldIdb = Object.getOwnPropertyDescriptor(globalThis, "indexedDB");
  const factory = new IDBFactory(), databases: IDBDatabase[] = [], open = factory.open;
  factory.open = (...args: Parameters<IDBFactory["open"]>) => { const request = open.apply(factory, args); request.addEventListener("success", () => databases.push(request.result)); return request; };
  Object.defineProperty(window.location, "origin", { configurable: true, value: origin }); vi.stubGlobal("indexedDB", factory);
  resetKvConnectionForTests(); setKvBackendForTests(null); window.localStorage.clear(); window.sessionStorage.clear(); setSession("native-note-bearer", origin);
  let release!: () => void, armed = false, reached = false;
  const held = new Promise<void>(resolve => { release = resolve; });
  const originals: Promise<unknown>[] = [], deliveries: Promise<unknown>[] = [], restorers: Array<() => void> = [];
  const own = <T,>(promise: Promise<T>): Promise<T> => { originals.push(promise); void promise.catch(() => undefined); return promise; };
  for (const name of ["notes", "createNote", "updateNote"] as const) {
    const original = api[name];
    const observer = vi.spyOn(api, name).mockImplementation(((...args: never[]) => own((original as (...args: never[]) => Promise<unknown>)(...args))) as never);
    restorers.push(() => observer.mockRestore());
  }
  const save = drafts.savePortalDraft;
  const saving = vi.spyOn(drafts, "savePortalDraft").mockImplementation((...args) => own(save(...args))); restorers.push(() => saving.mockRestore());
  const set = kv.setItem.bind(kv);
  const setting = vi.spyOn(kv, "setItem").mockImplementation((...args) => {
    const original = own(set(...args));
    if (action !== "create" || !armed || args[0] !== `portal.draft.${OWNER}.${PATIENT}`) return original;
    armed = false;
    const delivery = original.then(async () => { reached = true; await held; }); deliveries.push(delivery); return delivery;
  }); restorers.push(() => setting.mockRestore());
  const subtle = crypto.subtle, encrypt = subtle.encrypt;
  const encrypting = vi.spyOn(subtle, "encrypt").mockImplementation((...args) => {
    const original = own(encrypt.apply(subtle, args)), algorithm = args[0];
    if (action !== "edit" || !armed || typeof algorithm !== "object" || !("additionalData" in algorithm) || new TextDecoder().decode(algorithm.additionalData) !== JSON.stringify(["note", OWNER, PATIENT, CLIENT])) return original;
    armed = false;
    const delivery = original.then(async ciphertext => { reached = true; await held; return ciphertext; }); deliveries.push(delivery); return delivery;
  }); restorers.push(() => encrypting.mockRestore());
  const drain = async (): Promise<void> => {
    let count = -1;
    while (count !== originals.length + deliveries.length + handlers.length) {
      count = originals.length + deliveries.length + handlers.length;
      const outcomes = await Promise.allSettled([...originals, ...deliveries, ...handlers]);
      const failure = outcomes.find(result => result.status === "rejected"); if (failure?.status === "rejected") throw failure.reason;
      await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); });
    }
    expect(faults).toEqual([]);
  };
  let root: Awaited<ReturnType<typeof render>> | undefined;
  function Routes() { const [chart, setChart] = useState(true); return chart ? <PatientView patient={patient} session={session} onBack={() => setChart(false)} /> : <p>Current clinician caseload</p>; }
  try {
    root = await render(<Routes />);
    await vi.waitFor(() => expect(textOf(root!)).toContain(action === "edit" ? ORIGINAL : "No notes yet."));
    await drain();
    if (action === "edit") { await press(root, "Edit"); await typeTextarea(root, "Editing note…", WRITING); }
    else await typeTextarea(root, "Note about this patient…", WRITING);
    await drain(); armed = true; await press(root, action === "edit" ? "Save edit" : "Save note");
    try { await vi.waitFor(() => { if (!reached) throw new Error("The actual native write producer has not completed"); }, { timeout: 10_000 }); }
    catch (cause) { throw new Error("SetupError: native completed producer was not observed", { cause }); }
    if (retire) { await press(root, "Back to patients"); expect(textOf(root)).toContain("Current clinician caseload"); }
    expect(hasSession()).toBe(true);
    await act(async () => { release(); await drain(); });
    if (retire) expect(writes, "A retired chart cannot dispatch its old encrypted note through the still-current authenticated bearer").toEqual([]);
    else { expect(writes).toEqual([{ method: action === "create" ? "POST" : "PATCH", authorization: "Bearer native-note-bearer", plaintext: WRITING }]); expect(textOf(root)).toContain(WRITING); }
  } finally {
    release();
    try { if (root) await act(async () => { root!.unmount(); }); await drain(); }
    finally {
      restorers.reverse().forEach(restore => restore()); clearSession(); databases.forEach(db => db.close()); resetKvConnectionForTests();
      if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin);
      if (oldIdb) Object.defineProperty(globalThis, "indexedDB", oldIdb); else Reflect.deleteProperty(globalThis, "indexedDB");
      setKvBackendForTests(null); session.noteKey.fill(0); session.noteKeyV2.fill(0); wrapKey.fill(0);
      server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  }
}, 60_000);
