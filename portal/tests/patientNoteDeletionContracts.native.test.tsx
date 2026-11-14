import { createDecipheriv } from "node:crypto";
import { createServer } from "node:http";
import { IDBFactory } from "fake-indexeddb";
import { act } from "react";
import { expect, it, vi } from "vitest";
import { api, clearSession, setSession } from "../src/api";
import { encryptNote } from "../src/crypto";
import { drainPortalDraftWritesForTests } from "../src/noteDrafts";
import { resetKvConnectionForTests, setKvBackendForTests } from "../src/kvstore";
import { PatientView, type PortalSession } from "../src/views/PatientView";
import { press, render, textOf, typeTextarea } from "./helpers/rtr";

/** Note IDs are opaque to this consumer. Each newly displayed clinical record
 * needs its own two-step confirmation, even if an accepted HTTP response reuses
 * the ID of a removed record. Ciphertext remains bound to its own client ID. */
it("requires a fresh deletion confirmation for a newly saved note with a reused opaque server ID", async () => {
  const owner = "1234567890abcdef1234567890abcdef", patientId = "fedcba0987654321fedcba0987654321";
  const identity = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const session: PortalSession = { userId: owner, username: "native-note-clinician", noteKey: new Uint8Array(32).fill(31), noteKeyV2: new Uint8Array(32).fill(32), privateKey: identity.privateKey, publicKeyB64: "" };
  const patient = { user_id: patientId, username: "Native note patient", status: "revoked", granted_at: "2026-10-01", revoked_at: "2026-10-02", ephemeral_pub: null, wrapped_key: null };
  const originalText = "Authenticated first clinical record", nextText = "A distinct authenticated replacement record";
  const sealed = await encryptNote(session.noteKeyV2, owner, patientId, "first-client-note", originalText);
  const first = { id: "opaque-reusable-record-id", client_note_id: "first-client-note", blob: sealed.blobB64, pattern_pid: null, version: 1, created_at: "2026-10-01T00:00:00Z", updated_at: "2026-10-01T00:00:00Z" };
  let rows = [first]; const deletes: string[] = [], saved: string[] = [], faults: unknown[] = [], handlers: Promise<void>[] = [], producers: Promise<unknown>[] = [];
  const server = createServer((request, response) => {
    const handling = (async () => {
      try {
        const path = new URL(request.url ?? "/", "http://127.0.0.1").pathname;
        expect(request.headers.authorization).toBe("Bearer native-deletion-bearer");
        let value: unknown, status = 200;
        if (request.method === "GET" && path.endsWith(`/patients/${patientId}/notes`)) { value = rows; response.setHeader("X-Notes-Revision", "1"); }
        else if (request.method === "DELETE" && path.endsWith(`/notes/${first.id}`)) { deletes.push(first.id); rows = []; value = null; }
        else if (request.method === "POST" && path.endsWith(`/patients/${patientId}/notes`)) {
          const pieces: Buffer[] = []; for await (const part of request) pieces.push(Buffer.from(part));
          const body = JSON.parse(Buffer.concat(pieces).toString()) as { client_note_id: string; blob: string };
          const bytes = Buffer.from(body.blob, "base64"), decipher = createDecipheriv("aes-256-gcm", session.noteKeyV2, bytes.subarray(0, 12));
          decipher.setAAD(Buffer.from(JSON.stringify(["note", owner, patientId, body.client_note_id]))); decipher.setAuthTag(bytes.subarray(-16));
          const plain = Buffer.concat([decipher.update(bytes.subarray(12, -16)), decipher.final()]);
          try { saved.push((JSON.parse(plain.toString()) as { text: string }).text); } finally { plain.fill(0); }
          value = { ...first, client_note_id: body.client_note_id, blob: body.blob, created_at: "2026-10-03T00:00:00Z", updated_at: "2026-10-03T00:00:00Z" }; rows = [value as typeof first]; status = 201;
        } else { status = 404; value = { detail: "Unknown owned note route" }; }
        response.writeHead(status, { "Content-Type": "application/json" }); response.end(JSON.stringify(value));
      } catch (error) { faults.push(error); response.writeHead(500, { "Content-Type": "application/json" }); response.end(JSON.stringify({ detail: "Owned note fixture failed" })); }
    })(); handlers.push(handling);
  });
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", resolve); });
  const address = server.address(); if (!address || typeof address === "string") throw new Error("SetupError: native note listener missing");
  const origin = `http://127.0.0.1:${address.port}`, oldOrigin = Object.getOwnPropertyDescriptor(window.location, "origin"), oldIdb = Object.getOwnPropertyDescriptor(globalThis, "indexedDB"), databases: IDBDatabase[] = [];
  const factory = new IDBFactory(), opening = factory.open;
  factory.open = (...args: Parameters<IDBFactory["open"]>) => { const request = opening.apply(factory, args); request.addEventListener("success", () => databases.push(request.result)); return request; };
  Object.defineProperty(window.location, "origin", { configurable: true, value: origin }); vi.stubGlobal("indexedDB", factory); resetKvConnectionForTests(); setKvBackendForTests(null); setSession("native-deletion-bearer", origin);
  const observers = (["notes", "deleteNote", "createNote"] as const).map(name => {
    const original = api[name]; return vi.spyOn(api, name).mockImplementation(((...args: never[]) => { const promise = (original as (...args: never[]) => Promise<unknown>)(...args); producers.push(promise); void promise.catch(() => undefined); return promise; }) as never);
  });
  let root: Awaited<ReturnType<typeof render>> | undefined;
  try {
    root = await render(<PatientView patient={patient} session={session} onBack={() => {}} />);
    await vi.waitFor(() => { expect(textOf(root!)).toContain(originalText); expect(textOf(root!)).toContain("Drafts are encrypted on this device."); });
    await press(root, "Delete"); expect(deletes).toEqual([]); expect(textOf(root)).toContain("Permanently delete this note?");
    await press(root, "Confirm delete"); await vi.waitFor(() => { expect(deletes).toEqual([first.id]); expect(textOf(root!)).not.toContain(originalText); });
    await typeTextarea(root, "Note about this patient…", nextText); await press(root, "Save note");
    await vi.waitFor(() => { expect(saved).toEqual([nextText]); expect(textOf(root!)).toContain(nextText); expect(textOf(root!)).toContain("Draft saved encrypted on this device."); });
    expect(textOf(root), "A new clinical record must start unarmed even when the server reuses an opaque note ID").not.toContain("Permanently delete this note?");
    await press(root, "Delete"); expect(deletes).toEqual([first.id]); expect(textOf(root)).toContain("Permanently delete this note?");
    await press(root, "Confirm delete"); await vi.waitFor(() => { expect(deletes).toEqual([first.id, first.id]); expect(textOf(root!)).not.toContain(nextText); });
    expect(faults).toEqual([]);
  } finally {
    try { if (root) await act(async () => root!.unmount()); await Promise.allSettled([...producers, ...handlers]); await drainPortalDraftWritesForTests(); }
    finally { observers.forEach(observer => observer.mockRestore()); clearSession(); databases.forEach(db => db.close()); resetKvConnectionForTests(); setKvBackendForTests(null); session.noteKey.fill(0); session.noteKeyV2.fill(0);
      if (oldOrigin) Object.defineProperty(window.location, "origin", oldOrigin); if (oldIdb) Object.defineProperty(globalThis, "indexedDB", oldIdb); else Reflect.deleteProperty(globalThis, "indexedDB");
      server.closeAllConnections(); await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())); }
  }
}, 30_000);
