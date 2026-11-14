import { createCipheriv, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { ErrorBoundary } from "../src/ErrorBoundary";
import { clearSession, hasSession } from "../src/api";
import { flush, press, render, textOf, textOfNode, typeInto } from "./helpers/rtr";

beforeEach(() => {
  vi.useRealTimers();
  clearSession();
  window.localStorage.clear();
  window.sessionStorage.clear();
  window.location.hash = "";
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); clearSession(); });

it("offers the sign-in form on the first public shell render", async () => {
  vi.stubGlobal("fetch", async () => Response.json({ sharing_available: true }));
  const root = await render(<ErrorBoundary><App /></ErrorBoundary>);
  await flush();
  expect(root.root.findAllByType("input").filter(node => node.props.autoComplete === "username")).toHaveLength(1);
  expect(root.root.findAllByType("button").filter(node => textOfNode(node) === "Sign in")).toHaveLength(1);
  expect(textOf(root)).not.toContain("Unlocking…");
  expect(hasSession()).toBe(false);
});

it("opens the caseload after the real sharing-key import completes", async () => {
  const username = "shell_contract", owner = "0123456789abcdef0123456789abcdef";
  const password = "correct horse battery staple", salt = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const master = pbkdf2Sync(password, salt, 600_000, 32, "sha256");
  const auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/auth/v1"), 32));
  const wrap = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from("mindpattern/portal-wrap/v1"), 32));
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" });
  const patientId = "11111111111111111111111111111111", noteId = "22222222222222222222222222222222";
  const clinicalText = "A private note remains readable after the sharing identity is adopted.";
  const identityNotes = Buffer.from(hkdfSync("sha256", privateDer, Buffer.alloc(32), Buffer.from("mindpattern/portal-notes/v2"), 32));
  const noteNonce = randomBytes(12), noteCipher = createCipheriv("aes-256-gcm", identityNotes, noteNonce);
  noteCipher.setAAD(Buffer.from(JSON.stringify(["note", owner, patientId, noteId])));
  const noteBlob = Buffer.concat([noteNonce, noteCipher.update(Buffer.from(JSON.stringify({ v: 1, text: clinicalText }))), noteCipher.final(), noteCipher.getAuthTag()]).toString("base64");
  identityNotes.fill(0);
  const nonce = randomBytes(12), cipher = createCipheriv("aes-256-gcm", wrap, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["therapist-key", username])));
  const sealed = Buffer.concat([nonce, cipher.update(privateDer), cipher.final(), cipher.getAuthTag()]).toString("base64");
  const verifier = auth.toString("base64");
  master.fill(0); auth.fill(0); wrap.fill(0); privateDer.fill(0);
  let privateImported = false;
  const nativeImport = crypto.subtle.importKey.bind(crypto.subtle);
  vi.spyOn(crypto.subtle, "importKey").mockImplementation((async (...args: Parameters<typeof nativeImport>) => {
    const result = await nativeImport(...args);
    if (args[0] === "pkcs8" && result.algorithm.name === "ECDH") privateImported = true;
    return result;
  }) as typeof crypto.subtle.importKey);
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url).pathname;
    if (path === "/api/v1/meta") return Response.json({ sharing_available: true });
    if (path === "/api/v1/auth/salt") return Response.json({ salt: salt.toString("base64") });
    if (path === "/api/v1/auth/login") {
      const body = JSON.parse(String(init?.body));
      expect(body.username).toBe(username); expect(body.verifier).toBe(verifier);
      return Response.json({ token: "native-shell-contract", user_id: owner, role: "therapist", expires_in: 86_400 });
    }
    if (path === "/api/v1/therapist/me") return Response.json({ username, display_name: "Dr. Shell Contract", wrap_key_blob: sealed, wrap_pub_key: pair.publicKey.export({ format: "der", type: "spki" }).toString("base64"), totp_enabled: true });
    if (path === "/api/v1/therapist/patients") return Response.json([{ user_id: patientId, username: "clinical_note_owner", status: "revoked", granted_at: "2026-09-01T00:00:00Z", revoked_at: "2026-09-02T00:00:00Z", ephemeral_pub: null, wrapped_key: null }]);
    if (path === `/api/v1/therapist/patients/${patientId}/notes`) return Response.json([{ id: noteId, client_note_id: noteId, blob: noteBlob, created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z", version: 1, pattern_pid: null }]);
    if (path === "/api/v1/auth/logout") return new Response(null, { status: 204 });
    throw new Error(`Unexpected HTTP request: ${path}`);
  });
  const root = await render(<ErrorBoundary><App /></ErrorBoundary>);
  expect(root.root.findAllByType("input").filter(node => node.props.autoComplete === "username")).toHaveLength(1);
  await typeInto(root, "Username", username); await typeInto(root, "Password", password); await press(root, "Sign in");
  await vi.waitFor(() => expect(privateImported).toBe(true), { timeout: 5_000 });
  await act(async () => { await flush(12); });
  expect(textOf(root)).toContain("Patients — Dr. Shell Contract");
  expect(root.root.findAllByType("button").filter(node => textOfNode(node) === "Sign out")).toHaveLength(1);
  expect(hasSession()).toBe(true);
  await vi.waitFor(() => expect(root.root.findAllByType("button").filter(node => textOfNode(node) === "Open my notes")).toHaveLength(1));
  await press(root, "Open my notes");
  await vi.waitFor(() => expect(textOf(root)).toContain(clinicalText), { timeout: 3_000 });
}, 15_000);
