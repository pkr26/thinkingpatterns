import { generateKeyPairSync, hkdfSync, pbkdf2Sync } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PatientsView } from "../src/views/PatientsView";
import { clearSession, setSession } from "../src/api";
import { flush, press, render, textOf, typeInto } from "./helpers/rtr";

beforeEach(() => { vi.useRealTimers(); clearSession(); window.localStorage.clear(); window.sessionStorage.clear(); });
afterEach(() => { clearSession(); vi.unstubAllGlobals(); });

it("keeps a successful authenticator enrollment usable when its accepted response omits recovery codes", async () => {
  const username = "native_totp_response", owner = "0123456789abcdef0123456789abcdef";
  const password = "correct horse battery staple", salt = Buffer.from("000102030405060708090a0b0c0d0e0f", "hex");
  const master = pbkdf2Sync(password, salt, 600_000, 32, "sha256");
  const derive = (label: string) => Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), Buffer.from(label), 32));
  const verifierBytes = derive("mindpattern/auth/v1"), verifier = verifierBytes.toString("base64");
  const noteKey = new Uint8Array(derive("mindpattern/portal-notes/v1"));
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const privateDer = pair.privateKey.export({ format: "der", type: "pkcs8" });
  const noteKeyV2 = new Uint8Array(hkdfSync("sha256", privateDer, Buffer.alloc(32), Buffer.from("mindpattern/portal-notes/v2"), 32));
  const privateKey = await crypto.subtle.importKey("pkcs8", new Uint8Array(privateDer), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicKeyB64 = pair.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  master.fill(0); verifierBytes.fill(0); privateDer.fill(0);
  let enabled = false;
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const path = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url).pathname;
    if (path === "/api/v1/therapist/patients") return Response.json([]);
    if (path === "/api/v1/therapist/me") return Response.json({ username, display_name: "Dr. Native TOTP", wrap_pub_key: publicKeyB64, wrap_key_blob: "unused-current-profile", totp_enabled: enabled });
    if (path === "/api/v1/auth/salt") return Response.json({ salt: salt.toString("base64") });
    const body = JSON.parse(String(init?.body));
    expect(new Headers(init?.headers).get("Authorization")).toBe("Bearer native-totp-response");
    expect(body.verifier).toBe(verifier);
    if (path === "/api/v1/account/totp/setup") return Response.json({ secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:native?secret=JBSWY3DPEHPK3PXP" });
    if (path === "/api/v1/account/totp/enable") { expect(body.code).toBe("123456"); enabled = true; return Response.json({}); }
    throw new Error(`Unexpected authenticated request: ${path}`);
  });
  setSession("native-totp-response", "http://localhost:5173");
  const root = await render(<PatientsView displayName="Dr. Native TOTP" session={{ username, userId: owner, noteKey, noteKeyV2, privateKey, publicKeyB64 }} onOpen={() => {}} onSignOut={() => {}} />);
  await flush(); await press(root, "Show account security");
  await vi.waitFor(() => expect(textOf(root)).toContain("Set up authenticator"));
  await typeInto(root, "Current password (to authorize setup)", password); await press(root, "Set up authenticator");
  await vi.waitFor(() => expect(textOf(root)).toContain("Enable two-factor"));
  await typeInto(root, "Current password (to authorize setup)", password); await typeInto(root, "6-digit code from the app", "123456");
  await press(root, "Enable two-factor");
  await vi.waitFor(() => expect(textOf(root)).toContain("Two-factor authentication is on:"), { timeout: 3_000 });
  expect(enabled).toBe(true);
  expect(textOf(root)).toContain("Disable two-factor");
  expect(textOf(root)).not.toContain("could not enable two-factor");
}, 15_000);
