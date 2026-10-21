/** authored transient salt custody through the actual Settings
 * consumer. Genuine native provider Promises are forwarded unchanged. Salt
 * metadata is public; the observer proves bounded buffer retirement only. */
import { createCipheriv, createDecipheriv, hkdfSync, pbkdf2Sync } from "node:crypto";


import { act } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { SettingsView } from "../src/views/Settings";
import { vault } from "../src/vault";
import { __setLocaleForTests, applyLanguagePref, t } from "../src/strings";
import { installSession, resetTestState } from "./helpers/api";
import { render, textOf, textOfNode, typeInto } from "./helpers/rtr";

const OWNER = "synthetic-settings-salt-owner", USERNAME = "synthetic_settings_salt";
const PASSWORD = "a-fresh-long-passphrase-7", OLD_PASSWORD = "original-long-passphrase-9";
const RANDOM_DATA = Buffer.alloc(32, 63), PUBLIC_SALT = Buffer.alloc(16, 67);
const PARAMS = { algorithm: "pbkdf2-sha256", version: 1, iterations: 100_000 };
const DEFAULT_PARAMS = { ...PARAMS, iterations: 600_000 };
type Flow = "v2-password" | "v1-upgrade";
type Root = Awaited<ReturnType<typeof render>>;
type Captured = { actual: Uint8Array; before: Buffer; originalPromise: Promise<ArrayBuffer> };
const response = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
let witness: Record<string, unknown> = {};


async function until(ready: () => boolean, label: string): Promise<void> {
  const end = Date.now() + 15_000;
  while (!ready()) {
    if (Date.now() >= end) throw new Error(`SetupError: actual Settings producer deadline ${label}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
  await act(async () => { await Promise.resolve(); });
}

function envelope(password: string, salt: Buffer, data: Buffer): string {
  const master = pbkdf2Sync(password, salt, PARAMS.iterations, 32, "sha256");
  const kek = Buffer.from(hkdfSync("sha256", master, salt, "mindpattern/envelope/v2", 32));
  const nonce = Buffer.alloc(12, 71), cipher = createCipheriv("aes-256-gcm", kek, nonce);
  try { cipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: PARAMS, username: USERNAME }))); return Buffer.concat([nonce, cipher.update(data), cipher.final(), cipher.getAuthTag()]).toString("base64"); }
  finally { master.fill(0); kek.fill(0); }
}

function independentOpen(wrapped: string, salt: Buffer, params: typeof PARAMS): Buffer {
  const master = pbkdf2Sync(PASSWORD, salt, params.iterations, 32, "sha256");
  const kek = Buffer.from(hkdfSync("sha256", master, salt, "mindpattern/envelope/v2", 32)), wire = Buffer.from(wrapped, "base64");
  const decipher = createDecipheriv("aes-256-gcm", kek, wire.subarray(0, 12));
  try { decipher.setAAD(Buffer.from(JSON.stringify({ context: "envelope", kdf_params: params, username: USERNAME }))); decipher.setAuthTag(wire.subarray(-16)); return Buffer.concat([decipher.update(wire.subarray(12, -16)), decipher.final()]); }
  finally { master.fill(0); kek.fill(0); }
}

function independentVerifier(salt: Buffer, iterations: number): string {
  const master = pbkdf2Sync(PASSWORD, salt, iterations, 32, "sha256"), auth = Buffer.from(hkdfSync("sha256", master, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  try { return auth.toString("base64"); } finally { master.fill(0); auth.fill(0); }
}

async function publicPress(root: Root, label: string): Promise<void> {
  const button = root.root.findAllByType("button").find(node => textOfNode(node) === label);
  if (!button || button.props.disabled || typeof button.props.onClick !== "function") throw new Error(`SetupError: actual public Settings button unavailable ${label}`);
  // Shipped Button intentionally discards the async handler Promise. Its
  // actual remote acknowledgement plus rendered busy-finally is the finite
  // completion barrier; no private handler is extracted or rewritten.
  await act(async () => { button.props.onClick(); });
}

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); resetTestState(); applyLanguagePref("auto"); __setLocaleForTests("en");  });

it.each(["v2-password", "v1-upgrade"] as const)("retires owned native PBKDF2 salt after actual Settings %s completion", async (flow: Flow) => {
  vi.useRealTimers(); resetTestState(); applyLanguagePref("auto"); __setLocaleForTests("en"); installSession(OWNER, USERNAME);
  // A v1 account's data/auth keys derive from the same current600k password.
  // A v2 account has independent random data but its current verifier still
  // derives from the original600k password; its wrap cost can be100k.
  const currentMaster = pbkdf2Sync(flow === "v2-password" ? OLD_PASSWORD : PASSWORD, PUBLIC_SALT, 600_000, 32, "sha256");
  const currentAuth = Buffer.from(hkdfSync("sha256", currentMaster, Buffer.alloc(32), "mindpattern/auth/v1", 32));
  const currentData = flow === "v2-password" ? Buffer.from(RANDOM_DATA) : Buffer.from(hkdfSync("sha256", currentMaster, Buffer.alloc(32), "mindpattern/data/v1", 32));
  currentMaster.fill(0);
  const expectedParams = flow === "v2-password" ? PARAMS : DEFAULT_PARAMS;
  const callerData = new Uint8Array(currentData), callerAuth = new Uint8Array(currentAuth);
  vault.unlock({ dataKey: callerData, authKey: callerAuth }, OWNER);
   witness = { case: flow, stage: "setup", nodeVersion: process.version, limits: ["Public nonsecret salt metadata; authored transient-byte custody only.", "Actual Settings consumer with real native WebCrypto, synthetic Node transport/storage/renderer seams; no whole-App/backend/browser/device claim."] };
  let acknowledged = false, wire: { salt: string; wrapped: string; verifier: string } | undefined, notice: string | undefined;
  const initialWrap = envelope(OLD_PASSWORD, PUBLIC_SALT, currentData);
  vi.stubGlobal("fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = new URL(url).pathname, body = init?.body ? JSON.parse(String(init.body)) as Record<string, unknown> : {};
    if (String(init?.body ?? "").includes(PASSWORD)) throw new Error("SetupError: plaintext password crossed Settings transport");
    if (path.endsWith("/meta")) return response({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, audio_available: false });
    if (path.endsWith("/account/llm-consent") || path.endsWith("/account/voice-consent")) return response({ enabled: false, active_for_current_policy: false });
    if (path.endsWith("/auth/key-envelope")) return response({ key_scheme: flow === "v2-password" ? "v2" : "v1", salt: PUBLIC_SALT.toString("base64"), kdf_params: flow === "v2-password" ? PARAMS : null, wrapped_data_key: flow === "v2-password" ? initialWrap : null });
    if (path.endsWith("/account/access-log")) return response([]);
    if (path.endsWith("/auth/salt")) {
      if (body.username !== USERNAME) throw new Error("SetupError: upgrade salt requested for wrong public owner");
      return response({ salt: PUBLIC_SALT.toString("base64") });
    }
    if (path.endsWith("/processing/sessions")) {
      if (body.data_key !== currentData.toString("base64")) throw new Error("SetupError: possession request differs from current caller data key");
      return response({ session_token: "synthetic-current-key-possession", expires_in: 300 });
    }
    if (path.endsWith("/account/password") && flow === "v2-password") {
      if (body.verifier !== currentAuth.toString("base64") || new Headers(init?.headers).get("X-Processing-Token") !== "synthetic-current-key-possession" || JSON.stringify(body.new_kdf_params) !== JSON.stringify(expectedParams)) throw new Error("SetupError: actual public password credential/proof/params differ");
      wire = { salt: String(body.new_salt), wrapped: String(body.wrapped_data_key), verifier: String(body.new_verifier) };
      acknowledged = true; return new Response(null, { status: 204 });
    }
    if (path.endsWith("/account/key-envelope/upgrade") && flow === "v1-upgrade") {
      if (new Headers(init?.headers).get("X-Processing-Token") !== "synthetic-current-key-possession" || JSON.stringify(body.kdf_params) !== JSON.stringify(expectedParams) || new Headers(init?.headers).get("X-Account-Verifier") !== currentAuth.toString("base64")) throw new Error("SetupError: actual public upgrade current credential/proof/params differ");
      wire = { salt: PUBLIC_SALT.toString("base64"), wrapped: String(body.wrapped_data_key), verifier: new Headers(init?.headers).get("X-Account-Verifier") ?? "" };
      acknowledged = true; return new Response(null, { status: 204 });
    }
    throw new Error(`SetupError: unexpected actual Settings request ${path}`);
  });
  const root = await render(<SettingsView onLockdown={message => { notice = message; }} />);
  const label = flow === "v2-password" ? t("settings.changePasswordButton") : t("settings.upgradeButton");
  await until(() => root.root.findAllByType("button").some(node => textOfNode(node) === label), "initial live credential controls");
  const captured: Captured[] = [], nativeDerive = crypto.subtle.deriveBits;
  const forward = ((...args: Parameters<SubtleCrypto["deriveBits"]>) => {
    const promise = Reflect.apply(nativeDerive, crypto.subtle, args) as Promise<ArrayBuffer>;
    const algorithm = args[0] as Pbkdf2Params;
    if (algorithm.name === "PBKDF2") {
      if (!(algorithm.salt instanceof Uint8Array) || algorithm.salt.byteLength !== 16) throw new Error("SetupError: native Settings PBKDF2 owned salt has unsupported shape");
      captured.push({ actual: algorithm.salt, before: Buffer.from(algorithm.salt), originalPromise: promise });
    }
    return promise;
  }) as SubtleCrypto["deriveBits"];
  const observer = vi.spyOn(crypto.subtle, "deriveBits").mockImplementation(forward);
  if (flow === "v2-password") { await typeInto(root, t("settings.newPasswordField"), PASSWORD); await typeInto(root, t("settings.confirmPasswordField"), PASSWORD); }
  else await typeInto(root, t("settings.upgradePasswordField"), PASSWORD);
  await publicPress(root, label);
  await until(() => acknowledged && !root.root.findAllByType("button").some(node => textOfNode(node) === t("settings.working"))
    && (flow === "v2-password" ? notice !== undefined : textOf(root).includes(t("settings.upgradeDoneNote"))), "acknowledged handler and rendered busy-finally");
  observer.mockRestore();
  if (!wire || !acknowledged || captured.length === 0) throw new Error("SetupError: actual salt producer/remote acknowledgement missing");
  await Promise.all(captured.map(record => record.originalPromise));
  const currentWire = wire, matched = captured.filter(record => record.before.toString("base64") === currentWire.salt);
  if (matched.length === 0 || matched.some(record => record.before.every(byte => byte === 0))) throw new Error("SetupError: native pre-use salt does not match authenticated public metadata");
  const opened = independentOpen(currentWire.wrapped, Buffer.from(currentWire.salt, "base64"), expectedParams);
  const expectedVerifier = independentVerifier(Buffer.from(currentWire.salt, "base64"), 600_000);
  witness = { ...witness, stage: "behavior-oracle", publicProducer: { complete: true, actualRemoteAcknowledged: acknowledged, current600kAccountVerifierValidated: true, legacyEnvelopeParamsNull: flow === "v1-upgrade", renderedBusyFinallyCompleted: true, originalNativePromisesCompleted: true, positiveNativePreUseSaltMatchedPublicWire: true, publicSaltB64: currentWire.salt }, checks: [] };

  try {
    {
const name = "independent authenticated envelope preserves current data key";
const passed = opened.equals(currentData);
 witness.checks = [...(witness.checks as unknown[]), { name, passed }];  expect(passed, name).toBe(true);
}
    {
const name = "independent verifier matches actual credential wire";
const passed = currentWire.verifier === expectedVerifier;
 witness.checks = [...(witness.checks as unknown[]), { name, passed }];  expect(passed, name).toBe(true);
}
    {
const name = "all actual owned PBKDF2 salt inputs retire after completed handler";
const passed = matched.every(record => record.actual.every(byte => byte === 0));
 witness.checks = [...(witness.checks as unknown[]), { name, passed }];  expect(passed, name).toBe(true);
}
    {
const name = "caller data and auth buffers remain intact";
const passed = Buffer.from(callerData).equals(currentData) && Buffer.from(callerAuth).equals(currentAuth);
 witness.checks = [...(witness.checks as unknown[]), { name, passed }];  expect(passed, name).toBe(true);
}
    {
const name = "caller public input metadata remains intact";
const passed = PUBLIC_SALT.equals(Buffer.alloc(16, 67)) && Buffer.from(currentWire.salt, "base64").length === 16;
 witness.checks = [...(witness.checks as unknown[]), { name, passed }];  expect(passed, name).toBe(true);
}

  } finally { opened.fill(0); currentData.fill(0); currentAuth.fill(0); }
}, 60_000);
