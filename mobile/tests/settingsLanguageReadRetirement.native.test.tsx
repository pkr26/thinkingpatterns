/** Direct mounted Settings route, physical encrypted language receipt and real
 * HTTP/client/vault. This does not claim an AppNavigator or device commit run. */
import ReactTestRenderer, { act } from "react-test-renderer";
import { createServer, type ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Text } from "react-native";
import { SettingsScreen } from "../src/screens/SettingsScreen";
import { ThemeProvider, themeStorageKey } from "../src/theme";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { setLocale } from "../src/strings";
import { runTestControl } from "./helpers/testControl";
import * as keychain from "./helpers/keychainMock";
import storage from "./helpers/storageMock";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const OWNER = "b".repeat(32), LANGUAGE_SLOT = "@mindpattern/language_pref";
const OLD_BEARER = "owned-settings-original-bearer", NEW_BEARER = "owned-settings-replacement-bearer";
const INITIAL_ROUTES = ["/api/v1/meta", "/api/v1/account/llm-consent", "/api/v1/account/voice-consent", "/api/v1/auth/key-envelope"];
let screen: ReturnType<typeof ReactTestRenderer.create> | undefined;
let server: ReturnType<typeof createServer> | undefined, origin = "";
let recoveryRequests: string[] = [], finishedRoutes = new Set<string>(), faults: unknown[] = [], releases: Array<() => void> = [];
let originalFetch: typeof fetch;
const setup = (message: string) => new Error(`SetupError: Settings language fixture: ${message}`);
async function finite<T>(label: string, work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(`owned ${label} did not settle`)), 15000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function flush() { await act(async () => { for (let i = 0; i < 80; i++) await Promise.resolve(); }); }
function text() { return screen?.root.findAllByType(Text).map(node => node.props.children).flat(Infinity).filter(value => typeof value === "string" || typeof value === "number").join(" ") ?? ""; }
async function waitFor(label: string, ready: () => boolean) {
  const deadline = Date.now() + 5000;
  while (!ready()) {
    if (Date.now() >= deadline) throw setup(`${label} did not become observable: ${text()}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
}
async function mount() {
  await act(async () => { screen = ReactTestRenderer.create(<ThemeProvider><SettingsScreen navigation={{ navigate: () => undefined, popToTop: () => undefined }} /></ThemeProvider>); });
  await flush();
}
async function unmount() { if (screen) await act(async () => { screen!.unmount(); screen = undefined; }); }
async function account(bearer: string) {
  await finite("session publication", api.setSession(bearer, OWNER, "owned-settings"));
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 6) }, OWNER);
}
function send(response: ServerResponse, value: unknown) { response.writeHead(200, { "content-type": "application/json" }); response.end(JSON.stringify(value)); }
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); setLocale("en"); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); vault.lock();
  recoveryRequests = []; finishedRoutes = new Set(); faults = []; releases = []; originalFetch = globalThis.fetch;
  server = createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "", origin), bearer = request.headers.authorization ?? "";
      if (request.method !== "GET" || (bearer !== `Bearer ${OLD_BEARER}` && bearer !== `Bearer ${NEW_BEARER}`) || url.search) throw setup("unexpected native method, bearer or query");
      response.once("finish", () => finishedRoutes.add(url.pathname));
      if (url.pathname === "/api/v1/meta") { send(response, { unlock_days: 30, llm_available: true, sharing_available: true, audio_available: true }); return; }
      if (url.pathname === "/api/v1/account/llm-consent" || url.pathname === "/api/v1/account/voice-consent") { send(response, { enabled: false, active_for_current_policy: true }); return; }
      if (url.pathname === "/api/v1/auth/key-envelope") { send(response, { key_scheme: "v1", salt: Buffer.alloc(16, 3).toString("base64"), kdf_params: null, wrapped_data_key: null }); return; }
      if (url.pathname === "/api/v1/account/recovery") {
        recoveryRequests.push(bearer);
        send(response, { enabled: true, set_at: bearer === `Bearer ${OLD_BEARER}` ? "2026-10-05T12:00:00Z" : "2026-10-06T12:00:00Z", scheme: "v2" }); return;
      }
      throw setup(`unexpected owned native route ${url.pathname}`);
    } catch (error) { faults.push(error); response.writeHead(500, { "content-type": "application/json" }); response.end(JSON.stringify({ detail: "Owned fixture fault" })); }
  });
  await finite("HTTP listen", new Promise<void>((resolve, reject) => { server!.once("error", reject); server!.listen(0, "127.0.0.1", () => { server!.removeListener("error", reject); resolve(); }); }));
  const address = server.address(); if (!address || typeof address === "string") throw setup("owned HTTP address missing"); origin = `http://127.0.0.1:${address.port}`;
  if (await setBaseUrl(origin) !== null) throw setup("owned loopback origin was refused");
  await account(OLD_BEARER); await secureStore.setItem(LANGUAGE_SLOT, "en");
});
afterEach(async () => {
  for (const release of releases) release(); await flush(); await unmount(); vault.lock(); await finite("session cleanup", api.clearSession());
  server?.closeAllConnections(); if (server?.listening) await finite("HTTP close", new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())));
  server = undefined; vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null); setLocale("en");
  if (faults.length) throw setup(`native HTTP fault: ${String(faults[0])}`);
  if (globalThis.fetch !== originalFetch) throw setup("native fetch identity changed");
});

describe("Settings post-language-read request admission", () => {
  it.each(["live route", "retired route"] as const)("keeps physical language completion bound to its %s", async mode => {
    const read = storage.getItem; let armed = true, captured: string | null = null, release!: () => void, entered!: () => void, settled!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; }), started = new Promise<void>(resolve => { entered = resolve; }), releasedBackend = new Promise<void>(resolve => { settled = resolve; }); releases.push(release);
    vi.spyOn(storage, "getItem").mockImplementation(async key => {
      const original = await read(key);
      if (armed && key === LANGUAGE_SLOT) {
        armed = false; captured = original;
        if (!original || JSON.parse(original).v !== 1 || typeof JSON.parse(original).c !== "string") throw setup("original physical language ciphertext missing");
        entered(); await gate; settled();
      }
      return original;
    });
    await mount(); await finite("physical language read entry", started);
    await waitFor("other original Settings requests", () => INITIAL_ROUTES.every(path => finishedRoutes.has(path))); await flush();
    expect(recoveryRequests).toEqual([]); expect(captured).not.toContain('"en"');
    if (mode === "retired route") { await unmount(); vault.lock(); await finite("original session retirement", api.clearSession()); await account(NEW_BEARER); }
    release(); await finite("original encrypted language release", releasedBackend);
    // v1 decoding has only its cached device-key await and synchronous decrypt.
    // Finish that receipt before admitting the fresh route's healthy read.
    await flush(); await new Promise<void>(resolve => setImmediate(resolve)); await flush();
    if (mode === "live route") {
      await waitFor("live public recovery status", () => text().includes("Recovery kit active since 2026-10-05."));
      expect(recoveryRequests).toEqual([`Bearer ${OLD_BEARER}`]);
    } else {
      await finite("healthy replacement metadata completion", api.meta());
      await mount(); await waitFor("replacement public recovery status", () => text().includes("Recovery kit active since 2026-10-06."));
      expect(recoveryRequests, "an unmounted language continuation must not borrow the replacement account's authenticated native provider lane").toEqual([`Bearer ${NEW_BEARER}`]);

      // The earlier theme receipt owns a different cancellation boundary:
      // retirement must prevent admission of a new encrypted language read.
      await unmount();
      const themeSlot = themeStorageKey(), backendReads: Promise<string | null>[] = [];
      let releaseTheme!: () => void, themeReceipts = 0, languageReads = 0;
      const themeGate = new Promise<void>(resolve => { releaseTheme = resolve; });
      releases.push(releaseTheme);
      vi.spyOn(storage, "getItem").mockImplementation(key => {
        const original = read(key);
        if (key === LANGUAGE_SLOT) languageReads++;
        const delivered = original.then(async value => {
          if (key === themeSlot) { themeReceipts++; await themeGate; }
          return value;
        });
        backendReads.push(delivered);
        return delivered;
      });
      try {
        await mount();
        await waitFor("both original theme receipts", () => themeReceipts === 2);
        expect(languageReads).toBe(0);
        await unmount();
        releaseTheme();
        let drained = 0;
        await act(async () => {
          while (drained < backendReads.length) {
            const current = backendReads.slice(drained); drained = backendReads.length;
            const results = await finite("original theme/language backend receipts", Promise.allSettled(current));
            const failed = results.find(result => result.status === "rejected");
            if (failed?.status === "rejected") throw failed.reason;
          }
        });
        await flush();
        expect(languageReads, "a retired Settings theme receipt must not admit a new encrypted native language read").toBe(0);
        await finite("live replacement session control", api.meta());
      } finally {
        releaseTheme();
        await unmount();
        let drained = 0;
        while (drained < backendReads.length) {
          const current = backendReads.slice(drained); drained = backendReads.length;
          await finite("owned theme receipt cleanup", Promise.allSettled(current));
        }
      }
    }
  });
});
