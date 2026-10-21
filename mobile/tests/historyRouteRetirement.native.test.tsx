/** Mounted History actions through the real client/crypto/session stores,
 * Node HTTP/fetch and installed React Native Alert producer callbacks.
 * Existing device aliases supply only native transport/drawing boundaries. */
import ReactTestRenderer, { act } from "react-test-renderer";
import { createServer, type ServerResponse } from "node:http";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Alert, Text, TouchableOpacity } from "react-native";
import { HistoryScreen } from "../src/screens/HistoryScreen";
import { api, setBaseUrl } from "../src/api/client";
import { vault } from "../src/vault";
import { encryptEntry } from "../src/crypto/journalCrypto";
import { setSecureStoreBackend } from "../src/secureStore";
import { resetEntryVersionMirrors } from "../src/entryVersions";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import { installedNativeAlert } from "./helpers/nativeAlert";
import * as Keychain from "./helpers/keychainMock";
import storage from "./helpers/storageMock";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
type Root = ReturnType<typeof ReactTestRenderer.create>;
const OWNER = "b".repeat(32), KEY = Buffer.alloc(32, 6), DAY = "2026-10-05";
const OLD_BEARER = "owned-history-original-bearer", NEW_BEARER = "owned-history-replacement-bearer";
const ENTRY = "history_route_owned_entry";
const setup = (message: string) => new Error(`SetupError: history route fixture: ${message}`);
const writing = (text: string, version = 1) => ({ id: `server-${ENTRY}`, client_entry_id: ENTRY,
  entry_date: DAY, received_at: `${DAY}T12:00:00Z`, content_version: version,
  blob: encryptEntry({ dataKey: KEY }, OWNER, ENTRY, text, DAY, null, undefined, version).blobB64 });
let screen: Root | undefined, systemWindow: Root | undefined;
let dialog: ReturnType<typeof installedNativeAlert>;
let server: ReturnType<typeof createServer> | undefined;
let rows: ReturnType<typeof writing>[] = [], requests: Array<{ method: string; bearer: string }> = [];
let faults: unknown[] = [], releases: Array<() => void> = [];
let origin = "", originalFetch: typeof fetch;
async function finite<T>(label: string, work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(`owned ${label} did not settle`)), 15000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}
async function flush() { await act(async () => { for (let i = 0; i < 80; i++) await Promise.resolve(); }); }
function screenText() { return screen?.root.findAllByType(Text).map(node => node.props.children).flat(Infinity).filter(value => typeof value === "string" || typeof value === "number").join(" ") ?? ""; }
async function waitFor(label: string, ready: () => boolean) {
  const deadline = Date.now() + 5000;
  while (!ready()) {
    if (Date.now() >= deadline) throw setup(`${label} did not become observable: ${screenText()}`);
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 5)); });
  }
}
async function mountHistory() {
  await act(async () => { screen = ReactTestRenderer.create(<HistoryScreen navigation={{ navigate: () => undefined }} />); });
  await flush();
}
async function retireHistory() {
  if (screen) { await act(async () => { screen!.unmount(); screen = undefined; }); }
}
async function pressScreen(label: string) {
  const target = screen?.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  if (!target || target.props.disabled) throw setup(`public History action unavailable: ${label}`);
  await act(async () => { void target.props.onPress(); }); await flush();
}
async function drawSystemWindow() {
  await act(async () => {
    if (systemWindow) systemWindow.update(<dialog.Window />);
    else systemWindow = ReactTestRenderer.create(<dialog.Window />);
  });
}
async function pressSystemWindow(label: string) {
  await drawSystemWindow();
  const target = systemWindow!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  if (!target) throw setup(`installed Native system-window action unavailable: ${label}`);
  await act(async () => { target.props.onPress(); }); await flush(); await drawSystemWindow();
}
async function installAccount(bearer: string) {
  await finite("credential publication", api.setSession(bearer, OWNER, "owned-history"));
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(KEY) }, OWNER);
}
async function replaceAccount() {
  await retireHistory();
  vault.lock(); await finite("original session retirement", api.clearSession());
  await installAccount(NEW_BEARER);
}
function send(response: ServerResponse, value: unknown) {
  response.writeHead(200, { "content-type": "application/json", "X-Entries-Revision": "1" }); response.end(JSON.stringify(value));
}
beforeEach(async () => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); Keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(resetEntryVersionMirrors);
  vault.lock(); originalFetch = globalThis.fetch; requests = []; faults = []; releases = [];
  rows = [writing("Original live journal writing")];
  dialog = installedNativeAlert("ios"); vi.spyOn(Alert, "alert").mockImplementation(dialog.alert);
  server = createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "", origin), bearer = request.headers.authorization ?? "";
      if (bearer !== `Bearer ${OLD_BEARER}` && bearer !== `Bearer ${NEW_BEARER}`) throw setup("actual native bearer differs");
      if (request.method === "GET" && url.pathname === "/api/v1/entries") {
        if (url.searchParams.get("offset") !== "0" || url.searchParams.get("limit") !== "100" || url.searchParams.get("page_bytes") !== "2097152") throw setup("public initial-page bounds differ");
        requests.push({ method: "GET", bearer }); send(response, rows); return;
      }
      if (request.method === "DELETE" && url.pathname === `/api/v1/entries/${ENTRY}`) {
        requests.push({ method: "DELETE", bearer }); rows = []; send(response, {}); return;
      }
      throw setup(`unexpected actual native route ${request.method} ${url.pathname}`);
    } catch (error) { faults.push(error); response.writeHead(500, { "content-type": "application/json" }); response.end(JSON.stringify({ detail: "Owned fixture fault" })); }
  });
  await finite("HTTP listen", new Promise<void>((resolve, reject) => { server!.once("error", reject); server!.listen(0, "127.0.0.1", () => { server!.removeListener("error", reject); resolve(); }); }));
  const address = server.address(); if (!address || typeof address === "string") throw setup("owned HTTP address missing");
  origin = `http://127.0.0.1:${address.port}`;
  if (await setBaseUrl(origin) !== null) throw setup("owned loopback origin was refused");
  await installAccount(OLD_BEARER);
});
afterEach(async () => {
  for (const release of releases) release(); await flush(); await retireHistory();
  if (systemWindow) { await act(async () => { systemWindow!.unmount(); systemWindow = undefined; }); }
  vault.lock(); await finite("session cleanup", api.clearSession());
  server?.closeAllConnections();
  if (server?.listening) await finite("HTTP close", new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve())));
  server = undefined; vi.restoreAllMocks(); storage.__reset(); Keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  if (faults.length) throw setup(`native HTTP fixture fault: ${String(faults[0])}`);
  if (globalThis.fetch !== originalFetch) throw setup("native fetch identity changed");
});

describe("History route admission retirement", () => {
  it.each(["live route", "retired route"] as const)("keeps installed Native final delete confirmation bound to its %s", async mode => {
    await mountHistory(); await waitFor("original public journal row", () => screenText().includes("Original live journal writing"));
    await pressScreen("Entry from Monday, October 5, 2026"); await pressScreen("Delete this entry"); await pressSystemWindow("Delete");
    if (mode === "retired route") {
      await replaceAccount(); rows = [writing("Replacement session journal writing", 2)];
    }
    await pressSystemWindow("Delete permanently");
    if (mode === "live route") await waitFor("healthy owned deletion completion", () => rows.length === 0);
    // A fresh public read is a native network completion barrier and proves
    // replacement credentials work even when the old dialog is refused.
    await finite("live account public read", api.listEntriesPage({ limit: 100, offset: 0, pageBytes: 2097152 }));
    const deletes = requests.filter(request => request.method === "DELETE");
    expect(deletes, "a retired system dialog must not borrow the replacement bearer").toEqual(mode === "live route" ? [{ method: "DELETE", bearer: `Bearer ${OLD_BEARER}` }] : []);
    expect(rows.map(row => row.client_entry_id)).toEqual(mode === "live route" ? [] : [ENTRY]);
    if (mode === "retired route") {
      await mountHistory(); await waitFor("replacement public journal row", () => screenText().includes("Replacement session journal writing"));
      await pressScreen("Entry from Monday, October 5, 2026"); await pressScreen("Delete this entry"); await pressSystemWindow("Delete"); await pressSystemWindow("Delete permanently");
      await waitFor("healthy replacement deletion completion", () => rows.length === 0);
      await finite("healthy replacement completion", api.listEntriesPage({ limit: 100, offset: 0, pageBytes: 2097152 }));
      expect(requests.filter(request => request.method === "DELETE")).toEqual([{ method: "DELETE", bearer: `Bearer ${NEW_BEARER}` }]); expect(rows).toEqual([]);
    }
  });

  it.each(["live route", "retired route"] as const)("keeps a physically held initial owner read bound to its %s", async mode => {
    const get = storage.getItem; let armed = true, heldCiphertext: string | null = null, release!: () => void, entered!: () => void, settled!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; }), started = new Promise<void>(resolve => { entered = resolve; }), releasedBackendSettled = new Promise<void>(resolve => { settled = resolve; }); releases.push(release);
    vi.spyOn(storage, "getItem").mockImplementation(async key => {
      const value = await get(key);
      if (armed && key === "@mindpattern/user_id") {
        armed = false; heldCiphertext = value;
        if (!value || JSON.parse(value).v !== 1 || typeof JSON.parse(value).c !== "string") throw setup("physical owner ciphertext was not captured");
        entered(); await gate; settled();
      }
      return value;
    });
    await mountHistory(); await finite("physical encrypted owner-read entry", started);
    expect(requests).toEqual([]); expect(heldCiphertext).not.toContain(OWNER);
    if (mode === "retired route") { await replaceAccount(); rows = [writing("Replacement session journal writing", 2)]; }
    release(); await finite("released original encrypted backend read", releasedBackendSettled);
    // The unchanged v1 facade now has only its cached device-key await and
    // synchronous decryption before this original owner receipt settles.
    // Drain that continuation before admitting the replacement healthy read.
    await flush(); await new Promise<void>(resolve => setImmediate(resolve)); await flush();
    if (mode === "live route") {
      await waitFor("held live public journal row", () => screenText().includes("Original live journal writing"));
      expect(requests).toEqual([{ method: "GET", bearer: `Bearer ${OLD_BEARER}` }]);
    } else {
      await mountHistory(); await waitFor("fresh replacement public journal row", () => screenText().includes("Replacement session journal writing"));
      expect(requests, "an unmounted initial read must leave the replacement account's native provider lane unused").toEqual([{ method: "GET", bearer: `Bearer ${NEW_BEARER}` }]);
    }
  });
});
