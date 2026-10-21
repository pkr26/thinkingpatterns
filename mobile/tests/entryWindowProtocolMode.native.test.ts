/** Public bounded-window paging through the real client, encrypted session
 * store and Node HTTP/fetch/Response. Native device stores retain the suite's
 * existing aliases; this fixture makes no physical-device or backend claim. */
import { createServer, type ServerResponse } from "node:http";
import { expect, it, vi } from "vitest";
import * as Keychain from "./helpers/keychainMock";
import { api, setBaseUrl } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import storage from "./helpers/storageMock";

const OWNER = "a".repeat(32), BEARER = "owned-window-bearer";
const SINCE = "2026-10-01", UNTIL = "2026-11-01";
const entry = (id: string) => ({ id, client_entry_id: id, blob: "owned-window-ciphertext", entry_date: "2026-10-05", received_at: "2026-10-05T12:00:00Z" });
const setup = (message: string) => new Error(`SetupError: ${message}`);
async function finite<T>(label: string, work: Promise<T>): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([work, new Promise<never>((_resolve, reject) => { timer = setTimeout(() => reject(setup(`owned ${label} did not settle`)), 15000); })]); }
  finally { if (timer !== undefined) clearTimeout(timer); }
}

it.each(["stable snapshot", "stable headerless", "legacy-to-snapshot replacement"] as const)("keeps a native bounded entry window coherent through %s", async scenario => {
  vi.useRealTimers(); storage.__reset(); Keychain.__reset(); setSecureStoreBackend(null);
  const nativeFetch = globalThis.fetch, requests: Array<{ offset: string | null; revision: string | null }> = [], faults: unknown[] = [];
  const first = entry("entry_window_first"), second = entry("entry_window_second"), fresh = entry("entry_window_fresh");
  let origin = "";
  function send(response: ServerResponse, rows: ReturnType<typeof entry>[], headers: Record<string, string> = {}) {
    response.writeHead(200, { "content-type": "application/json", ...headers }); response.end(JSON.stringify(rows));
  }
  const server = createServer((request, response) => {
    try {
      const url = new URL(request.url ?? "", origin), params = url.searchParams;
      if (request.method !== "GET" || url.pathname !== "/api/v1/entries" || request.headers.authorization !== `Bearer ${BEARER}`) throw setup("native route or live bearer differs");
      if (params.get("since") !== SINCE || params.get("until") !== UNTIL || params.get("limit") !== "500" || params.get("page_bytes") !== "2097152") throw setup("public date-window bounds were not forwarded");
      requests.push({ offset: params.get("offset"), revision: params.get("expected_revision") });
      if (requests.length > 3) throw setup("unexpected extra native window request");
      if (scenario === "legacy-to-snapshot replacement") {
        if (requests.length === 1) send(response, [first], { "X-Next-Offset": "1" });
        else if (requests.length === 2) send(response, [second], { "X-Entries-Revision": "7" });
        else send(response, [fresh], { "X-Entries-Revision": "8" });
      } else {
        const headers: Record<string, string> = scenario === "stable snapshot" ? { "X-Entries-Revision": "7" } : {};
        if (requests.length === 1) send(response, [first], { ...headers, "X-Next-Offset": "1" });
        else send(response, [first, second], headers);
      }
    } catch (error) { faults.push(error); response.writeHead(500, { "content-type": "application/json" }); response.end(JSON.stringify({ detail: "Owned fixture fault" })); }
  });
  try {
    await finite("HTTP listen", new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(0, "127.0.0.1", () => { server.removeListener("error", reject); resolve(); }); }));
    const address = server.address(); if (!address || typeof address === "string") throw setup("owned HTTP address absent");
    origin = `http://127.0.0.1:${address.port}`;
    if (await setBaseUrl(origin) !== null) throw setup("public loopback server selection was refused");
    await api.setSession(BEARER, OWNER, "owned-window-clinician");
    const rows = await finite("window completion", api.listEntriesWindow(SINCE, UNTIL, 2));
    if (faults.length) throw setup(`native fixture fault: ${String(faults[0])}`);
    if (globalThis.fetch !== nativeFetch) throw setup("native fetch identity changed");
    expect(rows).toEqual(scenario === "legacy-to-snapshot replacement" ? [fresh] : [first, second]);
    expect(requests).toEqual(scenario === "legacy-to-snapshot replacement"
      ? [{ offset: "0", revision: null }, { offset: "1", revision: null }, { offset: "0", revision: null }]
      : [{ offset: "0", revision: null }, { offset: "1", revision: scenario === "stable snapshot" ? "7" : null }]);
  } finally {
    try { await finite("session retirement", api.clearSession()); }
    finally {
      server.closeAllConnections();
      if (server.listening) await finite("HTTP close", new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
      storage.__reset(); Keychain.__reset(); setSecureStoreBackend(null);
    }
    if (faults.length) throw setup(`native fixture fault: ${String(faults[0])}`);
    if (globalThis.fetch !== nativeFetch) throw setup("native fetch identity changed during retirement");
  }
});
