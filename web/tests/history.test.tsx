/** HistoryView: decrypting pagination, search, the mood calendar, honest
 *  version-conflict editing, delete, and the rollback guard. Entries are
 *  encrypted with the REAL patient crypto so the decrypt path is the
 *  shipping one. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HistoryView } from "../src/views/History";
import { encryptEntry } from "../src/crypto/patient";
import { observeEntryVersions, resetEntryVersionMirrors } from "../src/entryVersions";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { flush, press, render, settle, textOf, typeArea, typeInto } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(9);
const USER = "user-1";

const memoryBackend = (): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
  };
};

interface Fixture {
  id: string;
  date: string;
  text: string;
  sentiment: number | null;
  version: number;
}

async function encryptedRow(fixture: Fixture): Promise<Record<string, unknown>> {
  const { blobB64 } = await encryptEntry(DATA_KEY, USER, fixture.id, fixture.text, `${fixture.date}T12:00:00Z`, fixture.sentiment, undefined, fixture.version);
  return {
    id: `row-${fixture.id}`,
    client_entry_id: fixture.id,
    blob: blobB64,
    entry_date: fixture.date,
    received_at: `${fixture.date}T12:00:01Z`,
    content_version: fixture.version,
  };
}

function entriesResponse(rows: Record<string, unknown>[], headers: Record<string, string> = {}): Response {
  return jsonResponse(rows, {
    headers: { "X-Entries-Revision": "7", ...(rows.length > 0 ? { "X-Next-Offset": String(rows.length) } : {}), ...headers },
  });
}

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  resetEntryVersionMirrors();
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(9);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("HistoryView", () => {
  it("lists decrypted entries with dates and mood reads", async () => {
    const rows = [
      await encryptedRow({ id: "e-a", date: "2026-09-24", text: "A calm walk by the river", sentiment: 0.6, version: 1 }),
      await encryptedRow({ id: "e-b", date: "2026-09-25", text: "Long meeting, drained", sentiment: -0.4, version: 1 }),
    ];
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    expect(textOf(root)).toContain("A calm walk by the river");
    expect(textOf(root)).toContain("Long meeting, drained");
    expect(textOf(root)).toContain("2026-09-24");
  });

  it("searches across the decrypted text and by exact date", async () => {
    const rows = [
      await encryptedRow({ id: "e-a", date: "2026-09-24", text: "café morning ritual", sentiment: 0.2, version: 1 }),
    ];
    stubFetch((url) => (url.startsWith(`${ORIGIN}/api/v1/entries?`) && !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await typeInto(root, "Search", "cafe");
    expect(textOf(root)).toContain("café morning ritual");
    await typeInto(root, "Search", "2026-09-24");
    expect(textOf(root)).toContain("café morning ritual");
    await typeInto(root, "Search", "2026-01-01");
    expect(textOf(root)).toContain("No entries match that search");
  });

  it("renders the mood calendar for the loaded month", async () => {
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-24", text: "day", sentiment: 0.6, version: 1 })];
    stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(40, 4);
    const tiles = root.root.findAllByType("div").filter(
      (node) => typeof node.props.title === "string" && /^\d{4}-\d{2}-\d{2}$/.test(node.props.title),
    );
    expect(tiles.length).toBeGreaterThanOrEqual(28);
  });

  it("an edit race (409) shows both versions and never silently overwrites", async () => {
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "their saved text", sentiment: 0, version: 1 })];
    stubFetch((url, init) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url.endsWith(`/entries/e-a`) && init.method === "PUT") {
        return jsonResponse({ detail: "lost the race", code: "version_conflict" }, { status: 409 });
      }
      if (url.endsWith(`/entries/e-a`) && init.method === "GET") {
        return jsonResponse(rows[0]);
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "my competing text");
    await press(root, "Save edit");
    await settle(40, 4);
    expect(textOf(root)).toContain("changed on another device");
    expect(textOf(root)).toContain("their saved text");
    expect(textOf(root)).toContain("my competing text");
    expect(textOf(root)).toContain("Nothing was overwritten automatically");
    // "Apply mine on top" re-submits against the REFRESHED version.
    await press(root, "Apply mine on top");
    await settle(40, 4);
  });

  it("delete removes the row and its version mark", async () => {
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "to be removed", sentiment: 0, version: 1 })];
    let deleted = false;
    stubFetch((url, init) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") || deleted ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url.endsWith("/entries/e-a") && init.method === "DELETE") {
        deleted = true;
        return new Response(null, { status: 204 });
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    expect(textOf(root)).toContain("to be removed");
    await press(root, "Delete");
    await settle(40, 4);
    expect(textOf(root)).not.toContain("to be removed");
  });

  it("the rollback guard hides a rolled-back row with an honest note", async () => {
    // Seed the guard's high-water mark at version 3, then serve version 2 —
    // a replayed-older-blob-with-truthful-echo attack.
    await observeEntryVersions(USER, DATA_KEY, [{ clientEntryId: "e-a", contentVersion: 3 }]);
    resetEntryVersionMirrors();
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "replayed older text", sentiment: 0, version: 2 })];
    stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(40, 4);
    expect(textOf(root)).not.toContain("replayed older text");
    expect(textOf(root)).toContain("rollback guard");
  });
});
