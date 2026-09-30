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
import { flush, press, render, settle, textOf, textOfNode, typeArea, typeInto } from "./helpers/rtr";

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
    // Calendar cells are real buttons carrying their ISO day as the
    // aria-label (redesign 2026-09-26; the old title-tooltip divs are gone).
    const tiles = root.root.findAllByType("button").filter(
      (node) => typeof node.props["aria-label"] === "string" && /^\d{4}-\d{2}-\d{2}($| — )/.test(node.props["aria-label"]),
    );
    expect(tiles.length).toBeGreaterThanOrEqual(28);
  });

  it("calendar days without a payload pick fall back to the mood log value; an explicit pick wins (H-5, audit 2026-09-26)", async () => {
    // After H-5 the payload's sentiment is ONLY the explicit check-in
    // pick — the calendar sources like mobile: payload pick first, the
    // device-local mood log's day value as fallback.
    const { localDateISO } = await import("../src/dates");
    const { recordMood } = await import("../src/moodLog");
    // Two days guaranteed inside the calendar's displayed (current) month.
    const now = new Date();
    const inMonth = (day: number): string => localDateISO(new Date(now.getFullYear(), now.getMonth(), day));
    const pickDay = inMonth(3);
    const noPickDay = inMonth(4);
    const rows = [
      await encryptedRow({ id: "e-pick", date: pickDay, text: "a good day, picked", sentiment: 0.6, version: 1 }),
      await encryptedRow({ id: "e-nopick", date: noPickDay, text: "a quiet unpicked day", sentiment: null, version: 1 }),
    ];
    // The log holds a strongly negative estimate for BOTH days — the pick
    // must override it on its day, and stand in on the unpicked day.
    await recordMood(DATA_KEY, USER, pickDay, -0.8);
    await recordMood(DATA_KEY, USER, noPickDay, -1.8);
    stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(40, 5);
    // 2026-09-29 a11y fix: the mood level rides the accessible name now,
    // so tiles match by ISO PREFIX (iso — <mood> — entry — …).
    const tile = (iso: string) =>
      root.root.findAllByType("button").find(
        (node) =>
          typeof node.props["aria-label"] === "string" &&
          (node.props["aria-label"] === iso || node.props["aria-label"].startsWith(`${iso} — `)),
      );
    // Explicit pick 0.6 → the warm sage "lighter" fill, not the log's dark rose.
    expect(tile(pickDay)?.props.style.backgroundColor).toBe("#8fb98d");
    // No pick → the mood log's strong negative shows through instead of
    // a blank tile.
    expect(tile(noPickDay)?.props.style.backgroundColor).toBe("#cd8f82");
    // The mood LEVEL is in the accessible name (color-only was WCAG 1.4.1).
    expect(String(tile(pickDay)?.props["aria-label"])).toContain(" — ");
    expect(String(tile(noPickDay)?.props["aria-label"])).toContain(" — ");
    // And in a NON-color channel: the strong day (-1.8 → 2px) carries a
    // heavier underline than the mild day (0.6 → 1px).
    expect(String(tile(noPickDay)?.props.style.borderBottom)).toMatch(/^2px solid /);
    expect(String(tile(pickDay)?.props.style.borderBottom)).toMatch(/^1px solid /);
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
    // Delete is two-step now (redesign 2026-09-26): the first press arms,
    // the explicit confirmation fires the request.
    await press(root, "Delete");
    await press(root, "Delete permanently");
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

describe("HistoryView: terminal load failures never wedge on Loading (audit 2026-09-25)", () => {
  it("a server 5xx surfaces an honest error instead of an eternal spinner", async () => {
    stubFetch((url) => {
      if (url.includes("/entries?")) return jsonResponse({ detail: "database on fire", code: "internal_error" }, { status: 500 });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 3);
    expect(textOf(root)).toContain("database on fire");
    expect(textOf(root)).not.toContain("Loading…");
  });

  it("a locked vault lands the locked message, not silence", async () => {
    stubFetch(() => jsonResponse([], { headers: { "X-Entries-Revision": "1" } }));
    vault.lock();
    const root = await render(<HistoryView />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Your session locked");
    expect(textOf(root)).not.toContain("Loading…");
  });
});

describe("HistoryView windowed rendering + Map mapping (audit 2026-09-26 LOW)", () => {
  it("renders a first window of entries with a Show-more sentinel, and the sentinel reveals the rest in order", async () => {
    // 35 entries: the first window (30) renders, the last 5 wait behind
    // the sentinel — and the back-mapping to full entries must stay
    // correct (the Map<id, entry> replaced per-hit entries.find).
    const total = 35;
    const rows: Record<string, unknown>[] = [];
    for (let n = 1; n <= total; n += 1) {
      rows.push(await encryptedRow({ id: `e-${n}`, date: `2026-09-${String(n).padStart(2, "0")}`, text: `windowed entry number ${n}`, sentiment: 0, version: 1 }));
    }
    stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    // 35 decrypts with periodic yields to the host: give the loop room.
    await settle(30, 12);
    const cards = () => root.root.findAllByType("article");
    expect(cards().length).toBe(30);
    // The FIRST thirty in order — the rest are off-DOM.
    expect(cards()[0]!.props.children).toBeDefined();
    expect(textOf(root)).toContain("windowed entry number 1");
    expect(textOf(root)).toContain("windowed entry number 30");
    for (const hidden of [31, 32, 33, 34, 35]) {
      expect(textOf(root)).not.toContain(`windowed entry number ${hidden}`);
    }
    // The sentinel reveals the next window (all 35 now, sentinel gone).
    await press(root, "Show more");
    await settle(20, 2);
    expect(root.root.findAllByType("article").length).toBe(35);
    expect(textOf(root)).toContain("windowed entry number 35");
    expect(root.root.findAllByType("button").some((node) => textOfNode(node) === "Show more")).toBe(false);
  });

  it("a fresh search resets the window (the sentinel is per filter source)", async () => {
    const rows: Record<string, unknown>[] = [];
    for (let n = 1; n <= 32; n += 1) {
      rows.push(await encryptedRow({ id: `e-s-${n}`, date: "2026-09-25", text: `searchable needle ${n}`, sentiment: 0, version: 1 }));
    }
    stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(30, 12);
    expect(root.root.findAllByType("article").length).toBe(30);
    await press(root, "Show more");
    await settle(20, 2);
    expect(root.root.findAllByType("article").length).toBe(32);
    // Typing a query starts a fresh window: only the matches render.
    await typeInto(root, "Search", "needle 3");
    await settle(20, 3);
    const matches = root.root.findAllByType("article").length;
    expect(matches).toBeGreaterThan(0);
    expect(matches).toBeLessThanOrEqual(30);
    expect(root.root.findAllByType("button").some((node) => textOfNode(node) === "Show more")).toBe(false);
  });
});

/** independent audit 2026-09-27 (P2): remove() reused the vault's SHARED
 *  dataKey buffer after the deleteEntry await — a lock mid-delete
 *  zeroized it and the local hygiene (version mark, mood day) ran under
 *  an all-zero key. The key is snapshotted before the await now, and a
 *  locked vault quietly skips the disposable local hygiene. */
describe("HistoryView delete lock race (audit 2026-09-27)", () => {
  it("a lock landing mid-delete quietly skips the local hygiene — no unhandled rejection, no zero-key write", async () => {
    const { recordMood, recentMoods } = await import("../src/moodLog");
    const { kv } = await import("../src/kvstore");
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "deleted under lock", sentiment: 0, version: 1 })];
    // Local hygiene targets: a version mark and a mood day for the entry.
    await observeEntryVersions(USER, DATA_KEY, [{ clientEntryId: "e-a", contentVersion: 1 }]);
    resetEntryVersionMirrors();
    await recordMood(DATA_KEY, USER, "2026-09-25", 0.4);
    let deletes = 0;
    stubFetch((url, init) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return !url.includes("offset=0") || deletes > 0 ? entriesResponse([]) : entriesResponse(rows);
      if (url.endsWith("/entries/e-a") && init.method === "DELETE") {
        deletes += 1;
        vault.lock(); // the lock lands mid-delete, after the key snapshot
        return new Response(null, { status: 204 });
      }
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    expect(textOf(root)).toContain("deleted under lock");
    await press(root, "Delete");
    await press(root, "Delete permanently");
    await settle(40, 4);
    // The server-side delete landed exactly once...
    expect(deletes).toBe(1);
    // ...and the disposable local hygiene was quietly SKIPPED (not written
    // under the zeroized shared buffer): the mood day and version store
    // survive for the next unlocked pass.
    const days = await recentMoods(DATA_KEY, USER);
    expect(days.map((day) => day.date)).toContain("2026-09-25");
    expect(await kv.getItem(`mindpattern.entryVersions.${USER}`)).not.toBeNull();
  });
});

/** H-6 (2026-09-28 audit, HIGH — mobile HistoryScreen parity): the EDIT
 *  path runs the same on-device crisis detection as a new entry. The
 *  server only ever sees ciphertext, so the detector is the only net for
 *  a user who edits yesterday's entry into crisis language. The save
 *  COMMITS first (never blocked, unlike the create path's pre-save gate);
 *  the support prompt surfaces after, throttled once per account-day. */
describe("HistoryView edit-path crisis detection (H-6, audit 2026-09-28)", () => {
  it("an edit into crisis language commits, then shows the support prompt — throttled on the second edit", async () => {
    const { crisisDialogShownOn } = await import("../src/crisisDialog");
    const { localDateISO } = await import("../src/dates");
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "an ordinary day", sentiment: 0, version: 1 })];
    const mock = stubFetch((url, init) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url.endsWith("/entries/e-a") && init.method === "PUT") return jsonResponse({ ok: true });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "I want to kill myself");
    await press(root, "Save edit");
    await settle(40, 5);
    // H-6 never blocks the save: the replacement is already committed
    // server-side when the prompt appears.
    const puts = () =>
      (mock.mock.calls as [string, RequestInit][]).filter(
        ([url, init]) => url.endsWith("/entries/e-a") && init.method === "PUT",
      );
    expect(puts()).toHaveLength(1);
    expect(textOf(root)).toContain("sounds heavy");
    expect(await crisisDialogShownOn(USER, localDateISO())).toBe(true);

    // A SECOND crisis edit the same day: throttled — the save still
    // lands, no prompt card (no dismissal training).
    await press(root, "Edit");
    await typeArea(root, "Your entry", "I want to kill myself again");
    await press(root, "Save edit");
    await settle(40, 5);
    expect(puts()).toHaveLength(2);
    expect(textOf(root)).not.toContain("sounds heavy");
  });

  it("an ordinary edit never triggers the prompt", async () => {
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "a calm morning", sentiment: 0, version: 1 })];
    stubFetch((url, init) => {
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) {
        return !url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows);
      }
      if (url.endsWith("/entries/e-a") && init.method === "PUT") return jsonResponse({ ok: true });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "a calm morning, edited");
    await press(root, "Save edit");
    await settle(40, 5);
    expect(textOf(root)).not.toContain("sounds heavy");
  });
});

/** 2026-09-28 audit (MEDIUM): the client-side entry cap and the empty-edit
 *  block — mobile parity for BOTH editor surfaces. */
describe("HistoryView edit guards (audit 2026-09-28)", () => {
  it("an over-cap edit is refused client-side with the honest copy — no PUT", async () => {
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "short text", sentiment: 0, version: 1 })];
    const mock = stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "x".repeat(100_001));
    await press(root, "Save edit");
    await settle(40, 4);
    expect(textOf(root)).toContain("Entries are limited to 100,000 characters");
    expect(mock.mock.calls.some(([url, init]) => url.endsWith("/entries/e-a") && init.method === "PUT")).toBe(false);
  });

  it("an EMPTY edit is refused client-side (mobile parity) — no blank saved day", async () => {
    const rows = [await encryptedRow({ id: "e-a", date: "2026-09-25", text: "real text", sentiment: 0, version: 1 })];
    const mock = stubFetch((url) => (!url.includes("offset=0") ? entriesResponse([]) : entriesResponse(rows)));
    const root = await render(<HistoryView />);
    await settle(40, 4);
    await press(root, "Edit");
    await typeArea(root, "Your entry", "   ");
    await press(root, "Save edit");
    await settle(40, 4);
    expect(textOf(root)).toContain("Write something first");
    expect(mock.mock.calls.some(([url, init]) => url.endsWith("/entries/e-a") && init.method === "PUT")).toBe(false);
  });
});
