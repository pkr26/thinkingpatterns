/**
 * HistoryScreen: the decrypt-on-device journal — list with mood badges,
 * detail view, edit-as-replace (delete + create under a fresh id), the calm
 * double-confirm delete, the honest offline state, pull-to-refresh,
 * pagination, and hostile-payload hygiene.
 *
 * The crypto and the mood log are REAL (node engine alias + storage mock):
 * rows are encrypted with the same envelope the Entry screen writes, so the
 * decrypt path is exercised end to end.
 */
import { beforeEach, afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, BackHandler } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError, ENTRY_PAGE_BYTES } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock(), ENTRY_PAGE_BYTES };
});

const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity }) };
});

const { api, ApiError } = await import("../../src/api/client");
const { HistoryScreen, formatEntryDate } = await import("../../src/screens/HistoryScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { decryptEntry } = await import("../../src/crypto/MindPatternCrypto");
const { recordMood, recentMoods } = await import("../../src/moodLog");
const {
  render,
  flush,
  textOf,
  allText,
  pressLabel,
  lastAlert,
  pressAlertButton,
  inputByPlaceholder,
  act,
} = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const dataKey = Buffer.alloc(32, 5);
const nav = { navigate: vi.fn() };

type Sentiment = number | null | unknown;

/** Encrypt an entry row exactly the way a synced save would have made it.
 *  The optional `structured` bag emits a v2 payload (malformed values are
 *  deliberately passable — the decrypt-side sanitizers are under test). */
function entryRow(
  clientEntryId: string,
  text: string,
  entryDate: string,
  sentiment: Sentiment = null,
  receivedAt: string | null = `${entryDate}T10:00:00.000Z`,
  structured?: { energy?: unknown; sleep?: unknown; tags?: unknown },
) {
  const base = { v: 1 as number, text, sentiment, created_at: entryDate };
  const payload = JSON.stringify(structured ? { ...base, v: 2, ...structured } : base);
  return {
    id: `srv-${clientEntryId}`,
    client_entry_id: clientEntryId,
    blob: encrypt(dataKey, Buffer.from(payload), buildAad("entry", "user-1", clientEntryId)).toString("base64"),
    entry_date: entryDate,
    received_at: receivedAt,
  };
}

/** A navigation prop whose addListener captures focus callbacks. */
function navWithFocus() {
  const listeners: Array<() => void> = [];
  const focusNav = {
    navigate: vi.fn(),
    addListener: vi.fn((_event: string, cb: () => void) => {
      listeners.push(cb);
      return vi.fn();
    }),
  };
  return { focusNav, fireFocus: () => listeners.forEach((cb) => cb()) };
}

/** Rendered entry rows (list mode) by their accessibility label prefix. */
function entryRows(root: Awaited<ReturnType<typeof render>>) {
  return root.root.findAll(
    (n) => typeof n.props.accessibilityLabel === "string" && n.props.accessibilityLabel.startsWith("Entry from "),
  );
}

function moodBadges(root: Awaited<ReturnType<typeof render>>): string[] {
  return root.root
    .findAll((n) => typeof n.props.accessibilityLabel === "string" && n.props.accessibilityLabel.startsWith("Mood: "))
    .map((n) => n.props.accessibilityLabel as string);
}

/** Drive list → detail → edit for the entry whose snippet/text matches. */
async function openEditor(root: Awaited<ReturnType<typeof render>>, text: string) {
  await pressLabel(root, text);
  await pressLabel(root, "Edit this entry");
  const { TextInput } = await import("react-native");
  const editor = root.root.findAllByType(TextInput).find((n) => n.props.accessibilityLabel === "Edit entry");
  if (!editor) throw new Error("editor not open");
  return editor;
}

beforeEach(() => {
  resetApi(api as never);
  Alert.alert.mockClear();
  touchActivity.mockClear();
  nav.navigate.mockClear();
  storage.__reset();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-1");
});

describe("HistoryScreen list", () => {
  it("renders past entries decrypted on-device, newest day first", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-01-aaa", "first day\nwith a newline", "2026-09-01"),
      entryRow("e-2026-09-03-bbb", "third day", "2026-09-03"),
      entryRow("e-2026-09-02-ccc", "second day", "2026-09-02"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("third day");
    expect(text).toContain("second day");
    expect(text).toContain("first day with a newline"); // snippets flatten newlines
    expect(entryRows(root)).toHaveLength(3);
    const flat = allText(root);
    const idx = (s: string) => flat.findIndex((line) => line.includes(s));
    expect(idx("2026-09-03")).toBeLessThan(idx("2026-09-02"));
    expect(idx("2026-09-02")).toBeLessThan(idx("2026-09-01"));
    // Rows are buttons whose a11y label carries the friendly date.
    expect(entryRows(root).map((n) => n.props.accessibilityLabel)).toContain("Entry from Thursday, September 3, 2026");
  });

  it("shows a spinner while the first load is in flight", async () => {
    let resolveList!: (v: unknown) => void;
    vi.mocked(api.listEntries).mockImplementation(() => new Promise((resolve) => (resolveList = resolve)));
    const { ActivityIndicator } = await import("react-native");
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(root.root.findAllByType(ActivityIndicator).length).toBeGreaterThan(0);
    await act(async () => resolveList([]));
    await flush();
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(0);
    expect(textOf(root)).toContain("No entries yet.");
    await act(async () => root.unmount());
  });

  it("an empty journal says so calmly", async () => {
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("No entries yet.");
    expect(textOf(root)).toContain("decrypted only on this device.");
  });

  it("offline is honest: history needs a connection, today's writing does not", async () => {
    vi.mocked(api.listEntries).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain(
      "Your journal history loads when you're online; today's writing always works offline.",
    );
    expect(textOf(root)).not.toContain("No entries yet."); // an honest state, not a fake empty one
    // Back online, a retry loads the journal.
    vi.mocked(api.listEntries).mockResolvedValue([entryRow("e-2026-09-03-bbb", "third day", "2026-09-03")] as never);
    await pressLabel(root, "Try again");
    await flush();
    expect(textOf(root)).toContain("third day");
  });

  it("a server failure shows calm copy with an alert role and a retry", async () => {
    vi.mocked(api.listEntries).mockRejectedValue(new ApiError(500, "boom"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("The server hit a problem — try again in a moment.");
    expect(root.root.findAll((n) => n.props.accessibilityRole === "alert")).toHaveLength(1);
    // The error card's retry recovers when the server does.
    vi.mocked(api.listEntries).mockResolvedValue([entryRow("e-2026-09-03-bbb", "third day", "2026-09-03")] as never);
    await pressLabel(root, "Try again");
    await flush();
    expect(textOf(root)).toContain("third day");
    expect(textOf(root)).not.toContain("try again in a moment");
  });

  it("long entries collapse to a one-line snippet with an ellipsis", async () => {
    const longText = `start ${"x".repeat(200)} end`;
    vi.mocked(api.listEntries).mockResolvedValue([entryRow("e-2026-09-03-bbb", longText, "2026-09-03")] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const flat = allText(root).join(" ");
    expect(flat).toContain(`${"start " + "x".repeat(134)}…`); // 140 chars + ellipsis
    expect(flat).not.toContain("end"); // the tail is behind the detail view
    // …and the detail view shows the whole thing.
    await pressLabel(root, "start");
    expect(textOf(root)).toContain(longText);
  });

  it("requires a stored account id", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("account id missing — sign in again");
  });

  it("pull-to-refresh reloads the list", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([entryRow("e-2026-09-03-bbb", "third day", "2026-09-03")] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(api.listEntries).toHaveBeenCalledTimes(1);
    const { ScrollView } = await import("react-native");
    const scroll = root.root.findByType(ScrollView);
    const rc = (scroll.props as { refreshControl: React.ReactElement }).refreshControl;
    await act(async () => {
      await (rc.props as { onRefresh: () => unknown }).onRefresh();
    });
    await flush();
    expect(api.listEntries).toHaveBeenCalledTimes(2);
  });

  it("history reveals in pages of 50 with a calm 'show older' button", async () => {
    const rows = [];
    for (let i = 1; i <= 120; i++) {
      const day = String(((i - 1) % 28) + 1).padStart(2, "0");
      const month = String(Math.floor((i - 1) / 28) + 1).padStart(2, "0");
      rows.push(entryRow(`e-2026-${month}-${day}-row${i}`, `entry number ${i}`, `2026-${month}-${day}`));
    }
    vi.mocked(api.listEntries).mockResolvedValue(rows as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(entryRows(root)).toHaveLength(50);
    await pressLabel(root, "Show older entries (70 more)");
    await flush();
    expect(entryRows(root)).toHaveLength(100);
    await pressLabel(root, "Show older entries (20 more)");
    await flush();
    expect(entryRows(root)).toHaveLength(120);
    expect(textOf(root)).not.toContain("Show older entries");
    expect(touchActivity).toHaveBeenCalled();
  });

  it("uses the server's byte-page continuation to load older history", async () => {
    const first = entryRow("e-2026-09-03-first", "first page", "2026-09-03");
    const second = entryRow("e-2026-09-02-second", "second page", "2026-09-02");
    vi.mocked(api.listEntriesPage)
      .mockResolvedValueOnce({ entries: [first], nextOffset: 1, revision: null } as never)
      .mockResolvedValueOnce({ entries: [second], nextOffset: null, revision: null } as never);

    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(api.listEntriesPage).toHaveBeenCalledWith({ limit: 100, offset: 0, pageBytes: 2 * 1024 * 1024 });
    expect(textOf(root)).toContain("Load older entries");

    await pressLabel(root, "Load older entries");
    await flush();
    expect(api.listEntriesPage).toHaveBeenLastCalledWith({ limit: 100, offset: 1, pageBytes: 2 * 1024 * 1024 });
    expect(textOf(root)).toContain("second page");
    expect(textOf(root)).not.toContain("Load older entries");
  });

  it("carries a modern snapshot revision exactly across an older-page request", async () => {
    const revision = "9223372036854775807";
    const first = entryRow("e-2026-09-03-snapshot", "newer snapshot", "2026-09-03");
    const second = entryRow("e-2026-09-02-snapshot", "older snapshot", "2026-09-02");
    vi.mocked(api.listEntriesPage)
      .mockResolvedValueOnce({ entries: [first], nextOffset: 1, revision } as never)
      .mockResolvedValueOnce({ entries: [second], nextOffset: null, revision } as never);

    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(1, {
      limit: 100,
      offset: 0,
      pageBytes: 2 * 1024 * 1024,
    });

    await pressLabel(root, "Load older entries");
    await flush();
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(2, {
      limit: 100,
      offset: 1,
      pageBytes: 2 * 1024 * 1024,
      expectedRevision: revision,
    });
    expect(textOf(root)).toContain("older snapshot");
  });

  it("restarts cleanly from page one when the snapshot changes while loading older history", async () => {
    const stale = entryRow("e-2026-09-03-stale", "stale snapshot", "2026-09-03");
    const fresh = entryRow("e-2026-09-04-fresh", "fresh snapshot", "2026-09-04");
    vi.mocked(api.listEntriesPage)
      .mockResolvedValueOnce({ entries: [stale], nextOffset: 1, revision: "5" } as never)
      .mockRejectedValueOnce(new ApiError(409, "entries changed while paging", "collection_changed"))
      .mockResolvedValueOnce({ entries: [fresh], nextOffset: null, revision: "6" } as never);

    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Load older entries");
    await flush();
    await flush();

    expect(api.listEntriesPage).toHaveBeenNthCalledWith(2, {
      limit: 100,
      offset: 1,
      pageBytes: 2 * 1024 * 1024,
      expectedRevision: "5",
    });
    // A fresh first page deliberately starts without expected_revision and
    // replaces, rather than appends to, the invalidated snapshot.
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(3, {
      limit: 100,
      offset: 0,
      pageBytes: 2 * 1024 * 1024,
    });
    expect(textOf(root)).toContain("fresh snapshot");
    expect(textOf(root)).not.toContain("stale snapshot");
    expect(textOf(root)).toContain("Reloading the latest history from the start.");
  });

  it("uses the full-page legacy fallback continuation to load older history", async () => {
    const fullLegacyPage = Array.from({ length: 100 }, (_, index) =>
      entryRow(
        `e-2026-09-${String((index % 28) + 1).padStart(2, "0")}-legacy-${index}`,
        `legacy page ${index}`,
        `2026-09-${String((index % 28) + 1).padStart(2, "0")}`,
      ),
    );
    const older = entryRow("e-2026-08-01-legacy-next", "legacy next page", "2026-08-01");
    // This is the typed result from listEntriesPage's safe compatibility
    // fallback: old servers omit X-Next-Offset on an exactly-full page.
    vi.mocked(api.listEntriesPage)
      .mockResolvedValueOnce({ entries: fullLegacyPage, nextOffset: 100, revision: null } as never)
      .mockResolvedValueOnce({ entries: [older], nextOffset: null, revision: null } as never);

    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Show older entries (50 more)");
    await flush();
    expect(textOf(root)).toContain("Load older entries");

    await pressLabel(root, "Load older entries");
    await flush();
    expect(api.listEntriesPage).toHaveBeenLastCalledWith({ limit: 100, offset: 100, pageBytes: 2 * 1024 * 1024 });
    expect(textOf(root)).toContain("legacy next page");
  });

  it("caps manual history downloads and clearly says when more remains on the server", async () => {
    const pages = Array.from({ length: 5 }, (_, index) => ({
      entries: [entryRow(`e-2026-09-0${index + 1}-cap`, `cap page ${index + 1}`, `2026-09-0${index + 1}`)],
      // A continuation after page five proves the screen's own cap, rather
      // than server completion, stopped any further plaintext accumulation.
      nextOffset: index + 1,
    }));
    vi.mocked(api.listEntriesPage).mockImplementation(async () => pages.shift() as never);

    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    let staleLoadOlder: (() => unknown) | undefined;
    for (let page = 0; page < 4; page++) {
      if (page === 3) {
        staleLoadOlder = root.root.find(
          (node) => node.props.accessibilityLabel === "Load older encrypted journal entries",
        ).props.onPress as () => unknown;
      }
      await pressLabel(root, "Load older entries");
      await flush();
    }

    expect(api.listEntriesPage).toHaveBeenCalledTimes(5);
    expect(textOf(root)).toContain("safe download limit (500 entries or 5 pages)");
    expect(textOf(root)).toContain("More encrypted history remains on the server.");
    expect(textOf(root)).not.toContain("Load older entries");
    // Even a stale native tap handler from the just-hidden control cannot
    // start a sixth request before React finishes committing the cap state.
    await act(async () => {
      staleLoadOlder?.();
    });
    await flush();
    expect(api.listEntriesPage).toHaveBeenCalledTimes(5);
  });

  it("a tampered blob is skipped and honestly counted (singular and plural)", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "readable", "2026-09-03"),
      { id: "x", client_entry_id: "e-2026-09-02-bad", blob: "AAAA", entry_date: "2026-09-02", received_at: "2026-09-02T10:00:00Z" },
      { id: "y", client_entry_id: "e-2026-09-01-bad", blob: "AAAA", entry_date: "2026-09-01", received_at: "2026-09-01T10:00:00Z" },
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("readable");
    expect(entryRows(root)).toHaveLength(1);
    expect(textOf(root)).toContain("2 entries couldn't be read on this device.");

    // Singular reads right too.
    vi.mocked(api.listEntries).mockResolvedValue([
      { id: "x", client_entry_id: "e-2026-09-02-bad", blob: "AAAA", entry_date: "2026-09-02", received_at: "2026-09-02T10:00:00Z" },
    ] as never);
    const second = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(textOf(second)).toContain("1 entry couldn't be read on this device.");
  });

  it("a failing mood-log read still renders the entries — just without fallback badges", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "still here", "2026-09-03"),
    ] as never);
    // Sabotage storage reads so the (real) mood log decrypt fails.
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      const root = await render(<HistoryScreen navigation={nav} />);
      await flush();
      expect(textOf(root)).toContain("still here");
      expect(moodBadges(root)).toHaveLength(0);
    } finally {
      storage.getItem = original;
    }
  });

  it("hostile row shapes degrade instead of crashing", async () => {
    const weird = {
      id: "w",
      client_entry_id: "e-2026-09-03-zzz",
      blob: encrypt(
        dataKey,
        Buffer.from(JSON.stringify({ v: 1, text: 42, sentiment: null, created_at: "x" })),
        buildAad("entry", "user-1", "e-2026-09-03-zzz"),
      ).toString("base64"),
      entry_date: 42, // not a string
      received_at: null,
    };
    vi.mocked(api.listEntries).mockResolvedValue([weird] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(entryRows(root)).toHaveLength(1); // an empty-date, empty-snippet row — never a throw
  });

  it("a crafted payload sentiment is clamped before it ever renders", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-aaa", "clamped high", "2026-09-03", 5),
      entryRow("e-2026-09-03-bbb", "not a number", "2026-09-03", "lots"),
      entryRow("e-2026-09-03-ccc", "not finite", "2026-09-03", undefined),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    // 5 clamps to 1 → "Light"; the string and the dropped field → no badge.
    expect(moodBadges(root)).toEqual(["Mood: Light"]);
  });
});

describe("HistoryScreen mood badges", () => {
  it("the entry's own check-in pick wins; the device-local log is the fallback", async () => {
    // One day only exists in the (real, encrypted) mood log.
    await recordMood(dataKey, "user-1", "2026-09-02", 0.5);
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-04-ddd", "explicit light", "2026-09-04", 1),
      entryRow("e-2026-09-03-bbb", "explicit heavy", "2026-09-03", -1),
      entryRow("e-2026-09-02-ccc", "log backed", "2026-09-02"), // null payload mood
      entryRow("e-2026-09-01-aaa", "no signal", "2026-09-01"), // null + no log
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(moodBadges(root).sort()).toEqual(["Mood: Good", "Mood: Heavy", "Mood: Light"]);
    // The detail view carries the same badge — and its absence stays absent.
    await pressLabel(root, "no signal");
    expect(moodBadges(root)).toHaveLength(0);
    await pressLabel(root, "Back to history");
    await pressLabel(root, "explicit heavy");
    expect(moodBadges(root)).toEqual(["Mood: Heavy"]);
  });
});

describe("HistoryScreen detail", () => {
  it("opens the full text with the friendly date and returns to the list", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "the whole entry, every word of it", "2026-09-03"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "the whole entry");
    expect(textOf(root)).toContain("Thursday, September 3, 2026");
    expect(textOf(root)).toContain("the whole entry, every word of it");
    expect(textOf(root)).toContain("Edit this entry");
    expect(textOf(root)).toContain("Delete this entry");
    await pressLabel(root, "Back to history");
    await flush();
    expect(entryRows(root)).toHaveLength(1);
    expect(textOf(root)).not.toContain("Delete this entry");
  });
});

describe("HistoryScreen delete", () => {
  const oneEntry = () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "to be removed", "2026-09-03"),
    ] as never);
  };

  it("is a calm double confirmation — and only then hits the server", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "to be removed");
    await pressLabel(root, "Delete this entry");
    expect(lastAlert()[0]).toBe("Delete this entry?");
    expect(lastAlert()[1]).toBe(
      "This removes the entry from your journal on every device. This can't be undone.",
    );
    await pressAlertButton("Delete");
    expect(lastAlert()[0]).toBe("Final confirmation");
    expect(lastAlert()[1]).toContain("permanent");
    expect(api.deleteEntry).not.toHaveBeenCalled();
    await pressAlertButton("Delete permanently");
    await flush();
    expect(api.deleteEntry).toHaveBeenCalledWith("e-2026-09-03-bbb");
    expect(textOf(root)).toContain("Entry deleted");
    expect(textOf(root)).toContain("No entries yet.");
    await act(async () => root.unmount()); // clears the status timer
  });

  it("either Cancel stops the delete cold", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "to be removed");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Cancel"); // first dialog
    expect(api.deleteEntry).not.toHaveBeenCalled();
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Cancel"); // second dialog
    expect(api.deleteEntry).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("to be removed");
  });

  it("an offline delete changes nothing and says so", async () => {
    oneEntry();
    vi.mocked(api.deleteEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "to be removed");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently");
    await flush();
    expect(lastAlert()[0]).toBe("Needs a connection");
    expect(lastAlert()[1]).toContain("can't run offline");
    expect(lastAlert()[1]).toContain("nothing was changed");
    // Still on the detail view, entry intact.
    expect(textOf(root)).toContain("to be removed");
    expect(textOf(root)).not.toContain("Entry deleted");
  });

  it("a 404 delete is already the goal state — the row goes quietly", async () => {
    oneEntry();
    vi.mocked(api.deleteEntry).mockRejectedValue(new ApiError(404, "not found"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "to be removed");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently");
    await flush();
    expect(textOf(root)).toContain("Entry deleted");
    expect(textOf(root)).toContain("No entries yet.");
  });

  it("other delete failures surface calm copy and keep the entry", async () => {
    oneEntry();
    vi.mocked(api.deleteEntry).mockRejectedValue(new ApiError(500, "boom"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "to be removed");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently");
    await flush();
    expect(lastAlert()[0]).toBe("Could not delete");
    expect(lastAlert()[1]).toBe("The server hit a problem — try again in a moment.");
    expect(textOf(root)).toContain("to be removed");
  });

  it("a double-tap on the final confirmation deletes once (the busy guard)", async () => {
    oneEntry();
    let resolveDelete!: (v: unknown) => void;
    vi.mocked(api.deleteEntry).mockImplementation(() => new Promise((resolve) => (resolveDelete = resolve)));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "to be removed");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently"); // in flight…
    await pressAlertButton("Delete permanently"); // …a leaked second tap: swallowed
    await act(async () => resolveDelete({}));
    await flush();
    expect(api.deleteEntry).toHaveBeenCalledTimes(1);
    await act(async () => root.unmount());
  });
});

describe("HistoryScreen edit (atomic replacement)", () => {
  const oneEntry = (sentiment: Sentiment = null) => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "original words", "2026-09-03", sentiment),
    ] as never);
  };

  it("atomically replaces the stable id — same date and chosen mood are preserved", async () => {
    oneEntry(-1);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    expect(editor.props.value).toBe("original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(api.deleteEntry).not.toHaveBeenCalled();
    expect(api.createEntry).not.toHaveBeenCalled();
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    const [updatedId, blob, date, version] = vi.mocked(api.updateEntry).mock.calls[0] as unknown as [string, string, string, number];
    expect(updatedId).toBe("e-2026-09-03-bbb");
    expect(date).toBe("2026-09-03");
    // M-2 (2026-09-20): the replacement declares and AAD-binds its content
    // version (1 for a version-less legacy row).
    expect(version).toBe(1);
    const payload = decryptEntry({ dataKey }, "user-1", updatedId, blob, version);
    expect(payload.text).toBe("revised words");
    expect(payload.sentiment).toBe(-1); // the day's explicit pick survived the edit
    // Detail shows the update; the device-local log kept the chosen value.
    expect(textOf(root)).toContain("revised words");
    expect(textOf(root)).toContain("Updated ✓");
    expect(textOf(root)).not.toContain("original words");
    const days = await recentMoods(dataKey, "user-1", 30);
    expect(days.find((d) => d.date === "2026-09-03")?.value).toBe(-1);
    await act(async () => root.unmount());
  });

  it("an entry without a chosen mood re-estimates the day from the new text", async () => {
    oneEntry(null);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("good great happy");
    });
    await pressLabel(root, "Save changes");
    await flush();
    const days = await recentMoods(dataKey, "user-1", 30);
    expect(days.find((d) => d.date === "2026-09-03")?.value).toBe(1);
  });

  it("an edit preserves the v2 structured channels — energy, sleep and tags ride the replacement (2026-09-19 data-loss fix)", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-ccc", "structured day", "2026-09-03", null, null, {
        energy: -1,
        sleep: 2,
        tags: ["work", "family"],
      }),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "structured day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("structured day, revised");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    const [updatedId, blob] = vi.mocked(api.updateEntry).mock.calls[0] as unknown as [string, string, string];
    const payload = decryptEntry({ dataKey }, "user-1", updatedId, blob, 1);
    // The typo fix must not have erased the day's check-ins.
    expect(payload.v).toBe(2);
    expect(payload.text).toBe("structured day, revised");
    expect(payload.energy).toBe(-1);
    expect(payload.sleep).toBe(2);
    expect(payload.tags).toEqual(["work", "family"]);
    await act(async () => root.unmount());
  });

  it("malformed structured values degrade to absent at decrypt time — never a payload the server would reject", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-ddd", "weird channels day", "2026-09-03", null, null, {
        energy: "high",
        sleep: 99,
        tags: "work",
      }),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "weird channels day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("weird channels day, revised");
    });
    await pressLabel(root, "Save changes");
    await flush();
    const [updatedId, blob] = vi.mocked(api.updateEntry).mock.calls[0] as unknown as [string, string, string];
    const payload = decryptEntry({ dataKey }, "user-1", updatedId, blob, 1);
    // Nothing structured survived sanitization: the re-encrypt emits the v1
    // shape (empty structured), which the server accepts everywhere.
    expect(payload.v).toBe(1);
    expect(payload.energy).toBeUndefined();
    expect(payload.sleep).toBeUndefined();
    expect(payload.tags).toBeUndefined();
    await act(async () => root.unmount());
  });

  it("tag sanitization mirrors the server's cleaning — strip, lowercase, cap, dedupe", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-eee", "taggy day", "2026-09-03", null, null, {
        tags: ["  Work ", "WORK", "a-very-long-tag-name-over-24-chars", "", "family"],
      }),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "taggy day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("taggy day, revised");
    });
    await pressLabel(root, "Save changes");
    await flush();
    const [updatedId, blob] = vi.mocked(api.updateEntry).mock.calls[0] as unknown as [string, string, string];
    const payload = decryptEntry({ dataKey }, "user-1", updatedId, blob, 1);
    expect(payload.tags).toEqual(["work", "a-very-long-tag-name-ove", "family"]);
    await act(async () => root.unmount());
  });

  it("saving an unchanged edit is a no-op straight back to the entry", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await openEditor(root, "original words");
    await pressLabel(root, "Save changes");
    await flush();
    expect(api.updateEntry).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Edit this entry"); // detail again
  });

  it("the editor's Cancel returns untouched, and a blank draft cannot save", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("   ");
    });
    const { touchableByLabel } = await import("../helpers/rtr");
    expect(touchableByLabel(root, "Save changes").props.disabled).toBe(true);
    await pressLabel(root, "Cancel");
    expect(textOf(root)).toContain("original words");
    expect(api.updateEntry).not.toHaveBeenCalled();
  });

  it("the editor enforces the same 100k cap as the Entry screen", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("x".repeat(100_001));
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Entry too long", expect.stringContaining("100,000"));
    expect(api.updateEntry).not.toHaveBeenCalled();
  });

  it("an offline edit keeps both the original and the typed replacement", async () => {
    oneEntry();
    vi.mocked(api.updateEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(lastAlert()[0]).toBe("Needs a connection");
    expect(lastAlert()[1]).toContain("original entry");
    expect(lastAlert()[1]).toContain("text are both still safe");
    expect(api.createEntry).not.toHaveBeenCalled();
    expect(api.deleteEntry).not.toHaveBeenCalled();
  });

  it("a 404 from atomic replacement preserves the draft and original", async () => {
    oneEntry();
    vi.mocked(api.updateEntry).mockRejectedValue(new ApiError(404, "already gone"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    expect(api.createEntry).not.toHaveBeenCalled();
    expect(lastAlert()[0]).toBe("Could not update");
    expect(lastAlert()[1]).toContain("original entry is unchanged");
  });

  it("a failed atomic replacement keeps the text and never removes the old version", async () => {
    oneEntry();
    vi.mocked(api.updateEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(lastAlert()[0]).toBe("Needs a connection");
    expect(lastAlert()[1]).toContain("original entry and this text are both still safe");
    // The editor stayed open with the text — a retry is one tap away.
    const { TextInput } = await import("react-native");
    const stillOpen = root.root.findAllByType(TextInput).find((n) => n.props.accessibilityLabel === "Edit entry");
    expect(stillOpen?.props.value).toBe("revised words");
  });

  it("an atomic replacement server failure surfaces calm copy", async () => {
    oneEntry();
    vi.mocked(api.updateEntry).mockRejectedValue(new ApiError(500, "boom"));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(lastAlert()[0]).toBe("Could not update");
    expect(lastAlert()[1]).toContain("The server hit a problem — try again in a moment.");
    expect(lastAlert()[1]).toContain("original entry is unchanged");
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("editing requires a stored account id — the text stays on screen", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    vi.mocked(api.getUserId).mockResolvedValue(null);
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(lastAlert()[0]).toBe("Session damaged");
    expect(api.deleteEntry).not.toHaveBeenCalled();
  });

  it("editing one entry leaves the others exactly as they were", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "first entry", "2026-09-03"),
      entryRow("e-2026-09-02-ccc", "second entry", "2026-09-02"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "first entry");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("first entry, revised");
    });
    await pressLabel(root, "Save changes");
    await flush();
    await pressLabel(root, "Back to history");
    await flush();
    expect(textOf(root)).toContain("first entry, revised");
    expect(textOf(root)).toContain("second entry"); // untouched
    expect(entryRows(root)).toHaveLength(2);
    await act(async () => root.unmount());
  });

  it("the editor uses the padding keyboard behavior on iOS and none on Android", async () => {
    oneEntry();
    const reactNative = await import("react-native");
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await openEditor(root, "original words");
    expect(root.root.findByType(reactNative.KeyboardAvoidingView).props.behavior).toBe("padding");
    const original = reactNative.Platform.OS;
    (reactNative.Platform as { OS: string }).OS = "android";
    try {
      const androidRoot = await render(<HistoryScreen navigation={nav} />);
      await flush();
      await openEditor(androidRoot, "original words");
      expect(androidRoot.root.findByType(reactNative.KeyboardAvoidingView).props.behavior).toBeUndefined();
    } finally {
      (reactNative.Platform as { OS: string }).OS = original;
    }
  });

  it("a double-tap on Save changes saves once (the busy guard)", async () => {
    oneEntry();
    let resolveUpdate!: (v: unknown) => void;
    vi.mocked(api.updateEntry).mockImplementation(() => new Promise((resolve) => (resolveUpdate = resolve)));
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    const { touchableByLabel } = await import("../helpers/rtr");
    const btn = touchableByLabel(root, "Save changes");
    await act(async () => {
      void (btn.props as { onPress: () => unknown }).onPress?.();
      void (btn.props as { onPress: () => unknown }).onPress?.();
    });
    await act(async () => resolveUpdate({}));
    await flush();
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    expect(api.deleteEntry).not.toHaveBeenCalled();
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("a blank draft fired straight through the handler is a no-op", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("   ");
    });
    const { touchableByLabel } = await import("../helpers/rtr");
    const btn = touchableByLabel(root, "Save changes");
    await act(async () => {
      void (btn.props as { onPress: () => unknown }).onPress?.(); // leaked press past the disabled control
    });
    await flush();
    expect(api.updateEntry).not.toHaveBeenCalled();
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("a locked vault mid-edit reports honestly instead of crashing", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    vault.lock(); // background lock landed between listing and saving
    await pressLabel(root, "Save changes");
    await flush();
    expect(lastAlert()[0]).toBe("Could not update");
    expect(lastAlert()[1]).toBe("vault is locked");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, "user-1");
  });

  it("a failed mood-log write after a successful edit is swallowed quietly", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "original words");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("revised words");
    });
    // The edit itself succeeds; only the device-local log write may fail.
    const original = storage.setItem;
    storage.setItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      await pressLabel(root, "Save changes");
      await flush();
      expect(textOf(root)).toContain("Updated ✓");
      expect(api.updateEntry).toHaveBeenCalledTimes(1);
    } finally {
      storage.setItem = original;
    }
  });

  it("a live status line is replaced, not stacked, by the next one", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "first entry", "2026-09-03"),
      entryRow("e-2026-09-02-ccc", "second entry", "2026-09-02"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    // Delete one (status: "Entry deleted"), then edit the other — the second
    // status clears the first timer instead of stacking.
    await pressLabel(root, "first entry");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently");
    await flush();
    expect(textOf(root)).toContain("Entry deleted");
    const editor = await openEditor(root, "second entry");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("second entry, revised");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(textOf(root)).toContain("Updated ✓");
    expect(textOf(root)).not.toContain("Entry deleted");
    await act(async () => root.unmount());
  });
});

describe("HistoryScreen focus reload and crisis access", () => {
  it("returning to the screen reloads; the first (mount) focus event does not double-load", async () => {
    const { focusNav, fireFocus } = navWithFocus();
    vi.mocked(api.listEntries).mockResolvedValue([entryRow("e-2026-09-03-bbb", "third day", "2026-09-03")] as never);
    const root = await render(<HistoryScreen navigation={focusNav} />);
    await flush();
    expect(api.listEntries).toHaveBeenCalledTimes(1);
    await act(async () => fireFocus()); // the mount focus: skipped
    await flush();
    expect(api.listEntries).toHaveBeenCalledTimes(1);
    await act(async () => fireFocus()); // a real return: reload
    await flush();
    expect(api.listEntries).toHaveBeenCalledTimes(2);
    await act(async () => root.unmount()); // unsubscribes without complaint
  });

  it("crisis help is one tap from the list, the detail, and the editor", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "an ordinary entry", "2026-09-03"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Need help now? Crisis resources");
    await pressLabel(root, "an ordinary entry");
    await pressLabel(root, "Need help now? Crisis resources");
    await pressLabel(root, "Edit this entry");
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate.mock.calls).toEqual([["Crisis"], ["Crisis"], ["Crisis"]]);
  });
});

describe("HistoryScreen Android hardware back (focus-scoped)", () => {
  /** Navigation prop whose addListener captures callbacks per event name. */
  function navWithFocusBlur() {
    const listeners: Record<string, Array<() => void>> = {};
    const focusBlurNav = {
      navigate: vi.fn(),
      addListener: vi.fn((event: string, cb: () => void) => {
        (listeners[event] ??= []).push(cb);
        return vi.fn();
      }),
    };
    return { focusBlurNav, fire: (event: string) => (listeners[event] ?? []).forEach((cb) => cb()) };
  }

  /** Capture hardwareBack subscriptions; one is "active" until its remove() runs. */
  function captureBack() {
    const subs: Array<{ handler: () => boolean; remove: ReturnType<typeof vi.fn> }> = [];
    BackHandler.addEventListener.mockImplementation(((event: string, handler: () => boolean) => {
      expect(event).toBe("hardwareBackPress");
      const sub = { handler, remove: vi.fn() };
      subs.push(sub);
      return sub;
    }) as never);
    const live = () => subs.filter((s) => s.remove.mock.calls.length === 0);
    return {
      activeCount: () => live().length,
      pressBack: (): boolean => {
        const current = live();
        if (current.length === 0) throw new Error("no active hardwareBack subscription");
        return current[current.length - 1]!.handler();
      },
    };
  }

  afterEach(() => {
    // Restore the inert default stub for the rest of the file.
    BackHandler.addEventListener.mockImplementation((() => ({ remove: vi.fn() })) as never);
  });

  it("back while focused in detail mode returns to the list (behavior unchanged)", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "an ordinary entry", "2026-09-03"),
    ] as never);
    const { focusBlurNav, fire } = navWithFocusBlur();
    const back = captureBack();
    const root = await render(<HistoryScreen navigation={focusBlurNav} />);
    await flush();
    fire("focus"); // the mount focus (consumed by the reload-skip)
    expect(back.activeCount()).toBe(0); // list mode owns no back press
    await pressLabel(root, "an ordinary entry");
    expect(back.activeCount()).toBe(1);
    expect(back.pressBack()).toBe(true); // consumed by History: detail → list
    await flush();
    expect(textOf(root)).not.toContain("Edit this entry");
    expect(back.activeCount()).toBe(0); // back in list mode: unsubscribed
  });

  it("back while focused in edit mode returns to the list too", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "an ordinary entry", "2026-09-03"),
    ] as never);
    const { focusBlurNav } = navWithFocusBlur();
    const back = captureBack();
    const root = await render(<HistoryScreen navigation={focusBlurNav} />);
    await flush();
    await openEditor(root, "an ordinary entry");
    expect(back.activeCount()).toBe(1);
    expect(back.pressBack()).toBe(true);
    await flush();
    // List again: the editor input is gone and the entry row is back.
    const { TextInput } = await import("react-native");
    expect(root.root.findAllByType(TextInput).find((n) => n.props.accessibilityLabel === "Edit entry")).toBeUndefined();
    expect(entryRows(root)).toHaveLength(1);
  });

  it("blur releases the back press for whichever screen is on top; focus reclaims it", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "an ordinary entry", "2026-09-03"),
    ] as never);
    const { focusBlurNav, fire } = navWithFocusBlur();
    const back = captureBack();
    const root = await render(<HistoryScreen navigation={focusBlurNav} />);
    await flush();
    await pressLabel(root, "an ordinary entry");
    expect(back.activeCount()).toBe(1);
    // A screen pushed on top (native-stack keeps History mounted beneath):
    // its back press must reach IT, not silently reset History to list mode.
    fire("blur");
    expect(back.activeCount()).toBe(0);
    // …and returning to History restores detail → list on back.
    fire("focus");
    expect(back.activeCount()).toBe(1);
    expect(back.pressBack()).toBe(true);
    await flush();
    expect(textOf(root)).not.toContain("Edit this entry");
  });

  it("unmounting while in detail mode removes the handler", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-bbb", "an ordinary entry", "2026-09-03"),
    ] as never);
    const { focusBlurNav } = navWithFocusBlur();
    const back = captureBack();
    const root = await render(<HistoryScreen navigation={focusBlurNav} />);
    await flush();
    await pressLabel(root, "an ordinary entry");
    expect(back.activeCount()).toBe(1);
    await act(async () => root.unmount());
    expect(back.activeCount()).toBe(0);
  });
});

describe("formatEntryDate", () => {
  it("renders friendly dates and survives garbage", () => {
    expect(formatEntryDate("2026-09-03")).toBe("Thursday, September 3, 2026");
    expect(formatEntryDate("not-a-date")).toBe("not-a-date");
  });
});

describe("HistoryScreen edit-path crisis detection (H-6, 2026-09-20)", () => {
  const oneEntry = (id = "e-2026-09-03-crisis") => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow(id, "an ordinary day", "2026-09-03"),
    ] as never);
  };

  it("editing an entry into crisis language points at support AFTER the update commits", async () => {
    oneEntry();
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "an ordinary day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("I want to kill myself");
    });
    await pressLabel(root, "Save changes");
    await flush();
    // The replacement landed first (never before or instead of saving)…
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    expect(textOf(root)).toContain("Updated ✓");
    // …then the same calm, throttled dialog a NEW entry gets.
    expect(Alert.alert).toHaveBeenCalledWith(
      "Support is available",
      expect.stringContaining("you do not have to carry it alone"),
      expect.anything(),
    );
    const buttons = lastAlert()[2] as Array<{ text: string; onPress?: () => void }>;
    const view = buttons.find((b) => b.text === "View support resources");
    expect(view).toBeTruthy();
    await act(async () => {
      view!.onPress?.();
    });
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
    await act(async () => root.unmount());
  });

  it("the per-day throttle applies to edits too — a second crisis edit the same day stays quiet", async () => {
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-crisis-a", "first ordinary day", "2026-09-03"),
      entryRow("e-2026-09-02-crisis-b", "second ordinary day", "2026-09-02"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    let editor = await openEditor(root, "first ordinary day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("I want to kill myself");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(Alert.alert).toHaveBeenCalledTimes(1);

    // A different day's entry, same crisis language, same calendar day:
    // the stamp suppresses the repeat (dialog-fatigue guard).
    await pressLabel(root, "Back to history");
    editor = await openEditor(root, "second ordinary day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("I want to end my life");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(api.updateEntry).toHaveBeenCalledTimes(2);
    expect(Alert.alert).toHaveBeenCalledTimes(1);
    await act(async () => root.unmount());
  });

  it("a non-crisis edit never raises the dialog", async () => {
    oneEntry("e-2026-09-03-calm");
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    const editor = await openEditor(root, "an ordinary day");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("a calmer revision");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(api.updateEntry).toHaveBeenCalledTimes(1);
    expect(Alert.alert).not.toHaveBeenCalled();
    await act(async () => root.unmount());
  });
});

describe("HistoryScreen pagination after edit/delete (L-67, 2026-09-20)", () => {
  it("a delete re-acquires the snapshot token on the next continuation instead of 409-restarting", async () => {
    // Two rows on page one: the delete target plus a keeper, so the list
    // (and its search box) survive the delete.
    const victim = entryRow("e-2026-09-03-p1", "page one entry", "2026-09-03");
    const keeper = entryRow("e-2026-09-02-p1b", "page one keeper", "2026-09-02");
    const page2 = entryRow("e-2026-08-01-p2", "page two entry", "2026-08-01");
    let serverRevision = "5";
    vi.mocked(api.listEntriesPage).mockImplementation(async (opts) => {
      const offset = (opts as { offset?: number } | undefined)?.offset ?? 0;
      if (offset === 0) return { entries: [victim, keeper], nextOffset: 2, revision: serverRevision } as never;
      return { entries: [page2], nextOffset: null, revision: serverRevision } as never;
    });

    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(1, {
      limit: 100, offset: 0, pageBytes: 2 * 1024 * 1024,
    });
    expect(textOf(root)).toContain("Load older entries");

    // A search filter is active while the delete happens — the fix means no
    // full reload runs, so the filter must survive the delete.
    const search = inputByPlaceholder(root, "Search your entries");
    await act(async () => {
      (search.props as { onChangeText: (t: string) => void }).onChangeText("page");
    });
    await flush();

    // Delete the visible entry (double confirmation).
    await pressLabel(root, "page one entry");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently");
    await flush();
    expect(textOf(root)).toContain("Entry deleted");

    // The server's revision moved (this delete, or any other device's write).
    serverRevision = "6";
    // The user clears their search to page deeper… (the list re-mounted
    // around the detail round-trip, so the input node is re-found.)
    const searchAgain = inputByPlaceholder(root, "Search your entries");
    await act(async () => {
      (searchAgain.props as { onChangeText: (t: string) => void }).onChangeText("");
    });
    await flush();
    await pressLabel(root, "Load older entries");
    await flush();

    // …and the continuation goes out UNPINNED (the stale token was dropped
    // by the delete) and ADOPTS the fresh revision — no 409, no restart.
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(2, {
      limit: 100, offset: 2, pageBytes: 2 * 1024 * 1024,
    });
    expect(textOf(root)).toContain("page two entry");
    expect(textOf(root)).toContain("page one keeper");
    expect(textOf(root)).not.toContain("Reloading the latest history from the start.");
    await act(async () => root.unmount());
  });

  it("a successful edit drops the token the same way (no self-inflicted 409 on the next page)", async () => {
    const page1 = entryRow("e-2026-09-03-edit-p1", "editable entry", "2026-09-03");
    const page2 = entryRow("e-2026-08-01-edit-p2", "older page entry", "2026-08-01");
    let serverRevision = "5";
    vi.mocked(api.listEntriesPage).mockImplementation(async (opts) => {
      const offset = (opts as { offset?: number } | undefined)?.offset ?? 0;
      if (offset === 0) return { entries: [page1], nextOffset: 1, revision: serverRevision } as never;
      return { entries: [page2], nextOffset: null, revision: serverRevision } as never;
    });
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();

    const editor = await openEditor(root, "editable entry");
    await act(async () => {
      (editor.props as { onChangeText: (t: string) => void }).onChangeText("editable entry, revised");
    });
    await pressLabel(root, "Save changes");
    await flush();
    expect(textOf(root)).toContain("Updated ✓");

    serverRevision = "6";
    await pressLabel(root, "Back to history");
    await pressLabel(root, "Load older entries");
    await flush();
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(2, {
      limit: 100, offset: 1, pageBytes: 2 * 1024 * 1024,
    });
    expect(textOf(root)).toContain("older page entry");
    expect(textOf(root)).not.toContain("Reloading the latest history from the start.");
    await act(async () => root.unmount());
  });

  it("an UNRELATED revision change on a pinned walk still restarts (the guard is intact)", async () => {
    const page1 = entryRow("e-2026-09-03-guard", "guard page one", "2026-09-03");
    const fresh = entryRow("e-2026-09-04-guard-fresh", "guard fresh page", "2026-09-04");
    vi.mocked(api.listEntriesPage)
      .mockResolvedValueOnce({ entries: [page1], nextOffset: 1, revision: "5" } as never)
      .mockResolvedValueOnce({ entries: [], nextOffset: null, revision: "9" } as never)
      .mockResolvedValueOnce({ entries: [fresh], nextOffset: null, revision: "9" } as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Load older entries");
    await flush();
    await flush();
    // The pinned continuation landed on a DIFFERENT snapshot: restart from
    // page one remains the only safe rendering.
    expect(api.listEntriesPage).toHaveBeenNthCalledWith(2, {
      limit: 100, offset: 1, pageBytes: 2 * 1024 * 1024, expectedRevision: "5",
    });
    expect(textOf(root)).toContain("Reloading the latest history from the start.");
    await act(async () => root.unmount());
  });
});

describe("HistoryScreen delete removes the day's local mood value (L-68, 2026-09-20)", () => {
  it("deleting an entry drops the day from the device-local mood log, streak and badge", async () => {
    await recordMood(dataKey, "user-1", "2026-09-03", 0.5);
    await recordMood(dataKey, "user-1", "2026-09-02", -0.5);
    vi.mocked(api.listEntries).mockResolvedValue([
      entryRow("e-2026-09-03-mood", "mood backed day", "2026-09-03"),
      entryRow("e-2026-09-02-mood", "neighbour day", "2026-09-02"),
    ] as never);
    const root = await render(<HistoryScreen navigation={nav} />);
    await flush();
    // The badge is the mood log's day value (no explicit payload pick).
    const badgesBefore = moodBadges(root);
    expect(badgesBefore).toContain("Mood: Good");

    await pressLabel(root, "mood backed day");
    await pressLabel(root, "Delete this entry");
    await pressAlertButton("Delete");
    await pressAlertButton("Delete permanently");
    await flush();

    // The device-local log no longer counts the deleted day; its sibling stays.
    const days = await recentMoods(dataKey, "user-1", 30);
    expect(days.map((d) => d.date)).toEqual(["2026-09-02"]);
    // The rendered fallback badge for that day is gone too — only the
    // neighbour's distinct value (Low) is still badged.
    expect(moodBadges(root)).toEqual(["Mood: Low"]);
    await act(async () => root.unmount());
  });
});
