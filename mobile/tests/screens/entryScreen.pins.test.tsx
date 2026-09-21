/**
 * Deep-mutation pins for EntryScreen (2026-09-15 Stryker campaign).
 *
 * Each block kills a specific surviving mutant class:
 *  - initial-state guards (no "Draft restored" chip without a restore; no
 *    count below the 90,000-char boundary — the boundary is strict >),
 *  - the transient status line lifecycle under fake timers (re-arm clears
 *    the previous timer, STATUS_MS self-clears, the unmount cleanup clears
 *    a live timer, and no clearTimeout(null) ever fires),
 *  - status tone colors (ok = success, offline = muted) via node-exact
 *    styles,
 *  - the 401 draft stash observed directly (peekDraft, no unmount that
 *    would re-stash), the unlockDays=0/activeDays=0 NaN guard,
 *  - node-exact style contracts (progress label, streak line, count line,
 *    mood check-in label/row/options/option-text, Hide keyboard ghost,
 *    keyboard-avoiding flex), the crisis-alert button contract,
 *  - operation without a navigation prop (the optional-chained listener).
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, Text } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

vi.mock("../../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/MindPatternCrypto")>();
  return { ...actual, encryptEntry: vi.fn(() => ({ blobB64: "QkxPQg==" })) };
});

class QueueFullError extends Error {
  constructor() {
    super("offline queue is full (200 entries) — sync before writing more");
    this.name = "QueueFullError";
  }
}
class QueueAbandonedError extends Error {
  constructor() {
    super("the queue was wiped while saving — the entry was NOT queued");
    this.name = "QueueAbandonedError";
  }
}
const recordMood = vi.fn(async () => {});
const recentMoods = vi.fn(async (): Promise<{ date: string; value: number }[]> => []);
const localStreak = vi.fn(async () => 0);
vi.mock("../../src/moodLog", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/moodLog")>();
  return { ...actual, recordMood, recentMoods, localStreak, localDateISO: vi.fn(() => "2026-09-04") };
});

vi.mock("../../src/offlineQueue", () => ({
  QueueFullError,
  QueueAbandonedError,
  enqueue: vi.fn(async () => {}),
  flushQueue: vi.fn(async () => 0),
}));

let sessionState: Record<string, unknown>;
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return {
    ...actual,
    useSession: () => sessionState,
  };
});

const { api, ApiError } = await import("../../src/api/client");
const { encryptEntry } = await import("../../src/crypto/MindPatternCrypto");
const { enqueue, flushQueue } = await import("../../src/offlineQueue");
const { localDateISO } = await import("../../src/moodLog");
const { peekDraft } = await import("../../src/store");
const { EntryScreen } = await import("../../src/screens/EntryScreen");
const { vault } = await import("../../src/vault");
const { render, flush, textOf, allText, pressLabel, typeInto, touchableByLabel, inputByPlaceholder, act, expectStyle } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const keys = { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) };
const nav = { navigate: vi.fn() };
const touchActivity = vi.fn();

beforeEach(async () => {
  resetApi(api as never);
  vi.mocked(enqueue).mockReset();
  vi.mocked(enqueue).mockImplementation(async () => {});
  vi.mocked(flushQueue).mockReset();
  vi.mocked(flushQueue).mockImplementation(async () => 0);
  vi.mocked(encryptEntry).mockClear();
  vi.mocked(encryptEntry).mockImplementation(() => ({ blobB64: "QkxPQg==" }));
  vi.mocked(recentMoods).mockReset();
  vi.mocked(recentMoods).mockImplementation(async () => []);
  vi.mocked(localStreak).mockReset();
  vi.mocked(localStreak).mockImplementation(async () => 0);
  Alert.alert.mockClear();
  nav.navigate.mockClear();
  touchActivity.mockClear();
  vault.lock();
  vault.unlock({ ...keys, masterKey: Buffer.alloc(32) });
  sessionState = { activeDays: 0, unlockDays: 30, touchActivity };
  storage.__reset();
  vi.mocked(localDateISO).mockReturnValue("2026-09-04");
  const { takeStashedDraft } = await import("../../src/store");
  takeStashedDraft("user-1");
  takeStashedDraft("user-2");
});

async function writeEntry(root: Awaited<ReturnType<typeof render>>, text: string): Promise<void> {
  await typeInto(root, "What's going on today?", text);
}

/** The check-ins sit behind the collapsed-by-default disclosure. */
async function openDetails(root: Awaited<ReturnType<typeof render>>): Promise<void> {
  await pressLabel(root, "Add details (optional)");
}

/** The style of the Text node whose flattened content contains `fragment`. */
function styleOfText(root: Awaited<ReturnType<typeof render>>, fragment: string): unknown {
  const flat = (children: unknown): string => {
    if (typeof children === "string") return children;
    if (typeof children === "number") return String(children);
    if (Array.isArray(children)) return children.map(flat).join("");
    return "";
  };
  const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
  if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}: ${allText(root).join(" | ")}`);
  return (node.props as { style: unknown }).style;
}

describe("EntryScreen pins: initial-state and boundary guards", () => {
  it("no 'Draft restored' chip on a clean mount (initial draftRestored is false)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Draft restored");
  });

  it("exactly 90,000 characters is still below the counter (the boundary is strict >)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "x".repeat(90_000));
    expect(textOf(root)).not.toContain("/ 100,000");
    // One more character and it appears.
    await writeEntry(root, "x".repeat(90_001));
    expect(textOf(root)).toContain("90,001 / 100,000");
  });

  it("unlockDays=0 with activeDays=0 renders a full bar, never NaN", async () => {
    sessionState = { activeDays: 0, unlockDays: 0, touchActivity };
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    const { View } = await import("react-native");
    const fill = root.root
      .findAllByType(View)
      .map((n) => n.props.style)
      .flat()
      .find((s: unknown) => typeof s === "object" && s !== null && "width" in (s as object));
    expect((fill as { width: string }).width).toBe("100%");
  });

  it("runs without a navigation prop at all (the focus listener hook is optional-chained)", async () => {
    const root = await render(<EntryScreen />);
    await flush();
    expect(textOf(root)).toContain("Save entry");
    await openDetails(root);
    expect(textOf(root)).toContain("How does today feel?");
  });
});

describe("EntryScreen pins: the transient status line (fake timers)", () => {
  it("re-arms per save, self-clears after STATUS_MS, and dies cleanly at unmount", async () => {
    vi.useFakeTimers();
    const clearSpy = vi.spyOn(global, "clearTimeout");
    try {
      const root = await render(<EntryScreen navigation={nav} />);
      await writeEntry(root, "first");
      await pressLabel(root, "Save entry");
      expect(textOf(root)).toContain("Saved ✓");
      // The FIRST showStatus had no live timer: nothing may be cleared with
      // a null id (an unconditional clearTimeout(null) shows up right here).
      expect(clearSpy.mock.calls.filter(([id]) => id == null)).toHaveLength(0);

      await act(async () => {
        vi.advanceTimersByTime(2_000);
      });
      await writeEntry(root, "second");
      await pressLabel(root, "Save entry");
      // The first save's 2600ms timer was cleared on re-arm: the second
      // status survives past the first save's deadline.
      await act(async () => {
        vi.advanceTimersByTime(601);
      });
      expect(textOf(root)).toContain("Saved ✓");
      // ...and clears after its own STATUS_MS.
      await act(async () => {
        vi.advanceTimersByTime(2_600);
      });
      expect(textOf(root)).not.toContain("Saved ✓");

      // The unmount cleanup clears the LIVE timer (a leaked one would fire
      // setStatus into an unmounted tree). Capture the armed handle via a
      // setTimeout spy, then require the unmount to clear exactly it — the
      // save's own re-arm clearTimeout fires too, so identity is the only
      // honest witness.
      clearSpy.mockClear();
      const setSpy = vi.spyOn(global, "setTimeout");
      try {
        await writeEntry(root, "third");
        await pressLabel(root, "Save entry");
        expect(textOf(root)).toContain("Saved ✓");
        const armed = setSpy.mock.results[setSpy.mock.results.length - 1]?.value;
        await act(async () => root.unmount());
        expect(clearSpy.mock.calls.some(([id]) => id === armed)).toBe(true);
      } finally {
        setSpy.mockRestore();
      }
    } finally {
      clearSpy.mockRestore();
      vi.useRealTimers();
    }
  });

  it("a fresh unmount with no live status timer clears nothing (no clearTimeout(null))", async () => {
    vi.useFakeTimers();
    const clearSpy = vi.spyOn(global, "clearTimeout");
    try {
      const root = await render(<EntryScreen navigation={nav} />);
      await act(async () => root.unmount());
      expect(clearSpy.mock.calls.filter(([id]) => id == null)).toHaveLength(0);
    } finally {
      clearSpy.mockRestore();
      vi.useRealTimers();
    }
  });
});

describe("EntryScreen pins: status tone colors", () => {
  it("an online save reads as success: the Saved ✓ line is success-colored", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "good day");
    await pressLabel(root, "Save entry");
    await flush();
    expect(styleOfText(root, "Saved ✓")).toEqual({ color: "#59c98a", fontSize: 13 });
  });

  it("an offline (queued) save reads as neutral: muted, never success-colored", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();
    expect(styleOfText(root, "Saved — will sync when online")).toEqual({ color: "#8a91a3", fontSize: 13 });
  });
});

describe("EntryScreen pins: the 401 draft stash", () => {
  it("the 401 path itself stashes the draft (observed without any unmount)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "keep me directly");
    await pressLabel(root, "Save entry");
    await flush();
    // No unmount here: only the 401 branch's own stashDraft can explain this.
    expect(peekDraft("user-1")).toBe("keep me directly");
  });
});

describe("EntryScreen pins: no-account drafts are never restored", () => {
  it("a draft stashed under a null user id is not restored on mount", async () => {
    // The mount restore is guarded by `if (id)`; without the guard,
    // takeStashedDraft(null) would match a null-keyed stash and replay it
    // into a signed-out session.
    const { stashDraft } = await import("../../src/store");
    stashDraft(null as never, "draft parked under no account");
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Draft restored");
    expect(textOf(root)).not.toContain("draft parked under no account");
  });
});

describe("EntryScreen pins: post-save state", () => {
  it("a successful save leaves no 'Draft restored' chip behind", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "done and saved");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    expect(textOf(root)).not.toContain("Draft restored");
  });
});

describe("EntryScreen pins: node-exact style contracts", () => {
  it("the countdown label, streak line and near-cap counter carry their exact styles", async () => {
    vi.mocked(localStreak).mockResolvedValue(4);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(styleOfText(root, "days to your patterns")).toEqual({ color: "#8a91a3", fontSize: 13 });
    expect(styleOfText(root, "Writing streak: 4 days")).toEqual({ color: "#8a91a3", fontSize: 12 });
    await writeEntry(root, "x".repeat(95_000));
    expect(styleOfText(root, "95,000 / 100,000")).toEqual({ color: "#8a91a3", fontSize: 12, textAlign: "right" });
  });

  it("the mood check-in block: container gap, label, row, option and option text", async () => {
    const { View } = await import("react-native");
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    expectStyle(root, { gap: 8 }); // the check-in block container (sm spacing)
    expect(styleOfText(root, "How does today feel?")).toEqual({ color: "#8a91a3", fontSize: 13 });
    const moodRow = root.root.findAllByType(View).find((n) => n.props.accessibilityLabel === "Mood check-in");
    expect(moodRow?.props.style).toEqual({ flexDirection: "row", gap: 8 });
    const okay = root.root.findAll((n) => n.props.accessibilityLabel === "Mood: Okay")[0];
    expect(okay.props.style).toEqual([
      { flex: 1, alignItems: "center", justifyContent: "center", paddingVertical: 10 },
      { backgroundColor: "#1a1e26", borderRadius: 10, minHeight: 44 },
    ]);
    expect(styleOfText(root, "Okay")).toEqual({ color: "#b6bdc9", fontSize: 13 });
  });

  it("the keyboard-avoiding wrapper is exactly {flex: 1}", async () => {
    const { KeyboardAvoidingView } = await import("react-native");
    const root = await render(<EntryScreen navigation={nav} />);
    expect(root.root.findByType(KeyboardAvoidingView).props.style).toEqual({ flex: 1 });
  });

  it("the Hide-keyboard affordance stays left-aligned (center={false})", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "anything");
    expect((touchableByLabel(root, "Hide keyboard").props as { style: unknown[] }).style).toEqual([
      { padding: 12 },
      false,
      { minHeight: 44 },
    ]);
  });

  it("the crisis help nav button carries its explicit accessibility label", async () => {
    const { TouchableOpacity } = await import("react-native");
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    const help = root.root
      .findAllByType(TouchableOpacity)
      .find((n) => n.props.accessibilityLabel === "Get help — crisis resources");
    expect(help).toBeDefined();
    expect(help?.props.accessibilityLabel).toBe("Get help — crisis resources");
  });
});

describe("EntryScreen pins: the crisis support dialog contract", () => {
  it("the support alert's buttons are exactly View-resources / Not-now(cancel)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I have been thinking about how to end it all");
    await pressLabel(root, "Save entry");
    await flush();
    const { lastAlert } = await import("../helpers/rtr");
    expect(lastAlert()[2]).toEqual([
      { text: "View support resources", onPress: expect.any(Function) },
      { text: "Not now", style: "cancel" },
    ]);
  });
});

describe("EntryScreen pins: 44pt touch contract on every chip (audit fix 23, 2026-09-21)", () => {
  it("sleep options meet t.minTouch like their mood/energy siblings (40pt before)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    const sleep = root.root.findAll((n) => n.props.accessibilityLabel === "Sleep: Rough")[0];
    expect(sleep).toBeTruthy();
    expect(sleep.props.style).toEqual([
      { flex: 1, alignItems: "center", justifyContent: "center", paddingVertical: 10 },
      { backgroundColor: "#1a1e26", borderRadius: 10, minHeight: 44 },
    ]);
  });

  it("activity-tag chips carry minHeight 44 (they measured ~33pt before)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    const tag = root.root.findAll((n) => n.props.accessibilityLabel === "Tag: work")[0];
    expect(tag).toBeTruthy();
    expect((tag.props.style as unknown[])[1]).toMatchObject({ minHeight: 44 });
    // The selected variant keeps the contract too.
    await pressLabel(root, "work");
    const selected = root.root.findAll(
      (n) => n.props.accessibilityLabel === "Tag: work" && n.props.accessibilityState?.checked === true,
    )[0];
    expect((selected.props.style as unknown[])[1]).toMatchObject({ minHeight: 44 });
  });

  it("prompt chips (blank-page starters) carry minHeight 44", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    const chip = root.root
      .findAll((n) => typeof n.props.accessibilityLabel === "string")
      .find((n) => (n.props.accessibilityLabel as string).startsWith("Start with:"));
    expect(chip).toBeTruthy();
    expect((chip!.props.style as unknown[])[1]).toMatchObject({ minHeight: 44, justifyContent: "center" });
  });
});
