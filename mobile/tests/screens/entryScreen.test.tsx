/**
 * EntryScreen: threshold progress copy, the save pipeline (encrypt →
 * upload, with per-failure-class fallbacks), offline queueing, and nav.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock() };
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
vi.mock("../../src/moodLog", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/moodLog")>();
  return { ...actual, recordMood, localDateISO: vi.fn(() => "2026-09-04") };
});

// C2: saving/syncing an entry must NEVER auto-ship the data key — the
// mini-brain refresh is an explicit, user-initiated act only. EntryScreen no
// longer imports brainSync at all, so nothing here can trigger a recompute.

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
const { enqueue, flushQueue, QueueFullError: QFErr, QueueAbandonedError: QAErr } = await import("../../src/offlineQueue");
const { takeStashedDraft } = await import("../../src/store");
const { EntryScreen } = await import("../../src/screens/EntryScreen");
const { vault } = await import("../../src/vault");
const { render, flush, textOf, pressLabel, typeInto, touchableByLabel, allText, act, inputByPlaceholder, pressAlertButton } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");

const keys = { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) };
const nav = { navigate: vi.fn() };
const touchActivity = vi.fn();

beforeEach(() => {
  resetApi(api as never);
  vi.mocked(enqueue).mockReset();
  vi.mocked(enqueue).mockImplementation(async () => {});
  vi.mocked(flushQueue).mockReset();
  vi.mocked(flushQueue).mockImplementation(async () => 0);
  vi.mocked(encryptEntry).mockClear();
  vi.mocked(encryptEntry).mockImplementation(() => ({ blobB64: "QkxPQg==" }));
  Alert.alert.mockClear();
  nav.navigate.mockClear();
  touchActivity.mockClear();
  vault.lock();
  vault.unlock({ ...keys, masterKey: Buffer.alloc(32) });
  sessionState = { activeDays: 0, unlockDays: 30, touchActivity };
  // The draft stash is module state (in store.tsx): consume any leftover
  // so one test's stashed draft cannot leak into the next.
  takeStashedDraft("user-1");
  takeStashedDraft("user-2");
});

async function writeEntry(root: Awaited<ReturnType<typeof render>>, text: string): Promise<void> {
  await typeInto(root, "What's going on today?", text);
}

describe("EntryScreen progress display", () => {
  it("shows the countdown before the threshold and the unlocked state after", async () => {
    const before = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(before)).toContain("0/30 days to your patterns");
    expect(textOf(before)).not.toContain("Patterns unlocked");
    // Not busy while idle: a typed entry makes Save enabled.
    await writeEntry(before, "draft text");
    expect(touchableByLabel(before, "Save entry").props.disabled).toBe(false);

    sessionState = { activeDays: 30, unlockDays: 30 };
    const after = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(after)).toContain("Patterns unlocked");
    expect(textOf(after)).not.toContain("days to your patterns");
  });

  it("starts with an empty editor and the exact layout container", async () => {
    const rtr = await import("../helpers/rtr");
    const reactNative = await import("react-native");
    const root = await render(<EntryScreen navigation={nav} />);
    expect(
      (rtr.inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("");
    const scroll = root.root.findByType(reactNative.ScrollView);
    expect(scroll.props.contentContainerStyle).toEqual({ padding: 20, gap: 16 });
    expect(scroll.props.style).toEqual({ flex: 1, backgroundColor: "#0f1115" });
  });

  it("renders a progress bar proportional to active days", async () => {
    sessionState = { activeDays: 12, unlockDays: 30 };
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    const { View } = await import("react-native");
    const fill = root.root
      .findAllByType(View)
      .map((n) => n.props.style)
      .flat()
      .find((s: unknown) => typeof s === "object" && s !== null && "width" in (s as object));
    expect(fill).toMatchObject({ width: "40%" });
  });

  it("accepts an entry of exactly the 100k cap", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "x".repeat(100_000));
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(api.createEntry).toHaveBeenCalledTimes(1);
  });

  it("pins the visual language of the screen (styles are a product contract)", async () => {
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expectStyle(root, { flex: 1, backgroundColor: "#0f1115" }); // container
    expectStyle(root, { gap: 6 }); // progressRow
    expectStyle(root, { color: "#8a91a3", fontSize: 13 }); // progressLabel
    expectStyle(root, { height: 6, borderRadius: 3, backgroundColor: "#1a1e26", overflow: "hidden" }); // progressTrack
    expectStyle(root, { height: 6, borderRadius: 3, backgroundColor: "#4f7cff" }); // progressFill
    expectStyle(root, {
      backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 12, padding: 16,
      fontSize: 16, minHeight: 220, textAlignVertical: "top",
    }); // input
    expectStyle(root, { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center" }); // button
    expectStyle(root, { color: "#fff", fontSize: 16, fontWeight: "600" }); // buttonText
    expectStyle(root, { flexDirection: "row", gap: 10 }); // navRow
    expectStyle(root, { flex: 1, backgroundColor: "#1a1e26", borderRadius: 10, padding: 14, alignItems: "center" }); // navButton
    expectStyle(root, { color: "#7f9bff", fontSize: 14, fontWeight: "600" }); // navText
  });

  it("flushes the offline queue on mount once the user id resolves", async () => {
    await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(flushQueue).toHaveBeenCalledWith("user-1");
    // C2: the flush cannot trigger an automatic data-key upload — the screen
    // holds no reference to brainSync.
  });

  it("skips the mount flush when no user id is stored", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(flushQueue).not.toHaveBeenCalled();
  });
});

describe("EntryScreen save pipeline", () => {
  it("ignores empty and whitespace-only entries", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "   ");
    expect(touchableByLabel(root, "Save entry").props.disabled).toBe(true);
    await pressLabel(root, "Save entry");
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("rejects entries over the 100k character cap with an honest alert", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "x".repeat(100_001));
    await pressLabel(root, "Save entry");
    expect(Alert.alert).toHaveBeenCalledWith("Entry too long", expect.stringContaining("100,000"));
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("encrypts on-device and clears the editor after a successful sync", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "good day, calm evening");
    await pressLabel(root, "Save entry");
    await flush();

    expect(encryptEntry).toHaveBeenCalledWith(
      expect.objectContaining({ dataKey: keys.dataKey }),
      "user-1",
      expect.stringMatching(/^e-\d{4}-\d{2}-\d{2}-/),
      "good day, calm evening",
      expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
      null,  // v3: no client sentiment — the server engine re-scores at analysis time
    );
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(Alert.alert).not.toHaveBeenCalled();
    // Editor cleared and disabled again.
    expect(touchableByLabel(root, "Save entry").props.disabled).toBe(true);
  });

  it("records local sentiment into the device-only mood log", async () => {
    const cases: Array<[string, number]> = [
      ["good great happy", 1],
      ["bad sad anxious stressed", -1],
      ["good then bad news", 0],
      ["nothing emotional here", 0],
    ];
    for (const [text, sentiment] of cases) {
      vi.mocked(encryptEntry).mockClear();
      recordMood.mockClear();
      const root = await render(<EntryScreen navigation={nav} />);
      await writeEntry(root, text);
      await pressLabel(root, "Save entry");
      await flush();
      // The encrypted payload never carries the quick score...
      expect(vi.mocked(encryptEntry).mock.calls[0]?.[5]).toBeNull();
      // ...but the device-local mood log (baseline-phase trend) does.
      expect(recordMood).toHaveBeenCalledWith(
        keys.dataKey,
        "user-1",
        expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
        sentiment,
      );
    }
  });

  it("refuses to save when the account id is missing (AAD would be unusable)", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "today was fine");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Session damaged", expect.stringContaining("Account id missing"));
    expect(api.createEntry).not.toHaveBeenCalled();
  });

  it("401 locks the vault (navigation gates to Unlock) and keeps the draft", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "keep me");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Session expired", expect.stringContaining("unlock again"));
    // The vault is locked — navigation's gate swaps to the Unlock screen —
    // and the dead session was NOT queued for a guaranteed re-failure.
    expect(vault.isUnlocked()).toBe(false);
    expect(enqueue).not.toHaveBeenCalled();
  });

  it("restores the stashed draft after a 401-forced lock, for the same account only", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const first = await render(<EntryScreen navigation={nav} />);
    await writeEntry(first, "keep me through the relock");
    await pressLabel(first, "Save entry");
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    first.unmount();

    // Same account re-unlocks: the draft is back in the editor.
    vault.unlock({ ...keys, masterKey: Buffer.alloc(32) });
    const second = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(
      (inputByPlaceholder(second, "What's going on today?").props as { value: string }).value,
    ).toBe("keep me through the relock");

    // A DIFFERENT account on the same device must never see the stash.
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const third = await render(<EntryScreen navigation={nav} />);
    await writeEntry(third, "alice's unsent entry");
    await pressLabel(third, "Save entry");
    await flush();
    third.unmount();
    vi.mocked(api.getUserId).mockResolvedValue("user-2");
    vault.unlock({ ...keys, masterKey: Buffer.alloc(32) });
    const fourth = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(
      (inputByPlaceholder(fourth, "What's going on today?").props as { value: string }).value,
    ).toBe("");
  });

  it("never queues a blob the server permanently rejects (422)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "entry_date in the future"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "keep me");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Entry rejected", expect.stringContaining("entry_date"));
    expect(enqueue).not.toHaveBeenCalled();
  });

  it("queues the same encrypted entry when offline", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();

    expect(enqueue).toHaveBeenCalledTimes(1);
    const queued = vi.mocked(enqueue).mock.calls[0][0];
    expect(queued).toMatchObject({ userId: "user-1", blobB64: "QkxPQg==", entryDate: expect.any(String) });
    expect(Alert.alert).toHaveBeenCalledWith("Saved offline", expect.stringContaining("back online"));
  });

  it("protects the queue instead of overflowing it", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QFErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Offline storage full",
      expect.stringContaining("still on screen"),
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
  });

  it("an abandoned enqueue (queue wiped mid-save) is LOUD: no 'Saved offline', draft kept", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QAErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();
    const alerts = Alert.alert.mock.calls.map((c) => c[0]);
    expect(alerts).toEqual(["Not saved"]);
    expect(alerts).not.toContain("Saved offline");
    expect(Alert.alert).toHaveBeenCalledWith("Not saved", expect.stringContaining("still on screen"));
    // The draft stays in the editor for another attempt.
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("offline thought");
  });

  it("surfaces unexpected save errors with their message", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new Error("disk full"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "any entry");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not save", "disk full");
  });

  it("reports a locked vault instead of crashing", async () => {
    vault.lock();
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "secret");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not save", "vault is locked");
  });

  it("falls back to 'unknown error' for non-Error failures", async () => {
    vi.mocked(encryptEntry).mockImplementation(() => {
      throw "crypto exploded"; // eslint-disable-line no-throw-literal
    });
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "secret");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Could not save", "unknown error");
  });

  it("queues on non-ApiError upload failures (plain network error)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new TypeError("fetch failed"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();
    expect(enqueue).toHaveBeenCalledTimes(1);
    expect(Alert.alert).toHaveBeenCalledWith("Saved offline", expect.any(String));
  });
});

describe("EntryScreen navigation", () => {
  it("offers Patterns, Question, Settings and crisis-help shortcuts", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(allText(root).join(" ")).toContain("Patterns");
    await pressLabel(root, "Patterns");
    await pressLabel(root, "Question");
    await pressLabel(root, "Settings");
    await pressLabel(root, "Get help");
    expect(nav.navigate.mock.calls).toEqual([["Insights"], ["Question"], ["Settings"], ["Crisis"]]);
  });

  it("renders the busy spinner instead of the button label while saving", async () => {
    let resolveCreate: ((v: unknown) => void) | undefined;
    vi.mocked(api.createEntry).mockImplementation(
      () => new Promise((resolve) => (resolveCreate = resolve)),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "slow save");
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Save entry");

    // Busy: the label is replaced by the spinner and the button is disabled.
    expect(allText(root)).not.toContain("Save entry");
    const { TouchableOpacity } = await import("react-native");
    const disabled = root.root.findAllByType(TouchableOpacity).filter((n) => n.props.disabled === true);
    expect(disabled).toHaveLength(1);

    await flush(); // let createEntry be called and the deferred be created
    await act(async () => {
      resolveCreate?.({});
    });
    await flush();
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(allText(root)).toContain("Save entry");
  });
});


describe("EntryScreen crisis detection (on-device, pre-encryption)", () => {
  it("shows the gentle support alert AFTER a successful save", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I have been thinking about how to end it all");
    await pressLabel(root, "Save entry");
    await flush();
    // The save ran first — detection never blocks or replaces it.
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(Alert.alert).toHaveBeenCalledWith(
      "Support is available",
      expect.stringContaining("one tap away"),
      expect.arrayContaining([
        expect.objectContaining({ text: "View support resources" }),
        expect.objectContaining({ text: "Not now" }),
      ]),
    );
  });

  it("'View support resources' navigates to Crisis; 'Not now' does nothing", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I want to die tonight");
    await pressLabel(root, "Save entry");
    await flush();
    await pressAlertButton("View support resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");

    nav.navigate.mockClear();
    Alert.alert.mockClear();
    const second = await render(<EntryScreen navigation={nav} />);
    await writeEntry(second, "no reason to live anymore");
    await pressLabel(second, "Save entry");
    await flush();
    await pressAlertButton("Not now");
    expect(nav.navigate).not.toHaveBeenCalled();
  });

  it("stays silent on ordinary entries", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "good day, calm evening with the dog");
    await pressLabel(root, "Save entry");
    await flush();
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("also points to support when the entry was queued offline (it is still saved)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "thinking about suicide");
    await pressLabel(root, "Save entry");
    await flush();
    expect(enqueue).toHaveBeenCalledTimes(1);
    const alerts = Alert.alert.mock.calls.map((c) => c[0]);
    expect(alerts).toContain("Saved offline");
    expect(alerts).toContain("Support is available");
  });

  it("does NOT point to support when the save failed (401 keeps the draft, no celebration dialog)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on");
    await pressLabel(root, "Save entry");
    await flush();
    const alerts = Alert.alert.mock.calls.map((c) => c[0]);
    expect(alerts).toEqual(["Session expired"]);
  });

  it("STILL points to support when a crisis-flagged entry hits a full queue (the text is on screen)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QFErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on like this");
    await pressLabel(root, "Save entry");
    await flush();
    // The queue-full alert comes first; acknowledging it opens the support
    // pointer — the failed save must not suppress it.
    const alerts = Alert.alert.mock.calls.map((c) => c[0]);
    expect(alerts).toEqual(["Offline storage full"]);
    await pressAlertButton("OK");
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Offline storage full", "Support is available"]);
    await pressAlertButton("View support resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
    // The draft was never cleared.
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("I can't go on like this");
  });

  it("queue-full on an ORDINARY entry does not open the support dialog", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QFErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "a perfectly ordinary day");
    await pressLabel(root, "Save entry");
    await flush();
    await pressAlertButton("OK");
    const alerts = Alert.alert.mock.calls.map((c) => c[0]);
    expect(alerts).toEqual(["Offline storage full"]);
  });
});

describe("EntryScreen draft-stash hygiene", () => {
  const stashVia401 = async (text: string): Promise<void> => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, text);
    await pressLabel(root, "Save entry");
    await flush();
    root.unmount();
    vault.unlock({ ...keys, masterKey: Buffer.alloc(32) });
  };

  it("a late getUserId() resolution does not clobber in-progress typing", async () => {
    await stashVia401("the stashed draft");
    // Now the remount: getUserId is SLOW, and the user starts typing before
    // it resolves.
    let resolveUserId!: (v: string | null) => void;
    vi.mocked(api.getUserId).mockImplementation(
      () => new Promise<string | null>((resolve) => (resolveUserId = resolve)),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "fresh typing already here");
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveUserId("user-1");
    });
    await flush();
    // The stash is consumed but NOT applied over non-empty text...
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("fresh typing already here");
    // ...and it is consumed (one-shot): a later remount must not resurrect it.
    expect(takeStashedDraft("user-1")).toBeNull();
  });

  it("still applies the stash when the field is empty at resolution time", async () => {
    await stashVia401("restore me");
    let resolveUserId!: (v: string | null) => void;
    vi.mocked(api.getUserId).mockImplementation(
      () => new Promise<string | null>((resolve) => (resolveUserId = resolve)),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveUserId("user-1");
    });
    await flush();
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("restore me");
  });

  it("a failed getUserId() keeps the stash for the next mount instead of dropping the draft", async () => {
    await stashVia401("do not lose me");
    vi.mocked(api.getUserId).mockRejectedValue(new Error("storage exploded"));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    // No crash, empty editor, and the stash survived the rejection.
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("");
    expect(takeStashedDraft("user-1")).toBe("do not lose me");
  });

  it("a mismatched account never consumes the stash — the owning account still restores it", async () => {
    await stashVia401("alice's draft");
    // A DIFFERENT account mounts: no restore, no consume.
    vi.mocked(api.getUserId).mockResolvedValue("user-2");
    const other = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(
      (inputByPlaceholder(other, "What's going on today?").props as { value: string }).value,
    ).toBe("");
    other.unmount();
    // The stash survived the mismatched mount: the owning account's next
    // mount restores it (a consumed stash would render an empty editor).
    vi.mocked(api.getUserId).mockResolvedValue("user-1");
    const mine = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(
      (inputByPlaceholder(mine, "What's going on today?").props as { value: string }).value,
    ).toBe("alice's draft");
  });
});

describe("EntryScreen inactivity auto-lock wiring", () => {
  it("resets the idle countdown on every keystroke", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await typeInto(root, "What's going on today?", "t");
    await typeInto(root, "What's going on today?", "to");
    await typeInto(root, "What's going on today?", "tod");
    expect(touchActivity).toHaveBeenCalledTimes(3);
  });
});
