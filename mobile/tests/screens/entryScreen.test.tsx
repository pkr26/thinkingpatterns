/**
 * EntryScreen: threshold progress copy, the save pipeline (encrypt →
 * upload, with per-failure-class fallbacks), offline queueing, and nav.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

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

// The HealthKit State of Mind mirror (2026-09-19): fire-and-forget after a
// successful save — mocked here so the wiring (when it fires, with what)
// is observable without the native seam.
const mirrorMoodCheckIn = vi.fn(async () => false);
vi.mock("../../src/healthkit", () => ({
  mirrorMoodCheckIn: (...args: unknown[]) => mirrorMoodCheckIn(...(args as [string, number, string])),
}));

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
    // Spied (real implementation preserved): the L-56 tests assert whether
    // the unmount/finally paths stashed, while restore still works.
    stashDraft: vi.fn(actual.stashDraft),
  };
});

const { api, ApiError } = await import("../../src/api/client");
const { encryptEntry } = await import("../../src/crypto/MindPatternCrypto");
const { enqueue, flushQueue, QueueFullError: QFErr, QueueAbandonedError: QAErr } = await import("../../src/offlineQueue");
const { localDateISO } = await import("../../src/moodLog");
const { recordCrisisDialogShown } = await import("../../src/crisisDialog");
const { takeStashedDraft, stashDraft } = await import("../../src/store");
const { EntryScreen } = await import("../../src/screens/EntryScreen");
const { vault } = await import("../../src/vault");
const { render, flush, textOf, pressLabel, firePress, typeInto, touchableByLabel, allText, act, inputByPlaceholder, pressAlertButton } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

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
  vi.mocked(recentMoods).mockReset();
  vi.mocked(recentMoods).mockImplementation(async () => []);
  vi.mocked(localStreak).mockReset();
  vi.mocked(localStreak).mockImplementation(async () => 0);
  mirrorMoodCheckIn.mockReset();
  mirrorMoodCheckIn.mockResolvedValue(false);
  Alert.alert.mockClear();
  nav.navigate.mockClear();
  touchActivity.mockClear();
  vault.lock();
  vault.unlock({ ...keys, masterKey: Buffer.alloc(32) });
  sessionState = { activeDays: 0, unlockDays: 30, touchActivity };
  // The crisis-dialog throttle stamp lives in AsyncStorage
  // (@mindpattern/crisis_dialog_<userId>) and localDateISO feeds its day:
  // reset both so one test's shown dialog cannot throttle the next test's.
  storage.__reset();
  vi.mocked(localDateISO).mockReturnValue("2026-09-04");
  // The draft stash is module state (in store.tsx): consume any leftover
  // so one test's stashed draft cannot leak into the next.
  takeStashedDraft("user-1");
  takeStashedDraft("user-2");
});

async function writeEntry(root: Awaited<ReturnType<typeof render>>, text: string): Promise<void> {
  await typeInto(root, "What's going on today?", text);
}

/** The check-ins live behind the "Add details (optional)" disclosure
 *  (collapsed by default) — open it before touching mood/energy/sleep/tags. */
async function openDetails(root: Awaited<ReturnType<typeof render>>): Promise<void> {
  await pressLabel(root, "Add details (optional)");
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
    // Themed container: [base, colors] pair (design-system pass).
    expect(scroll.props.style).toEqual([{ flex: 1 }, { backgroundColor: "#0f1115" }]);
    // Keyboard hygiene: drag-to-dismiss on the scroll container.
    expect(scroll.props.keyboardDismissMode).toBe("on-drag");
  });

  it("a hostile unlockDays of 0 still renders a full bar, never NaN/Infinity", async () => {
    sessionState = { activeDays: 5, unlockDays: 0, touchActivity };
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    const { View } = await import("react-native");
    const fill = root.root
      .findAllByType(View)
      .map((n) => n.props.style)
      .flat()
      .find((s: unknown) => typeof s === "object" && s !== null && "width" in (s as object));
    expect(fill).toMatchObject({ width: "100%" });
    expect(textOf(root)).toContain("Patterns unlocked");
  });

  it("renders a progress bar proportional to active days", async () => {    sessionState = { activeDays: 12, unlockDays: 30 };
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

  describe("threshold moment (one-time patterns-ready card, 2026-09-19)", () => {
    it("shows the card once on the crossing day — then never again for this account", async () => {
      sessionState = { activeDays: 30, unlockDays: 30, touchActivity };
      const first = await render(<EntryScreen navigation={nav} />);
      await flush();
      expect(textOf(first)).toContain("your patterns are ready for a first look");
      expect(textOf(first)).toContain("30 days of writing");
      await pressLabel(first, "See your patterns");
      expect(nav.navigate).toHaveBeenCalledWith("Insights");
      await act(async () => first.unmount());

      // A fresh mount, same account: the recorded stamp suppresses it forever.
      const second = await render(<EntryScreen navigation={nav} />);
      await flush();
      expect(textOf(second)).not.toContain("your patterns are ready");
      await act(async () => second.unmount());
    });

    it("below the threshold the card never appears", async () => {
      sessionState = { activeDays: 29, unlockDays: 30, touchActivity };
      const root = await render(<EntryScreen navigation={nav} />);
      await flush();
      expect(textOf(root)).not.toContain("your patterns are ready");
      await act(async () => root.unmount());
    });

    it("'Not now' hides the card for the rest of the session", async () => {
      sessionState = { activeDays: 30, unlockDays: 30, touchActivity };
      const root = await render(<EntryScreen navigation={nav} />);
      await flush();
      expect(textOf(root)).toContain("your patterns are ready");
      await pressLabel(root, "Not now");
      expect(textOf(root)).not.toContain("your patterns are ready");
      expect(nav.navigate).not.toHaveBeenCalled();
      await act(async () => root.unmount());
    });

    it("a hostile unlockDays of 0 never fires the moment (there was no wait)", async () => {
      sessionState = { activeDays: 5, unlockDays: 0, touchActivity };
      const root = await render(<EntryScreen navigation={nav} />);
      await flush();
      expect(textOf(root)).not.toContain("your patterns are ready");
      await act(async () => root.unmount());
    });
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
    // Design-system pass: styles now compose theme tokens (dark palette),
    // and the audit's failing colors moved: button fill #4f7cff → #3b5bdb
    // (white label 3.71:1 → 5.67:1), input minHeight 220 → autogrow 140.
    const { expectStyle } = await import("../helpers/rtr");
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expectStyle(root, { flex: 1 }); // container base
    expectStyle(root, { backgroundColor: "#0f1115" }); // themed container
    expectStyle(root, { gap: 6 }); // progressRow
    expectStyle(root, { color: "#8a91a3", fontSize: 13 }); // progressLabel
    expectStyle(root, { height: 6, overflow: "hidden" }); // progressTrack base
    expectStyle(root, { backgroundColor: "#1a1e26", borderRadius: 3 }); // progressTrack themed
    expectStyle(root, { height: 6 }); // progressFill base
    expectStyle(root, { backgroundColor: "#4f7cff", borderRadius: 3, width: "0%" }); // progressFill themed
    expectStyle(root, { minHeight: 140, textAlignVertical: "top" }); // input base (autogrow)
    expectStyle(root, {
      backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 12, padding: 16, fontSize: 16,
    }); // input themed
    expectStyle(root, { borderRadius: 10, padding: 16, alignItems: "center", justifyContent: "center" }); // PrimaryButton base
    expectStyle(root, { backgroundColor: "#3b5bdb", minHeight: 44 }); // PrimaryButton themed (AA fix)
    expectStyle(root, { fontWeight: "600" }); // buttonText base
    expectStyle(root, { color: "#ffffff", fontSize: 16 }); // buttonText themed
    // 2026-09-17: navigation is the PERSISTENT bottom bar (MainShell), no
    // longer an in-scroll NavRow. Its styles are pinned in
    // components.bottomNav.test.tsx; this screen keeps the chips row.
    expectStyle(root, { backgroundColor: "#141821", borderRadius: 10 }); // prompt chip themed
    expectStyle(root, { paddingHorizontal: 12, paddingVertical: 8 }); // prompt chip base
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
      { energy: null, sleep: null, tags: [] },
      1,     // M-2 (2026-09-20): first content generation, v2 version-bound AAD
    );
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    expect(api.createEntry).toHaveBeenCalledWith(
      expect.stringMatching(/^e-\d{4}-\d{2}-\d{2}-/),
      expect.any(String),
      expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
      1,
    );
    expect(Alert.alert).not.toHaveBeenCalled();
    // Editor cleared and disabled again; success is a quiet inline line,
    // not a modal (the save-feedback inversion fix).
    expect(touchableByLabel(root, "Save entry").props.disabled).toBe(true);
    expect(textOf(root)).toContain("Saved ✓");
  });

  it("records local sentiment into the device-only mood log", async () => {
    const cases: Array<[string, number]> = [
      ["good great happy", 1],
      ["bad sad anxious stressed", -1],
      ["good then bad news", 0],
      // The graded engine (src/brain/sentiment.ts, 2026-09-19) gives this
      // neutral text a small negative — pinned in tests/mood.test.ts.
      ["nothing emotional here", -0.111],
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
        undefined,
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
    expect(Alert.alert).toHaveBeenCalledWith(
      "Session expired",
      expect.stringContaining("unlock again"),
      // The alert's OK can chain the throttled support dialog for
      // crisis-flagged text (2026-09-20 audit, M-15).
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
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
    // Calm copy, no raw server detail in the dialog (audit error-copy fix).
    expect(Alert.alert).toHaveBeenCalledWith(
      "Entry not accepted",
      expect.stringContaining("still on screen"),
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
    expect(enqueue).not.toHaveBeenCalled();
  });

  it("queues the same encrypted entry when offline — confirmed inline, no modal", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();

    expect(enqueue).toHaveBeenCalledTimes(1);
    const queued = vi.mocked(enqueue).mock.calls[0][0];
    expect(queued).toMatchObject({ userId: "user-1", blobB64: "QkxPQg==", entryDate: expect.any(String) });
    // The interruptive "Saved offline" modal became an inline status line.
    expect(Alert.alert).not.toHaveBeenCalled();
    expect(textOf(root)).toContain("Saved — will sync when online");
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
    // The "Not saved" alert now carries an OK button that chains the
    // (throttled) support dialog for crisis-flagged text — this entry is
    // ordinary, so the chain stays quiet.
    expect(Alert.alert).toHaveBeenCalledWith(
      "Not saved",
      expect.stringContaining("still on screen"),
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
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
    expect(Alert.alert).toHaveBeenCalledWith(
      "Could not save",
      "disk full",
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
  });

  it("reports a locked vault instead of crashing", async () => {
    vault.lock();
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "secret");
    await pressLabel(root, "Save entry");
    await flush();
    // A lock landing mid-save (2026-09-20 audit, C-1): the keys are
    // re-acquired AFTER the user-id await, so the save dies loudly here
    // instead of encrypting under the zeroized key.
    expect(Alert.alert).toHaveBeenCalledWith(
      "Could not save",
      "vault is locked",
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
  });

  it("falls back to calm copy for non-Error failures", async () => {
    vi.mocked(encryptEntry).mockImplementation(() => {
      throw "crypto exploded"; // eslint-disable-line no-throw-literal
    });
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "secret");
    await pressLabel(root, "Save entry");
    await flush();
    // Was "unknown error"; the error-copy pass made the fallback a sentence.
    expect(Alert.alert).toHaveBeenCalledWith(
      "Could not save",
      "Something went wrong — try again.",
      expect.arrayContaining([expect.objectContaining({ text: "OK" })]),
    );
  });

  it("queues on non-ApiError upload failures (plain network error)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new TypeError("fetch failed"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "offline thought");
    await pressLabel(root, "Save entry");
    await flush();
    expect(enqueue).toHaveBeenCalledTimes(1);
    // Inline confirmation, not a modal.
    expect(textOf(root)).toContain("Saved — will sync when online");
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("a second press in the same frame cannot double-upload (synchronous guard)", async () => {
    let resolveCreate: ((v: unknown) => void) | undefined;
    vi.mocked(api.createEntry).mockImplementation(
      () => new Promise((resolve) => (resolveCreate = resolve)),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "double tap me");
    const { touchableByLabel, act } = await import("../helpers/rtr");
    const button = touchableByLabel(root, "Save entry");
    await act(async () => {
      // Two onPress invocations before the first await settles: the
      // synchronous in-flight ref must swallow the second.
      void (button.props as { onPress: () => unknown }).onPress();
      void (button.props as { onPress: () => unknown }).onPress();
    });
    await act(async () => {
      resolveCreate?.({});
    });
    await flush();
    expect(api.createEntry).toHaveBeenCalledTimes(1);
  });

  it("the editor stays editable while idle and locks while a save is in flight", async () => {
    let resolveCreate: ((v: unknown) => void) | undefined;
    vi.mocked(api.createEntry).mockImplementation(
      () => new Promise((resolve) => (resolveCreate = resolve)),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    expect(inputByPlaceholder(root, "What's going on today?").props.editable).toBe(true);
    await writeEntry(root, "slow save");
    const { firePress, act } = await import("../helpers/rtr");
    await firePress(root, "Save entry");
    // Mid-save the field is non-editable so the clear on success cannot
    // wipe text typed over an in-flight request.
    expect(inputByPlaceholder(root, "What's going on today?").props.editable).toBe(false);
    await act(async () => {
      resolveCreate?.({});
    });
    await flush();
    expect(inputByPlaceholder(root, "What's going on today?").props.editable).toBe(true);
  });

  it("shows a soft character count only near the 100k cap", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "short");
    expect(textOf(root)).not.toContain("/ 100,000");
    await writeEntry(root, "x".repeat(95_000));
    expect(textOf(root)).toContain("95,000 / 100,000");
  });

  it("offers a keyboard-dismiss affordance once there is text", async () => {
    const { Keyboard } = await import("react-native");
    vi.mocked(Keyboard.dismiss).mockClear();
    const root = await render(<EntryScreen navigation={nav} />);
    expect(textOf(root)).not.toContain("Hide keyboard");
    await writeEntry(root, "anything");
    await pressLabel(root, "Hide keyboard");
    expect(Keyboard.dismiss).toHaveBeenCalledTimes(1);
  });

  it("marks the journal input private from keyboard caches", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    const input = inputByPlaceholder(root, "What's going on today?");
    expect(input.props.autoCorrect).toBe(false);
    expect(input.props.spellCheck).toBe(false);
    expect(input.props.autoCapitalize).toBe("sentences");
    expect(input.props.textContentType).toBe("none");
    expect(input.props.accessibilityLabel).toBe("Journal entry");
  });

  it("the progress bar is a real progressbar to assistive tech", async () => {
    sessionState = { activeDays: 12, unlockDays: 30, touchActivity };
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    const bar = root.root.findAll((n) => n.props.accessibilityRole === "progressbar")[0];
    expect(bar.props.accessibilityValue).toEqual({ min: 0, max: 30, now: 12 });
    expect(bar.props.accessibilityLabel).toBe("Progress toward your patterns: 12 of 30 days");
  });
});

describe("EntryScreen navigation", () => {
  it("offers History, Patterns, Question, Settings and crisis-help shortcuts", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(allText(root).join(" ")).toContain("History");
    await pressLabel(root, "History");
    await pressLabel(root, "Patterns");
    await pressLabel(root, "Question");
    await pressLabel(root, "Settings");
    await pressLabel(root, "Get help");
    expect(nav.navigate.mock.calls).toEqual([["History"], ["Insights"], ["Question"], ["Settings"], ["Crisis"]]);
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
    // The dialog is throttled to once per calendar day per account — the
    // second half of this test runs on the NEXT day so it re-arms.
    vi.mocked(localDateISO).mockReturnValue("2026-09-05");
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
    expect(alerts).toContain("Support is available");
    // The offline save itself is confirmed inline, not with a modal.
    expect(alerts).not.toContain("Saved offline");
    expect(textOf(root)).toContain("Saved — will sync when online");
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
    await flush(); // the throttled support dialog fires after the storage stamp resolves
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

describe("EntryScreen crisis-dialog throttle (once per calendar day per account)", () => {
  it("a second crisis-flagged save the same day does NOT re-show the dialog", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Support is available"]);

    // Same account, same calendar day: the save still succeeds and
    // confirms inline — but the dialog does not fire again (fatigue
    // trains dismissal; src/crisisDialog.ts).
    Alert.alert.mockClear();
    await writeEntry(root, "no reason to live anymore");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("the dialog fires again on the next calendar day", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Support is available"]);

    Alert.alert.mockClear();
    vi.mocked(localDateISO).mockReturnValue("2026-09-05"); // a new LOCAL day re-arms it
    await writeEntry(root, "I can't go on");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Support is available"]);
  });

  it("the queue-abandoned path chains the support dialog (it dropped it before)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QAErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Not saved"]);
    // The entry went nowhere, but the crisis is still on screen — the
    // support pointer chains off the loud alert's OK.
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Not saved", "Support is available"]);
    await pressAlertButton("View support resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("the queue-abandoned chain respects the day's throttle stamp", async () => {
    // The dialog already ran today: the abandoned save must not re-show it.
    await recordCrisisDialogShown("user-1", "2026-09-04");
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QAErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on");
    await pressLabel(root, "Save entry");
    await flush();
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Not saved"]);
  });

  it("the queue-abandoned chain stays quiet for an ordinary entry", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new QAErr());
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "a perfectly ordinary day");
    await pressLabel(root, "Save entry");
    await flush();
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Not saved"]);
  });

  // 2026-09-20 audit M-15: the 401, 422 and unexpected-error save failures
  // previously dropped the support pointer entirely — a crisis-flagged entry
  // that went NOWHERE was the one case with no dialog. All three now chain
  // the same throttled support dialog via their OK button.
  it("chains the support dialog when a crisis-flagged entry is rejected (422)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "entry_date in the future"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I can't go on like this");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Entry not accepted"]);
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Entry not accepted", "Support is available"]);
    await pressAlertButton("View support resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("chains the support dialog when a crisis-flagged save dies on 401", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "I want to disappear forever");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Session expired"]);
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Session expired", "Support is available"]);
  });

  it("chains the support dialog when a crisis-flagged save fails unexpectedly", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(0, "server unreachable"));
    vi.mocked(enqueue).mockRejectedValue(new Error("disk full"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "everyone would be better off without me");
    await pressLabel(root, "Save entry");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Could not save"]);
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Could not save", "Support is available"]);
  });

  // 2026-09-20 audit L-56: the unmount cleanup used to stash the draft
  // even while a save was in flight — the completed save ALSO came back as
  // a restored draft, and re-saving it minted a fresh clientEntryId the
  // server's dedupe could never catch. The in-flight save owns the text:
  // success leaves no stash; failure stashes in the save flow's finally.
  it("unmounting mid-save leaves NO draft once the save lands (no duplicate on re-save)", async () => {
    // The suite never clears this spy (other tests legitimately stash) —
    // start from a clean call log.
    vi.mocked(stashDraft).mockClear();
    // A TIMER-deferred upload keeps the save genuinely in flight across
    // the unmount (a bare pending promise gets drained by act's microtask
    // flush before the unmount can observe the in-flight state).
    vi.mocked(api.createEntry).mockImplementation(
      () => new Promise((res) => { setTimeout(() => res({}), 60); }) as Promise<never>,
    );
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "saved while backgrounding");
    await firePress(root, "Save entry");
    root.unmount(); // the save is still in flight
    expect(stashDraft).not.toHaveBeenCalled(); // the cleanup must not stash an in-flight save
    await new Promise((r) => { setTimeout(r, 140); }); // the upload lands after the unmount
    await flush();
    expect(stashDraft).not.toHaveBeenCalled(); // and the landed save must not stash either
    // Re-mount: nothing restores — the entry is already saved.
    const again = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect((inputByPlaceholder(again, "What's going on today?").props as { value: string }).value).toBe("");
  }, 10_000);

  it("a save that dies AFTER unmount still honors the draft guarantee", async () => {
    vi.mocked(stashDraft).mockClear();
    vi.mocked(api.createEntry).mockImplementation(
      () => new Promise((_res, rej) => { setTimeout(() => rej(new ApiError(0, "server unreachable")), 60); }) as Promise<never>,
    );
    vi.mocked(enqueue).mockRejectedValue(new QFErr()); // and the queue cannot take it either
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "words that must survive");
    await firePress(root, "Save entry");
    root.unmount(); // the save is still in flight
    await new Promise((r) => { setTimeout(r, 140); }); // the upload dies after the unmount
    await flush();
    expect(stashDraft).toHaveBeenCalledWith("user-1", "words that must survive");
    const again = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect((inputByPlaceholder(again, "What's going on today?").props as { value: string }).value).toBe("words that must survive");
  }, 10_000);

  it("an ORDINARY 422 save stays quiet after OK (no false support dialog)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "entry_date in the future"));
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "a perfectly ordinary day");
    await pressLabel(root, "Save entry");
    await flush();
    await pressAlertButton("OK");
    await flush();
    expect(Alert.alert.mock.calls.map((c) => c[0])).toEqual(["Entry not accepted"]);
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

describe("EntryScreen draft survival on ANY unmount (backgrounding fix)", () => {
  // NOTE: react-test-renderer defers effect cleanups until the next act();
  // the unmounts below are act-wrapped so the stash happens deterministically
  // (on device, the native renderer commits the cleanup at unmount).
  it("stashes a non-empty draft on unmount and restores it with a chip on the next mount", async () => {
    const first = await render(<EntryScreen navigation={nav} />);
    await flush(); // getUserId resolved — the screen knows its account
    await writeEntry(first, "half-written, phone rang");
    const { act } = await import("../helpers/rtr");
    await act(async () => first.unmount()); // background-lock unmount: no save, no alert

    const second = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(
      (inputByPlaceholder(second, "What's going on today?").props as { value: string }).value,
    ).toBe("half-written, phone rang");
    expect(textOf(second)).toContain("Draft restored");
  });

  it("stashes nothing when the editor is empty or whitespace", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await writeEntry(root, "   ");
    const { act } = await import("../helpers/rtr");
    await act(async () => root.unmount());
    expect(takeStashedDraft("user-1")).toBeNull();
  });

  it("stashes nothing after a successful save (the editor was cleared)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "done and saved");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    const { act } = await import("../helpers/rtr");
    await act(async () => root.unmount());
    expect(takeStashedDraft("user-1")).toBeNull();
  });

  it("typing after a restore dismisses the chip", async () => {
    const first = await render(<EntryScreen navigation={nav} />);
    await flush();
    await writeEntry(first, "bring me back");
    const { act } = await import("../helpers/rtr");
    await act(async () => first.unmount());

    const second = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(second)).toContain("Draft restored");
    await writeEntry(second, "bring me back, continued");
    expect(textOf(second)).not.toContain("Draft restored");
  });

  it("a failed getUserId() on mount never enables a blind stash (account-binding)", async () => {
    vi.mocked(api.getUserId).mockRejectedValue(new Error("storage exploded"));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await writeEntry(root, "orphaned typing");
    const { act } = await import("../helpers/rtr");
    await act(async () => root.unmount());
    // No known owner → nothing stashed under a guess.
    expect(takeStashedDraft("user-1")).toBeNull();
  });
});

describe("EntryScreen status line and platform plumbing", () => {
  it("a second save replaces the live status timer instead of stacking", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await writeEntry(root, "first");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    // Second save while the first status is still on screen: the timer is
    // cleared and re-armed, not stacked (branch: statusTimer was live).
    await writeEntry(root, "second");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    expect(api.createEntry).toHaveBeenCalledTimes(2);
  });

  it("an unmount before getUserId resolves neither restores nor stashes", async () => {
    let resolveUserId!: (v: string | null) => void;
    vi.mocked(api.getUserId).mockImplementation(
      () => new Promise<string | null>((resolve) => (resolveUserId = resolve)),
    );
    const root = await render(<EntryScreen navigation={nav} />);
    const { act } = await import("../helpers/rtr");
    await act(async () => root.unmount()); // cleanup runs here (see note above)
    await act(async () => {
      resolveUserId("user-1");
    });
    // The cancelled flag swallowed the late resolution: no flush, no crash.
    expect(flushQueue).not.toHaveBeenCalled();
  });

  it("uses the padding keyboard behavior on iOS and none on Android", async () => {
    const reactNative = await import("react-native");
    const root = await render(<EntryScreen navigation={nav} />);
    expect(root.root.findByType(reactNative.KeyboardAvoidingView).props.behavior).toBe("padding");
    const original = reactNative.Platform.OS;
    (reactNative.Platform as { OS: string }).OS = "android";
    try {
      const androidRoot = await render(<EntryScreen navigation={nav} />);
      expect(androidRoot.root.findByType(reactNative.KeyboardAvoidingView).props.behavior).toBeUndefined();
    } finally {
      (reactNative.Platform as { OS: string }).OS = original;
    }
  });
});

describe("EntryScreen inactivity auto-lock wiring", () => {  it("resets the idle countdown on every keystroke", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await typeInto(root, "What's going on today?", "t");
    await typeInto(root, "What's going on today?", "to");
    await typeInto(root, "What's going on today?", "tod");
    expect(touchActivity).toHaveBeenCalledTimes(3);
  });
});

describe("EntryScreen 'Already wrote today' (device-local hint)", () => {
  it("shows the chip when today's date is in the mood log", async () => {
    vi.mocked(recentMoods).mockResolvedValue([
      { date: "2026-09-03", value: 0.4 },
      { date: "2026-09-04", value: -0.2 }, // localDateISO is pinned to 2026-09-04
    ]);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Already wrote today");
  });

  it("stays hidden when today is not in the log (absence is never a verdict)", async () => {
    vi.mocked(recentMoods).mockResolvedValue([{ date: "2026-09-01", value: 0.4 }]);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Already wrote today");
  });

  it("a failing mood-log read never breaks the screen", async () => {
    vi.mocked(recentMoods).mockRejectedValue(new Error("decrypt failed"));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Already wrote today");
    expect(textOf(root)).toContain("Save entry");
  });

  it("a successful save flips the chip on immediately", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Already wrote today");
    await writeEntry(root, "writing right now");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Already wrote today");
  });

  it("a failed save does NOT claim today was written", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "validation_error"));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await writeEntry(root, "not going anywhere");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).not.toContain("Already wrote today");
  });
});

describe("EntryScreen check-in disclosure (Add details)", () => {
  it("is collapsed by default: no check-in rows, the toggle present, Save reachable", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Add details (optional)");
    expect(textOf(root)).not.toContain("How does today feel?");
    expect(textOf(root)).not.toContain("And your energy?");
    expect(textOf(root)).not.toContain("How did you sleep?");
    expect(textOf(root)).not.toContain("What shaped today?");
    expect(root.root.findAll((n) => n.props.accessibilityRole === "radio")).toHaveLength(0);
    expect(root.root.findAll((n) => n.props.accessibilityLabel === "Day tags")).toHaveLength(0);
    // Nothing is set, so there is no summary line either.
    expect(textOf(root)).not.toContain("Details added:");
    // Save does not require expanding anything.
    expect(touchableByLabel(root, "Save entry")).toBeDefined();
  });

  it("expands the four sections and the toggle flips to 'Hide details'", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    expect(textOf(root)).toContain("How does today feel?");
    expect(textOf(root)).toContain("And your energy?");
    expect(textOf(root)).toContain("How did you sleep?");
    expect(textOf(root)).toContain("What shaped today?");
    expect(root.root.findAll((n) => n.props.accessibilityRole === "radio")).toHaveLength(13);
    const toggle = root.root.findAll((n) => n.props.accessibilityLabel === "Hide details")[0];
    expect(toggle.props.accessibilityState).toEqual({ expanded: true });
    await pressLabel(root, "Hide details");
    expect(textOf(root)).not.toContain("How does today feel?");
    expect(root.root.findAll((n) => n.props.accessibilityRole === "radio")).toHaveLength(0);
    expect(textOf(root)).toContain("Add details (optional)");
  });

  it("the collapsed summary names exactly the set channels, in display order", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Good"); // mood
    await pressLabel(root, "Rested"); // sleep
    await pressLabel(root, "work"); // tags
    await pressLabel(root, "Hide details");
    expect(textOf(root)).toContain("Details added: mood, sleep, tags");
    expect(textOf(root)).not.toContain("Details added: mood, energy");
    // The summary control is a real button with an honest label.
    const summary = root.root.findAll((n) =>
      n.props.accessibilityLabel === "Details added: mood, sleep, tags. Tap to show details.",
    )[0];
    expect(summary.props.accessibilityRole).toBe("button");
  });

  it("energy alone reads as exactly 'Details added: energy'", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Steady");
    await pressLabel(root, "Hide details");
    expect(textOf(root)).toContain("Details added: energy");
  });

  it("tapping the summary line expands the details", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Low");
    await pressLabel(root, "Hide details");
    expect(textOf(root)).toContain("Details added: mood");
    await pressLabel(root, "Details added: mood");
    expect(textOf(root)).toContain("How does today feel?");
    // The pick survived the collapse/expand round-trip.
    const low = root.root
      .findAll((n) => n.props.accessibilityLabel === "Mood: Low")
      .find((n) => n.props.accessibilityRole === "radio");
    expect(low?.props.accessibilityState).toEqual({ selected: true });
  });

  it("a pick made and hidden behind the fold still rides in the save", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Heavy");
    await pressLabel(root, "Hide details");
    expect(textOf(root)).toContain("Details added: mood"); // nothing silently set
    await writeEntry(root, "a heavy day, briefly noted");
    await pressLabel(root, "Save entry");
    await flush();
    expect(vi.mocked(encryptEntry).mock.calls[0]?.[5]).toBe(-1);
    expect(api.createEntry).toHaveBeenCalledTimes(1);
    // The save clears the check-in — and with it the summary line.
    expect(textOf(root)).not.toContain("Details added:");
  });
});

describe("EntryScreen mood check-in (explicit beats the text guess)", () => {
  it("renders all five options as a radio group with labels and selected state", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    const radios = root.root.findAll((n) => n.props.accessibilityRole === "radio");
    expect(radios.map((r) => r.props.accessibilityLabel)).toEqual([
      "Mood: Heavy",
      "Mood: Low",
      "Mood: Okay",
      "Mood: Good",
      "Mood: Light",
      "Energy: Drained",
      "Energy: Steady",
      "Energy: Energized",
      "Sleep: Rough",
      "Sleep: Poor",
      "Sleep: Okay",
      "Sleep: Good",
      "Sleep: Rested",
    ]);
    expect(radios.every((r) => r.props.accessibilityState?.selected === false)).toBe(true);
    // The group itself is labeled, and picking one flips only its state.
    expect(root.root.findAll((n) => n.props.accessibilityLabel === "Mood check-in")).toHaveLength(1);
    await pressLabel(root, "Good");
    const after = root.root.findAll((n) => n.props.accessibilityRole === "radio");
    expect(after.find((r) => r.props.accessibilityLabel === "Mood: Good")?.props.accessibilityState).toEqual({
      selected: true,
    });
    expect(after.find((r) => r.props.accessibilityLabel === "Mood: Heavy")?.props.accessibilityState).toEqual({
      selected: false,
    });
    // Tapping is real interaction: the idle countdown restarts.
    expect(touchActivity).toHaveBeenCalled();
  });

  it("an explicit pick wins: it rides in the payload AND lands in the mood log", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await writeEntry(root, "a long heavy day");
    await pressLabel(root, "Heavy");
    await pressLabel(root, "Save entry");
    await flush();
    // The encrypted payload's sentiment field carries the explicit pick…
    expect(vi.mocked(encryptEntry).mock.calls[0]?.[5]).toBe(-1);
    // …and the device-local log records it instead of the text estimate.
    expect(recordMood).toHaveBeenCalledWith(
      keys.dataKey,
      "user-1",
      expect.stringMatching(/^\d{4}-\d{2}-\d{2}$/),
      -1,
        undefined,
);
    expect(textOf(root)).toContain("Saved ✓");
  });

  it("no pick: the payload stays null and the log takes the text estimate (today's behavior)", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await writeEntry(root, "good great happy");
    await pressLabel(root, "Save entry");
    await flush();
    expect(vi.mocked(encryptEntry).mock.calls[0]?.[5]).toBeNull();
    expect(recordMood).toHaveBeenCalledWith(keys.dataKey, "user-1", expect.any(String), 1, undefined);
  });

  it("tapping the pick again clears it — saving falls back to the estimate", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Light");
    await pressLabel(root, "Light"); // second tap undoes the pick
    expect(
      root.root.findAll((n) => n.props.accessibilityRole === "radio")
        .every((r) => r.props.accessibilityState?.selected === false),
    ).toBe(true);
    await writeEntry(root, "bad sad anxious");
    await pressLabel(root, "Save entry");
    await flush();
    expect(vi.mocked(encryptEntry).mock.calls[0]?.[5]).toBeNull();
    expect(recordMood).toHaveBeenCalledWith(keys.dataKey, "user-1", expect.any(String), -1, undefined);
  });

  it("a successful save clears the pick — the check-in is per entry", async () => {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Low");
    await writeEntry(root, "a hard morning");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    expect(
      root.root.findAll((n) => n.props.accessibilityRole === "radio")
        .every((r) => r.props.accessibilityState?.selected === false),
    ).toBe(true);
  });

  it("a FAILED save keeps the pick (the entry and its mood are still on screen)", async () => {
    vi.mocked(api.createEntry).mockRejectedValue(new ApiError(422, "validation_error"));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Low");
    await writeEntry(root, "still here");
    await pressLabel(root, "Save entry");
    await flush();
    const low = root.root
      .findAll((n) => n.props.accessibilityRole === "radio")
      .find((r) => r.props.accessibilityLabel === "Mood: Low");
    expect(low?.props.accessibilityState).toEqual({ selected: true });
  });
});

describe("EntryScreen HealthKit mirror (fire-and-forget, after the save)", () => {
  const PREF = "@mindpattern/mirror_mood_to_health_user-1";

  /** Render, pick an explicit mood and save — the mirror's firing conditions. */
  async function pickAndSave(mood: string, text: string): Promise<void> {
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, mood);
    await writeEntry(root, text);
    await pressLabel(root, "Save entry");
    await flush();
  }

  it("an explicit pick with the pref ON mirrors to Health AFTER the save lands", async () => {
    await storage.setItem(PREF, JSON.stringify({ enabled: true }));
    await pickAndSave("Light", "a light day");
    expect(mirrorMoodCheckIn).toHaveBeenCalledTimes(1);
    expect(mirrorMoodCheckIn).toHaveBeenCalledWith("user-1", 1, "2026-09-04");
    // The mirror never disturbs the save itself.
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("the pref gate lives in the seam — the screen delegates EVERY explicit pick", async () => {
    // The wiring hands the pick to mirrorMoodCheckIn unconditionally; the
    // mirrorMoodToHealth pref (default OFF) is checked inside the seam
    // (pinned in tests/healthkit.test.ts). Anything else would fork the
    // decision across two layers.
    await pickAndSave("Heavy", "a heavy day");
    expect(mirrorMoodCheckIn).toHaveBeenCalledTimes(1);
    expect(mirrorMoodCheckIn).toHaveBeenCalledWith("user-1", -1, "2026-09-04");
  });

  it("a vault that locked mid-save skips the mirror silently (belt-and-braces guard)", async () => {
    // E.g. the unauthorized hook racing this save: the save itself still
    // completes, but a locked vault must never hand a mood to Health.
    vi.mocked(api.createEntry).mockImplementation(async () => {
      vault.lock();
      return {};
    });
    await pickAndSave("Light", "saved while the lock raced in");
    expect(mirrorMoodCheckIn).not.toHaveBeenCalled();
  });

  it("no explicit pick: the text-derived estimate is never mirrored to Health", async () => {
    await storage.setItem(PREF, JSON.stringify({ enabled: true }));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await writeEntry(root, "good great happy"); // estimate 1, but not a pick
    await pressLabel(root, "Save entry");
    await flush();
    expect(mirrorMoodCheckIn).not.toHaveBeenCalled();
  });

  it("a FAILED save never mirrors (queue full: the entry went nowhere)", async () => {
    await storage.setItem(PREF, JSON.stringify({ enabled: true }));
    vi.mocked(api.createEntry).mockRejectedValue(new Error("offline"));
    vi.mocked(enqueue).mockImplementation(async () => {
      throw new QFErr();
    });
    await pickAndSave("Light", "offline with a full queue");
    expect(mirrorMoodCheckIn).not.toHaveBeenCalled();
  });

  it("a mirror rejection is swallowed: the save still reads as saved, no alert", async () => {
    await storage.setItem(PREF, JSON.stringify({ enabled: true }));
    mirrorMoodCheckIn.mockRejectedValue(new Error("seam exploded"));
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    await openDetails(root);
    await pressLabel(root, "Okay");
    await writeEntry(root, "an ordinary day");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Saved ✓");
    expect(Alert.alert).not.toHaveBeenCalled();
  });
});

describe("EntryScreen writing streak (device-local, hidden at zero)", () => {
  it("shows the current streak next to the threshold progress", async () => {
    vi.mocked(localStreak).mockResolvedValue(4);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Writing streak: 4 days");
  });

  it("singular reads right: 1 day", async () => {
    vi.mocked(localStreak).mockResolvedValue(1);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Writing streak: 1 day");
    expect(textOf(root)).not.toContain("1 days");
  });

  it("stays hidden at 0 (no guilt) and when the read fails", async () => {
    vi.mocked(localStreak).mockResolvedValue(0);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Writing streak");

    vi.mocked(localStreak).mockRejectedValue(new Error("decrypt failed"));
    const second = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(second)).not.toContain("Writing streak");
    expect(textOf(second)).toContain("Save entry");
  });

  it("refreshes after a successful save", async () => {
    vi.mocked(localStreak).mockResolvedValueOnce(2).mockResolvedValue(3);
    const root = await render(<EntryScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("Writing streak: 2 days");
    await writeEntry(root, "today's entry");
    await pressLabel(root, "Save entry");
    await flush();
    expect(textOf(root)).toContain("Writing streak: 3 days");
  });
});

describe("EntryScreen focus-time draft restore (the 'Write about this' bridge)", () => {
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

  it("a draft stashed AFTER mount restores on focus — the bridge works while the editor stays mounted", async () => {
    const { focusNav, fireFocus } = navWithFocus();
    const root = await render(<EntryScreen navigation={focusNav} />);
    await flush(); // mount restore ran with nothing stashed
    // The Question screen stashes its text and navigates here.
    stashDraft("user-1", "What took up most space in your mind today?");
    const { act } = await import("../helpers/rtr");
    await act(async () => fireFocus());
    await flush();
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("What took up most space in your mind today?");
    expect(textOf(root)).toContain("Draft restored");
    // Cleanup unsubscribes the focus listener without complaint.
    await act(async () => root.unmount());
  });

  it("a focus restore APPENDS the bridged question below in-progress typing (never drops it)", async () => {
    const { focusNav, fireFocus } = navWithFocus();
    const root = await render(<EntryScreen navigation={focusNav} />);
    await flush();
    await writeEntry(root, "my own words already here");
    stashDraft("user-1", "a stashed question");
    const { act } = await import("../helpers/rtr");
    await act(async () => fireFocus());
    await flush();
    // The bridge used to consume the stash and silently DROP the question
    // over non-empty text; now it appends below a blank line (one-shot).
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("my own words already here\n\na stashed question");
    expect(textOf(root)).toContain("Draft restored");
    // …and the stash was consumed, not left to surprise a later mount.
    expect(takeStashedDraft("user-1")).toBeNull();
    await act(async () => root.unmount());
  });

  it("an editor holding only whitespace counts as empty for the bridge (set, not appended)", async () => {
    const { focusNav, fireFocus } = navWithFocus();
    const root = await render(<EntryScreen navigation={focusNav} />);
    await flush();
    await writeEntry(root, "  \n  ");
    stashDraft("user-1", "a stashed question");
    const { act } = await import("../helpers/rtr");
    await act(async () => fireFocus());
    await flush();
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("a stashed question");
    await act(async () => root.unmount());
  });

  it("focus with nothing stashed and no resolved account is a quiet no-op", async () => {
    const { focusNav, fireFocus } = navWithFocus();
    vi.mocked(api.getUserId).mockResolvedValue(null);
    const root = await render(<EntryScreen navigation={focusNav} />);
    await flush();
    const { act } = await import("../helpers/rtr");
    await act(async () => fireFocus());
    await flush();
    expect(
      (inputByPlaceholder(root, "What's going on today?").props as { value: string }).value,
    ).toBe("");
    await act(async () => root.unmount());
  });
});
