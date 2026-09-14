/**
 * crisisDialog.ts: the once-per-calendar-day throttle for the crisis
 * support dialog. Pins the per-account ISO date stamp, the day rollover,
 * the account isolation, and — the safety property — that a storage
 * failure can never PERMANENTLY suppress the dialog (fail toward showing).
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  crisisDialogShownOn,
  recordCrisisDialogShown,
  clearCrisisDialogStamp,
} = await import("../src/crisisDialog");
const storage = (await import("./helpers/storageMock")).default;

const STAMP_KEY = "@mindpattern/crisis_dialog_user-1";

beforeEach(() => {
  storage.__reset();
});

describe("crisisDialog throttle", () => {
  it("is not shown before any record, and the record lands as an ISO date stamp", async () => {
    expect(await crisisDialogShownOn("user-1", "2026-09-14")).toBe(false);
    await recordCrisisDialogShown("user-1", "2026-09-14");
    expect(await storage.getItem(STAMP_KEY)).toBe("2026-09-14");
    expect(await crisisDialogShownOn("user-1", "2026-09-14")).toBe(true);
  });

  it("a new calendar day re-arms the dialog", async () => {
    await recordCrisisDialogShown("user-1", "2026-09-14");
    expect(await crisisDialogShownOn("user-1", "2026-09-15")).toBe(false);
    // …and a re-show restamps the day.
    await recordCrisisDialogShown("user-1", "2026-09-15");
    expect(await storage.getItem(STAMP_KEY)).toBe("2026-09-15");
  });

  it("throttles per account — a second account on the same device is unaffected", async () => {
    await recordCrisisDialogShown("user-1", "2026-09-14");
    expect(await crisisDialogShownOn("user-2", "2026-09-14")).toBe(false);
  });

  it("a failed WRITE still throttles within the session (memory mirror)", async () => {
    const original = storage.setItem;
    storage.setItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      await recordCrisisDialogShown("user-1", "2026-09-14"); // must not throw
    } finally {
      storage.setItem = original;
    }
    // Storage has nothing, yet the mirror suppresses the repeat…
    expect(await storage.getItem(STAMP_KEY)).toBeNull();
    const originalGet = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      expect(await crisisDialogShownOn("user-1", "2026-09-14")).toBe(true);
      expect(await crisisDialogShownOn("user-1", "2026-09-15")).toBe(false);
    } finally {
      storage.getItem = originalGet;
    }
  });

  it("a failed READ with no memory record fails toward SHOWING the dialog", async () => {
    // A fresh account id: the module's memory mirror is process state, so
    // this test must not inherit a stamp an earlier test recorded.
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      expect(await crisisDialogShownOn("user-reader", "2026-09-14")).toBe(false);
    } finally {
      storage.getItem = original;
    }
  });

  it("clearCrisisDialogStamp wipes both the stored stamp and the mirror", async () => {
    await recordCrisisDialogShown("user-1", "2026-09-14");
    await clearCrisisDialogStamp("user-1");
    expect(await storage.getItem(STAMP_KEY)).toBeNull();
    // The mirror is wiped too: even with storage broken, the next check
    // fails toward showing (not toward a stale suppression).
    const original = storage.getItem;
    storage.getItem = vi.fn(async () => {
      throw new Error("disk gone");
    }) as never;
    try {
      expect(await crisisDialogShownOn("user-1", "2026-09-14")).toBe(false);
    } finally {
      storage.getItem = original;
    }
  });
});
