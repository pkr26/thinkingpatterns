/**
 * src/onboarding.ts: the memory-only pending flag (one-shot per
 * registration) and the persisted per-account seen flag (the keyConsent
 * idiom — wiped on account deletion).
 */
import { beforeEach, describe, expect, it } from "vitest";

const storage = (await import("./helpers/storageMock")).default;
const {
  queueOnboarding,
  takePendingOnboarding,
  hasSeenOnboarding,
  recordOnboardingSeen,
  clearOnboardingSeen,
  onboardingSeenCached,
} = await import("../src/onboarding");

beforeEach(() => {
  storage.__reset();
  takePendingOnboarding(); // drain leftovers between tests
});

describe("pending flag (memory-only, one-shot)", () => {
  it("is false until queued, true exactly once after", () => {
    expect(takePendingOnboarding()).toBe(false);
    queueOnboarding();
    expect(takePendingOnboarding()).toBe(true);
    expect(takePendingOnboarding()).toBe(false);
  });

  it("re-queueing re-arms it (a second registration in the same session)", () => {
    queueOnboarding();
    expect(takePendingOnboarding()).toBe(true);
    queueOnboarding();
    expect(takePendingOnboarding()).toBe(true);
    expect(takePendingOnboarding()).toBe(false);
  });
});

describe("seen flag (persisted, account-bound)", () => {
  it("starts unseen and persists once recorded", async () => {
    expect(await hasSeenOnboarding("user-1")).toBe(false);
    await recordOnboardingSeen("user-1");
    expect(await hasSeenOnboarding("user-1")).toBe(true);
  });

  it("is bound to the account — another account on the same device is still asked", async () => {
    await recordOnboardingSeen("user-1");
    expect(await hasSeenOnboarding("user-2")).toBe(false);
  });

  it("clearOnboardingSeen wipes it (account-deletion hygiene)", async () => {
    await recordOnboardingSeen("user-1");
    await clearOnboardingSeen("user-1");
    expect(await hasSeenOnboarding("user-1")).toBe(false);
  });
});

describe("M-18: the persisted-flag mirror (render-time gate input)", () => {
  // Fresh account ids: the module-level mirror intentionally survives
  // across calls within a process, so these tests must not depend on the
  // resolution state the earlier describes left behind.
  const A = "mirror-user-a";
  const B = "mirror-user-b";

  it("onboardingSeenCached answers null before resolution and mirrors resolution after", async () => {
    expect(onboardingSeenCached(A)).toBeNull(); // not resolved yet
    expect(await hasSeenOnboarding(A)).toBe(false);
    expect(onboardingSeenCached(A)).toBe(false); // due: panels show
    await recordOnboardingSeen(A);
    expect(onboardingSeenCached(A)).toBe(true); // done: journal
  });

  it("the mirror is account-bound like the flag itself", async () => {
    await hasSeenOnboarding(B);
    expect(onboardingSeenCached(B)).toBe(false);
    await recordOnboardingSeen(B);
    expect(onboardingSeenCached(B)).toBe(true);
    expect(onboardingSeenCached("some-third-user")).toBeNull();
  });

  it("clearOnboardingSeen invalidates the mirror (deletion hygiene)", async () => {
    await hasSeenOnboarding(B);
    await recordOnboardingSeen(B);
    await clearOnboardingSeen(B);
    expect(onboardingSeenCached(B)).toBeNull();
    expect(await hasSeenOnboarding(B)).toBe(false); // storage is truth
  });

  it("storage stays the source of truth: a fresh read overrules the mirror", async () => {
    await recordOnboardingSeen(A); // mirror: seen
    // The persisted flag is removed out from under the process (deletion
    // on another surface, or a test reset): the next async read must say
    // unseen, not answer from the mirror.
    await storage.removeItem(`@mindpattern/onboarding_seen_${A}`);
    expect(await hasSeenOnboarding(A)).toBe(false);
    expect(onboardingSeenCached(A)).toBe(false);
  });

  it("a storage failure REJECTS (never silently answers from the mirror)", async () => {
    await recordOnboardingSeen(A); // mirror: seen
    const original = storage.getItem;
    storage.getItem = (async () => {
      throw new Error("disk gone");
    }) as typeof storage.getItem;
    try {
      await expect(hasSeenOnboarding(A)).rejects.toThrow("disk gone");
    } finally {
      storage.getItem = original;
    }
    // The mirror is untouched by the failure.
    expect(onboardingSeenCached(A)).toBe(true);
  });
});
