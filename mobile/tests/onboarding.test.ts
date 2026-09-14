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
