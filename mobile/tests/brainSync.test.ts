/**
 * Daily mini-brain refresh: the consent and cadence guards.
 *
 * The refresh ships the data key in a single-use processing session, so
 * the guards are security properties, not UX niceties:
 *  - never before the threshold,
 *  - never for an account that has not explicitly used insights once
 *    (a stored blob is the evidence of that first, deliberate tap),
 *  - never more than once per calendar day,
 *  - never with a locked vault, and never louder than silence on failure.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

vi.mock("../src/api/client", () => {
  return {
    api: {
      getUserId: vi.fn(async () => "user-1"),
      insights: vi.fn(async () => ({ phase: "insight", blob: "blob" })),
      openProcessingSession: vi.fn(async () => ({ session_token: "tok" })),
      recompute: vi.fn(async () => ({})),
    },
  };
});

const { api } = (await import("../src/api/client")) as any;
const { vault } = await import("../src/vault");
const { maybeDailyRecompute } = await import("../src/brainSync");

/** The LOCAL calendar day, matching moodLog.localDateISO (the stamp moved
 *  from UTC to local so the once-per-day cap holds off-UTC). */
const localToday = (): string =>
  new Date(Date.now() - new Date().getTimezoneOffset() * 60_000).toISOString().slice(0, 10);

const KEYS = {
  masterKey: Buffer.alloc(32, 1),
  authKey: Buffer.alloc(32, 2),
  dataKey: Buffer.alloc(32, 3),
};

beforeEach(() => {
  storage.__reset();
  vi.mocked(api.getUserId).mockClear();
  vi.mocked(api.getUserId).mockImplementation(async () => "user-1");
  vi.mocked(api.insights).mockClear();
  vi.mocked(api.insights).mockImplementation(async () => ({ phase: "insight", blob: "blob" }));
  vi.mocked(api.openProcessingSession).mockClear();
  vi.mocked(api.openProcessingSession).mockImplementation(async () => ({ session_token: "tok" }));
  vi.mocked(api.recompute).mockClear();
  vi.mocked(api.recompute).mockImplementation(async () => ({}));
  vault.unlock(KEYS, "user-1");
});

describe("maybeDailyRecompute", () => {
  it("runs once per day for an insight-phase account with prior insights", async () => {
    await maybeDailyRecompute();
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);
    expect(api.recompute).toHaveBeenCalledWith("tok");

    // Same calendar day: the second call is a no-op.
    await maybeDailyRecompute();
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);
  });

  it("never runs before the threshold", async () => {
    vi.mocked(api.insights).mockImplementation(async () => ({ phase: "baseline", blob: null }));
    await maybeDailyRecompute();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("never runs for an account that has not used insights yet", async () => {
    // Insight phase but no stored blob: the FIRST analysis must stay an
    // explicit user action on the Question screen.
    vi.mocked(api.insights).mockImplementation(async () => ({ phase: "insight", blob: null }));
    await maybeDailyRecompute();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  // H5: the vault's keys must BELONG to the session's account — a
  // session/vault desync must never ship one account's data key into
  // another account's processing session.
  it("aborts when the vault keys do not belong to the session account", async () => {
    vault.lock();
    vault.unlock(KEYS, "user-2"); // keys owned by ANOTHER account
    await maybeDailyRecompute();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    vault.lock();
    vault.unlock(KEYS); // legacy unlock with no owner: unverified, refuse
    await maybeDailyRecompute();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("skips silently when the vault is locked", async () => {
    vault.lock();
    await maybeDailyRecompute();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  it("swallows failures without stamping the day (retries next launch)", async () => {
    vi.mocked(api.recompute).mockImplementation(async () => {
      throw new Error("server unreachable");
    });
    await maybeDailyRecompute();
    expect(storage.getItem("@mindpattern/last_recompute_user-1")).resolves.toBeNull();
  });

  it("stamps the day only after a successful refresh", async () => {
    await maybeDailyRecompute();
    await expect(storage.getItem("@mindpattern/last_recompute_user-1")).resolves.toBe(localToday());
  });

  it("does nothing when no user id is stored", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    await maybeDailyRecompute();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
  });

  // M8: the stamp is PER-ACCOUNT — one account's refresh must not satisfy
  // (and skip) another's, because each upload ships that account's data key.
  it("keys the daily stamp per account", async () => {
    await maybeDailyRecompute();
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);

    // A different account on the same device and day still gets its run —
    // with ITS OWN keys in the vault (the binding check below would refuse
    // user-1's keys for user-2's session, by design).
    vi.mocked(api.getUserId).mockResolvedValue("user-2");
    vault.lock();
    vault.unlock(KEYS, "user-2");
    await maybeDailyRecompute();
    expect(api.openProcessingSession).toHaveBeenCalledTimes(2);
    expect(await storage.getItem("@mindpattern/last_recompute_user-1")).toBe(localToday());
    expect(await storage.getItem("@mindpattern/last_recompute_user-2")).toBe(localToday());
  });

  // M8: concurrent callers share one run instead of both passing the
  // last === today check and both uploading the data key.
  it("concurrent invocations share a single in-flight run", async () => {
    let resolveInsights!: (v: unknown) => void;
    vi.mocked(api.insights).mockImplementation(
      () => new Promise((resolve) => (resolveInsights = resolve)),
    );
    const first = maybeDailyRecompute();
    const second = maybeDailyRecompute();
    // Let the shared run advance to (and park on) the insights await.
    await new Promise((r) => setTimeout(r, 0));
    resolveInsights({ phase: "insight", blob: "blob" });
    await first;
    await second;
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);

    // After the shared run completes, a NEW call is a fresh (stamped-out)
    // no-op. Restore the immediate mock first — the parked resolver is spent.
    vi.mocked(api.insights).mockImplementation(async () => ({ phase: "insight", blob: "blob" }));
    await maybeDailyRecompute();
    expect(api.openProcessingSession).toHaveBeenCalledTimes(1);
  });
});
