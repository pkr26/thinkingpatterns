/**
 * SessionProvider: the tri-state auth model, unlock-day discovery from
 * server meta, vault-observer wiring, active-day refresh, and the
 * sign-out wipe ordering.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { AppState, Text } from "react-native";

const accountErasureMocks = vi.hoisted(() => ({
  eraseDeletedAccountLocals: vi.fn(async () => [] as string[]),
  retryPendingAccountErasures: vi.fn(async () => 0),
}));
vi.mock("../src/accountErasure", () => accountErasureMocks);

const voiceScratchMocks = vi.hoisted(() => ({
  scrubAllVoiceScratchFiles: vi.fn(async () => {}),
}));
vi.mock("../src/audio/voiceScratch", () => voiceScratchMocks);

vi.mock("../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ApiError, api: makeApiMock(), setUnauthorizedHandler: vi.fn(), setOriginChangeHandler: vi.fn() };
});

// The queue module is mocked at the wiring boundary: what the store must do
// is CALL the coordination/sync entry points (their internals carry their
// own suite in offlineQueue.test.ts / reconnectFlush.test.ts).
vi.mock("../src/offlineQueue", () => ({
  prepareQueueRekey: vi.fn(async () => []),
  pendingEntryIds: vi.fn(async () => []),
  abortInFlightFlush: vi.fn(),
  abortInFlightFlush: vi.fn(),
  flushQueueOnReconnect: vi.fn(async () => {}),
}));

// The reminder reconciliation is likewise observed at the wiring boundary
// (its logic is covered in tests/reminderSync.test.ts): the store must
// reconcile ONCE per mount for the stored account, and never for none.
const syncReminderSchedule = vi.fn(async () => false);
vi.mock("../src/reminderSync", () => ({
  syncReminderSchedule: (...args: unknown[]) => syncReminderSchedule(...(args as [string])),
}));

// M-19 sign-out hygiene seams: the store must CALL disableBiometricUnlock
// for the signed-out account and cancel the device-global reminder (their
// internals carry their own suites).
const disableBiometricUnlock = vi.fn(async () => {});
vi.mock("../src/biometricUnlock", () => ({
  disableBiometricUnlock: (...args: unknown[]) => disableBiometricUnlock(...(args as [string])),
}));
const cancelDailyReminder = vi.fn(async () => true);
const cancelMeasureReminder = vi.fn(async () => true);
vi.mock("../src/nativeFeatures", () => ({
  cancelDailyReminder: () => cancelDailyReminder(),
  // 2026-09-27 clinical wave: sign-out also cancels the opt-in check-in
  // reminder (its own stable notification id, same device-global class).
  cancelMeasureReminder: () => cancelMeasureReminder(),
  reminderCapability: () => ({ available: false, reason: "notification module not linked" }),
  // 2026-09-26 audit LOW: biometricCapability was deleted (dead probe of a
  // non-dependency) — dropped from this mock with it.
}));

const { api, setUnauthorizedHandler, setOriginChangeHandler } = await import("../src/api/client");
const { changeLocalOrigin, __resetLocalKeyLifecycleForTests } = await import("../src/localWriteGuard");
const { abortInFlightFlush, flushQueueOnReconnect } = await import("../src/offlineQueue");
const { resetApi } = await import("./helpers/apiMock");
const { SessionProvider, useSession, stashDraft, takeStashedDraft, hasDraft, peekDraft, peekStashedJournalDraft, clearStashedJournalDraft } = await import("../src/store");
const { vault } = await import("../src/vault");
const { render: renderRaw, flush, textOf, act } = await import("./helpers/rtr");
const roots: Awaited<ReturnType<typeof renderRaw>>[] = [];
const render = async (element: React.ReactElement) => { const root = await renderRaw(element); roots.push(root); return root; };
afterEach(async () => { await act(async () => { for (const root of roots.splice(0)) root.unmount(); }); });

type Session = ReturnType<typeof useSession>;
let session: Session;

function Probe() {
  session = useSession();
  return (
    <Text>{`${session.authStatus}|${session.unlocked}|${session.activeDays}|${session.unlockDays}`}</Text>
  );
}

beforeEach(() => {
  __resetLocalKeyLifecycleForTests();
  // Fresh default implementations per test so per-test overrides cannot leak.
  resetApi(api as never);
  vi.mocked(setUnauthorizedHandler).mockClear();
  vi.mocked(AppState.addEventListener).mockClear();
  vi.mocked(abortInFlightFlush).mockClear();
  vi.mocked(flushQueueOnReconnect).mockClear();
  syncReminderSchedule.mockClear();
  accountErasureMocks.eraseDeletedAccountLocals.mockReset().mockResolvedValue([]);
  accountErasureMocks.retryPendingAccountErasures.mockReset().mockResolvedValue(0);
  voiceScratchMocks.scrubAllVoiceScratchFiles.mockReset().mockResolvedValue();
  vault.lock();
  // Sign-out/origin-switch tests deliberately suppress stale editor cleanup.
  // A fresh authenticated test session re-enables normal draft stashing.
  session?.markLoggedIn();
});

describe("SessionProvider", () => {
  it("scrubs crash-left plaintext voice files before reading any saved session", async () => {
    let finishScrub!: () => void;
    voiceScratchMocks.scrubAllVoiceScratchFiles.mockImplementationOnce(
      () => new Promise<void>(resolve => { finishScrub = resolve; }),
    );
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    await render(<SessionProvider><Probe /></SessionProvider>);
    await flush();
    expect(session.authStatus).toBe("loading");
    expect(accountErasureMocks.retryPendingAccountErasures).not.toHaveBeenCalled();
    expect(api.isLoggedIn).not.toHaveBeenCalled();

    await act(async () => { finishScrub(); });
    await flush();
    expect(accountErasureMocks.retryPendingAccountErasures).toHaveBeenCalledOnce();
    expect(api.isLoggedIn).toHaveBeenCalledOnce();
    expect(session.authStatus).toBe("loggedIn");
  });

  it("fails closed before credential hydration when crash-scratch cleanup fails", async () => {
    voiceScratchMocks.scrubAllVoiceScratchFiles.mockRejectedValueOnce(new Error("disk failure"));
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    await render(<SessionProvider><Probe /></SessionProvider>);
    await flush();
    expect(session.authStatus).toBe("loggedOut");
    expect(session.erasureIncomplete).toBe(true);
    expect(accountErasureMocks.retryPendingAccountErasures).not.toHaveBeenCalled();
    expect(api.isLoggedIn).not.toHaveBeenCalled();
  });

  it("keeps authentication behind pending-erasure recovery across a partial-failure restart", async () => {
    let finishRecovery!: (remaining: number) => void;
    accountErasureMocks.retryPendingAccountErasures.mockImplementationOnce(
      () => new Promise<number>(resolve => { finishRecovery = resolve; }),
    );
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    const unlock = vi.spyOn(vault, "unlock");
    const first = await render(<SessionProvider><Probe /></SessionProvider>);
    await flush();
    expect(session.authStatus).toBe("loading");
    expect(api.isLoggedIn).not.toHaveBeenCalled();
    expect(unlock).not.toHaveBeenCalled();

    await act(async () => { finishRecovery(1); });
    await flush();
    expect(textOf(first)).toBe("loggedOut|false|0|30");
    expect(api.isLoggedIn).not.toHaveBeenCalled();
    expect(unlock).not.toHaveBeenCalled();

    // A later cold-start pass still retries the retained checkpoint.
    accountErasureMocks.retryPendingAccountErasures.mockResolvedValueOnce(0);
    vi.mocked(api.isLoggedIn).mockResolvedValueOnce(false);
    const second = await render(<SessionProvider><Probe /></SessionProvider>);
    await flush();
    expect(textOf(second)).toBe("loggedOut|false|0|30");
    expect(accountErasureMocks.retryPendingAccountErasures).toHaveBeenCalledTimes(2);
  });

  it("remote account death locks immediately and dispatches captured durable cleanup; ordinary 401 does not", async () => {
    await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    await act(async () => {
      session.markLoggedIn();
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) }, "a".repeat(32));
    });
    const handler = vi.mocked(setUnauthorizedHandler).mock.calls.at(-1)?.[0];
    await act(async () => {
      handler?.({ status: 401, code: "unauthorized", accountDeleted: false, userId: "a".repeat(32), username: "alice", origin: "https://old.example" });
    });
    expect(vault.isUnlocked()).toBe(false);
    expect(accountErasureMocks.eraseDeletedAccountLocals).not.toHaveBeenCalled();

    await act(async () => {
      handler?.({ status: 410, code: "account_deleted", accountDeleted: true, userId: "a".repeat(32), username: "alice", origin: "https://old.example" });
    });
    await flush();
    expect(session.authStatus).toBe("loggedOut");
    expect(accountErasureMocks.eraseDeletedAccountLocals).toHaveBeenCalledWith(
      "a".repeat(32), "alice", { origin: "https://old.example" },
    );
  });
  it("a late boot credential read cannot turn a newer verified login back into loggedOut", async () => {
    let resolveBoot!: (value: boolean) => void;
    vi.mocked(api.isLoggedIn).mockImplementationOnce(() => new Promise(resolve => { resolveBoot = resolve; }));
    await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    await act(async () => {
      session.markLoggedIn();
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 7) }, "user-1");
      resolveBoot(false);
    }); await flush();
    expect(session.authStatus).toBe("loggedIn"); expect(session.unlocked).toBe(true);
  });
  it("a late saved-session boot result cannot resurrect authentication after switching the server", async () => {
    let resolveBoot!: (value: boolean) => void;
    vi.mocked(api.isLoggedIn).mockImplementationOnce(() => new Promise(resolve => { resolveBoot = resolve; }));
    await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    changeLocalOrigin();
    await act(async () => { vi.mocked(setOriginChangeHandler).mock.calls.at(-1)?.[0]?.(); resolveBoot(true); }); await flush();
    expect(session.authStatus).toBe("loggedOut"); expect(session.unlocked).toBe(false);
  });
  it("locks immediately and cannot wipe a replacement login when an old logout settles after an origin switch", async () => {
    await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 7) }, "user-1");
    stashDraft("user-1", "old private draft");
    let release!: () => void;
    vi.mocked(api.logout).mockImplementationOnce(async () => { await new Promise<void>(resolve => { release = resolve; }); return {} as never; });
    let pending!: Promise<void>;
    await act(async () => { pending = session.signOut(); }); await flush();
    expect(release).toBeTypeOf("function"); expect(vault.isUnlocked()).toBe(false); expect(hasDraft("user-1")).toBe(false);
    changeLocalOrigin();
    await act(async () => { vi.mocked(setOriginChangeHandler).mock.calls.at(-1)?.[0]?.(); });
    vi.mocked(api.getUserId).mockResolvedValue("user-2"); vi.mocked(api.getUsername).mockResolvedValue("replacement");
    await act(async () => {
      session.markLoggedIn();
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 8) }, "user-2");
    });
    stashDraft("user-2", "replacement private draft");
    await act(async () => { release(); await pending; }); await flush();
    expect(api.clearSession).not.toHaveBeenCalled(); expect(api.clearCachedSalt).not.toHaveBeenCalled();
    expect(api.clearCachedKeyEnvelope).not.toHaveBeenCalled(); expect(disableBiometricUnlock).not.toHaveBeenCalled();
    expect(vault.ownerUserId()).toBe("user-2"); expect(session.authStatus).toBe("loggedIn");
    expect(peekDraft("user-2")).toBe("replacement private draft");
  });
  it("resolves a saved session to loggedIn and a missing one to loggedOut", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    const first = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(first)).toBe("loggedIn|false|0|30");

    vi.mocked(api.isLoggedIn).mockResolvedValue(false);
    const second = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(second)).toBe("loggedOut|false|0|30");
  });

  it("reconciles the local reminder schedule once per mount for the stored account — never without one", async () => {
    // App start with a stored account: the native schedule converges to
    // the stored preference (opt-in only; reminders.ts defaults off).
    await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(syncReminderSchedule).toHaveBeenCalledTimes(1);
    expect(syncReminderSchedule).toHaveBeenCalledWith("user-1");

    // No account on the device: nothing to reconcile, no notification work.
    syncReminderSchedule.mockClear();
    vi.mocked(api.getUserId).mockResolvedValue(null);
    await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(syncReminderSchedule).not.toHaveBeenCalled();
  });

  it("renders the loading gate until isLoggedIn resolves", async () => {
    let resolveLogin!: (v: boolean) => void;
    vi.mocked(api.isLoggedIn).mockImplementation(
      () => new Promise<boolean>((resolve) => (resolveLogin = resolve)),
    );
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    expect(textOf(root)).toBe("loading|false|0|30");
    await flush();
    resolveLogin(false);
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|30");

    // The provider's own markLoggedIn flips the published status directly.
    session.markLoggedIn();
    await flush();
    expect(textOf(root)).toBe("loggedIn|false|0|30");
  });

  it("ignores async results that land after unmount", async () => {
    let resolveLogin!: (v: boolean) => void;
    vi.mocked(api.isLoggedIn).mockImplementation(
      () => new Promise<boolean>((resolve) => (resolveLogin = resolve)),
    );
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    root.unmount();
    resolveLogin(false);
    await flush();
    // No React "state update on unmounted component" crash — and a fresh
    // provider still mounts cleanly afterwards.
    vi.mocked(api.isLoggedIn).mockResolvedValue(false);
    const again = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(again)).toBe("loggedOut|false|0|30");
  });

  it("adopts the server's unlock_days when meta reports a number", async () => {
    vi.mocked(api.meta).mockResolvedValue({ unlock_days: 45 } as never);
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|45");
  });

  it("keeps the 30-day default when meta is offline or malformed", async () => {
    vi.mocked(api.meta).mockRejectedValue(new Error("offline"));
    const first = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(first)).toBe("loggedOut|false|0|30");

    vi.mocked(api.meta).mockResolvedValue({ unlock_days: "soon" } as never);
    const second = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(second)).toBe("loggedOut|false|0|30");
  });

  it("tracks the vault lock state through subscriptions", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|30");

    const keys = { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) };
    await act(async () => {
      vault.unlock(keys);
    });
    expect(textOf(root)).toBe("loggedOut|true|0|30");
    vault.lock();
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });

  it("refreshActiveDays publishes the server count and survives failures", async () => {
    vi.mocked(api.insights).mockResolvedValue({ active_days: 12 } as never);
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.refreshActiveDays();
    });
    expect(textOf(root)).toBe("loggedOut|false|12|30");

    vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    await act(async () => {
      await session.refreshActiveDays();
    });
    expect(textOf(root)).toBe("loggedOut|false|12|30");
  });

  it("ignores late progress responses after a newer refresh, adopted count or sign-out", async () => {
    const root = await render(<SessionProvider><Probe /></SessionProvider>);
    await flush();
    let finishOld!: (value: unknown) => void;
    vi.mocked(api.insights).mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve; }));
    let old!: Promise<void>;
    await act(async () => { old = session.refreshActiveDays(); });
    vi.mocked(api.insights).mockResolvedValueOnce({ active_days: 11 } as never);
    await act(async () => { await session.refreshActiveDays(); finishOld({ active_days: 2 }); await old; });
    expect(textOf(root)).toBe("loggedOut|false|11|30");

    vi.mocked(api.insights).mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve; }));
    await act(async () => { old = session.refreshActiveDays(); });
    await act(async () => { const read = await session.beginProgressRead(); session.applyActiveDays(12, read!); finishOld({ active_days: 3 }); await old; });
    expect(textOf(root)).toBe("loggedOut|false|12|30");

    vi.mocked(api.insights).mockImplementationOnce(() => new Promise(resolve => { finishOld = resolve; }));
    await act(async () => { old = session.refreshActiveDays(); });
    await act(async () => { await session.signOut(); finishOld({ active_days: 99 }); await old; });
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });

  it("setUnlockDays updates the published threshold", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    session.setUnlockDays(7);
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|7");
  });

  it("signOut: local wipe proceeds even when the server logout fails", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    vi.mocked(api.insights).mockResolvedValue({ active_days: 20 } as never);
    vi.mocked(api.logout).mockRejectedValue(new Error("offline"));
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.refreshActiveDays();
    });
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });

    await act(async () => {
      await session.signOut();
    });

    expect(api.logout).toHaveBeenCalledTimes(1);
    expect(api.clearSession).toHaveBeenCalledTimes(1);
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });

  it("signOut with a healthy server: revocation and session clear", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
    expect(api.logout).toHaveBeenCalledTimes(1);
    expect(api.clearSession).toHaveBeenCalledTimes(1);
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });

  // M2 regression: unsynced offline entries live ONLY in the queue — sign-out
  // must not destroy them (account isolation is enforced at flush time).
  it("signOut keeps the offline queue intact", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    const { changeLocalSessionOwner } = await import("../src/localWriteGuard");
    changeLocalSessionOwner("user-1");
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    // The queue store was never touched: the key survives sign-out.
    const storage = (await import("./helpers/storageMock")).default;
    await storage.setItem("@mindpattern/queue", JSON.stringify([{ userId: "u1", clientEntryId: "e", blobB64: "AA==", entryDate: "2026-09-04" }]));
    await act(async () => {
      await session.signOut();
    });
    expect(await storage.getItem("@mindpattern/queue")).not.toBeNull();
  });

  // M6 regression: derived keys must not outlive a background transition.
  it("locks the vault when the app goes to background or inactive", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    });
    expect(textOf(root)).toBe("loggedOut|true|0|30");

    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)?.[1] as (s: string) => void;
    expect(listener).toBeTypeOf("function");
    await act(async () => {
      listener("background");
    });
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });

  it("useSession outside a provider returns safe no-op defaults", async () => {
    const root = await render(<Probe />);
    expect(textOf(root)).toBe("loading|false|0|30");
    // Every default is callable and does nothing.
    session.markLoggedIn();
    session.setUnlockDays(3);
    session.touchActivity();
    await act(async () => {
      await session.refreshActiveDays();
      await session.signOut();
    });
    expect(textOf(root)).toBe("loading|false|0|30");
  });

  // The inactivity countdown must be a REAL reset: interaction restarts the
  // full 5-minute window rather than merely delaying the original deadline.
  // (flush() needs real timers, and earlier tests in this file leave mounted
  // providers subscribed to the vault — so the unlock happens while real
  // timers are still active; fake timers go on right after, and the fake
  // countdown is then armed by touchActivity / the AppState listener.)
  it("locks after 5 idle minutes, and touchActivity restarts the countdown", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    });
    vi.useFakeTimers();
    try {
      expect(vault.isUnlocked()).toBe(true);

      // Activity arms the (fake) countdown; 4:59 idle — still unlocked.
      act(() => {
        session.touchActivity();
      });
      act(() => {
        vi.advanceTimersByTime(4 * 60_000 + 59_000);
      });
      expect(vault.isUnlocked()).toBe(true);

      // Interaction one second before the deadline restarts the countdown,
      // so the original deadline passes without a lock.
      act(() => {
        session.touchActivity();
      });
      act(() => {
        vi.advanceTimersByTime(4 * 60_000 + 59_000);
      });
      expect(vault.isUnlocked()).toBe(true);

      // One more idle second crosses the NEW deadline: locked, and the
      // published session state follows the vault.
      await act(async () => {
        vi.advanceTimersByTime(1_000);
      });
      expect(vault.isUnlocked()).toBe(false);
      expect(textOf(root)).toBe("loggedOut|false|0|30");
    } finally {
      vi.useRealTimers();
    }
  });

  it("arms no countdown while the vault is locked", async () => {
    await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    vi.useFakeTimers();
    try {
      expect(vault.isUnlocked()).toBe(false);
      act(() => {
        session.touchActivity(); // locked vault: no timer is armed
      });
      act(() => {
        vi.advanceTimersByTime(10 * 60_000);
      });
      expect(vault.isUnlocked()).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it("returning to the foreground restarts the inactivity countdown", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)?.[1] as (s: string) => void;
    await act(async () => {
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    });
    vi.useFakeTimers();
    try {
      // Foreground return = activity: it arms the countdown.
      act(() => {
        listener("active");
      });
      act(() => {
        vi.advanceTimersByTime(4 * 60_000 + 59_000);
      });
      expect(vault.isUnlocked()).toBe(true);

      // Another foreground return restarts it.
      act(() => {
        listener("active");
      });
      act(() => {
        vi.advanceTimersByTime(4 * 60_000 + 59_000);
      });
      expect(vault.isUnlocked()).toBe(true);

      await act(async () => {
        vi.advanceTimersByTime(1_000);
      });
      expect(vault.isUnlocked()).toBe(false);
      expect(textOf(root)).toBe("loggedOut|false|0|30");
    } finally {
      vi.useRealTimers();
    }
  });

  it("unmounting the provider disarms the inactivity countdown", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    });
    vi.useFakeTimers();
    try {
      act(() => {
        session.touchActivity(); // arm the countdown
      });
      act(() => {
        root.unmount(); // provider cleanup must clear the pending timer
      });
      act(() => {
        vi.advanceTimersByTime(10 * 60_000);
      });
      // No ghost timer fires after unmount: the vault is still unlocked.
      expect(vault.isUnlocked()).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  // M2: a 401 from ANY api call must lock the vault app-wide — the store
  // registers the client's unauthorized hook, and the lock flips the
  // published `unlocked` flag (what navigation gates on).
  it("registers the 401 hook: any unauthorized response locks the vault and flips the gate", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(setUnauthorizedHandler).toHaveBeenCalledTimes(1);
    await act(async () => {
      vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    });
    expect(textOf(root)).toBe("loggedOut|true|0|30");

    // The client invokes the registered handler before throwing its 401.
    const handler = vi.mocked(setUnauthorizedHandler).mock.calls[0]?.[0] as ((death: { accountDeleted: boolean }) => void) | null;
    expect(handler).toBeTypeOf("function");
    await act(async () => {
      handler?.({ accountDeleted: false });
    });
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });

  it("unregisters the 401 hook when the provider unmounts", async () => {
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      root.unmount();
    });
    expect(vi.mocked(setUnauthorizedHandler).mock.calls.at(-1)?.[0]).toBeNull();
  });

  // M-19 (2026-09-20 audit): sign-out removes the biometric data-key wrap
  // for the account and cancels the device-global daily reminder — the
  // shared-device user must not be nudged (or key-wrapped) by a session
  // that no longer exists. Account deletion already did both.
  it("signOut disables the biometric wrap and cancels the daily reminder", async () => {
    vi.mocked(api.getUserId).mockResolvedValue("u-19");
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    disableBiometricUnlock.mockClear();
    cancelDailyReminder.mockClear();
    await act(async () => {
      await session.signOut();
    });
    expect(disableBiometricUnlock).toHaveBeenCalledWith("u-19");
    // Device-global: cancelled even when the account id resolves.
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
  });

  it("signOut cancels the reminder even with no resolvable account id", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    disableBiometricUnlock.mockClear();
    cancelDailyReminder.mockClear();
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
    expect(disableBiometricUnlock).not.toHaveBeenCalled();
    expect(cancelDailyReminder).toHaveBeenCalledTimes(1);
  });

  // M2 draft-stash hygiene: the plaintext draft must not outlive the
  // session in the JS heap.
  it("signOut wipes the stashed draft", async () => {
    stashDraft("user-1", "the previous user's plaintext draft");
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
    expect(takeStashedDraft("user-1")).toBeNull();
  });

  it("takeStashedDraft is account-bound: a mismatch neither returns nor consumes the stash", async () => {
    stashDraft("user-1", "alice's draft");
    // A different account never sees it — and the stash SURVIVES the
    // mismatched probe (the account check precedes the consume).
    expect(takeStashedDraft("user-2")).toBeNull();
    // The owning account still gets it back, exactly once.
    expect(takeStashedDraft("user-1")).toBe("alice's draft");
    expect(takeStashedDraft("user-1")).toBeNull();
  });
});

describe("M9: unlock_days sanitization", () => {
  it("rejects hostile unlock_days values and keeps the 30-day default", async () => {
    for (const bad of [0, -5, 400, 1.5, "soon", null]) {
      vi.mocked(api.meta).mockResolvedValue({ unlock_days: bad } as never);
      const root = await render(
        <SessionProvider>
          <Probe />
        </SessionProvider>,
      );
      await flush();
      expect(textOf(root)).toBe("loggedOut|false|0|30");
    }
  });

  it("keeps a sane server value and its bounds", async () => {
    vi.mocked(api.meta).mockResolvedValue({ unlock_days: 365 } as never);
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|365");
  });
});

describe("context identity stabilization", () => {
  // The audit finding: context functions were recreated every render, so a
  // consumer's useCallback(..., [refreshActiveDays]) (InsightsScreen.load)
  // refired its effect on every provider render — double fetch + decrypt
  // per mount. Pin: an unrelated state change must not refire the effect.
  it("keeps function identities stable across unrelated state changes", async () => {
    let loads = 0;
    let seen: Session | null = null;
    function Consumer() {
      const s = useSession();
      seen = s;
      const load = React.useCallback(async () => {
        loads += 1;
      }, [s.refreshActiveDays]);
      React.useEffect(() => {
        void load();
      }, [load]);
      return <Text>{`${s.unlockDays}`}</Text>;
    }
    const root = await render(
      <SessionProvider>
        <Consumer />
      </SessionProvider>,
    );
    await flush();
    expect(loads).toBe(1);
    const firstSignOut = seen!.signOut;
    const firstRefresh = seen!.refreshActiveDays;

    // An unrelated state change re-renders consumers with new data...
    await act(async () => {
      seen!.setUnlockDays(7);
    });
    await flush();
    expect(textOf(root)).toBe("7");

    // ...but the effect did not refire, and the published references are
    // literally the same objects.
    expect(loads).toBe(1);
    expect(seen!.signOut).toBe(firstSignOut);
    expect(seen!.refreshActiveDays).toBe(firstRefresh);
  });
});

describe("sign-out flush coordination", () => {
  it("signOut aborts the in-flight flush BEFORE revoking the session", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
    expect(abortInFlightFlush).toHaveBeenCalledTimes(1);
    // The abort must land before the token dies — a flush 401 after that
    // point is self-inflicted and requeues instead of rejecting.
    const abortOrder = vi.mocked(abortInFlightFlush).mock.invocationCallOrder[0]!;
    expect(abortOrder).toBeLessThan(vi.mocked(api.logout).mock.invocationCallOrder[0]!);
    expect(abortOrder).toBeLessThan(vi.mocked(api.clearSession).mock.invocationCallOrder[0]!);
  });
});

describe("reconnect flush wiring", () => {
  it("foregrounding triggers a queue flush; backgrounding does not", async () => {
    await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)?.[1] as (s: string) => void;
    await act(async () => {
      listener("active");
    });
    expect(flushQueueOnReconnect).toHaveBeenCalledTimes(1);
    await act(async () => {
      listener("background");
    });
    expect(flushQueueOnReconnect).toHaveBeenCalledTimes(1);
    await act(async () => {
      listener("active");
    });
    expect(flushQueueOnReconnect).toHaveBeenCalledTimes(2);
  });
});

describe("foreground activeDays refresh (E-10, audit round 2, 2026-09-21, F-11)", () => {
  // Constraint: an always-open app must not keep a stale activeDays count
  // across midnight — the "active" branch of the AppState listener re-reads
  // the server's count (refreshActiveDays), exactly like it flushes the
  // queue above. Nothing else in the provider calls api.insights.
  it("foregrounding re-reads the server's active-days count; backgrounding does not", async () => {
    vi.mocked(api.insights).mockResolvedValue({ active_days: 41 } as never);
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    expect(textOf(root)).toBe("loggedOut|false|0|30"); // nothing fetched yet

    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)?.[1] as (s: string) => void;
    await act(async () => {
      listener("active");
    });
    await flush();
    expect(api.insights).toHaveBeenCalledTimes(1);
    expect(textOf(root)).toBe("loggedOut|false|41|30");

    // Backgrounding never refreshes; the next foreground adopts the rolled-
    // forward count, not a cached one.
    vi.mocked(api.insights).mockResolvedValue({ active_days: 42 } as never);
    await act(async () => {
      listener("background");
    });
    await flush();
    expect(api.insights).toHaveBeenCalledTimes(1);
    await act(async () => {
      listener("active");
    });
    await flush();
    expect(api.insights).toHaveBeenCalledTimes(2);
    expect(textOf(root)).toBe("loggedOut|false|42|30");
  });
});

describe("authoritative progress on boot and verified unlock", () => {
  it("hydrates a saved bearer and refreshes again on a verified vault unlock, with no fetch on lock", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true);
    let finish!: (value: unknown) => void;
    vi.mocked(api.insights).mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const root = await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    expect(session.activeDaysKnown).toBe(false); expect(session.activeDaysLoading).toBe(true);
    await act(async () => { finish({ active_days: 11 }); }); await flush();
    expect(session.activeDaysKnown).toBe(true); expect(session.activeDaysLoading).toBe(false);
    expect(textOf(root)).toBe("loggedIn|false|11|30");
    vi.mocked(api.insights).mockResolvedValue({ active_days: 12 } as never);
    await act(async () => vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32), dataKey: Buffer.alloc(32) }, "user-1")); await flush();
    expect(textOf(root)).toBe("loggedIn|true|12|30"); expect(api.insights).toHaveBeenCalledTimes(2);
    await act(async () => vault.lock()); await flush();
    expect(api.insights).toHaveBeenCalledTimes(2); expect(session.activeDays).toBe(12);
  });
  it("an offline first fetch is unknown, a valid server zero is known, and subsequent failures retain it", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true); vi.mocked(api.insights).mockRejectedValue(new Error("offline"));
    await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    expect(session.activeDaysKnown).toBe(false); expect(session.activeDaysLoading).toBe(false);
    vi.mocked(api.insights).mockResolvedValue({ active_days: 0 } as never);
    await act(async () => { await session.refreshActiveDays(); });
    expect(session.activeDays).toBe(0); expect(session.activeDaysKnown).toBe(true);
    vi.mocked(api.insights).mockRejectedValue(new Error("offline again"));
    await act(async () => { await session.refreshActiveDays(); }); expect(session.activeDaysKnown).toBe(true);
  });
  it("a new owner cannot inherit the prior owner's known count when its fetch fails", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true); vi.mocked(api.insights).mockResolvedValue({ active_days: 11 } as never);
    await render(<SessionProvider><Probe /></SessionProvider>); await flush(); expect(session.activeDaysKnown).toBe(true);
    vi.mocked(api.getUserId).mockResolvedValue("user-2"); vi.mocked(api.insights).mockRejectedValue(new Error("offline new owner"));
    await act(async () => { await session.refreshActiveDays(); });
    expect(session.activeDays).toBe(0); expect(session.activeDaysKnown).toBe(false);
    await act(async () => { await session.signOut(); }); expect(session.activeDaysKnown).toBe(false);
  });
  it("an old owner read cannot reset a newer owner's successful count", async () => {
    await render(<SessionProvider><Probe /></SessionProvider>); await flush();
    vi.mocked(api.insights).mockResolvedValue({ active_days: 11 } as never);
    await act(async () => { await session.refreshActiveDays(); });
    let release!: (owner: string) => void;
    vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    let old!: Promise<void>; await act(async () => { old = session.refreshActiveDays(); });
    vi.mocked(api.getUserId).mockResolvedValue("user-2"); vi.mocked(api.insights).mockResolvedValue({ active_days: 12 } as never);
    await act(async () => { await session.refreshActiveDays(); release("user-1"); await old; });
    expect(session.activeDays).toBe(12); expect(session.activeDaysKnown).toBe(true);
  });
  it("malformed initial metadata remains unknown and a missing owner clears a known count", async () => {
    vi.mocked(api.isLoggedIn).mockResolvedValue(true); vi.mocked(api.insights).mockResolvedValue({ active_days: "0" } as never);
    await render(<SessionProvider><Probe /></SessionProvider>); await flush(); expect(session.activeDaysKnown).toBe(false);
    await act(async () => { const read = await session.beginProgressRead(); session.applyActiveDays(11, read!); }); expect(session.activeDaysKnown).toBe(true);
    vi.mocked(api.getUserId).mockResolvedValue(null);
    await act(async () => { await session.refreshActiveDays(); }); expect(session.activeDaysKnown).toBe(false);
  });
});

describe("draft stash survival", () => {
  it("preserves complete origin-bound RAM fields, clones tags, and clears only an acknowledged matching revision", () => {
    const origin = "https://journal.example", user = "ram-fields-owner";
    const journal = { v: 1 as const, editorId: "a".repeat(32), revision: 4, text: "unfinished", mood: 1, energy: -1, sleep: 5, tags: ["rest"] };
    stashDraft(user, journal.text, journal, origin);
    expect(peekStashedJournalDraft(user, "https://other.example")).toBeNull();
    expect(takeStashedDraft(user, "https://other.example")).toBeNull();
    const copy = peekStashedJournalDraft(user, origin)!; copy.tags.push("work");
    expect(peekStashedJournalDraft(user, origin)?.tags).toEqual(["rest"]);
    clearStashedJournalDraft(user, origin, journal.editorId, 3); expect(peekDraft(user)).toBe("unfinished");
    clearStashedJournalDraft(user, origin, "b".repeat(32), 4); expect(peekDraft(user)).toBe("unfinished");
    clearStashedJournalDraft(user, origin, journal.editorId, 4); expect(peekDraft(user)).toBeNull();
    stashDraft(user, "question bridge"); expect(peekStashedJournalDraft(user, origin)).toBeNull();
    expect(takeStashedDraft(user, origin)).toBe("question bridge");
  });
  // The draft stash must survive vault.lock() — a background transition
  // unmounts the editor, and the unsent text waits for re-unlock.
  it("a stashed draft survives vault.lock() within the session", () => {
    stashDraft("user-1", "half-written thoughts");
    vault.lock(); // what a background transition does
    expect(hasDraft("user-1")).toBe(true);
    expect(peekDraft("user-1")).toBe("half-written thoughts");
    // peek does not consume; take does — exactly once.
    expect(peekDraft("user-1")).toBe("half-written thoughts");
    expect(takeStashedDraft("user-1")).toBe("half-written thoughts");
    expect(hasDraft("user-1")).toBe(false);
    expect(peekDraft("user-1")).toBeNull();
  });

  it("hasDraft/peekDraft are account-bound and never consume", () => {
    stashDraft("user-1", "alice's draft");
    expect(hasDraft("user-2")).toBe(false);
    expect(peekDraft("user-2")).toBeNull();
    // The owning account still gets it back afterwards.
    expect(takeStashedDraft("user-1")).toBe("alice's draft");
  });
});

describe("haptics preference loads at session start (audit fix 19, 2026-09-21)", () => {
  it("a cold start with a stored 'off' keeps haptics disabled with no screen interaction", async () => {
    // The sensory-anxiety setting used to be ignored until Settings was
    // opened (the only caller of loadHapticsSetting); the provider mount
    // now loads it, before any screen could fire a pulse.
    const storage = (await import("./helpers/storageMock")).default;
    const { hapticsEnabled, loadHapticsSetting } = await import("../src/haptics");
    await storage.setItem("@mindpattern/haptics.enabled", "off");
    try {
      await render(
        <SessionProvider>
          <Probe />
        </SessionProvider>,
      );
      await flush();
      expect(hapticsEnabled()).toBe(false);
    } finally {
      // Restore the module default for any later test in this file.
      storage.__reset();
      await loadHapticsSetting();
    }
    expect(hapticsEnabled()).toBe(true);
  });
});
