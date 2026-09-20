/**
 * SessionProvider: the tri-state auth model, unlock-day discovery from
 * server meta, vault-observer wiring, active-day refresh, and the
 * sign-out wipe ordering.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { AppState, Text } from "react-native";

vi.mock("../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ApiError, api: makeApiMock(), setUnauthorizedHandler: vi.fn(), setOriginChangeHandler: vi.fn() };
});

// The queue module is mocked at the wiring boundary: what the store must do
// is CALL the coordination/sync entry points (their internals carry their
// own suite in offlineQueue.test.ts / reconnectFlush.test.ts).
vi.mock("../src/offlineQueue", () => ({
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
vi.mock("../src/nativeFeatures", () => ({
  cancelDailyReminder: () => cancelDailyReminder(),
  reminderCapability: () => ({ available: false, reason: "notification module not linked" }),
  biometricCapability: () => ({ available: false, reason: "biometric module not linked" }),
}));

const { api, setUnauthorizedHandler } = await import("../src/api/client");
const { abortInFlightFlush, flushQueueOnReconnect } = await import("../src/offlineQueue");
const { resetApi } = await import("./helpers/apiMock");
const { SessionProvider, useSession, stashDraft, takeStashedDraft, hasDraft, peekDraft } = await import("../src/store");
const { vault } = await import("../src/vault");
const { render, flush, textOf, act } = await import("./helpers/rtr");

type Session = ReturnType<typeof useSession>;
let session: Session;

function Probe() {
  session = useSession();
  return (
    <Text>{`${session.authStatus}|${session.unlocked}|${session.activeDays}|${session.unlockDays}`}</Text>
  );
}

beforeEach(() => {
  // Fresh default implementations per test so per-test overrides cannot leak.
  resetApi(api as never);
  vi.mocked(setUnauthorizedHandler).mockClear();
  vi.mocked(AppState.addEventListener).mockClear();
  vi.mocked(abortInFlightFlush).mockClear();
  vi.mocked(flushQueueOnReconnect).mockClear();
  syncReminderSchedule.mockClear();
  vault.lock();
  // Sign-out/origin-switch tests deliberately suppress stale editor cleanup.
  // A fresh authenticated test session re-enables normal draft stashing.
  session?.markLoggedIn();
});

describe("SessionProvider", () => {
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
    const root = await render(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
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
    const handler = vi.mocked(setUnauthorizedHandler).mock.calls[0]?.[0] as (() => void) | null;
    expect(handler).toBeTypeOf("function");
    await act(async () => {
      handler?.();
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

describe("draft stash survival", () => {
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
