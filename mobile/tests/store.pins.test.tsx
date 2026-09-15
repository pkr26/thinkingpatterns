/**
 * Deep-mutation pins for the session store (2026-09-15 Stryker campaign).
 * Targets (see /tmp/surv_store.tsx.txt):
 *  - sanitizeUnlockDays adopting exactly 1 (the < 1 boundary is strict),
 *  - a fresh vault unlock arming the idle countdown THROUGH the subscriber
 *    (not just via a manual touchActivity call),
 *  - "inactive" backgrounding locking the vault like "background" does,
 *  - unknown AppState values NOT firing the reconnect flush,
 *  - unmount really unsubscribing (no ghost idle lock after unmount) and
 *    really removing the AppState subscription,
 *  - refreshActiveDays keeping the last value when active_days is absent,
 *  - signOut wiping per-account hygiene exactly when the ids exist.
 */
// @ts-nocheck

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { AppState, Text } from "react-native";

vi.mock("../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ApiError, api: makeApiMock(), setUnauthorizedHandler: vi.fn() };
});

vi.mock("../src/offlineQueue", () => ({
  abortInFlightFlush: vi.fn(),
  flushQueueOnReconnect: vi.fn(async () => {}),
}));

vi.mock("../src/unlockProof", () => ({ clearUnlockProof: vi.fn(async () => {}) }));
vi.mock("../src/brainSync", () => ({ clearRecomputeStamp: vi.fn(async () => {}) }));

const { api } = await import("../src/api/client");
const { abortInFlightFlush, flushQueueOnReconnect } = await import("../src/offlineQueue");
const { clearUnlockProof } = await import("../src/unlockProof");
const { clearRecomputeStamp } = await import("../src/brainSync");
const { resetApi } = await import("./helpers/apiMock");
const { SessionProvider, useSession } = await import("../src/store");
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

const keys = { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) };

// Every mounted provider subscribes to the vault; leftover subscribers from
// earlier tests would arm ghost idle timers on a later unlock and contaminate
// the unmount-hygiene assertions. Unmount everything after each test.
const mounted: { unmount: () => void }[] = [];
const mount = (ui: React.ReactElement) => {
  const pending = render(ui);
  return pending.then((root) => {
    mounted.push(root);
    return root;
  });
};

beforeEach(() => {
  resetApi(api as never);
  vi.mocked(abortInFlightFlush).mockClear();
  vi.mocked(flushQueueOnReconnect).mockClear();
  vi.mocked(clearUnlockProof).mockClear();
  vi.mocked(clearRecomputeStamp).mockClear();
  vi.mocked(AppState.addEventListener).mockClear();
  vault.lock();
});

afterEach(async () => {
  while (mounted.length > 0) {
    const root = mounted.pop();
    await act(async () => {
      root.unmount();
    });
  }
});

describe("store pins: sanitizeUnlockDays boundary", () => {
  it("unlock_days of exactly 1 is adopted (the lower bound is inclusive)", async () => {
    vi.mocked(api.meta).mockResolvedValue({ unlock_days: 1 } as never);
    const root = await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    // 1 day is a hostile-input boundary: < 1 must reject, <= 1 must not.
    expect(textOf(root)).toBe("loggedOut|false|0|1");
  });
});

describe("store pins: idle countdown wiring", () => {
  it("a fresh vault unlock arms the 5-minute countdown through the subscriber alone", async () => {
    const root = await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush(); // real timers for the mount effects
    vi.useFakeTimers();
    try {
      await act(async () => {
        vault.unlock(keys);
      });
      expect(vault.isUnlocked()).toBe(true);
      // NO manual touchActivity here: the store's own vault subscription
      // must have started the countdown.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5 * 60_000);
      });
      expect(vault.isUnlocked()).toBe(false);
      expect(textOf(root)).toBe("loggedOut|false|0|30");
    } finally {
      vi.useRealTimers();
    }
  });

  it("an 'inactive' state locks the vault exactly like 'background'", async () => {
    await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      vault.unlock(keys);
    });
    expect(vault.isUnlocked()).toBe(true);
    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)?.[1] as (s: string) => void;
    await act(async () => {
      listener("inactive");
    });
    expect(vault.isUnlocked()).toBe(false);
  });

  it("an unknown AppState value is neither backgrounding nor foregrounding (no flush)", async () => {
    await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    const listener = vi.mocked(AppState.addEventListener).mock.calls.at(-1)?.[1] as (s: string) => void;
    await act(async () => {
      listener("some-future-state");
    });
    expect(flushQueueOnReconnect).not.toHaveBeenCalled();
  });
});

describe("store pins: unmount hygiene", () => {
  it("unmount unsubscribes from the vault — a later unlock arms no ghost lock", async () => {
    const root = await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    act(() => {
      root.unmount();
    });
    vi.useFakeTimers();
    try {
      // If the subscription leaked, this unlock arms an idle timer whose
      // 5-minute fire would lock the vault with NO provider mounted.
      await act(async () => {
        vault.unlock(keys);
      });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(5 * 60_000);
      });
      expect(vault.isUnlocked()).toBe(true);
    } finally {
      vi.useRealTimers();
      vault.lock();
    }
  });

  it("unmount removes the AppState subscription", async () => {
    const root = await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    const subscription = vi.mocked(AppState.addEventListener).mock.results.at(-1)?.value as {
      remove: ReturnType<typeof vi.fn>;
    };
    expect(subscription).toBeDefined();
    act(() => {
      root.unmount();
    });
    expect(subscription.remove).toHaveBeenCalled();
  });
});

describe("store pins: refreshActiveDays guard", () => {
  it("insights without active_days keeps the published count at 0 (never undefined)", async () => {
    vi.mocked(api.insights).mockResolvedValue({} as never);
    const root = await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.refreshActiveDays();
    });
    // A guard forced to true would setActiveDays(undefined) and render
    // "undefined" into the published state.
    expect(textOf(root)).toBe("loggedOut|false|0|30");
  });
});

describe("store pins: signOut account hygiene", () => {
  it("clears the unlock proof, recompute stamp and cached salt for the CURRENT ids", async () => {
    vi.mocked(api.getUserId).mockResolvedValue("u-9");
    vi.mocked(api.getUsername).mockResolvedValue("kim");
    await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
    expect(clearRecomputeStamp).toHaveBeenCalledWith("u-9");
    expect(clearUnlockProof).toHaveBeenCalledWith("u-9");
    expect(api.clearCachedSalt).toHaveBeenCalledWith("kim");
  });

  it("with NO stored ids, none of the per-account wipes run", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(api.getUsername).mockResolvedValue(null);
    await mount(
      <SessionProvider>
        <Probe />
      </SessionProvider>,
    );
    await flush();
    await act(async () => {
      await session.signOut();
    });
    expect(clearRecomputeStamp).not.toHaveBeenCalled();
    expect(clearUnlockProof).not.toHaveBeenCalled();
    expect(api.clearCachedSalt).not.toHaveBeenCalled();
  });
});
