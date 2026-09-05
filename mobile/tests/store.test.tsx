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
  return { ApiError, api: makeApiMock() };
});

const { api } = await import("../src/api/client");
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

beforeEach(() => {
  // Fresh default implementations per test so per-test overrides cannot leak.
  resetApi(api as never);
  vi.mocked(AppState.addEventListener).mockClear();
  vault.lock();
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
    await act(async () => {
      await session.refreshActiveDays();
      await session.signOut();
    });
    expect(textOf(root)).toBe("loading|false|0|30");
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
