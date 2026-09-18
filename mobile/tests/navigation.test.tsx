/**
 * AppNavigator tri-state: loading → BootSplash (never a flash of Login over
 * a live session), loggedOut → Login, loggedIn-but-locked → Unlock,
 * unlocked → the four app screens.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { ActivityIndicator } from "react-native";

vi.mock("../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api/client")>();
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ...actual, ApiError, api: makeApiMock() };
});

vi.mock("../src/offlineQueue", () => ({
  enqueue: vi.fn(async () => {}),
  flushQueue: vi.fn(async () => 0),
  QueueFullError: class QueueFullError extends Error {},
  // The Settings screen's recovery surface reads these on mount.
  rejectedEntryCount: vi.fn(async () => 0),
  requeueRejected: vi.fn(async () => 0),
  quarantinedQueueExists: vi.fn(async () => false),
  hasLegacyQueueRecovery: vi.fn(async () => false),
}));

let sessionState: Record<string, unknown> = { authStatus: "loading", unlocked: false };
vi.mock("../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/store")>();
  return {
    ...actual,
    useSession: () => sessionState,
  };
});

const { AppNavigator } = await import("../src/navigation");
const { api } = await import("../src/api/client");
const { takePendingOnboarding } = await import("../src/onboarding");
const { render, flush, textOf, screenNames, screenOptions } = await import("./helpers/rtr");
const { resetApi } = await import("./helpers/apiMock");
const { vault } = await import("../src/vault");
const { navigationStub } = await import("./helpers/navigationStackMock");

beforeEach(() => {
  resetApi(api as never);
  navigationStub.navigate.mockClear();
  navigationStub.popToTop.mockClear();
  navigationStub.replace.mockClear();
  takePendingOnboarding(); // drain any leftover so tests cannot leak into each other
  vault.lock();
  sessionState = { authStatus: "loading", unlocked: false };
});

describe("AppNavigator", () => {
  it("shows the boot splash while the saved session resolves", async () => {
    const root = await render(<AppNavigator />);
    await flush();
    // L8: crisis help stays reachable even during the boot gate.
    expect(screenNames(root)).toEqual(["Booting", "Crisis"]);
    expect(root.root.findAllByType(ActivityIndicator)).toHaveLength(1);
    expect(screenOptions(root, "Booting")).toEqual({ headerShown: false });
    // Branded splash (design-system pass): name + calm tagline, themed bg.
    // The tagline is honest copy (audit fix): "Your patterns. Your keys.
    // Nobody else's." overstated it — the key visits server memory once
    // during a consented analysis.
    expect(textOf(root)).toContain("MindPattern");
    expect(textOf(root)).toContain("Your patterns, from your words. Encrypted on this device.");
    const { expectStyle } = await import("./helpers/rtr");
    expectStyle(root, { flex: 1, alignItems: "center", justifyContent: "center", gap: 12 });
    expectStyle(root, { backgroundColor: "#0f1115" });
    expectStyle(root, { fontSize: 28, fontWeight: "700" }); // brand
    expectStyle(root, { color: "#e8eaf0" }); // brand themed
  });

  it("logged out: the login screen plus crisis access — nothing else", async () => {
    sessionState = { authStatus: "loggedOut", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    expect(screenNames(root)).toEqual(["Login", "Crisis"]);
    expect(textOf(root)).toContain("MindPattern");
    expect(screenOptions(root, "Login")).toEqual({ headerShown: false });
    // Crisis is a first-class screen even before sign-in (M7).
    expect(screenOptions(root, "Crisis")).toEqual({ title: "Get help" });
  });

  it("cold restart: logged in but locked lands on the unlock gate, with crisis access", async () => {
    sessionState = { authStatus: "loggedIn", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    expect(screenNames(root)).toEqual(["Unlock", "Crisis"]);
    expect(textOf(root)).toContain("Locked");
    expect(screenOptions(root, "Unlock")).toEqual({ headerShown: false });
    expect(screenOptions(root, "Crisis")).toEqual({ title: "Get help" });
  });

  // M7: the locked state is when users most need help — the affordance is
  // one tap away and never requires unlocking.
  it("the locked state's 'Get help' affordance navigates to Crisis without unlocking", async () => {
    sessionState = { authStatus: "loggedIn", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    const { pressLabel } = await import("./helpers/rtr");
    await pressLabel(root, "Need help now? Crisis resources");
    expect(navigationStub.navigate).toHaveBeenCalledWith("Crisis");
    expect(vault.isUnlocked()).toBe(false);
  });

  it("the logged-out state's 'Get help' affordance navigates to Crisis", async () => {
    sessionState = { authStatus: "loggedOut", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    const { pressLabel } = await import("./helpers/rtr");
    await pressLabel(root, "Need help now? Crisis resources");
    expect(navigationStub.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("unlocked: all app screens are reachable", async () => {
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { authStatus: "loggedIn", unlocked: true };
    const root = await render(<AppNavigator />);
    await flush();

    expect(screenNames(root)).toEqual(["Entry", "History", "Insights", "Question", "Settings", "TherapistShare", "Privacy", "Crisis"]);
    const text = textOf(root);
    expect(text).toContain("Save entry");
    expect(text).toContain("Show today's question");
    expect(text).toContain("Save server URL");
    expect(text).toContain("Delete my account and data");
    // Screen titles are the product's navigation contract.
    expect(screenOptions(root, "Entry")).toEqual({ title: "Today" });
    expect(screenOptions(root, "History")).toEqual({ title: "History" });
    expect(screenOptions(root, "Insights")).toEqual({ title: "Patterns" });
    expect(screenOptions(root, "Question")).toEqual({ title: "One question" });
    expect(screenOptions(root, "Settings")).toEqual({ title: "Settings" });
    expect(screenOptions(root, "Privacy")).toEqual({ title: "Privacy" });
    // Crisis help is a first-class screen: offline, always one hop away.
    expect(screenOptions(root, "Crisis")).toEqual({ title: "Get help" });
  });

  it("a session-context re-render keeps the shell screens' component identity (no remount)", async () => {
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { authStatus: "loggedIn", unlocked: true };
    const root = await render(<AppNavigator />);
    await flush();
    const componentOf = (name: string): unknown =>
      (root.root
        .findAll((n) => (n.props as { name?: unknown } | undefined)?.name === name)
        .find(() => true)!.props as { component?: unknown }).component;
    const before = ["History", "Insights", "Question", "Settings"].map((n) => [n, componentOf(n)] as const);
    // Any session/active-days context change re-renders AppNavigator; a
    // fresh wrapped identity per render would REMOUNT the screen and destroy
    // its local state (e.g. a History edit draft mid-typing).
    sessionState = { authStatus: "loggedIn", unlocked: true, unlockDays: 45 };
    const { act } = await import("./helpers/rtr");
    await act(async () => {
      root.update(<AppNavigator />);
    });
    await flush();
    for (const [name, component] of before) {
      expect(componentOf(name)).toBe(component);
    }
  });

  it("a just-registered account lands on onboarding FIRST, before the journal", async () => {
    const { queueOnboarding } = await import("../src/onboarding");
    queueOnboarding(); // what LoginScreen does on a successful register
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { authStatus: "loggedIn", unlocked: true };
    const root = await render(<AppNavigator />);
    await flush();

    expect(screenNames(root)).toEqual([
      "Onboarding", "Entry", "History", "Insights", "Question", "Settings", "TherapistShare", "Privacy", "Crisis",
    ]);
    expect(screenOptions(root, "Onboarding")).toEqual({ headerShown: false });
    // The first panel is what a brand-new account actually sees.
    expect(textOf(root)).toContain("Write each day");
  });

  it("a plain login or unlock never sees onboarding (the pending flag is one-shot)", async () => {
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { authStatus: "loggedIn", unlocked: true };
    const root = await render(<AppNavigator />);
    await flush();
    expect(screenNames(root)).not.toContain("Onboarding");
    // Even after a previous registration queued it, the flag was consumed
    // by that first transition — re-entering the main flow shows the
    // journal directly.
  });

  it("leaving the main flow resets the onboarding gate (a LATER registration can show it again)", async () => {
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { authStatus: "loggedIn", unlocked: true };
    const root = await render(<AppNavigator />);
    await flush();
    expect(screenNames(root)).not.toContain("Onboarding");

    // Sign out: the main branch unmounts; the gate re-arms.
    vault.lock();
    sessionState = { authStatus: "loggedOut", unlocked: false };
    const { act } = await import("./helpers/rtr");
    await act(async () => {
      root.update(<AppNavigator />);
    });
    await flush();
    expect(screenNames(root)).toEqual(["Login", "Crisis"]);

    // A new registration on the same device queues onboarding again.
    const { queueOnboarding } = await import("../src/onboarding");
    queueOnboarding();
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { authStatus: "loggedIn", unlocked: true };
    await act(async () => {
      root.update(<AppNavigator />);
    });
    await flush();
    expect(screenNames(root)[0]).toBe("Onboarding");
  });
});
