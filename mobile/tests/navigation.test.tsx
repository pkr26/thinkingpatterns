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
const { render, flush, textOf, screenNames, screenOptions } = await import("./helpers/rtr");
const { resetApi } = await import("./helpers/apiMock");
const { vault } = await import("../src/vault");
const { navigationStub } = await import("./helpers/navigationStackMock");

beforeEach(() => {
  resetApi(api as never);
  navigationStub.navigate.mockClear();
  navigationStub.popToTop.mockClear();
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
    // Boot splash visual contract.
    const { expectStyle } = await import("./helpers/rtr");
    expectStyle(root, { flex: 1, backgroundColor: "#0f1115", alignItems: "center", justifyContent: "center" });
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

    expect(screenNames(root)).toEqual(["Entry", "Insights", "Question", "Settings", "Crisis"]);
    const text = textOf(root);
    expect(text).toContain("Save entry");
    expect(text).toContain("Show today's question");
    expect(text).toContain("Save server URL");
    expect(text).toContain("Delete my account and data");
    // Screen titles are the product's navigation contract.
    expect(screenOptions(root, "Entry")).toEqual({ title: "Today" });
    expect(screenOptions(root, "Insights")).toEqual({ title: "Patterns" });
    expect(screenOptions(root, "Question")).toEqual({ title: "One question" });
    expect(screenOptions(root, "Settings")).toEqual({ title: "Settings" });
    // Crisis help is a first-class screen: offline, always one hop away.
    expect(screenOptions(root, "Crisis")).toEqual({ title: "Get help" });
  });
});
