import React from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AppState, View } from "react-native";
import { act, render } from "./helpers/rtr";
import { emitAppState } from "./helpers/rnMock";

const seams = vi.hoisted(() => ({
  language: vi.fn<() => Promise<void>>(),
  routing: vi.fn<() => Promise<(() => void) | null>>(),
  ready: vi.fn(),
  stop: vi.fn(),
}));
vi.mock("../src/languagePref", () => ({ applyStoredLanguageChoice: seams.language }));
vi.mock("../src/nativeFeatures", () => ({ startNotificationPressRouting: seams.routing }));
vi.mock("../src/notificationRoute", () => ({ notifyNavigationReady: seams.ready }));
vi.mock("../src/navigation", () => ({
  navigationRef: { current: null },
  AppNavigator: () => <View testID="navigator" />,
}));
vi.mock("../src/store", () => ({ SessionProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@react-navigation/native", () => ({ NavigationContainer: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("react-native-safe-area-context", () => ({ SafeAreaProvider: ({ children }: { children: React.ReactNode }) => children }));
import { darkTheme } from "../src/theme";

const roots: Awaited<ReturnType<typeof render>>[] = [];
const mount = async () => { const { default: App } = await import("../App"); const root = await render(<App />); roots.push(root); return root; };
function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
beforeEach(() => {
  AppState.currentState = "active";
  AppState.addEventListener.mockClear();
  seams.language.mockReset().mockResolvedValue();
  seams.routing.mockReset().mockResolvedValue(seams.stop);
  seams.ready.mockClear(); seams.stop.mockClear();
});
afterEach(async () => { await act(async () => { for (const root of roots.splice(0)) root.unmount(); }); });
const shield = (root: Awaited<ReturnType<typeof render>>) => root.root.findAllByType(View).find(node => node.props.accessibilityLabel === "Fathom");

describe("application lifecycle", () => {
  it("waits for the stored language before mounting navigation", async () => {
    AppState.currentState = "inactive";
    const gate = deferred<void>(); seams.language.mockReturnValue(gate.promise);
    const root = await mount();
    const overlay = shield(root)!;
    expect(overlay).toBeDefined();
    expect(Object.assign({}, ...overlay.props.style)).toEqual({ position: "absolute", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: darkTheme.colors.bg });
    expect(root.root.findAllByType(View).some(n => n.props.testID === "navigator")).toBe(false);
    await act(async () => { gate.resolve(); });
    expect(root.root.findAllByType(View).some(n => n.props.testID === "navigator")).toBe(true);
    expect(seams.language).toHaveBeenCalledTimes(1);
  });
  it.each(["background", "inactive", "unknown"])("shields %s and restores the app when active", async state => {
    const root = await mount(); expect(shield(root)).toBeUndefined();
    await act(async () => emitAppState(state));
    const overlay = shield(root)!;
    expect(overlay).toBeDefined();
    expect(Object.assign({}, ...overlay.props.style)).toEqual({ position: "absolute", top: 0, right: 0, bottom: 0, left: 0, backgroundColor: darkTheme.colors.bg });
    expect(overlay.props).toMatchObject({ pointerEvents: "auto", accessibilityViewIsModal: true, importantForAccessibility: "yes" });
    await act(async () => emitAppState("active")); expect(shield(root)).toBeUndefined();
  });
  it("starts shielded if first launched while inactive", async () => {
    AppState.currentState = "inactive"; expect(shield(await mount())).toBeDefined();
  });
  it("unsubscribes app state and notification routing at unmount", async () => {
    const root = await mount();
    expect(seams.routing).toHaveBeenCalledTimes(1);
    const subscription = AppState.addEventListener.mock.results[0]!.value;
    await act(async () => root.unmount());
    expect(subscription.remove).toHaveBeenCalledTimes(1); expect(seams.stop).toHaveBeenCalledTimes(1);
  });
  it("disposes a notification subscription arriving after unmount", async () => {
    const gate = deferred<(() => void) | null>(); seams.routing.mockReturnValue(gate.promise);
    const root = await mount(); await act(async () => root.unmount());
    await act(async () => gate.resolve(seams.stop)); expect(seams.stop).toHaveBeenCalledTimes(1);
  });
  it("tolerates an unavailable notification module", async () => {
    seams.routing.mockResolvedValue(null); const root = await mount();
    expect(root.root.findAllByType(View).some(n => n.props.testID === "navigator")).toBe(true);
    await act(async () => root.unmount()); expect(seams.stop).not.toHaveBeenCalled();
  });
  it("does not dispose an active subscription before unmount", async () => {
    await mount(); expect(seams.stop).not.toHaveBeenCalled();
  });
  it("stays unmounted when stored language arrives after shutdown", async () => {
    const gate = deferred<void>(); seams.language.mockReturnValue(gate.promise);
    const root = await mount(); await act(async () => root.unmount());
    await act(async () => gate.resolve());
    expect(root.toJSON()).toBeNull(); expect(seams.stop).toHaveBeenCalledTimes(1);
  });
  it("tolerates an unavailable subscription resolving after unmount", async () => {
    const gate = deferred<(() => void) | null>(); seams.routing.mockReturnValue(gate.promise);
    const root = await mount(); await act(async () => root.unmount());
    await act(async () => gate.resolve(null)); expect(seams.stop).not.toHaveBeenCalled();
  });
});
