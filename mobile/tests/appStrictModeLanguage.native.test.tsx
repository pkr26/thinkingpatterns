/** Exported App gate under the installed React StrictMode lifecycle.
 * Declared language-module Promise seam; navigator presence is public output.
 * No actual native store, authentication, backend or hardware timing claim. */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { AppState, View } from "react-native";
import storage from "./helpers/storageMock";

const seams = vi.hoisted(() => ({
  language: vi.fn<() => Promise<void>>(),
}));
vi.mock("../src/languagePref", () => ({ applyStoredLanguageChoice: seams.language }));
vi.mock("../src/nativeFeatures", () => ({ startNotificationPressRouting: async () => null }));
vi.mock("../src/notificationRoute", () => ({ notifyNavigationReady: () => {} }));
vi.mock("../src/navigation", () => ({
  navigationRef: { current: null },
  AppNavigator: () => <View accessibilityLabel="Application navigation is available" />,
}));
vi.mock("../src/store", () => ({ SessionProvider: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("@react-navigation/native", () => ({ NavigationContainer: ({ children }: { children: React.ReactNode }) => children }));
vi.mock("react-native-safe-area-context", () => ({ SafeAreaProvider: ({ children }: { children: React.ReactNode }) => children }));
import App from "../App";

let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
const receipts: Array<{ waiting: Promise<void>; release: () => void }> = [];
function receipt() {
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  const row = { waiting, release };
  receipts.push(row);
  return row;
}
function navigationAvailable() {
  return root!.root.findAllByType(View).some(node => node.props.accessibilityLabel === "Application navigation is available");
}
async function drain() {
  for (const row of receipts) row.release();
  await act(async () => { await Promise.allSettled(receipts.map(row => row.waiting)); });
}
beforeEach(() => {
  vi.restoreAllMocks(); storage.__reset(); AppState.currentState = "active";
  receipts.length = 0;
  seams.language.mockReset().mockImplementation(() => receipt().waiting);
});
afterEach(async () => {
  await drain();
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  receipts.length = 0;
  vi.restoreAllMocks();
});

it("a language receipt retired by actual StrictMode cleanup cannot open navigation while reconnect still waits", async () => {
  await act(async () => { root = ReactTestRenderer.create(<React.StrictMode><App /></React.StrictMode>); });
  try {
    // Admission invariant: the installed renderer actually performed setup,
    // cleanup and reconnect. This count is not a runtime mutation oracle.
    if (receipts.length !== 2) throw new Error("SetupError: installed StrictMode did not admit both startup-language operations");
    expect(navigationAvailable()).toBe(false);
    await act(async () => { receipts[0]!.release(); await receipts[0]!.waiting; });
    expect(navigationAvailable(), "A retired startup receipt cannot release the current App language gate").toBe(false);
    await act(async () => { receipts[1]!.release(); await receipts[1]!.waiting; });
    expect(navigationAvailable()).toBe(true);
  } finally { await drain(); }
});
