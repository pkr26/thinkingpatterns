import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { Text, TextInput, TouchableOpacity } from "react-native";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

vi.mock("../../src/recoveryFlow", () => ({ recoverAccountWithKey: vi.fn() }));
const markLoggedIn = vi.fn();
vi.mock("../../src/store", async (importOriginal) => ({
  ...await importOriginal<typeof import("../../src/store")>(),
  useSession: () => ({ markLoggedIn }),
}));
const { recoverAccountWithKey } = await import("../../src/recoveryFlow");
const { RecoveryScreen } = await import("../../src/screens/RecoveryScreen");
const { localWriteScopeEpoch } = await import("../../src/localWriteGuard");
const { vault } = await import("../../src/vault");
let root: ReactTestRenderer.ReactTestRenderer | undefined;
const nav = { navigate: vi.fn() };

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
  vi.mocked(recoverAccountWithKey).mockReset();
  vi.mocked(recoverAccountWithKey).mockResolvedValue({
    userId: "u-77", username: "pat", dataKey: Buffer.alloc(32, 9), ownershipEpoch: localWriteScopeEpoch(),
  });
  vi.spyOn(vault, "unlock").mockImplementation(() => {});
  nav.navigate.mockClear(); markLoggedIn.mockClear();
});
afterEach(async () => {
  if (root) { await act(async () => { root!.unmount(); }); root = undefined; }
  vi.clearAllTimers(); vi.useRealTimers(); vi.restoreAllMocks();
});

it("unmount releases the pending recovery navigation timer", async () => {
  await act(async () => { root = ReactTestRenderer.create(<RecoveryScreen navigation={nav} />); });
  const fill = async (label: string, value: string) => {
    const field = root!.root.findAllByType(TextInput).find(item => item.props.accessibilityLabel === label);
    expect(field, `missing input ${label}`).toBeDefined();
    await act(async () => { field!.props.onChangeText(value); });
  };
  await fill("Username", "pat"); await fill("Recovery key", "a2V5");
  await fill("New password (12+ characters)", "Str0ng-new-pass-2026!");
  await fill("Confirm new password", "Str0ng-new-pass-2026!");
  const button = root!.root.findAllByType(TouchableOpacity).find(item => item.props.accessibilityLabel === "Recover and set new password");
  expect(button).toBeDefined();
  await act(async () => { button!.props.onPress(); await Promise.resolve(); });
  const visible = root!.root.findAllByType(Text).map(item => String(item.props.children)).join(" ");
  expect(visible).toContain("Recovered. Your journal is unlocked");
  expect(markLoggedIn).toHaveBeenCalledTimes(1);
  expect(vi.getTimerCount(), "a successful recovery schedules one navigation timer").toBe(1);
  await act(async () => { root!.unmount(); }); root = undefined;
  expect(vi.getTimerCount(), "unmount must release the pending navigation timer").toBe(0);
  expect(nav.navigate).not.toHaveBeenCalled();
}, 12000);
