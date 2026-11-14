import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TouchableOpacity } from "react-native";
import { api } from "../../src/api/client";
import { vault } from "../../src/vault";
import { OnboardingScreen } from "../../src/screens/OnboardingScreen";
import { accountStorageKey } from "../../src/accountStorage";
import { installLocalDataKey, __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { setSecureStoreBackend } from "../../src/secureStore";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "a".repeat(32), OTHER = "b".repeat(32);
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let releases: Array<() => void> = [];
const navigation = () => ({ navigate: vi.fn(), replace: vi.fn() });
async function flush() {
  await act(async () => { for (let turn = 0; turn < 100; turn++) await Promise.resolve(); });
}
async function mount(nav: ReturnType<typeof navigation>) {
  await act(async () => { root = ReactTestRenderer.create(<OnboardingScreen navigation={nav} />); });
  await flush();
}
async function press(label: string) {
  const button = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === label);
  expect(button, `public onboarding action: ${label}`).toBeDefined();
  expect(button!.props.disabled).not.toBe(true);
  await act(async () => { void button!.props.onPress(); });
  await flush();
}
async function lastPanel() {
  await press("Continue to panel 2 of 3");
  await press("Continue to panel 3 of 3");
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  releases.push(release);
  return { promise, release };
}
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); releases = [];
  runTestControl(setSecureStoreBackend, null);
  runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock();
  await api.setSession("onboarding-current-bearer", USER, "onboarding-current");
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 3) }, USER);
  installLocalDataKey(USER, vault.get().dataKey);
});
afterEach(async () => {
  for (const release of releases) release(); await flush();
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vault.lock(); await api.clearSession(); vi.restoreAllMocks();
});

it("a completion's account lookup cannot acknowledge a route that already unmounted", async () => {
  const nav = navigation(); await mount(nav); await lastPanel();
  const held = gate(), read = storage.getItem; let reached = false, armed = true;
  vi.spyOn(storage, "getItem").mockImplementation(async key => {
    const value = await read(key);
    if (armed && key === "@mindpattern/user_id") { armed = false; reached = true; await held.promise; }
    return value;
  });
  await press("I understand — start writing"); expect(reached).toBe(true);
  await act(async () => { root!.unmount(); root = undefined; });
  held.release(); await flush();
  expect(await read(accountStorageKey.onboardingSeen(USER))).toBeNull();
  expect(nav.replace).not.toHaveBeenCalled();
});

it.each(["unmount", "navigation replacement", "session replacement", "vault owner replacement"] as const)(
  "an acknowledged completion stays with its original %s lifetime", async retirement => {
    const nav = navigation(); await mount(nav); await lastPanel();
    const held = gate(), write = storage.setItem; let reached = false;
    let adoption: ReturnType<typeof api.setSession> | undefined;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      await write(key, value);
      if (key === accountStorageKey.onboardingSeen(USER)) { reached = true; await held.promise; }
    });
    await press("I understand — start writing"); expect(reached).toBe(true);
    if (retirement === "unmount") await act(async () => { root!.unmount(); root = undefined; });
    else if (retirement === "navigation replacement") {
      await act(async () => root!.update(<OnboardingScreen navigation={navigation()} />));
    } else if (retirement === "session replacement") {
      adoption = api.setSession("onboarding-replacement-bearer", USER, "onboarding-replacement");
      await flush();
    } else await act(async () => vault.unlock({
      masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 4), dataKey: Buffer.alloc(32, 5),
    }, OTHER));
    nav.replace.mockClear(); held.release(); await flush(); await adoption;
    expect(nav.replace).not.toHaveBeenCalled();
  },
);

it("a vault belonging to a different account cannot acknowledge the current login's onboarding", async () => {
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 4), dataKey: Buffer.alloc(32, 5) }, OTHER);
  const nav = navigation(); await mount(nav); await lastPanel();
  await press("I understand — start writing");
  expect(await storage.getItem(accountStorageKey.onboardingSeen(USER))).toBeNull();
  expect(nav.replace).not.toHaveBeenCalled();
});
