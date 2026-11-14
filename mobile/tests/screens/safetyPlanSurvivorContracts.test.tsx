import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TextInput, TouchableOpacity } from "react-native";
import { api } from "../../src/api/client";
import { vault } from "../../src/vault";
import { SafetyPlanScreen } from "../../src/screens/SafetyPlanScreen";
import { loadSafetyPlan, loadSafetyPlanDraft } from "../../src/safetyPlan";
import { accountStorageKey } from "../../src/accountStorage";
import { installLocalDataKey, waitLocalWriteCommits, __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { setSecureStoreBackend } from "../../src/secureStore";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const USER = "c".repeat(32), KEY = Buffer.alloc(32, 17);
let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
let releases: Array<() => void> = [];
async function flush() {
  await act(async () => { for (let turn = 0; turn < 100; turn++) await Promise.resolve(); });
}
function gate() {
  let release!: () => void;
  const promise = new Promise<void>(resolve => { release = resolve; });
  releases.push(release); return { promise, release };
}
async function edit(value: string) {
  const field = root!.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "My warning signs");
  expect(field).toBeDefined();
  await act(async () => field!.props.onChangeText(value));
  await flush();
}
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); releases = [];
  runTestControl(setSecureStoreBackend, null);
  runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock();
  await api.setSession("safety-plan-current-bearer", USER, "safety-plan-current");
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(KEY) }, USER);
  installLocalDataKey(USER, vault.get().dataKey);
  vi.useFakeTimers();
});
afterEach(async () => {
  for (const release of releases) release(); await flush();
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  await flush(); await waitLocalWriteCommits();
  vi.useRealTimers(); vault.lock(); await api.clearSession(); vi.restoreAllMocks();
});

it("a later edit remains recoverable when an admitted draft write outlives Save and one native retry refuses", async () => {
  await act(async () => { root = ReactTestRenderer.create(<SafetyPlanScreen navigation={{ goBack() {}, navigate() {} }} />); });
  await flush();
  const firstDraft = gate(), savedPlan = gate(), write = storage.setItem;
  let draftStarted = false, saveStarted = false, draftWrites = 0;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === accountStorageKey.safetyPlanDraft(USER)) {
      draftWrites++;
      if (draftWrites === 1) { draftStarted = true; await firstDraft.promise; }
      else if (draftWrites === 2) throw new Error("Native draft space temporarily unavailable");
    }
    if (key === accountStorageKey.safetyPlan(USER)) { saveStarted = true; await savedPlan.promise; }
    await write(key, value);
  });
  await edit("The explicitly saved earlier plan");
  await act(async () => { await vi.advanceTimersByTimeAsync(300); });
  expect(draftStarted, "an admitted autosave must reach encrypted native persistence").toBe(true);
  const save = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save my safety plan");
  expect(save).toBeDefined();
  await act(async () => { void save!.props.onPress(); }); await flush();
  expect(saveStarted, "the explicit save uses its independent encrypted slot").toBe(true);
  await edit("The newer unfinished plan must remain recoverable");
  savedPlan.release(); await flush();
  await act(async () => { await vi.advanceTimersByTimeAsync(300); });
  firstDraft.release(); await flush(); await waitLocalWriteCommits(); await flush();
  expect((await loadSafetyPlan(KEY, USER))?.warningSigns).toBe("The explicitly saved earlier plan");
  expect((await loadSafetyPlanDraft(KEY, USER))?.warningSigns).toBe("The newer unfinished plan must remain recoverable");
});
