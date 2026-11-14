/** Explicit Node concurrent-renderer task profile, run with vitest.history-task.config.ts.
 * The platform/navigation hosts are declared doubles. SessionProvider,
 * AppNavigator, History, HTTP client, vault and crypto execute real code.
 * This proves a current-tree input contract, not physical-device scheduling.
 */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { TouchableOpacity } from "react-native";
import { createAudioPlayer } from "expo-audio";
import { writeFileSync } from "node:fs";
import { AppNavigator } from "../src/navigation";
import { SessionProvider } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { HistoryScreen } from "../src/screens/HistoryScreen";
import { api } from "../src/api/client";
import { vault } from "../src/vault";
import { encryptAudio, encryptEntry } from "../src/crypto/journalCrypto";
import { recordOnboardingSeen } from "../src/onboarding";
import { resetEntryVersionMirrors } from "../src/entryVersions";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { setSecureStoreBackend } from "../src/secureStore";
import { runTestControl } from "./helpers/testControl";
import { emitAppState } from "./helpers/rnMock";
import storage from "./helpers/storageMock";
import * as files from "./helpers/expoFsMock";
import { __resetAudioMock, playerControls } from "./helpers/expoAudioMock";

// Select History from the REAL AppNavigator's admitted screen list. When the
// real gate removes History, render that gate. This does not keep a retired
// route mounted or save a component/callback across the gate transition.
vi.mock("@react-navigation/native-stack", async () => {
  const React = await import("react");
  function flatten(children: React.ReactNode): React.ReactElement<any>[] {
    return React.Children.toArray(children).flatMap((child: any) => child.type === React.Fragment
      ? flatten(child.props.children) : [child]);
  }
  return { createNativeStackNavigator() {
    const Screen = ({ component }: { component?: React.ComponentType<any> }) => component
      ? React.createElement(component, { navigation: { navigate() {} } }) : null;
    const Navigator = ({ children }: { children?: React.ReactNode }) => {
      const screens = flatten(children);
      return screens.find(screen => screen.props.name === "History") ?? screens[0] ?? null;
    };
    return { Navigator, Screen };
  } };
});

type Root = ReturnType<typeof ReactTestRenderer.create>;
type Phase = { phase: string; vaultUnlocked: boolean; historyMounted: number; currentPlayControls?: number };
const USER = "c".repeat(32), KEY = Buffer.alloc(32, 7), ID = "history-current-task-audio";
const AUDIO = Buffer.from("Native current-tree playback bytes");
let root: Root | undefined;
let applicationErrors: unknown[] = [];
let phases: Phase[] = [];
let attachmentReads = 0;
const onApplicationRejection = (error: unknown) => applicationErrors.push(error);
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
async function flush() { await act(async () => { for (let i = 0; i < 80; i++) await Promise.resolve(); }); }
function response(url: string, body: unknown, headers: Record<string, string> = {}) {
  const result = new Response(JSON.stringify(body), { headers: { "Content-Type": "application/json", ...headers } });
  Object.defineProperty(result, "url", { value: url }); return result;
}
function currentPlay() {
  return root!.root.findAllByType(TouchableOpacity).filter(node => node.props.accessibilityLabel === "Play recording");
}
async function mount() {
  await recordOnboardingSeen(USER);
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><SessionProvider><AppNavigator /></SessionProvider></ThemeProvider>); });
  await flush(); expect(currentPlay()).toHaveLength(1); expect(vault.isUnlocked()).toBe(true);
}
beforeEach(async () => {
  applicationErrors = []; phases = []; attachmentReads = 0;
  process.on("unhandledRejection", onApplicationRejection);
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  vi.useRealTimers(); vi.restoreAllMocks(); __resetAudioMock(); storage.__reset(); files.__resetFiles();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(resetEntryVersionMirrors);
  vault.lock(); await api.setSession("history-current-task-bearer", USER, "history-current-task");
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 3), dataKey: Buffer.from(KEY) }, USER);
  const date = "2026-10-05";
  const entry = { id: "server-current-task-audio", client_entry_id: ID, entry_date: date,
    received_at: `${date}T12:00:00Z`, content_version: 1,
    blob: encryptEntry({ dataKey: KEY }, USER, ID, "Current task writing", date, null, undefined, 1).blobB64,
    audio: { attachment_id: "att-current-task", expires_at: "2027-10-29T00:00:00Z" } };
  vi.stubGlobal("fetch", async (url: string) => {
    const path = new URL(url).pathname;
    if (path.includes("/audio/attachments/")) { attachmentReads++; return response(url,
      { blob: encryptAudio({ dataKey: KEY }, USER, ID, AUDIO).blobB64, mime_type: "audio/m4a", duration_seconds: 4 }); }
    if (path.endsWith("/entries")) return response(url, [entry], { "X-Entries-Revision": "1" });
    if (path.endsWith("/insights")) return response(url, { active_days: 5 });
    if (path.endsWith("/meta")) return response(url, { unlock_days: 30 });
    return response(url, {});
  });
});
afterEach(async () => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vault.lock(); await api.clearSession(); await turn();
  process.off("unhandledRejection", onApplicationRejection);
  vi.restoreAllMocks(); vi.unstubAllGlobals();
  expect(applicationErrors, "The owned native application error surface stays empty through cleanup").toEqual([]);
});

it("a current mounted playback input decrypts its recording and a current Stop releases its native player", async () => {
  await mount(); await act(async () => currentPlay()[0]!.props.onPress()); await flush();
  expect(attachmentReads).toBe(1); expect(playerControls.play).toHaveBeenCalledTimes(1);
  const source = vi.mocked(createAudioPlayer).mock.calls[0]?.[0] as { uri: string } | undefined;
  expect(source?.uri, "real authenticated audio reaches the native scratch provider").toBeDefined();
  expect(Buffer.from(await files.readAsStringAsync(source!.uri), "base64")).toEqual(AUDIO);
  const stop = root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Stop playback");
  expect(stop).toBeDefined(); await act(async () => stop!.props.onPress()); await flush();
  expect(playerControls.release).toHaveBeenCalledTimes(1);
  expect(files.__hasFile(source!.uri)).toBe(false);
});

it("a currently mounted History input refuses the retired vault before its navigation commit", async () => {
  await mount();
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = false;
  try {
    await new Promise<void>((resolve, reject) => setImmediate(() => {
      // Arm a DISTINCT input Task before lifecycle retirement enqueues render
      // work. The Task resolves the live tree anew, never a saved responder.
      setImmediate(() => {
        try {
          const current = currentPlay();
          phases.push({ phase: "input-task", vaultUnlocked: vault.isUnlocked(), currentPlayControls: current.length,
            historyMounted: root!.root.findAllByType(HistoryScreen).length });
          if (current.length !== 1) throw new Error("SetupError: native task profile was not admitted before navigation commit");
          expect(vault.isUnlocked()).toBe(false); expect(current[0]!.props.disabled).not.toBe(true);
          current[0]!.props.onPress(); setImmediate(resolve);
        } catch (error) { reject(error); }
      });
      emitAppState("background");
      phases.push({ phase: "retirement-task", vaultUnlocked: vault.isUnlocked(), historyMounted: root!.root.findAllByType(HistoryScreen).length });
    }));
    await turn();
    expect(applicationErrors, "A live current-tree playback input must refuse a retired vault without an asynchronous application error").toEqual([]);
    expect(attachmentReads).toBe(0); expect(playerControls.play).not.toHaveBeenCalled();
  } finally {
    (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
    if (process.env.HISTORY_TASK_WITNESS) writeFileSync(process.env.HISTORY_TASK_WITNESS, JSON.stringify({
      kind: "node-concurrent-current-tree-native-input-task-v1", node: process.version,
      declaredNavigationAndPlatformHostDoubles: true, physicalDeviceSchedulingClaim: false,
      phases, applicationErrors: applicationErrors.map(error => String(error)), attachmentReads,
    }, null, 2));
    await flush();
  }
});
