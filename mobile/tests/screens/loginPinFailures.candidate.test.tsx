/** Public-flow candidate regressions with real client/secureStore and controlled native boundaries.
 * React Activity cases model a public host; they do not claim native navigation delivery. */
import React, { Activity } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Alert, Text, TextInput, TouchableOpacity, Switch } from "react-native";
import RTR, { act } from "react-test-renderer";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
import { runTestControl } from "../helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { api, getBaseUrl, setBaseUrl } from "../../src/api/client";

vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ markLoggedIn: vi.fn(), refreshActiveDays: vi.fn() }) };
});
import { LoginScreen } from "../../src/screens/LoginScreen";
(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
async function render(ui: React.ReactElement) { let root!: ReturnType<typeof RTR.create>; await act(async () => { root = RTR.create(ui); }); return root; }
async function flush(times = 3) { for (let i = 0; i < times; i++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); }
function inputByPlaceholder(root: ReturnType<typeof RTR.create>, placeholder: string) { const node = root.root.findAllByType(TextInput).find(item => item.props.placeholder === placeholder); if (!node) throw new Error(`SetupError: input ${placeholder} missing`); return node; }
async function typeInto(root: ReturnType<typeof RTR.create>, placeholder: string, value: string) { await act(async () => inputByPlaceholder(root, placeholder).props.onChangeText(value)); }
async function pressLabel(root: ReturnType<typeof RTR.create>, label: string) { const button = root.root.findAllByType(TouchableOpacity).find(item => item.props.accessibilityLabel === label || item.findAllByType(Text).some(text => text.props.children === label)); if (!button || typeof button.props.onPress !== "function") throw new Error(`SetupError: button ${label} missing`); await act(async () => { button.props.onPress(); }); }
const BASE = "@mindpattern/base_url", PIN = "@mindpattern/pinned_origin";
const oldUrl = "http://localhost:8000", nextUrl = "http://localhost:9000";

beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); keychain.__reset();
  runTestControl(setSecureStoreBackend, null); runTestControl(__resetLocalKeyLifecycleForTests);
  expect(await setBaseUrl(oldUrl)).toBeNull();
  await api.confirmCurrentOrigin();
  vi.mocked(Alert.alert).mockClear();
});
afterEach(() => { vi.restoreAllMocks(); runTestControl(setSecureStoreBackend, null); });

it("pin read failure shows unverified rather than suppressing it", async () => {
  expect(await setBaseUrl(nextUrl)).toBeNull();
  expect(await api.originPinChanged()).toBe(true);
  const read = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async (key) => {
    if (key === PIN) throw new Error("injected pin storage unavailable");
    return read(key);
  });
  await expect(api.originPinChanged()).rejects.toThrow("injected pin storage unavailable");
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  await flush();
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  expect(root.root.findAll((node) => node.props.accessibilityLabel === "Warning: server address changed")).toHaveLength(0);
  expect(root.root.findAllByType(Text).some(node => node.props.accessibilityLabel === "Selected server address" && JSON.stringify(node.props.children).includes(nextUrl))).toBe(true);
  await act(async () => root.unmount());
});

it("post-save read failure keeps committed URL but clears credentials and shows unverified", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  await flush();
  await typeInto(root, "password", "a private password");
  await pressLabel(root, "Change server");
  const field = root.root.findAllByType(TextInput).find((node) => node.props.accessibilityLabel === "Selected server address");
  if (!field) throw new Error("SetupError: no editable server field");
  await act(async () => field.props.onChangeText(nextUrl));
  const read = storage.getItem.bind(storage), write = storage.setItem.bind(storage);
  let committed = false, failed = false;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { await write(key, value); if (key === BASE && value === nextUrl) committed = true; });
  vi.spyOn(storage, "getItem").mockImplementation(async (key) => {
    if (key === BASE && committed && !failed) { failed = true; throw new Error("injected post-commit read failure"); }
    return read(key);
  });
  await pressLabel(root, "Save server"); await flush(8);
  expect(committed).toBe(true); expect(failed).toBe(true);
  expect(await getBaseUrl()).toBe(nextUrl);
  expect(vi.mocked(Alert.alert)).not.toHaveBeenCalledWith("Invalid URL", expect.any(String));
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => root.unmount());
});

function deferred<T>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
function host(mode: "visible" | "hidden") { return <Activity mode={mode}><LoginScreen navigation={{ navigate: () => undefined }} /></Activity>; }
function changedWarning(root: ReturnType<typeof RTR.create>) { return root.root.findAll((node) => node.props.accessibilityLabel === "Warning: server address changed").length > 0; }

it("an old Activity-hosted check cannot erase a newer warning", async () => {
  const old = deferred<boolean>();
  vi.spyOn(api, "originPinChanged").mockReturnValueOnce(old.promise).mockResolvedValueOnce(true);
  const root = await render(host("visible")); await flush();
  await act(async () => root.update(host("hidden")));
  await act(async () => root.update(host("visible"))); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => old.resolve(false)); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("an old confirmation cannot dismiss a later Activity-hosted check", async () => {
  const confirmation = deferred<void>();
  vi.spyOn(api, "originPinChanged").mockResolvedValue(true);
  vi.spyOn(api, "confirmCurrentOrigin").mockReturnValue(confirmation.promise);
  const root = await render(host("visible")); await flush();
  expect(changedWarning(root)).toBe(true);
  const trust = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!trust || typeof trust.props.onPress !== "function") throw new Error("SetupError: trust action missing");
  await act(async () => trust.props.onPress());
  await act(async () => root.update(host("hidden")));
  await act(async () => root.update(host("visible"))); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => confirmation.resolve()); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("strict pin reads distinguish absence, unreadable values, and keystore failure while legacy reads stay tolerant", async () => {
  await storage.removeItem(PIN);
  expect(await secureStore.getItemStrict(PIN)).toBeNull();
  for (const damaged of ["", "{bad json", "not-a-ciphertext"]) {
    await storage.setItem(PIN, damaged);
    expect(await secureStore.getItem(PIN)).toBeNull();
    await expect(secureStore.getItemStrict(PIN)).rejects.toThrow();
  }
  await api.confirmCurrentOrigin();
  runTestControl(setSecureStoreBackend, null); // clear cached device key
  keychain.__failReads(true);
  expect(await secureStore.getItem(PIN)).toBeNull();
  await expect(secureStore.getItemStrict(PIN)).rejects.toThrow();
  keychain.__failReads(false);
});

it("trusting a verified changed origin updates the real pin and dismisses the warning", async () => {
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  expect(changedWarning(root)).toBe(true);
  const trust = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!trust || typeof trust.props.onPress !== "function") throw new Error("SetupError: trust action missing");
  await act(async () => trust.props.onPress()); await flush(8);
  expect(await api.originPinChanged()).toBe(false);
  expect(changedWarning(root)).toBe(false);
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(false);
  await act(async () => root.unmount());
});

it("a stale check after a real origin change cannot replace the newer verification", async () => {
  const old = deferred<boolean>();
  vi.spyOn(api, "originPinChanged").mockReturnValueOnce(old.promise);
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await act(async () => { expect(await setBaseUrl(nextUrl)).toBeNull(); }); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => old.resolve(false)); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("a failed trust confirmation preserves the earlier warning and marks verification unknown", async () => {
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  expect(changedWarning(root)).toBe(true);
  const trust = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!trust || typeof trust.props.onPress !== "function") throw new Error("SetupError: trust action missing");
  vi.spyOn(api, "confirmCurrentOrigin").mockRejectedValueOnce(new Error("injected write failure"));
  await act(async () => trust.props.onPress()); await flush();
  expect(changedWarning(root)).toBe(true);
  expect(root.root.findAllByType(Text).some(node => Array.isArray(node.props.children) && node.props.children.includes("A different server was detected earlier. Its current status could not be verified."))).toBe(true);
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => root.unmount());
});

it("held real server save fences stale credential edits, submit, and duplicate saves", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old secret");
  await pressLabel(root, "Change server");
  const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
  if (!field) throw new Error("SetupError: no editable server field");
  await act(async () => field.props.onChangeText(nextUrl));
  const oldPassword = inputByPlaceholder(root, "password");
  const oldEdit = oldPassword.props.onChangeText, oldSubmit = oldPassword.props.onSubmitEditing;
  const save = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save server");
  if (!save) throw new Error("SetupError: no save button");
  const gate = deferred<void>(), write = storage.setItem.bind(storage); let writes = 0;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === BASE && value === nextUrl) { writes++; await gate.promise; }
    await write(key, value);
  });
  const login = vi.spyOn(api, "login");
  await act(async () => save.props.onPress()); await flush();
  expect(writes).toBe(1);
  expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
  expect(field.props.editable).toBe(false);
  await act(async () => { oldEdit("new secret typed too late"); oldSubmit(); field.props.onChangeText("http://localhost:9999"); save.props.onPress(); });
  expect(field.props.value).toBe(nextUrl);
  expect(login).not.toHaveBeenCalled(); expect(writes).toBe(1);
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  await act(async () => gate.resolve()); await flush(8);
  expect(await getBaseUrl()).toBe(nextUrl);
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  await act(async () => root.unmount());
});

it("a rejected server save releases the fence and a subsequent save can succeed", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "password", "secret to clear"); await pressLabel(root, "Change server");
  const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
  if (!field) throw new Error("SetupError: no editable server field");
  await act(async () => field.props.onChangeText(nextUrl));
  const write = storage.setItem.bind(storage); let attempts = 0;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === BASE && value === nextUrl && ++attempts === 1) throw new Error("injected storage write failure");
    await write(key, value);
  });
  await pressLabel(root, "Save server"); await flush(8);
  expect(vi.mocked(Alert.alert)).toHaveBeenCalledWith("Could not save server", expect.any(String));
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  await pressLabel(root, "Save server"); await flush(8);
  expect(attempts).toBe(2); expect(await getBaseUrl()).toBe(nextUrl);
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  await act(async () => root.unmount());
});

it("credentials cannot be entered or submitted before an initial pin check resolves", async () => {
  const pin = deferred<boolean>(); vi.spyOn(api, "originPinChanged").mockReturnValueOnce(pin.promise);
  const login = vi.spyOn(api, "login");
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice");
  const password = inputByPlaceholder(root, "password");
  expect(password.props.editable).toBe(false);
  await act(async () => { password.props.onChangeText("not admitted yet"); password.props.onSubmitEditing(); });
  expect(inputByPlaceholder(root, "password").props.value).toBe(""); expect(login).not.toHaveBeenCalled();
  await act(async () => pin.resolve(false)); await flush();
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  await act(async () => root.unmount());
});

it("a user can abandon a stalled check, and its late completion cannot erase uncertainty", async () => {
  const pin = deferred<boolean>(); vi.spyOn(api, "originPinChanged").mockReturnValueOnce(pin.promise);
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
  await pressLabel(root, "Continue without verification"); await flush();
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => pin.resolve(false)); await flush();
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => root.unmount());
});

it("retry supersedes a pending check and a later completion cannot replace the new result", async () => {
  const pin = deferred<boolean>(); vi.spyOn(api, "originPinChanged").mockReturnValueOnce(pin.promise).mockResolvedValueOnce(true);
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await pressLabel(root, "Retry server check"); await flush();
  expect(changedWarning(root)).toBe(true); expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  await act(async () => pin.resolve(false)); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("a committed save with a stalled post-save read can be explicitly left unverified", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "password", "secret to clear"); await pressLabel(root, "Change server");
  const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
  if (!field) throw new Error("SetupError: no editable server field");
  await act(async () => field.props.onChangeText(nextUrl));
  const gate = deferred<void>(), read = storage.getItem.bind(storage), write = storage.setItem.bind(storage);
  let committed = false, held = false;
  vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => { await write(key, value); if (key === BASE && value === nextUrl) committed = true; });
  vi.spyOn(storage, "getItem").mockImplementation(async (key) => { if (key === BASE && committed && !held) { held = true; await gate.promise; } return read(key); });
  await pressLabel(root, "Save server"); await flush(8);
  expect(committed).toBe(true); expect(held).toBe(true);
  expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
  await pressLabel(root, "Continue without verification"); await flush();
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => gate.resolve()); await flush();
  expect(await getBaseUrl()).toBe(nextUrl);
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => root.unmount());
});

it("an old verification cannot release the fence for a newer in-flight server write", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  const firstReadGate = deferred<void>(), secondWriteGate = deferred<void>(), read = storage.getItem.bind(storage), write = storage.setItem.bind(storage);
  try {
    await flush();
    await pressLabel(root, "Change server");
    const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
    if (!field) throw new Error("SetupError: no editable server field");
    await act(async () => field.props.onChangeText(nextUrl));
    const secondUrl = "http://localhost:9100"; let firstCommitted = false, firstReadHeld = false, secondWriteHeld = false;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === BASE && value === secondUrl) { secondWriteHeld = true; await secondWriteGate.promise; }
      await write(key, value); if (key === BASE && value === nextUrl) firstCommitted = true;
    });
    vi.spyOn(storage, "getItem").mockImplementation(async (key) => {
      if (key === BASE && firstCommitted && !firstReadHeld) { firstReadHeld = true; await firstReadGate.promise; }
      return read(key);
    });
    await pressLabel(root, "Save server"); await flush(8);
    expect(firstReadHeld).toBe(true);
    await act(async () => field.props.onChangeText(secondUrl));
    await pressLabel(root, "Save server"); await flush(8);
    expect(secondWriteHeld).toBe(true);
    await act(async () => firstReadGate.resolve()); await flush();
    expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
    expect(field.props.editable).toBe(false);
    const save = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save server");
    if (!save) throw new Error("SetupError: newer save button missing");
    expect(save.props.disabled).toBe(true);
    expect(save.props.accessibilityState.disabled).toBe(true);
    await act(async () => secondWriteGate.resolve()); await flush(8);
    expect(await getBaseUrl()).toBe(secondUrl);
    expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  } finally {
    firstReadGate.resolve(); secondWriteGate.resolve();
    try { await flush(8); } finally { await act(async () => root.unmount()); }
  }
});

it("a real external origin transition clears the old password after stale trust completion", async () => {
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "password", "old origin secret");
  const confirmation = deferred<void>(); vi.spyOn(api, "confirmCurrentOrigin").mockReturnValueOnce(confirmation.promise);
  const trust = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!trust || typeof trust.props.onPress !== "function") throw new Error("SetupError: trust action missing");
  await act(async () => trust.props.onPress());
  expect(await setBaseUrl("http://localhost:9100")).toBeNull();
  await act(async () => confirmation.resolve()); await flush();
  expect(await getBaseUrl()).toBe("http://localhost:9100");
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("stale trust after an external origin transition also clears registration confirmation", async () => {
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await pressLabel(root, "New here? Create an account");
  await typeInto(root, "password", "old origin secret"); await typeInto(root, "confirm password", "old origin secret");
  const confirmation = deferred<void>(); vi.spyOn(api, "confirmCurrentOrigin").mockReturnValueOnce(confirmation.promise);
  const trust = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!trust || typeof trust.props.onPress !== "function") throw new Error("SetupError: trust action missing");
  await act(async () => trust.props.onPress());
  expect(await setBaseUrl("http://localhost:9100")).toBeNull();
  await act(async () => confirmation.resolve()); await flush();
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(inputByPlaceholder(root, "confirm password").props.value).toBe("");
  await act(async () => root.unmount());
});

it("after a real external origin change an old password cannot enter the submit flow", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old origin secret");
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const salt = vi.spyOn(api, "saltFor").mockRejectedValueOnce(new Error("stop at controlled submit boundary"));
  await pressLabel(root, "Sign in"); await flush(8);
  expect(await getBaseUrl()).toBe(nextUrl);
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(salt).not.toHaveBeenCalled();
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("unverified consent from an old scope cannot authorize a later origin", async () => {
  vi.spyOn(api, "originPinChanged").mockRejectedValueOnce(new Error("injected pin read failure"));
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old unverified secret");
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const salt = vi.spyOn(api, "saltFor").mockRejectedValueOnce(new Error("stop at boundary"));
  await pressLabel(root, "Sign in"); await flush(8);
  expect(salt).not.toHaveBeenCalled(); expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("a retained password edit from an old scope clears instead of appending credentials", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "password", "old origin secret");
  const edit = inputByPlaceholder(root, "password").props.onChangeText;
  expect(await setBaseUrl(nextUrl)).toBeNull();
  await act(async () => edit("old origin secret plus new input")); await flush(8);
  expect(inputByPlaceholder(root, "password").props.value).toBe(""); expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("a real pending own-session adoption does not trigger false external-origin reverification", async () => {
  const pinCheck = vi.spyOn(api, "originPinChanged");
  vi.spyOn(api, "saltFor").mockResolvedValueOnce({ salt: Buffer.alloc(16, 3).toString("base64") });
  vi.spyOn(api, "login").mockResolvedValueOnce({ token: "test-token", user_id: "a".repeat(32) });
  const original = api.setSession.bind(api), gate = deferred<void>();
  let admitted = false, actualSettled = false;
  vi.spyOn(api, "setSession").mockImplementation((...args) => {
    const operation = original(...args); admitted = true;
    return operation.then(async () => { actualSettled = true; await gate.promise; throw new Error("controlled completion after session adoption"); });
  });
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old secret valid until completion");
  const edit = inputByPlaceholder(root, "password").props.onChangeText;
  const checksBefore = pinCheck.mock.calls.length;
  await pressLabel(root, "Sign in");
  await vi.waitFor(() => expect(admitted && actualSettled).toBe(true), { timeout: 10_000, interval: 20 });
  await act(async () => edit("updated input during owned transition")); await flush();
  expect(inputByPlaceholder(root, "password").props.value).toBe("updated input during owned transition");
  expect(pinCheck).toHaveBeenCalledTimes(checksBefore);
  await act(async () => gate.resolve()); await flush(8);
  await act(async () => root.unmount());
});

it("an idle real external origin transition clears the form and starts a new check before another submit", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old origin secret");
  const pin = deferred<boolean>(); vi.spyOn(api, "originPinChanged").mockReturnValue(pin.promise);
  await act(async () => { expect(await setBaseUrl(nextUrl)).toBeNull(); }); await flush();
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
  await act(async () => pin.resolve(true)); await flush();
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("an unmounted screen does not start a pin check after a real scope transition", async () => {
  const check = vi.spyOn(api, "originPinChanged");
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  const calls = check.mock.calls.length;
  await act(async () => root.unmount());
  expect(await setBaseUrl(nextUrl)).toBeNull();
  expect(check).toHaveBeenCalledTimes(calls);
});

it("a held login retires old credentials after an external origin transition without another action", async () => {
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old origin secret");
  const gate = deferred<{ salt: string }>();
  const salt = vi.spyOn(api, "saltFor").mockReturnValueOnce(gate.promise);
  const login = vi.spyOn(api, "login");
  await pressLabel(root, "Sign in"); await flush(); expect(salt).toHaveBeenCalledTimes(1);
  await act(async () => { expect(await setBaseUrl(nextUrl)).toBeNull(); }); await flush();
  await act(async () => gate.resolve({ salt: Buffer.alloc(16, 3).toString("base64") })); await flush(8);
  expect(login).not.toHaveBeenCalled();
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  expect(changedWarning(root)).toBe(true);
  await act(async () => root.unmount());
});

it("a retained Activity login releases its retired attempt and clears credentials", async () => {
  const gate = deferred<{ salt: string }>(); const salt = vi.spyOn(api, "saltFor").mockReturnValueOnce(gate.promise);
  const root = await render(host("visible")); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "old Activity secret");
  await pressLabel(root, "Sign in"); await flush(); expect(salt).toHaveBeenCalledTimes(1);
  await act(async () => root.update(host("hidden")));
  await act(async () => { expect(await setBaseUrl(nextUrl)).toBeNull(); });
  await act(async () => root.update(host("visible"))); await flush();
  await act(async () => gate.resolve({ salt: Buffer.alloc(16, 3).toString("base64") })); await flush(8);
  const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Sign in");
  if (!button) throw new Error("SetupError: no sign-in action");
  expect(button.props.disabled).not.toBe(true);
  expect(inputByPlaceholder(root, "password").props.value).toBe("");
  await act(async () => root.unmount());
});

it("a retired Activity login cannot release a newer pending attempt", async () => {
  const first = deferred<{ salt: string }>(), second = deferred<{ salt: string }>();
  const salt = vi.spyOn(api, "saltFor").mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
  const root = await render(host("visible")); await flush();
  await typeInto(root, "username", "alice"); await typeInto(root, "password", "first secret");
  await pressLabel(root, "Sign in"); await flush(); expect(salt).toHaveBeenCalledTimes(1);
  await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
  await typeInto(root, "password", "newer secret"); await pressLabel(root, "Sign in"); await flush();
  expect(salt).toHaveBeenCalledTimes(2);
  await act(async () => first.resolve({ salt: Buffer.alloc(16, 3).toString("base64") })); await flush(8);
  const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Sign in");
  if (!button) throw new Error("SetupError: no sign-in action");
  expect(button.props.disabled).toBe(true);
  expect(inputByPlaceholder(root, "password").props.value).toBe("newer secret");
  await act(async () => root.unmount());
  await act(async () => second.resolve({ salt: Buffer.alloc(16, 3).toString("base64") })); await flush();
});


it("a retired dispatched registration immediately offers honest sign-in recovery before its response", async () => {
  const gate = deferred<void>(); let requests = 0;
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    requests++; await gate.promise;
    const response = new Response(JSON.stringify({ token: "synthetic-token", user_id: "a".repeat(32), role: "user" }), { status: 200 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const root = await render(host("visible")); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true)); await pressLabel(root, "Create account");
    await vi.waitFor(() => expect(requests).toBe(1), { timeout: 15000, interval: 20 });
    await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again.")).toBe(true);
    expect(requests).toBe(1); await pressLabel(root, "Try signing in");
    expect(root.root.findAllByType(TouchableOpacity).some(node => node.props.accessibilityLabel === "Sign in")).toBe(true);
    await act(async () => gate.resolve()); await flush(8); expect(requests).toBe(1); expect(await api.isLoggedIn()).toBe(false);
  } finally { gate.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it("a retired registration completion cannot release a newer pending registration", async () => {
  const first = deferred<void>(), second = deferred<void>(); let requests = 0;
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    const n = ++requests; await (n === 1 ? first.promise : second.promise);
    const response = new Response(JSON.stringify(n === 1 ? { token: "synthetic-token", user_id: "a".repeat(32), role: "user" } : { detail: "username taken" }), { status: n === 1 ? 200 : 409 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const root = await render(host("visible")); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true)); await pressLabel(root, "Create account");
    await vi.waitFor(() => expect(requests).toBe(1), { timeout: 15000, interval: 20 });
    await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
    await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!"); await pressLabel(root, "Create account");
    await vi.waitFor(() => expect(requests).toBe(2), { timeout: 15000, interval: 20 });
    await act(async () => first.resolve()); await flush(8);
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Create account");
    if (!button) throw new Error("SetupError: no create action");
    expect(button.props.accessibilityState.busy).toBe(true);
    expect(inputByPlaceholder(root, "password").props.value).toBe("Synthetic Passphrase 2026!");
    await act(async () => second.resolve()); await vi.waitFor(() => expect(vi.mocked(Alert.alert)).toHaveBeenCalled(), { timeout: 10000 });
    expect(vi.mocked(Alert.alert)).toHaveBeenCalledWith("Couldn't create account", "That username is already taken. Try another, or sign in instead.");
  } finally { first.resolve(); second.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it("an external transition warns about a dispatched registration without waiting for its response", async () => {
  const gate = deferred<void>(); let requests = 0;
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    requests++; await gate.promise;
    const response = new Response(JSON.stringify({ token: "synthetic-token", user_id: "a".repeat(32), role: "user" }), { status: 200 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true)); await pressLabel(root, "Create account");
    await vi.waitFor(() => expect(requests).toBe(1), { timeout: 15000, interval: 20 });
    await act(async () => { expect(await setBaseUrl(nextUrl)).toBeNull(); }); await flush(8);
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again.")).toBe(true);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
    expect(root.root.findAllByType(TouchableOpacity).some(node => node.props.accessibilityLabel === "Try signing in")).toBe(true);
    await pressLabel(root, "Try signing in");
    expect(await getBaseUrl()).toBe(nextUrl); // Returning to sign-in does not switch servers.
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again. ".trim())).toBe(true);
    expect(requests).toBe(1); expect(await api.isLoggedIn()).toBe(false);
  } finally { gate.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it.each(["edit", "submit"] as const)("a retained %s retires a pending registration on a same-origin external transition", async (action) => {
  const gate = deferred<void>(); let requests = 0;
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    requests++; await gate.promise;
    const response = new Response(JSON.stringify({ token: "synthetic-token", user_id: "a".repeat(32), role: "user" }), { status: 200 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true)); await pressLabel(root, "Create account");
    await vi.waitFor(() => expect(requests).toBe(1), { timeout: 15000, interval: 20 });
    const retained = inputByPlaceholder(root, "password");
    await act(async () => { const change = setBaseUrl("http://localhost:8000/new"); if (action === "edit") retained.props.onChangeText("stale retained edit"); else retained.props.onSubmitEditing(); expect(await change).toBeNull(); }); await flush(8);
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again.")).toBe(true);
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Create account");
    if (!button) throw new Error("SetupError: no create action"); expect(button.props.accessibilityState.busy).toBe(false);
    expect(requests).toBe(1);
  } finally { gate.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it("a successful registration retired during held session adoption retains recovery guidance", async () => {
  let requests = 0, adopted = false; const gate = deferred<void>();
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    requests++; const response = new Response(JSON.stringify({ token: "synthetic-token", user_id: "a".repeat(32), role: "user" }), { status: 200 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const original = api.setSession.bind(api);
  vi.spyOn(api, "setSession").mockImplementation((...args) => original(...args).then(async () => { adopted = true; await gate.promise; }));
  const root = await render(host("visible")); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true)); await pressLabel(root, "Create account");
    await vi.waitFor(() => { expect(requests).toBe(1); expect(adopted).toBe(true); }, { timeout: 15000, interval: 20 });
    await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again.")).toBe(true);
    await act(async () => gate.resolve()); await flush(8);
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again.")).toBe(true);
  } finally { gate.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it("an external transition during held successful registration adoption retains recovery guidance", async () => {
  let requests = 0, adopted = false; const gate = deferred<void>();
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    requests++; const response = new Response(JSON.stringify({ token: "synthetic-token", user_id: "a".repeat(32), role: "user" }), { status: 200 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const original = api.setSession.bind(api);
  vi.spyOn(api, "setSession").mockImplementation((...args) => original(...args).then(async () => { adopted = true; await gate.promise; }));
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true)); await pressLabel(root, "Create account");
    await vi.waitFor(() => { expect(requests).toBe(1); expect(adopted).toBe(true); }, { timeout: 15000, interval: 20 });
    await act(async () => { expect(await setBaseUrl(nextUrl)).toBeNull(); }); await flush(8);
    expect(root.root.findAllByType(Text).some(node => node.props.children === "The previous account creation may have completed on the server used for that attempt. Return to that server and try signing in there before creating the account again.")).toBe(true);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
    await pressLabel(root, "Try signing in"); expect(await getBaseUrl()).toBe(nextUrl); expect(requests).toBe(1);
  } finally { gate.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it("a retained pre-hide sign-in callback cannot reuse cleared credentials", async () => {
  const gate = deferred<{ salt: string }>();
  const salt = vi.spyOn(api, "saltFor").mockReturnValueOnce(gate.promise).mockRejectedValueOnce(new Error("controlled second submit boundary"));
  const root = await render(host("visible")); await flush();
  try {
    await typeInto(root, "username", "alice"); await typeInto(root, "password", "old Activity secret");
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Sign in");
    if (!button) throw new Error("SetupError: no sign-in action"); const retained = button.props.onPress;
    await act(async () => { void retained(); }); await flush(); expect(salt).toHaveBeenCalledTimes(1);
    await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
    await act(async () => { void retained(); }); await flush(8);
    expect(salt).toHaveBeenCalledTimes(1);
    await typeInto(root, "password", "new Activity secret"); await pressLabel(root, "Sign in"); await flush(8);
    expect(salt).toHaveBeenCalledTimes(2);
  } finally { gate.resolve({ salt: Buffer.alloc(16, 3).toString("base64") }); await act(async () => root.unmount()); }
});

it("retained pre-hide registration and edit callbacks cannot recreate cleared input or retry", async () => {
  const gate = deferred<void>(); let requests = 0;
  vi.stubGlobal("fetch", async (url: string | URL, init?: RequestInit) => {
    const value = String(url); if (!new URL(value).pathname.endsWith("/auth/register") || init?.method !== "POST") throw new Error("SetupError: unexpected transport");
    requests++; await gate.promise; const response = new Response(JSON.stringify({ token: "synthetic-token", user_id: "a".repeat(32), role: "user" }), { status: 200 }); Object.defineProperty(response, "url", { value }); return response;
  });
  const root = await render(host("visible")); await flush();
  try {
    await pressLabel(root, "New here? Create an account"); await typeInto(root, "username", "alice"); await typeInto(root, "password", "Synthetic Passphrase 2026!"); await typeInto(root, "confirm password", "Synthetic Passphrase 2026!");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true));
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Create account");
    if (!button) throw new Error("SetupError: no create action");
    const retainedSubmit = button.props.onPress, retainedEdit = inputByPlaceholder(root, "password").props.onChangeText;
    await act(async () => { void retainedSubmit(); }); await vi.waitFor(() => expect(requests).toBe(1), { timeout: 15000, interval: 20 });
    await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
    await act(async () => { retainedEdit("old retained secret"); void retainedSubmit(); }); await flush(8);
    expect(inputByPlaceholder(root, "password").props.value).toBe(""); expect(requests).toBe(1);
  } finally { gate.resolve(); await act(async () => root.unmount()); vi.unstubAllGlobals(); }
}, 30_000);

it("a revealed checking screen exposes fresh controls while rejecting a retained old control", async () => {
  const pin = deferred<boolean>(); vi.spyOn(api, "originPinChanged").mockReturnValue(pin.promise);
  const root = await render(host("visible")); await flush();
  const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Continue without verification");
  if (!button) throw new Error("SetupError: no initial continue action"); const stale = button.props.onPress;
  await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
  await act(async () => stale()); await flush();
  expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
  await pressLabel(root, "Continue without verification"); await flush();
  expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => pin.resolve(false)); await flush();
  expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(true);
  await act(async () => root.unmount());
});

it("retained pre-hide server editor callbacks cannot replace the newer visible draft or save it", async () => {
  const root = await render(host("visible")); await flush();
  const change = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Change server");
  if (!change) throw new Error("SetupError: no change-server action"); const staleChange = change.props.onPress;
  await pressLabel(root, "Change server");
  const draft = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
  const save = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Save server");
  if (!draft || !save) throw new Error("SetupError: no server editor");
  await act(async () => draft.props.onChangeText("http://localhost:9000"));
  const staleEdit = draft.props.onChangeText, staleSave = save.props.onPress;
  await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
  const fresh = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
  if (!fresh) throw new Error("SetupError: no revealed server editor");
  await act(async () => fresh.props.onChangeText("http://localhost:9100"));
  await act(async () => { staleEdit("http://localhost:9200"); staleSave(); staleChange(); }); await flush(8);
  expect(fresh.props.value).toBe("http://localhost:9100"); expect(await getBaseUrl()).toBe(oldUrl);
  await pressLabel(root, "Save server"); await flush(8); expect(await getBaseUrl()).toBe("http://localhost:9100");
  await act(async () => root.unmount());
});

it("a retained pre-hide trust callback cannot confirm the origin, while a fresh callback can", async () => {
  expect(await setBaseUrl(nextUrl)).toBeNull();
  const root = await render(host("visible")); await flush();
  const old = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!old || typeof old.props.onPress !== "function") throw new Error("SetupError: no trust action");
  const stale = old.props.onPress; const confirmation = vi.spyOn(api, "confirmCurrentOrigin");
  await act(async () => root.update(host("hidden"))); await act(async () => root.update(host("visible"))); await flush();
  await act(async () => stale()); await flush();
  expect(confirmation).not.toHaveBeenCalled(); expect(await api.originPinChanged()).toBe(true);
  const fresh = root.root.findAllByType(Text).find(node => node.props.children === "I trust this server");
  if (!fresh || typeof fresh.props.onPress !== "function") throw new Error("SetupError: no revealed trust action");
  await act(async () => fresh.props.onPress()); await flush(8);
  expect(confirmation).toHaveBeenCalledTimes(1); expect(await api.originPinChanged()).toBe(false);
  await act(async () => root.unmount());
});


it("retires the earlier session callback when a later sign-in begins", async () => {
  const callbacks: Array<() => boolean> = [];
  vi.spyOn(api, "saltFor").mockResolvedValue({ salt: Buffer.alloc(16, 3).toString("base64") });
  vi.spyOn(api, "login").mockResolvedValue({ token: "synthetic-token", user_id: "a".repeat(32) });
  vi.spyOn(api, "setSession").mockImplementation(async (_token, _userId, _username, options) => {
    if (typeof options?.stillCurrent !== "function") throw new Error("SetupError: missing session callback");
    callbacks.push(options.stillCurrent);
    throw new Error("controlled session storage failure");
  });
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  try {
    await flush();
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "synthetic login password");
    await pressLabel(root, "Sign in");
    await vi.waitFor(() => expect(callbacks).toHaveLength(1), { timeout: 10_000, interval: 20 });
    await flush(8);
    expect(callbacks[0]()).toBe(true);
    await pressLabel(root, "Sign in");
    await vi.waitFor(() => expect(callbacks).toHaveLength(2), { timeout: 10_000, interval: 20 });
    await flush(8);
    expect(callbacks[0]()).toBe(false);
    expect(callbacks[1]()).toBe(true);
  } finally {
    await act(async () => root.unmount());
  }
}, 30_000);


it("an old Activity pin-check rejection cannot replace a newer verified warning", async () => {
  let rejectOld!: (reason: Error) => void;
  const old = new Promise<boolean>((_resolve, reject) => { rejectOld = reject; });
  vi.spyOn(api, "originPinChanged").mockReturnValueOnce(old).mockResolvedValueOnce(true);
  const root = await render(host("visible"));
  let rejected = false;
  try {
    await flush();
    await act(async () => root.update(host("hidden")));
    await act(async () => root.update(host("visible")));
    await flush();
    expect(changedWarning(root)).toBe(true);
    expect(root.root.findAllByType(Text).some(node => node.props.children === "I trust this server")).toBe(true);
    await act(async () => { rejected = true; rejectOld(new Error("controlled old pin check failure")); });
    await flush();
    expect(changedWarning(root)).toBe(true);
    expect(root.root.findAllByType(Text).some(node => node.props.children === "I trust this server")).toBe(true);
    expect(root.root.findAll((node) => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.")).toBe(false);
  } finally {
    if (!rejected) { await act(async () => { rejectOld(new Error("controlled cleanup")); }); await flush(); }
    await act(async () => root.unmount());
  }
});


it("a pending retired session callback cannot revive when a newer Activity login starts", async () => {
  const callbacks: Array<() => boolean> = [];
  const rejects: Array<(reason: Error) => void> = [];
  const submitted: Promise<void>[] = [];
  const unexpected: unknown[] = [];
  vi.spyOn(api, "saltFor").mockResolvedValue({ salt: Buffer.alloc(16, 3).toString("base64") });
  vi.spyOn(api, "login").mockResolvedValue({ token: "synthetic-token", user_id: "a".repeat(32) });
  vi.spyOn(api, "setSession").mockImplementation((_token, _userId, _username, options) => {
    if (typeof options?.stillCurrent !== "function") throw new Error("SetupError: missing session callback");
    callbacks.push(options.stillCurrent);
    return new Promise<void>((_resolve, reject) => { rejects.push(reject); });
  });
  const root = await render(host("visible"));
  const start = async () => {
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Sign in");
    if (!button || typeof button.props.onPress !== "function") throw new Error("SetupError: missing sign-in action");
    await act(async () => { submitted.push(Promise.resolve(button.props.onPress()).then(() => {}, error => { unexpected.push(error); })); });
  };
  try {
    await flush();
    await typeInto(root, "username", "alice");
    await typeInto(root, "password", "synthetic first password");
    await start();
    await vi.waitFor(() => expect(callbacks).toHaveLength(1), { timeout: 10_000, interval: 20 });
    expect(callbacks[0]()).toBe(true);
    await act(async () => root.update(host("hidden")));
    await act(async () => root.update(host("visible")));
    await flush();
    await typeInto(root, "password", "synthetic newer password");
    await start();
    await vi.waitFor(() => expect(callbacks).toHaveLength(2), { timeout: 10_000, interval: 20 });
    expect(callbacks[0]()).toBe(false);
    expect(callbacks[1]()).toBe(true);
    await act(async () => { for (const reject of rejects) reject(new Error("controlled session completion")); await Promise.all(submitted); });
    expect(unexpected).toEqual([]);
  } finally {
    await act(async () => { root.unmount(); });
    await act(async () => { for (const reject of rejects) reject(new Error("controlled cleanup")); await Promise.all(submitted); });
  }
}, 30_000);


it("announces the pending saved-server check until password entry is available", async () => {
  const pin = deferred<boolean>();
  vi.spyOn(api, "originPinChanged").mockReturnValueOnce(pin.promise);
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  const checkingCopy = "Checking the saved server address…";
  const hasCheckingAnnouncement = () => root.root.findAll((node) =>
    node.props.accessibilityRole === "alert" && node.props.children === checkingCopy
  ).length > 0;
  try {
    await flush();
    expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
    expect(hasCheckingAnnouncement()).toBe(true);

    await act(async () => pin.resolve(false)); await flush();
    expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
    expect(hasCheckingAnnouncement()).toBe(false);
    expect(changedWarning(root)).toBe(false);
  } finally {
    try { await act(async () => pin.resolve(false)); await flush(); }
    finally { await act(async () => root.unmount()); }
  }
});


it("registration confirmation and creation stay unavailable until the server check finishes", async () => {
  const pin = deferred<boolean>();
  vi.spyOn(api, "originPinChanged").mockReturnValueOnce(pin.promise);
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  const createButton = () => {
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Create account");
    if (!button) throw new Error("SetupError: Create account button missing");
    return button;
  };
  try {
    await flush();
    await pressLabel(root, "New here? Create an account");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true));
    expect(root.root.findByType(Switch).props.value).toBe(true);
    expect(inputByPlaceholder(root, "confirm password").props.editable).toBe(false);
    expect(createButton().props.disabled).toBe(true);
    expect(createButton().props.accessibilityState.disabled).toBe(true);

    // A delivered native change event must obey the same pending-check fence.
    await typeInto(root, "confirm password", "synthetic pending confirmation");
    expect(inputByPlaceholder(root, "confirm password").props.value).toBe("");

    await act(async () => pin.resolve(false)); await flush();
    expect(inputByPlaceholder(root, "confirm password").props.editable).not.toBe(false);
    expect(createButton().props.disabled).toBe(false);
    expect(createButton().props.accessibilityState.disabled).toBe(false);
    await typeInto(root, "confirm password", "synthetic verified confirmation");
    expect(inputByPlaceholder(root, "confirm password").props.value).toBe("synthetic verified confirmation");
  } finally {
    try { await act(async () => pin.resolve(false)); await flush(); }
    finally { await act(async () => root.unmount()); }
  }
});


it("retired registration callbacks cannot edit the revealed form or change its mode", async () => {
  const root = await render(host("visible"));
  const switchMode = () => {
    const button = root.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Already have an account? Sign in");
    if (!button) throw new Error("SetupError: registration mode switch missing");
    return button;
  };
  try {
    await flush();
    await pressLabel(root, "New here? Create an account");
    const staleUsername = inputByPlaceholder(root, "username").props.onChangeText;
    const staleConfirmation = inputByPlaceholder(root, "confirm password").props.onChangeText;
    const staleAge = root.root.findByType(Switch).props.onValueChange;
    const staleMode = switchMode().props.onPress;
    await act(async () => root.update(host("hidden")));
    await act(async () => root.update(host("visible"))); await flush();
    expect(inputByPlaceholder(root, "confirm password").props.editable).not.toBe(false);
    await typeInto(root, "username", "current-user");
    await typeInto(root, "confirm password", "synthetic current confirmation");
    await act(async () => root.root.findByType(Switch).props.onValueChange(false));

    await act(async () => staleUsername("retired-user"));
    expect(inputByPlaceholder(root, "username").props.value).toBe("current-user");
    await act(async () => staleConfirmation("synthetic retired confirmation"));
    expect(inputByPlaceholder(root, "confirm password").props.value).toBe("synthetic current confirmation");
    await act(async () => staleAge(true));
    expect(root.root.findByType(Switch).props.value).toBe(false);
    await act(async () => staleMode());
    expect(root.root.findAllByType(TextInput).filter(node => node.props.placeholder === "confirm password")).toHaveLength(1);

    await typeInto(root, "username", "fresh-user");
    await typeInto(root, "confirm password", "synthetic fresh confirmation");
    await act(async () => root.root.findByType(Switch).props.onValueChange(true));
    expect(inputByPlaceholder(root, "username").props.value).toBe("fresh-user");
    expect(inputByPlaceholder(root, "confirm password").props.value).toBe("synthetic fresh confirmation");
    expect(root.root.findByType(Switch).props.value).toBe(true);
    await pressLabel(root, "Already have an account? Sign in");
    expect(root.root.findAllByType(TextInput).filter(node => node.props.placeholder === "confirm password")).toHaveLength(0);
  } finally { await act(async () => root.unmount()); }
});


it("a failed server save explains uncertainty until a successful retry verifies the new address", async () => {
  const releaseFailure = deferred<void>();
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  const unverified = () => root.root.findAll(node => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.");
  try {
    await flush();
    await typeInto(root, "password", "synthetic password to clear");
    await pressLabel(root, "Change server");
    const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
    if (!field) throw new Error("SetupError: no editable server field");
    await act(async () => field.props.onChangeText(nextUrl));
    const write = storage.setItem.bind(storage); let attempts = 0;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === BASE && value === nextUrl && ++attempts === 1) {
        await releaseFailure.promise;
        throw new Error("injected pre-write server storage failure");
      }
      await write(key, value);
    });
    await pressLabel(root, "Save server"); await flush(8);
    expect(attempts).toBe(1);
    expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
    await act(async () => releaseFailure.resolve()); await flush(8);
    expect(await getBaseUrl()).toBe(oldUrl);
    expect(vi.mocked(Alert.alert)).toHaveBeenCalledWith("Could not save server", "The server address could not be saved or verified. Check the selected address before entering credentials.");
    expect(unverified()).toBe(true);
    expect(changedWarning(root)).toBe(false);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
    expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);

    await pressLabel(root, "Save server"); await flush(8);
    expect(attempts).toBe(2);
    expect(await getBaseUrl()).toBe(nextUrl);
    expect(unverified()).toBe(false);
    expect(changedWarning(root)).toBe(true);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
    expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
  } finally {
    releaseFailure.resolve();
    try { await flush(8); } finally { await act(async () => root.unmount()); }
  }
});


it("a retired server save cannot alert the revealed screen and a fresh check still works", async () => {
  const releaseFailure = deferred<void>();
  const root = await render(host("visible"));
  try {
    await flush();
    await typeInto(root, "password", "synthetic password to clear");
    await pressLabel(root, "Change server");
    const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
    if (!field) throw new Error("SetupError: no editable server field");
    await act(async () => field.props.onChangeText(nextUrl));
    const write = storage.setItem.bind(storage); let attempts = 0;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === BASE && value === nextUrl && ++attempts === 1) {
        await releaseFailure.promise;
        throw new Error("injected retired server write failure");
      }
      await write(key, value);
    });
    await pressLabel(root, "Save server"); await flush(8);
    expect(attempts).toBe(1);
    expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
    await act(async () => root.update(host("hidden")));
    await act(async () => root.update(host("visible"))); await flush();
    expect(vi.mocked(Alert.alert)).not.toHaveBeenCalled();
    await act(async () => releaseFailure.resolve()); await flush(8);
    expect(vi.mocked(Alert.alert)).not.toHaveBeenCalled();
    expect(await getBaseUrl()).toBe(oldUrl);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");

    await pressLabel(root, "Retry server check"); await flush(8);
    expect(inputByPlaceholder(root, "password").props.editable).not.toBe(false);
    expect(root.root.findAll(node => node.props.accessibilityRole === "alert")).toHaveLength(0);
    expect(changedWarning(root)).toBe(false);
    expect(root.root.findAllByType(Text).some(node => node.props.accessibilityLabel === "Selected server address" && JSON.stringify(node.props.children).includes(oldUrl))).toBe(true);
    expect(attempts).toBe(1);
  } finally {
    releaseFailure.resolve();
    try { await flush(8); } finally { await act(async () => root.unmount()); }
  }
});


it("an acknowledged server save stays unverified until the requested address is actually retained", async () => {
  const releaseWrite = deferred<void>();
  const root = await render(<LoginScreen navigation={{ navigate: () => undefined }} />);
  const unverified = () => root.root.findAll(node => node.props.accessibilityRole === "alert").some(node => node.props.children === "Could not verify the saved server address. Check the address before entering credentials.");
  const selectRequestedAddress = async () => {
    await pressLabel(root, "Change server");
    const field = root.root.findAllByType(TextInput).find(node => node.props.accessibilityLabel === "Selected server address");
    if (!field) throw new Error("SetupError: no editable server field");
    await act(async () => field.props.onChangeText(nextUrl));
  };
  try {
    await flush();
    await typeInto(root, "password", "synthetic password to clear");
    await selectRequestedAddress();
    const write = storage.setItem.bind(storage); let attempts = 0;
    vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
      if (key === BASE && value === nextUrl && ++attempts === 1) {
        await releaseWrite.promise;
        return;
      }
      await write(key, value);
    });
    await pressLabel(root, "Save server"); await flush(8);
    expect(attempts).toBe(1);
    expect(inputByPlaceholder(root, "password").props.editable).toBe(false);
    await act(async () => releaseWrite.resolve()); await flush(8);
    expect(await getBaseUrl()).toBe(oldUrl);
    expect(root.root.findAllByType(Text).some(node => node.props.accessibilityLabel === "Selected server address" && JSON.stringify(node.props.children).includes(oldUrl))).toBe(true);
    expect(unverified()).toBe(true);
    expect(changedWarning(root)).toBe(false);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");

    await selectRequestedAddress();
    await pressLabel(root, "Save server"); await flush(8);
    expect(attempts).toBe(2);
    expect(await getBaseUrl()).toBe(nextUrl);
    expect(unverified()).toBe(false);
    expect(changedWarning(root)).toBe(true);
    expect(inputByPlaceholder(root, "password").props.value).toBe("");
  } finally {
    releaseWrite.resolve();
    try { await flush(8); } finally { await act(async () => root.unmount()); }
  }
});
