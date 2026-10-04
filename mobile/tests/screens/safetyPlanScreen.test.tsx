/**
 * SafetyPlanScreen (independent audit 2026-09-27, coverage): the load/save
 * flow, the new-plan crisis-line prefill, editing, the honest locked states
 * (mount-time and mid-save), save failure, and the wrong-key-absent
 * discipline — REAL envelope crypto against the in-memory storage mock, the
 * measures.test.tsx idiom.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, AppState } from "react-native";
import { TextInput } from "../helpers/rnMock";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actualApi = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ...actualApi, ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity }) };
});

const { api } = await import("../../src/api/client");
const { SafetyPlanScreen } = await import("../../src/screens/SafetyPlanScreen");
const { vault } = await import("../../src/vault");
const { saveSafetyPlan } = await import("../../src/safetyPlan");
const { render: renderRaw, flush, textOf, pressLabel, firePress, touchableByLabel, act } = await import("../helpers/rtr");
const { waitLocalWriteCommits } = await import("../../src/localWriteGuard");
const roots: Awaited<ReturnType<typeof renderRaw>>[] = [];
const render = async (element: React.ReactElement) => { const root = await renderRaw(element); roots.push(root); return root; };
afterEach(async () => { await act(async () => { for (const root of roots.splice(0)) root.unmount(); }); await waitLocalWriteCommits(); });
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const dataKey = Buffer.alloc(32, 7);
const USER = "user-1";
const SLOT = `@mindpattern/safety_plan_${USER}`;

/** The screen's TextInputs carry accessibilityLabels (no placeholders). */
function inputByLabel(root: Awaited<ReturnType<typeof render>>, label: string) {
  const node = root.root.findAllByType(TextInput).find(
    (n) => n.props.accessibilityLabel === label,
  );
  if (!node) throw new Error(`no TextInput labeled ${label}`);
  return node;
}

async function typeIntoField(
  root: Awaited<ReturnType<typeof render>>,
  label: string,
  value: string,
): Promise<void> {
  await act(async () => {
    inputByLabel(root, label).props.onChangeText(value);
  });
}

const nav = { navigate: vi.fn(), goBack: vi.fn() };

beforeEach(() => {
  resetApi(api as never);
  Alert.alert.mockClear();
  touchActivity.mockClear();
  storage.__reset();
  nav.navigate.mockClear();
  nav.goBack.mockClear();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, USER);
});

describe("SafetyPlanScreen: load", () => {
  it("renders the honest intro and all six fields after the load settles", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    const text = textOf(root);
    expect(text).toContain("it is never sent anywhere");
    expect(text).toContain("1. My warning signs");
    expect(text).toContain("6. Making my environment safer");
    expect(text).toContain("What you could move, lock or set aside");
    expect(touchableByLabel(root, "Save my safety plan")).toBeTruthy();
  });

  it("loads an existing plan into the fields", async () => {
    await saveSafetyPlan(dataKey, USER, {
      warningSigns: "Sleep slipping",
      copingStrategies: "",
      peoplePlaces: "",
      askForHelp: "Ana",
      professionals: "Dr. Okafor",
      environmentSafer: "",
    });
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    expect(inputByLabel(root, "My warning signs").props.value).toBe("Sleep slipping");
    expect(inputByLabel(root, "Who I can ask for help").props.value).toBe("Ana");
    expect(inputByLabel(root, "Professionals and services").props.value).toBe("Dr. Okafor");
  });

  it("a brand-new plan prefills ONLY the professionals field with the crisis lines", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    expect(inputByLabel(root, "Professionals and services").props.value).toContain("988");
    expect(inputByLabel(root, "Professionals and services").props.value).toContain("741741");
    for (const other of ["My warning signs", "Things I can do to cope", "Making my environment safer"]) {
      expect(inputByLabel(root, other).props.value).toBe("");
    }
  });

  it("a stored plan under a DIFFERENT key reads as absent — the new-plan prefill shows instead", async () => {
    // The rotation/account-switch case: the slot exists but the vault's key
    // cannot open it; the honest answer is a fresh plan, never a partial one.
    await saveSafetyPlan(Buffer.alloc(32, 42), USER, {
      warningSigns: "old key's plan",
      copingStrategies: "",
      peoplePlaces: "",
      askForHelp: "",
      professionals: "",
      environmentSafer: "",
    });
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    expect(inputByLabel(root, "My warning signs").props.value).toBe("");
    expect(inputByLabel(root, "Professionals and services").props.value).toContain("988");
  });
});

describe("SafetyPlanScreen: edit and save", () => {
  it("cannot save a previous account's mounted form into a replacement account", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />); await flush();
    await typeIntoField(root, "My warning signs", "Private words from the original account");
    vi.mocked(api.getUserId).mockResolvedValue("replacement-account");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.alloc(32, 9) }, "replacement-account");
    await pressLabel(root, "Save my safety plan"); await flush();
    expect(await storage.getItem("@mindpattern/safety_plan_replacement-account")).toBeNull();
    expect(Alert.alert).toHaveBeenCalledWith("Could not save", expect.any(String));
    expect(inputByLabel(root, "My warning signs").props.value).toBe("Private words from the original account");
  });
  it("a late explicit-save ACK retains a newer encrypted draft instead of acknowledging different words", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />); await flush();
    await typeIntoField(root, "My warning signs", "the explicitly saved older words");
    const original = storage.setItem; let release!: () => void;
    const gate = vi.spyOn(storage, "setItem").mockImplementation(async (slot, raw) => {
      await original(slot, raw);
      if (slot === SLOT) await new Promise<void>(resolve => { release = resolve; });
    });
    await firePress(root, "Save my safety plan"); await flush(); expect(release).toBeTypeOf("function");
    await typeIntoField(root, "My warning signs", "newer words while save was waiting");
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 350)); });
    await act(async () => release()); await flush(); gate.mockRestore();
    const { loadSafetyPlan, loadSafetyPlanDraft } = await import("../../src/safetyPlan");
    expect((await loadSafetyPlan(dataKey, USER))?.warningSigns).toBe("the explicitly saved older words");
    expect((await loadSafetyPlanDraft(dataKey, USER))?.warningSigns).toBe("newer words while save was waiting");
    expect(inputByLabel(root, "My warning signs").props.value).toBe("newer words while save was waiting");
  });
  it("typing updates the field and marks activity; saving persists ciphertext and shows the calm status", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    await typeIntoField(root, "My warning signs", "Skipping meals");
    await typeIntoField(root, "Things I can do to cope", "Cold water");
    expect(touchActivity).toHaveBeenCalledTimes(2);

    await pressLabel(root, "Save my safety plan");
    await flush();

    // The slot is ciphertext, never field names or values.
    const raw = await storage.getItem(SLOT);
    expect(raw).not.toBeNull();
    expect(raw!).not.toContain("Skipping meals");
    expect(raw!).not.toContain("warningSigns");
    // The calm confirmation appeared.
    expect(textOf(root)).toContain("Saved — encrypted, as always.");
    // And it really opens back under the vault's key.
    const { loadSafetyPlan } = await import("../../src/safetyPlan");
    expect((await loadSafetyPlan(dataKey, USER))?.copingStrategies).toBe("Cold water");
  });

  it("a save that fails keeps every field on screen exactly as typed, with honest copy", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    await typeIntoField(root, "People and places that help", "The library");
    const failing = storage.setItem.bind(storage);
    const spy = vi.spyOn(storage, "setItem").mockImplementation(async (key: string, value: string) => {
      if (key === SLOT) throw new Error("disk full");
      return failing(key, value);
    });
    try {
      await pressLabel(root, "Save my safety plan");
      await flush();
    } finally {
      spy.mockRestore();
    }
    expect(Alert.alert).toHaveBeenCalledWith(
      "Could not save",
      "Your plan is still on screen exactly as you typed it — try again.",
    );
    expect(inputByLabel(root, "People and places that help").props.value).toBe("The library");
  });

  it("no saved account on the device surfaces the session-damaged dialog and saves nothing", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    // The mount load saw a healthy session; the account record disappears
    // before the save (the session-damaged window the dialog names).
    vi.mocked(api.getUserId).mockResolvedValue(null);
    await pressLabel(root, "Save my safety plan");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Session damaged",
      "Account id missing — please sign in again.",
    );
    expect(await storage.getItem(SLOT)).toBeNull();
  });
});

describe("SafetyPlanScreen: locked states", () => {
  it("a delayed initial account lookup cannot adopt a replacement vault's plan", async () => {
    let release!: (value: string) => void;
    vi.mocked(api.getUserId).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
    const root = await render(<SafetyPlanScreen navigation={nav} />); await flush();
    const replacementKey = Buffer.alloc(32, 9);
    await saveSafetyPlan(replacementKey, "replacement-account", { ...(await import("../../src/safetyPlan")).emptySafetyPlan(), warningSigns: "The replacement account's private plan" });
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: replacementKey }, "replacement-account");
    await act(async () => release("replacement-account")); await flush();
    expect(textOf(root)).toContain("unlock to read or edit it");
    expect(textOf(root)).not.toContain("1. My warning signs");
  });
  it("a locked vault at mount shows the locked view with crisis help one tap away", async () => {
    vault.lock();
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("unlock to read or edit it");
    expect(textOf(root)).not.toContain("1. My warning signs");
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });

  it("a vault that locks between load and save refuses honestly and swaps to the locked view", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    await typeIntoField(root, "My warning signs", "typed before the lock");
    vault.lock();
    await pressLabel(root, "Save my safety plan");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith("Locked", expect.stringContaining("unlock to read or edit it"));
    expect(textOf(root)).not.toContain("1. My warning signs");
    // Nothing was written under a dead key.
    expect(await storage.getItem(SLOT)).toBeNull();
  });
});

describe("SafetyPlanScreen: navigation and status lifecycle", () => {
  it("back hands off to the navigator", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Back");
    expect(nav.goBack).toHaveBeenCalledTimes(1);
  });

  it("the saved status clears itself after its moment", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    vi.useFakeTimers();
    try {
      await pressLabel(root, "Save my safety plan");
      expect(textOf(root)).toContain("Saved — encrypted, as always.");
      await act(async () => { await vi.advanceTimersByTimeAsync(2600); });
      expect(textOf(root)).not.toContain("Saved — encrypted, as always.");
    } finally {
      vi.useRealTimers();
    }
  });
});


describe("encrypted safety-plan interruption drafts", () => {
  it("background/lock preserves unsaved edits separately and restores them after unlock", async () => {
    const root = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    await typeIntoField(root, "My warning signs", "An unfinished private note");
    const restoreKey = Buffer.from(vault.get().dataKey);
    const listener = [...AppState.addEventListener.mock.calls].reverse().find(([event]) => event === "change")![1];
    await act(async () => { listener("background"); vault.lock(); });
    await act(async () => { root.unmount(); });
    await flush();
    expect(await storage.getItem(SLOT)).toBeNull(); // explicit Save still owns the saved plan
    const draft = await storage.getItem(`@mindpattern/safety_plan_draft_${USER}`);
    expect(draft).not.toBeNull(); expect(draft).not.toContain("unfinished private note");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: restoreKey }, USER);
    const reopened = await render(<SafetyPlanScreen navigation={nav} />);
    await flush();
    expect(inputByLabel(reopened, "My warning signs").props.value).toBe("An unfinished private note");
    expect(textOf(reopened)).toContain("Your unsaved encrypted draft was restored");
    await pressLabel(reopened, "Save my safety plan"); await flush();
    expect(await storage.getItem(`@mindpattern/safety_plan_draft_${USER}`)).toBeNull();
  });
});
