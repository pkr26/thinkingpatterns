/** The lock-time draft seal (audit 2026-09-26, MEDIUM user-data-loss): a
 *  hidden-tab/idle/expiry lock unmounts the editor while the draft lives
 *  only in component state — the seal persists it data-key-encrypted and
 *  the editor restores it after re-unlock. Module custody, the editor's
 *  restore/save/discard contract, and the App-level lock wiring, with real
 *  crypto throughout. */
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  clearActiveDraft,
  loadActiveDraft,
  preserveActiveDraft,
  registerDraftSource,
  rewrapActiveDraft,
  saveActiveDraft,
  type EntryDraft,
} from "../src/entryDraft";
import { EntryView } from "../src/views/Entry";
import { App } from "../src/App";
import { setKvBackendForTests, kv, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { clearSession, hasSession } from "../src/api/client";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, textOfNode, typeArea } from "./helpers/rtr";

const USER = "user-1";
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(3);
const OTHER_KEY = new Uint8Array(new ArrayBuffer(32)).fill(4);

const memoryBackend = (): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
    async keys() {
      return [...map.keys()];
    },
  };
};

const unlockVault = (): void => {
  vault.unlock({ authKey: DATA_KEY.slice(), dataKey: DATA_KEY.slice() }, USER);
};

const DRAFT: EntryDraft = { text: "half-written honesty", mood: 0.5, energy: -0.5, sleep: null, tags: ["work"] };

function authStubs(): ReturnType<typeof stubFetch> {
  return stubFetch((url) => {
    if (url.endsWith("/entries")) return jsonResponse({ id: "row" }, { status: 201 });
    if (url.endsWith("/auth/logout")) return new Response(null, { status: 204 });
    return jsonResponse({ detail: "unmatched", code: "not_found" }, { status: 404 });
  });
}

// Deterministic LoginView stand-in (real crypto avoided; the state machine
// and the seal are what the App-level tests prove). Same mock shape as
// tests/app.test.tsx. vi.mock is hoisted — top level on purpose.
vi.mock("../src/views/LoginView", async () => {
  const { setSession } = await import("../src/api/client");
  const { vault } = await import("../src/vault");
  const React = await import("react");
  return {
    LoginView: (props: { onSuccess: (s: { userId: string; username: string }) => void }) =>
      React.createElement("button", {
        onClick: () => {
          setSession("tok", "user-7", "alice");
          const key = () => new Uint8Array(new ArrayBuffer(32));
          vault.unlock({ authKey: key(), dataKey: key() }, "user-7");
          props.onSuccess({ userId: "user-7", username: "alice" });
        },
      }, "Sign in"),
  };
});

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  unlockVault();
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
  try {
    registerDraftSource(() => null);
  } catch {
    // already unregistered
  }
});

describe("entryDraft custody (module)", () => {
  it("seals, reloads, and clears the draft under the data key", async () => {
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    // The slot is ciphertext, not plaintext (storage-scrape posture).
    const raw = await kv.getItem(`mindpattern.draft.active.${USER}`);
    expect(raw).toBeTruthy();
    expect(raw).not.toContain("half-written");
    expect(await loadActiveDraft(DATA_KEY, USER)).toEqual(DRAFT);
    await clearActiveDraft(USER);
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
  });

  it("an EMPTY draft clears the slot instead of sealing nothing", async () => {
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    await saveActiveDraft(DATA_KEY, USER, { text: "   ", mood: null, energy: null, sleep: null, tags: [] });
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
  });

  it("a wrong key or tampered bytes produce an explicit unreadable record without deleting ciphertext", async () => {
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    await expect(loadActiveDraft(OTHER_KEY, USER)).rejects.toThrow("could not be authenticated");
    await kv.setItem(`mindpattern.draft.active.${USER}`, "!!!not-ciphertext!!!");
    await expect(loadActiveDraft(DATA_KEY, USER)).rejects.toThrow("could not be authenticated");
  });

  it("validation rejects hostile half-written records", async () => {
    const key = `mindpattern.draft.active.${USER}`;
    await kv.setItem(key, '{"text": 42}');
    await expect(loadActiveDraft(DATA_KEY, USER)).rejects.toThrow("could not be authenticated");
    await kv.setItem(key, JSON.stringify({ text: "ok", mood: "happy", energy: null, sleep: null, tags: [] }));
    await expect(loadActiveDraft(DATA_KEY, USER)).rejects.toThrow("could not be authenticated");
    await kv.setItem(key, JSON.stringify({ text: "ok", mood: null, energy: null, sleep: null, tags: [7] }));
    await expect(loadActiveDraft(DATA_KEY, USER)).rejects.toThrow("could not be authenticated");
  });

  it("rewrap re-seals under a rotation's new key (B-7 family)", async () => {
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    await rewrapActiveDraft(DATA_KEY, OTHER_KEY, USER);
    expect(await loadActiveDraft(OTHER_KEY, USER)).toEqual(DRAFT);
  });

  it("preserveActiveDraft seals the registered editor's live state; an empty editor CLEARS; no editor = slot untouched", async () => {
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    const unregister = registerDraftSource(() => ({ text: "fresh take", mood: null, energy: null, sleep: null, tags: [] }));
    await preserveActiveDraft();
    expect((await loadActiveDraft(DATA_KEY, USER))?.text).toBe("fresh take");
    // Empty editor at lock time: the stale slot must not resurrect later.
    registerDraftSource(() => ({ text: "", mood: null, energy: null, sleep: null, tags: [] }));
    await preserveActiveDraft();
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
    // No editor mounted: a lock elsewhere in the app leaves the slot alone.
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    unregister();
    registerDraftSource(() => null);
    await preserveActiveDraft();
    expect((await loadActiveDraft(DATA_KEY, USER))?.text).toBe("half-written honesty");
  });

  it("preserveActiveDraft survives the vault locking immediately after (the key-snapshot idiom)", async () => {
    registerDraftSource(() => DRAFT);
    const sealed = preserveActiveDraft();
    vault.lock(); // the lockDown continuation zeroizes the shared buffer NOW
    await sealed;
    vault.unlock({ authKey: DATA_KEY.slice(), dataKey: DATA_KEY.slice() }, USER);
    expect(await loadActiveDraft(DATA_KEY, USER)).toEqual(DRAFT);
  });

  /** independent audit 2026-09-27 (P2): a lock can seal the draft WHILE a
   *  save is in flight; if the save's clear committed before the seal's
   *  write landed, the sealed slot survived a successful save and
   *  resurrected the entry as a draft. The combined clear now waits for
   *  any in-flight seal first — the clear is always the last write. */
  it("a save's clear cannot commit before an in-flight lock seal — no resurrected draft", async () => {
    // A gated kv backend: the seal's write hangs until released, exactly
    // like a slow IndexedDB commit would.
    let releaseSeal: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      releaseSeal = resolve;
    });
    const inner = memoryBackend();
    setKvBackendForTests({
      async getItem(k) {
        return inner.getItem(k);
      },
      async setItem(k, v) {
        if (k === `mindpattern.draft.active.${USER}`) await gate;
        return inner.setItem(k, v);
      },
      async removeItem(k) {
        return inner.removeItem(k);
      },
    });
    // Pre-seed the slot with an EARLIER sealed draft (bypassing the gate):
    // mid-race, its survival is what proves the clear has not committed.
    await inner.setItem(`mindpattern.draft.active.${USER}`, "earlier-sealed-blob");
    // The lock seals the half-written entry; the write is IN FLIGHT.
    registerDraftSource(() => DRAFT);
    const sealing = preserveActiveDraft();
    await new Promise((resolve) => setTimeout(resolve, 10));
    // The save completes while the seal is still pending: its clear must
    // queue BEHIND the seal (the old bare removeItem committed now, and the
    // seal's setItem then resurrected the slot).
    const clearing = clearActiveDraft(USER);
    await new Promise((resolve) => setTimeout(resolve, 10));
    expect(await kv.getItem(`mindpattern.draft.active.${USER}`)).toBe("earlier-sealed-blob"); // the clear is still queued
    releaseSeal();
    await Promise.all([sealing, clearing]);
    // The seal landed, then the clear removed it: the slot is genuinely
    // empty — the saved entry cannot come back as a draft.
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
  });

  it("a discard racing an in-flight seal gets the same combined clear (both slots)", async () => {
    // Same race, discard path: the explicit discard's clear also waits for
    // the in-flight seal, so "this entry is not happening" cannot be undone
    // by a late seal write.
    let releaseSeal: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      releaseSeal = resolve;
    });
    const inner = memoryBackend();
    setKvBackendForTests({
      async getItem(k) {
        return inner.getItem(k);
      },
      async setItem(k, v) {
        if (k === `mindpattern.draft.active.${USER}`) await gate;
        return inner.setItem(k, v);
      },
      async removeItem(k) {
        return inner.removeItem(k);
      },
    });
    registerDraftSource(() => DRAFT);
    const sealing = preserveActiveDraft();
    await new Promise((resolve) => setTimeout(resolve, 10));
    const clearing = clearActiveDraft(USER);
    releaseSeal();
    await Promise.all([sealing, clearing]);
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
  });
});

describe("EntryView draft contract", () => {
  beforeEach(() => { installSession(USER); });
  it("lock mid-draft → re-unlock → the editor restores text AND structured picks", async () => {
    authStubs();
    let root = await render(<EntryView onSaved={() => undefined} />);
    await typeArea(root, "How was today?", "draft in progress");
    await press(root, "Good"); // mood pick
    await press(root, "Energized"); // energy pick
    await press(root, "work"); // activity tag
    // The lock: seal (exactly what App.lockDown does), then keys die.
    await preserveActiveDraft();
    vault.lock();
    clearSession();
    await act(async () => {
      root.unmount();
    });
    // Re-unlock, fresh editor mount: the draft comes back — the whole
    // multi-field state, exactly as the editor models it.
    installSession(USER);
    unlockVault();
    root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("draft in progress");
    // The restored note is honest, and the picks are re-selected
    // (aria-pressed chips: mood + energy + activity tag).
    expect(textOf(root)).toContain("Unsent draft restored");
    const pressed = root.root.findAllByType("button").filter((n) => n.props["aria-pressed"] === true);
    expect(pressed.length).toBeGreaterThanOrEqual(3);
    const labels = pressed.map((node) => textOfNode(node));
    expect(labels).toContain("Good");
    expect(labels).toContain("Energized");
    expect(labels).toContain("work");
  });

  it("a successful save clears the sealed draft", async () => {
    installSession(USER);
    authStubs();
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("half-written honesty");
    await press(root, "Save entry");
    await settle(40, 5);
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
    expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("");
  });

  it("an explicit discard clears the editor AND the sealed draft", async () => {
    await saveActiveDraft(DATA_KEY, USER, DRAFT);
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    await press(root, "Discard draft");
    await settle(20, 2);
    expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("");
    expect(await loadActiveDraft(DATA_KEY, USER)).toBeNull();
    expect(textOf(root)).not.toContain("Unsent draft restored");
  });

  it("a lock racing the save press is the honest locked message, never an unhandled throw (audit LOW)", async () => {
    const mock = authStubs();
    const root = await render(<EntryView onSaved={() => undefined} />);
    await typeArea(root, "How was today?", "about to be locked out");
    vault.lock();
    await press(root, "Save entry");
    await settle(20, 2);
    expect(textOf(root)).toContain("session locked");
    expect(mock.mock.calls.some(([url]) => String(url).endsWith("/entries"))).toBe(false);
  });
});

describe("App wiring: the hidden-tab lock seals the draft (the real user-data-loss path)", () => {
  it("visibilitychange→hidden seals the in-progress entry; re-sign-in restores it into the editor", async () => {
    authStubs();
    const root = await render(<App />);
    await settle(40, 3);
    await press(root, "Sign in");
    await settle(40, 3);
    // First-run onboarding → Today.
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await settle(40, 3);
    await typeArea(root, "How was today?", "written then the tab went dark");
    // The lock: hidden tab → lockDown → seal BEFORE vault.lock().
    const shimWindow = (globalThis as { window?: { dispatchEvent: (event: unknown) => boolean } }).window;
    await act(async () => {
      shimWindow!.dispatchEvent({ type: "visibilitychange", visibilityState: "hidden" });
    });
    await settle(40, 4);
    expect(vault.isUnlocked()).toBe(false);
    expect(hasSession()).toBe(false);
    // Re-sign-in (the same account, same browser): onboarding is stamped,
    // so the app lands on Today and the editor restores the draft.
    await press(root, "Sign in");
    await settle(40, 4);
    expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("written then the tab went dark");
    expect(textOf(root)).toContain("Unsent draft restored");
  });

  it("after the restored draft is saved, the slot is empty and a later lock seals nothing", async () => {
    authStubs();
    const root = await render(<App />);
    await settle(40, 3);
    await press(root, "Sign in");
    await settle(40, 3);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await settle(40, 3);
    await typeArea(root, "How was today?", "seal me then save me");
    const shimWindow = (globalThis as { window?: { dispatchEvent: (event: unknown) => boolean } }).window;
    await act(async () => {
      shimWindow!.dispatchEvent({ type: "visibilitychange", visibilityState: "hidden" });
    });
    await settle(40, 4);
    await press(root, "Sign in");
    await settle(40, 4);
    await press(root, "Save entry");
    await settle(40, 5);
    expect(await loadActiveDraft(new Uint8Array(new ArrayBuffer(32)), "user-7")).toBeNull();
    // A second lock with an empty editor must not resurrect anything.
    await act(async () => {
      shimWindow!.dispatchEvent({ type: "visibilitychange", visibilityState: "hidden" });
    });
    await settle(40, 4);
    await press(root, "Sign in");
    await settle(40, 4);
    expect(root.root.findAllByType("textarea")[0]!.props.value).toBe("");
  });
});
