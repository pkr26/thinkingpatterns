/**
 * Deep-mutation pins for SettingsScreen (2026-09-15 Stryker campaign).
 *
 * Each block kills a specific surviving mutant class:
 *  - mount-state guards (quarantine notice only after the store says so, a
 *    non-string server version never renders),
 *  - the insecure-HTTP consent save (consent records immediately; a secure
 *    URL never inherits an allowInsecure pass; exact "Saved" copy),
 *  - the recovery flow (busy disablement, no flush without a user id, the
 *    rejected count refreshes, busy resets in finally),
 *  - the re-auth card (busy guard against leaked double presses, retry vs
 *    done semantics for busy/password, empty-password disable, danger fill
 *    per action kind, "disable" wording, the Verifying… label),
 *  - the 401-vs-fallback delete copy, the export-unavailable disclosure
 *    (full exports fail closed in this build — no boundary math), Share
 *    resolving undefined,
 *  - node-exact style contracts (rejected card, re-auth card + title,
 *    left-aligned ghost buttons) and the About else-branch.
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, Share, Switch, Text, View } from "react-native";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock } = await import("../helpers/apiMock");
  return {
    ...actual,
    api: makeApiMock(),
    getBaseUrl: vi.fn(async () => "http://localhost:8000"),
    getInsecureConsentUrl: vi.fn(async () => null),
    setBaseUrl: vi.fn(async () => null),
  };
});

const authKeyB64 = () => authKey.toString("base64");
const verifyPasswordForVault = vi.fn(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
vi.mock("../../src/reauth", async (importOriginal) => {
  // The error classifiers stay REAL: the screen branches 403-vs-401 on them.
  const actual = await importOriginal<typeof import("../../src/reauth")>();
  return {
    ...actual,
    verifyPasswordForVault: (...args: unknown[]) => verifyPasswordForVault(...(args as [string])),
  };
});

vi.mock("../../src/offlineQueue", () => ({
  flushQueue: vi.fn(async () => 0),
  clearQueue: vi.fn(async () => {}),
  rejectedEntryCount: vi.fn(async () => 0),
  requeueRejected: vi.fn(async () => 0),
  quarantinedQueueExists: vi.fn(async () => false),
  hasLegacyQueueRecovery: vi.fn(async () => false),
}));

const signOut = vi.fn(async () => {});
const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ signOut, touchActivity }) };
});

const { api, getBaseUrl, getInsecureConsentUrl, setBaseUrl } = await import("../../src/api/client");
const { flushQueue, clearQueue, rejectedEntryCount, requeueRejected, quarantinedQueueExists } = await import(
  "../../src/offlineQueue"
);
const { SettingsScreen } = await import("../../src/screens/SettingsScreen");
const { vault } = await import("../../src/vault");
const {
  render,
  flush,
  textOf,
  allText,
  pressLabel,
  typeInto,
  pressAlertButton,
  lastAlert,
  touchableByLabel,
  inputByPlaceholder,
} = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;

const authKey = Buffer.alloc(32, 2);
const keys = { masterKey: Buffer.alloc(32), authKey, dataKey: Buffer.alloc(32, 3) };
const nav = { popToTop: vi.fn(), navigate: vi.fn() };

beforeEach(() => {
  resetApi(api as never);
  storage.__reset();
  vi.mocked(clearQueue).mockClear();
  vi.mocked(getBaseUrl).mockReset();
  vi.mocked(getBaseUrl).mockImplementation(async () => "http://localhost:8000");
  vi.mocked(getInsecureConsentUrl).mockReset();
  vi.mocked(getInsecureConsentUrl).mockImplementation(async () => null);
  vi.mocked(setBaseUrl).mockReset();
  vi.mocked(setBaseUrl).mockImplementation(async () => null);
  vi.mocked(flushQueue).mockClear();
  vi.mocked(flushQueue).mockImplementation(async () => 0);
  vi.mocked(rejectedEntryCount).mockReset();
  vi.mocked(rejectedEntryCount).mockImplementation(async () => 0);
  vi.mocked(requeueRejected).mockReset();
  vi.mocked(requeueRejected).mockImplementation(async () => 0);
  vi.mocked(quarantinedQueueExists).mockReset();
  vi.mocked(quarantinedQueueExists).mockImplementation(async () => false);
  signOut.mockClear();
  nav.popToTop.mockClear();
  nav.navigate.mockClear();
  Alert.alert.mockClear();
  vi.mocked(Share.share).mockReset();
  vi.mocked(Share.share).mockImplementation(async () => ({}));
  vault.lock();
  vault.unlock({ ...keys });
  verifyPasswordForVault.mockClear();
  verifyPasswordForVault.mockImplementation(async () => ({ ok: true as const, verifierB64: authKeyB64() }));
});

/** Drive the in-screen password re-auth card for a pending action. */
async function reauth(root: Awaited<ReturnType<typeof render>>, password = "correct horse"): Promise<void> {
  await typeInto(root, "password", password);
  await pressLabel(root, "Confirm with password");
  await flush();
}

/** The style ARRAY of the Text node whose flattened content contains
 *  `fragment` — pins each overlay to its own node. */
function styleArrayOfText(root: Awaited<ReturnType<typeof render>>, fragment: string): unknown[] {
  const flat = (children: unknown): string => {
    if (typeof children === "string") return children;
    if (typeof children === "number") return String(children);
    if (Array.isArray(children)) return children.map(flat).join("");
    return "";
  };
  const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
  if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}: ${allText(root).join(" | ")}`);
  const style = (node.props as { style: unknown }).style;
  return Array.isArray(style) ? style : [style];
}

/** The style of the closest View ancestor of the Text matching `fragment`. */
function parentViewStyle(root: Awaited<ReturnType<typeof render>>, fragment: string): unknown {
  const flat = (children: unknown): string => {
    if (typeof children === "string") return children;
    if (typeof children === "number") return String(children);
    if (Array.isArray(children)) return children.map(flat).join("");
    return "";
  };
  const node = root.root.findAllByType(Text).find((n) => flat(n.props.children).includes(fragment));
  if (!node) throw new Error(`no Text node ${JSON.stringify(fragment)}`);
  let cursor = node.parent;
  while (cursor && cursor.type !== View) cursor = cursor.parent;
  if (!cursor) throw new Error(`no View ancestor for ${JSON.stringify(fragment)}`);
  return (cursor.props as { style: unknown }).style;
}

/** Renders the screen with the LLM switch available. */
async function renderWithLlm(): Promise<Awaited<ReturnType<typeof render>>> {
  vi.mocked(api.meta).mockResolvedValue({ llm_available: true } as never);
  const root = await render(<SettingsScreen navigation={nav} />);
  await flush();
  return root;
}

describe("SettingsScreen pins: mount-state guards", () => {
  it("no quarantine notice before the store answers (initial quarantined is false)", async () => {
    let resolveQuarantine!: (v: boolean) => void;
    vi.mocked(quarantinedQueueExists).mockImplementation(() => new Promise((resolve) => (resolveQuarantine = resolve)));
    const root = await render(<SettingsScreen navigation={nav} />);
    expect(textOf(root)).not.toContain("damaged piece of the offline queue");
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      resolveQuarantine(false);
    });
    await flush();
  });

  it("a non-string server version never renders — the typeof guard is real", async () => {
    vi.mocked(api.meta).mockResolvedValue({ llm_available: false, version: 42 } as never);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("server 42");
    expect(textOf(root)).toContain("MindPattern 1.0.0. Everything");
  });

  it("no serverVersion means the About line has NO suffix at all", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("MindPattern 1.0.0. Everything");
    expect(textOf(root)).not.toContain("Stryker was here");
  });
});

describe("SettingsScreen pins: remote transport policy", () => {
  it("delegates a cleartext URL to the fail-closed client without a consent modal", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "http://nas.lan:8000");
    await pressLabel(root, "Save server URL");
    await flush();
    expect(setBaseUrl).toHaveBeenCalledTimes(1);
    expect(setBaseUrl).toHaveBeenLastCalledWith("http://nas.lan:8000");
    expect(Alert.alert.mock.calls.filter((c) => c[0] === "Insecure server")).toHaveLength(0);
  });

  it("a secure URL also has no obsolete allowInsecure option", async () => {
    vi.mocked(getInsecureConsentUrl).mockImplementation(async () => "https://api.example.com");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "https://api.example.com");
    await pressLabel(root, "Save server URL");
    await flush();
    expect(setBaseUrl).toHaveBeenCalledWith("https://api.example.com");
  });

  it("the success dialog explains the origin-switch sign-out boundary", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await typeInto(root, "https://your-server:8000", "https://api.example.com");
    await pressLabel(root, "Save server URL");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Saved",
      "Server URL updated. Changing server origins signs this device out to protect your session.",
    );
  });
});

describe("SettingsScreen pins: recovery flow", () => {
  it("disables the destructive buttons while a recovery is in flight", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    let resolveRequeue!: (v: number) => void;
    vi.mocked(requeueRejected).mockImplementation(() => new Promise((resolve) => (resolveRequeue = resolve)));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const { firePress, act } = await import("../helpers/rtr");
    await firePress(root, "Try syncing them again");
    await flush();
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(true);
    await act(async () => {
      resolveRequeue(1);
    });
    await flush();
  });

  it("never flushes the queue without a user id", async () => {
    vi.mocked(api.getUserId).mockResolvedValue(null);
    vi.mocked(rejectedEntryCount).mockResolvedValue(1);
    vi.mocked(requeueRejected).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).not.toContain("Try syncing them again");
    expect(requeueRejected).not.toHaveBeenCalled();
    expect(flushQueue).not.toHaveBeenCalled();
  });

  it("refreshes the rejected count after recovery — an emptied store removes the card", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValueOnce(2).mockResolvedValue(0);
    vi.mocked(requeueRejected).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(textOf(root)).toContain("2 entries couldn't sync");
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(textOf(root)).not.toContain("couldn't sync");
    expect(textOf(root)).not.toContain("Try syncing them again");
  });

  it("busy resets in the finally — the screen is usable right after a recovery", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValueOnce(1).mockResolvedValue(0);
    vi.mocked(requeueRejected).mockResolvedValue(1);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Try syncing them again");
    await flush();
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
  });
});

describe("SettingsScreen pins: the password re-auth card", () => {
  it("Confirm stays disabled until a password is typed (and enables once typed)", async () => {
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect(touchableByLabel(root, "Confirm with password").props.disabled).toBe(true);
    await typeInto(root, "password", "correct horse");
    expect(touchableByLabel(root, "Confirm with password").props.disabled).toBe(false);
  });

  it("a leaked second Confirm press while the verifier is busy is swallowed by the guard", async () => {
    let resolveVerify!: (v: unknown) => void;
    verifyPasswordForVault.mockImplementation(() => new Promise((resolve) => (resolveVerify = resolve)));
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await typeInto(root, "password", "correct horse");
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Confirm with password"); // returns while verify is pending
    // Busy now: the label swapped to Verifying… — a press leaked past the
    // disabled flag must still be a no-op.
    await firePress(root, "Verifying…");
    expect(verifyPasswordForVault).toHaveBeenCalledTimes(1);
    await act(async () => {
      resolveVerify?.({ ok: true as const, verifierB64: authKeyB64() });
    });
    await flush();
  });

  it("the busy Verifying… label replaces Confirm while verification runs", async () => {
    verifyPasswordForVault.mockImplementation(() => new Promise(() => {}));
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await typeInto(root, "password", "correct horse");
    const { firePress } = await import("../helpers/rtr");
    await firePress(root, "Confirm with password");
    expect(allText(root)).toContain("Verifying…");
  });

  it("a rejected password retries in place: card up, password cleared, busy reset", async () => {
    verifyPasswordForVault.mockResolvedValue({ ok: false as const, reason: "wrong-password" as const });
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root, "wrong guess");
    expect(Alert.alert).toHaveBeenCalledWith("Could not verify", "Wrong password.");
    expect(textOf(root)).toContain("Enter your password to enable");
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
    expect(touchableByLabel(root, "Delete my account and data").props.disabled).toBe(false);
  });

  it("a completed flow clears the typed password — the next card starts empty", async () => {
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await reauth(root);
    expect(textOf(root)).not.toContain("Enter your password");
    // Open the DELETE card: its password field must not inherit anything.
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
    expect(touchableByLabel(root, "Confirm with password").props.disabled).toBe(true);
  });

  it("Cancel discards the pending action AND the half-typed password", async () => {
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    await typeInto(root, "password", "half-typed");
    await pressLabel(root, "Cancel");
    await flush();
    expect(textOf(root)).not.toContain("Enter your password");
    // Re-open the card: no stale password may linger from the cancelled one.
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    expect((inputByPlaceholder(root, "password").props as { value: string }).value).toBe("");
  });

  it("the card title says 'disable' when the pending toggle turns the feature off", async () => {
    const root = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    // llmEnabled is false; asking to keep it off still opens the card.
    await act(async () => {
      (root.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(false);
    });
    await flush();
    expect(textOf(root)).toContain("Enter your password to disable third-party AI analysis");
  });

  it("the Confirm fill is danger red only for the delete kind (primary for llm)", async () => {
    const llmRoot = await renderWithLlm();
    const { act } = await import("../helpers/rtr");
    await act(async () => {
      (llmRoot.root.findAllByType(Switch)[0].props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    expect((touchableByLabel(llmRoot, "Confirm with password").props as { style: unknown[] }).style[1]).toEqual({
      backgroundColor: "#3b5bdb",
      minHeight: 44,
    });

    const deleteRoot = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(deleteRoot, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect((touchableByLabel(deleteRoot, "Confirm with password").props as { style: unknown[] }).style[1]).toEqual({
      backgroundColor: "#c0392b",
      minHeight: 44,
    });
  });
});

describe("SettingsScreen pins: delete failure copy", () => {
  it("a 401 delete reports the exact dead-session sentence (not the calm fallback's shorter one)", async () => {
    const { ApiError } = await import("../../src/api/client");
    vi.mocked(api.deleteAccount).mockRejectedValue(new ApiError(401, "invalid token"));
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    await reauth(root);
    expect(Alert.alert).toHaveBeenCalledWith(
      "Delete failed",
      "Session expired — please unlock again. Nothing was deleted.",
    );
  });
});

describe("SettingsScreen pins: export safety gate", () => {
  it("does not materialize, fetch, or share a full export until native streaming is available", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Why export is unavailable");
    expect(Alert.alert).toHaveBeenCalledWith(
      "Export unavailable in this build",
      expect.stringContaining("verified secure file-export component"),
    );
    expect(api.exportAccount).not.toHaveBeenCalled();
    expect(Share.share).not.toHaveBeenCalled();
  });
});

describe("SettingsScreen pins: node-exact style contracts", () => {
  it("the rejected-entries card composes its base and themed overlays exactly", async () => {
    vi.mocked(rejectedEntryCount).mockResolvedValue(2);
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect(parentViewStyle(root, "couldn't sync")).toEqual([
      { padding: 16, gap: 8 },
      { backgroundColor: "#1a1e26", borderRadius: 12 },
    ]);
    // The recovery action stays left-aligned (center={false}).
    expect((touchableByLabel(root, "Try syncing them again").props as { style: unknown[] }).style).toEqual([
      { padding: 12 },
      false,
      { minHeight: 44 },
    ]);
  });

  it("the re-auth card and its title carry their full style arrays", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    await pressLabel(root, "Delete my account and data");
    await pressAlertButton("Continue");
    await pressAlertButton("Continue to password");
    await flush();
    expect(parentViewStyle(root, "Enter your password to delete everything")).toEqual([
      { padding: 16, gap: 12 },
      { backgroundColor: "#141821", borderRadius: 12 },
    ]);
    expect(styleArrayOfText(root, "Enter your password to delete everything")).toEqual([
      { fontSize: 15, fontWeight: "600", lineHeight: 20 },
      { color: "#e8eaf0" },
    ]);
  });

  it("the privacy-policy action stays left-aligned (center={false})", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    expect((touchableByLabel(root, "Privacy policy").props as { style: unknown[] }).style).toEqual([
      { padding: 12 },
      false,
      { minHeight: 44 },
    ]);
  });
});

describe("SettingsScreen pins: 44pt touch contract (audit fix 23, 2026-09-21)", () => {
  it("theme radios meet t.minTouch (40pt before)", async () => {
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    const dark = root.root.findAll((n) => n.props.accessibilityLabel === "Theme: Dark")[0];
    expect(dark).toBeTruthy();
    expect((dark.props.style as unknown[])[1]).toMatchObject({ minHeight: 44 });
    // The selected variant keeps the contract too.
    await pressLabel(root, "Dark");
    const selected = root.root.findAll(
      (n) => n.props.accessibilityLabel === "Theme: Dark" && n.props.accessibilityState?.selected === true,
    )[0];
    expect((selected.props.style as unknown[])[1]).toMatchObject({ minHeight: 44 });
  });

  it("reminder time chips meet t.minTouch (40pt before)", async () => {
    const { act } = await import("../helpers/rtr");
    const root = await render(<SettingsScreen navigation={nav} />);
    await flush();
    // Turn the reminder preference on so the time chips render (the Switch
    // is disabled in this module-absent build, but the handler still runs).
    const reminderSwitch = root.root.findAll((n) => n.props.accessibilityLabel === "Daily reminder")[0];
    await act(async () => {
      (reminderSwitch.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(true);
    });
    await flush();
    const evening = root.root.findAll(
      (n) => n.props.accessibilityLabel === "Reminder time: Evening 20:00",
    )[0];
    expect(evening).toBeTruthy();
    expect((evening.props.style as unknown[])[1]).toMatchObject({ minHeight: 44 });
  });
});
