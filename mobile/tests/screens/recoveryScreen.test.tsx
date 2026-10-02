/**
 * RecoveryScreen (wave 3, 2026-09-30; reworked 2026-10-01): the recovery-
 * key flow's UI contract — validation never leaves the device, the vault
 * unlocks with the M7 authKeyKnown:false marker (the auth-key slot holds a
 * placeholder until a full sign-in), success lands on the Entry screen,
 * and every failure path stays calm. The screen rework shipped without a
 * suite while CI was quota-blocked; this is the coverage that goes with
 * it. The crypto/flow logic itself is pinned by tests/recoveryFlow.test.ts
 * — here recoverAccountWithKey is the seam.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Text, TextInput } from "react-native";
import type { ReactTestInstance, ReactTestRenderer } from "react-test-renderer";

vi.mock("../../src/recoveryFlow", () => ({
  recoverAccountWithKey: vi.fn(),
}));

const markLoggedIn = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ markLoggedIn }) };
});

const { recoverAccountWithKey } = await import("../../src/recoveryFlow");
const { RecoveryScreen } = await import("../../src/screens/RecoveryScreen");
const { vault } = await import("../../src/vault");
const { render, act, allText, pressLabel, touchableByLabel } = await import("../helpers/rtr");

const nav = { navigate: vi.fn() };
const DATA_KEY = Buffer.alloc(32, 9);
const STRONG = "Str0ng-new-pass-2026!";

/** RecoveryScreen's inputs carry accessibility labels, not placeholders
 *  (they render their own label Text above each field). */
function inputByLabel(root: ReactTestRenderer, label: string): ReactTestInstance {
  const node = root.root.findAllByType(TextInput).find((n) => n.props?.accessibilityLabel === label);
  if (!node) throw new Error(`no TextInput labeled ${JSON.stringify(label)}`);
  return node;
}

async function fill(
  root: ReactTestRenderer,
  label: string,
  value: string,
): Promise<void> {
  const input = inputByLabel(root, label);
  await act(async () => {
    input.props.onChangeText?.(value);
  });
}

async function screen(): Promise<ReactTestRenderer> {
  return render(<RecoveryScreen navigation={nav} />);
}

async function pressRecover(root: ReactTestRenderer): Promise<void> {
  await pressLabel(root, "Recover and set new password");
}

describe("RecoveryScreen", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Strip per-test implementations/queues, not just call records.
    vi.mocked(recoverAccountWithKey).mockReset();
    // The vault's real unlock would mutate shared module state; the call
    // args (data key, authKeyKnown marker) are what this screen owns.
    vi.spyOn(vault, "unlock").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders the calm recovery copy", async () => {
    const root = await screen();
    const text = allText(root).join(" ");
    expect(text).toContain("Recover your journal");
    expect(text).toContain("only the password changes");
  });

  it("empty fields surface guidance and fire nothing", async () => {
    const root = await screen();
    await pressRecover(root);
    expect(allText(root).join(" ")).toContain("Enter your username and the recovery key first.");
    expect(recoverAccountWithKey).not.toHaveBeenCalled();
    expect(vault.unlock).not.toHaveBeenCalled();
  });

  it("a policy-failing new password is refused before anything leaves the device", async () => {
    const root = await screen();
    await fill(root, "Username", "pat");
    await fill(root, "Recovery key", "aaaa");
    await fill(root, "New password (12+ characters)", "short");
    await fill(root, "Confirm new password", "short");
    await pressRecover(root);
    expect(allText(root).join(" ")).toContain("at least 12 characters");
    expect(recoverAccountWithKey).not.toHaveBeenCalled();
  });

  it("a mismatched confirmation is refused before any network call", async () => {
    const root = await screen();
    await fill(root, "Username", "pat");
    await fill(root, "Recovery key", "aaaa");
    await fill(root, "New password (12+ characters)", STRONG);
    await fill(root, "Confirm new password", "a different one entirely!");
    await pressRecover(root);
    expect(allText(root).join(" ")).toContain("The two new passwords do not match.");
    expect(recoverAccountWithKey).not.toHaveBeenCalled();
  });

  it("success: the flow runs once, the vault unlocks with the M7 authKeyKnown marker, done lands on Entry", async () => {
    vi.mocked(recoverAccountWithKey).mockResolvedValue({
      userId: "u-77",
      username: "pat",
      dataKey: DATA_KEY,
    });
    const root = await screen();
    await fill(root, "Username", "pat");
    await fill(root, "Recovery key", "a2V5");
    await fill(root, "New password (12+ characters)", STRONG);
    await fill(root, "Confirm new password", STRONG);
    await pressRecover(root);
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(recoverAccountWithKey).toHaveBeenCalledWith("pat", "a2V5", STRONG);
    expect(vault.unlock).toHaveBeenCalledTimes(1);
    const call = vi.mocked(vault.unlock).mock.calls[0]!;
    expect(call[1]).toBe("u-77");
    expect(call[0].dataKey).toEqual(DATA_KEY);
    // M7 (2026-10-01): the auth-key slot holds a placeholder during this
    // unlock — the vault must not claim the password is known.
    expect(call[2]).toEqual({ authKeyKnown: false });
    expect(markLoggedIn).toHaveBeenCalledTimes(1);
    expect(allText(root).join(" ")).toContain("Recovered. Your journal is unlocked");

    // Done disables the action: a completed recovery cannot be re-fired.
    expect(touchableByLabel(root, "Recover and set new password").props.disabled).toBe(true);

    // The calm beat, then the Entry screen.
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 950));
    });
    expect(nav.navigate).toHaveBeenCalledWith("Entry");
  });

  it("a typed failure surfaces the flow's message and stays retryable", async () => {
    vi.mocked(recoverAccountWithKey).mockRejectedValueOnce(
      new Error("the recovery key must be 32 bytes of base64 (copy it exactly from your kit)"),
    );
    const root = await screen();
    await fill(root, "Username", "pat");
    await fill(root, "Recovery key", "aaaa");
    await fill(root, "New password (12+ characters)", STRONG);
    await fill(root, "Confirm new password", STRONG);
    await pressRecover(root);
    expect(allText(root).join(" ")).toContain("copy it exactly from your kit");
    expect(vault.unlock).not.toHaveBeenCalled();
    expect(touchableByLabel(root, "Recover and set new password").props.disabled).toBe(false);
  });

  it("a non-Error rejection falls back to the calm generic copy", async () => {
    vi.mocked(recoverAccountWithKey).mockRejectedValueOnce("network down");
    const root = await screen();
    await fill(root, "Username", "pat");
    await fill(root, "Recovery key", "a2V5");
    await fill(root, "New password (12+ characters)", STRONG);
    await fill(root, "Confirm new password", STRONG);
    await pressRecover(root);
    expect(allText(root).join(" ")).toContain("Recovery did not complete.");
  });

  it("the quiet escapes stay reachable: back to sign in, crisis resources", async () => {
    const root = await screen();
    await pressLabel(root, "Back to sign in");
    expect(nav.navigate).toHaveBeenCalledWith("Login");
    await pressLabel(root, "Need help now? Crisis resources");
    expect(nav.navigate).toHaveBeenCalledWith("Crisis");
  });
});
