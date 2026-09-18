/**
 * Deep-mutation pins for navigation, theme and reauth (2026-09-15 Stryker
 * campaign). Targets:
 *  - navigation: the BootSplash's themed style overlays pinned TO THEIR NODES
 *    (the crisis screen renders the same palette values and masked whole-tree
 *    style asserts), the inMain conjunction (an early consume of the pending
 *    onboarding flag), and the loading branch's Crisis screen options,
 *  - theme: the exact type-scale entries and palette hex values no existing
 *    test pins (dark/light flags, borders, light primaryBright/sparkDown),
 *  - reauth: keysEqual's length guard against a longer prefix key, the salt
 *    fallback catch, and the zeroize calls on both match and mismatch.
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Text, View } from "react-native";

vi.mock("../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api/client")>();
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ...actual, ApiError, api: makeApiMock() };
});

vi.mock("../src/offlineQueue", () => ({
  enqueue: vi.fn(async () => {}),
  flushQueue: vi.fn(async () => 0),
  QueueFullError: class QueueFullError extends Error {},
  rejectedEntryCount: vi.fn(async () => 0),
  requeueRejected: vi.fn(async () => 0),
  quarantinedQueueExists: vi.fn(async () => false),
  hasLegacyQueueRecovery: vi.fn(async () => false),
}));

let sessionState: Record<string, unknown> = { authStatus: "loading", unlocked: false };
vi.mock("../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/store")>();
  return {
    ...actual,
    useSession: () => sessionState,
  };
});

// Spy on zeroize while keeping the real fill: the reauth zeroize pins count
// argument shapes (3 buffers on mismatch, 2 on success).
vi.mock("../src/crypto/kdf", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/kdf")>();
  return { ...actual, zeroize: vi.fn(actual.zeroize) };
});

const { AppNavigator } = await import("../src/navigation");
const { api } = await import("../src/api/client");
const { darkTheme, lightTheme } = await import("../src/theme");
const { deriveKeys, deriveKeysAsync } = await import("../src/crypto/MindPatternCrypto");
const { verifyPasswordForVault } = await import("../src/reauth");
const { zeroize } = await import("../src/crypto/kdf");
const { vault } = await import("../src/vault");
const { takePendingOnboarding, queueOnboarding } = await import("../src/onboarding");
const { render, flush, screenNames, screenOptions, act } = await import("./helpers/rtr");
const { resetApi } = await import("./helpers/apiMock");
const { navigationStub } = await import("./helpers/navigationStackMock");

const flat = (children: unknown): string => {
  if (typeof children === "string") return children;
  if (Array.isArray(children)) return children.map(flat).join("");
  return "";
};

const styleArray = (node: { props: { style?: unknown } }): unknown[] => {
  const style = node.props.style;
  return Array.isArray(style) ? style : [style];
};

const splashBase = { flex: 1, alignItems: "center", justifyContent: "center", gap: 12 };

beforeEach(() => {
  resetApi(api as never);
  navigationStub.navigate.mockClear();
  navigationStub.popToTop.mockClear();
  navigationStub.replace.mockClear();
  takePendingOnboarding(); // drain any leftover between tests
  vault.lock();
  sessionState = { authStatus: "loading", unlocked: false };
});

describe("navigation pins: BootSplash themed styles are pinned to their nodes", () => {
  it("the splash View carries its themed background INSIDE its own style array", async () => {
    sessionState = { authStatus: "loading", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    const splash = root.root
      .findAllByType(View)
      .find((n) => styleArray(n).some((s) => JSON.stringify(s) === JSON.stringify(splashBase)));
    expect(splash).toBeDefined();
    // The themed overlay must be an entry of THE SAME style array (CrisisScreen
    // renders #0f1115 elsewhere in the tree, so a whole-tree assert is blind).
    expect(styleArray(splash)).toContainEqual({ backgroundColor: "#0f1115" });
  });

  it("the brand Text node carries the themed text color in its own style array", async () => {
    sessionState = { authStatus: "loading", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    const brand = root.root.findAllByType(Text).find((n) => flat(n.props.children) === "MindPattern");
    expect(brand).toBeDefined();
    expect(styleArray(brand)).toContainEqual({ fontSize: 28, fontWeight: "700" });
    expect(styleArray(brand)).toContainEqual({ color: "#e8eaf0" });
  });

  it("the tagline Text node carries exactly the muted 13px style object", async () => {
    sessionState = { authStatus: "loading", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    const tagline = root.root
      .findAllByType(Text)
      .find((n) => flat(n.props.children) === "Your patterns, from your words. Encrypted on this device.");
    expect(tagline).toBeDefined();
    expect(tagline.props.style).toEqual({ color: "#8a91a3", fontSize: 13 });
  });
});

describe("navigation pins: inMain conjunction and pending onboarding", () => {
  it("a non-main state with unlocked=true must not consume the pending onboarding flag", async () => {
    queueOnboarding();
    // loggedOut + unlocked: NOT the main flow — the pending flag survives.
    sessionState = { authStatus: "loggedOut", unlocked: true };
    const root = await render(<AppNavigator />);
    await flush();
    expect(screenNames(root)).toEqual(["Login", "Crisis"]);

    // A loading hop resets any early showOnboarding state…
    sessionState = { authStatus: "loading", unlocked: false };
    await act(async () => {
      root.update(<AppNavigator />);
    });
    await flush();

    // …so entering the main flow NOW must consume the still-pending flag.
    sessionState = { authStatus: "loggedIn", unlocked: true };
    await act(async () => {
      root.update(<AppNavigator />);
    });
    await flush();
    expect(screenNames(root)[0]).toBe("Onboarding");
  });
});

describe("navigation pins: loading-branch Crisis options", () => {
  it("the Crisis screen keeps its 'Get help' title while the session resolves", async () => {
    sessionState = { authStatus: "loading", unlocked: false };
    const root = await render(<AppNavigator />);
    await flush();
    expect(screenNames(root)).toEqual(["Booting", "Crisis"]);
    expect(screenOptions(root, "Crisis")).toEqual({ title: "Get help" });
  });
});

describe("theme pins: exact scale and palette values", () => {
  it("the display/question/titleLg type entries are the full contract", () => {
    expect(darkTheme.type.display).toEqual({ fontSize: 34, fontWeight: "700" });
    expect(darkTheme.type.question).toEqual({ fontSize: 22, fontWeight: "600", lineHeight: 30 });
    expect(darkTheme.type.titleLg).toEqual({ fontSize: 20, fontWeight: "700", lineHeight: 27 });
    // One shared scale object: the light theme reads the same entries.
    expect(lightTheme.type.display).toBe(darkTheme.type.display);
  });

  it("theme flags and the otherwise-unpinned palette hexes are exact", () => {
    expect(darkTheme.dark).toBe(true);
    expect(lightTheme.dark).toBe(false);
    expect(darkTheme.colors.border).toBe("#222733");
    expect(lightTheme.colors.border).toBe("#d5dae4");
    expect(lightTheme.colors.primaryBright).toBe("#3b5bdb");
    expect(lightTheme.colors.sparkDown).toBe("#c64650");
  });
});

describe("reauth pins", () => {
  const SALT = Buffer.alloc(16, 3);
  const SALT_B64 = SALT.toString("base64");
  const PASSWORD = "correct horse battery staple";
  const freshKeys = () => deriveKeys(PASSWORD, SALT);

  beforeEach(() => {
    vi.mocked(api.getUsername).mockClear();
    vi.mocked(api.getUsername).mockImplementation(async () => "alice");
    vi.mocked(api.getCachedSalt).mockClear();
    vi.mocked(api.getCachedSalt).mockImplementation(async () => SALT_B64);
    vi.mocked(api.saltFor).mockClear();
    vi.mocked(api.cacheSalt).mockClear();
    vi.mocked(api.cacheSalt).mockImplementation(async () => {});
    vault.lock();
    vault.unlock({ ...freshKeys() });
    vi.mocked(zeroize).mockClear();
  });

  it("a vault key LONGER than the derived key is a mismatch even if it extends it (length guard)", async () => {
    vault.lock();
    const correct = freshKeys();
    // 33-byte authKey whose first 32 bytes ARE the correct key: byte-for-byte
    // equal over the derived length — only the length guard rejects it.
    vault.unlock({
      masterKey: Buffer.alloc(32),
      authKey: Buffer.concat([Buffer.from(correct.authKey), Buffer.from([0x99])]),
      dataKey: Buffer.alloc(32),
    });
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "wrong-password" });
  });

  it("a salt fetched online but failing to cache reports offline (the catch returns)", async () => {
    vi.mocked(api.getCachedSalt).mockResolvedValue(null);
    vi.mocked(api.saltFor).mockResolvedValue({ salt: SALT_B64 } as never);
    vi.mocked(api.cacheSalt).mockRejectedValue(new Error("disk full") as never);
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "offline" });
  });

  it("a wrong password zeroizes all three derived buffers", async () => {
    await verifyPasswordForVault("wrong password");
    expect(vi.mocked(zeroize).mock.calls.some((c) => c.length === 3)).toBe(true);
  });

  it("a correct password zeroizes master and data keys (2 buffers), never the verifier", async () => {
    const result = await verifyPasswordForVault(PASSWORD);
    expect(result.ok).toBe(true);
    expect(vi.mocked(zeroize).mock.calls.some((c) => c.length === 2)).toBe(true);
    expect(vi.mocked(zeroize).mock.calls.some((c) => c.length === 3)).toBe(false);
  });
});
