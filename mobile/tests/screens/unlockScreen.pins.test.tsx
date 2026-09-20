/**
 * Deep-mutation pins for UnlockScreen (2026-09-15 Stryker campaign).
 *
 *  - the vault's ownerUserId binding after a verified online unlock
 *    (`(await api.getUserId()) ?? undefined` → `&& undefined` loses it),
 *  - the honest subtitle's themed overlay pinned to its own node (the
 *    global expectStyle matcher is satisfied by GhostButton's text, which
 *    shares {color: muted, fontSize: 14}).
 */
// @ts-nocheck

import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert, Text } from "react-native";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock() };
});

vi.mock("../../src/unlockProof", () => ({
  storeUnlockProof: vi.fn(async () => {}),
  verifyUnlockProof: vi.fn(async (): Promise<"ok" | "wrong" | "absent"> => "ok"),
  clearUnlockProof: vi.fn(async () => {}),
  unlockProofExists: vi.fn(async () => false),
}));

vi.mock("../../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/crypto/MindPatternCrypto")>();
  return {
    ...actual,
    deriveKeysAsync: vi.fn(async () => ({
      masterKey: Buffer.alloc(32, 1),
      authKey: Buffer.alloc(32, 2),
      dataKey: Buffer.alloc(32, 3),
    })),
  };
});

const signOut = vi.fn(async () => {});
const refreshActiveDays = vi.fn(async () => {});
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return {
    ...actual,
    useSession: () => ({ signOut, refreshActiveDays }),
  };
});

const { api } = await import("../../src/api/client");
const { deriveKeysAsync } = await import("../../src/crypto/MindPatternCrypto");
const { UnlockScreen } = await import("../../src/screens/UnlockScreen");
const { vault } = await import("../../src/vault");
const { render, flush, allText, pressLabel, typeInto } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");

/** Flatten a Text node's children (they may be arrays) to its exact string. */
const flat = (children: unknown): string => {
  if (typeof children === "string") return children;
  if (Array.isArray(children)) return children.map(flat).join("");
  return "";
};

beforeEach(() => {
  resetApi(api as never);
  vi.mocked(deriveKeysAsync).mockReset();
  vi.mocked(deriveKeysAsync).mockImplementation(async () => ({
    masterKey: Buffer.alloc(32, 1),
    authKey: Buffer.alloc(32, 2),
    dataKey: Buffer.alloc(32, 3),
  }));
  signOut.mockClear();
  refreshActiveDays.mockClear();
  Alert.alert.mockClear();
  vault.lock();
});

describe("UnlockScreen pins", () => {
  it("a verified online unlock binds the vault to the stored account id", async () => {
    const root = await render(<UnlockScreen />);
    await typeInto(root, "password", "correct horse");
    await pressLabel(root, "Unlock");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    expect(vault.ownerUserId()).toBe("user-1");
    // H-2 pin: the PASSWORD path always stores a KNOWN auth key (only the
    // biometric path passes authKeyKnown:false).
    expect(vault.get().authKeyKnown).toBe(true);
  });

  it("the honest subtitle carries its themed overlay on its own node", async () => {
    const root = await render(<UnlockScreen />);
    await flush();
    const node = root.root
      .findAllByType(Text)
      .find((n) => flat(n.props.children).includes("Your journal is encrypted with keys only you hold"));
    expect(node).toBeDefined();
    expect(node.props.style).toEqual(
      [{ textAlign: "center", marginBottom: 24, lineHeight: 20 }, { color: "#8a91a3", fontSize: 14 }],
    );
  });
});
