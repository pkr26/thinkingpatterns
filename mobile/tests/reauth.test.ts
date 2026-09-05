/**
 * H2: password re-authentication for destructive actions. The verifier is
 * only released when the typed password re-derives the vault's own key.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

vi.mock("../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ApiError, api: makeApiMock() };
});

import { deriveKeys } from "../src/crypto/MindPatternCrypto";
import { verifyPasswordForVault } from "../src/reauth";
import { vault } from "../src/vault";
import { api } from "../src/api/client";

const SALT = Buffer.alloc(16, 3);
const SALT_B64 = SALT.toString("base64"); // the salt the vault keys derive from
const PASSWORD = "correct horse battery staple";

/** Fresh keys per use: vault.lock() zeroizes the shared underlying buffers,
 *  so a module-level singleton would read back as zeros after the first test. */
const freshKeys = (): { masterKey: Buffer; authKey: Buffer; dataKey: Buffer } => deriveKeys(PASSWORD, SALT);

beforeEach(() => {
  storage.__reset();
  vi.mocked(api.getUsername).mockClear();
  vi.mocked(api.getUsername).mockImplementation(async () => "alice");
  vi.mocked(api.getCachedSalt).mockClear();
  vi.mocked(api.getCachedSalt).mockImplementation(async () => SALT_B64);
  vi.mocked(api.saltFor).mockClear();
  vault.lock();
  // The vault holds the keys the CORRECT password derives.
  vault.unlock({ ...freshKeys() });
});

describe("verifyPasswordForVault", () => {
  it("releases the verifier for the correct password", async () => {
    const result = await verifyPasswordForVault(PASSWORD);
    expect(result).toEqual({ ok: true, verifierB64: freshKeys().authKey.toString("base64") });
  });

  it("refuses a wrong password without leaking the verifier", async () => {
    const result = await verifyPasswordForVault("wrong password");
    expect(result).toEqual({ ok: false, reason: "wrong-password" });
  });

  it("refuses when the vault is locked", async () => {
    vault.lock();
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "locked" });
  });

  it("refuses when no account is stored", async () => {
    vi.mocked(api.getUsername).mockResolvedValue(null);
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "no-account" });
  });

  it("falls back to fetching the salt online when none is cached", async () => {
    vi.mocked(api.getCachedSalt).mockResolvedValue(null);
    vi.mocked(api.saltFor).mockResolvedValue({ salt: SALT_B64 } as never);
    const result = await verifyPasswordForVault(PASSWORD);
    expect(result).toEqual({ ok: true, verifierB64: freshKeys().authKey.toString("base64") });
    expect(api.cacheSalt).toHaveBeenCalledWith("alice", SALT_B64);
  });

  it("reports offline when no salt is available anywhere", async () => {
    vi.mocked(api.getCachedSalt).mockResolvedValue(null);
    vi.mocked(api.saltFor).mockRejectedValue(new Error("offline") as never);
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "offline" });
  });

  it("a similar-but-different salt derivation never matches the vault key", async () => {
    // Same password, DIFFERENT salt (the cross-origin poisoning case).
    vi.mocked(api.getCachedSalt).mockResolvedValue(Buffer.alloc(16, 9).toString("base64"));
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "wrong-password" });
  });
});
