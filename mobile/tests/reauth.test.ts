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
import { verifyPasswordForVault, isVerificationFailedError, isSessionExpiredError } from "../src/reauth";
import { vault } from "../src/vault";
import { api, ApiError } from "../src/api/client";

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

  it("refuses an empty password before touching the vault or the network", async () => {
    expect(await verifyPasswordForVault("")).toEqual({ ok: false, reason: "wrong-password" });
    expect(api.getUsername).not.toHaveBeenCalled();
  });

  it("reports offline when the fetched salt comes back empty", async () => {
    vi.mocked(api.getCachedSalt).mockResolvedValue(null);
    vi.mocked(api.saltFor).mockResolvedValue({ salt: "" } as never);
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "offline" });
  });

  it("a vault holding a malformed (wrong-length) key never matches", async () => {
    // keysEqual's length guard: a truncated/corrupt key in the vault must
    // fail closed, not crash the comparison.
    vault.lock();
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(16, 9), dataKey: Buffer.alloc(32) });
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "wrong-password" });
  });

  it("a similar-but-different salt derivation never matches the vault key", async () => {
    // Same password, DIFFERENT salt (the cross-origin poisoning case).
    vi.mocked(api.getCachedSalt).mockResolvedValue(Buffer.alloc(16, 9).toString("base64"));
    expect(await verifyPasswordForVault(PASSWORD)).toEqual({ ok: false, reason: "wrong-password" });
  });
});

describe("verifier-failure classification (403 vs 401)", () => {
  it("403 verification_failed = wrong verifier, vault can stay unlocked", () => {
    expect(isVerificationFailedError(new ApiError(403, "verification failed", "verification_failed"))).toBe(true);
    // Legacy servers without the envelope: status alone carries the meaning.
    expect(isVerificationFailedError(new ApiError(403, "forbidden"))).toBe(true);
    expect(isSessionExpiredError(new ApiError(403, "verification failed", "verification_failed"))).toBe(false);
  });

  it("a 403 with a DIFFERENT code is not a verifier failure", () => {
    expect(isVerificationFailedError(new ApiError(403, "nope", "quota_exceeded"))).toBe(false);
  });

  it("401 = session expired (the vault is already locked by the client hook)", () => {
    expect(isSessionExpiredError(new ApiError(401, "invalid token", "unauthorized"))).toBe(true);
    expect(isSessionExpiredError(new ApiError(401, "invalid token"))).toBe(true);
    expect(isVerificationFailedError(new ApiError(401, "invalid token"))).toBe(false);
  });

  it("other failures classify as neither", () => {
    expect(isVerificationFailedError(new ApiError(500, "boom"))).toBe(false);
    expect(isSessionExpiredError(new ApiError(500, "boom"))).toBe(false);
    expect(isVerificationFailedError(new Error("network"))).toBe(false);
    expect(isSessionExpiredError("not an error object")).toBe(false);
  });
});
