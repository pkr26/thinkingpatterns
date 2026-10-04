/** Recovery-kit crypto + flow tests (wave 3, 2026-09-30). */
import { beforeEach, describe, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";

vi.mock("../src/api/client", async (importOriginal) => {
  const { ApiError } = await importOriginal<typeof import("../src/api/client")>();
  return {
    ApiError,
    api: {
      recoverLogin: vi.fn(),
      setSession: vi.fn(async () => {}),
      clearSession: vi.fn(async () => {}),
      openProcessingSession: vi.fn(async () => ({ session_token: "pst-1" })),
      resetPasswordWithRecovery: vi.fn(async () => ({})),
      keyEnvelope: vi.fn(async () => ({
        key_scheme: "v2",
        salt: "SALT==",
        kdf_params: null,
        wrapped_data_key: "WRAP==",
      })),
      cacheSalt: vi.fn(async () => {}),
      cacheKeyEnvelope: vi.fn(async () => {}),
      clearCachedSalt: vi.fn(async () => {}),
      clearCachedKeyEnvelope: vi.fn(async () => {}),
    },
  };
});

import {
  generateRecoveryKey,
  recoveryKeyFromB64,
  recoveryKeyToB64,
  recoveryKitText,
  recoveryVerifierKeyV2,
  sealDataKeyForRecovery,
  sealDataKeyForRecoveryV2,
  unsealDataKeyWithRecovery,
} from "../src/crypto/recovery";
import { ApiError as ApiErrorCtor } from "../src/api/client";
import { api } from "../src/api/client";

const mockedApi = vi.mocked(api);

beforeEach(() => {
  storage.__reset();
  vi.clearAllMocks();
  mockedApi.recoverLogin!.mockReset();
  mockedApi.setSession!.mockReset();
  mockedApi.setSession!.mockResolvedValue(undefined);
  mockedApi.cacheSalt!.mockReset();
  mockedApi.cacheSalt!.mockResolvedValue(undefined);
  mockedApi.cacheKeyEnvelope!.mockReset();
  mockedApi.cacheKeyEnvelope!.mockResolvedValue(undefined);
  mockedApi.clearSession!.mockReset();
  mockedApi.clearSession!.mockResolvedValue(undefined);
});

describe("recovery crypto", () => {
  it("round-trips the data key under the recovery key (AAD-bound)", () => {
    const recoveryKey = generateRecoveryKey();
    const dataKey = Buffer.alloc(32, 9);
    const sealed = sealDataKeyForRecovery(recoveryKey, dataKey, "user-9");
    // Envelope layout: 12B nonce + 32B key + 16B tag = 60 (the server's
    // WRAPPED_DATA_KEY_BYTES contract).
    expect(sealed.length).toBe(60);
    expect(unsealDataKeyWithRecovery(recoveryKey, sealed, "user-9")).toEqual(dataKey);
  });

  it("v2 seal/verifier are domain-separated from each other and from v1", () => {
    const recoveryKey = generateRecoveryKey();
    const dataKey = Buffer.alloc(32, 9);
    const sealedV2 = sealDataKeyForRecoveryV2(recoveryKey, dataKey, "user-9");
    // The v2 seal opens ONLY under the v2 label...
    expect(
      unsealDataKeyWithRecovery(recoveryKey, sealedV2, "user-9"),
    ).toBeNull(); // ...not the v1 label
    const verifier = recoveryVerifierKeyV2(recoveryKey);
    expect(verifier.length).toBe(32);
    // The transmitted verifier is NOT the raw key and NOT either seal KEK:
    expect(verifier.equals(recoveryKey)).toBe(false);
    expect(verifier.equals(Buffer.alloc(32, 9))).toBe(false);
  });

  it("a wrong recovery key or wrong account never opens the seal", () => {
    const recoveryKey = generateRecoveryKey();
    const sealed = sealDataKeyForRecovery(recoveryKey, Buffer.alloc(32, 5), "user-a");
    expect(unsealDataKeyWithRecovery(generateRecoveryKey(), sealed, "user-a")).toBeNull();
    expect(unsealDataKeyWithRecovery(recoveryKey, sealed, "user-b")).toBeNull();
  });

  it("the b64 helper accepts the kit's exact form and rejects others", () => {
    const key = generateRecoveryKey();
    const text = recoveryKeyToB64(key);
    expect(recoveryKeyFromB64(text)).toEqual(key);
    // Whitespace-tolerant (line-wrapped kits paste with breaks).
    expect(recoveryKeyFromB64(text.slice(0, 20) + "\n" + text.slice(20))).toEqual(key);
    expect(recoveryKeyFromB64("not base64 !!!")).toBeNull();
    expect(recoveryKeyFromB64(Buffer.alloc(31).toString("base64"))).toBeNull();
  });
});

describe("recoverAccountWithKey (the full flow)", () => {
  it("v2 kit: transmits ONLY the derived verifier, resets, refreshes caches", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const recoveryKey = generateRecoveryKey();
    const dataKey = Buffer.alloc(32, 7);
    const sealed = sealDataKeyForRecoveryV2(recoveryKey, dataKey, "user-77");
    mockedApi.recoverLogin!.mockResolvedValue({
      token: "tok",
      user_id: "user-77",
      expires_in: 900,
      role: "user",
      key_scheme: "v2",
      recovery_wrapped_data_key: sealed.toString("base64"),
      recovery_scheme: "v2",
    } as never);

    const outcome = await recoverAccountWithKey(
      "someuser",
      recoveryKeyToB64(recoveryKey),
      "a brand new passphrase",
      "v2",
    );

    expect(outcome.userId).toBe("user-77");
    expect(outcome.dataKey).toEqual(dataKey);
    // ONE recover call, carrying the DERIVED verifier (never the raw key)
    // and the v2 scheme hint.
    expect(mockedApi.recoverLogin).toHaveBeenCalledTimes(1);
    const call = mockedApi.recoverLogin!.mock.calls[0]!;
    expect(call[0]).toBe("someuser");
    expect(call[1]).toBe(recoveryVerifierKeyV2(recoveryKey).toString("base64"));
    expect(call[1]).not.toBe(recoveryKeyToB64(recoveryKey));
    expect(call[2]).toBe("v2");
    // The recovery session was stored BEFORE any dependent call.
    expect(mockedApi.setSession).toHaveBeenCalledWith("tok", "user-77", "someuser", { stillCurrent: expect.any(Function) });
    // Possession: the processing session carried the RECOVERED data key.
    expect(mockedApi.openProcessingSession).toHaveBeenCalledWith(dataKey.toString("base64"));
    // The reset proof was the DERIVED verifier, and the envelope swapped.
    const reset = mockedApi.resetPasswordWithRecovery!.mock.calls[0]!;
    expect(reset[0]).toBe(recoveryVerifierKeyV2(recoveryKey).toString("base64"));
    expect(reset[1].wrapped_data_key.length).toBeGreaterThan(0);
    expect(reset[2]).toBe("pst-1");
    // Caches follow the new credential; no half-state cleanup ran.
    expect(mockedApi.cacheSalt).toHaveBeenCalledWith("someuser", expect.any(String));
    expect(mockedApi.cacheKeyEnvelope).toHaveBeenCalledWith(
      "someuser",
      expect.objectContaining({ scheme: "v2" }),
    );
    expect(mockedApi.clearSession).not.toHaveBeenCalled();
  });

  it("legacy v1 requires explicit local selection and performs one proof request", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const key = generateRecoveryKey();
    const dataKey = Buffer.alloc(32, 3);
    mockedApi.recoverLogin!.mockResolvedValue({ token: "tok", user_id: "legacy-user", recovery_scheme: "v1", recovery_wrapped_data_key: sealDataKeyForRecovery(key, dataKey, "legacy-user").toString("base64") } as never);
    const outcome = await recoverAccountWithKey("someuser", recoveryKeyToB64(key), "a brand new passphrase", "v1");
    expect(outcome.dataKey).toEqual(dataKey);
    expect(mockedApi.recoverLogin).toHaveBeenCalledExactlyOnceWith("someuser", recoveryKeyToB64(key), "v1");
    expect(mockedApi.resetPasswordWithRecovery!.mock.calls[0]![0]).toBe(recoveryKeyToB64(key));
    expect(mockedApi.resetPasswordWithRecovery!.mock.calls[0]![2]).toBe("pst-1");
  });

  it("a uniform authentication failure cannot trigger a weaker-scheme retry", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const key = generateRecoveryKey();
    mockedApi.recoverLogin!.mockRejectedValue(new ApiErrorCtor(401, "invalid credentials", "invalid_credentials"));
    await expect(recoverAccountWithKey("someuser", recoveryKitText(key), "new passphrase", "v2")).rejects.toThrow("invalid credentials");
    expect(mockedApi.recoverLogin).toHaveBeenCalledTimes(1);
    expect(mockedApi.recoverLogin!.mock.calls[0]![1]).toBe(recoveryVerifierKeyV2(key).toString("base64"));
    expect(mockedApi.recoverLogin!.mock.calls[0]![1]).not.toBe(recoveryKeyToB64(key));
    expect(mockedApi.resetPasswordWithRecovery).not.toHaveBeenCalled();
  });

  it("a v2 prefix cannot be used with explicit v1 selection", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    await expect(recoverAccountWithKey("someuser", recoveryKitText(generateRecoveryKey()), "new passphrase", "v1")).rejects.toThrow(/v2.*legacy/i);
    expect(mockedApi.recoverLogin).not.toHaveBeenCalled();
  });

  it("a wrong recovery key never installs a session or resets credentials", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const realKey = generateRecoveryKey();
    const sealed = sealDataKeyForRecoveryV2(realKey, Buffer.alloc(32, 7), "user-1");
    mockedApi.recoverLogin!.mockResolvedValue({
      token: "tok",
      user_id: "user-1",
      expires_in: 900,
      role: "user",
      key_scheme: "v2",
      recovery_wrapped_data_key: sealed.toString("base64"),
      recovery_scheme: "v2",
    } as never);
    await expect(
      recoverAccountWithKey("someuser", recoveryKeyToB64(generateRecoveryKey()), "new passphrase", "v2"),
    ).rejects.toThrow(/did not open/i);
    expect(mockedApi.setSession).not.toHaveBeenCalled();
    expect(mockedApi.clearSession).not.toHaveBeenCalled();
    expect(mockedApi.resetPasswordWithRecovery).not.toHaveBeenCalled();
    expect(mockedApi.cacheSalt).not.toHaveBeenCalled();
  });

  it("cleans up an attempted session when secure storage fails", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const key = generateRecoveryKey();
    mockedApi.recoverLogin!.mockResolvedValue({ token: "tok", user_id: "user-1", recovery_scheme: "v2", recovery_wrapped_data_key: sealDataKeyForRecoveryV2(key, Buffer.alloc(32, 7), "user-1").toString("base64") } as never);
    mockedApi.setSession!.mockRejectedValueOnce(new Error("secure storage unavailable"));
    await expect(recoverAccountWithKey("someuser", recoveryKitText(key), "new passphrase", "v2")).rejects.toThrow("secure storage unavailable");
    expect(mockedApi.clearSession).toHaveBeenCalledOnce();
    expect(mockedApi.resetPasswordWithRecovery).not.toHaveBeenCalled();
  });

  it("reports a committed reset honestly when local caching fails", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const key = generateRecoveryKey();
    const dataKey = Buffer.alloc(32, 8);
    mockedApi.recoverLogin!.mockResolvedValue({ token: "tok", user_id: "user-1", username: "canonical", recovery_scheme: "v2", recovery_wrapped_data_key: sealDataKeyForRecoveryV2(key, dataKey, "user-1").toString("base64") } as never);
    mockedApi.cacheKeyEnvelope!.mockRejectedValueOnce(new Error("cache full"));
    const outcome = await recoverAccountWithKey("someuser", recoveryKitText(key), "new passphrase", "v2");
    expect(outcome).toMatchObject({ userId: "user-1", username: "canonical", localCacheReady: false });
    expect(outcome.dataKey).toEqual(dataKey);
    expect(mockedApi.resetPasswordWithRecovery).toHaveBeenCalledOnce();
    expect(mockedApi.clearCachedSalt).toHaveBeenCalledWith("canonical");
    expect(mockedApi.clearCachedKeyEnvelope).toHaveBeenCalledWith("canonical");
    expect(mockedApi.keyEnvelope).not.toHaveBeenCalled();
    expect(mockedApi.clearSession).not.toHaveBeenCalled();
  });
});
