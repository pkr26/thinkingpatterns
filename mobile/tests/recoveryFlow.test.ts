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
      openProcessingSession: vi.fn(async () => "pst-1"),
      resetPasswordWithRecovery: vi.fn(async () => ({})),
      keyEnvelope: vi.fn(async () => ({
        key_scheme: "v2",
        salt: "SALT==",
        kdf_params: null,
        wrapped_data_key: "WRAP==",
      })),
      cacheSalt: vi.fn(async () => {}),
      cacheKeyEnvelope: vi.fn(async () => {}),
    },
  };
});

import {
  generateRecoveryKey,
  recoveryKeyFromB64,
  recoveryKeyToB64,
  sealDataKeyForRecovery,
  unsealDataKeyWithRecovery,
} from "../src/crypto/recovery";
import { api } from "../src/api/client";

const mockedApi = vi.mocked(api);

beforeEach(() => {
  storage.__reset();
  vi.clearAllMocks();
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
  it("recovers, proves possession, swaps the credential, refreshes caches", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const recoveryKey = generateRecoveryKey();
    const dataKey = Buffer.alloc(32, 7);
    const sealed = sealDataKeyForRecovery(recoveryKey, dataKey, "user-77");
    mockedApi.recoverLogin!.mockResolvedValue({
      token: "tok",
      user_id: "user-77",
      expires_in: 900,
      role: "user",
      key_scheme: "v2",
      recovery_wrapped_data_key: sealed.toString("base64"),
    } as never);

    const outcome = await recoverAccountWithKey(
      "someuser",
      recoveryKeyToB64(recoveryKey),
      "a brand new passphrase",
    );

    expect(outcome.userId).toBe("user-77");
    expect(outcome.dataKey).toEqual(dataKey);
    // The recovery session was stored BEFORE any dependent call.
    expect(mockedApi.setSession).toHaveBeenCalledWith("tok", "user-77", "someuser");
    // Possession: the processing session carried the RECOVERED data key.
    expect(mockedApi.openProcessingSession).toHaveBeenCalledWith(dataKey.toString("base64"));
    // The reset used the recovery key as its proof and swapped the envelope.
    const reset = mockedApi.resetPasswordWithRecovery!.mock.calls[0]!;
    expect(reset[0]).toBe(recoveryKeyToB64(recoveryKey));
    expect(reset[1].wrapped_data_key.length).toBeGreaterThan(0);
    // Caches follow the new credential.
    expect(mockedApi.cacheSalt).toHaveBeenCalledWith("someuser", expect.any(String));
    expect(mockedApi.cacheKeyEnvelope).toHaveBeenCalledWith(
      "someuser",
      expect.objectContaining({ scheme: "v2" }),
    );
  });

  it("a wrong recovery key fails honestly before any reset", async () => {
    const { recoverAccountWithKey } = await import("../src/recoveryFlow");
    const realKey = generateRecoveryKey();
    const sealed = sealDataKeyForRecovery(realKey, Buffer.alloc(32, 7), "user-1");
    mockedApi.recoverLogin!.mockResolvedValue({
      token: "tok",
      user_id: "user-1",
      expires_in: 900,
      role: "user",
      key_scheme: "v2",
      recovery_wrapped_data_key: sealed.toString("base64"),
    } as never);
    await expect(
      recoverAccountWithKey("someuser", recoveryKeyToB64(generateRecoveryKey()), "new passphrase"),
    ).rejects.toThrow(/did not open/i);
    expect(mockedApi.resetPasswordWithRecovery).not.toHaveBeenCalled();
  });
});
