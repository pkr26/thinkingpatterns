import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { deriveMasterKey, toBase64, zeroize } from "../src/crypto/core";
import { derivePatientKeys } from "../src/crypto/keys";
import { freshStepUp } from "../src/reauth";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";

const PASSWORD = "fresh-step-up-password-7!";
const SALT = new Uint8Array(16).fill(23);

async function unlockForPassword(password = PASSWORD): Promise<void> {
  const master = await deriveMasterKey(password, SALT);
  const keys = await derivePatientKeys(master);
  const authKey = new Uint8Array(keys.authKey);
  const dataKey = new Uint8Array(32).fill(9);
  zeroize(master, keys.masterKey, keys.authKey, keys.dataKey);
  vault.unlock({ authKey, dataKey }, "user-1");
}

beforeEach(async () => {
  resetTestState();
  installSession("user-1", "alice");
  await unlockForPassword();
});

afterEach(() => {
  vi.unstubAllGlobals();
  vault.lock();
});

describe("fresh action-bound step-up", () => {
  it("derives from the freshly typed password and sends only the verifier and action", async () => {
    const fetch = stubFetch((url, init) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: toBase64(SALT) });
      if (url.endsWith("/auth/key-envelope")) return jsonResponse({ key_scheme: "v1", salt: toBase64(SALT), kdf_params: null, wrapped_data_key: null });
      if (url.endsWith("/account/step-up")) {
        expect(JSON.parse(String(init.body))).toMatchObject({ action: "llm_consent", verifier: expect.any(String) });
        expect(String(init.body)).not.toContain(PASSWORD);
        return jsonResponse({ proof: "one-use-proof", action: "llm_consent", expires_in: 120 });
      }
      return jsonResponse({}, { status: 404 });
    });

    await expect(freshStepUp(PASSWORD, "llm_consent")).resolves.toEqual({ ok: true, proof: "one-use-proof" });
    expect(fetch.mock.calls.filter(([url]) => String(url).endsWith("/account/step-up"))).toHaveLength(1);
  });

  it("rejects a wrong password locally without requesting a proof or target mutation", async () => {
    const fetch = stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: toBase64(SALT) });
      if (url.endsWith("/auth/key-envelope")) return jsonResponse({ key_scheme: "v1", salt: toBase64(SALT), kdf_params: null, wrapped_data_key: null });
      return jsonResponse({ detail: "must not be called" }, { status: 500 });
    });

    await expect(freshStepUp("definitely-wrong-password", "account_delete")).resolves.toEqual({ ok: false, reason: "wrong-password" });
    const urls = fetch.mock.calls.map(([url]) => String(url));
    expect(urls.some((url) => url.endsWith("/account/step-up"))).toBe(false);
    expect(urls.some((url) => url.endsWith("/account"))).toBe(false);
  });

  it("does not convert an expired or replayed proof response into success", async () => {
    stubFetch((url) => {
      if (url.endsWith("/auth/salt")) return jsonResponse({ salt: toBase64(SALT) });
      if (url.endsWith("/auth/key-envelope")) return jsonResponse({ key_scheme: "v1", salt: toBase64(SALT), kdf_params: null, wrapped_data_key: null });
      return jsonResponse({ detail: "replayed proof", code: "step_up_invalid" }, { status: 403 });
    });

    await expect(freshStepUp(PASSWORD, "sharing_revoke")).rejects.toMatchObject({ status: 403, code: "step_up_invalid" });
  });
});
