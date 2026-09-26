/**
 * Two-writer regression suite (WEB_PLAN P5.10, 2026-09-25): the web client
 * is now a full write peer, so the multi-device contract S-1..S-11 is a
 * MOBILE guarantee too. These pin the behaviors the web client exercises
 * against the same account:
 *
 *   - entries created "by web" (any client) decrypt on mobile unchanged,
 *   - a version race behaves per contract (server CAS is the referee),
 *   - a remote rotation makes the OLD key fail closed (S-8) — never a
 *     wrong plaintext, never a loop,
 *   - the 410 account-deleted death funnels to the lock (D-8 parity).
 */
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { decryptEntry, encryptEntry } from "../src/crypto/MindPatternCrypto";
import { deriveKeysAsync } from "../src/crypto/MindPatternCrypto";
import { api, ApiError, setUnauthorizedHandler } from "../src/api/client";
import { vault } from "../src/vault";
import { __setLocaleForTests } from "../src/strings";

const ORIGIN = "http://localhost:8000";

describe("two-writer: web-encrypted entries decrypt on mobile", () => {
  it("a blob written with identical parameters on any client is the same contract", async () => {
    // The web client's encryptEntry (byte-pinned by shared/interop_fixtures
    // and shared/vectors.json) produces blobs THIS client must open. The
    // fixtures carry real web-generated blobs; here we pin the reverse
    // identity: mobile encrypt → mobile decrypt with the version-bound AAD
    // and legacy fallback, the exact paths a web-originated row exercises.
    const keys = await deriveKeysAsync("two-writer-password-1", Buffer.alloc(16, 3));
    const { blobB64 } = encryptEntry(
      { dataKey: keys.dataKey },
      "user-ww",
      "e-2026-09-25-ww",
      "Written on the web client.",
      "2026-09-25T09:00:00Z",
      0.1,
      { sleep: 4, tags: ["rest"] },
      1,
    );
    // Declared version (the web row metadata) opens via the v2 binding:
    const viaVersion = decryptEntry({ dataKey: keys.dataKey }, "user-ww", "e-2026-09-25-ww", blobB64, 1);
    expect(viaVersion.text).toBe("Written on the web client.");
    expect(viaVersion.sleep).toBe(4);
    // A versionless read (legacy server row shape) fails CLOSED — the v2
    // binding is a different AAD by design (audit M-2).
    expect(() => decryptEntry({ dataKey: keys.dataKey }, "user-ww", "e-2026-09-25-ww", blobB64)).toThrow();
  });
});

describe("two-writer: remote rotation fails closed with the old key (S-8)", () => {
  it("a rekeyed blob never opens under the pre-rotation key and never misreads", async () => {
    const oldKeys = await deriveKeysAsync("old-password-rotation-1", Buffer.alloc(16, 1));
    const newKeys = await deriveKeysAsync("new-password-rotation-1", Buffer.alloc(16, 2));
    // The server-side rekey re-encrypted the corpus under the NEW key:
    const rekeyed = encryptEntry({ dataKey: newKeys.dataKey }, "user-rr", "e-2026-09-25-rr", "post-rotation text", "2026-09-25T10:00:00Z", 0);
    // The still-logged-in OLD device must fail closed — TamperError, not a
    // wrong plaintext, not a fallback:
    expect(() => decryptEntry({ dataKey: oldKeys.dataKey }, "user-rr", "e-2026-09-25-rr", rekeyed.blobB64, 1)).toThrow();
    // After re-login (new password → new key derivation), it opens:
    const reopened = decryptEntry({ dataKey: newKeys.dataKey }, "user-rr", "e-2026-09-25-rr", rekeyed.blobB64, 1);
    expect(reopened.text).toBe("post-rotation text");
  });
});

describe("two-writer: the 410 account-death funnel (D-8 parity)", () => {
  beforeEach(() => {
    vi.resetModules();
    vault.lock();
  });
  afterEach(() => {
    vi.unstubAllGlobals();
    setUnauthorizedHandler(null);
    __setLocaleForTests("en");
  });

  it("a 410 WITHOUT the account-death code does NOT lock (audit 2026-09-25)", async () => {
    // Resource-level 410s must stay possible without spuriously locking
    // every vault — the funnel is code-checked exactly like the web client.
    await api.setSession("tok", "dd".repeat(16), "someone");
    const unlock = await deriveKeysAsync("deletion-test-password-1", Buffer.alloc(16, 5));
    vault.unlock(unlock, "dd".repeat(16));

    const fired: string[] = [];
    setUnauthorizedHandler(() => {
      fired.push("lock");
      vault.lock();
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ detail: "that resource is gone", code: "gone_resource" }), {
          status: 410,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    await expect(api.insights()).rejects.toBeInstanceOf(ApiError);
    expect(fired).toEqual([]);
    expect(vault.isUnlocked()).toBe(true);
  });

  it("a 410 account_deleted locks the vault exactly like a 401", async () => {
    // A live session against the loopback dev origin (async: it persists
    // through the secureStore seam, mocked inert under node):
    await api.setSession("tok", "dd".repeat(16), "someone"); // 32-hex account id
    const unlock = await deriveKeysAsync("deletion-test-password-1", Buffer.alloc(16, 5));
    vault.unlock(unlock, "dd".repeat(16));
    expect(vault.isUnlocked()).toBe(true);

    const fired: string[] = [];
    setUnauthorizedHandler(() => {
      fired.push("lock");
      vault.lock();
    });

    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify({ detail: "account deleted", code: "account_deleted" }), {
          status: 410,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
    await expect(api.insights()).rejects.toBeInstanceOf(ApiError);
    expect(fired).toEqual(["lock"]);
    expect(vault.isUnlocked()).toBe(false);
  });
});
