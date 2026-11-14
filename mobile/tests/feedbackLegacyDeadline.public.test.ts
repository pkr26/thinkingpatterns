/** Supported direct legacy clear: a deadline and genuine vault-key proof belong to the caller. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../src/api/client";
import { vault } from "../src/vault";
import { accountStorageKey } from "../src/accountStorage";
import * as feedback from "../src/questionFeedback";
import { engine } from "../src/crypto/engine";
import { captureLocalWritePermit, installLocalDataKey, localWriteScopeEpoch, __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";

const USER = "a".repeat(32), KEY = Buffer.alloc(32, 21);
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); runTestControl(__resetLocalKeyLifecycleForTests);
  vault.lock(); await api.setSession("feedback caller deadline bearer", USER, "alice");
  vault.unlock({ masterKey: Buffer.alloc(32, 3), authKey: Buffer.alloc(32, 4), dataKey: Buffer.from(KEY) }, USER);
  installLocalDataKey(USER, vault.get().dataKey);
});
afterEach(async () => { vi.restoreAllMocks(); vi.useRealTimers(); vault.lock(); await api.clearSession(); storage.__reset(); });

it("a direct legacy clear preserves feedback when its caller deadline expires during genuine key validation", async () => {
  await feedback.recordFeedbackTap(KEY, USER, "kept until current recompute", true);
  const slot = accountStorageKey.feedback(USER), nativeRead = storage.getItem.bind(storage);
  const beforeWire = await nativeRead(slot);
  expect(typeof beforeWire).toBe("string");
  const permit = captureLocalWritePermit(USER, KEY), epoch = localWriteScopeEpoch();
  const fingerprint = engine.createHash("sha256").update(vault.get().dataKey).digest("hex");
  const startedAt = Date.UTC(2026, 9, 29, 12), expiresAt = startedAt + 1;
  let validatingCallerKey = false, expireAtProofCompletion = false;
  let clear: Promise<void> | undefined;
  try {
    vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(startedAt);
    const nativeCreateHash = engine.createHash.bind(engine);
    vi.spyOn(engine, "createHash").mockImplementation((...args) => {
      const hash = nativeCreateHash(...args), nativeDigest = hash.digest.bind(hash);
      vi.spyOn(hash, "digest").mockImplementation((...digestArgs: any[]) => {
        const bytes = (nativeDigest as (...args: any[]) => any)(...digestArgs);
        // Delegate the actual hash unchanged. Model elapsed wall time only at
        // completion of the public caller's synchronous key-validation work.
        if (validatingCallerKey && expireAtProofCompletion) {
          expireAtProofCompletion = false;
          vi.setSystemTime(expiresAt);
        }
        return bytes;
      });
      return hash;
    });
    const stillCurrent = () => {
      // A direct caller can combine a deadline with its actual owner/key proof.
      // Time is tested first so an already expired caller avoids proof work.
      if (Date.now() >= expiresAt || !vault.isUnlocked() || vault.ownerUserId() !== USER || localWriteScopeEpoch() !== epoch) return false;
      validatingCallerKey = true;
      try { return engine.createHash("sha256").update(vault.get().dataKey).digest("hex") === fingerprint; }
      finally { validatingCallerKey = false; }
    };
    clear = feedback.clearFeedback(USER, permit, undefined, stillCurrent);
    // clearFeedback's initial admission has completed; its serialized Promise
    // continuation has not run yet. The deadline is still live at this point.
    expect(Date.now()).toBe(startedAt);
    expireAtProofCompletion = true;
    const result = await clear.then(
      () => ({ status: "fulfilled" as const }),
      error => ({ status: "rejected" as const, message: error instanceof Error ? error.message : String(error) }),
    );
    expect(Date.now(), "the delegated caller-owned key proof completed at the deadline").toBe(expiresAt);
    expect(result, "an expired direct caller must not erase its encrypted feedback queue")
      .toEqual({ status: "rejected", message: "The feedback view has retired" });
    expect(await nativeRead(slot), "the previously persisted authenticated feedback is unchanged").toBe(beforeWire);
  } finally {
    expireAtProofCompletion = false;
    if (clear) await Promise.allSettled([clear]);
    vi.restoreAllMocks(); vi.useRealTimers();
  }
  // The rejection leaves the ordinary public serialization lane usable.
  await feedback.clearFeedback(USER, captureLocalWritePermit(USER, KEY), undefined, () => vault.isUnlocked() && vault.ownerUserId() === USER);
  expect(await nativeRead(slot)).toBeNull();
}, 8000);
