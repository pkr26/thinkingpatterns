/** Password changes preserve every registered local record. v1 prepares
 * a durable device-sealed journal, atomically commits server corpus,
 * sharing wraps and credentials, then applies idempotent local replacements.
 * Lost responses retry the exact UUID request without reopening expired
 * processing sessions. v2 rewraps the unchanged random data key in one
 * credential/envelope transaction. */
import { prepareLocalRekey, resumeLocalRekey, markLocalRekeyPhase, localRekeyRequest, storeLocalRekeyTokens, storeLocalRekeyRequest, pendingLocalRekey, pendingLocalRekeyOldSalt } from "./localRekey";
import { api, ApiError } from "./api/client";
import { deriveKeysAsync } from "./crypto/journalCrypto";
import { engine } from "./crypto/engine";
import { envelopeKek, TamperError, unwrapDataKey, validateKdfParams, wrapDataKey } from "./crypto/keyEnvelope";
import { deriveMasterKeyAsync, zeroize } from "./crypto/kdf";
import { cacheEnvelope, fetchEnvelope, type EnvelopeInfo } from "./keyScheme";
import { drainPendingQueueForRotation } from "./offlineQueue";
import { wrapDataKeyForTherapist } from "./crypto/sharing";
import { clearUnlockProof } from "./unlockProof";
import { verifyPasswordForVault } from "./reauth";
import { vault } from "./vault";
import { disableBiometricUnlock } from "./biometricUnlock";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { accountStorageKey } from "./accountStorage";
import { localWriteScopeEpoch, assertLocalTransitionScope, commitLocalTransitionWrite } from "./localWriteGuard";

/** An attempt owns the original vault and scope. Its own setSession is the
 * only allowed scope advance; external replacement retires all continuations,
 * including cache writes, key adoption, and failure cleanup. */
class RotationScope {
  private epoch = localWriteScopeEpoch();
  private original = vault.canReauthenticate() ? vault.get() : null;
  private checkVault = true;
  constructor(readonly userId: string) { this.assert(); }
  assert(): void {
    try {
      assertLocalTransitionScope(this.userId, this.epoch);
      if (this.checkVault) {
        if (!this.original || vault.ownerUserId() !== this.userId || !vault.canReauthenticate()) throw new Error();
        const now = vault.get();
        if (now.dataKey !== this.original.dataKey || now.authKey !== this.original.authKey) throw new Error();
      } else if (vault.canReauthenticate()) throw new Error();
    } catch { throw new ApiError(0, "The account or server changed; the previous password-change attempt was retired. Confirm any dispatched change before retrying.", "stale_operation"); }
  }
  completionScope(): number { this.assert(); return this.epoch; }
  current(): boolean { try { this.assert(); return true; } catch { return false; } }
  async run<T>(operation: () => Promise<T>): Promise<T> {
    this.assert(); const result = await operation(); this.assert(); return result;
  }
  async proof(operation: () => ReturnType<typeof verifyPasswordForVault>): ReturnType<typeof verifyPasswordForVault> {
    this.assert(); const result = await operation();
    // A verified biometric proof may intentionally replace this vault's
    // placeholder auth key. The data key, owner and scope must stay exact.
    if (result.ok && this.original?.authKeyKnown === false && this.epoch === localWriteScopeEpoch() && vault.ownerUserId() === this.userId && vault.canReauthenticate()) {
      const now = vault.get(); if (now.dataKey === this.original.dataKey) this.original = now;
    }
    this.assert(); return result;
  }
  async bestEffort(operation: () => Promise<unknown>): Promise<void> {
    this.assert(); try { await operation(); } catch { /* Public cache/native availability is best effort. */ } this.assert();
  }
  async localCommit<T>(operation: () => Promise<T>): Promise<T> {
    return this.run(() => commitLocalTransitionWrite(this.userId, this.epoch, operation));
  }
  lock(): void { this.assert(); vault.lock(); this.checkVault = false; }
  async adoptSession(session: { token: unknown; user_id: unknown }, username: string): Promise<void> {
    this.assert();
    if (session.user_id !== this.userId) throw new ApiError(0, "The password-change login returned a different account", "stale_operation");
    const pending = api.setSession(String(session.token), this.userId, username);
    // setSession retires prior work synchronously at admission.
    this.epoch = localWriteScopeEpoch();
    await pending; this.assert();
  }
  adoptAuthKey(key: Buffer): void {
    this.assert(); vault.adoptAuthKey(Buffer.from(key)); this.original = vault.get();
  }
}

/** 16 random bytes — the KDF salt size shared with registration.
 *  2026-09-26 audit H-2: the entropy now comes from the app's CSPRNG seam
 *  (engine.randomBytes — quick-crypto's native JSI RNG on device,
 *  node:crypto in tests; the same seam entryId.ts already uses). The old
 *  implementation called globalThis.crypto.getRandomValues, which React
 *  Native does not provide (RN 0.87 ships no Web Crypto global and
 *  react-native-get-random-values is not a dependency) — the call sat
 *  outside the typed-outcome try block, so password rotation crashed on
 *  device with a raw TypeError instead of returning a typed failure. */
function freshSalt(): Buffer {
  return Buffer.from(engine.randomBytes(16));
}

export type RotationStage = "verify" | "rekey" | "rewrap" | "credential" | "relogin";

export type RotationOutcome =
  | {
      ok: true;
      /** Which server flow ran (2026-09-26): "v2" = the O(1) envelope
       *  re-wrap — the data key (and therefore the corpus, the grants and
       *  the biometric wrap) is UNCHANGED; "v1" = the resumable rekey
       *  ladder re-encrypted everything under a new data key. */
      scheme: "v1" | "v2";
      /** Exact scope owned at completion; callbacks must reject later replacement. */
      sessionScope?: number;
      counts: { entries: number; insights: number; measures: number };
      recoveryInvalidated?: boolean;
      rewrapped: number;
      rewrapFailures: string[];
    }
  | {
      ok: false;
      stage: RotationStage;
      reason: "wrong-password" | "offline" | "server" | "already-rotated-unverifiable" | "queue-blocked";
      /** Client-authored local detail only; server detail is never rendered. */
      detail?: string;
    };

function localErrorDetail(error: unknown): string | undefined {
  return error instanceof ApiError ? undefined : error instanceof Error ? error.message : undefined;
}

/** B-1 (2026-09-26 audit follow-up): the pending rotation salt, persisted
 * locally BEFORE the rekey attempt and cleared only on full completion.
 * The ladder above can only verify when the retry derives the SAME keys
 * as the attempt that rekeyed the corpus — a fresh random salt per
 * attempt (the previous behavior) made the rekey_key_mismatch resume
 * path unreachable in production. The salt is public material (the
 * server stores it in the clear after rotation); it is inert without
 * the password. Keyed by user so a shared device never crosses accounts. */
const pendingSaltKey = accountStorageKey.pendingRotationSalt;

async function loadPendingSalt(userId: string): Promise<Buffer | null> {
  try {
    const b64 = await AsyncStorage.getItem(pendingSaltKey(userId));
    if (!b64) return null;
    const salt = Buffer.from(b64, "base64");
    return salt.length === 16 ? salt : null;
  } catch {
    return null;
  }
}

async function storePendingSalt(userId: string, salt: Buffer): Promise<void> {
  // The only caller runs this inside RotationScope.localCommit. That
  // explicit transition lane remains valid while normal account writes are
  // frozen, which is essential when a lost-response retry resumes a durable
  // rotation checkpoint.
  await AsyncStorage.setItem(pendingSaltKey(userId), salt.toString("base64"));
}

async function clearPendingSalt(userId: string): Promise<void> {
  try {
    await AsyncStorage.removeItem(pendingSaltKey(userId));
  } catch {
    // Nothing to recover — a stale non-secret salt is inert.
  }
}

/**
 * v2 password change (2026-09-26): unwrap with the OLD password, re-wrap
 * the SAME random data key under a FRESH salt, upload one payload. No
 * rekey, no consent re-wraps, no vault lock — the data key never changes,
 * so every ciphertext, processing session, therapist grant and biometric
 * wrap keeps opening. The server swaps salt + verifier + envelope in ONE
 * transaction and bumps the epoch, so this device re-logs-in immediately
 * and re-adopts the new auth key into the still-valid session.
 */
async function rotatePasswordV2(input: {
  username: string;
  userId: string;
  oldPassword: string;
  newPassword: string;
  oldVerifierB64: string;
  envelope: EnvelopeInfo;
  scope: RotationScope;
}): Promise<RotationOutcome> {
  const { username, userId, oldPassword, newPassword, oldVerifierB64, envelope, scope } = input;
  if (envelope.scheme !== "v2" || envelope.kdfParams === null || envelope.wrappedB64 === null) {
    return {
      ok: false,
      stage: "verify",
      reason: "server",
      detail: "the stored key envelope is malformed",
    };
  }
  const params = validateKdfParams(envelope.kdfParams);
  if (params === null) {
    return {
      ok: false,
      stage: "verify",
      reason: "server",
      detail: "this account's key envelope uses parameters this app cannot derive — update the app before changing the password",
    };
  }
  const salt = Buffer.from(envelope.saltB64, "base64");
  let dataKey: Buffer | null = null;
  let oldMaster: Buffer | null = null;
  let newKeys: Awaited<ReturnType<typeof deriveKeysAsync>> | null = null;
  try {
    // --- v2.1. open the envelope with the OLD password ---------------------
    scope.assert(); oldMaster = await deriveMasterKeyAsync(oldPassword, salt, params.iterations); scope.assert();
    const oldKek = envelopeKek(oldMaster, salt);
    try {
      // A wrong old password fails the envelope's GCM authentication — the
      // same wrong-password verdict the reauth oracle would have given.
      dataKey = unwrapDataKey(Buffer.from(envelope.wrappedB64, "base64"), oldKek, username, params);
    } catch (err) {
      scope.assert();
      if (err instanceof TamperError) return { ok: false, stage: "verify", reason: "wrong-password" };
      return { ok: false, stage: "verify", reason: "server", detail: "the stored key envelope is malformed" };
    } finally {
      zeroize(oldKek);
    }
    zeroize(oldMaster);
    oldMaster = null;

    // --- v2.2. re-wrap the SAME key under the NEW salt ---------------------
    // The re-wrap KEEPS the account's current kdf_params (validated above):
    // the server retains the stored params blob when new_kdf_params is
    // absent, so wrapping under anything else would desynchronize the blob
    // from the AAD and brick the next unlock. A params change is a separate
    // future action, deliberately not smuggled into a password change.
    // Re-audit 2026-09-27 (L): the KEK must be derived at the SAME
    // iteration count the AAD declares — the old call used the 600k default
    // unconditionally, so a non-default-params account (e.g. 800k) produced
    // a KEK the next unlock (which derives at the envelope's own count)
    // could never reproduce. The params and the KEK now come from one
    // source: the envelope.
    const newSalt = freshSalt();
    scope.assert(); newKeys = await deriveKeysAsync(newPassword, newSalt, params.iterations); scope.assert();
    const newKek = envelopeKek(newKeys.masterKey, newSalt);
    let wrappedB64: string;
    try {
      wrappedB64 = wrapDataKey(dataKey, newKek, username, params).toString("base64");
    } finally {
      zeroize(newKek);
    }

    // --- v2.3. possession probe + one transaction: credential + envelope ---
    // M-1 client side (2026-09-28 wire change): the PUT now demands POSSESSION
    // of the current data key on EVERY call — the verifier proves the old
    // password, but only a live owner-bound processing session opened with
    // the UNWRAPPED data key proves this device holds the key whose envelope
    // it is about to replace (the same probe the v1→v2 migration path ships;
    // single-use, consumed by the swap). Nothing below ever falls back to a
    // tokenless call: a refusal means the server did not accept the swap,
    // and both sides are still untouched.
    let processingToken: string;
    try {
      processingToken = String(
        (await scope.run(() => api.openProcessingSession(dataKey!.toString("base64")))).session_token,
      );
    } catch (err) {
      scope.assert();
      if (err instanceof ApiError && err.code === "processing_session_invalid") {
        // The unwrapped key did not authenticate stored ciphertext: this
        // device's envelope view is stale relative to the account. Retrying
        // with the same key cannot fix that — same honest-retry copy as the
        // PUT-side refusal below.
        return {
          ok: false,
          stage: "credential",
          reason: "server",
          detail:
            "the server could not verify this device's encryption key session — unlock again and retry the password change",
        };
      }
      return {
        ok: false,
        stage: "credential",
        reason: err instanceof ApiError ? "server" : "offline",
        detail: localErrorDetail(err),
      };
    }
    try {
      await scope.run(() => api.changePassword(
        oldVerifierB64,
        newSalt.toString("base64"),
        newKeys!.authKey.toString("base64"),
        wrappedB64,
        processingToken,
      ));
    } catch (err) {
      scope.assert();
      if (
        err instanceof ApiError &&
        (err.code === "processing_session_required" ||
          (err.status === 403 && err.code === "processing_session_invalid"))
      ) {
        // The possession probe was refused (422 = the token never arrived,
        // 403 = it did not authenticate). The swap is one transaction, so
        // nothing moved server-side; the honest next step is a fresh attempt
        // after an unlock — never a tokenless retry that would smuggle the
        // new envelope past the probe.
        return {
          ok: false,
          stage: "credential",
          reason: "server",
          detail:
            "the server could not verify this device's encryption key session — unlock again and retry the password change",
        };
      }
      if (err instanceof ApiError && err.status === 403) {
        // The typed old-password proof was rejected server-side.
        return { ok: false, stage: "credential", reason: "wrong-password" };
      }
      // 401: the session-death hook has already locked the vault; the
      // server state is UNCHANGED (the swap is one transaction), so an
      // honest typed failure with an intact next-unlock path is correct.
      return {
        ok: false,
        stage: "credential",
        reason: err instanceof ApiError ? "server" : "offline",
        detail: localErrorDetail(err),
      };
    }

    // --- v2.4. re-login (the epoch bump killed every bearer) ----------------
    try {
      const session = await scope.run(() => api.login(username, newKeys!.authKey.toString("base64")));
      await scope.adoptSession(session, username);
    } catch (err) {
      scope.assert();
      // Server-side the password HAS changed: the honest next step is a
      // fresh sign-in with it. Cache what the next unlock needs FIRST so
      // this device is not stranded behind a stale envelope.
      await scope.bestEffort(() => api.cacheSalt(username, newSalt.toString("base64")));
      await scope.bestEffort(() => cacheEnvelope(username, {
        scheme: "v2",
        saltB64: newSalt.toString("base64"),
        kdfParams: params,
        wrappedB64,
      }));
      scope.lock(); // the old auth key is dead; the data key is unchanged but unreachable until re-login
      await scope.bestEffort(() => scope.localCommit(() => disableBiometricUnlock(userId)));
      return { ok: false, stage: "relogin", reason: err instanceof ApiError ? "server" : "offline" };
    }
    await scope.bestEffort(() => api.cacheSalt(username, newSalt.toString("base64")));
    await scope.bestEffort(() => cacheEnvelope(username, {
      scheme: "v2",
      saltB64: newSalt.toString("base64"),
      kdfParams: params,
      wrappedB64,
    }));

    // --- v2.5. keep the session: same data key, new auth key ----------------
    // The vault's data key is STILL CORRECT (that is the point of v2), so
    // unlike the v1 flow there is nothing to lock or re-derive. Only the
    // auth-key slot moves: adopt a COPY so the finally-block's zeroize of
    // the derivation cannot touch the live session key.
    try {
      scope.adoptAuthKey(newKeys.authKey);
    } catch {
      // The vault locked mid-flow (a 401 hook raced us): the rotation
      // itself completed; the next unlock uses the new password via the
      // cached envelope above. Nothing else to clean up.
    }

    return {
      ok: true,
      scheme: "v2",
      sessionScope: scope.completionScope(),
      counts: { entries: 0, insights: 0, measures: 0 },
      rewrapped: 0,
      rewrapFailures: [],
    };
  } catch (err) {
    // H-2 discipline: a LOCAL failure (derivation, the CSPRNG seam, an
    // unexpected internal error) must be a typed outcome, never an
    // escaped throw.
    return {
      ok: false,
      stage: "verify",
      reason: err instanceof ApiError ? "server" : "offline",
      detail: localErrorDetail(err),
    };
  } finally {
    if (dataKey) zeroize(dataKey);
    if (oldMaster) zeroize(oldMaster);
    if (newKeys) {
      // The adopted copy (if any) is independent memory — zeroizing the
      // derivation's own buffers leaves the vault's live key intact.
      zeroize(newKeys.masterKey, newKeys.authKey, newKeys.dataKey);
    }
  }
}

async function rotatePasswordOwned(input: {
  username: string;
  userId: string;
  oldPassword: string;
  newPassword: string;
}): Promise<RotationOutcome> {
  const { username, userId, oldPassword, newPassword } = input;
  const scope = new RotationScope(userId);

  // --- 1. old-password proof (the same reauth discipline as delete/grant) --
  const checkpointOldSalt = await scope.run(() => pendingLocalRekeyOldSalt(userId));
  const reauth = await scope.proof(() => verifyPasswordForVault(oldPassword, checkpointOldSalt ? { saltB64: checkpointOldSalt } : undefined));
  if (!reauth.ok) {
    return {
      ok: false,
      stage: "verify",
      reason: reauth.reason === "wrong-password" ? "wrong-password" : "offline",
    };
  }
  const oldVerifierB64 = reauth.verifierB64;

  // --- 1b. key-scheme routing (2026-09-26) ---------------------------------
  // v2 accounts take the O(1) local re-wrap (rotatePasswordV2); v1 accounts
  // keep the resumable rekey ladder below. A 404 = a pre-envelope server:
  // no v2 account can exist there, so v1 semantics hold. An unreachable
  // server is the flow's established typed offline outcome; a server that
  // ANSWERS with an envelope this app cannot derive (argon2id etc.) is an
  // honest "update the app" — never "check your connection".
  const resumingV1 = await scope.run(() => pendingLocalRekey(userId));
  const envelopeFetch = resumingV1 ? { status: "legacy" as const } : await scope.run(() => fetchEnvelope());
  if (envelopeFetch.status === "unreachable") {
    return { ok: false, stage: "verify", reason: "offline" };
  }
  if (envelopeFetch.status === "invalid") {
    return {
      ok: false,
      stage: "verify",
      reason: "server",
      detail: "this account's key envelope uses parameters this app cannot derive — update the app before changing the password",
    };
  }
  if (envelopeFetch.status === "ok" && envelopeFetch.envelope.scheme === "v2") {
    return rotatePasswordV2({
      username,
      userId,
      oldPassword,
      newPassword,
      oldVerifierB64,
      envelope: envelopeFetch.envelope,
      scope,
    });
  }

  // --- 2. derive the new generation under a fresh random salt ---------------
  let saltB64: string | null = checkpointOldSalt ?? await scope.run(() => api.getCachedSalt(username));
  if (!saltB64) {
    try {
      const { salt } = await scope.run(() => api.saltFor(username));
      saltB64 = salt;
      await scope.run(() => api.cacheSalt(username, salt));
    } catch {
      return { ok: false, stage: "verify", reason: "offline" };
    }
  }
  if (!saltB64) return { ok: false, stage: "verify", reason: "offline" };

  // 2026-09-26 audit H-2: the key derivations (and the fresh-salt draw they
  // bracket) moved INSIDE the try block. freshSalt() used to run before it,
  // so the on-device TypeError from the missing Web Crypto global escaped
  // rotatePassword entirely as an unhandled rejection; now every derivation
  // failure becomes a typed outcome (the "offline" bucket is the flow's
  // established local-failure reason — see the stage-3 classifier below).
  let oldKeys: Awaited<ReturnType<typeof deriveKeysAsync>> | null = null;
  let newKeys: Awaited<ReturnType<typeof deriveKeysAsync>> | null = null;
  let newSaltB64 = "";
  let newVerifierB64 = "";

  try {
    scope.assert(); oldKeys = await deriveKeysAsync(oldPassword, Buffer.from(saltB64!, "base64")); scope.assert();
    // B-1: reuse the PENDING salt from an attempt that died at/after its
    // rekey, so this retry derives the same keys that already encrypted
    // the corpus — that is what makes the mismatch ladder above
    // reachable. Only a first attempt (or one that died before its rekey
    // could move anything) draws fresh entropy.
    const newSalt = (await scope.run(() => loadPendingSalt(userId))) ?? freshSalt();
    await scope.localCommit(() => storePendingSalt(userId, newSalt));
    scope.assert(); newKeys = await deriveKeysAsync(newPassword, newSalt); scope.assert();
    newSaltB64 = newSalt.toString("base64");
    newVerifierB64 = newKeys.authKey.toString("base64");
    // --- 2b. drain the offline queue BEFORE any server-side step ----------
    // independent audit 2026-09-27 (P2, parity with the web fix): the queue's
    // blobs are sealed under the OLD data key and were never part of the
    // rekey ladder's server-side rewrap family — after the rekey they would
    // upload and become permanently undecryptable. Best-effort drain FIRST
    // (the user is necessarily online to rotate); anything that cannot leave
    // right now ABORTS before any server-side step, honestly — a rotation
    // that orphaned queued entries is the worse outcome by far.
    const remainingQueued = await scope.run(() => drainPendingQueueForRotation(userId).catch(() => -1));
    if (remainingQueued !== 0) {
      return { ok: false, stage: "verify", reason: "queue-blocked" };
    }
    // Freeze writing before preparing every key-bound local store. The
    // derived keys are independent of the vault, so lock/unmount is safe.
    scope.lock();
    try { await scope.run(() => prepareLocalRekey(userId, oldKeys!.dataKey, newKeys!.dataKey, { oldSaltB64: saltB64! })); }
    catch { scope.assert(); return { ok: false, stage: "verify", reason: "queue-blocked" }; }
    await scope.run(() => markLocalRekeyPhase(userId, "server"));
    // Rekey and retire the old credential in one server transaction.
    // Reuse the exact operation and original token headers after a lost
    // response; a committed retry must precede current-epoch endpoints.
    const checkpoint = await scope.run(() => localRekeyRequest(userId, newKeys!.dataKey));
    let body = checkpoint.body;
    if (!body) {
      try {
        const consent_wraps = [];
        for (const consent of await scope.run(() => api.listConsents())) {
          if (consent.status !== "active") continue;
          if (!consent.therapist_wrap_pub_key) throw new Error("An active sharing grant has no current public key");
          const wrap = wrapDataKeyForTherapist(newKeys.dataKey, consent.therapist_wrap_pub_key, userId, consent.therapist_id);
          consent_wraps.push({ consent_id: consent.id, therapist_wrap_pub_key: consent.therapist_wrap_pub_key, ephemeral_pub: wrap.ephemeralPubB64, wrapped_key: wrap.wrappedKeyB64 });
        }
        body = { operation_id: checkpoint.operationId, new_salt: newSaltB64, new_verifier: newVerifierB64, consent_wraps };
        await scope.run(() => storeLocalRekeyRequest(userId, newKeys!.dataKey, body!));
      } catch (err) {
        scope.assert();
        return { ok: false, stage: "rewrap", reason: err instanceof ApiError ? "server" : "offline", detail: localErrorDetail(err) };
      }
    }
    if (body.new_salt !== newSaltB64 || body.new_verifier !== newVerifierB64) return { ok: false, stage: "verify", reason: "queue-blocked" };
    let tokens = checkpoint.tokens;
    let result: any;
    try {
      if (tokens) {
        try { result = await scope.run(() => api.rekeyStoredData(tokens!.old, tokens!.next, oldVerifierB64, body!)); }
        catch (err) {
          if (!(err instanceof ApiError) || err.code !== "processing_session_invalid") throw err;
          // No commit exists and the old epoch is still valid. Refresh
          // expired, single-use headers while retaining the same body.
          tokens = undefined;
        }
      }
      if (!tokens) {
        const old = (await scope.run(() => api.openProcessingSession(oldKeys!.dataKey.toString("base64")))).session_token;
        const next = (await scope.run(() => api.openProcessingSession(newKeys!.dataKey.toString("base64")))).session_token;
        tokens = { old, next };
        await scope.run(() => storeLocalRekeyTokens(userId, newKeys!.dataKey, tokens!));
        result = await scope.run(() => api.rekeyStoredData(old, next, oldVerifierB64, body!));
      }
      if (result?.credential_rotated !== true || result?.operation_id !== checkpoint.operationId) {
        throw new Error("The server does not support atomic password rotation; update the server before retrying");
      }
    } catch (err) {
      scope.assert();
      return { ok: false, stage: "rekey", reason: err instanceof ApiError && err.status === 403 ? "wrong-password" : err instanceof ApiError ? "server" : "offline", detail: localErrorDetail(err) };
    }
    const counts = { entries: Number(result.entries), insights: Number(result.insights), measures: Number(result.measures) };
    const recoveryInvalidated = result.recovery_invalidated === true;
    try {
      await scope.run(() => markLocalRekeyPhase(userId, "credential"));
      await scope.run(() => resumeLocalRekey(userId, newKeys!.dataKey));
      await scope.localCommit(() => clearUnlockProof(userId));
    } catch (err) {
      scope.assert();
      return { ok: false, stage: "credential", reason: "offline", detail: localErrorDetail(err) };
    }
    // The atomic epoch bump retired every old bearer. Obtain the new
    // bearer before allowing account requests again.
    try {
      const session = await scope.run(() => api.login(username, newVerifierB64));
      await scope.adoptSession(session, username);
    } catch (err) {
      scope.assert();
      await scope.bestEffort(() => api.cacheSalt(username, newSaltB64));
      return { ok: false, stage: "relogin", reason: err instanceof ApiError ? "server" : "offline" };
    }
    // Sharing wraps were committed in the same transaction and guarded
    // against concurrent grant/public-key changes by the server.
    const rewrapFailures: string[] = [];
    const rewrapped = Number.isSafeInteger(result.consents_rewrapped) && result.consents_rewrapped >= 0 && result.consents_rewrapped <= body.consent_wraps.length
      ? result.consents_rewrapped : body.consent_wraps.length;

    // B-2(audit follow-up, post-relogin hole): cacheSalt is a local CACHE
    // of public material — best-effort only. It used to sit un-caught
    // between the successful re-login and the vault lock: a throw there
    // returned a typed "verify/offline" failure while the server had
    // ALREADY rekeyed the blobs and retired the old credential, leaving
    // the vault unlocked on the dead OLD data key — the exact F-4
    // data-loss shape this flow's later stages each guard against.
    await scope.bestEffort(() => api.cacheSalt(username, newSaltB64));
    // Full completion: the pending rotation salt has done its job.
    await scope.localCommit(() => clearPendingSalt(userId));

    // The registered journal has already rekeyed authored data and guards.
    // Drop stale in-memory mirrors; ciphertext high-water marks remain.
    const { resetEntryVersionMirrors } = await scope.run(() => import("./entryVersions"));
    resetEntryVersionMirrors();
    // Audit fix 7 (2026-09-21): the rotation must SELF-COMPLETE. Locking the
    // vault and dropping the biometric wrap happen HERE, inside the flow —
    // they used to hang off the success alert's OK button, which Android
    // can dismiss without firing; in that window the vault kept the OLD
    // data key and new entries were encrypted under it, permanently
    // undecryptable. Best-effort wrap removal: the rotation itself already
    // succeeded server-side.
    scope.lock();
    await scope.bestEffort(() => scope.localCommit(() => disableBiometricUnlock(userId)));

    return { ok: true, scheme: "v1", sessionScope: scope.completionScope(), counts, rewrapped, rewrapFailures, recoveryInvalidated };
  } catch (err) {
    // H-2: a LOCAL failure before/outside the staged server flow (key
    // derivation, the CSPRNG seam, unexpected internal errors) must be a
    // typed outcome like every other failure — never an escaped throw.
    return {
      ok: false,
      stage: "verify",
      reason: err instanceof ApiError ? "server" : "offline",
      detail: localErrorDetail(err),
    };
  } finally {
    // Nothing is derived yet → nothing to wipe (the H-2 restructure moved
    // derivation inside the try, so a mid-derivation failure reaches here
    // with one or both sets still null).
    if (oldKeys) {
      if (scope.current()) {
        scope.lock();
        await scope.bestEffort(() => scope.localCommit(() => disableBiometricUnlock(userId))).catch(() => {});
      }
      zeroize(oldKeys.masterKey, oldKeys.authKey, oldKeys.dataKey);
    }
    if (newKeys) zeroize(newKeys.masterKey, newKeys.authKey, newKeys.dataKey);
  }
}

/** All entry/retirement errors are typed; a retired attempt never cleans up
 * a replacement vault. Its durable checkpoint remains available for recovery. */
export async function rotatePassword(input: {
  username: string; userId: string; oldPassword: string; newPassword: string;
}): Promise<RotationOutcome> {
  try { return await rotatePasswordOwned(input); }
  catch (err) {
    return { ok: false, stage: "verify", reason: err instanceof ApiError ? "server" : "offline", detail: localErrorDetail(err) };
  }
}
