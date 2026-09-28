/**
 * Password rotation: the recovery path for captured credentials and keys
 * (audit fix H-1/M-3, 2026-09-20).
 *
 * Until now NOTHING in the system could retire a login credential: the
 * derived auth key was the standing password-equivalent forever, so a
 * phished verifier (or one request-body capture of the data key) meant a
 * permanent compromise. The account's KEY SCHEME decides the route:
 *
 * v1 (password-derived data key) — the resumable rekey ladder:
 *   1. verify the OLD password locally (reauth semantics),
 *   2. derive the NEW key generation (fresh random salt, new password),
 *   3. POST /processing/rekey       — server re-encrypts every stored blob
 *                                     old data key -> new data key,
 *   4. PUT /consents/{id}/rewrap    — every ACTIVE therapist grant gets the
 *                                     new data key wrapped to the same
 *                                     therapist,
 *   5. PUT /account/credential      — retire the old login credential; the
 *                                     epoch bump kills every bearer,
 *   6. re-login under the new credential and rebind device-local state.
 *
 * v2 (random data key behind a password-wrapped envelope, 2026-09-26) —
 * O(1), no rekey at all: unwrap the envelope locally with the old
 * password, re-wrap the SAME random data key under the new salt, and PUT
 * /account/password, which swaps the credential and the envelope in ONE
 * server transaction. The corpus, the processing-session key, every
 * therapist grant and the biometric wrap keep working under the unchanged
 * data key; only the password-locker rotates. The vault therefore STAYS
 * unlocked (its data key is still correct); only the auth key slot is
 * re-adopted after the post-rotation re-login.
 *
 * Idempotent retry (v1): if a previous attempt died between (3) and (5),
 * the rekey step answers rekey_key_mismatch (the blobs are already under
 * the new key). The flow then verifies the NEW key really decrypts a live
 * entry and continues from (4) instead of failing — a half-finished
 * rotation must always be finishable.
 */
import { api, ApiError } from "./api/client";
import { decryptEntry, deriveKeysAsync } from "./crypto/MindPatternCrypto";
import { buildAad, decrypt } from "./crypto/envelope";
import { engine } from "./crypto/engine";
import { envelopeKek, TamperError, unwrapDataKey, validateKdfParams, wrapDataKey } from "./crypto/keyEnvelope";
import { deriveMasterKeyAsync, zeroize } from "./crypto/kdf";
import { cacheEnvelope, fetchEnvelope, type EnvelopeInfo } from "./keyScheme";
import { drainPendingQueueForRotation, rewrapQueue } from "./offlineQueue";
import { wrapDataKeyForTherapist } from "./crypto/sharing";
import { rebindEntryVersions, forgetAllEntryVersions } from "./entryVersions";
import { clearMoodLog } from "./moodLog";
import { clearFeedback } from "./questionFeedback";
import { clearUnlockProof } from "./unlockProof";
import { verifyPasswordForVault } from "./reauth";
import { vault } from "./vault";
import { disableBiometricUnlock } from "./biometricUnlock";
import AsyncStorage from "@react-native-async-storage/async-storage";

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
      counts: { entries: number; insights: number; measures: number };
      rewrapped: number;
      rewrapFailures: string[];
    }
  | {
      ok: false;
      stage: RotationStage;
      reason: "wrong-password" | "offline" | "server" | "already-rotated-unverifiable" | "queue-blocked";
      /** Human-oriented detail (already sanitized server text or a local
       * constant) — the UI may render it after errors.ts treatment. */
      detail?: string;
    };

/** Can the NEW key decrypt at least one live blob? (Retry ladder step:
 * proves a rekey_key_mismatch means "already rekeyed", not "wrong key".)
 *
 * 2026-09-26 audit follow-ups:
 *  - B-1(mobile): the entry probe now passes the row's content_version —
 *    every entry saved since M-2 (2026-09-20) is v2-AAD-bound, so the
 *    legacy three-part-AAD-only retry read FALSE for any real journal and
 *    the ladder dead-ended "already-rotated-unverifiable" even with the
 *    correct key. (The web port written the same day got this right.)
 *  - B-2: an EMPTY journal no longer trivially verifies — the rekey also
 *    moved MEASURES, so the probe falls through to one measure row; both
 *    empty trivially verifies (nothing to mismatch). Without this, a user
 *    with a PHQ-9 history but zero entries would "verify", complete the
 *    credential rotation, and silently orphan every stored measure. */
async function newKeyReadsJournal(userId: string, newDataKey: Buffer): Promise<boolean> {
  try {
    const page = await api.listEntriesPage({ limit: 1, offset: 0 });
    if (page.entries.length > 0) {
      const entry = page.entries[0]!;
      if (typeof entry.blob !== "string") return false;
      try {
        decryptEntry(
          { dataKey: newDataKey },
          userId,
          entry.client_entry_id,
          entry.blob,
          entry.content_version ?? undefined,
        );
        return true;
      } catch {
        return false;
      }
    }
    const measuresPage = await api.listMeasuresPage({ limit: 1, offset: 0 });
    const measures = measuresPage.measures as Array<{
      blob?: unknown;
      client_measure_id?: unknown;
    }>;
    if (!Array.isArray(measures) || measures.length === 0) return true;
    const row = measures[0]!;
    if (typeof row.blob !== "string" || typeof row.client_measure_id !== "string") return false;
    try {
      decrypt(newDataKey, Buffer.from(row.blob, "base64"), buildAad("measure", userId, row.client_measure_id));
      return true;
    } catch {
      return false;
    }
  } catch {
    return false;
  }
}

/** B-1 (2026-09-26 audit follow-up): the pending rotation salt, persisted
 * locally BEFORE the rekey attempt and cleared only on full completion.
 * The ladder above can only verify when the retry derives the SAME keys
 * as the attempt that rekeyed the corpus — a fresh random salt per
 * attempt (the previous behavior) made the rekey_key_mismatch resume
 * path unreachable in production. The salt is public material (the
 * server stores it in the clear after rotation); it is inert without
 * the password. Keyed by user so a shared device never crosses accounts. */
const pendingSaltKey = (userId: string) => `mindpattern.rotatePendingSalt.${userId}`;

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
  try {
    await AsyncStorage.setItem(pendingSaltKey(userId), salt.toString("base64"));
  } catch {
    // Best-effort: without persistence the retry draws a fresh salt and
    // the ladder honestly refuses — degraded, never wrong.
  }
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
}): Promise<RotationOutcome> {
  const { username, userId, oldPassword, newPassword, oldVerifierB64, envelope } = input;
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
  let adoptedAuthKey = false;
  try {
    // --- v2.1. open the envelope with the OLD password ---------------------
    oldMaster = await deriveMasterKeyAsync(oldPassword, salt, params.iterations);
    const oldKek = envelopeKek(oldMaster, salt);
    try {
      // A wrong old password fails the envelope's GCM authentication — the
      // same wrong-password verdict the reauth oracle would have given.
      dataKey = unwrapDataKey(Buffer.from(envelope.wrappedB64, "base64"), oldKek, username, params);
    } catch (err) {
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
    newKeys = await deriveKeysAsync(newPassword, newSalt, params.iterations);
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
        (await api.openProcessingSession(dataKey.toString("base64"))).session_token,
      );
    } catch (err) {
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
        detail: err instanceof ApiError ? err.message : undefined,
      };
    }
    try {
      await api.changePassword(
        oldVerifierB64,
        newSalt.toString("base64"),
        newKeys.authKey.toString("base64"),
        wrappedB64,
        processingToken,
      );
    } catch (err) {
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
        return { ok: false, stage: "credential", reason: "wrong-password", detail: err.message };
      }
      // 401: the session-death hook has already locked the vault; the
      // server state is UNCHANGED (the swap is one transaction), so an
      // honest typed failure with an intact next-unlock path is correct.
      return {
        ok: false,
        stage: "credential",
        reason: err instanceof ApiError ? "server" : "offline",
        detail: err instanceof ApiError ? err.message : undefined,
      };
    }

    // --- v2.4. re-login (the epoch bump killed every bearer) ----------------
    try {
      const session = await api.login(username, newKeys.authKey.toString("base64"));
      await api.setSession(String(session.token), String(session.user_id), username);
    } catch (err) {
      // Server-side the password HAS changed: the honest next step is a
      // fresh sign-in with it. Cache what the next unlock needs FIRST so
      // this device is not stranded behind a stale envelope.
      await api.cacheSalt(username, newSalt.toString("base64")).catch(() => {});
      await cacheEnvelope(username, {
        scheme: "v2",
        saltB64: newSalt.toString("base64"),
        kdfParams: params,
        wrappedB64,
      }).catch(() => {});
      vault.lock(); // the old auth key is dead; the data key is unchanged but unreachable until re-login
      await disableBiometricUnlock(userId).catch(() => {});
      return { ok: false, stage: "relogin", reason: err instanceof ApiError ? "server" : "offline" };
    }
    await api.cacheSalt(username, newSalt.toString("base64")).catch(() => {});
    await cacheEnvelope(username, {
      scheme: "v2",
      saltB64: newSalt.toString("base64"),
      kdfParams: params,
      wrappedB64,
    }).catch(() => {});

    // --- v2.5. keep the session: same data key, new auth key ----------------
    // The vault's data key is STILL CORRECT (that is the point of v2), so
    // unlike the v1 flow there is nothing to lock or re-derive. Only the
    // auth-key slot moves: adopt a COPY so the finally-block's zeroize of
    // the derivation cannot touch the live session key.
    try {
      vault.adoptAuthKey(Buffer.from(newKeys.authKey));
      adoptedAuthKey = true;
    } catch {
      // The vault locked mid-flow (a 401 hook raced us): the rotation
      // itself completed; the next unlock uses the new password via the
      // cached envelope above. Nothing else to clean up.
    }

    return {
      ok: true,
      scheme: "v2",
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
      detail: err instanceof ApiError ? err.message : undefined,
    };
  } finally {
    if (dataKey) zeroize(dataKey);
    if (oldMaster) zeroize(oldMaster);
    if (newKeys) {
      // The adopted copy (if any) is independent memory — zeroizing the
      // derivation's own buffers leaves the vault's live key intact.
      if (!adoptedAuthKey) zeroize(newKeys.authKey);
      zeroize(newKeys.masterKey, newKeys.dataKey);
    }
  }
}

export async function rotatePassword(input: {
  username: string;
  userId: string;
  oldPassword: string;
  newPassword: string;
}): Promise<RotationOutcome> {
  const { username, userId, oldPassword, newPassword } = input;

  // --- 1. old-password proof (the same reauth discipline as delete/grant) --
  const reauth = await verifyPasswordForVault(oldPassword);
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
  const envelopeFetch = await fetchEnvelope();
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
    });
  }

  // --- 2. derive the new generation under a fresh random salt ---------------
  let saltB64: string | null = await api.getCachedSalt(username);
  if (!saltB64) {
    try {
      const { salt } = await api.saltFor(username);
      saltB64 = salt;
      await api.cacheSalt(username, salt);
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
    oldKeys = await deriveKeysAsync(oldPassword, Buffer.from(saltB64, "base64"));
    // B-1: reuse the PENDING salt from an attempt that died at/after its
    // rekey, so this retry derives the same keys that already encrypted
    // the corpus — that is what makes the mismatch ladder above
    // reachable. Only a first attempt (or one that died before its rekey
    // could move anything) draws fresh entropy.
    const newSalt = (await loadPendingSalt(userId)) ?? freshSalt();
    await storePendingSalt(userId, newSalt);
    newKeys = await deriveKeysAsync(newPassword, newSalt);
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
    const remainingQueued = await drainPendingQueueForRotation(userId).catch(() => -1);
    if (remainingQueued !== 0) {
      return { ok: false, stage: "verify", reason: "queue-blocked" };
    }
    // --- 3. rekey every stored blob old -> new -----------------------------
    let counts = { entries: 0, insights: 0, measures: 0 };
    try {
      const oldToken = (await api.openProcessingSession(oldKeys!.dataKey.toString("base64"))).session_token;
      const newToken = (await api.openProcessingSession(newKeys!.dataKey.toString("base64"))).session_token;
      counts = await api.rekeyStoredData(oldToken, newToken, oldVerifierB64);
    } catch (err) {
      if (err instanceof ApiError && err.code === "rekey_key_mismatch") {
        // A previous attempt already moved the blobs to (this or another)
        // new key. Continue ONLY if the key we are about to make current
        // can actually read the journal.
        if (!(await newKeyReadsJournal(userId, newKeys!.dataKey))) {
          // B-3 (web twin, 2026-09-26 follow-up): the corpus is provably
          // under a key this vault cannot read. The OLD data key still in
          // the vault is dead for every stored blob — a new entry sealed
          // under it now would be permanently undecryptable, and the
          // biometric wrap would keep restoring the dead key. Same F-4
          // self-clean as the later stages: lock, best-effort wrap drop.
          vault.lock();
          await disableBiometricUnlock(userId).catch(() => {});
          return {
            ok: false,
            stage: "rekey",
            reason: "already-rotated-unverifiable",
            detail:
              "the stored data was already re-keyed by an earlier attempt, but the new password cannot read it — it was rotated to a different new password",
          };
        }
        // Audit 2026-09-28: the local flag that used to live here was dead —
        // the newKeyReadsJournal verification above is the gate; nothing
        // downstream needed to know which branch rekeyed.
      } else if (err instanceof ApiError && err.status === 403) {
        return { ok: false, stage: "rekey", reason: "wrong-password", detail: err.message };
      } else {
        return { ok: false, stage: "rekey", reason: err instanceof ApiError ? "server" : "offline", detail: err instanceof ApiError ? err.message : undefined };
      }
    }

    // --- 4. re-wrap every ACTIVE therapist grant to the new key ------------
    const rewrapFailures: string[] = [];
    let rewrapped = 0;
    try {
      const consents = await api.listConsents();
      for (const consent of consents) {
        if (consent.status !== "active") continue;
        if (!consent.therapist_wrap_pub_key) continue;
        try {
          const wrap = wrapDataKeyForTherapist(
            newKeys!.dataKey,
            consent.therapist_wrap_pub_key,
            userId,
            consent.therapist_id,
          );
          await api.rewrapConsent(consent.id, wrap.ephemeralPubB64, wrap.wrappedKeyB64, oldVerifierB64);
          rewrapped += 1;
        } catch {
          // One therapist's rewrap failing must not abort the rotation;
          // the patient can re-grant from the pairing flow afterwards.
          rewrapFailures.push(consent.display_name || consent.username);
        }
      }
    } catch {
      // Listing consents failed: the rotation itself is still valid; the
      // grants keep their OLD wrapped keys and stop working — surfaced as
      // failures rather than silently dropped.
      rewrapFailures.push("(could not list sharing grants)");
    }

    // --- 5. retire the old login credential ---------------------------------
    try {
      await api.rotateCredential(oldVerifierB64, newSaltB64, newVerifierB64);
    } catch (err) {
      // 2026-09-26 v2 key scheme: the OLD endpoint refuses v2 accounts with
      // 409 key_scheme_conflict — the account was upgraded (this device's
      // scheme fetch said v1, another device said otherwise mid-flow).
      // Audit 2026-09-28: stage 3 (api.rekeyStoredData) ALREADY committed the
      // rekey before this stage runs, so the OLD data key this vault holds is
      // dead for every stored blob — the same F-4 self-clean the generic
      // branch below applies (lock first, then best-effort wrap removal).
      if (err instanceof ApiError && err.code === "key_scheme_conflict") {
        vault.lock();
        await disableBiometricUnlock(userId).catch(() => {});
        return {
          ok: false,
          stage: "credential",
          reason: "server",
          detail:
            "this account now uses the newer key protection (it may have been upgraded from another device) — unlock again and retry the password change",
        };
      }
      // Audit round 2 (2026-09-21) F-4: the failure path must self-clean for
      // the same reason the success path below does — the SERVER-side state
      // has already moved (stage 3 rekeyed every blob to the new key), so the
      // OLD data key this vault still holds is dead. An entry written in the
      // window before the user retries would be sealed under a key nothing
      // can decrypt with, and the biometric wrap would keep RESTORING that
      // dead key after every unlock. Constraint: mirror the success-path
      // idiom exactly (lock first, then best-effort wrap removal).
      vault.lock();
      await disableBiometricUnlock(userId).catch(() => {});
      return {
        ok: false,
        stage: "credential",
        reason: err instanceof ApiError ? "server" : "offline",
        detail:
          err instanceof ApiError
            ? err.message
            : undefined,
      };
    }

    // --- 6. re-login under the new credential and rebind device state -------
    try {
      const session = await api.login(username, newVerifierB64);
      await api.setSession(String(session.token), String(session.user_id), username);
    } catch (err) {
      // Audit round 2 (2026-09-21) F-4: same constraint as the credential
      // stage above — the server has rekeyed the blobs AND retired the old
      // login credential, so the vault's OLD data key must not survive a
      // failed re-login (local writes would seal under a dead key; the wrap
      // would keep restoring it). Lock + best-effort wrap drop, then report.
      vault.lock();
      await disableBiometricUnlock(userId).catch(() => {});
      return {
        ok: false,
        stage: "relogin",
        reason: err instanceof ApiError ? "server" : "offline",
      };
    }
    // B-2(audit follow-up, post-relogin hole): cacheSalt is a local CACHE
    // of public material — best-effort only. It used to sit un-caught
    // between the successful re-login and the vault lock: a throw there
    // returned a typed "verify/offline" failure while the server had
    // ALREADY rekeyed the blobs and retired the old credential, leaving
    // the vault unlocked on the dead OLD data key — the exact F-4
    // data-loss shape this flow's later stages each guard against.
    await api.cacheSalt(username, newSaltB64).catch(() => {});
    // Full completion: the pending rotation salt has done its job.
    await clearPendingSalt(userId);

    // Data-key-bound local caches: rebind what survives a key change
    // (entry-version marks), clear what must be re-created on next use
    // (mood log, question feedback, unlock proof — all sealed under the
    // OLD data key).
    await rebindEntryVersions(userId, oldKeys!.dataKey, newKeys!.dataKey).catch(() =>
      forgetAllEntryVersions(userId),
    );
    // The offline queue rides the same rewrap family (independent audit
    // 2026-09-27, P2): anything still held locally — a REJECTED entry, or an
    // item queued after the drain by another write mid-rotation — is
    // rewrapped old→new under the SAME AAD, under the queue's storage mutex.
    // A blob that cannot be rewrapped stays as-is (it fails visibly on
    // requeue); the completed rotation is never blocked or unwound by it.
    await rewrapQueue(userId, oldKeys!.dataKey, newKeys!.dataKey).catch(() => {});
    await clearMoodLog(userId).catch(() => {});
    await clearFeedback(userId).catch(() => {});
    await clearUnlockProof(userId).catch(() => {});

    // Audit fix 7 (2026-09-21): the rotation must SELF-COMPLETE. Locking the
    // vault and dropping the biometric wrap happen HERE, inside the flow —
    // they used to hang off the success alert's OK button, which Android
    // can dismiss without firing; in that window the vault kept the OLD
    // data key and new entries were encrypted under it, permanently
    // undecryptable. Best-effort wrap removal: the rotation itself already
    // succeeded server-side.
    vault.lock();
    await disableBiometricUnlock(userId).catch(() => {});

    return { ok: true, scheme: "v1", counts, rewrapped, rewrapFailures };
  } catch (err) {
    // H-2: a LOCAL failure before/outside the staged server flow (key
    // derivation, the CSPRNG seam, unexpected internal errors) must be a
    // typed outcome like every other failure — never an escaped throw.
    return {
      ok: false,
      stage: "verify",
      reason: err instanceof ApiError ? "server" : "offline",
      detail: err instanceof ApiError ? err.message : undefined,
    };
  } finally {
    // Nothing is derived yet → nothing to wipe (the H-2 restructure moved
    // derivation inside the try, so a mid-derivation failure reaches here
    // with one or both sets still null).
    if (oldKeys) zeroize(oldKeys.masterKey, oldKeys.authKey, oldKeys.dataKey);
    if (newKeys) zeroize(newKeys.masterKey, newKeys.authKey, newKeys.dataKey);
  }
}
