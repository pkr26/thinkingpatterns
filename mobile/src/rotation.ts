/**
 * Password rotation: the recovery path for captured credentials and keys
 * (audit fix H-1/M-3, 2026-09-20).
 *
 * Until now NOTHING in the system could retire a login credential: the
 * derived auth key was the standing password-equivalent forever, so a
 * phished verifier (or one request-body capture of the data key) meant a
 * permanent compromise. This module orchestrates the server's three new
 * endpoints in the required order:
 *
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
 * Idempotent retry: if a previous attempt died between (3) and (5), the
 * rekey step answers rekey_key_mismatch (the blobs are already under the
 * new key). The flow then verifies the NEW key really decrypts a live
 * entry and continues from (4) instead of failing — a half-finished
 * rotation must always be finishable.
 */
import { api, ApiError } from "./api/client";
import { decryptEntry, deriveKeysAsync } from "./crypto/MindPatternCrypto";
import { engine } from "./crypto/engine";
import { wrapDataKeyForTherapist } from "./crypto/sharing";
import { zeroize } from "./crypto/kdf";
import { rebindEntryVersions, forgetAllEntryVersions } from "./entryVersions";
import { clearMoodLog } from "./moodLog";
import { clearFeedback } from "./questionFeedback";
import { clearUnlockProof } from "./unlockProof";
import { verifyPasswordForVault } from "./reauth";
import { vault } from "./vault";
import { disableBiometricUnlock } from "./biometricUnlock";

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
      counts: { entries: number; insights: number; measures: number };
      rewrapped: number;
      rewrapFailures: string[];
    }
  | {
      ok: false;
      stage: RotationStage;
      reason: "wrong-password" | "offline" | "server" | "already-rotated-unverifiable";
      /** Human-oriented detail (already sanitized server text or a local
       * constant) — the UI may render it after errors.ts treatment. */
      detail?: string;
    };

/** Can the NEW key decrypt at least one live entry? (Retry ladder step:
 * proves a rekey_key_mismatch means "already rekeyed", not "wrong key".)
 * An empty journal trivially verifies — there is nothing to mismatch. */
async function newKeyReadsJournal(userId: string, newDataKey: Buffer): Promise<boolean> {
  try {
    const page = await api.listEntriesPage({ limit: 1, offset: 0 });
    if (page.entries.length === 0) return true;
    const entry = page.entries[0]!;
    if (typeof entry.blob !== "string") return false;
    try {
      decryptEntry({ dataKey: newDataKey }, userId, entry.client_entry_id, entry.blob);
      return true;
    } catch {
      return false;
    }
  } catch {
    return false;
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
    const newSalt = freshSalt();
    newKeys = await deriveKeysAsync(newPassword, newSalt);
    newSaltB64 = newSalt.toString("base64");
    newVerifierB64 = newKeys.authKey.toString("base64");
    // --- 3. rekey every stored blob old -> new -----------------------------
    let counts = { entries: 0, insights: 0, measures: 0 };
    let alreadyRekeyed = false;
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
          return {
            ok: false,
            stage: "rekey",
            reason: "already-rotated-unverifiable",
            detail:
              "the stored data was already re-keyed by an earlier attempt, but the new password cannot read it — it was rotated to a different new password",
          };
        }
        alreadyRekeyed = true;
      } else if (err instanceof ApiError && err.status === 403) {
        return { ok: false, stage: "rekey", reason: "wrong-password", detail: err.message };
      } else {
        return { ok: false, stage: "rekey", reason: err instanceof ApiError ? "server" : "offline", detail: err instanceof ApiError ? err.message : undefined };
      }
    }
    void alreadyRekeyed; // (kept for clarity; verification above was the gate)

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
    await api.cacheSalt(username, newSaltB64);

    // Data-key-bound local caches: rebind what survives a key change
    // (entry-version marks), clear what must be re-created on next use
    // (mood log, question feedback, unlock proof — all sealed under the
    // OLD data key).
    await rebindEntryVersions(userId, oldKeys!.dataKey, newKeys!.dataKey).catch(() =>
      forgetAllEntryVersions(userId),
    );
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

    return { ok: true, counts, rewrapped, rewrapFailures };
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
