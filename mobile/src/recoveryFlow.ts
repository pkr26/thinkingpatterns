/**
 * The account-recovery flow (wave 3, 2026-09-30): forgot password, hold
 * the recovery key, set a new one — without losing a single word.
 *
 * One function drives the whole sequence (the RecoveryScreen calls it):
 *   1. POST /auth/recover with the recovery key (server bumps the epoch —
 *      every old bearer dies; the response carries the SEALED data key).
 *   2. Unseal the data key locally (HKDF(recovery key) → AES-GCM).
 *   3. Prove possession: open a processing session WITH the recovered
 *      data key (the same probe every envelope replacement requires).
 *   4. Derive a brand-new password's keys (fresh salt, canonical params)
 *      and wrap the SAME data key under them; PUT /account/recovery/
 *      password swaps salt + verifier + envelope atomically.
 *   5. Refresh the local salt/envelope caches so the NEXT unlock uses the
 *      new password, and hand the data key to the vault.
 */
import { api } from "./api/client";
import { deriveAuthKey, deriveMasterKeyAsync, zeroize } from "./crypto/kdf";
import {
  defaultKdfParams,
  envelopeKek,
  wrapDataKey,
} from "./crypto/keyEnvelope";
import {
  recoveryKeyFromB64,
  unsealDataKeyWithRecovery,
} from "./crypto/recovery";
import { engine } from "./crypto/engine";

export interface RecoveryOutcome {
  userId: string;
  username: string;
  dataKey: Buffer;
}

export async function recoverAccountWithKey(
  username: string,
  recoveryKeyText: string,
  newPassword: string,
): Promise<RecoveryOutcome> {
  const recoveryKey = recoveryKeyFromB64(recoveryKeyText);
  if (recoveryKey === null) {
    throw new Error("the recovery key must be 32 bytes of base64 (copy it exactly from your kit)");
  }
  const result = await api.recoverLogin(username.trim(), recoveryKey.toString("base64"));
  // The new bearer is stored FIRST: every subsequent call (processing
  // session, reset, envelope cache) rides the recovery session.
  await api.setSession(result.token, result.user_id, username.trim());

  const sealed = Buffer.from(result.recovery_wrapped_data_key, "base64");
  const dataKey = unsealDataKeyWithRecovery(recoveryKey, sealed, result.user_id);
  if (dataKey === null) {
    throw new Error("the recovery key did not open this account's sealed key — check the kit and username");
  }

  // Possession probe (same contract as every envelope replacement).
  const processingToken = await api.openProcessingSession(dataKey.toString("base64"));

  // New password → fresh salt + canonical params; the DATA KEY NEVER
  // CHANGES (v2 semantics — only its locker does).
  const salt = Buffer.from(engine.randomBytes(16));
  const params = defaultKdfParams();
  const master = await deriveMasterKeyAsync(newPassword, salt, params.iterations);
  try {
    const authKey = deriveAuthKey(master);
    const kek = envelopeKek(master, salt);
    const wrapped = wrapDataKey(dataKey, kek, username.trim(), params);
    zeroize(kek);
    await api.resetPasswordWithRecovery(
      recoveryKey.toString("base64"),
      {
        new_salt: salt.toString("base64"),
        new_verifier: authKey.toString("base64"),
        new_kdf_params: params,
        wrapped_data_key: wrapped.toString("base64"),
      },
      processingToken,
    );
    zeroize(authKey);
  } finally {
    zeroize(master);
  }
  // The recovery key outlives the reset proof, then dies.
  zeroize(recoveryKey);

  // Local caches follow the new credential so the next unlock works.
  await api.cacheSalt(username.trim(), salt.toString("base64"));
  const fresh = await api.keyEnvelope();
  await api.cacheKeyEnvelope(username.trim(), {
    scheme: "v2",
    saltB64: salt.toString("base64"),
    kdfParams: fresh.kdf_params,
    wrappedB64: fresh.wrapped_data_key,
  });

  return { userId: result.user_id, username: username.trim(), dataKey };
}
