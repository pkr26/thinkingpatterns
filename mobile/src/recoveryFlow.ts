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
  recoveryVerifierKeyV2,
  unsealDataKeyWithRecoveryScheme,
  type RecoveryScheme,
} from "./crypto/recovery";
import { ApiError } from "./api/client";
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
  // 2026-10-01 audit C1: scheme negotiation. New kits are v2 — transmit
  // ONLY the domain-separated verifier (never the raw key). A kit stored
  // under v1 answers 401 recovery_scheme_mismatch (protocol negotiation,
  // not a credential miss): retry once with the legacy raw-key form.
  const verifierV2 = recoveryVerifierKeyV2(recoveryKey);
  let result: Awaited<ReturnType<typeof api.recoverLogin>>;
  let proofB64: string;
  try {
    result = await api.recoverLogin(username.trim(), verifierV2.toString("base64"), "v2");
    proofB64 = verifierV2.toString("base64");
  } catch (err) {
    if (!(err instanceof ApiError) || err.code !== "recovery_scheme_mismatch") throw err;
    result = await api.recoverLogin(username.trim(), recoveryKey.toString("base64"), "v1");
    proofB64 = recoveryKey.toString("base64");
  } finally {
    verifierV2.fill(0);
  }
  const kitScheme: RecoveryScheme = result.recovery_scheme ?? "v1";
  // The new bearer is stored FIRST (every subsequent call rides the
  // recovery session) — but 2026-10-01 audit M9 wraps the REST of the
  // flow so a mid-flight failure clears it again: no stored half-state.
  await api.setSession(result.token, result.user_id, username.trim());
  let dataKey: Buffer;
  let salt: Buffer | null = null;
  try {
    const sealed = Buffer.from(result.recovery_wrapped_data_key, "base64");
    const opened = unsealDataKeyWithRecoveryScheme(recoveryKey, sealed, result.user_id, kitScheme);
    if (opened === null) {
      throw new Error(
        "the recovery key did not open this account's sealed key — check the kit and username",
      );
    }
    dataKey = opened;

    // Possession probe (same contract as every envelope replacement).
    const processingToken = await api.openProcessingSession(dataKey.toString("base64"));

    // New password → fresh salt + canonical params; the DATA KEY NEVER
    // CHANGES (v2 semantics — only its locker does).
    salt = Buffer.from(engine.randomBytes(16));
    const params = defaultKdfParams();
    const master = await deriveMasterKeyAsync(newPassword, salt, params.iterations);
    try {
      const authKey = deriveAuthKey(master);
      const kek = envelopeKek(master, salt);
      const wrapped = wrapDataKey(dataKey, kek, username.trim(), params);
      zeroize(kek);
      await api.resetPasswordWithRecovery(
        proofB64,
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
  } catch (err) {
    // M9: the recovery did not prove out — drop the stored bearer and the
    // switched account so a retry starts clean (a hostile server_id or a
    // mid-flow network failure must not leave a half-session behind).
    await api.clearSession().catch(() => undefined);
    throw err;
  }
  // The recovery key outlives the reset proof, then dies.
  zeroize(recoveryKey);

  // Local caches follow the new credential so the next unlock works.
  if (salt !== null) {
    await api.cacheSalt(username.trim(), salt.toString("base64"));
    const fresh = await api.keyEnvelope();
    await api.cacheKeyEnvelope(username.trim(), {
      scheme: "v2",
      saltB64: salt.toString("base64"),
      kdfParams: fresh.kdf_params,
      wrappedB64: fresh.wrapped_data_key,
    });
    zeroize(salt);
  }

  return { userId: result.user_id, username: username.trim(), dataKey };
}
