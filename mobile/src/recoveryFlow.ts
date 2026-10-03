/** Password recovery keeps the data key, locally selects the kit scheme,
 * and returns a committed success even when a local cache cannot be saved. */
import { api, ApiError } from "./api/client";
import { localWriteScopeEpoch } from "./localWriteGuard";
import { deriveAuthKey, deriveMasterKeyAsync, zeroize } from "./crypto/kdf";
import { defaultKdfParams, envelopeKek, wrapDataKey } from "./crypto/keyEnvelope";
import { recoveryKeyFromB64, recoveryVerifierKeyV2, unsealDataKeyWithRecoveryScheme, type RecoveryScheme } from "./crypto/recovery";
import { engine } from "./crypto/engine";
export interface RecoveryOutcome { userId: string; username: string; dataKey: Buffer; ownershipEpoch: number; localCacheReady?: boolean }
export async function recoverAccountWithKey(username: string, recoveryKeyText: string, newPassword: string, scheme: RecoveryScheme = "v2", options: { stillCurrent?: () => boolean } = {}): Promise<RecoveryOutcome> {
  let epoch = localWriteScopeEpoch();
  const ownsAttempt = () => options.stillCurrent?.() !== false;
  const current = () => ownsAttempt() && epoch === localWriteScopeEpoch();
  const assertCurrent = () => { if (!current()) throw new ApiError(0, "Recovery stopped because the account or server changed. Confirm any completed password reset before retrying.", "stale_operation"); };
  const wait = async <T>(work: () => Promise<T>, discard?: (value: T) => void): Promise<T> => {
    assertCurrent(); const value = await work();
    if (!current()) { discard?.(value); assertCurrent(); } return value;
  };
  const recoveryKey = recoveryKeyFromB64(recoveryKeyText);
  if (!recoveryKey) throw new Error("the recovery key must be 32 bytes of base64 (copy it exactly from your kit)");
  let dataKey: Buffer | null = null;
  let salt: Buffer | null = null;
  let verifier: Buffer | null = null;
  let returned = false;
  let sessionAttempted = false;
  try {
    const selected: RecoveryScheme = recoveryKeyText.trim().startsWith("mindpattern-recovery:v1:") ? "v1" : scheme;
    if (recoveryKeyText.trim().startsWith("mindpattern-recovery:v2:") && selected !== "v2") throw new Error("A v2 recovery kit cannot be used as a legacy kit");
    // Remote errors/metadata can never ask us to send a v2 kit's raw key.
    verifier = selected === "v2" ? recoveryVerifierKeyV2(recoveryKey) : Buffer.from(recoveryKey);
    const proof = verifier.toString("base64");
    const result = await wait(() => api.recoverLogin(username.trim(), proof, selected));
    if ((result.recovery_scheme ?? "v1") !== selected) throw new Error("The account's recovery scheme does not match the selected kit");
    const canonicalUsername = typeof result.username === "string" && result.username ? result.username : username.trim();
    dataKey = unsealDataKeyWithRecoveryScheme(recoveryKey, Buffer.from(result.recovery_wrapped_data_key, "base64"), result.user_id, selected);
    if (!dataKey) throw new Error("the recovery key did not open this account's sealed key — check the kit and username");
    sessionAttempted = true;
    assertCurrent();
    const pending = api.setSession(result.token, result.user_id, canonicalUsername, { stillCurrent: ownsAttempt });
    epoch = localWriteScopeEpoch(); await pending; assertCurrent();
    const { session_token: processingToken } = await wait(() => api.openProcessingSession(dataKey!.toString("base64")));
    if (typeof processingToken !== "string" || !processingToken) throw new Error("Invalid processing-session response");
    salt = Buffer.from(engine.randomBytes(16));
    const params = defaultKdfParams();
    const master = await wait(() => deriveMasterKeyAsync(newPassword, salt!, params.iterations), value => zeroize(value));
    let wrapped: Buffer;
    try {
      const authKey = deriveAuthKey(master);
      const kek = envelopeKek(master, salt);
      try { wrapped = wrapDataKey(dataKey, kek, canonicalUsername, params); } finally { zeroize(kek); }
      try {
        await wait(() => api.resetPasswordWithRecovery(proof, {
          new_salt: salt!.toString("base64"), new_verifier: authKey.toString("base64"),
          new_kdf_params: params, wrapped_data_key: wrapped.toString("base64"),
        }, processingToken));
      } finally { zeroize(authKey); }
    } finally { zeroize(master); }
    // Credential reset has committed. Cache failures require an online unlock,
    // not another reset or a false report that the new password failed.
    let localCacheReady = true;
    try {
      await wait(() => api.cacheSalt(canonicalUsername, salt!.toString("base64")));
      await wait(() => api.cacheKeyEnvelope(canonicalUsername, {
        scheme: "v2", saltB64: salt!.toString("base64"), kdfParams: params, wrappedB64: wrapped!.toString("base64"),
      }));
    } catch {
      assertCurrent();
      localCacheReady = false;
      await Promise.allSettled([
        Promise.resolve().then(() => api.clearCachedSalt(canonicalUsername)),
        Promise.resolve().then(() => api.clearCachedKeyEnvelope(canonicalUsername)),
      ]);
      assertCurrent();
    }
    assertCurrent();
    returned = true;
    return { userId: result.user_id, username: canonicalUsername, dataKey, ownershipEpoch: epoch, localCacheReady };
  } catch (err) {
    if (sessionAttempted && current()) await api.clearSession().catch(() => {});
    throw err;
  } finally {
    zeroize(recoveryKey);
    if (salt) zeroize(salt);
    if (verifier) zeroize(verifier);
    if (dataKey && !returned) zeroize(dataKey);
  }
}
