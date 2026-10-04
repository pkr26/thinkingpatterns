/**
 * v1 → v2 key-envelope upgrade (2026-09-26 crypto wave), self-service from
 * Settings after unlock.
 *
 * A v1 account's data key is DERIVED from the password; migrating to v2
 * wraps THAT SAME KEY under a password-derived KEK and uploads the
 * envelope — the account flips to key_scheme="v2", every stored blob keeps
 * decrypting under the unchanged key, and future password changes become
 * O(1) (see rotation.ts's v2 branch).
 *
 * The server demands two independent proofs, and this flow ships both:
 *   1. the password verifier (X-Account-Verifier) — the same gate as every
 *      credential-adjacent action (reauth.ts discipline);
 *   2. POSSESSION of the current data key (X-Processing-Token): a live
 *      owner-bound processing session whose key AUTHENTICATES stored
 *      ciphertext. The server otherwise cannot tell the real data key from
 *      any 32 bytes, and an envelope over the wrong key would brick every
 *      future unlock — its 403 envelope_key_mismatch is surfaced as calm,
 *      honest copy, never auto-retried.
 *
 * Composition with the biometric wrap (biometricUnlock.ts): unchanged by
 * design. The Keychain wrap stores whatever data key the session holds;
 * the upgrade does not rotate that key, so the wrap keeps restoring the
 * right one.
 */
import { api, ApiError } from "./api/client";
import { defaultKdfParams, envelopeKek, wrapDataKey } from "./crypto/keyEnvelope";
import { deriveMasterKeyAsync, zeroize } from "./crypto/kdf";
import { cacheEnvelope, fetchEnvelope } from "./keyScheme";
import { verifyPasswordForVault } from "./reauth";
import { vault } from "./vault";
import { captureLocalWritePermit, assertLocalWritePermit, localWriteScopeEpoch } from "./localWriteGuard";

export type UpgradeStage = "verify" | "wrap" | "upgrade";

export type UpgradeOutcome =
  | {
      ok: true;
      /** True when the account was ALREADY v2 — nothing was sent, the
       *  action is a no-op and the copy says so honestly. */
      already: boolean;
    }
  | {
      ok: false;
      stage: UpgradeStage;
      reason: "wrong-password" | "locked" | "no-account" | "offline" | "server" | "key-mismatch" | "session-expired";
      /** Client-authored local detail only; server detail is never rendered. */
      detail?: string;
    };

function localErrorDetail(error: unknown): string | undefined {
  return error instanceof ApiError ? undefined : error instanceof Error ? error.message : undefined;
}

export async function upgradeKeyProtection(input: {
  username: string;
  userId: string;
  password: string;
  /** Verifier from an already-run reauth (Settings types the password
   *  once); omitted → the flow verifies itself via reauth semantics. */
  verifierB64?: string;
}): Promise<UpgradeOutcome> {
  const { username, userId, password } = input;
  const epoch = localWriteScopeEpoch();
  if (!vault.isUnlocked() || vault.ownerUserId() !== userId) return { ok: false, stage: "verify", reason: "locked" };
  const original = vault.get();
  const dataKeyCopy = Buffer.from(original.dataKey);
  const assertOwner = () => {
    if (epoch !== localWriteScopeEpoch() || !vault.isUnlocked() || vault.ownerUserId() !== userId || vault.get().dataKey !== original.dataKey) throw new Error("The account or unlocked key changed during the upgrade");
  };
  try {
  const permit = captureLocalWritePermit(userId, original.dataKey);
  const assertCurrent = () => { assertOwner(); assertLocalWritePermit(permit); };


  // --- 1. password proof -----------------------------------------------------
  let verifierB64 = input.verifierB64 ?? null;
  if (verifierB64 === null) {
    const reauth = await verifyPasswordForVault(password);
    assertCurrent();
    if (!reauth.ok) {
      return {
        ok: false,
        stage: "verify",
        reason: reauth.reason === "wrong-password" ? "wrong-password" : reauth.reason === "locked" ? "locked" : reauth.reason === "no-account" ? "no-account" : "offline",
      };
    }
    verifierB64 = reauth.verifierB64;
  } else if (!vault.isUnlocked()) {
    return { ok: false, stage: "verify", reason: "locked" };
  }

  // --- 2. the account's current scheme ----------------------------------------
  assertCurrent();
  const fetched = await fetchEnvelope();
  assertCurrent();
  if (fetched.status === "unreachable") {
    return { ok: false, stage: "verify", reason: "offline" };
  }
  if (fetched.status === "legacy") {
    return {
      ok: false,
      stage: "verify",
      reason: "server",
      detail: "this server does not support the newer key protection yet",
    };
  }
  if (fetched.status === "invalid") {
    return {
      ok: false,
      stage: "verify",
      reason: "server",
      detail: "this account's key envelope uses parameters this app cannot derive — update the app first",
    };
  }
  if (fetched.envelope.scheme === "v2") {
    // Already upgraded (another device, or a fresh v2 registration): refresh
    // the local cache so offline unlocks know, and report the no-op.
    await cacheEnvelope(username, fetched.envelope).catch(() => {});
    assertCurrent();
    return { ok: true, already: true };
  }

  // --- 3. wrap the CURRENT data key under the password-derived KEK ------------
  if (!vault.isUnlocked()) return { ok: false, stage: "wrap", reason: "locked" };
  // The vault binding check the key-shipping flows share: the session's key
  // must belong to THIS account before it is wrapped as its envelope.
  if (vault.ownerUserId() !== userId) {
    return { ok: false, stage: "wrap", reason: "locked" };
  }
  const salt = Buffer.from(fetched.envelope.saltB64, "base64");
  if (salt.length < 8) {
    return { ok: false, stage: "wrap", reason: "server", detail: "this account's salt is malformed" };
  }
  const params = defaultKdfParams();
  let master: Buffer | null = null;
  let wrappedB64: string;
  try {
    master = await deriveMasterKeyAsync(password, salt);
    assertCurrent();
    const kek = envelopeKek(master, salt);
    try {
      wrappedB64 = wrapDataKey(dataKeyCopy, kek, username, params).toString("base64");
    } finally {
      zeroize(kek);
    }
  } catch (err) {
    return {
      ok: false,
      stage: "wrap",
      reason: err instanceof ApiError ? "server" : "offline",
      detail: localErrorDetail(err),
    };
  } finally {
    if (master) zeroize(master);
  }

  // --- 4. possession proof + upload --------------------------------------------
  try {
    assertCurrent();
    const session = await api.openProcessingSession(dataKeyCopy.toString("base64"));
    assertCurrent();
    await api.upgradeKeyEnvelope(params, wrappedB64, String(session.session_token), verifierB64);
    assertCurrent();
  } catch (err) {
    if (err instanceof ApiError && err.code === "envelope_key_mismatch") {
      // The processing session's key did not authenticate stored ciphertext:
      // this device's data key is not the account's. Retrying cannot fix
      // that — an envelope over the wrong key would brick the account.
      return {
        ok: false,
        stage: "upgrade",
        reason: "key-mismatch",
        detail:
          "the key on this device does not match the data stored on the server — unlock again with the current password before upgrading",
      };
    }
    if (err instanceof ApiError && err.code === "processing_session_invalid") {
      return { ok: false, stage: "upgrade", reason: "offline" };
    }
    if (err instanceof ApiError && err.status === 403) {
      // A verifier rejection on a reauth-supplied proof: the typed password
      // did not match after all.
      return { ok: false, stage: "upgrade", reason: "wrong-password" };
    }
    if (err instanceof ApiError && err.status === 401) {
      // Session death: the client hook has already locked the vault.
      return { ok: false, stage: "upgrade", reason: "session-expired" };
    }
    return {
      ok: false,
      stage: "upgrade",
      reason: err instanceof ApiError ? "server" : "offline",
      detail: localErrorDetail(err),
    };
  }

  // --- 5. cache the envelope: the next unlock (and offline unlock) is v2 -------
  assertCurrent();
  await cacheEnvelope(username, {
    scheme: "v2",
    saltB64: fetched.envelope.saltB64,
    kdfParams: params,
    wrappedB64,
  }).catch(() => {});
  // The data key is unchanged: the unlock proof, the biometric wrap, the
  // offline queue and every stored blob keep working as they are.
  assertCurrent();
  return { ok: true, already: false };
  } catch {
    return { ok: false, stage: "verify", reason: "locked", detail: "The account or key changed; unlock again before upgrading" };
  } finally { zeroize(dataKeyCopy); }
}
