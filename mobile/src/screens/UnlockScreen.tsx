/**
 * Cold-restart unlock gate. The session token lives on disk, but the key
 * vault is memory-only — after an app restart the user is "logged in" yet
 * locked out of every crypto operation. This screen re-derives the keys
 * from the password and re-verifies via login, which also refreshes a
 * possibly-expired token in the same round.
 *
 * OFFLINE VERIFICATION (the critical fix): the old offline path unlocked
 * the vault with ANY password — nothing verified the derivation. Now a
 * marker sealed under the data key at the last ONLINE login (see
 * unlockProof.ts) is opened with the freshly derived key: the wrong
 * password fails AEAD authentication and the vault stays locked, so a
 * mistyped password can never encrypt new entries under a wrong key.
 *
 * HONEST COPY (audit fix): the old subtitle claimed "Your keys never leave
 * this device" — false, since a processing session ships the data key once
 * (single-use, memory-only). The subtitle now tells the truth calmly.
 *
 * BIOMETRIC UNLOCK (2026-09-19): when this device has biometrics AND the
 * account previously stored a biometric wrap (src/biometricUnlock.ts), a
 * primary "Unlock with biometrics" button appears ABOVE the password
 * field. It restores LOCAL DECRYPTION only — a 401 from the server still
 * requires the password, which is why the dummies below are honest: the
 * vault zeroizes the master key the moment it takes ownership, and the
 * auth key exists solely to log in with the password. The password path is
 * never demoted, never hidden, and stays the default; every biometric
 * failure lands as one calm inline line, not a lockout.
 */
import { localWriteScopeEpoch } from "../localWriteGuard";
import { resumeLocalRekey, pendingLocalRekey, pendingLocalRekeyOldSalt } from "../localRekey";
import { rotatePassword } from "../rotation";
import React, { useEffect, useRef, useState } from "react";
import {
  Alert,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
} from "react-native";
import qcrypto from "react-native-quick-crypto"; // registers the Buffer global used below
import { api, ApiError } from "../api/client";
import { deriveKeysAsync } from "../crypto/MindPatternCrypto";
import type { Keys } from "../crypto/MindPatternCrypto";
import { KDF_ITERATIONS, zeroize } from "../crypto/kdf";
import { cachedEnvelope, cacheEnvelope, fetchEnvelope, unwrapSessionDataKey, type EnvelopeInfo } from "../keyScheme";
import { vault } from "../vault";
import { useSession } from "../store";
import { storeUnlockProof, verifyUnlockProof } from "../unlockProof";
import {
  clearUnlockFailures,
  recordUnlockFailure,
  unlockFailureDelayMs,
} from "../unlockBackoff";
import {
  biometricsSupported,
  disableBiometricUnlock,
  hasBiometricUnlock,
  unwrapBiometricDataKey,
} from "../biometricUnlock";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy } from "../components/errors";
import { t as tr } from "../strings";

/** S-5 (2026-09-26 pentest): the flat guessing pad moved into
 *  unlockBackoff.ts as BASE_UNLOCK_FAIL_DELAY_MS and now ESCALATES — see
 *  the catch in unlock() for the single record+pause site. */

export function UnlockScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { signOut, refreshActiveDays } = useSession();
  const [password, setPassword] = useState("");
  const [rotationPending, setRotationPending] = useState(false);
  const [rotationPassword, setRotationPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true), attempt = useRef(0), submitting = useRef(false);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; attempt.current++; }; }, []);
  const beginAttempt = () => {
    submitting.current = true; const id = ++attempt.current; let epoch = localWriteScopeEpoch();
    const ownsAttempt = () => mounted.current && attempt.current === id;
    const current = () => ownsAttempt() && epoch === localWriteScopeEpoch();
    const assertCurrent = () => { if (!current()) throw new ApiError(0, "This unlock attempt ended when the account or server changed. Try again.", "stale_operation"); };
    const wait = async <T,>(work: () => Promise<T>, discard?: (value: T) => void): Promise<T> => {
      assertCurrent(); const value = await work();
      if (!current()) { discard?.(value); assertCurrent(); } return value;
    };
    const adoptSession = async (token: string, userId: string, name: string) => {
      assertCurrent(); const pending = api.setSession(token,userId,name,{ stillCurrent: ownsAttempt });
      epoch = localWriteScopeEpoch(); await pending; assertCurrent();
    };
    const finish = () => { if (attempt.current === id) submitting.current = false; if (ownsAttempt()) setBusy(false); };
    const adoptCommittedRotation = (completionScope: number | undefined) => {
      if (completionScope === undefined) { assertCurrent(); return; }
      if (!ownsAttempt() || completionScope !== localWriteScopeEpoch()) throw new ApiError(0,"The rotation completed in a retired session.","stale_operation");
      epoch = completionScope; assertCurrent();
    };
    return { ownsAttempt,current,assertCurrent,wait,adoptSession,adoptCommittedRotation,finish };
  };
  /** Offered only when this device has biometrics AND the account has a
   *  stored wrap — the check itself never prompts (biometricUnlock.ts). */
  const [showBiometric, setShowBiometric] = useState(false);
  /** Calm inline failure line; never a dialog, never a lockout. */
  const [biometricError, setBiometricError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    void api.getUserId().then(async userId => { if (userId && !cancelled) setRotationPending(await pendingLocalRekey(userId)); }).catch(() => {});
    void (async () => {
      // Quiet probe: unsupported device, no stored wrap, or no session
      // account all leave the screen exactly as it was — password only.
      try {
        if (!(await biometricsSupported())) return;
        const userId = await api.getUserId();
        if (!userId || cancelled) return;
        if (await hasBiometricUnlock(userId)) {
          if (!cancelled) setShowBiometric(true);
        }
      } catch {
        /* the password path needs nothing from this probe */
      }
    })();
    return () => {
      cancelled = true;
    };
    // Stryker disable next-line ArrayDeclaration: a string-literal element is reference-stable, so React's Object.is dep comparison never sees a change — identical to []
  }, []);

  const unlockWithBiometrics = async () => {
    if (busy || submitting.current) return;
    const {current,assertCurrent,wait,finish} = beginAttempt();
    setBusy(true);
    let ownedDataKey: Buffer | null = null;
    try {
      const userId = await wait(() => api.getUserId());
      if (!userId) throw new Error("no saved account on this device");
      const dataKey = await wait(() => unwrapBiometricDataKey(userId), key => key?.fill(0));
      ownedDataKey = dataKey;
      if (dataKey === null) throw new Error("biometric unlock declined");
      // Audit fix 8 (2026-09-21): the unwrapped key runs the SAME sealed
      // proof check the password path runs. A stale wrap (a rotation or a
      // re-enrollment left the OLD key sealed) otherwise "unlocks" with the
      // wrong key and the whole journal reads as tamper failures. A "wrong"
      // proof deletes the stored wrap; any non-ok proof refuses the unlock
      // and falls back to the password path below.
      const proof = await wait(() => verifyUnlockProof(dataKey, userId));
      if (proof !== "ok") {
        if (proof === "wrong") await wait(() => disableBiometricUnlock(userId).catch(() => {}));
        setShowBiometric(false);
        setBiometricError(true);
        return;
      }
      // WHY the dummy master/auth keys are honest here: vault.unlock
      // zeroizes the master key immediately (it exists only to derive the
      // other two), and the auth key is only ever SENT at password login —
      // biometric unlock restores local decryption, not server
      // re-authentication. A 401 later still asks for the password.
      // authKeyKnown:false (H-2) tells the vault the authKey slot holds
      // PLACEHOLDER ZEROS: reauth.ts must never compare a real derivation
      // against them (that reported every correct password as wrong) — it
      // verifies online via api.login instead, until the real key is
      // re-adopted.
      await wait(() => resumeLocalRekey(userId, dataKey));
      assertCurrent();
      vault.unlock(
        { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32), dataKey },
        userId,
        { authKeyKnown: false },
      );
      ownedDataKey = null; // the vault owns and zeroizes this buffer
      setPassword(""); // the field was empty anyway; keep the invariant
      setBiometricError(false);
      await wait(() => refreshActiveDays());
    } catch {
      // Cancel, lockout, missing wrap, read failure — one calm line. The
      // password path below is untouched and still the guaranteed way in.
      if (current()) setBiometricError(true);
    } finally {
      ownedDataKey?.fill(0);
      finish();
    }
  };

  const unlock = async () => {
    if (!password || busy || submitting.current) return;
    const {current,assertCurrent,wait,adoptSession,finish} = beginAttempt();
    setBusy(true);
    let derived: Keys | null = null;
    let username: string | null = null;
    // v2 sessions: the envelope's random data key, held until the vault
    // takes ownership (the catch zeroizes it on a mid-flow failure).
    let sessionDataKey: Buffer | null = null;
    try {
      username = await wait(() => api.getUsername());
      const expectedOwner = await wait(() => api.getUserId());
      if (!expectedOwner) throw new Error(tr("unlock.noAccount"));
      if (!username) throw new Error(tr("unlock.noAccount"));
      let saltB64: string;
      let offline = false;
      try {
        const { salt } = await wait(() => api.saltFor(username!));
        saltB64 = salt;
        // Cache the (public, origin-bound) salt: it is what makes the NEXT
        // unlock work when the network is unreachable.
        await wait(() => api.cacheSalt(username!, salt));
      } catch (saltErr) {
        assertCurrent();
        // Offline with a cached salt: derive keys locally. Unlocking the
        // vault never needed a bearer token — sync just fails and retries.
        const cached = await wait(() => api.getCachedSalt(username!));
        if (!cached) throw saltErr;
        saltB64 = cached;
        offline = true; // the salt fetch already proved the network dead
      }
      // Async derivation: no 100–400ms JS-thread freeze mid-flow.
      derived = await wait(() => deriveKeysAsync(password, Buffer.from(saltB64, "base64")), key => zeroize(key.masterKey,key.authKey,key.dataKey));
      const keys = derived;
      // TS narrowing: the null check above proved `username` non-null, but
      // the unwrapFor closure below would otherwise still see string|null.
      const accountName: string = username;
      // v2 KEY ENVELOPE (2026-09-26): when set, the session's data key is
      // the envelope's RANDOM key (unwrapped below), and keys.dataKey — the
      // unused v1 data label — is zeroized before the vault unlock.
      /** Unwrap a v2 envelope, reusing the master key just derived when it
       *  was derived under this envelope's own salt and cost parameters.
       *  The GCM authentication is the password proof (offline) and a
       *  consistency check (online); a structural failure is a calm local
       *  error, never "wrong password". */
      const unwrapFor = async (envelope: EnvelopeInfo): Promise<Buffer> => {
        const res = await wait(() => unwrapSessionDataKey({
          password,
          username: accountName,
          envelope,
          derivedMaster: { key: keys.masterKey, saltB64, iterations: KDF_ITERATIONS },
        }), value => { if (value.ok) zeroize(value.dataKey); });
        if (res.ok) return res.dataKey;
        if (res.reason === "tamper") {
          // S-5: the envelope did not open under this password — the same
          // funnel as the sealed proof's "wrong" (401 → escalating pause).
          // Stryker disable next-line StringLiteral: dead message — the catch maps ANY 401 to the constant "Wrong password." dialog, so this thrown text is never read
          throw new ApiError(401, tr("common.wrongPassword"));
        }
        throw new Error(tr("unlock.envelopeFailed"));
      };
      let verifiedOnline = false;
      // Re-audit 2026-09-27 (M): the online v2 account whose envelope can be
      // NEITHER fetched ("invalid" — the server answered with a shape this
      // client refuses; "unreachable" — the endpoint failed) NOR read from
      // this device's cache used to fall through to v1 semantics: the vault
      // unlocked on the v1-DERIVED data key, the sealed proof was refreshed
      // under it, and every entry written that session became permanently
      // unreadable. The session is now REFUSED — the copy is set here and
      // thrown BELOW the try, because this try's catch deliberately swallows
      // non-401 failures to reach the offline path, and the refusal must
      // bypass that fall-through.
      // independent audit 2026-09-27 (P2): the refusal now also covers the
      // STALE-v1-MARKER case. A definitive server answer ("ok" v1, or
      // "legacy" — a 404 from a pre-envelope server) or a cached v2 ENVELOPE
      // with material are the ONLY things that may authorize the v1 path; a
      // cached v1 marker alone is a scheme hint from an earlier session, and
      // routing on it after a FAILED fetch re-seals the proof under the
      // v1-derived key — safe today only because v1→v2 wraps the SAME data
      // key, and a silent wrong-key write the moment any future scheme
      // rotation lands. Fail closed with honest retry copy instead.
      let envelopeRefusal: string | null = null;
      if (!offline) {
        try {
          const body = await wait(() => api.login(username!, keys.authKey.toString("base64")));
          if (body.user_id !== expectedOwner) throw new ApiError(0,"The account changed before unlock.","stale_operation");
          await adoptSession(body.token, body.user_id, username);
          // KEY SCHEME: the fresh bearer fetches the envelope. Only a
          // definitive answer routes the session; a FAILED fetch falls back
          // to the cached envelope, and only a cached v2 ENVELOPE (which
          // authenticates the password itself through GCM) may carry the
          // session from there.
          const fetched = await wait(() => fetchEnvelope());
          if (fetched.status === "ok") {
            const envelope = fetched.envelope;
            if (envelope.scheme === "v2") {
              const dataKey = await unwrapFor(envelope);
              sessionDataKey = dataKey;
              // Verified online AND by the envelope's own authentication:
              // refresh the sealed proof so a future offline unlock (and the
              // biometric path) checks against this very key.
              await wait(() => storeUnlockProof(dataKey, body.user_id));
              await wait(() => cacheEnvelope(username!, envelope).catch(() => {}));
            } else {
              // Definitive v1 answer: refresh the sealed proof so the next
              // offline unlock checks against this very key.
              await wait(() => storeUnlockProof(keys.dataKey, body.user_id));
              await wait(() => cacheEnvelope(username!, envelope).catch(() => {}));
            }
          } else if (fetched.status === "legacy") {
            // 404 from a pre-envelope server — a definitive answer that
            // cannot host a v2 account: v1 semantics hold.
            await wait(() => storeUnlockProof(keys.dataKey, body.user_id));
          } else {
            // "unreachable" | "invalid": the server gave NO scheme answer
            // this session. Only a cached v2 envelope (material + its own
            // GCM proof) may proceed; a stale v1 marker may not.
            const cached = await wait(() => cachedEnvelope(username!));
            if (cached !== null && cached.scheme === "v2") {
              const dataKey = await unwrapFor(cached);
              sessionDataKey = dataKey;
              await wait(() => storeUnlockProof(dataKey, body.user_id));
            } else {
              envelopeRefusal = tr(fetched.status === "invalid" ? "login.envelopeUnrecognized" : "unlock.schemeUnconfirmed");
            }
          }
          verifiedOnline = true;
        } catch (loginErr) {
          assertCurrent();
          if (loginErr instanceof ApiError && loginErr.code === "stale_operation") throw loginErr;
          // A definitive wrong-password rejection is never an offline case.
          if (loginErr instanceof ApiError && loginErr.status === 401) throw loginErr;
          // Otherwise (network died mid-flow): fall through to the sealed
          // proof / cached envelope below — it verifies the password
          // without the server.
        }
      }
      if (envelopeRefusal !== null) {
        // The password was accepted online but the account's real data key
        // could not be verified — unlocking on the v1-derived label would
        // silently corrupt everything written this session. Honest refusal:
        // our own Error text passes through requestFailureCopy verbatim.
        throw new Error(envelopeRefusal);
      }
      if (!verifiedOnline) {
        // OFFLINE PATH — must be VERIFIED, never assumed. v2 accounts open
        // the CACHED envelope: the wrong password fails its GCM
        // authentication, exactly like the sealed marker does for v1.
        const cached = await wait(() => cachedEnvelope(username!));
        if (cached !== null && cached.scheme === "v2") {
          sessionDataKey = await unwrapFor(cached);
        } else {
          const userId = await wait(() => api.getUserId());
          if (!userId) throw new Error(tr("unlock.noAccount"));
          const proof = await wait(() => verifyUnlockProof(keys.dataKey, userId));
          if (proof === "absent") {
            throw new Error(tr("unlock.offlineNotEnabled"));
          }
          if (proof === "wrong") {
            // S-5 (2026-09-26 pentest): wrong-proof and online-401 both funnel
            // into the catch's single escalating record+pause — one failure,
            // one increment, one delay. First failure pays the historical
            // 500 ms exactly; subsequent ones double up to 30 s, durably.
            // Stryker disable next-line StringLiteral: dead message — the catch maps ANY 401 to the constant "Wrong password." dialog, so this thrown text is never read
            throw new ApiError(401, tr("common.wrongPassword"));
          }
        }
      }
      const localOwner = await wait(() => api.getUserId());
      if (localOwner !== expectedOwner) throw new Error("The saved account changed before key adoption.");
      await wait(() => resumeLocalRekey(expectedOwner, sessionDataKey ?? keys.dataKey, { credentialConfirmed: !offline }));
      assertCurrent();
      if (sessionDataKey !== null) {
        vault.unlock(
          { masterKey: keys.masterKey, authKey: keys.authKey, dataKey: sessionDataKey },
          expectedOwner,
        );
        zeroize(keys.dataKey); // the v1 data label never protects v2 storage
      } else {
        vault.unlock(derived, expectedOwner); // vault takes ownership and zeroizes the master key
      }
      sessionDataKey = null; // the vault owns it now
      derived = null;
      setPassword(""); // minimize the password's lifetime in memory
      setBiometricError(false); // the promised password path worked — retract the biometric nudge
      // S-5: an honest success forgives the whole failure count.
      if (username) await wait(() => clearUnlockFailures(username!).catch(() => {}));
      await wait(() => refreshActiveDays());
    } catch (err) {
      if (sessionDataKey) zeroize(sessionDataKey);
      if (derived) zeroize(derived.masterKey, derived.authKey, derived.dataKey);
      if (!current()) return;
      vault.lock(); // a failed unlock must never leave stale keys live
      // 401 = wrong password (our own sealed proof throws the same). Other
      // ApiErrors map to calm copy; our own local Error text passes through.
      if (err instanceof ApiError && err.status === 401) {
        // S-5: the ONLINE wrong-password path escalates through the same
        // durable counter (the server throttles per-IP; this throttles
        // per-DEVICE, covering the offline oracle's online twin).
        const failures = username ? await recordUnlockFailure(username).catch(() => 1) : 1;
        if (!current()) return;
        await new Promise((resolve) => setTimeout(resolve, unlockFailureDelayMs(failures)));
        if (!current()) return;
      }
      const message =
        err instanceof ApiError && err.status === 401
          ? tr("common.wrongPassword")
          : requestFailureCopy(err);
      Alert.alert(tr("unlock.failedTitle"), message);
    } finally {
      finish();
    }
  };

  const finishInterruptedRotation = async () => {
    if (busy || submitting.current || !password || !rotationPassword) return;
    const {current,assertCurrent,wait,adoptCommittedRotation,finish} = beginAttempt();
    setBusy(true); let ownedKeys: Keys | null = null;
    try {
      const userId = await wait(() => api.getUserId()); const username = await wait(() => api.getUsername());
      if (!userId || !username) throw new Error(tr("common.reauthNoAccount"));
      const salt = await wait(() => pendingLocalRekeyOldSalt(userId)) ?? await wait(() => api.getCachedSalt(username));
      if (!salt) throw new Error(tr("common.reauthOffline"));
      ownedKeys = await wait(() => deriveKeysAsync(password, Buffer.from(salt, "base64")), key => zeroize(key.masterKey,key.authKey,key.dataKey));
      const proof = await wait(() => verifyUnlockProof(ownedKeys!.dataKey, userId));
      if (proof !== "ok") throw new Error(tr("common.wrongPassword"));
      assertCurrent();
      // The delegate separately guards its remote/key transition. A
      // restricted vault cannot admit ordinary old-key producers.
      vault.unlock(ownedKeys, userId, { writeSuspended: true }); ownedKeys = null;
      const outcome = await rotatePassword({ username, userId, oldPassword: password, newPassword: rotationPassword });
      if (!outcome.ok) { assertCurrent(); throw new Error(outcome.detail ?? tr("settings.rotateFailedTitle")); }
      // A successful rotation admits at most its one deliberate re-login.
      adoptCommittedRotation(outcome.sessionScope);
      vault.lock();
      setRotationPending(false); setPassword(""); setRotationPassword("");
      Alert.alert(tr("settings.rotateSuccessTitle"), tr("unlock.rotationFinished"));
    } catch (err) {
      if (current()) { vault.lock(); Alert.alert(tr("settings.rotateFailedTitle"), requestFailureCopy(err)); }
    } finally { if (ownedKeys) zeroize(ownedKeys.masterKey,ownedKeys.authKey,ownedKeys.dataKey); finish(); }
  };

  return (
    <KeyboardAvoidingView
      style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxxl, gap: t.spacing.md }]}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView
        contentContainerStyle={{ flexGrow: 1, justifyContent: "center", gap: t.spacing.md }}
        keyboardShouldPersistTaps="handled"
      >
      <Text style={[styles.title, { color: t.colors.text }]} maxFontSizeMultiplier={1.6}>
        {tr("unlock.title")}
      </Text>
      <Text style={[styles.subtitle, { color: t.colors.muted, fontSize: 14 }]}>
        {tr("unlock.body")}
      </Text>
      {showBiometric && (
      <PrimaryButton
          label={tr("unlock.biometric")}
          onPress={() => void unlockWithBiometrics()}
          disabled={busy}
          accessibilityLabel={tr("unlock.biometric")}
        />
      )}
      {biometricError && (
        <Text
          style={{ color: t.colors.muted, fontSize: 13, textAlign: "center", lineHeight: 18 }}
          accessibilityRole="alert"
        >
          {tr("unlock.biometricFailed")}
        </Text>
      )}
      <TextInput
        style={{
          backgroundColor: t.colors.card,
          color: t.colors.text,
          borderRadius: t.radius.md,
          padding: 14,
          fontSize: 16,
        }}
        placeholder={tr("common.passwordPlaceholder")}
        placeholderTextColor={t.colors.placeholder}
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={unlock}
        accessibilityLabel={tr("common.passwordA11y")}
        textContentType="password"
        autoComplete="current-password"
      />
        {rotationPending && <>
        <Text style={{ color: t.colors.body }}>{tr("unlock.rotationPending")}</Text>
        <TextInput value={rotationPassword} onChangeText={setRotationPassword} secureTextEntry autoCapitalize="none" autoCorrect={false} accessibilityLabel={tr("unlock.rotationPassword")} style={{ color: t.colors.text, backgroundColor: t.colors.card, padding: 14 }} />
        <GhostButton label={tr("unlock.finishRotation")} disabled={busy} onPress={() => void finishInterruptedRotation()} />
      </>}
      <PrimaryButton label={tr("unlock.button")} onPress={unlock} disabled={!password} busy={busy} />
      <GhostButton label={tr("unlock.signOutInstead")} onPress={() => { attempt.current++; submitting.current = false; void signOut(); }} />
      {/* Crisis help needs no unlock and no network — the locked state is
          exactly when it must be one tap away. */}
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center" },
  title: { fontSize: 34, fontWeight: "700", textAlign: "center" },
  subtitle: { textAlign: "center", marginBottom: 24, lineHeight: 20 },
});
