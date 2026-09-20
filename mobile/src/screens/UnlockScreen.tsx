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
import React, { useEffect, useState } from "react";
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
import { zeroize } from "../crypto/kdf";
import { vault } from "../vault";
import { useSession } from "../store";
import { storeUnlockProof, verifyUnlockProof } from "../unlockProof";
import { biometricsSupported, hasBiometricUnlock, unwrapBiometricDataKey } from "../biometricUnlock";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy } from "../components/errors";
import { t as tr } from "../strings";

/** Throttles offline password guessing: each failed offline proof check
 *  pauses before the dialog appears (PBKDF2 already costs ~100ms+ per
 *  guess; this pads the feedback loop). */
const FAILED_PROOF_DELAY_MS = 500;

export function UnlockScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { signOut, refreshActiveDays } = useSession();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  /** Offered only when this device has biometrics AND the account has a
   *  stored wrap — the check itself never prompts (biometricUnlock.ts). */
  const [showBiometric, setShowBiometric] = useState(false);
  /** Calm inline failure line; never a dialog, never a lockout. */
  const [biometricError, setBiometricError] = useState(false);

  useEffect(() => {
    let cancelled = false;
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
    if (busy) return;
    setBusy(true);
    try {
      const userId = await api.getUserId();
      if (!userId) throw new Error("no saved account on this device");
      const dataKey = await unwrapBiometricDataKey(userId);
      if (dataKey === null) throw new Error("biometric unlock declined");
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
      vault.unlock(
        { masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32), dataKey },
        userId,
        { authKeyKnown: false },
      );
      setPassword(""); // the field was empty anyway; keep the invariant
      setBiometricError(false);
      await refreshActiveDays();
    } catch {
      // Cancel, lockout, missing wrap, read failure — one calm line. The
      // password path below is untouched and still the guaranteed way in.
      setBiometricError(true);
    } finally {
      setBusy(false);
    }
  };

  const unlock = async () => {
    if (!password || busy) return;
    setBusy(true);
    let derived: Keys | null = null;
    try {
      const username = await api.getUsername();
      if (!username) throw new Error(tr("unlock.noAccount"));
      let saltB64: string;
      let offline = false;
      try {
        const { salt } = await api.saltFor(username);
        saltB64 = salt;
        // Cache the (public, origin-bound) salt: it is what makes the NEXT
        // unlock work when the network is unreachable.
        await api.cacheSalt(username, salt);
      } catch (saltErr) {
        // Offline with a cached salt: derive keys locally. Unlocking the
        // vault never needed a bearer token — sync just fails and retries.
        const cached = await api.getCachedSalt(username);
        if (!cached) throw saltErr;
        saltB64 = cached;
        offline = true; // the salt fetch already proved the network dead
      }
      // Async derivation: no 100–400ms JS-thread freeze mid-flow.
      derived = await deriveKeysAsync(password, Buffer.from(saltB64, "base64"));
      const keys = derived;
      let verifiedOnline = false;
      if (!offline) {
        try {
          const body = await api.login(username, keys.authKey.toString("base64"));
          await api.setSession(body.token, body.user_id, username);
          // Verified against the server: refresh the sealed proof so the
          // next offline unlock checks against this very key.
          await storeUnlockProof(keys.dataKey, body.user_id);
          verifiedOnline = true;
        } catch (loginErr) {
          // A definitive wrong-password rejection is never an offline case.
          if (loginErr instanceof ApiError && loginErr.status === 401) throw loginErr;
          // Otherwise (network died mid-flow): fall through to the sealed
          // proof below — it verifies the password without the server.
        }
      }
      if (!verifiedOnline) {
        // OFFLINE PATH — must be VERIFIED, never assumed. The sealed
        // marker only opens under the correct data key.
        const userId = await api.getUserId();
        if (!userId) throw new Error(tr("unlock.noAccount"));
        const proof = await verifyUnlockProof(keys.dataKey, userId);
        if (proof === "absent") {
          throw new Error(tr("unlock.offlineNotEnabled"));
        }
        if (proof === "wrong") {
          await new Promise((resolve) => setTimeout(resolve, FAILED_PROOF_DELAY_MS));
          // Stryker disable next-line StringLiteral: dead message — the catch maps ANY 401 to the constant "Wrong password." dialog, so this thrown text is never read
          throw new ApiError(401, tr("common.wrongPassword"));
        }
      }
      vault.unlock(derived, (await api.getUserId()) ?? undefined); // vault takes ownership and zeroizes the master key
      derived = null;
      setPassword(""); // minimize the password's lifetime in memory
      setBiometricError(false); // the promised password path worked — retract the biometric nudge
      await refreshActiveDays();
    } catch (err) {
      if (derived) zeroize(derived.masterKey, derived.authKey, derived.dataKey);
      vault.lock(); // a failed unlock must never leave stale keys live
      // 401 = wrong password (our own sealed proof throws the same). Other
      // ApiErrors map to calm copy; our own local Error text passes through.
      const message =
        err instanceof ApiError && err.status === 401
          ? tr("common.wrongPassword")
          : requestFailureCopy(err);
      Alert.alert(tr("unlock.failedTitle"), message);
    } finally {
      setBusy(false);
    }
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
      <PrimaryButton label={tr("unlock.button")} onPress={unlock} disabled={!password} busy={busy} />
      <GhostButton label={tr("unlock.signOutInstead")} onPress={() => void signOut()} />
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
