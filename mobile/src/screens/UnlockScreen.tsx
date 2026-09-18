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
 */
import React, { useState } from "react";
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
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy } from "../components/errors";

/** Throttles offline password guessing: each failed offline proof check
 *  pauses before the dialog appears (PBKDF2 already costs ~100ms+ per
 *  guess; this pads the feedback loop). */
const FAILED_PROOF_DELAY_MS = 500;

export function UnlockScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { signOut, refreshActiveDays } = useSession();
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const unlock = async () => {
    if (!password || busy) return;
    setBusy(true);
    let derived: Keys | null = null;
    try {
      const username = await api.getUsername();
      if (!username) throw new Error("no saved account on this device — please sign in");
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
        if (!userId) throw new Error("no saved account on this device — please sign in");
        const proof = await verifyUnlockProof(keys.dataKey, userId);
        if (proof === "absent") {
          throw new Error(
            "offline unlock is not enabled on this device yet — sign in once while online to enable it",
          );
        }
        if (proof === "wrong") {
          await new Promise((resolve) => setTimeout(resolve, FAILED_PROOF_DELAY_MS));
          // Stryker disable next-line StringLiteral: dead message — the catch maps ANY 401 to the constant "Wrong password." dialog, so this thrown text is never read
          throw new ApiError(401, "Wrong password.");
        }
      }
      vault.unlock(derived, (await api.getUserId()) ?? undefined); // vault takes ownership and zeroizes the master key
      derived = null;
      setPassword(""); // minimize the password's lifetime in memory
      await refreshActiveDays();
    } catch (err) {
      if (derived) zeroize(derived.masterKey, derived.authKey, derived.dataKey);
      vault.lock(); // a failed unlock must never leave stale keys live
      // 401 = wrong password (our own sealed proof throws the same). Other
      // ApiErrors map to calm copy; our own local Error text passes through.
      const message =
        err instanceof ApiError && err.status === 401
          ? "Wrong password."
          : requestFailureCopy(err);
      Alert.alert("Unlock failed", message);
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
        Locked
      </Text>
      <Text style={[styles.subtitle, { color: t.colors.muted, fontSize: 14 }]}>
        Your journal is encrypted with keys only you hold. Re-enter your password to unlock this
        device. When you ask for your patterns, the key visits the server once — held in memory,
        then destroyed. Nothing else ever leaves.
      </Text>
      <TextInput
        style={{
          backgroundColor: t.colors.card,
          color: t.colors.text,
          borderRadius: t.radius.md,
          padding: 14,
          fontSize: 16,
        }}
        placeholder="password"
        placeholderTextColor={t.colors.placeholder}
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={unlock}
        accessibilityLabel="Password"
        textContentType="password"
        autoComplete="current-password"
      />
      <PrimaryButton label="Unlock" onPress={unlock} disabled={!password} busy={busy} />
      <GhostButton label="Sign out instead" onPress={() => void signOut()} />
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
