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
 */
import React, { useState } from "react";
import {
  ActivityIndicator,
  Alert,
  KeyboardAvoidingView,
  Platform,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
} from "react-native";
import qcrypto from "react-native-quick-crypto"; // registers the Buffer global used below
import { api, ApiError } from "../api/client";
import { deriveKeys } from "../crypto/MindPatternCrypto";
import type { Keys } from "../crypto/MindPatternCrypto";
import { zeroize } from "../crypto/kdf";
import { vault } from "../vault";
import { useSession } from "../store";
import { storeUnlockProof, verifyUnlockProof } from "../unlockProof";

/** Throttles offline password guessing: each failed offline proof check
 *  pauses before the dialog appears (PBKDF2 already costs ~100ms+ per
 *  guess; this pads the feedback loop). */
const FAILED_PROOF_DELAY_MS = 500;

export function UnlockScreen({ navigation }: { navigation: any }): React.JSX.Element {
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
      derived = deriveKeys(password, Buffer.from(saltB64, "base64"));
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
      const message =
        err instanceof ApiError && err.status === 401
          ? "Wrong password."
          : err instanceof Error
            ? err.message
            : "unknown error";
      Alert.alert("Unlock failed", message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <KeyboardAvoidingView style={styles.container} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <Text style={styles.title}>Locked</Text>
      <Text style={styles.subtitle}>
        Your keys never leave this device. Re-enter your password to unlock this session.
      </Text>
      <TextInput
        style={styles.input}
        placeholder="password"
        placeholderTextColor="#5c6370"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={unlock}
      />
      <TouchableOpacity style={styles.button} onPress={unlock} disabled={busy || !password}>
        {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>Unlock</Text>}
      </TouchableOpacity>
      <TouchableOpacity onPress={() => void signOut()}>
        <Text style={styles.switch}>Sign out instead</Text>
      </TouchableOpacity>
      {/* Crisis help needs no unlock and no network — the locked state is
          exactly when it must be one tap away. */}
      <TouchableOpacity style={styles.helpButton} onPress={() => navigation.navigate("Crisis")}>
        <Text style={styles.helpText}>Need help now? Crisis resources</Text>
      </TouchableOpacity>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center", padding: 32, gap: 12, backgroundColor: "#0f1115" },
  title: { fontSize: 34, fontWeight: "700", color: "#e8eaf0", textAlign: "center" },
  subtitle: { fontSize: 14, color: "#8a91a3", textAlign: "center", marginBottom: 24, lineHeight: 20 },
  input: { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 16 },
  button: { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 8 },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },
  switch: { color: "#7f9bff", textAlign: "center", marginTop: 16 },
  helpButton: { backgroundColor: "#242a38", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 24 },
  helpText: { color: "#7f9bff", fontSize: 14, fontWeight: "600" },
});
