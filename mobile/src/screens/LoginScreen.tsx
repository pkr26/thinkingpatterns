/**
 * Onboarding / login. The password exists in component state for the minimum
 * time: keys are derived, the master key is zeroized, and only the auth key
 * ever crosses the network. The password itself is stored nowhere — on
 * failure every derived buffer is zeroized before the retry.
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
import qcrypto from "react-native-quick-crypto";
import { api, ApiError } from "../api/client";
import { deriveKeys } from "../crypto/MindPatternCrypto";
import type { Keys } from "../crypto/MindPatternCrypto";
import { zeroize } from "../crypto/kdf";
import { vault } from "../vault";
import { useSession } from "../store";
import { storeUnlockProof } from "../unlockProof";

export function LoginScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const { refreshActiveDays, markLoggedIn } = useSession();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    const name = username.trim();
    if (!name || !password || busy) return;
    if (mode === "register" && password.length < 8) {
      Alert.alert("Password too short", "Use at least 8 characters — this password derives your encryption keys.");
      return;
    }
    setBusy(true);
    let derived: Keys | null = null;
    try {
      let verifiedUserId = "";
      if (mode === "register") {
        // Buffer.from() copies: quick-crypto's Buffer type differs from
        // node's in the .d.ts, but the bytes are identical.
        const salt = Buffer.from(qcrypto.randomBytes(16));
        derived = deriveKeys(password, salt);
        const body = await api.register(name, salt.toString("base64"), derived.authKey.toString("base64"));
        await api.setSession(body.token, body.user_id, name);
        // The account was created on THIS device: seal the offline-unlock
        // proof under the data key right away.
        await storeUnlockProof(derived.dataKey, body.user_id);
        await api.cacheSalt(name, salt.toString("base64"));
        verifiedUserId = body.user_id;
      } else {
        const { salt: saltB64 } = await api.saltFor(name);
        // Cache the (public, origin-bound) salt so a later cold-restart
        // unlock can derive keys even when the network is unreachable.
        await api.cacheSalt(name, saltB64);
        derived = deriveKeys(password, Buffer.from(saltB64, "base64"));
        const body = await api.login(name, derived.authKey.toString("base64"));
        await api.setSession(body.token, body.user_id, name);
        // Login SUCCEEDED — the password is verified. Seal the proof that
        // offline unlocks will be checked against (see UnlockScreen).
        await storeUnlockProof(derived.dataKey, body.user_id);
        verifiedUserId = body.user_id;
      }
      // The vault records WHICH account these keys belong to — key-shipping
      // operations (processing sessions) verify that binding.
      vault.unlock(derived, verifiedUserId || undefined); // takes ownership; zeroizes the master key
      derived = null;
      setPassword(""); // minimize the password's lifetime in memory
      await refreshActiveDays();
      markLoggedIn();
    } catch (err) {
      if (derived) zeroize(derived.masterKey, derived.authKey, derived.dataKey);
      vault.lock();
      Alert.alert("Sign in failed", err instanceof Error ? err.message : "unknown error");
    } finally {
      setBusy(false);
    }
  };

  return (
    <KeyboardAvoidingView style={styles.container} behavior={Platform.OS === "ios" ? "padding" : undefined}>
      <Text style={styles.title}>MindPattern</Text>
      <Text style={styles.subtitle}>Your patterns. Your keys. Nobody else's.</Text>
      <TextInput
        style={styles.input}
        placeholder="username"
        placeholderTextColor="#5c6370"
        autoCapitalize="none"
        value={username}
        onChangeText={setUsername}
      />
      <TextInput
        style={styles.input}
        placeholder="password"
        placeholderTextColor="#5c6370"
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={submit}
      />
      <TouchableOpacity style={styles.button} onPress={submit} disabled={busy}>
        {busy ? <ActivityIndicator color="#fff" /> : <Text style={styles.buttonText}>{mode === "login" ? "Sign in" : "Create account"}</Text>}
      </TouchableOpacity>
      <TouchableOpacity onPress={() => setMode(mode === "login" ? "register" : "login")}>
        <Text style={styles.switch}>{mode === "login" ? "New here? Create an account" : "Already have an account? Sign in"}</Text>
      </TouchableOpacity>
      {/* Crisis help needs no account and no network. */}
      <TouchableOpacity style={styles.helpButton} onPress={() => navigation.navigate("Crisis")}>
        <Text style={styles.helpText}>Need help now? Crisis resources</Text>
      </TouchableOpacity>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center", padding: 32, gap: 12, backgroundColor: "#0f1115" },
  title: { fontSize: 34, fontWeight: "700", color: "#e8eaf0", textAlign: "center" },
  subtitle: { fontSize: 14, color: "#8a91a3", textAlign: "center", marginBottom: 24 },
  input: { backgroundColor: "#1a1e26", color: "#e8eaf0", borderRadius: 10, padding: 14, fontSize: 16 },
  button: { backgroundColor: "#4f7cff", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 8 },
  buttonText: { color: "#fff", fontSize: 16, fontWeight: "600" },
  switch: { color: "#7f9bff", textAlign: "center", marginTop: 16 },
  helpButton: { backgroundColor: "#242a38", borderRadius: 10, padding: 16, alignItems: "center", marginTop: 24 },
  helpText: { color: "#7f9bff", fontSize: 14, fontWeight: "600" },
});
