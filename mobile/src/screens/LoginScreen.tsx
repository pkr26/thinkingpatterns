/**
 * Onboarding / login. The password exists in component state for the minimum
 * time: keys are derived, the master key is zeroized, and only the auth key
 * ever crosses the network. The password itself is stored nowhere — on
 * failure every derived buffer is zeroized before the retry.
 *
 * REGISTRATION HONESTY (audit fix): there is NO password reset — a forgotten
 * password means permanent journal loss (zero-knowledge cuts both ways).
 * Registration says so in plain sight, asks for the password twice, and
 * shows a simple strength hint (length + variety heuristic, on-device only).
 *
 * Errors never leak raw server text: ApiError maps to calm copy by status.
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
import qcrypto from "react-native-quick-crypto";
import { api, ApiError } from "../api/client";
import { deriveKeysAsync } from "../crypto/MindPatternCrypto";
import type { Keys } from "../crypto/MindPatternCrypto";
import { zeroize } from "../crypto/kdf";
import { vault } from "../vault";
import { useSession } from "../store";
import { storeUnlockProof } from "../unlockProof";
import { queueOnboarding } from "../onboarding";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy } from "../components/errors";

/** Calm, domain-aware copy for a failed sign-in/registration. */
function signInFailureCopy(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return "That username or password didn't match.";
    if (err.status === 409) return "That username is already taken. Try another, or sign in instead.";
  }
  return requestFailureCopy(err);
}

/** On-device strength heuristic: length + character variety. No zxcvbn, no
 *  network — just enough to nudge away from "password123". */
export function passwordStrength(password: string): { label: "weak" | "fair" | "strong"; hint: string } {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  if (score <= 2) return { label: "weak", hint: "Longer is stronger — aim for a short sentence or several words." };
  if (score <= 4) return { label: "fair", hint: "Good start — more length or a symbol makes it stronger." };
  return { label: "strong", hint: "" };
}

export function LoginScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { refreshActiveDays, markLoggedIn } = useSession();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  // Stryker disable next-line StringLiteral: dead initializer — register mode is reachable only through the toggle (which clears confirm in the same batch) and login mode never reads confirm
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    const name = username.trim();
    if (!name || !password || busy) return;
    if (mode === "register") {
      if (password.length < 8) {
        Alert.alert("Password too short", "Use at least 8 characters — this password derives your encryption keys.");
        return;
      }
      if (password !== confirm) {
        Alert.alert("Passwords don't match", "Type the same password twice — there is no reset if it's lost.");
        return;
      }
    }
    setBusy(true);
    let derived: Keys | null = null;
    try {
      // Stryker disable next-line StringLiteral: dead initializer — both branches assign body.user_id before the only read at vault.unlock
    let verifiedUserId = "";
      if (mode === "register") {
        // Buffer.from() copies: quick-crypto's Buffer type differs from
        // node's in the .d.ts, but the bytes are identical.
        const salt = Buffer.from(qcrypto.randomBytes(16));
        // Async derivation: no 100–400ms JS-thread freeze mid-flow.
        derived = await deriveKeysAsync(password, salt);
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
        derived = await deriveKeysAsync(password, Buffer.from(saltB64, "base64"));
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
      setConfirm("");
      await refreshActiveDays();
      // A brand-new account routes through first-run onboarding (once — see
      // src/onboarding.ts); a plain login never does.
      if (mode === "register") queueOnboarding();
      markLoggedIn();
    } catch (err) {
      if (derived) zeroize(derived.masterKey, derived.authKey, derived.dataKey);
      vault.lock();
      Alert.alert(
        mode === "register" ? "Couldn't create account" : "Sign in failed",
        signInFailureCopy(err),
      );
    } finally {
      setBusy(false);
    }
  };

  const strength = mode === "register" && password.length > 0 ? passwordStrength(password) : null;
  // Stryker disable next-line ConditionalExpression: confirm.length > 0 implies register mode (the confirm field is register-only and every exit to login clears it), so the mode check is redundant — the same-line whole-condition mutant is killable and pinned in loginScreen.pins.test.tsx
  const mismatch = mode === "register" && confirm.length > 0 && confirm !== password;

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
        MindPattern
      </Text>
      <Text style={[styles.subtitle, { color: t.colors.muted, fontSize: 14 }]}>
        Your patterns, from your words. Encrypted on this device.
      </Text>
      <TextInput
        style={inputTheme(t)}
        placeholder="username"
        placeholderTextColor={t.colors.placeholder}
        autoCapitalize="none"
        value={username}
        onChangeText={setUsername}
        accessibilityLabel="Username"
        textContentType="username"
        autoComplete="username"
      />
      <TextInput
        style={inputTheme(t)}
        placeholder="password"
        placeholderTextColor={t.colors.placeholder}
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={submit}
        accessibilityLabel="Password"
        textContentType={mode === "register" ? "newPassword" : "password"}
        autoComplete={mode === "register" ? "new-password" : "current-password"}
      />
      {mode === "register" && (
        <TextInput
          style={inputTheme(t)}
          placeholder="confirm password"
          placeholderTextColor={t.colors.placeholder}
          secureTextEntry
          value={confirm}
          onChangeText={setConfirm}
          onSubmitEditing={submit}
          accessibilityLabel="Confirm password"
          textContentType="newPassword"
          autoComplete="new-password"
        />
      )}
      {strength && (
        <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }} accessibilityLiveRegion="polite">
          Password strength: {strength.label}.{strength.hint ? ` ${strength.hint}` : ""}
        </Text>
      )}
      {mismatch && (
        <Text style={{ color: t.colors.error, fontSize: t.type.meta.fontSize }} accessibilityRole="alert">
          Passwords don't match.
        </Text>
      )}
      {mode === "register" && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          There is no password reset. If you forget this password, no one — including us — can
          recover your journal.
        </Text>
      )}
      <PrimaryButton
        label={mode === "login" ? "Sign in" : "Create account"}
        onPress={submit}
        busy={busy}
      />
      <GhostButton
        label={mode === "login" ? "New here? Create an account" : "Already have an account? Sign in"}
        onPress={() => {
          setMode(mode === "login" ? "register" : "login");
          setConfirm("");
        }}
      />
      {/* Crisis help needs no account and no network. */}
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const inputTheme = (t: ReturnType<typeof useTheme>) => ({
  backgroundColor: t.colors.card,
  color: t.colors.text,
  borderRadius: t.radius.md,
  padding: 14,
  fontSize: 16,
});

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center" },
  title: { fontSize: 34, fontWeight: "700", textAlign: "center" },
  subtitle: { textAlign: "center", marginBottom: 24 },
});
