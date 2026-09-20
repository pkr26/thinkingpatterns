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
 * PASSWORD POLICY: identical to the therapist portal (portal/src/views/
 * LoginView.tsx) so both clients share one contract — and this password
 * derives the MORE valuable key, the patient data key. Minimum 12
 * characters; at 12–15 characters, at least three of the four character
 * types. A 16+ character passphrase is accepted without symbol rules.
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
import { t as tr } from "../strings";

/** Calm, domain-aware copy for a failed sign-in/registration. */
function signInFailureCopy(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return tr("login.badCredentials");
    if (err.status === 409) return tr("login.usernameTaken");
  }
  return requestFailureCopy(err);
}

/** On-device strength heuristic: length + character variety. No zxcvbn, no
 *  network — just enough to nudge away from "password123". The returned
 *  label/hint are catalog lookups (rendered verbatim on screen). */
export function passwordStrength(password: string): { label: string; hint: string } {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 14) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  if (score <= 2) return { label: tr("login.strength.weak"), hint: tr("login.strengthWeakHint") };
  if (score <= 4) return { label: tr("login.strength.fair"), hint: tr("login.strengthFairHint") };
  return { label: tr("login.strength.strong"), hint: "" };
}

/**
 * Registration password policy — mirrors the portal's passwordPolicyError
 * exactly (same thresholds, same character classes). Returns "" when the
 * password is acceptable; otherwise calm copy for the alert.
 */
export function passwordPolicyError(password: string): string {
  if (password.length < 12) return tr("login.policyMin");
  const classes = [/[a-z]/.test(password), /[A-Z]/.test(password), /\d/.test(password), /[^A-Za-z0-9]/.test(password)]
    .filter(Boolean).length;
  if (password.length < 16 && classes < 3) {
    return tr("login.policyVariety");
  }
  return "";
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
      const policyError = passwordPolicyError(password);
      if (policyError) {
        Alert.alert(
          password.length < 12 ? tr("login.policyShortTitle") : tr("login.policyVarietyTitle"),
          policyError,
        );
        return;
      }
      if (password !== confirm) {
        Alert.alert(tr("login.mismatchTitle"), tr("login.mismatchBody"));
        return;
      }
    }
    setBusy(true);
    let derived: Keys | null = null;
    // L-65 (2026-09-20 audit): once api.register resolves, the ACCOUNT
    // EXISTS on the server no matter what happens next. A later failure
    // (session write, unlock proof, salt cache — typically a connection
    // drop mid-flow) used to surface as a generic "couldn't create
    // account", stranding the user on a register form whose retry would
    // now 409 "username taken". The failure copy says the honest next
    // step: switch to sign-in with the credentials that just worked.
    let accountCreated = false;
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
        accountCreated = true;
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
        mode === "register" && accountCreated
          ? tr("login.registerPartialTitle")
          : mode === "register"
            ? tr("login.registerFailedTitle")
            : tr("login.signInFailedTitle"),
        mode === "register" && accountCreated ? tr("login.registerPartialBody") : signInFailureCopy(err),
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
        {tr("login.subtitle")}
      </Text>
      <TextInput
        style={inputTheme(t)}
        placeholder={tr("login.usernamePlaceholder")}
        placeholderTextColor={t.colors.placeholder}
        autoCapitalize="none"
        value={username}
        onChangeText={setUsername}
        accessibilityLabel={tr("login.usernameA11y")}
        textContentType="username"
        autoComplete="username"
      />
      <TextInput
        style={inputTheme(t)}
        placeholder={tr("common.passwordPlaceholder")}
        placeholderTextColor={t.colors.placeholder}
        secureTextEntry
        value={password}
        onChangeText={setPassword}
        onSubmitEditing={submit}
        accessibilityLabel={tr("common.passwordA11y")}
        textContentType={mode === "register" ? "newPassword" : "password"}
        autoComplete={mode === "register" ? "new-password" : "current-password"}
      />
      {mode === "register" && (
        <TextInput
          style={inputTheme(t)}
          placeholder={tr("login.confirmPlaceholder")}
          placeholderTextColor={t.colors.placeholder}
          secureTextEntry
          value={confirm}
          onChangeText={setConfirm}
          onSubmitEditing={submit}
          accessibilityLabel={tr("login.confirmA11y")}
          textContentType="newPassword"
          autoComplete="new-password"
        />
      )}
      {strength && (
        <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }} accessibilityLiveRegion="polite">
          {`${tr("login.strength", { label: strength.label })}${strength.hint ? ` ${strength.hint}` : ""}`}
        </Text>
      )}
      {mismatch && (
        <Text style={{ color: t.colors.error, fontSize: t.type.meta.fontSize }} accessibilityRole="alert">
          {tr("login.mismatchInline")}
        </Text>
      )}
      {mode === "register" && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("login.policyHint")}
        </Text>
      )}
      {mode === "register" && (
        <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, lineHeight: 19 }}>
          {tr("login.noReset")}
        </Text>
      )}
      <PrimaryButton
        label={mode === "login" ? tr("login.signIn") : tr("login.createAccount")}
        onPress={submit}
        busy={busy}
      />
      <GhostButton
        label={mode === "login" ? tr("login.switchToRegister") : tr("login.switchToSignIn")}
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
