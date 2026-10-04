/**
 * Account recovery with the recovery key (wave 3, 2026-09-30).
 *
 * Reached from the login screen ("Forgot password? Use a recovery key").
 * The user proves the username + recovery key, chooses a NEW password,
 * and one button runs the whole sequence (recoverAccountWithKey): the
 * journal's data key is recovered, the new password takes over
 * server-side, the local caches follow, and the vault unlocks — every
 * word intact. Calm copy throughout: this screen is used on a bad day.
 */
import React, { useEffect, useRef, useState } from "react";
import {
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";

import { CrisisHelpButton, GhostButton, PrimaryButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { useTheme } from "../theme";
import { t as tr } from "../strings";
import { vault } from "../vault";
import { useSession } from "../store";
import { recoverAccountWithKey } from "../recoveryFlow";
import { passwordPolicyError } from "./LoginScreen";
import { localWriteScopeEpoch } from "../localWriteGuard";
import { ApiError } from "../api/client";

export function RecoveryScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { markLoggedIn } = useSession();
  const [username, setUsername] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [legacyKit, setLegacyKit] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("neutral");
  const [done, setDone] = useState(false);
  const mounted = useRef(true), attempt = useRef(0), submitting = useRef(false);
  const navigationTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => { mounted.current = true; return () => {
    mounted.current = false; attempt.current++;
    if (navigationTimer.current) clearTimeout(navigationTimer.current);
  }; }, []);

  const showStatus = (message: string, tone: InlineStatusTone) => {
    setStatusTone(tone);
    setStatus(message);
  };

  const run = async () => {
    if (busy || done || submitting.current) return;
    if (!username.trim() || !recoveryKey.trim()) {
      showStatus(tr("recovery.missingFields"), "neutral");
      return;
    }
    // 2026-10-01 audit LOW: the FULL registration policy (variety,
    // common-word, sequence checks — LoginScreen's passwordPolicyError),
    // not the old length-only gate a recovery-set password slipped under.
    const policy = passwordPolicyError(newPassword);
    if (policy) {
      showStatus(policy, "neutral");
      return;
    }
    if (newPassword !== confirm) {
      showStatus(tr("recovery.passwordMismatch"), "neutral");
      return;
    }
    setBusy(true);
    setStatus(null);
    submitting.current = true; const id = ++attempt.current;
    const ownsAttempt = () => mounted.current && attempt.current === id;
    let ownedKey: Buffer | null = null;
    try {
      const outcome = await recoverAccountWithKey(username, recoveryKey, newPassword, legacyKit ? "v1" : "v2", { stillCurrent: ownsAttempt });
      ownedKey = outcome.dataKey;
      if (!ownsAttempt() || outcome.ownershipEpoch !== localWriteScopeEpoch()) return;
      const epoch = localWriteScopeEpoch();
      vault.unlock(
        {
          masterKey: Buffer.alloc(32), // placeholder — zeroized by unlock
          authKey: Buffer.alloc(32), // the new password's auth key is re-derived on next login
          dataKey: outcome.dataKey,
        },
        outcome.userId,
        // 2026-10-01 audit M7: the auth-key slot holds a placeholder, so
        // the vault must NOT claim the password is known — reauth used to
        // compare every later password against zeros ("Wrong password"
        // on account deletion, consents, biometric enable, key upgrade
        // and password rotation until a full sign-out/in).
        { authKeyKnown: false },
      );
      ownedKey = null;
      markLoggedIn(); // the vault subscription flips `unlocked` on unlock
      setDone(true);
      setRecoveryKey(""); setNewPassword(""); setConfirm("");
      showStatus(tr("recovery.doneBody") + (outcome.localCacheReady === false ? "\n" + tr("recovery.onlineUnlockRequired") : ""), "ok");
      navigationTimer.current = setTimeout(() => { if (ownsAttempt() && epoch === localWriteScopeEpoch()) navigation.navigate("Entry"); }, 900);
    } catch (err) {
      if (!ownsAttempt()) return;
      showStatus(
        err instanceof ApiError
          ? tr("recovery.failedBody")
          : err instanceof Error && err.message
            ? err.message
            : tr("recovery.failedBody"),
        "neutral",
      );
    } finally {
      ownedKey?.fill(0);
      if (attempt.current === id) submitting.current = false;
      if (ownsAttempt()) setBusy(false);
    }
  };

  return (
    <KeyboardAvoidingView
      style={{ flex: 1 }}
      behavior={Platform.OS === "ios" ? "padding" : undefined}
    >
      <ScrollView
        style={[styles.container, { backgroundColor: t.colors.bg }]}
        contentContainerStyle={{ padding: 20, gap: 16 }}
        keyboardDismissMode="on-drag"
        keyboardShouldPersistTaps="handled"
      >
        <View style={{ gap: 6 }}>
          <Text style={{ color: t.colors.body, fontSize: t.type.display.fontSize, fontWeight: "700" }}>
            {tr("recovery.title")}
          </Text>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {tr("recovery.subtitle")}
          </Text>
        </View>
        <View style={{ gap: 4 }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("recovery.usernameLabel")}
          </Text>
          <TextInput
            value={username}
            onChangeText={setUsername}
            autoCapitalize="none"
            autoCorrect={false}
            spellCheck={false}
            textContentType="none"
            accessibilityLabel={tr("recovery.usernameLabel")}
            style={[styles.input, { backgroundColor: t.colors.card, color: t.colors.body, borderColor: t.colors.border }]}
          />
        </View>
        <View style={{ gap: 4 }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("recovery.keyLabel")}
          </Text>
          <TextInput
            value={recoveryKey}
            onChangeText={setRecoveryKey}
            autoCapitalize="none"
            autoCorrect={false}
            spellCheck={false}
            multiline
            style={[styles.input, styles.keyInput, { backgroundColor: t.colors.card, color: t.colors.body, borderColor: t.colors.border }]}
            accessibilityLabel={tr("recovery.keyLabel")}
          />
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("recovery.keyHint")}
          </Text>
          <GhostButton label={tr(legacyKit ? "recovery.legacySelected" : "recovery.useLegacy")} onPress={() => setLegacyKit(!legacyKit)} disabled={busy} />
        </View>
        <View style={{ gap: 4 }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("recovery.newPasswordLabel")}
          </Text>
          <TextInput
            value={newPassword}
            onChangeText={setNewPassword}
            secureTextEntry
            autoCapitalize="none"
            textContentType="newPassword"
            accessibilityLabel={tr("recovery.newPasswordLabel")}
            style={[styles.input, { backgroundColor: t.colors.card, color: t.colors.body, borderColor: t.colors.border }]}
          />
        </View>
        <View style={{ gap: 4 }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("recovery.confirmLabel")}
          </Text>
          <TextInput
            value={confirm}
            onChangeText={setConfirm}
            secureTextEntry
            autoCapitalize="none"
            textContentType="newPassword"
            accessibilityLabel={tr("recovery.confirmLabel")}
            style={[styles.input, { backgroundColor: t.colors.card, color: t.colors.body, borderColor: t.colors.border }]}
          />
        </View>
        <InlineStatus message={status} tone={statusTone} />
        <PrimaryButton
          label={busy ? tr("common.working") : tr("recovery.action")}
          onPress={() => void run()}
          disabled={busy || done}
        />
        <GhostButton
          label={tr("recovery.backToLogin")}
          onPress={() => navigation.navigate("Login")}
          disabled={busy}
        />
        <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  input: {
    borderRadius: 10,
    borderWidth: 1,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 15,
    minHeight: 44,
  },
  keyInput: { minHeight: 72, textAlignVertical: "top" },
});
