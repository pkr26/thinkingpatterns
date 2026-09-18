/**
 * Settings: third-party analysis consent, sync recovery, ciphertext export,
 * re-authenticated hard delete, sign out — with the developer-only server
 * URL tucked into an "Advanced" section at the bottom (a consumer screen
 * must not lead with it) and an honest About section.
 *
 * DESTRUCTIVE ACTIONS RE-AUTHENTICATE FOR REAL: "confirm with your sign-in
 * key" used to read the authKey from the unlocked vault — two taps on an
 * unattended phone deleted the journal. The delete flow and the LLM
 * consent toggle now demand the PASSWORD, re-derive the key, and compare
 * it to the vault's key before anything is sent (see reauth.ts). Failures
 * branch honestly: a 403 verifier rejection means "that password didn't
 * match — try again" (the card stays up); a 401 means the session died
 * (the vault is already locked; the only path is re-unlock).
 *
 * EXPORT SAFETY: full-account export is intentionally unavailable until a
 * reviewed native streaming-to-file component exists; buffering a capped
 * account in JS before invoking Share is not safe on a phone.
 *
 * RECOVERY: entries the server permanently rejected are preserved in the
 * offline queue's rejected store (never destroyed); a "Recovered entries"
 * row appears when any exist and requeues them in one tap.
 */
import React, { useEffect, useState } from "react";
import { Alert, ScrollView, StyleSheet, Switch, Text, TextInput, TouchableOpacity, View } from "react-native";
import { api, getBaseUrl, parseServerUrl, setBaseUrl } from "../api/client";
import { ThemeMode, themeStorageKey, useSetThemeMode } from "../theme";
import { hapticsEnabled, loadHapticsSetting, setHapticsEnabled } from "../haptics";
import { reminderCapability, biometricCapability } from "../nativeFeatures";
import { vault } from "../vault";
import { useSession } from "../store";
import { verifyPasswordForVault, isVerificationFailedError, isSessionExpiredError } from "../reauth";
import {
  rejectedEntryCount,
  requeueRejected,
  quarantinedQueueExists,
  flushQueue,
  hasLegacyQueueRecovery,
} from "../offlineQueue";
import { clearKeyShipConsent } from "../components/keyConsent";
import { clearOnboardingSeen } from "../onboarding";
import { clearCrisisDialogStamp } from "../crisisDialog";
import { clearFeedback } from "../questionFeedback";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy, calmFallbackCopy } from "../components/errors";

/** Keep in sync with package.json; shown in About (the server reports its
 *  own version via /api/meta). */
const APP_VERSION = "1.0.0";

type PendingAction = { kind: "llm"; enabled: boolean } | { kind: "delete" } | null;

export function SettingsScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { signOut, touchActivity } = useSession();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [llmAvailable, setLlmAvailable] = useState(false);
  const [sharingAvailable, setSharingAvailable] = useState(false);
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [serverVersion, setServerVersion] = useState<string | null>(null);
  const [rejectedCount, setRejectedCount] = useState(0);
  const [quarantined, setQuarantined] = useState(false);
  const [legacyQueueRecovery, setLegacyQueueRecovery] = useState(false);
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");

  React.useEffect(() => {
    getBaseUrl().then(setUrl);
    api.meta()
      .then((m) => {
        // Stryker disable next-line OptionalChaining: a null/undefined meta makes m.llm_available throw inside this .then, and the chained .catch(() => {}) swallows it — llmAvailable stays false exactly as with the chain
        setLlmAvailable(Boolean(m?.llm_available));
        // Sharing is fail-closed: only a server that explicitly advertises
        // verified-clinician sharing may expose a pairing flow.
        setSharingAvailable(m?.sharing_available === true);
        // Stryker disable next-line OptionalChaining: with m null/undefined, typeof m.version throws into the same .catch(() => {}) — no observable difference (the typeof guard itself stays live)
        if (typeof m?.version === "string") setServerVersion(m.version);
      })
      .catch(() => {});
    // Stryker disable next-line OptionalChaining: an undefined consent payload makes c.enabled throw into the .catch(() => {}) — setLlmEnabled is never reached either way
    api.getLlmConsent().then((c) => setLlmEnabled(Boolean(c?.enabled))).catch(() => {});
    // Sync-recovery surfaces are scoped to the authenticated account and
    // configured server; no account can learn another's queued metadata.
    api.getUserId().then((userId) => {
      if (!userId) return;
      rejectedEntryCount(userId).then(setRejectedCount).catch(() => {});
      quarantinedQueueExists(userId).then(setQuarantined).catch(() => {});
    }).catch(() => {});
    hasLegacyQueueRecovery().then(setLegacyQueueRecovery).catch(() => {});
  }, // Stryker disable next-line ArrayDeclaration: [] and ["Stryker was here"] are both referentially constant — the mount effect runs exactly once either way (test seam)
     []);

  const saveUrl = async () => {
    const parsed = parseServerUrl(url);
    if (!parsed) {
      Alert.alert("Invalid URL", "Enter a full URL like https://your-server:8000");
      return;
    }
    const error = await setBaseUrl(parsed.url);
    if (error) Alert.alert("Could not save server", error);
    else Alert.alert("Saved", "Server URL updated. Changing server origins signs this device out to protect your session.");
  };

  /** One tap: move rejected entries back into the live queue and flush.
   *  Whatever doesn't fit stays safely in the rejected store. */
  const recoverRejected = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const userId = await api.getUserId();
      if (!userId) {
        Alert.alert("Sign in required", "Sign in again before retrying saved entries.");
        return;
      }
      const moved = await requeueRejected(userId);
      if (userId) await flushQueue(userId).catch(() => {}); // offline: next flush handles it
      const left = await rejectedEntryCount(userId);
      setRejectedCount(left);
      Alert.alert(
        "Recovered entries",
        moved > 0
          ? `${moved} ${moved === 1 ? "entry" : "entries"} moved back into the sync queue — ${left === 0 ? "they upload on the next sync." : `${left} still waiting.`}`
          : "Nothing could be moved yet — the entries stay safely stored on this device.",
      );
    } catch {
      Alert.alert("Could not retry", "The saved entries are still safe on this device.");
    } finally {
      setBusy(false);
    }
  };

  /** Destructive flows land here FIRST — the actual action only runs after
   *  the typed password re-derives the vault's own auth key. */
  const confirmWithPassword = async () => {
    if (!pending || busy || !password) return;
    setBusy(true);
    // done: the flow concluded (success or unrecoverable) — clear the card.
    // retry: the password itself was rejected — the card STAYS UP, the fix
    // is one corrected password away.
    const done = () => { setBusy(false); setPending(null); setPassword(""); };
    const retry = () => { setBusy(false); setPassword(""); };
    try {
      const reauth = await verifyPasswordForVault(password);
      if (!reauth.ok) {
        const messages = {
          locked: "The vault is locked — unlock again first.",
          "no-account": "No saved account on this device — sign in again.",
          "wrong-password": "Wrong password.",
          offline: "Cannot verify your password offline right now — try again when online.",
        } as const;
        Alert.alert("Could not verify", messages[reauth.reason]);
        retry();
        return;
      }
      if (pending.kind === "llm") {
        const result = await api.setLlmConsent(pending.enabled, reauth.verifierB64);
        setLlmEnabled(result.enabled);
      } else {
        await deleteAccountOnServer(reauth.verifierB64);
      }
      done();
    } catch (err) {
      if (isVerificationFailedError(err)) {
        // 403: the verifier itself was rejected — the typed password no
        // longer matches. NOT a session death: stay on the card for a retry.
        Alert.alert("That password didn't match", "Check it and try again — nothing was changed.");
        retry();
        return;
      }
      if (isSessionExpiredError(err)) {
        // 401: the client hook has already locked the vault; the stack is
        // about to swap to Unlock. Say why.
        Alert.alert("Session expired", "Please unlock again.");
      } else {
        Alert.alert("Could not complete", calmFallbackCopy(err, "Something went wrong — try again."));
      }
      done();
    }
  };

  const deleteAccountOnServer = async (verifierB64: string) => {
    try {
      const userId = await api.getUserId();
      const username = await api.getUsername();
      await api.deleteAccount(verifierB64);
      vault.lock();
      // Local cleanup is attempted in full, but a failure here must NOT be
      // reported as a failed delete (the server data is already gone and a
      // retry can never work) — the user is told the truth instead.
      try {
        const { clearQueue } = await import("../offlineQueue");
        const { clearMoodLog } = await import("../moodLog");
        const { clearRecomputeStamp } = await import("../brainSync");
        const { clearUnlockProof } = await import("../unlockProof");
        if (userId) await clearQueue(userId);
        if (userId) {
          await clearMoodLog(userId);
          await clearRecomputeStamp(userId);
          await clearUnlockProof(userId);
          await clearKeyShipConsent(userId); // the consent flag dies with its account
          await clearOnboardingSeen(userId); // so does the onboarding acknowledgment
          await clearCrisisDialogStamp(userId); // and the dialog-throttle stamp
          await clearFeedback(userId); // and the pending question-feedback taps
        }
        if (username) await api.clearCachedSalt(username);
      } catch {
        // Reported in the success dialog below.
      }
      await signOut(); // revokes tokens, clears the session
      Alert.alert(
        "Deleted",
        "Your account and data were deleted from the server. If anything failed to clear on this device, reinstalling the app removes the remnants.",
      );
    } catch (err) {
      // The server still holds the account — keep the local session intact
      // so the user can retry instead of believing it worked.
      if (isVerificationFailedError(err)) {
        Alert.alert("Delete failed", "The server didn't accept that password. Nothing was deleted — check it and try again.");
      } else if (isSessionExpiredError(err)) {
        Alert.alert("Delete failed", "Session expired — please unlock again. Nothing was deleted.");
      } else {
        Alert.alert("Delete failed", calmFallbackCopy(err, "Something went wrong — try again."));
      }
    }
  };

  /** Full exports deliberately fail closed in this build. The API streams
   * ciphertext, but React Native's stock fetch/Share path buffers it into a
   * JS string first; an account near the server cap could exhaust memory and
   * expose plaintext in a share intent. Re-enable only with a reviewed
   * native streaming-to-file implementation. */
  const explainExportUnavailable = () => {
    Alert.alert(
      "Export unavailable in this build",
      "To protect large journals, this app needs its verified secure file-export component before it can create an export. Your entries remain safely on the server and this device.",
    );
  };

  const deleteEverything = () => {
    Alert.alert(
      "Delete everything?",
      "All entries, patterns and your account will be permanently deleted from the server. " +
        "Your local encrypted queue is also wiped. This cannot be undone. You will be asked for your password.",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Continue",
          style: "destructive",
          onPress: () =>
            Alert.alert("Final confirmation", "Deleting is irreversible. You will be asked for your password next.", [
              { text: "Cancel", style: "cancel" },
              // The password prompt below IS the real confirmation.
              { text: "Continue to password", style: "destructive", onPress: () => setPending({ kind: "delete" }) },
            ]),
        },
      ],
    );
  };

  // Appearance state (2026-09-17). The radio starts at the provider's own
  // default and takes the PERSISTED preference from storage below — never a
  // value derived from the active palette (a "system" preference on a
  // dark-OS device must not select "Dark" as if it were the override).
  const setThemeMode = useSetThemeMode();
  const [themeMode, setThemeModeState] = useState<ThemeMode>("system");
  const [haptics, setHaptics] = useState(true);
  const [reminders] = useState(reminderCapability());
  const [biometrics] = useState(biometricCapability());
  React.useEffect(() => {
    void loadHapticsSetting().then(setHaptics);
  }, []);
  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const AsyncStorage = (await import("@react-native-async-storage/async-storage")).default;
        const stored = await AsyncStorage.getItem(themeStorageKey());
        if (!cancelled && (stored === "dark" || stored === "light" || stored === "system")) {
          setThemeModeState(stored);
        }
      } catch {
        /* non-sensitive preference; default stands */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const themed = {
    label: { color: t.colors.muted, fontSize: 12, fontWeight: "700" as const, letterSpacing: 1, marginTop: 8 },
    input: {
      backgroundColor: t.colors.card,
      color: t.colors.text,
      borderRadius: t.radius.md,
      padding: 14,
      fontSize: 15,
    },
    rowText: { color: t.colors.body, fontSize: 13, flex: 1, lineHeight: 18 },
    footnote: { color: t.colors.muted, fontSize: 12, lineHeight: 18 },
  };

  return (
    <ScrollView
      style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxl, gap: 14 }]}
      onTouchStart={touchActivity}
      contentContainerStyle={{ paddingBottom: t.spacing.xxxl }}
    >
      {/* Crisis help: one tap from here, works offline (see CrisisScreen). */}
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />

      {rejectedCount > 0 && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
          <Text style={themed.rowText}>
            {rejectedCount} {rejectedCount === 1 ? "entry" : "entries"} couldn't sync and{" "}
            {rejectedCount === 1 ? "was" : "were"} kept safely on this device.
          </Text>
          <GhostButton
            label="Try syncing them again"
            center={false}
            onPress={recoverRejected}
            disabled={busy}
            accessibilityLabel="Try syncing the recovered entries again"
          />
        </View>
      )}
      {quarantined && (
        <Text style={themed.footnote}>
          A damaged piece of the offline queue was set aside instead of deleted. New entries sync
          normally.
        </Text>
      )}
      {legacyQueueRecovery && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderColor: t.colors.border, borderWidth: 1, borderRadius: t.radius.lg }]} accessibilityRole="alert">
          <Text style={{ color: t.colors.text, fontSize: t.type.title.fontSize, fontWeight: "700" }}>Older offline entries need recovery</Text>
          <Text style={themed.footnote}>
            This update protected unsent encrypted entries from being sent to the wrong server. They remain on this device but cannot be safely assigned automatically; contact support before clearing app data.
          </Text>
        </View>
      )}

      {llmAvailable && (
        <>
          <Text style={themed.label}>Third-party AI analysis</Text>
          <View style={[styles.row, { backgroundColor: t.colors.card, borderRadius: t.radius.md }]}>
            <Text style={themed.rowText}>
              Allow sending your (decrypted) entries to an external AI service for pattern analysis.
              Off by default; needs your password to change.
            </Text>
            <Switch
              value={llmEnabled}
              disabled={busy}
              onValueChange={(enabled) => setPending({ kind: "llm", enabled })}
              trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
              accessibilityLabel="Allow third-party AI analysis"
              accessibilityState={{ checked: llmEnabled, disabled: busy }}
            />
          </View>
        </>
      )}
      {pending && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>
            {pending.kind === "delete"
              ? "Enter your password to delete everything"
              : `Enter your password to ${pending.enabled ? "enable" : "disable"} third-party AI analysis`}
          </Text>
          <TextInput
            style={themed.input}
            placeholder="password"
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={password}
            onChangeText={setPassword}
            accessibilityLabel="Password confirmation"
            textContentType="password"
          />
          <PrimaryButton
            label={busy ? "Verifying…" : "Confirm with password"}
            onPress={confirmWithPassword}
            disabled={!password}
            danger={pending.kind === "delete"}
            accessibilityLabel="Confirm with password"
          />
          <GhostButton
            label="Cancel"
            disabled={busy}
            onPress={() => { setPending(null); setPassword(""); }}
          />
        </View>
      )}

      {/* Appearance & feel (2026-09-17): theme override, haptics, and the
          native-feature seams (reminders/biometrics light up when their
          native modules are linked — see src/nativeFeatures.ts). */}
      <Text style={themed.label}>APPEARANCE</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <View style={{ flexDirection: "row", gap: 8 }}>
          {(["system", "dark", "light"] as ThemeMode[]).map((mode) => (
            <TouchableOpacity
              key={mode}
              style={[
                styles.moodOptionLike,
                {
                  backgroundColor: themeMode === mode ? t.colors.primary : t.colors.cardDeep,
                  borderRadius: t.radius.md,
                  minHeight: 40,
                },
              ]}
              onPress={() => {
                touchActivity();
                setThemeModeState(mode);
                setThemeMode(mode);
              }}
              accessibilityRole="radio"
              accessibilityState={{ selected: themeMode === mode }}
              accessibilityLabel={`Theme: ${mode}`}
            >
              <Text style={{ color: themeMode === mode ? t.colors.onPrimary : t.colors.body, fontSize: 13 }}>
                {mode === "system" ? "System" : mode === "dark" ? "Dark" : "Light"}
              </Text>
            </TouchableOpacity>
          ))}
        </View>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
          <Text style={themed.rowText}>Quiet haptics on taps and saves</Text>
          <Switch
            value={haptics}
            onValueChange={(on) => {
              touchActivity();
              setHaptics(on);
              void setHapticsEnabled(on);
            }}
            accessibilityLabel="Haptics"
          />
        </View>
        {!reminders.available && (
          <Text style={themed.footnote}>
            Daily reminders will appear here once the notification module is linked in the app build.
          </Text>
        )}
        {!biometrics.available && (
          <Text style={themed.footnote}>
            Face/fingerprint unlock will appear here once the biometric module is linked in the app build.
          </Text>
        )}
      </View>

      {sharingAvailable ? (
        <GhostButton
          label="Share with my therapist"
          center={false}
          onPress={() => navigation.navigate("TherapistShare")}
          accessibilityLabel="Share your entries and patterns with a therapist"
        />
      ) : (
        <Text style={themed.footnote}>
          Therapist sharing is not available on this server. It stays disabled until verified clinician enrollment is configured.
        </Text>
      )}
      <GhostButton
        label="Why export is unavailable"
        center={false}
        onPress={explainExportUnavailable}
        accessibilityLabel="Why export is unavailable in this build"
      />
      <PrimaryButton label="Delete my account and data" onPress={deleteEverything} disabled={busy} danger />
      <GhostButton
        label="Sign out"
        onPress={async () => { vault.lock(); await signOut(); navigation.popToTop(); }}
      />

      <Text style={themed.label}>About</Text>
      <Text style={themed.footnote}>
        MindPattern {APP_VERSION}
        {serverVersion ? ` · server ${serverVersion}` : ""}. Everything you write is encrypted on
        this device before it leaves. The one exception — pattern analysis — runs in a single-use
        session you start yourself. No advice, no diagnosis, ever.
      </Text>
      <GhostButton
        label="Privacy policy"
        center={false}
        onPress={() => navigation.navigate("Privacy")}
        accessibilityLabel="Read the privacy policy"
      />

      <Text style={themed.label}>Advanced</Text>
      <Text style={themed.footnote}>Only change this if you run your own server.</Text>
      <TextInput
        style={themed.input}
        value={url}
        onChangeText={setUrl}
        autoCapitalize="none"
        placeholder="https://your-server:8000"
        placeholderTextColor={t.colors.placeholder}
        accessibilityLabel="Server URL"
        textContentType="URL"
        autoComplete="off"
      />
      <PrimaryButton label="Save server URL" onPress={saveUrl} disabled={busy} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  card: { padding: 16, gap: 8 },
  moodOptionLike: { flex: 1, alignItems: "center", justifyContent: "center" },
  row: { flexDirection: "row", alignItems: "center", gap: 12, padding: 14 },
  reauthCard: { padding: 16, gap: 12 },
  reauthTitle: { fontSize: 15, fontWeight: "600", lineHeight: 20 },
});
