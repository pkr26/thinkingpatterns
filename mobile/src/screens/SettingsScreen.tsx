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
import { cancelDailyReminder, reminderCapability } from "../nativeFeatures";
import { getReminderPrefs, setReminderEnabled, setReminderTime, clearReminderPrefs } from "../reminders";
import { syncReminderSchedule } from "../reminderSync";
import {
  clearMoodMirrorPref,
  ensureStateOfMindWriteAccess,
  getMoodMirrorPref,
  healthKitCapability,
  setMoodMirrorPref,
} from "../healthkit";
import {
  biometricsSupported,
  disableBiometricUnlock,
  enableBiometricUnlock,
  hasBiometricUnlock,
} from "../biometricUnlock";
import { vault } from "../vault";
import { useSession } from "../store";
import { verifyPasswordForVault, isVerificationFailedError, isSessionExpiredError } from "../reauth";
import { rotatePassword } from "../rotation";
import { passwordPolicyError } from "./LoginScreen";
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
import { clearThresholdNotice } from "../thresholdNotice";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy, calmFallbackCopy } from "../components/errors";
import { t as tr } from "../strings";

/** Keep in sync with package.json; shown in About (the server reports its
 *  own version via /api/meta). */
const APP_VERSION = "1.0.0";

/** The offered reminder times — an evening default, never a morning alarm.
 *  A custom stored time appears as its own extra chip. Labels resolve at
 *  module load (the app locale is resolved once at startup). */
const REMINDER_PRESETS: readonly { label: string; hour: number; minute: number }[] = [
  { label: tr("settings.reminderMorning"), hour: 9, minute: 0 },
  { label: tr("settings.reminderMidday"), hour: 12, minute: 0 },
  { label: tr("settings.reminderEvening"), hour: 20, minute: 0 },
];

type PendingAction =
  | { kind: "llm"; enabled: boolean }
  | { kind: "delete" }
  // M-4 (2026-09-20): enabling the biometric wrap persists the data key in
  // the Keychain indefinitely — the same standing as grant/delete, so it
  // takes the same typed-password card instead of one confirm tap.
  | { kind: "bio" }
  | null;

export function SettingsScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { signOut, touchActivity } = useSession();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [llmAvailable, setLlmAvailable] = useState(false);
  // null = the server could not be reached, so availability is UNKNOWN —
  // a very different message from an authoritative "disabled by this
  // server". Confusing the two erodes trust in a mental-health app.
  const [sharingAvailable, setSharingAvailable] = useState<boolean | null>(null);
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [serverVersion, setServerVersion] = useState<string | null>(null);
  const [rejectedCount, setRejectedCount] = useState(0);
  const [quarantined, setQuarantined] = useState(false);
  const [legacyQueueRecovery, setLegacyQueueRecovery] = useState(false);
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");
  // H-1/M-3 (2026-09-20): the change-password (rotation) card. Two fields —
  // the CURRENT password (the card's usual reauth field) and the new one.
  const [showRotate, setShowRotate] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  React.useEffect(() => {
    getBaseUrl().then(setUrl);
    api.meta()
      .then((m) => {
        // Stryker disable next-line OptionalChaining: a null/undefined meta makes m.llm_available throw inside this .then, and the chained .catch(() => {}) swallows it — llmAvailable stays false exactly as with the chain
        setLlmAvailable(Boolean(m?.llm_available));
        // Sharing is fail-closed: only a server that explicitly advertises
        // verified-clinician sharing may expose a pairing flow. On success
        // the answer is authoritative; a failure leaves the state UNKNOWN
        // (null) so the copy below never blames the server for being
        // unreachable.
        setSharingAvailable(m?.sharing_available === true);
        // Stryker disable next-line OptionalChaining: with m null/undefined, typeof m.version throws into the same .catch(() => {}) — no observable difference (the typeof guard itself stays live)
        if (typeof m?.version === "string") setServerVersion(m.version);
      })
      .catch(() => setSharingAvailable(null));
    // Stryker disable next-line OptionalChaining: an undefined consent payload makes c.enabled throw into the .catch(() => {}) — setLlmEnabled is never reached either way
    api.getLlmConsent().then((c) => setLlmEnabled(Boolean(c?.enabled))).catch(() => {});
    // Sync-recovery surfaces are scoped to the authenticated account and
    // configured server; no account can learn another's queued metadata.
    api.getUserId().then((userId) => {
      if (!userId) return;
      rejectedEntryCount(userId).then(setRejectedCount).catch(() => {});
      quarantinedQueueExists(userId).then(setQuarantined).catch(() => {});
      // The reminder preference (non-sensitive, per account) and the
      // biometric-wrap existence (quiet Keychain read, never prompts).
      getReminderPrefs(userId)
        .then((prefs) => {
          setReminderOn(prefs.enabled);
          setReminderTimeState({ hour: prefs.hour, minute: prefs.minute });
        })
        .catch(() => {});
      // The Health mirror opt-in (non-sensitive, per account) — the
      // preference reads back even while the Health module is absent.
      getMoodMirrorPref(userId).then(setMirrorHealthOn).catch(() => {});
      hasBiometricUnlock(userId).then(setBioEnabled).catch(() => {});
    }).catch(() => {});
    hasLegacyQueueRecovery().then(setLegacyQueueRecovery).catch(() => {});
    biometricsSupported().then(setBioSupported).catch(() => {});
  }, // Stryker disable next-line ArrayDeclaration: [] and ["Stryker was here"] are both referentially constant — the mount effect runs exactly once either way (test seam)
     []);

  const saveUrl = async () => {
    const parsed = parseServerUrl(url);
    if (!parsed) {
      Alert.alert(tr("settings.invalidUrlTitle"), tr("settings.invalidUrlBody"));
      return;
    }
    const error = await setBaseUrl(parsed.url);
    if (error) Alert.alert(tr("settings.couldNotSaveServerTitle"), error);
    else Alert.alert(tr("settings.serverSavedTitle"), tr("settings.serverSavedBody"));
  };

  /** One tap: move rejected entries back into the live queue and flush.
   *  Whatever doesn't fit stays safely in the rejected store. */
  const recoverRejected = async () => {
    if (busy) return;
    setBusy(true);
    try {
      const userId = await api.getUserId();
      if (!userId) {
        Alert.alert(tr("settings.signInRequiredTitle"), tr("settings.signInRequiredBody"));
        return;
      }
      const moved = await requeueRejected(userId);
      if (userId) await flushQueue(userId).catch(() => {}); // offline: next flush handles it
      const left = await rejectedEntryCount(userId);
      setRejectedCount(left);
      Alert.alert(
        tr("settings.recoveredTitle"),
        moved > 0
          ? tr("settings.recoveredMoved", {
              count: moved,
              unit: tr(moved === 1 ? "history.entryWord" : "history.entryWordPlural"),
              rest:
                left === 0
                  ? tr("settings.recoveredUploadNext")
                  : tr("settings.recoveredStillWaiting", { count: left }),
            })
          : tr("settings.recoveredNone"),
      );
    } catch {
      Alert.alert(tr("settings.couldNotRetryTitle"), tr("settings.couldNotRetryBody"));
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
          locked: tr("common.reauthLocked"),
          "no-account": tr("common.reauthNoAccount"),
          "wrong-password": tr("common.wrongPassword"),
          offline: tr("common.reauthOffline"),
        } as const;
        Alert.alert(tr("common.couldNotVerifyTitle"), messages[reauth.reason]);
        retry();
        return;
      }
      if (pending.kind === "llm") {
        const result = await api.setLlmConsent(pending.enabled, reauth.verifierB64);
        setLlmEnabled(result.enabled);
      } else if (pending.kind === "bio") {
        // The password proof just ran: enabling the biometric wrap now
        // proves the enabler knows the password, not merely that they hold
        // the foregrounded unlocked session (M-4).
        const userId = await api.getUserId().catch(() => null);
        if (!userId) {
          Alert.alert(tr("common.reauthNoAccount"));
          retry();
          return;
        }
        await enableBiometricWrap(userId);
      } else {
        await deleteAccountOnServer(reauth.verifierB64);
      }
      done();
    } catch (err) {
      if (isVerificationFailedError(err)) {
        // 403: the verifier itself was rejected — the typed password no
        // longer matches. NOT a session death: stay on the card for a retry.
        Alert.alert(tr("common.passwordMismatchTitle"), tr("common.passwordMismatchBody"));
        retry();
        return;
      }
      if (isSessionExpiredError(err)) {
        // 401: the client hook has already locked the vault; the stack is
        // about to swap to Unlock. Say why.
        Alert.alert(tr("common.sessionExpiredTitle"), tr("common.unlockAgainBody"));
      } else {
        Alert.alert(tr("common.couldNotCompleteTitle"), calmFallbackCopy(err, tr("errors.generic")));
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
          await clearThresholdNotice(userId); // and the one-time threshold card stamp
          await clearReminderPrefs(userId); // and the reminder opt-in
          await clearMoodMirrorPref(userId); // and the Health mirror opt-in
          await disableBiometricUnlock(userId); // and the biometric data-key wrap
          await cancelDailyReminder().catch(() => {}); // a deleted account must not be nudged
        }
        if (username) await api.clearCachedSalt(username);
      } catch {
        // Reported in the success dialog below.
      }
      await signOut(); // revokes tokens, clears the session
      Alert.alert(tr("settings.deletedTitle"), tr("settings.deletedBody"));
    } catch (err) {
      // A VERIFIER rejection (403) must RETHROW to the outer handler so the
      // password card STAYS UP for one corrected retry (audit L-62: this
      // inner catch used to swallow it, clearing the card only on the
      // delete path — the documented retry contract applied to the LLM
      // toggle alone). Nothing was deleted: the account still exists.
      if (isVerificationFailedError(err)) throw err;
      // The server still holds the account — keep the local session intact
      // so the user can retry instead of believing it worked.
      if (isSessionExpiredError(err)) {
        Alert.alert(tr("settings.deleteFailedTitle"), tr("settings.deleteFailedSession"));
      } else {
        Alert.alert(tr("settings.deleteFailedTitle"), calmFallbackCopy(err, tr("errors.generic")));
      }
    }
  };

  /** Full exports deliberately fail closed in this build. The API streams
   * ciphertext, but React Native's stock fetch/Share path buffers it into a
   * JS string first; an account near the server cap could exhaust memory and
   * expose plaintext in a share intent. Re-enable only with a reviewed
   * native streaming-to-file implementation. */
  const explainExportUnavailable = () => {
    Alert.alert(tr("settings.exportTitle"), tr("settings.exportBody"));
  };

  /** Reminder opt-in: persist first (the preference is readable whatever
   *  this build can schedule), then reconcile the native schedule. */
  const toggleReminders = async (on: boolean) => {
    touchActivity();
    const userId = await api.getUserId().catch(() => null);
    if (!userId) return; // no account: nothing to bind the preference to
    try {
      await setReminderEnabled(userId, on);
    } catch {
      Alert.alert(tr("settings.reminderSaveFailedTitle"), tr("settings.reminderSaveFailedBody"));
      return;
    }
    setReminderOn(on);
    const scheduled = await syncReminderSchedule(userId).catch(() => false);
    if (on && !scheduled && reminders.available) {
      // The module is linked but the OS said no — honest, and fixable by
      // the user in system settings. (An unlinked module is already
      // explained by the muted reason line under the switch.)
      Alert.alert(tr("settings.reminderNotScheduledTitle"), tr("settings.reminderNotScheduledBody"));
    }
  };

  /** Choose the reminder time; the preference saves even while the native
   *  side is unavailable, and syncs whenever it can. */
  const chooseReminderTime = async (hour: number, minute: number) => {
    touchActivity();
    const userId = await api.getUserId().catch(() => null);
    if (!userId) return;
    await setReminderTime(userId, hour, minute).catch(() => {});
    setReminderTimeState({ hour, minute });
    void syncReminderSchedule(userId).catch(() => {});
  };

  /** Health mirror opt-in (2026-09-19): persist first (the preference is
   *  readable whatever this build can write), then — on enabling, with the
   *  module linked — ask for Health WRITE access HERE, where the user just
   *  flipped the switch, so the OS prompt never surprises them at a future
   *  check-in and a denial is reported instead of silently skipping. */
  const toggleHealthMirror = async (on: boolean) => {
    touchActivity();
    const userId = await api.getUserId().catch(() => null);
    if (!userId) return; // no account: nothing to bind the preference to
    try {
      await setMoodMirrorPref(userId, on);
    } catch {
      Alert.alert(tr("settings.healthMirrorSaveFailedTitle"), tr("settings.healthMirrorSaveFailedBody"));
      return;
    }
    setMirrorHealthOn(on);
    if (on && health.available) {
      const granted = await ensureStateOfMindWriteAccess().catch(() => false);
      if (!granted) {
        // The preference stays saved (the user's choice is real); the
        // honest note says what to fix — mirroring just won't land yet.
        Alert.alert(tr("settings.healthMirrorDeniedTitle"), tr("settings.healthMirrorDeniedBody"));
      }
    }
  };

  /** Biometric unlock: enabling is an explicit, explained act — the Alert
   *  states the trade before anything is stored. */
  const toggleBiometrics = async (on: boolean) => {
    touchActivity();
    const userId = await api.getUserId().catch(() => null);
    if (!userId) return;
    if (!on) {
      try {
        await disableBiometricUnlock(userId);
        setBioEnabled(false);
      } catch {
        Alert.alert(tr("settings.bioOffFailedTitle"), tr("settings.bioOffFailedBody"));
      }
      return;
    }
    Alert.alert(tr("settings.bioTitle"), tr("settings.bioBody"), [
      { text: tr("common.cancel"), style: "cancel" },
      {
        text: tr("settings.bioEnable"),
        // M-4: the explainer is step one; the password card is the gate —
        // a foregrounded unlocked phone must not be enough to persist the
        // data key in the Keychain forever.
        onPress: () => setPending({ kind: "bio" }),
      },
    ]);
  };

  const enableBiometricWrap = async (userId: string) => {
    try {
      // Settings only renders while the vault is unlocked — but the read
      // lives inside the same guard so a locked vault degrades honestly.
      const { dataKey } = vault.get();
      await enableBiometricUnlock(userId, dataKey);
      setBioEnabled(true);
    } catch {
      Alert.alert(tr("settings.bioOnFailedTitle"), tr("settings.bioOnFailedBody"));
    }
  };

  /** H-1/M-3: rotate the credential AND the data key. Runs the full server
   *  flow (rekey -> re-wrap grants -> retire old credential -> re-login);
   *  on success the vault is locked so the next unlock uses the new
   *  password, and the user is signed out to re-verify on this device. */
  const runRotate = async () => {
    if (busy || !password || !newPassword) return;
    const policyError = passwordPolicyError(newPassword);
    if (policyError) {
      Alert.alert(tr("login.policyVarietyTitle"), policyError);
      return;
    }
    setBusy(true);
    try {
      const userId = await api.getUserId().catch(() => null);
      const username = await api.getUsername().catch(() => null);
      if (!userId || !username) {
        Alert.alert(tr("common.reauthNoAccount"));
        return;
      }
      const outcome = await rotatePassword({ username, userId, oldPassword: password, newPassword });
      if (outcome.ok) {
        const rewrapNote =
          outcome.rewrapFailures.length > 0
            ? `\n\n${tr("settings.rotateRewrapFailed", { names: outcome.rewrapFailures.join(", ") })}`
            : "";
        Alert.alert(
          tr("settings.rotateSuccessTitle"),
          `${tr("settings.rotateSuccessBody")}${rewrapNote}`,
          [{ text: tr("common.ok"), onPress: () => void signOut() }],
        );
      } else if (outcome.reason === "wrong-password") {
        Alert.alert(tr("settings.rotateFailedTitle"), tr("settings.rotateWrongOld"));
      } else if (outcome.reason === "offline") {
        Alert.alert(tr("settings.rotateFailedTitle"), tr("common.reauthOffline"));
      } else {
        Alert.alert(
          tr("settings.rotateFailedTitle"),
          outcome.detail ?? tr("errors.generic"),
        );
      }
    } finally {
      setPassword("");
      setNewPassword("");
      setBusy(false);
    }
  };

  const deleteEverything = () => {
    Alert.alert(tr("settings.deleteAllTitle"), tr("settings.deleteAllBody"), [
      { text: tr("common.cancel"), style: "cancel" },
      {
        text: tr("common.continue"),
        style: "destructive",
        onPress: () =>
          Alert.alert(tr("common.finalConfirmation"), tr("settings.deleteAllFinalBody"), [
            { text: tr("common.cancel"), style: "cancel" },
            // The password prompt below IS the real confirmation.
            {
              text: tr("settings.continueToPassword"),
              style: "destructive",
              onPress: () => setPending({ kind: "delete" }),
            },
          ]),
      },
    ]);
  };

  // Appearance state (2026-09-17). The radio starts at the provider's own
  // default and takes the PERSISTED preference from storage below — never a
  // value derived from the active palette (a "system" preference on a
  // dark-OS device must not select "Dark" as if it were the override).
  const setThemeMode = useSetThemeMode();
  const [themeMode, setThemeModeState] = useState<ThemeMode>("system");
  const [haptics, setHaptics] = useState(true);
  const [reminders] = useState(reminderCapability());
  // The HealthKit State of Mind seam capability — probed once, sync, the
  // reminderCapability idiom. The mirror ROW is always visible (the
  // preference is real); the switch is enabled only when available.
  const [health] = useState(healthKitCapability());
  // Local reminder preference (reminders.ts) — readable even when the
  // native notification module is absent in this build; the Switch is
  // disabled then, never hidden-with-a-guess.
  const [reminderOn, setReminderOn] = useState(false);
  const [reminderTime, setReminderTimeState] = useState({ hour: 20, minute: 0 });
  // The Health mirror preference (healthkit.ts) — same honesty rules.
  const [mirrorHealthOn, setMirrorHealthOn] = useState(false);
  // Biometric unlock wrap state — the section only appears when this
  // device actually has biometrics (biometricUnlock.ts quiet probe).
  const [bioSupported, setBioSupported] = useState(false);
  const [bioEnabled, setBioEnabled] = useState(false);
  React.useEffect(() => {
    void loadHapticsSetting().then(setHaptics);
  }, []);
  // The persisted theme preference (audit L-63: this used to exist twice,
  // byte-for-byte — one dead duplicate). One read, cancellation-guarded;
  // a missing/invalid value leaves the provider's default selected.
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
            {rejectedCount === 1
              ? tr("settings.rejectedOne", { count: rejectedCount })
              : tr("settings.rejectedMany", { count: rejectedCount })}
          </Text>
          <GhostButton
            label={tr("settings.retrySync")}
            center={false}
            onPress={recoverRejected}
            disabled={busy}
            accessibilityLabel={tr("settings.retrySyncA11y")}
          />
        </View>
      )}
      {quarantined && (
        <Text style={themed.footnote}>{tr("settings.quarantinedNote")}</Text>
      )}
      {legacyQueueRecovery && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderColor: t.colors.border, borderWidth: 1, borderRadius: t.radius.lg }]} accessibilityRole="alert">
          <Text style={{ color: t.colors.text, fontSize: t.type.title.fontSize, fontWeight: "700" }}>{tr("settings.legacyTitle")}</Text>
          <Text style={themed.footnote}>{tr("settings.legacyBody")}</Text>
        </View>
      )}

      {llmAvailable && (
        <>
          <Text style={themed.label}>{tr("settings.llmLabel")}</Text>
          <View style={[styles.row, { backgroundColor: t.colors.card, borderRadius: t.radius.md }]}>
            <Text style={themed.rowText}>{tr("settings.llmBody")}</Text>
            <Switch
              value={llmEnabled}
              disabled={busy}
              onValueChange={(enabled) => setPending({ kind: "llm", enabled })}
              trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
              accessibilityLabel={tr("settings.llmA11y")}
              accessibilityState={{ checked: llmEnabled, disabled: busy }}
            />
          </View>
        </>
      )}
      {pending && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>
            {pending.kind === "delete"
              ? tr("settings.reauthDeleteTitle")
              : pending.kind === "bio"
                ? tr("settings.reauthBioTitle")
                : tr("settings.reauthLlmTitle", {
                    action: tr(pending.enabled ? "settings.enableWord" : "settings.disableWord"),
                  })}
          </Text>
          <TextInput
            style={themed.input}
            placeholder={tr("common.passwordPlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={password}
            onChangeText={setPassword}
            accessibilityLabel={tr("common.passwordConfirmA11y")}
            textContentType="password"
          />
          <PrimaryButton
            label={busy ? tr("common.verifying") : tr("common.confirmWithPassword")}
            onPress={confirmWithPassword}
            disabled={!password}
            danger={pending.kind === "delete"}
            accessibilityLabel={tr("common.confirmWithPassword")}
          />
          <GhostButton
            label={tr("common.cancel")}
            disabled={busy}
            onPress={() => { setPending(null); setPassword(""); }}
          />
        </View>
      )}

      {/* Appearance & feel (2026-09-17): theme override + haptics. */}
      <Text style={themed.label}>{tr("settings.appearanceLabel")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <View style={{ flexDirection: "row", gap: 8 }}>
          {(["system", "dark", "light"] as ThemeMode[]).map((mode) => {
            // L-64: the radio's a11y label interpolates the LOCALIZED mode
            // name — a Spanish screen reader heard "Tema: dark" before.
            const modeLabel = tr(mode === "system" ? "settings.themeSystem" : mode === "dark" ? "settings.themeDark" : "settings.themeLight");
            return (
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
                accessibilityLabel={tr("settings.themeA11y", { mode: modeLabel })}
              >
                <Text style={{ color: themeMode === mode ? t.colors.onPrimary : t.colors.body, fontSize: 13 }}>
                  {modeLabel}
                </Text>
              </TouchableOpacity>
            );
          })}
        </View>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
          <Text style={themed.rowText}>{tr("settings.hapticsLabel")}</Text>
          <Switch
            value={haptics}
            onValueChange={(on) => {
              touchActivity();
              setHaptics(on);
              void setHapticsEnabled(on);
            }}
            accessibilityLabel={tr("settings.hapticsA11y")}
          />
        </View>
      </View>

      {/* Local journaling reminders (2026-09-19): the preference is always
          real; the native schedule follows what this build can do. */}
      <Text style={themed.label}>{tr("settings.reminderLabel")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <Text style={themed.footnote}>{tr("settings.reminderNote")}</Text>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
          <Text style={themed.rowText}>{tr("settings.remindMeLabel")}</Text>
          <Switch
            value={reminderOn}
            disabled={!reminders.available}
            onValueChange={(on) => void toggleReminders(on)}
            trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
            accessibilityLabel={tr("settings.dailyReminderA11y")}
            accessibilityState={{ checked: reminderOn, disabled: !reminders.available }}
          />
        </View>
        {reminderOn && (
          <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }} accessibilityLabel={tr("settings.reminderTimeA11y")}>
            {[
              ...REMINDER_PRESETS,
              // A stored custom time (never one of the presets) shows as
              // its own chip so the current choice is always visible.
              ...((REMINDER_PRESETS.some((p) => p.hour === reminderTime.hour && p.minute === reminderTime.minute)
                ? []
                : [
                    {
                      label: `${reminderTime.hour}:${String(reminderTime.minute).padStart(2, "0")}`,
                      hour: reminderTime.hour,
                      minute: reminderTime.minute,
                    },
                  ]) as { label: string; hour: number; minute: number }[]),
            ].map((preset) => {
              const selected =
                preset.hour === reminderTime.hour && preset.minute === reminderTime.minute;
              return (
                <TouchableOpacity
                  key={preset.label}
                  style={[
                    styles.timeChip,
                    {
                      backgroundColor: selected ? t.colors.primary : t.colors.cardDeep,
                      borderRadius: t.radius.md,
                      minHeight: 40,
                    },
                  ]}
                  onPress={() => void chooseReminderTime(preset.hour, preset.minute)}
                  accessibilityRole="radio"
                  accessibilityState={{ selected }}
                  accessibilityLabel={tr("settings.reminderTimeOptionA11y", { label: preset.label })}
                >
                  <Text style={{ color: selected ? t.colors.onPrimary : t.colors.body, fontSize: 13 }}>
                    {preset.label}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        )}
        {!reminders.available && (
          <Text style={themed.footnote}>
            {tr("settings.reminderUnavailableNote", { reason: reminders.reason ?? "" })}
          </Text>
        )}
      </View>

      {/* HealthKit State of Mind mirror (2026-09-19): WRITE-ONLY — the
          honest disclosure rides with the row; the preference is always
          real, the switch only works where the module is linked. */}
      <Text style={themed.label}>{tr("settings.healthMirrorLabel")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
          <Text style={themed.rowText}>{tr("settings.healthMirrorRow")}</Text>
          <Switch
            value={mirrorHealthOn}
            disabled={!health.available}
            onValueChange={(on) => void toggleHealthMirror(on)}
            trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
            accessibilityLabel={tr("settings.healthMirrorA11y")}
            accessibilityState={{ checked: mirrorHealthOn, disabled: !health.available }}
          />
        </View>
        <Text style={themed.footnote}>{tr("settings.healthMirrorNote")}</Text>
        {!health.available && (
          <Text style={themed.footnote}>
            {tr("settings.healthMirrorUnavailableNote", { reason: health.reason ?? "" })}
          </Text>
        )}
      </View>

      {/* Biometric unlock (2026-09-19): shown only where it can work. */}
      {bioSupported && (
        <>
          <Text style={themed.label}>{tr("settings.biometricLabel")}</Text>
          <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
            <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
              <Text style={themed.rowText}>{tr("settings.biometricRow")}</Text>
              <Switch
                value={bioEnabled}
                onValueChange={(on) => void toggleBiometrics(on)}
                trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
                accessibilityLabel={tr("settings.biometricA11y")}
                accessibilityState={{ checked: bioEnabled, disabled: false }}
              />
            </View>
            <Text style={themed.footnote}>{tr("settings.biometricNote")}</Text>
          </View>
        </>
      )}

      {sharingAvailable === true ? (
        <GhostButton
          label={tr("settings.shareWithTherapist")}
          center={false}
          onPress={() => navigation.navigate("TherapistShare")}
          accessibilityLabel={tr("settings.shareWithTherapistA11y")}
        />
      ) : sharingAvailable === false ? (
        <Text style={themed.footnote}>{tr("settings.sharingOffNote")}</Text>
      ) : (
        <Text style={themed.footnote}>{tr("settings.sharingUnknownNote")}</Text>
      )}
      <GhostButton
        label={tr("settings.measures")}
        center={false}
        onPress={() => navigation.navigate("Measures")}
        accessibilityLabel={tr("settings.measuresA11y")}
      />
      <GhostButton
        label={tr("settings.whyExport")}
        center={false}
        onPress={explainExportUnavailable}
        accessibilityLabel={tr("settings.whyExportA11y")}
      />
      <GhostButton
        label={showRotate ? tr("settings.changePasswordCancel") : tr("settings.changePasswordLabel")}
        disabled={busy}
        onPress={() => { touchActivity(); setShowRotate((open) => !open); setNewPassword(""); }}
      />
      {showRotate && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>{tr("settings.changePasswordTitle")}</Text>
          <Text style={themed.footnote}>{tr("settings.changePasswordBody")}</Text>
          <TextInput
            style={themed.input}
            placeholder={tr("common.passwordPlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={password}
            onChangeText={setPassword}
            accessibilityLabel={tr("common.passwordConfirmA11y")}
            textContentType="password"
          />
          <TextInput
            style={themed.input}
            placeholder={tr("settings.newPasswordPlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={newPassword}
            onChangeText={setNewPassword}
            accessibilityLabel={tr("settings.newPasswordA11y")}
            textContentType="newPassword"
          />
          <PrimaryButton
            label={busy ? tr("settings.rotateWorking") : tr("settings.changePasswordButton")}
            onPress={() => void runRotate()}
            disabled={busy || !password || !newPassword}
            accessibilityLabel={tr("settings.changePasswordButton")}
          />
          <GhostButton
            label={tr("common.cancel")}
            disabled={busy}
            onPress={() => { setShowRotate(false); setPassword(""); setNewPassword(""); }}
          />
        </View>
      )}
      <PrimaryButton label={tr("settings.deleteAccount")} onPress={deleteEverything} disabled={busy} danger />
      <GhostButton
        label={tr("settings.signOut")}
        onPress={async () => { vault.lock(); await signOut(); navigation.popToTop(); }}
      />

      <Text style={themed.label}>{tr("settings.aboutLabel")}</Text>
      <Text style={themed.footnote}>
        {tr("settings.aboutBody", {
          version: APP_VERSION,
          server: serverVersion ? tr("settings.serverVersionTag", { version: serverVersion }) : "",
        })}
      </Text>
      <GhostButton
        label={tr("settings.privacyPolicy")}
        center={false}
        onPress={() => navigation.navigate("Privacy")}
        accessibilityLabel={tr("settings.privacyPolicyA11y")}
      />

      <Text style={themed.label}>{tr("settings.advancedLabel")}</Text>
      <Text style={themed.footnote}>{tr("settings.advancedNote")}</Text>
      <TextInput
        style={themed.input}
        value={url}
        onChangeText={setUrl}
        autoCapitalize="none"
        placeholder={tr("settings.serverUrlPlaceholder")}
        placeholderTextColor={t.colors.placeholder}
        accessibilityLabel={tr("settings.serverUrlA11y")}
        textContentType="URL"
        autoComplete="off"
      />
      <PrimaryButton label={tr("settings.saveServerUrl")} onPress={saveUrl} disabled={busy} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1 },
  card: { padding: 16, gap: 8 },
  moodOptionLike: { flex: 1, alignItems: "center", justifyContent: "center" },
  timeChip: { paddingHorizontal: 12, paddingVertical: 8, alignItems: "center", justifyContent: "center" },
  row: { flexDirection: "row", alignItems: "center", gap: 12, padding: 14 },
  reauthCard: { padding: 16, gap: 12 },
  reauthTitle: { fontSize: 15, fontWeight: "600", lineHeight: 20 },
});
