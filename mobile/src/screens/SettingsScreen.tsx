/**
 * Account preferences, processing consent, local recovery, and deletion.
 * Sensitive changes require the typed password through reauth.ts. A rejected
 * verifier leaves the password card open; an expired session returns to
 * unlock. The server selector lives in the Advanced section.
 *
 * Full-account export stays disabled until a native streaming-to-file path
 * is available. Saved recordings have a separate export action. Rejected
 * entry uploads are retained and can be requeued from the recovery section.
 */
import { audioQueueStatus, retryAudioQueue, listSavedAudio, exportSavedAudio, removeSavedAudio } from "../audioQueue";
import { eraseDeletedAccountLocals } from "../accountErasure";
import React, { useEffect, useRef, useState } from "react";
import { Alert, AppState, Platform, ScrollView, StyleSheet, Switch, Text, TextInput, TouchableOpacity, View } from "react-native";
import { api, getBaseUrl, parseServerUrl, setBaseUrl } from "../api/client";
import { ThemeMode, themeStorageKey, useSetThemeMode } from "../theme";
import { loadHapticsSetting, setHapticsEnabled } from "../haptics";
import { reminderCapability } from "../nativeFeatures";
import { getReminderPrefs, setReminderEnabled, setReminderTime } from "../reminders";
import { useReminderPreferenceIntent } from "../reminderPreferences";
import { readLanguageChoice, writeLanguageChoice, type LanguageChoice } from "../languagePref";
import {
  generateRecoveryKey,
  recoveryKitText,
  recoveryVerifierKeyV2,
  sealDataKeyForRecoveryV2,
} from "../crypto/recovery";
import { syncReminderSchedule, syncMeasureReminderSchedule } from "../reminderSync";
import {
  getMeasureReminderPrefs,
  MEASURE_INTERVAL_WEEKS,
  setMeasureReminderEnabled,
  setMeasureReminderInterval,
} from "../measureReminders";
import {
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
import { localWriteScopeEpoch } from "../localWriteGuard";
import { useSession } from "../store";
import { verifyPasswordForVault, isVerificationFailedError, isSessionExpiredError } from "../reauth";
import { rotatePassword } from "../rotation";
import { upgradeKeyProtection } from "../envelopeUpgrade";
import { fetchEnvelope, type KeyScheme } from "../keyScheme";
import { passwordPolicyError } from "./LoginScreen";
import {
  rejectedEntryCount,
  requeueRejected,
  quarantinedQueueExists,
  flushQueue,
  hasLegacyQueueRecovery,
} from "../offlineQueue";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { requestFailureCopy, calmFallbackCopy } from "../components/errors";
import { t as tr, dateLocaleTag } from "../strings";

/** App version injected from package.json by Babel and the test setup. */
declare const __APP_VERSION__: string;
const APP_VERSION: string = __APP_VERSION__;

/** Resolve preset labels at render time so language changes update them.
 * Custom stored times appear as an additional option. */
const reminderPresets = (): readonly { label: string; hour: number; minute: number }[] => [
  { label: tr("settings.reminderMorning"), hour: 9, minute: 0 },
  { label: tr("settings.reminderMidday"), hour: 12, minute: 0 },
  { label: tr("settings.reminderEvening"), hour: 20, minute: 0 },
];

type PendingAction =
  | { kind: "llm"; enabled: boolean }
  // Voice consent permits uploading recordings, so it requires the password.
  | { kind: "voice"; enabled: boolean }
  | { kind: "delete" }
  | { kind: "recovery-create" }
  | { kind: "recovery-remove" }
  // Persisting a biometric data-key wrap requires password verification.
  | { kind: "bio" }
  // Uploading a password-wrapped data key requires password verification.
  | { kind: "upgrade" }
  | null;

type SensitiveOwnership = { scope: number; owner: string | null; sensitive: object; dataKey: Buffer | null };

export function SettingsScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { signOut, touchActivity } = useSession();
  const beginReminderIntent = useReminderPreferenceIntent();
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  // Native releases can arrive in the same frame before React commits busy.
  // Keep sensitive admission live until its own completion releases it.
  const sensitiveSubmission = useRef<SensitiveOwnership | null>(null);
  const [llmAvailable, setLlmAvailable] = useState(false);
  const [llmProvider, setLlmProvider] = useState("");
  const [llmRetention, setLlmRetention] = useState("");
  const [llmFingerprint, setLlmFingerprint] = useState("");
  // Unknown availability must remain distinct from an explicit server refusal.
  const [sharingAvailable, setSharingAvailable] = useState<boolean | null>(null);
  const [llmEnabled, setLlmEnabled] = useState(false);
  const [llmStale, setLlmStale] = useState(false);
  // Metadata supplies voice availability/provider; the consent record supplies
  // the opt-in and policy version. Availability stays unknown until metadata loads.
  const [voiceAvailable, setVoiceAvailable] = useState<boolean | null>(null);
  const [voiceProvider, setVoiceProvider] = useState("");
  const [voiceRetention, setVoiceRetention] = useState("");
  const [voiceFingerprint, setVoiceFingerprint] = useState("");
  const [voiceEnabled, setVoiceEnabled] = useState(false);
  // Initial reads can finish after a password-confirmed write. Once the
  // server acknowledges a newer value, that older read cannot publish it.
  const acknowledgedPreferences = useRef({ llm: false, voice: false, recovery: false, dailyEnabled: false, dailyTime: false, measureEnabled: false, measureInterval: false, health: false, biometric: false, theme: false, language: false, haptics: false });
  // enabled-but-stale: the server's transcription provider changed since
  // the consent was given; the toggle must be re-confirmed to accept the
  // new terms.
  const [voiceStale, setVoiceStale] = useState(false);
  const [serverVersion, setServerVersion] = useState<string | null>(null);
  const [rejectedCount, setRejectedCount] = useState(0);
  const [quarantined, setQuarantined] = useState(false);
  const [legacyQueueRecovery, setLegacyQueueRecovery] = useState(false);
  const [pending, setPending] = useState<PendingAction>(null);
  const [password, setPassword] = useState("");
  // Password rotation has its own current/new password fields.
  const [showRotate, setShowRotate] = useState(false);
  const [newPassword, setNewPassword] = useState("");
  // Keep rotation and destructive-action passwords separate so one card cannot
  // satisfy another action with a password entered earlier.
  const [rotateCurrentPassword, setRotateCurrentPassword] = useState("");
  // The key scheme controls upgrade availability and rotation copy.
  // An unavailable server leaves it unknown.
  const [keyScheme, setKeyScheme] = useState<KeyScheme | null>(null);
  const captureSensitiveOwnership = (): SensitiveOwnership => ({ scope: localWriteScopeEpoch(), owner: vault.ownerUserId(), sensitive: sensitiveEpoch.current, dataKey: vault.canReauthenticate() ? vault.get().dataKey : null });
  const ownsSensitiveScope = (operation: SensitiveOwnership) => operation.scope === localWriteScopeEpoch() && operation.sensitive === sensitiveEpoch.current;
  const assertSensitiveOwnership = (operation: SensitiveOwnership, requireVault = true) => {
    if (!ownsSensitiveScope(operation) || !operation.owner || (requireVault && (!vault.canReauthenticate() || vault.ownerUserId() !== operation.owner || vault.get().dataKey !== operation.dataKey))) {
      throw new Error(tr("common.sessionDamagedTitle"));
    }
  };
  // Request credential reads can await native providers after the screen's
  // own admission proof. Recheck that exact view and physical key before
  // the client may dispatch a verifier or wrapped data key.
  const sensitiveRequestCurrent = (operation: SensitiveOwnership): boolean => {
    try { assertSensitiveOwnership(operation); return true; } catch { return false; }
  };


  React.useEffect(() => {
    // Leave the field empty if the stored origin cannot be read.
    getBaseUrl().then(setUrl).catch(() => {});
    api.meta()
      .then((m) => {
        setLlmAvailable(Boolean(m?.llm_available));
        setLlmProvider(typeof m?.llm_provider_name === "string" ? m.llm_provider_name : "");
        setLlmRetention(typeof m?.llm_data_retention === "string" ? m.llm_data_retention : "");
        setLlmFingerprint(typeof m?.llm_policy_fingerprint === "string" ? m.llm_policy_fingerprint : "");
        // Sharing is fail-closed: only a server that explicitly advertises
        // verified-clinician sharing may expose a pairing flow. On success
        // the answer is authoritative; a failure leaves the state UNKNOWN
        // (null) so the copy below never blames the server for being
        // unreachable.
        setSharingAvailable(m?.sharing_available === true);
        // Voice availability/provider ride the same meta answer; a missing
        // audio_available never counts as offered (fail closed like sharing).
        setVoiceAvailable(m?.audio_available === true);
        setVoiceProvider(typeof m?.stt_provider_name === "string" ? m.stt_provider_name : "");
        setVoiceRetention(typeof m?.stt_data_retention === "string" ? m.stt_data_retention : "");
        setVoiceFingerprint(typeof m?.stt_policy_fingerprint === "string" ? m.stt_policy_fingerprint : "");
        if (typeof m?.version === "string") setServerVersion(m.version);
      })
      .catch(() => setSharingAvailable(null));
    api.getLlmConsent().then((c) => {
      if (acknowledgedPreferences.current.llm) return;
      setLlmEnabled(c?.enabled === true && c.active_for_current_policy === true);
      setLlmStale(c?.enabled === true && c.active_for_current_policy !== true);
    }).catch(() => {});
    // The voice consent record (same read discipline as the LLM consent):
    // enabled + policy currency; a failed read leaves the switch OFF and
    // the stale note hidden — never a guessed state.
    api.getVoiceConsent()
      .then((c) => {
        if (acknowledgedPreferences.current.voice) return;
        setVoiceEnabled(c?.enabled === true && c.active_for_current_policy === true);
        setVoiceStale(c != null && c.enabled === true && c.active_for_current_policy !== true);
      })
      .catch(() => {});
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
          if (!acknowledgedPreferences.current.dailyEnabled) setReminderOn(prefs.enabled);
          if (!acknowledgedPreferences.current.dailyTime) setReminderTimeState({ hour: prefs.hour, minute: prefs.minute });
        })
        .catch(() => {});
      // The check-in reminder preference (non-sensitive, per account).
      getMeasureReminderPrefs(userId)
        .then((prefs) => {
          if (!acknowledgedPreferences.current.measureEnabled) setMeasureReminderOn(prefs.enabled);
          if (!acknowledgedPreferences.current.measureInterval) setMeasureIntervalState(prefs.intervalWeeks);
        })
        .catch(() => {});
      // The Health mirror opt-in (non-sensitive, per account) — the
      // preference reads back even while the Health module is absent.
      getMoodMirrorPref(userId).then(enabled => { if (!acknowledgedPreferences.current.health) setMirrorHealthOn(enabled); }).catch(() => {});
      hasBiometricUnlock(userId).then(enabled => { if (!acknowledgedPreferences.current.biometric) setBioEnabled(enabled); }).catch(() => {});
    }).catch(() => {});
    hasLegacyQueueRecovery().then(setLegacyQueueRecovery).catch(() => {});
    biometricsSupported().then(setBioSupported).catch(() => {});
    // One envelope read selects the upgrade card and password-rotation copy.
    fetchEnvelope()
      .then((fetched) => {
        if (fetched.status === "ok") setKeyScheme(fetched.envelope.scheme);
      })
      .catch(() => {});
  },
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
    if (!sensitiveRequestCurrent(renderedSensitiveOwnership)) return;
    if (busy || sensitiveSubmission.current || !vault.canReauthenticate()) return;
    const operation = captureSensitiveOwnership();
    sensitiveSubmission.current = operation;
    setBusy(true);
    try {
      assertSensitiveOwnership(operation);
      const userId = await api.getUserId();
      assertSensitiveOwnership(operation);
      if (!userId) {
        Alert.alert(tr("settings.signInRequiredTitle"), tr("settings.signInRequiredBody"));
        return;
      }
      if (userId !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
      const moved = await requeueRejected(userId);
      assertSensitiveOwnership(operation);
      if (userId) await flushQueue(userId).catch(() => {}); // offline: next flush handles it
      assertSensitiveOwnership(operation);
      const left = await rejectedEntryCount(userId);
      assertSensitiveOwnership(operation);
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
      if (ownsSensitiveScope(operation)) Alert.alert(tr("settings.couldNotRetryTitle"), tr("settings.couldNotRetryBody"));
    } finally {
      if (sensitiveSubmission.current === operation) {
        sensitiveSubmission.current = null;
        setBusy(false);
      }
    }
  };

  /** Destructive flows land here FIRST — the actual action only runs after
   *  the typed password re-derives the vault's own auth key. */
  const confirmWithPassword = async () => {
    if (!sensitiveRequestCurrent(renderedSensitiveOwnership)) return;
    if (!pending || busy || !password || sensitiveSubmission.current || !vault.canReauthenticate()) return;
    setBusy(true);
    // done: the flow concluded (success or unrecoverable) — clear the card.
    // retry: the password itself was rejected — the card STAYS UP, the fix
    // is one corrected password away.
    const operation = captureSensitiveOwnership();
    sensitiveSubmission.current = operation;
    const done = () => { if (ownsSensitiveScope(operation)) { setBusy(false); setPending(null); setPassword(""); } };
    const retry = () => { if (ownsSensitiveScope(operation)) { setBusy(false); setPassword(""); } };
    try {
      assertSensitiveOwnership(operation);
      const reauth = await verifyPasswordForVault(password);
      assertSensitiveOwnership(operation);
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
        const result = await api.setLlmConsent(pending.enabled, reauth.verifierB64, () => sensitiveRequestCurrent(operation));
        assertSensitiveOwnership(operation);
        acknowledgedPreferences.current.llm = true;
        setLlmEnabled(result.enabled === true && result.active_for_current_policy === true);
        setLlmStale(result.enabled === true && result.active_for_current_policy !== true);
      } else if (pending.kind === "voice") {
        const result = await api.setVoiceConsent(pending.enabled, reauth.verifierB64, () => sensitiveRequestCurrent(operation));
        assertSensitiveOwnership(operation);
        acknowledgedPreferences.current.voice = true;
        setVoiceEnabled(result.enabled === true && result.active_for_current_policy === true);
        setVoiceStale(result.enabled === true && result.active_for_current_policy !== true);
      } else if (pending.kind === "bio") {
        // The password proof just ran: enabling the biometric wrap now
        // proves the enabler knows the password, not merely that they hold
        // the foregrounded unlocked session (M-4).
        const userId = await api.getUserId().catch(() => null);
        if (!userId) {
          Alert.alert(tr("common.couldNotVerifyTitle"), tr("common.reauthNoAccount"));
          retry();
          return;
        }
        assertSensitiveOwnership(operation);
        if (userId !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
        await enableBiometricWrap(userId, operation);
      } else if (pending.kind === "recovery-create") {
        await createRecoveryKit(reauth.verifierB64, operation);
      } else if (pending.kind === "recovery-remove") {
        await removeRecoveryKit(reauth.verifierB64, operation);
      } else if (pending.kind === "upgrade") {
        // A rejected password keeps the card open for a corrected retry.
        if (await runUpgrade(password, reauth.verifierB64, operation)) {
          retry();
          return;
        }
      } else {
        await deleteAccountOnServer(reauth.verifierB64, operation);
      }
      done();
    } catch (err) {
      if (!ownsSensitiveScope(operation)) return;
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
    } finally {
      if (sensitiveSubmission.current === operation) {
        sensitiveSubmission.current = null;
        setBusy(false);
        // A same-origin credential refresh retires the proof without
        // replacing this route. Release its card for a fresh confirmation.
        if (!ownsSensitiveScope(operation)) { setPending(null); setPassword(""); }
      }
    }
  };

  const deleteAccountOnServer = async (verifierB64: string, operation: SensitiveOwnership) => {
    try {
      assertSensitiveOwnership(operation);
      const origin = await getBaseUrl(); assertSensitiveOwnership(operation);
      const userId = await api.getUserId(); assertSensitiveOwnership(operation);
      const username = await api.getUsername(); assertSensitiveOwnership(operation);
      if (userId !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
      await api.deleteAccount(verifierB64, () => sensitiveRequestCurrent(operation));
      assertSensitiveOwnership(operation);
      vault.lock();
      let failures: string[] = [];
      if (userId) failures = await eraseDeletedAccountLocals(userId, username, { origin, preserveSession: true }).catch(() => ["device cleanup"]);
      // Erasure retires the credential tuple immediately and advances the
      // local scope. Publish the matching logged-out UI even when a later
      // native cleanup task failed and left a retry checkpoint.
      const survivingOwner = await api.getUserId().catch(() => null);
      if (survivingOwner !== null && survivingOwner !== userId) return;
      await signOut().catch(async () => {
        failures.push("session cleanup");
        await api.clearSession().catch(() => {});
      });
      Alert.alert(tr("settings.deletedTitle"), tr("settings.deletedBody") +
        (failures.length ? `\n\n${tr("settings.localCleanupIncomplete")}` : ""));
    } catch (err) {
      if (!ownsSensitiveScope(operation)) return;
      // Propagate verifier rejection so the outer handler keeps the password card
      // open. The server still holds the account.
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
    const intent = beginReminderIntent("daily-enabled");
    if (!intent) return;
    const userId = await api.getUserId().catch(() => null);
    if (!intent.current() || userId !== intent.owner) return;
    try {
      await setReminderEnabled(userId, on);
    } catch {
      if (!intent.current()) return;
      Alert.alert(tr("settings.reminderSaveFailedTitle"), tr("settings.reminderSaveFailedBody"));
      return;
    }
    if (!intent.current()) return;
    acknowledgedPreferences.current.dailyEnabled = true;
    setReminderOn(on);
    const scheduled = await syncReminderSchedule(userId).catch(() => false);
    if (!intent.current()) return;
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
    const intent = beginReminderIntent("daily-time");
    if (!intent) return;
    const userId = await api.getUserId().catch(() => null);
    if (!intent.current() || userId !== intent.owner) return;
    try { await setReminderTime(userId, hour, minute); } catch {
      if (!intent.current()) return;
      Alert.alert(tr("settings.reminderSaveFailedTitle"), tr("settings.reminderSaveFailedBody")); return;
    }
    if (!intent.current()) return;
    acknowledgedPreferences.current.dailyTime = true;
    setReminderTimeState({ hour, minute });
    void syncReminderSchedule(userId).catch(() => {});
  };

  /** Check-in reminders (2026-09-27): the same persist-first-then-sync
   *  contract as the daily reminder — the preference is real whatever this
   *  build can schedule, and the sync decides whether a nudge is due. */
  const toggleMeasureReminders = async (on: boolean) => {
    touchActivity();
    const intent = beginReminderIntent("measure-enabled");
    if (!intent) return;
    const userId = await api.getUserId().catch(() => null);
    if (!intent.current() || userId !== intent.owner) return;
    try {
      await setMeasureReminderEnabled(userId, on);
    } catch {
      if (!intent.current()) return;
      Alert.alert(tr("settings.reminderSaveFailedTitle"), tr("settings.reminderSaveFailedBody"));
      return;
    }
    if (!intent.current()) return;
    acknowledgedPreferences.current.measureEnabled = true;
    setMeasureReminderOn(on);
    void syncMeasureReminderSchedule(userId).catch(() => {});
  };

  /** Choose the check-in cadence (weeks); same contract as the time chips. */
  const chooseMeasureInterval = async (weeks: number) => {
    touchActivity();
    const intent = beginReminderIntent("measure-interval");
    if (!intent) return;
    const userId = await api.getUserId().catch(() => null);
    if (!intent.current() || userId !== intent.owner) return;
    try { await setMeasureReminderInterval(userId, weeks); } catch {
      if (!intent.current()) return;
      Alert.alert(tr("settings.reminderSaveFailedTitle"), tr("settings.reminderSaveFailedBody")); return;
    }
    if (!intent.current()) return;
    acknowledgedPreferences.current.measureInterval = true;
    setMeasureIntervalState(weeks);
    void syncMeasureReminderSchedule(userId).catch(() => {});
  };

  /** Health mirror opt-in (2026-09-19): persist first (the preference is
   *  readable whatever this build can write), then — on enabling, with the
   *  module linked — ask for Health WRITE access HERE, where the user just
   *  flipped the switch, so the OS prompt never surprises them at a future
   *  check-in and a denial is reported instead of silently skipping. */
  const toggleHealthMirror = async (on: boolean) => {
    touchActivity();
    const intent = beginReminderIntent("health-mirror");
    if (!intent) return;
    const userId = await api.getUserId().catch(() => null);
    if (!intent.current() || userId !== intent.owner) return;
    try {
      await setMoodMirrorPref(userId, on);
    } catch {
      if (!intent.current()) return;
      Alert.alert(tr("settings.healthMirrorSaveFailedTitle"), tr("settings.healthMirrorSaveFailedBody"));
      return;
    }
    if (!intent.current()) return;
    acknowledgedPreferences.current.health = true;
    setMirrorHealthOn(on);
    if (on && health.available) {
      const granted = await ensureStateOfMindWriteAccess().catch(() => false);
      if (!intent.current()) return;
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
    if (!sensitiveRequestCurrent(renderedSensitiveOwnership)) return;
    touchActivity();
    const operation = captureSensitiveOwnership();
    const userId = await api.getUserId().catch(() => null);
    if (!ownsSensitiveScope(operation) || !userId || userId !== operation.owner) return;
    if (!on) {
      try {
        await disableBiometricUnlock(userId);
        if (!ownsSensitiveScope(operation)) return;
        acknowledgedPreferences.current.biometric = true;
        setBioEnabled(false);
      } catch {
        if (!ownsSensitiveScope(operation)) return;
        Alert.alert(tr("settings.bioOffFailedTitle"), tr("settings.bioOffFailedBody"));
      }
      return;
    }
    Alert.alert(tr("settings.bioTitle"), tr("settings.bioBody"), [
      { text: tr("common.cancel"), style: "cancel" },
      {
        text: tr("settings.bioEnable"),
        // Require the typed password before persisting a biometric data-key wrap.
        onPress: () => setPending({ kind: "bio" }),
      },
    ]);
  };

  const enableBiometricWrap = async (userId: string, operation: SensitiveOwnership) => {
    try {
      // Settings only renders while the vault is unlocked — but the read
      // lives inside the same guard so a locked vault degrades honestly.
      const { dataKey } = vault.get();
      await enableBiometricUnlock(userId, dataKey);
      assertSensitiveOwnership(operation);
      acknowledgedPreferences.current.biometric = true;
      setBioEnabled(true);
    } catch {
      if (!ownsSensitiveScope(operation)) return;
      Alert.alert(tr("settings.bioOnFailedTitle"), tr("settings.bioOnFailedBody"));
    }
  };

  /** H-1/M-3: rotate the credential AND the data key. Runs the full server
   *  flow (rekey -> re-wrap grants -> retire old credential -> re-login);
   *  on success the vault is locked so the next unlock uses the new
   *  password, and the user is signed out to re-verify on this device. */
  const runRotate = async () => {
    if (!sensitiveRequestCurrent(renderedSensitiveOwnership)) return;
    if (busy || !rotateCurrentPassword || !newPassword || sensitiveSubmission.current || !vault.canReauthenticate()) return;
    const policyError = passwordPolicyError(newPassword);
    if (policyError) {
      // Match the alert title to the failed password-policy rule.
      Alert.alert(
        newPassword.length < 12 ? tr("login.policyShortTitle") : tr("login.policyVarietyTitle"),
        policyError,
      );
      return;
    }
    setBusy(true);
    const operation = captureSensitiveOwnership();
    sensitiveSubmission.current = operation;
    try {
      assertSensitiveOwnership(operation);
      const userId = await api.getUserId().catch(() => null); assertSensitiveOwnership(operation);
      const username = await api.getUsername().catch(() => null); assertSensitiveOwnership(operation);
      if (userId && userId !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
      if (!userId || !username) {
        Alert.alert(tr("common.reauthNoAccount"));
        return;
      }
      const outcome = await rotatePassword({ username, userId, oldPassword: rotateCurrentPassword, newPassword });
      if (!outcome.ok && !ownsSensitiveScope(operation)) return;
      if (outcome.ok) {
        const completionScope = outcome.sessionScope ?? operation.scope;
        if (completionScope !== localWriteScopeEpoch()) return;
        const rewrapNote =
          outcome.scheme === "v2"
            ? "" // v2 keeps every grant under the unchanged data key — nothing to report
            : outcome.rewrapFailures.length > 0
            ? `\n\n${tr("settings.rotateRewrapFailed", { names: outcome.rewrapFailures.join(", ") })}`
            : "";
        // Rotation performs required key cleanup before this dismissible alert.
        // The confirmation also signs out so login uses the new credentials.
        Alert.alert(
          tr("settings.rotateSuccessTitle"),
          `${outcome.scheme === "v2" ? tr("settings.rotateSuccessBodyV2") : tr("settings.rotateSuccessBody")}${rewrapNote}${outcome.scheme === "v1" ? "\n\n" + tr("settings.rotationRecoveryReset") : ""}`,
          [{ text: tr("common.ok"), onPress: () => { if (completionScope === localWriteScopeEpoch()) void signOut(); } }],
        );
        // v2: the vault kept the SAME (still-correct) data key and adopted
        // the new auth key — but the change-password copy signs out anyway:
        // one honest place to re-verify, and other devices need their
        // unlock refreshed regardless.
        if (outcome.scheme === "v2") setKeyScheme("v2");
      } else if (outcome.reason === "wrong-password") {
        Alert.alert(tr("settings.rotateFailedTitle"), tr("settings.rotateWrongOld"));
      } else if (outcome.reason === "queue-blocked") {
        // Rotation must not strand queued entries encrypted under the old data key.
        Alert.alert(tr("settings.rotateFailedTitle"), tr("settings.rotateQueueBlocked"));
      } else if (outcome.reason === "offline") {
        Alert.alert(tr("settings.rotateFailedTitle"), tr("common.reauthOffline"));
      } else {
        Alert.alert(
          tr("settings.rotateFailedTitle"),
          outcome.detail ?? tr("errors.generic"),
        );
      }
    } catch (err) {
      if (!ownsSensitiveScope(operation)) return;
      // Unexpected rotation errors use localized fallback copy.
      Alert.alert(tr("settings.rotateFailedTitle"), calmFallbackCopy(err, tr("errors.generic")));
    } finally {
      if (sensitiveSubmission.current === operation) {
        sensitiveSubmission.current = null;
        setRotateCurrentPassword("");
        setNewPassword("");
        setBusy(false);
      }
    }
  };

  /** Upgrade a legacy account after password verification. Return true to
   * keep the password card open for a corrected retry. */
  const runUpgrade = async (password: string, verifierB64: string, operation: SensitiveOwnership): Promise<boolean> => {
    assertSensitiveOwnership(operation);
    const userId = await api.getUserId().catch(() => null); assertSensitiveOwnership(operation);
    const username = await api.getUsername().catch(() => null); assertSensitiveOwnership(operation);
    if (userId && userId !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
    if (!userId || !username) {
      Alert.alert(tr("common.reauthNoAccount"));
      return true;
    }
    const outcome = await upgradeKeyProtection({ username, userId, password, verifierB64 });
    assertSensitiveOwnership(operation);
    if (outcome.ok) {
      setKeyScheme("v2");
      Alert.alert(
        outcome.already ? tr("settings.upgradeAlreadyTitle") : tr("settings.upgradeSuccessTitle"),
        outcome.already ? tr("settings.upgradeAlreadyBody") : tr("settings.upgradeSuccessBody"),
      );
      return false;
    }
    if (outcome.reason === "wrong-password") {
      Alert.alert(tr("common.passwordMismatchTitle"), tr("common.passwordMismatchBody"));
      return true;
    }
    if (outcome.reason === "session-expired") {
      Alert.alert(tr("common.sessionExpiredTitle"), tr("common.unlockAgainBody"));
      return false;
    }
    if (outcome.reason === "key-mismatch") {
      // 403 envelope_key_mismatch: the server proved this device's key is
      // not the account's. Never auto-retried — the honest next step is a
      // fresh unlock with the current password.
      Alert.alert(tr("settings.upgradeFailedTitle"), tr("settings.upgradeKeyMismatchBody"));
      return false;
    }
    Alert.alert(
      tr("settings.upgradeFailedTitle"),
      outcome.detail ?? (outcome.reason === "offline" ? tr("common.reauthOffline") : tr("errors.generic")),
    );
    return false;
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

  // Select the saved theme preference, not the resolved palette: system mode
  // must remain selected even when the device currently uses a dark palette.
  const setThemeMode = useSetThemeMode();
  const [themeMode, setThemeModeState] = useState<ThemeMode>("system");
  const [audioStatus, setAudioStatus] = useState({ total: 0, needsAttention: 0 });
  const [savedAudio, setSavedAudio] = useState<Awaited<ReturnType<typeof listSavedAudio>>>([]);
  const savedAudioOwnership = useRef<SensitiveOwnership | null>(null);
  const refreshSavedAudio = async () => {
    const operation = captureSensitiveOwnership(); assertSensitiveOwnership(operation);
    const owner = await api.getUserId();
    assertSensitiveOwnership(operation);
    if (!owner || owner !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
    const status = await audioQueueStatus(owner); assertSensitiveOwnership(operation);
    const recordings = await listSavedAudio(owner); assertSensitiveOwnership(operation);
    savedAudioOwnership.current = operation;
    setAudioStatus(status); setSavedAudio(recordings);
  };
  const savedAudioOwner = async (operation: SensitiveOwnership | null): Promise<string> => {
    if (!operation) throw new Error(tr("common.sessionDamagedTitle"));
    assertSensitiveOwnership(operation);
    const owner = await api.getUserId(); assertSensitiveOwnership(operation);
    if (!owner || owner !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
    return owner;
  };
  useEffect(() => { void refreshSavedAudio().catch(() => {}); }, []);
  const [language, setLanguageState] = useState<LanguageChoice>("device");

  /** Create/replace a recovery kit after fresh password verification.
   * The raw recovery key is generated on device and is never uploaded. */
  const createRecoveryKit = async (verifierB64: string, operation: SensitiveOwnership): Promise<void> => {
    const operationEpoch = sensitiveEpoch.current;
    touchActivity();
    try {
      assertSensitiveOwnership(operation);
      const userId = await api.getUserId(); assertSensitiveOwnership(operation);
      const username = await api.getUsername(); assertSensitiveOwnership(operation);
      if (userId !== operation.owner) throw new Error(tr("common.sessionDamagedTitle"));
      if (!userId || !username || !vault.isUnlocked()) throw new Error("session");
      const keys = vault.get();
      setBusy(true);
      const recoveryKey = generateRecoveryKey();
      try {
        // Use separate recovery derivation labels for sealing and verification.
        // Only the verifier leaves the device; it cannot decrypt the journal.
        const sealed = sealDataKeyForRecoveryV2(recoveryKey, keys.dataKey, userId);
        const verifierKey = recoveryVerifierKeyV2(recoveryKey);
        try {
          await api.setupRecoveryKit(
            verifierB64,
            verifierKey.toString("base64"),
            sealed.toString("base64"),
            "v2",
            () => sensitiveRequestCurrent(operation),
          );
        } finally {
          verifierKey.fill(0);
        }
        assertSensitiveOwnership(operation);
        acknowledgedPreferences.current.recovery = true;
        setRecoveryEnabled(true);
        if (sensitiveEpoch.current === operationEpoch) setRecoveryKeyShown(recoveryKitText(recoveryKey));
        recoveryKey.fill(0);
        const status = await api.recoveryStatus().catch(() => null);
        if (status && ownsSensitiveScope(operation)) setRecoverySetAt(status.set_at);
      } finally {
        recoveryKey.fill(0);
      }
    } catch {
      if (!ownsSensitiveScope(operation)) return;
      Alert.alert(tr("settings.recoveryTitle"), tr("settings.recoverySetupFailed"));
    } finally {
      if (ownsSensitiveScope(operation)) setBusy(false);
    }
  };

  const removeRecoveryKit = async (verifierB64: string, operation: SensitiveOwnership): Promise<void> => {
    touchActivity();
    try {
      assertSensitiveOwnership(operation);
      if (!vault.isUnlocked()) throw new Error("session");
      setBusy(true);
      await api.removeRecoveryKit(verifierB64, () => sensitiveRequestCurrent(operation));
      assertSensitiveOwnership(operation);
      acknowledgedPreferences.current.recovery = true;
      setRecoveryEnabled(false);
      setRecoverySetAt(null);
    } catch {
      if (!ownsSensitiveScope(operation)) return;
      Alert.alert(tr("settings.recoveryTitle"), tr("settings.recoveryRemoveFailed"));
    } finally {
      if (ownsSensitiveScope(operation)) setBusy(false);
    }
  };
  // Recovery keys are generated on-device and shown once after creation.
  const [recoveryEnabled, setRecoveryEnabled] = useState<boolean | null>(null);
  const [recoverySetAt, setRecoverySetAt] = useState<string | null>(null);
  const [recoveryKeyShown, setRecoveryKeyShown] = useState<string | null>(null);
  const sensitiveEpoch = useRef<object>({});
  useEffect(() => {
    const clearSensitive = () => {
      sensitiveEpoch.current = {};
      sensitiveSubmission.current = null;
      setRecoveryKeyShown(null); setPassword(""); setPending(null); setRotateCurrentPassword(""); setNewPassword(""); setBusy(false);
      savedAudioOwnership.current = null;
      setAudioStatus({ total: 0, needsAttention: 0 }); setSavedAudio([]);
      if (vault.canReauthenticate()) void refreshSavedAudio().catch(() => {});
    };
    let dataKey = vault.canReauthenticate() ? vault.get().dataKey : null;
    // A same-account key replacement can keep the credential epoch while
    // retiring this screen's password proof and one-time recovery disclosure.
    const vaultChange = vault.subscribe(() => {
      const next = vault.canReauthenticate() ? vault.get().dataKey : null;
      if (next !== dataKey) { dataKey = next; clearSensitive(); }
    });
    const sub = AppState.addEventListener("change", state => { if (state !== "active") clearSensitive(); });
    const blur = typeof navigation.addListener === "function" ? navigation.addListener("blur", clearSensitive) : undefined;
    return () => { sensitiveEpoch.current = {}; sub.remove(); vaultChange(); blur?.(); };
  }, [navigation]);
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
  // Check-in preferences remain readable when native reminders are unavailable.
  const [measureReminderOn, setMeasureReminderOn] = useState(false);
  const [measureInterval, setMeasureIntervalState] = useState(4);
  // The Health mirror preference (healthkit.ts) — same honesty rules.
  const [mirrorHealthOn, setMirrorHealthOn] = useState(false);
  // Biometric unlock wrap state — the section only appears when this
  // device actually has biometrics (biometricUnlock.ts quiet probe).
  const [bioSupported, setBioSupported] = useState(false);
  const [bioEnabled, setBioEnabled] = useState(false);
  React.useEffect(() => {
    void loadHapticsSetting().then(enabled => { if (!acknowledgedPreferences.current.haptics) setHaptics(enabled); });
  }, []);
  // Read the persisted theme once; missing/invalid values keep the default.
  React.useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const AsyncStorage = (await import("@react-native-async-storage/async-storage")).default;
        const stored = await AsyncStorage.getItem(themeStorageKey());
        if (!cancelled && !acknowledgedPreferences.current.theme && (stored === "dark" || stored === "light" || stored === "system")) {
          setThemeModeState(stored);
        }
        // Load language and recovery status even when no theme preference was saved.
        if (!cancelled) {
          const choice = await readLanguageChoice();
          if (!cancelled && !acknowledgedPreferences.current.language) setLanguageState(choice);
          try {
            const status = await api.recoveryStatus();
            if (!cancelled && !acknowledgedPreferences.current.recovery) {
              setRecoveryEnabled(status.enabled);
              setRecoverySetAt(status.set_at);
            }
          } catch {
            if (!cancelled && !acknowledgedPreferences.current.recovery) setRecoveryEnabled(null);
          }
        }
      } catch {
        /* non-sensitive preference; default stands */
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  // A granted Native touch can release before React commits the vault
  // subscriber's cleared password card. Bind admission to its rendered key.
  const renderedSensitiveOwnership = captureSensitiveOwnership();

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
            <Text style={themed.rowText}>{tr("settings.llmBody", {
              provider: llmProvider || tr("settings.notDisclosed"),
              retention: llmRetention || tr("settings.notDisclosed"),
              fingerprint: llmFingerprint || tr("settings.notDisclosed"),
            })}</Text>
            <Switch
              value={llmEnabled}
              disabled={busy}
              onValueChange={(enabled) => setPending({ kind: "llm", enabled })}
              trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
              accessibilityLabel={tr("settings.llmA11y")}
              accessibilityState={{ checked: llmEnabled, disabled: busy }}
            />
          </View>
          {llmStale && (
            <Text style={[themed.footnote, { color: t.colors.error }]} accessibilityRole="alert">
              {tr("settings.llmStaleNote")}
            </Text>
          )}
        </>
      )}
      {/* Voice journaling (VOICE_PLAN 2026-09-29): the mic's consent, the
          same re-authenticated standing as the LLM toggle — this is where
          recordings leave the device. Hidden entirely while meta is
          unreachable (null ≠ "not offered"); a server that answers but
          offers no transcription says so honestly. */}
      {voiceAvailable === true && (
        <>
          <Text style={themed.label}>{tr("settings.voiceLabel")}</Text>
          <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.md }]}>
            <View style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
              <Text style={themed.rowText}>{tr("settings.voiceRow")}</Text>
              <Switch
                value={voiceEnabled}
                disabled={busy}
                onValueChange={(enabled) => setPending({ kind: "voice", enabled })}
                trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
                accessibilityLabel={tr("settings.voiceA11y")}
                accessibilityState={{ checked: voiceEnabled, disabled: busy }}
              />
            </View>
            <Text style={themed.footnote}>
              {tr("settings.voiceNote", {
                provider: voiceProvider || tr("entry.voiceUnavailable"),
                retention: voiceRetention || tr("settings.notDisclosed"),
                fingerprint: voiceFingerprint || tr("settings.notDisclosed"),
              })}
            </Text>
            {voiceStale && (
              <Text style={[themed.footnote, { color: t.colors.error }]} accessibilityRole="alert">
                {tr("settings.voiceStaleNote")}
              </Text>
            )}
          </View>
        </>
      )}
      {voiceAvailable === false && (
        <Text style={themed.footnote}>{tr("settings.voiceNotOffered")}</Text>
      )}
      {pending && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>
            {pending.kind === "delete"
              ? tr("settings.reauthDeleteTitle")
              : pending.kind === "recovery-create" || pending.kind === "recovery-remove"
                ? tr("settings.reauthRecoveryTitle")
              : pending.kind === "bio"
                ? tr("settings.reauthBioTitle")
                : pending.kind === "upgrade"
                  ? tr("settings.reauthUpgradeTitle")
                  : pending.kind === "voice"
                    ? tr("settings.reauthVoiceTitle", {
                        action: tr(pending.enabled ? "settings.enableWord" : "settings.disableWord"),
                      })
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
            onChangeText={value => { if (sensitiveRequestCurrent(renderedSensitiveOwnership)) setPassword(value); }}
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

      {/* Language (2026-09-29 deep audit P2): in-app override of the
          device locale — device-level preference, applied immediately. */}
      <Text style={themed.label}>{tr("settings.languageTitle")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
        <View style={{ flexDirection: "row", gap: 8 }}>
          {(["device", "en", "es"] as LanguageChoice[]).map((choice) => {
            const choiceLabel =
              choice === "device"
                ? tr("settings.languageDevice")
                : choice === "en"
                  ? tr("settings.languageEnglish")
                  : tr("settings.languageSpanish");
            return (
              <TouchableOpacity
                key={choice}
                style={[
                  {
                    paddingHorizontal: 14,
                    alignItems: "center",
                    justifyContent: "center",
                    backgroundColor: language === choice ? t.colors.primary : t.colors.cardDeep,
                    borderRadius: t.radius.md,
                    minHeight: t.minTouch,
                  },
                ]}
                onPress={() => {
                  touchActivity();
                  acknowledgedPreferences.current.language = true;
                  setLanguageState(choice);
                  void writeLanguageChoice(choice);
                }}
                accessibilityRole="radio"
                accessibilityState={{ selected: language === choice }}
                accessibilityLabel={tr("settings.languageA11y", { choice: choiceLabel })}
              >
                <Text style={{ color: language === choice ? t.colors.onPrimary : t.colors.body, fontSize: 13 }}>
                  {choiceLabel}
                </Text>
              </TouchableOpacity>
            );
          })}
        </View>
        <Text style={[themed.rowText, { fontSize: 12 }]}>
          {tr("settings.languageNote")}
        </Text>
      </View>

      {/* Recovery kit (wave 3, 2026-09-30): the honest escape hatch from a
          forgotten password — opt-in, on-device key generation, shown
          exactly once. */}
      {audioStatus.total > 0 && <View style={{ gap: 8 }}>
        <Text style={{ color: t.colors.body }}>{tr("settings.savedAudioQueue", { count: audioStatus.total, attention: audioStatus.needsAttention })}</Text>
        <GhostButton label={tr("settings.retryAudio")} disabled={busy} onPress={() => {
          const operation = savedAudioOwnership.current;
          void (async () => {
            if (!operation || !ownsSensitiveScope(operation)) return;
            setBusy(true);
            try { const owner = await savedAudioOwner(operation); await retryAudioQueue(owner); if (operation) assertSensitiveOwnership(operation); await refreshSavedAudio(); }
            catch { if (ownsSensitiveScope(operation)) Alert.alert(tr("settings.couldNotRetryTitle"), tr("settings.couldNotRetryBody")); }
            finally { if (ownsSensitiveScope(operation)) setBusy(false); }
          })();
        }} />
        {savedAudio.map((item, index) => <View key={item.id} style={{ gap: 4 }}>
          <Text style={{ color: t.colors.body }}>{tr("settings.savedAudioItem", { number: index + 1, date: item.queuedAt ? new Date(item.queuedAt).toLocaleDateString(dateLocaleTag()) : tr("settings.recordingDateUnavailable") })}</Text>
          {item.needsAttention && <Text style={{ color: t.colors.muted }}>{tr("settings.audioNeedsAttention")}</Text>}
          <GhostButton label={tr("settings.exportAudio", { number: index + 1 })} disabled={busy} onPress={() => {
            const operation = savedAudioOwnership.current;
            void (async () => { if (!operation || !ownsSensitiveScope(operation)) return; setBusy(true); try { const owner = await savedAudioOwner(operation); await exportSavedAudio(owner, item.id); }
              catch (err) { if (ownsSensitiveScope(operation)) Alert.alert(tr("settings.exportFailedTitle"), requestFailureCopy(err)); } finally { if (ownsSensitiveScope(operation)) setBusy(false); } })();
          }} />
          <GhostButton label={tr("settings.removeAudio", { number: index + 1 })} disabled={busy} onPress={() => {
            const operation = savedAudioOwnership.current;
            Alert.alert(tr("settings.removeAudioTitle"), tr("settings.removeAudioBody"), [
              { text: tr("common.cancel"), style: "cancel" },
              { text: tr("settings.removeAudioConfirm"), style: "destructive", onPress: () => {
                void (async () => { if (!operation || !ownsSensitiveScope(operation)) return; setBusy(true); try { const owner = await savedAudioOwner(operation); await removeSavedAudio(owner, item.id, item.revision); if (operation) assertSensitiveOwnership(operation); await refreshSavedAudio(); }
                  catch (err) { if (ownsSensitiveScope(operation)) Alert.alert(tr("settings.couldNotRetryTitle"), requestFailureCopy(err)); } finally { if (ownsSensitiveScope(operation)) setBusy(false); } })();
              } },
            ]);
          }} />
        </View>)}
      </View>}
      <Text style={themed.label}>{tr("settings.recoveryTitle")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <Text style={themed.rowText}>
          {recoveryEnabled === null
            ? tr("settings.recoveryUnknown")
            : recoveryEnabled
              ? tr("settings.recoveryActiveSince", { date: (recoverySetAt ?? "").slice(0, 10) })
              : tr("settings.recoveryAbsent")}
        </Text>
        {recoveryKeyShown !== null && (
          <View style={[styles.card, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.md, gap: 6 }]}>
            <Text style={{ color: t.colors.danger, fontSize: 12, fontWeight: "700" }}>
              {tr("settings.recoveryShownOnce")}
            </Text>
            <Text selectable style={{ color: t.colors.body, fontSize: 12, fontFamily: Platform.select({ ios: "Menlo", default: "monospace" }) }}>
              {recoveryKeyShown}
            </Text>
            <Text style={{ color: t.colors.muted, fontSize: 12 }}>{tr("settings.recoveryCopyNote")}</Text>
            <PrimaryButton
              label={tr("settings.recoveryConfirmSaved")}
              onPress={() => {
                setRecoveryKeyShown(null);
                setRecoveryEnabled(true);
              }}
            />
          </View>
        )}
        {recoveryKeyShown === null && (
          <View style={{ flexDirection: "row", gap: 8, flexWrap: "wrap" }}>
            <GhostButton
              label={recoveryEnabled ? tr("settings.recoveryReplace") : tr("settings.recoveryCreate")}
              onPress={() => {
                if (recoveryEnabled) Alert.alert(tr("settings.recoveryTitle"), tr("settings.recoveryReplaceWarning"), [
                  { text: tr("common.cancel"), style: "cancel" },
                  { text: tr("settings.recoveryReplace"), onPress: () => setPending({ kind: "recovery-create" }) },
                ]);
                else setPending({ kind: "recovery-create" });
              }}
              disabled={busy}
            />
            {recoveryEnabled === true && (
              <GhostButton
                label={tr("settings.recoveryRemove")}
                onPress={() => setPending({ kind: "recovery-remove" })}
                disabled={busy}
              />
            )}
          </View>
        )}
        <Text style={{ color: t.colors.muted, fontSize: 12 }}>{tr("settings.recoveryNote")}</Text>
      </View>

      {/* Appearance & feel (2026-09-17): theme override + haptics. */}
      <Text style={themed.label}>{tr("settings.appearanceLabel")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <View style={{ flexDirection: "row", gap: 8 }}>
          {(["system", "dark", "light"] as ThemeMode[]).map((mode) => {
            // Use the localized mode name in the accessibility label.
            const modeLabel = tr(mode === "system" ? "settings.themeSystem" : mode === "dark" ? "settings.themeDark" : "settings.themeLight");
            return (
              <TouchableOpacity
                key={mode}
                style={[
                  styles.moodOptionLike,
                  {
                    backgroundColor: themeMode === mode ? t.colors.primary : t.colors.cardDeep,
                    borderRadius: t.radius.md,
                    // Keep the 44pt minimum touch target.
                    minHeight: t.minTouch,
                  },
                ]}
                onPress={() => {
                  touchActivity();
                  acknowledgedPreferences.current.theme = true;
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
              acknowledgedPreferences.current.haptics = true;
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
              ...reminderPresets(),
              // A stored custom time (never one of the presets) shows as
              // its own chip so the current choice is always visible.
              ...((reminderPresets().some((p) => p.hour === reminderTime.hour && p.minute === reminderTime.minute)
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
                      // Keep the 44pt minimum touch target.
                      minHeight: t.minTouch,
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
            {/* Audit 2026-09-28 (LOW): the reason is a catalog KEY from the
                capability seam — resolve it through tr() so the line speaks
                the app language, never raw English prose. */}
            {tr("settings.reminderUnavailableNote", { reason: reminders.reason ? tr(reminders.reason) : "" })}
          </Text>
        )}
      </View>

      {/* MBC check-in reminders (2026-09-27): an opt-in nudge to re-run a
          wellbeing questionnaire when the last one is older than the chosen
          cadence — local only, gentle by contract. */}
      <Text style={themed.label}>{tr("settings.measureReminderLabel")}</Text>
      <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
        <Text style={themed.footnote}>{tr("settings.measureReminderNote")}</Text>
        <View style={{ flexDirection: "row", alignItems: "center", gap: 10, minHeight: 40 }}>
          <Text style={themed.rowText}>{tr("settings.measureReminderRow")}</Text>
          <Switch
            value={measureReminderOn}
            disabled={!reminders.available}
            onValueChange={(on) => void toggleMeasureReminders(on)}
            trackColor={{ true: t.colors.primaryBright, false: t.colors.cardDeep }}
            accessibilityLabel={tr("settings.measureReminderA11y")}
            accessibilityState={{ checked: measureReminderOn, disabled: !reminders.available }}
          />
        </View>
        {measureReminderOn && (
          <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }} accessibilityLabel={tr("settings.measureIntervalA11y")}>
            {MEASURE_INTERVAL_WEEKS.map((weeks) => {
              const selected = measureInterval === weeks;
              const label = tr("settings.intervalWeeks", { count: weeks });
              return (
                <TouchableOpacity
                  key={weeks}
                  style={[
                    styles.timeChip,
                    {
                      backgroundColor: selected ? t.colors.primary : t.colors.cardDeep,
                      borderRadius: t.radius.md,
                      minHeight: t.minTouch,
                    },
                  ]}
                  onPress={() => void chooseMeasureInterval(weeks)}
                  accessibilityRole="radio"
                  accessibilityState={{ selected }}
                  accessibilityLabel={tr("settings.measureIntervalOptionA11y", { label })}
                >
                  <Text style={{ color: selected ? t.colors.onPrimary : t.colors.body, fontSize: 13 }}>
                    {label}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        )}
        {!reminders.available && (
          <Text style={themed.footnote}>
            {tr("settings.reminderUnavailableNote", { reason: reminders.reason ? tr(reminders.reason) : "" })}
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
            {/* Same reason-KEY resolution as the reminder note above
                (audit 2026-09-28). */}
            {tr("settings.healthMirrorUnavailableNote", { reason: health.reason ? tr(health.reason) : "" })}
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
      {/* The local safety plan (2026-09-27): encrypted on this device,
          never sent anywhere — one tap from Settings, one tap from crisis
          help. */}
      <GhostButton
        label={tr("common.makeSafetyPlan")}
        center={false}
        onPress={() => navigation.navigate("SafetyPlan")}
        accessibilityLabel={tr("settings.safetyPlanA11y")}
      />
      <GhostButton
        label={tr("settings.whyExport")}
        center={false}
        onPress={explainExportUnavailable}
        accessibilityLabel={tr("settings.whyExportA11y")}
      />
      {/* v1→v2 key-envelope upgrade (2026-09-26): shown only for accounts the
          SERVER says are v1 — the copy is honest that nothing is re-encrypted
          and the benefit is instant password changes. Unknown scheme (old or
          unreachable server) shows nothing rather than guessing. */}
      {keyScheme === "v1" && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.lg, gap: 8 }]}>
          <Text style={{ color: t.colors.text, fontSize: 15, fontWeight: "600" }}>{tr("settings.upgradeTitle")}</Text>
          <Text style={themed.footnote}>{tr("settings.upgradeBody")}</Text>
          <PrimaryButton
            label={tr("settings.upgradeButton")}
            disabled={busy}
            onPress={() => setPending({ kind: "upgrade" })}
            accessibilityLabel={tr("settings.upgradeButton")}
          />
        </View>
      )}

      <GhostButton
        label={showRotate ? tr("settings.changePasswordCancel") : tr("settings.changePasswordLabel")}
        disabled={busy}
        onPress={() => { touchActivity(); setShowRotate((open) => !open); setNewPassword(""); setRotateCurrentPassword(""); }}
      />
      {showRotate && (
        <View style={[styles.reauthCard, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.lg }]}>
          <Text style={[styles.reauthTitle, { color: t.colors.text }]}>
            {tr(keyScheme === "v2" ? "settings.changePasswordTitleV2" : "settings.changePasswordTitle")}
          </Text>
          {/* 2026-09-26: v2 accounts get the honest O(1) copy — no rekey,
              grants keep working; v1 accounts keep the rekey disclosure. */}
          <Text style={themed.footnote}>
            {tr(keyScheme === "v2" ? "settings.changePasswordBodyV2" : "settings.changePasswordBody")}
          </Text>
          {/* 2026-09-26 audit LOW: bound to rotateCurrentPassword — the
              rotation card's own state, never the re-auth card's. */}
          <TextInput
            style={themed.input}
            placeholder={tr("common.passwordPlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={rotateCurrentPassword}
            onChangeText={value => { if (sensitiveRequestCurrent(renderedSensitiveOwnership)) setRotateCurrentPassword(value); }}
            accessibilityLabel={tr("common.passwordConfirmA11y")}
            textContentType="password"
          />
          <TextInput
            style={themed.input}
            placeholder={tr("settings.newPasswordPlaceholder")}
            placeholderTextColor={t.colors.placeholder}
            secureTextEntry
            value={newPassword}
            onChangeText={value => { if (sensitiveRequestCurrent(renderedSensitiveOwnership)) setNewPassword(value); }}
            accessibilityLabel={tr("settings.newPasswordA11y")}
            textContentType="newPassword"
          />
          <PrimaryButton
            label={busy ? tr("settings.rotateWorking") : tr(keyScheme === "v2" ? "settings.changePasswordButtonV2" : "settings.changePasswordButton")}
            onPress={() => void runRotate()}
            disabled={busy || !rotateCurrentPassword || !newPassword}
            accessibilityLabel={tr(keyScheme === "v2" ? "settings.changePasswordButtonV2" : "settings.changePasswordButton")}
          />
          <GhostButton
            label={tr("common.cancel")}
            disabled={busy}
            onPress={() => { setShowRotate(false); setRotateCurrentPassword(""); setNewPassword(""); }}
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
