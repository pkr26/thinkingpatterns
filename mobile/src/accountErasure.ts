/** Durable, retryable local cleanup after the server confirms deletion.
 * Every cleanup runs even when another fails. No account key is required. */
import { secureStore } from "./secureStore";
import { localWriteScopeEpoch, commitLocalErasureWrite } from "./localWriteGuard";
import AsyncStorage from "@react-native-async-storage/async-storage";
import { api, canonicalOrigin, getBaseUrl } from "./api/client";
import { clearAudioQueue, abortInFlightAudioFlush } from "./audioQueue";
import { clearQueue, abortInFlightFlush } from "./offlineQueue";
import { clearLocalRekey, markAccountDeleted, waitLocalWriteCommits } from "./localRekey";
import { clearJournalDraft } from "./journalDraft";
import { clearSafetyPlan } from "./safetyPlan";
import { erasePendingMeasure } from "./pendingMeasure";
import { clearMoodLog } from "./moodLog";
import { eraseFeedback } from "./questionFeedback";
import { clearRecomputeStamp } from "./brainSync";
import { clearUnlockProof } from "./unlockProof";
import { clearKeyShipConsent } from "./components/keyConsent";
import { clearOnboardingSeen } from "./onboarding";
import { clearCrisisDialogStamp } from "./crisisDialog";
import { clearThresholdNotice } from "./thresholdNotice";
import { clearReminderPrefs } from "./reminders";
import { clearMeasureReminderPrefs, clearLastMeasureDate } from "./measureReminders";
import { clearMoodMirrorPref } from "./healthkit";
import { eraseBiometricUnlock } from "./biometricUnlock";
import { forgetAllEntryVersions } from "./entryVersions";
import { forgetAnalysisGeneration } from "./stateSeqGuard";
import { eraseUnlockFailures } from "./unlockBackoff";
import { cancelDailyReminder, cancelMeasureReminder } from "./nativeFeatures";
import { ACCOUNT_STORAGE_PREFIX, accountStorageKey, accountStorageKeysForOwner } from "./accountStorage";
import { scrubVoiceScratchForOwner } from "./audio/voiceScratch";
const PREFIX = ACCOUNT_STORAGE_PREFIX.erasure;
interface Erasure { userId: string; username: string | null; origin: string }
const keyFor = (job: Erasure) => accountStorageKey.erasure(job.origin, job.userId);
export async function eraseDeletedAccountLocals(userId: string, username: string | null, options: { origin?: string; preserveSession?: boolean } = {}): Promise<string[]> {
  const epoch = localWriteScopeEpoch();
  markAccountDeleted(userId);
  const origin = options.origin ?? await getBaseUrl();
  if (epoch !== localWriteScopeEpoch()) return ["server scope changed"];
  const job: Erasure = { userId, username, origin: canonicalOrigin(origin) };
  abortInFlightFlush(); abortInFlightAudioFlush();
  let checkpointFailed = false;
  try { await commitLocalErasureWrite(userId, epoch, () => secureStore.setItem(keyFor(job), JSON.stringify(job))); } catch { checkpointFailed = true; }
  const failures = await cleanup(job, { epoch, preserveSession: options.preserveSession });
  return checkpointFailed ? ["cleanup checkpoint", ...failures] : failures;
}
async function cleanup(job: Erasure, options: { epoch?: number; preserveSession?: boolean } = {}): Promise<string[]> {
  let epoch = options.epoch ?? localWriteScopeEpoch();
  if (canonicalOrigin(await getBaseUrl()) !== job.origin || epoch !== localWriteScopeEpoch()) return ["server scope changed"];
  const { userId, username } = job;
  markAccountDeleted(userId);
  // Credential retirement is independent of feature cleanup. A failed
  // notification/file/key deletion keeps this encrypted checkpoint, but
  // can never keep (or restore) an authenticated deleted-account tuple.
  let sessionFailed = false;
  try { await api.retireDeletedSession(userId); }
  catch { sessionFailed = true; }
  epoch = localWriteScopeEpoch();
  const check = () => { if (epoch !== localWriteScopeEpoch()) throw new Error("The account/server changed during local erasure"); };
  await waitLocalWriteCommits(userId);
  const currentOwner = await api.getUserId().catch(() => null);
  if (epoch !== localWriteScopeEpoch()) return ["account scope changed"];
  // clearLocalRekey drains existing commits itself, before tracking its own
  // deletion. Do not put that drain inside a tracked operation (self-wait).
  let rotationFailed = false;
  try { check(); await clearLocalRekey(userId); check(); } catch { rotationFailed = true; }
  const tasks: Array<[string, () => Promise<unknown>]> = [
    ["recordings", () => clearAudioQueue(userId)], ["entries", () => clearQueue(userId)],
    ["journal draft", () => clearJournalDraft(userId)],
    ["safety plan", () => clearSafetyPlan(userId)], ["completed check-in", () => erasePendingMeasure(userId)],
    ["mood log", () => clearMoodLog(userId)], ["feedback", () => eraseFeedback(userId)],
    ["recompute stamp", () => clearRecomputeStamp(userId)], ["unlock proof", () => clearUnlockProof(userId)],
    ["key sharing consent", () => clearKeyShipConsent(userId)], ["onboarding", () => clearOnboardingSeen(userId)],
    ["crisis dialog stamp", () => clearCrisisDialogStamp(userId)], ["threshold notice", () => clearThresholdNotice(userId)],
    ["reminder preferences", () => clearReminderPrefs(userId)], ["check-in preferences", () => clearMeasureReminderPrefs(userId)],
    ["check-in cadence", () => clearLastMeasureDate(userId)], ["health preference", () => clearMoodMirrorPref(userId)],
    ["biometric key", () => eraseBiometricUnlock(userId)], ["entry guards", () => forgetAllEntryVersions(userId)],
    ["analysis guard", () => forgetAnalysisGeneration(userId)], ["voice scratch", () => scrubVoiceScratchForOwner(userId)],

  ];
  const requireCancellation = async (cancel: () => Promise<boolean>): Promise<void> => {
    if (!await cancel()) throw new Error("Notification cancellation could not be verified");
  };
  if (!currentOwner || currentOwner === userId) tasks.push(["daily notification", () => requireCancellation(cancelDailyReminder)], ["check-in notification", () => requireCancellation(cancelMeasureReminder)]);
  if (username) tasks.push(["salt cache", () => api.clearCachedSalt(username)], ["key-envelope cache", () => api.clearCachedKeyEnvelope(username)], ["unlock failures", () => eraseUnlockFailures(username)]);
  const results = await Promise.allSettled(tasks.map(([, run]) => Promise.resolve().then(async () => {
    check(); await commitLocalErasureWrite(userId, epoch, run); check();
  })));
  const failed = results.flatMap((result, i) => result.status === "rejected" ? [tasks[i]![0]] : []);
  if (sessionFailed) failed.push("deleted-account session");
  if (rotationFailed) failed.push("key rotation checkpoint");
  // Guard clear helpers intentionally tolerate transient failures; verify
  // their physical slots independently before declaring local erasure done.
  try { check(); await commitLocalErasureWrite(userId, epoch, () => AsyncStorage.multiRemove([accountStorageKey.entryVersions(userId), accountStorageKey.entryV2Bound(userId), accountStorageKey.stateSequence(userId)])); check(); }
  catch { failed.push("persisted guards"); }
  // Registry-backed final sweep: feature-specific helpers handle native
  // side effects (files, Keychain, notifications), while this guarantees a
  // newly registered account slot cannot be forgotten by the checklist.
  try {
    check();
    const remaining = accountStorageKeysForOwner(await AsyncStorage.getAllKeys(), userId)
      .filter(key => key !== keyFor(job));
    if (remaining.length > 0) {
      await commitLocalErasureWrite(userId, epoch, () => AsyncStorage.multiRemove(remaining));
    }
    check();
  } catch { failed.push("account storage inventory"); }
  if (failed.length === 0) {
    try { check(); await commitLocalErasureWrite(userId, epoch, () => AsyncStorage.removeItem(keyFor(job))); check(); }
    catch { failed.push("cleanup checkpoint"); }
  }
  return failed;
}
export async function retryPendingAccountErasures(): Promise<number> {
  for (const key of (await AsyncStorage.getAllKeys()).filter(k => k.startsWith(PREFIX))) {
    try {
      const raw = await secureStore.getItem(key); if (!raw) continue;
      const job = JSON.parse(raw) as Erasure;
      if (typeof job.userId !== "string" || typeof job.origin !== "string" || !(typeof job.username === "string" || job.username === null)) continue;
      if (keyFor(job) !== key) continue;
      await cleanup(job);
    } catch { /* Keep the job so a later start can retry all remaining work. */ }
  }
  return (await AsyncStorage.getAllKeys()).filter(k => k.startsWith(PREFIX)).length;
}
