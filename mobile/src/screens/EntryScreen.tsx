/**
 * Daily entry: type (or paste speech-to-text output), encrypt on-device,
 * sync. Entries are encrypted before they leave the phone; the save flow
 * queues locally when offline and retries on next launch.
 *
 * Mood check-in: a one-tap row behind an "Add details (optional)"
 * disclosure above Save ("How does today feel?" and friends) — an
 * explicit pick wins over the quick text estimate, rides in the encrypted
 * payload's sentiment field, and lands in the device-local mood log.
 * Never picking is fine: the text estimate fills the log as before and the
 * payload sentiment stays null for the server's engine. The row never
 * blocks saving. The disclosure is COLLAPSED by default (2026-09-19): a
 * daily writer scrolled past ten optional rows on every write. Nothing
 * set is silently hidden — with anything picked while collapsed, a
 * "Details added: …" summary line names the set channels and expands on
 * tap; the picks themselves ride in the save exactly as before.
 *
 * Drafts survive EVERYTHING: backgrounding locks the vault and unmounts
 * this screen, but the unmount cleanup stashes any non-empty text
 * (memory-only, account-bound — see store.tsx) and the next mount restores
 * it with a small "Draft restored" chip. A half-written entry is never lost
 * to a phone call. A draft stashed AFTER mount (the Question screen's
 * "Write about this" bridge) restores through the focus listener — set into
 * an empty editor, or APPENDED below in-progress typing after a blank line:
 * the bridge never overwrites the user's words and never silently drops the
 * question.
 *
 * Save feedback is inline and quiet: "Saved ✓" / "Saved — will sync when
 * online" appear as a transient status line where the user is already
 * looking. Alerts are reserved for failures that need a decision.
 *
 * Keyboard privacy: autoCorrect/spellCheck are OFF and textContentType is
 * "none" — journal text must not train or linger in keyboard caches.
 */
import React, { useEffect, useRef, useState } from "react";
import {
  Alert,
  Keyboard,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  TouchableOpacity,
  View,
} from "react-native";
import { api, ApiError } from "../api/client";
import { encryptEntry, timeOfDayBucket } from "../crypto/MindPatternCrypto";
import { zeroize } from "../crypto/kdf";
import { vault } from "../vault";
import { useSession, stashDraft, takeStashedDraft } from "../store";
import { enqueue, flushQueue, QueueAbandonedError, QueueFullError } from "../offlineQueue";
import { localDateISO, localStreak, recordMood, recentMoods } from "../moodLog";
import { mirrorMoodCheckIn } from "../healthkit";
import {
  ACTIVITY_TAGS,
  ENERGY_OPTIONS,
  MOOD_OPTIONS,
  SLEEP_OPTIONS,
  activityTagLabel,
  localSentiment,
  optionLabel,
} from "../mood";
import { detectCrisisLanguage } from "../crisisDetect";
import { lightHaptic } from "../haptics";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { recordThresholdNotice, thresholdNoticeShown } from "../thresholdNotice";
import { newClientEntryId } from "../entryId";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone, NoticeChip } from "../components/InlineStatus";
import { MainShell } from "../components/BottomNav";
import { PROMPT_CHIPS, promptChipsFor } from "../promptChips";
import { requestFailureCopy } from "../components/errors";
import { getLocale, t as tr, dateLocaleTag } from "../strings";

/** Keeps the encrypted payload comfortably under the server's ~1 MiB cap. */
const MAX_ENTRY_CHARS = 100_000;
/** The character count stays out of the way until the cap is near. */
const SHOW_COUNT_ABOVE = 90_000;
/** How long the transient save confirmation stays on screen. */
const STATUS_MS = 2_600;

export function EntryScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { activeDays, unlockDays, touchActivity } = useSession();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [draftRestored, setDraftRestored] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  // Stryker disable next-line StringLiteral: the initial tone is unobservable — a status message only renders after showStatus set its own tone first
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("ok");
  /** Device-local signal: today's date appears in the on-device mood log.
   *  (Entries written on another device aren't in it — the chip's absence
   *  never means "you didn't write", so it's a nudge-free, calm hint.) */
  const [wroteToday, setWroteToday] = useState(false);
  /** The explicit mood check-in pick, or null (never required to save). */
  const [selectedMood, setSelectedMood] = useState<number | null>(null);
  /** Optional energy pick (2026-09-17): mood and energy are different
   *  axes; never required, cleared with the check-in after each save. */
  const [selectedEnergy, setSelectedEnergy] = useState<number | null>(null);
  /** Optional sleep-quality rating 1..5 and activity tags (payload v2). */
  const [sleepQuality, setSleepQuality] = useState<number | null>(null);
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  /** The check-in disclosure: collapsed by default (2026-09-19) — the four
   *  optional sections are opt-in screen real estate, never a toll every
   *  write pays. Expansion is view state only; picks survive collapse. */
  const [detailsOpen, setDetailsOpen] = useState(false);
  /** Current writing streak from the device-local mood log; hidden at 0
   *  (no guilt — a streak you don't have is not a debt). */
  const [streak, setStreak] = useState(0);
  /** The one-time threshold-crossing card (2026-09-19): the day the
   *  30-day ask completes finally announces itself. */
  const [patternsReady, setPatternsReady] = useState(false);
  /** Rotating gentle starters for blank-page days (never required). */
  const [chips] = useState<string[]>(() => promptChipsFor(new Date(), 3, getLocale()));
  // Refs mirror what the unmount cleanup and the double-tap guard need —
  // state alone arrives a frame too late for both.
  const textRef = useRef(text);
  const userIdRef = useRef<string | null>(null);
  const savingRef = useRef(false);
  // Set by the mount effect's cleanup: the save flow consults it in its
  // finally to honor the draft guarantee when an in-flight save dies
  // after the screen already unmounted (audit L-56).
  const unmountedRef = useRef(false);
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    textRef.current = text;
  }, [text]);

  /** Transient confirmation; replaces itself cleanly and never stacks. */
  const showStatus = (message: string, tone: InlineStatusTone) => {
    if (statusTimer.current) clearTimeout(statusTimer.current);
    setStatusTone(tone);
    setStatus(message);
    statusTimer.current = setTimeout(() => setStatus(null), STATUS_MS);
  };

  useEffect(() => {
    let cancelled = false;
    // Restore the draft a lock/background unmount stashed — only for the
    // same account it was written under (takeStashedDraft enforces
    // that), and only if the user has not already started typing: a late
    // getUserId() resolution must not clobber fresh text.
    const restoreDraftFor = (id: string) => {
      const restored = takeStashedDraft(id);
      // textRef (not state) is the latest committed text: a resolution (or
      // a focus event) that lands after the user started typing consumes
      // the stash without applying it over fresh text (one-shot).
      if (restored !== null && textRef.current === "") {
        setText(restored);
        setDraftRestored(true);
      }
    };
    api
      .getUserId()
      .then((id) => {
        if (cancelled) return;
        userIdRef.current = id;
        if (id) flushQueue(id).catch(() => {});
        if (id) {
          restoreDraftFor(id);
          // "Already wrote today" from the device-local mood log (the only
          // entry signal that needs no network round-trip).
          // Stryker disable next-line ConditionalExpression: with the vault locked, vault.get() throws inside this .then and the chain's .catch(() => {}) swallows it — recentMoods/localStreak are skipped exactly as with the guard
          if (vault.isUnlocked()) {
            recentMoods(vault.get().dataKey, id, 30)
              .then((days) => setWroteToday(days.some((d) => d.date === localDateISO())))
              .catch(() => {});
            // The streak line next to the progress bar — device-local too.
            localStreak(vault.get().dataKey, id)
              .then(setStreak)
              .catch(() => {});
          }
        }
      })
      .catch(() => {
        // The storage read failed: leaving the stash in place (instead of
        // dropping it) keeps the draft recoverable on the next mount.
      });
    // A draft stashed AFTER this screen mounted — the Question screen's
    // "Write about this" bridge — arrives while the editor is already
    // alive underneath; the focus event is the signal to pick it up.
    const focusSub = typeof navigation?.addListener === "function"
      ? (navigation.addListener("focus", () => {
          const id = userIdRef.current;
          if (!id) return;
          const bridged = takeStashedDraft(id);
          if (bridged === null) return;
          // The bridge must neither overwrite in-progress typing NOR
          // silently drop the question: empty editor → set it; non-empty →
          // append below a blank line. (Mount-time restore above keeps the
          // stricter empty-only rule — that stash is the user's OWN
          // interrupted draft, where a late resolution must not splice
          // older text under fresh typing.)
          const existing = textRef.current;
          if (existing.trim() === "") {
            setText(bridged);
          } else {
            setText(`${existing.trimEnd()}\n\n${bridged}`);
          }
          setDraftRestored(true);
        }) as (() => void) | undefined)
      : undefined;
    return () => {
      cancelled = true;
      focusSub?.();
      unmountedRef.current = true;
      if (statusTimer.current) clearTimeout(statusTimer.current);
      // THE draft guarantee: any non-empty text on unmount — background
      // lock, navigation, session expiry — is stashed for this account.
      // EXCEPT while a save is in flight (2026-09-20 audit L-56): the
      // in-flight save owns the text now — stashing here meant the
      // completed save ALSO restored as a draft, and re-saving it minted
      // a fresh clientEntryId the server's dedupe could never catch. The
      // save flow itself stashes in its finally if the entry never
      // landed (sync failed AND queueing failed after the unmount).
      const draft = textRef.current;
      const owner = userIdRef.current;
      if (owner && draft.trim() && !savingRef.current) stashDraft(owner, draft);
    };
    // NOTE (privacy hardening): this screen no longer triggers the daily
    // mini-brain recompute. That refresh SHIPS THE DATA KEY to the server
    // — after the red-team audit it is only ever sent as an explicit act
    // (the Question screen's button), never automatically after a sync.
  }, // Stryker disable next-line ArrayDeclaration: [] and ["Stryker was here"] are both referentially constant — the mount effect runs exactly once either way (test seam)
     []);

  // The threshold moment: when the server-reported active days first reach
  // the unlock threshold (and this account has never been told), show the
  // one-time card. unlockDays <= 0 (hostile/absurd metadata) never fires —
  // there was no wait to complete. The stamp is recorded when the card is
  // shown, so it can never nag; a storage read failure errs toward showing.
  useEffect(() => {
    if (unlockDays <= 0 || activeDays < unlockDays) return;
    let cancelled = false;
    void (async () => {
      const userId = userIdRef.current ?? (await api.getUserId().catch(() => null));
      if (!userId || cancelled) return;
      if (await thresholdNoticeShown(userId).catch(() => false)) return;
      if (cancelled) return;
      setPatternsReady(true);
      await recordThresholdNotice(userId).catch(() => {});
    })();
    return () => {
      cancelled = true;
    };
  }, [activeDays, unlockDays]);

  const save = async () => {
    const trimmed = text.trim();
    if (!trimmed) return;
    if (trimmed.length > MAX_ENTRY_CHARS) {
      Alert.alert(
        tr("entry.tooLongTitle"),
        tr("entry.tooLongBody", { max: MAX_ENTRY_CHARS.toLocaleString(dateLocaleTag()) }),
      );
      return;
    }
    // Double-tap guard: two presses inside one frame both pass a state-only
    // check; the ref is synchronous. The 409-dedupe on the server would hide
    // the second upload, but the user would wait on it.
    if (savingRef.current) return;
    savingRef.current = true;
    setBusy(true);
    // Crisis detection is ON-DEVICE and pre-encryption by necessity: the
    // server only ever sees ciphertext, so it cannot notice a crisis.
    // The result is never stored or transmitted — it only decides whether
    // to point at support resources after the entry is safely saved.
    // Computed BEFORE the try so every failure path below can offer support.
    const crisisLanguage = detectCrisisLanguage(trimmed);
    // The throttled support pointer is hoisted to function scope (assigned
    // once the account/date are known) so the OUTER catch's alert buttons
    // can chain it too — try and catch are separate block scopes. `landed`
    // is hoisted for the finally below (draft guarantee for the in-flight
    // window, audit L-56); the account id comes from userIdRef there.
    let maybeShowCrisisAlert: () => Promise<void> = async () => {};
    let landed = false;
    try {
      const userId = await api.getUserId();
      if (!userId) {
        // AAD-binding an entry to "" would make it permanently undecryptable.
        Alert.alert(tr("common.sessionDamagedTitle"), tr("entry.sessionDamagedBody"));
        return;
      }
      // Re-acquired AFTER the await, not before: vault.get() shares the
      // vault's key buffers, and a lock landing during the await (app
      // backgrounded, idle timeout, 401 hook) zeroizes them in place —
      // encrypting under the zeroed key would produce a blob that saves
      // "successfully" and can never be decrypted again. get() throws when
      // locked, which lands in this try's existing error path instead.
      const keys = vault.get();
      // LOCAL calendar day: the UTC day is wrong for non-UTC users in the
      // evening (it feeds entry ids, dates and the mood log).
      const today = localDateISO();
      // Never before or instead of saving: the entry is already safe
      // (synced or queued) before this dialog appears. Safe-messaging
      // tone — acknowledge, point at humans, no diagnosis.
      const showCrisisAlert = () =>
        Alert.alert(tr("entry.crisisAlertTitle"), tr("entry.crisisAlertBody"), [
          { text: tr("entry.crisisViewResources"), onPress: () => navigation.navigate("Crisis") },
          { text: tr("common.notNow"), style: "cancel" },
        ]);
      // Throttled to at most once per calendar day per account
      // (src/crisisDialog.ts): a dialog on EVERY crisis-flagged save trains
      // dismissal. The stamp records BEFORE the dialog so sequential saves
      // cannot double-fire; a storage failure fails toward showing.
      maybeShowCrisisAlert = async () => {
        if (await crisisDialogShownOn(userId, today)) return;
        await recordCrisisDialogShown(userId, today);
        showCrisisAlert();
      };
      // The explicit check-in pick, captured before the success path clears
      // it — only an explicit pick is ever mirrored OUT to the Health app
      // (the text-derived estimate stays device-local; a derived score is
      // not the user's own act and does not belong in Health).
      const moodPick = selectedMood;
      const clientEntryId = newClientEntryId(today);
      // sentiment: the explicit check-in pick rides in the encrypted
      // payload when the user made one. Without a pick it stays null — the
      // server's graded engine re-scores the text at recompute time either
      // way; the quick score below never rides in the payload.
      // M-2 (2026-09-20): a new entry is the FIRST content generation of
      // its id — encrypt under the version-bound v2 AAD and declare the
      // version to the server, which pins the AAD contract at the row.
      const { blobB64 } = encryptEntry(keys, userId, clientEntryId, trimmed, today, selectedMood, {
        energy: selectedEnergy,
        sleep: sleepQuality,
        tags: selectedTags,
        // P3 (2026-09-21): the coarse local writing window — a bucket,
        // never a clock time (the entry contract stays date-granular).
        tod: timeOfDayBucket(new Date().getHours()),
      }, 1);
      // The local mood log powers the baseline-phase trend view; it is
      // device-only metadata, encrypted under the data key, and never
      // leaves the phone. The explicit check-in wins when there is one;
      // otherwise the quick text estimate fills in, as before. The streak
      // line refreshes once the write lands.
      // Private snapshot for the ASYNC chain: recordMood/localStreak snapshot
      // the key at call time, but the localStreak continuation runs after
      // recordMood's awaits — a lock in that window would zeroize the
      // vault's shared buffer before localStreak snapshots it. This copy is
      // immune and zeroized when the chain settles.
      const dataKeyCopy = Buffer.from(keys.dataKey);
      void recordMood(dataKeyCopy, userId, today, selectedMood ?? localSentiment(trimmed), selectedEnergy ?? undefined)
        .then(() => localStreak(dataKeyCopy, userId))
        .then(setStreak)
        .catch(() => {})
        .finally(() => zeroize(dataKeyCopy));
      let queuedOffline = false;
      try {
        await api.createEntry(clientEntryId, blobB64, today, 1);
        landed = true;
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {
          // Session expired: the client's unauthorized hook has already
          // locked the vault app-wide (vault.lock() here is belt-and-braces
          // for callers bypassing the hook — the lock swaps the whole
          // screen stack, and this screen unmounts with it). The draft is
          // stashed for the re-unlock remount — it is NOT lost.
          stashDraft(userId, trimmed);
          landed = true; // already stashed for the re-unlock remount
          vault.lock();
          Alert.alert(tr("common.sessionExpiredTitle"), tr("entry.sessionExpiredBody"), [
            { text: tr("common.ok"), onPress: () => { if (crisisLanguage) void maybeShowCrisisAlert(); } },
          ]);
          return;
        }
        if (err instanceof ApiError && err.status === 422) {
          // The server permanently rejects this blob; queueing it would
          // poison the offline queue with an entry that can never sync. No
          // server detail text in the dialog — just the honest outcome.
          Alert.alert(tr("entry.notAcceptedTitle"), tr("entry.notAcceptedBody"), [
            { text: tr("common.ok"), onPress: () => { if (crisisLanguage) void maybeShowCrisisAlert(); } },
          ]);
          return;
        }
        // Offline, 5xx or throttled: queue the SAME encrypted entry —
        // the AAD is already bound to this clientEntryId and this account.
        try {
          await enqueue({ userId, clientEntryId, blobB64, entryDate: today });
          queuedOffline = true;
          landed = true;
        } catch (queueErr) {
          if (queueErr instanceof QueueFullError) {
            // The entry text is still on screen — a crisis-flagged entry
            // that could not be queued must STILL point at support.
            Alert.alert(
              tr("entry.queueFullTitle"),
              tr("entry.queueFullBody"),
              [{ text: tr("common.ok"), onPress: () => { if (crisisLanguage) void maybeShowCrisisAlert(); } }],
            );
            return;
          }
          if (queueErr instanceof QueueAbandonedError) {
            // The queue was wiped (sign-out / account deletion) mid-save:
            // the entry is NOT saved. Be loud — no "Saved offline", and the
            // draft stays on screen. A crisis-flagged entry that went
            // nowhere must STILL point at support (throttled like every
            // other path): the crisis is on screen even if the save isn't.
            Alert.alert(
              tr("entry.queueAbandonedTitle"),
              tr("entry.queueAbandonedBody"),
              [{ text: tr("common.ok"), onPress: () => { if (crisisLanguage) void maybeShowCrisisAlert(); } }],
            );
            return;
          }
          throw queueErr;
        }
      }
      setText("");
      setDraftRestored(false);
      setSelectedMood(null); // the check-in is per entry — never carry it over
      setSelectedEnergy(null);
      setSleepQuality(null);
      setSelectedTags([]);
      lightHaptic(); // quiet success pulse (respects the haptics setting)
      setWroteToday(true); // this save just wrote today
      // The save-feedback fix: BOTH outcomes are a quiet inline line now.
      // (Hoisted so the "neutral" literal sits alone on its own line:
      //  InlineStatus colors every non-"ok" tone with the same muted
      //  color, so "neutral" and "" are visually identical — while the
      //  "ok" literal on the showStatus line below stays live.)
      // Stryker disable next-line StringLiteral: InlineStatus colors every non-"ok" tone with the same muted color — "neutral" and "" render identically
      const offlineTone: InlineStatusTone = "neutral";
      showStatus(queuedOffline ? tr("entry.savedOffline") : tr("entry.saved"), queuedOffline ? offlineTone : "ok");
      // HealthKit State of Mind mirror (2026-09-19): fire-and-forget, only
      // AFTER the entry is safely saved (synced or queued), only for an
      // explicit check-in pick, only while the vault is unlocked, and only
      // when the per-account mirrorMoodToHealth pref is on (checked inside
      // mirrorMoodCheckIn). It can never block or fail the entry save:
      // every path in the seam returns false instead of throwing, and the
      // catch is the explicit guarantee of that here.
      if (moodPick !== null && vault.isUnlocked()) {
        void mirrorMoodCheckIn(userId, moodPick, today).catch(() => {});
      }
      if (crisisLanguage) await maybeShowCrisisAlert();
    } catch (err) {
      // The entry went nowhere (unsaved) — a crisis-flagged entry must
      // STILL point at support here, exactly like the queue-failure paths.
      Alert.alert(tr("entry.couldNotSaveTitle"), requestFailureCopy(err), [
        { text: tr("common.ok"), onPress: () => { if (crisisLanguage) void maybeShowCrisisAlert(); } },
      ]);
    } finally {
      savingRef.current = false;
      setBusy(false);
      // Draft guarantee for the in-flight window (audit L-56): the unmount
      // cleanup skipped stashing while this save owned the text. If the
      // screen went away AND the entry never landed (not synced, not
      // queued, not already stashed by the 401 path), stash it here —
      // a failed save must never eat the user's words either.
      const owner = userIdRef.current;
      if (unmountedRef.current && !landed && owner) {
        stashDraft(owner, trimmed);
      }
    }
  };

  // unlockDays comes from server metadata (clamped in the store, but a
  // hostile value of 0 must never produce NaN/Infinity styling here).
  const progress = unlockDays > 0 ? Math.min(1, activeDays / unlockDays) : 1;

  // Which check-in channels hold a pick, in display order — the collapsed
  // summary names them so nothing is ever silently set behind the fold.
  const detailChannels: string[] = [];
  if (selectedMood !== null) detailChannels.push(tr("entry.channelMood"));
  if (selectedEnergy !== null) detailChannels.push(tr("entry.channelEnergy"));
  if (sleepQuality !== null) detailChannels.push(tr("entry.channelSleep"));
  if (selectedTags.length > 0) detailChannels.push(tr("entry.channelTags"));

  return (
    <MainShell current="Entry" navigation={navigation} keyboard keyboardBehavior={Platform.OS === "ios" ? "padding" : undefined}>
      <ScrollView
        style={[styles.container, { backgroundColor: t.colors.bg }]}
        contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
        keyboardDismissMode="on-drag"
        keyboardShouldPersistTaps="handled"
      >
        <View style={{ gap: 6 }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {activeDays >= unlockDays
              ? tr("entry.patternsUnlocked")
              : tr("entry.daysToPatterns", { active: activeDays, total: unlockDays })}
          </Text>
          <View
            style={[styles.progressTrack, { backgroundColor: t.colors.card, borderRadius: t.radius.sm }]}
            accessibilityRole="progressbar"
            accessibilityLabel={tr("entry.progressA11y", { done: Math.min(activeDays, unlockDays), total: unlockDays })}
            accessibilityValue={{ min: 0, max: unlockDays, now: Math.min(activeDays, unlockDays) }}
          >
            <View
              style={[
                styles.progressFill,
                { backgroundColor: t.colors.primaryBright, borderRadius: t.radius.sm, width: `${progress * 100}%` },
              ]}
            />
          </View>
          {streak > 0 && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
              {streak === 1 ? tr("common.streakOne", { count: streak }) : tr("common.streakMany", { count: streak })}
            </Text>
          )}
        </View>
        {wroteToday && (
          <NoticeChip text={tr("entry.wroteToday")} accessibilityLabel={tr("entry.wroteToday")} />
        )}
        {draftRestored && <NoticeChip text={tr("entry.draftRestored")} />}
        {patternsReady && (
          // The payoff for thirty days of discipline — calm, honest about
          // sparseness (patterns still have to EARN their way in), and one
          // hop to the Patterns screen. Shown once per account, ever.
          <View style={[styles.readyCard, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
            <Text style={{ color: t.colors.text, fontSize: t.type.body.fontSize, lineHeight: 22 }}>
              {tr("entry.readyBody", { days: unlockDays })}
            </Text>
            <View style={{ flexDirection: "row", gap: 8 }}>
              <GhostButton
                label={tr("entry.seePatterns")}
                center={false}
                onPress={() => navigation.navigate("Insights")}
                accessibilityLabel={tr("entry.seePatternsA11y")}
              />
              <GhostButton
                label={tr("common.notNow")}
                center={false}
                onPress={() => setPatternsReady(false)}
                accessibilityLabel={tr("entry.dismissReadyA11y")}
              />
            </View>
          </View>
        )}
        {text.trim() === "" && chips.length > 0 && (
          // Blank-page help: three gentle starters, deterministic per day.
          // Tapping one only seeds the editor — nothing is auto-written.
          <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
            {chips.map((chip) => (
              <TouchableOpacity
                key={chip}
                // Fix 23 (2026-09-21): chips meet the app's own 44pt touch
                // contract (t.minTouch) — they measured ~33pt before.
                style={[styles.chip, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.md, minHeight: t.minTouch, justifyContent: "center" }]}
                onPress={() => {
                  touchActivity();
                  setText(`${chip} `);
                }}
                accessibilityRole="button"
                accessibilityLabel={tr("entry.startWith", { chip })}
              >
                <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize }}>{chip}</Text>
              </TouchableOpacity>
            ))}
          </View>
        )}
        <TextInput
          style={[
            styles.input,
            {
              backgroundColor: t.colors.card,
              color: t.colors.text,
              borderRadius: t.radius.lg,
              padding: t.spacing.lg,
              fontSize: t.type.bodyLarge.fontSize,
            },
          ]}
          multiline
          placeholder={tr("entry.placeholder")}
          placeholderTextColor={t.colors.placeholder}
          value={text}
          editable={!busy} // text typed mid-save must not be wiped by the clear
          onChangeText={(next) => {
            touchActivity(); // typing resets the inactivity auto-lock
            if (draftRestored) setDraftRestored(false);
            setText(next);
          }}
          accessibilityLabel={tr("entry.journalA11y")}
          // Privacy: keep journal text out of keyboard suggestion caches.
          autoCorrect={false}
          spellCheck={false}
          autoCapitalize="sentences"
          textContentType="none"
        />
        {text.length > SHOW_COUNT_ABOVE && (
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, textAlign: "right" }}>
            {tr("entry.charCount", {
              current: text.length.toLocaleString(dateLocaleTag()),
              max: MAX_ENTRY_CHARS.toLocaleString(dateLocaleTag()),
            })}
          </Text>
        )}
        {/* Keyboard-dismiss stays with the editor it dismisses. */}
        {text.length > 0 && (
          <GhostButton label={tr("entry.hideKeyboard")} onPress={() => Keyboard.dismiss()} center={false} />
        )}
        {/* The optional check-ins behind one disclosure (collapsed by
            default). Save sits directly under it — writing is the daily
            act; the details are an occasional one. */}
        <TouchableOpacity
          style={[styles.disclosure, { backgroundColor: t.colors.cardDeep, borderRadius: t.radius.md, minHeight: t.minTouch }]}
          onPress={() => {
            touchActivity();
            setDetailsOpen(!detailsOpen);
          }}
          accessibilityRole="button"
          accessibilityState={{ expanded: detailsOpen }}
          accessibilityLabel={detailsOpen ? tr("entry.hideDetails") : tr("entry.showDetails")}
        >
          <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize, fontWeight: "600" }}>
            {detailsOpen ? tr("entry.hideDetails") : tr("entry.showDetails")}
          </Text>
        </TouchableOpacity>
        {!detailsOpen && detailChannels.length > 0 && (
          // The quiet guarantee that collapse never hides a live pick: the
          // summary names exactly the set channels and itself expands.
          <TouchableOpacity
            onPress={() => {
              touchActivity();
              setDetailsOpen(true);
            }}
            accessibilityRole="button"
            accessibilityLabel={tr("entry.detailsAddedA11y", { channels: detailChannels.join(", ") })}
          >
            <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
              {tr("entry.detailsAdded", { channels: detailChannels.join(", ") })}
            </Text>
          </TouchableOpacity>
        )}
        {detailsOpen && (
          <>
        {/* The explicit check-in: one tap, radio semantics, never required.
            Tapping the selected option again clears it (back to the text
            estimate) — changing your mind costs nothing. */}
        <View style={{ gap: t.spacing.sm }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {tr("entry.moodQuestion")}
          </Text>
          <View style={styles.moodRow} accessibilityLabel={tr("entry.moodCheckInA11y")}>
            {MOOD_OPTIONS.map((option) => {
              const selected = selectedMood === option.value;
              return (
                <TouchableOpacity
                  key={option.label}
                  style={[
                    styles.moodOption,
                    {
                      backgroundColor: selected ? t.colors.primary : t.colors.card,
                      borderRadius: t.radius.md,
                      minHeight: t.minTouch,
                    },
                  ]}
                  onPress={() => {
                    touchActivity();
                    lightHaptic();
                    setSelectedMood(selected ? null : option.value);
                  }}
                  accessibilityRole="radio"
                  accessibilityState={{ selected }}
                  accessibilityLabel={tr("entry.moodOptionA11y", { label: optionLabel(option) })}
                >
                  <Text
                    maxFontSizeMultiplier={1.3}
                    style={{
                      color: selected ? t.colors.onPrimary : t.colors.body,
                      fontSize: t.type.bodySmall.fontSize,
                    }}
                  >
                    {optionLabel(option)}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </View>
        <View style={{ gap: t.spacing.sm }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {tr("entry.energyQuestion")}
          </Text>
          <View style={styles.moodRow} accessibilityLabel={tr("entry.energyCheckInA11y")}>
            {ENERGY_OPTIONS.map((option) => {
              const selected = selectedEnergy === option.value;
              return (
                <TouchableOpacity
                  key={option.label}
                  style={[
                    styles.moodOption,
                    {
                      backgroundColor: selected ? t.colors.primary : t.colors.card,
                      borderRadius: t.radius.md,
                      minHeight: t.minTouch,
                    },
                  ]}
                  onPress={() => {
                    touchActivity();
                    setSelectedEnergy(selected ? null : option.value);
                  }}
                  accessibilityRole="radio"
                  accessibilityState={{ selected }}
                  accessibilityLabel={tr("entry.energyOptionA11y", { label: optionLabel(option) })}
                >
                  <Text
                    style={{
                      color: selected ? t.colors.onPrimary : t.colors.body,
                      fontSize: t.type.bodySmall.fontSize,
                    }}
                  >
                    {optionLabel(option)}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </View>
        <View style={{ gap: t.spacing.sm }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {tr("entry.sleepQuestion")}
          </Text>
          <View style={styles.moodRow} accessibilityLabel={tr("entry.sleepA11y")}>
            {SLEEP_OPTIONS.map((option) => {
              const selected = sleepQuality === option.value;
              return (
                <TouchableOpacity
                  key={option.label}
                  style={[
                    styles.moodOption,
                    {
                      backgroundColor: selected ? t.colors.primary : t.colors.card,
                      borderRadius: t.radius.md,
                      // Fix 23 (2026-09-21): sleep options met the 44pt
                      // touch contract like their mood/energy siblings
                      // (they measured 40pt before).
                      minHeight: t.minTouch,
                    },
                  ]}
                  onPress={() => {
                    touchActivity();
                    lightHaptic();
                    setSleepQuality(selected ? null : option.value);
                  }}
                  accessibilityRole="radio"
                  accessibilityState={{ selected }}
                  accessibilityLabel={tr("entry.sleepOptionA11y", { label: optionLabel(option) })}
                >
                  <Text
                    maxFontSizeMultiplier={1.3}
                    style={{
                      color: selected ? t.colors.onPrimary : t.colors.body,
                      fontSize: t.type.bodySmall.fontSize,
                    }}
                  >
                    {optionLabel(option)}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </View>
        <View style={{ gap: t.spacing.sm }}>
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {tr("entry.tagsQuestion")}
          </Text>
          <View style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }} accessibilityLabel={tr("entry.tagsA11y")}>
            {ACTIVITY_TAGS.map((tag) => {
              const selected = selectedTags.includes(tag);
              return (
                <TouchableOpacity
                  key={tag}
                  style={[styles.chip, { backgroundColor: selected ? t.colors.primary : t.colors.cardDeep, borderRadius: t.radius.md, minHeight: t.minTouch, justifyContent: "center" }]}
                  onPress={() => {
                    touchActivity();
                    setSelectedTags(selected ? selectedTags.filter((x) => x !== tag) : [...selectedTags, tag]);
                  }}
                  accessibilityRole="checkbox"
                  accessibilityState={{ checked: selected }}
                  accessibilityLabel={tr("entry.tagA11y", { tag: activityTagLabel(tag) })}
                >
                  <Text
                    maxFontSizeMultiplier={1.3}
                    style={{ color: selected ? t.colors.onPrimary : t.colors.body, fontSize: t.type.bodySmall.fontSize }}
                  >
                    {activityTagLabel(tag)}
                  </Text>
                </TouchableOpacity>
              );
            })}
          </View>
        </View>
          </>
        )}
        <PrimaryButton label={tr("entry.save")} onPress={save} disabled={!text.trim()} busy={busy} />
        <InlineStatus message={status} tone={statusTone} />
      </ScrollView>
    </MainShell>
  );
}

const styles = StyleSheet.create({
  flex: { flex: 1 },
  container: { flex: 1 },
  progressTrack: { height: 6, overflow: "hidden" },
  progressFill: { height: 6 },
  // Autogrowing multiline: a modest floor, no ceiling — the box grows with
  // the entry instead of forcing a fixed 220pt frame.
  input: { minHeight: 140, textAlignVertical: "top" },
  moodRow: { flexDirection: "row", gap: 8 },
  moodOption: { flex: 1, alignItems: "center", justifyContent: "center", paddingVertical: 10 },
  disclosure: { alignItems: "center", justifyContent: "center" },
  chip: { paddingHorizontal: 12, paddingVertical: 8 },
  readyCard: { padding: 18, gap: 12 },
});
