/**
 * The daily journal editor (WEB_PLAN P4.1). Everything happens on-device
 * first: the crisis dialog tier runs PRE-encryption over what was just
 * typed (throttled to once per account-day); the mood check-in and streak
 * live in the device-local encrypted mood log. On save, the payload is
 * encrypted and either uploaded or parked in the ciphertext-only offline
 * queue (open-tab offline, WEB_PLAN D-6).
 *
 * H-5 (audit 2026-09-26): the encrypted payload's `sentiment` slot is the
 * user's EXPLICIT self-report — backend brain.py treats it as "the user's
 * own report, never a translation guess" and therapists read it. Only an
 * explicit mood pick rides in the payload (null otherwise, mobile
 * EntryScreen parity); the machine-derived sentimentScore stays
 * device-local (the on-device read line and the mood-log fallback).
 *
 * Drafts are memory-only: no plaintext at rest, ever (disclosed in the UI).
 */
import { useEffect, useMemo, useState } from "react";
import { api } from "../api/client";
import { encryptEntry, timeOfDayBucket } from "../crypto/patient";
import { detectCrisisLanguage } from "../crisisDetect";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { localDateISO } from "../dates";
import { newClientEntryId } from "../entryId";
import { recordMood, localStreak } from "../moodLog";
import { ENERGY_OPTIONS, MOOD_OPTIONS, SLEEP_OPTIONS, ACTIVITY_TAGS, activityTagLabel, optionLabel } from "../mood";
import { enqueue, queueLength } from "../offlineQueue";
import { promptChipsFor } from "../promptChips";
import { isOnline } from "../platform";
import { detectLanguage, sentimentScore } from "../brain/sentiment";
import { getLocale, t } from "../strings";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Note, TextArea } from "../ui";

export type SaveResult = "sent" | "queued";

export function EntryView(props: { onSaved: (result: SaveResult, date: string) => void }): React.JSX.Element {
  const [text, setText] = useState("");
  const [moodPick, setMoodPick] = useState<number | null>(null);
  const [energyPick, setEnergyPick] = useState<number | null>(null);
  const [sleepPick, setSleepPick] = useState<number | null>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [crisisPrompt, setCrisisPrompt] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [streak, setStreak] = useState<number | null>(null);
  const [queuedCount, setQueuedCount] = useState(0);

  const userId = vault.ownerUserId();
  // The on-device read is a display-only estimate — it never rides in the
  // payload (H-5); only an explicit pick does.
  const sentiment = useMemo(
    () => (text.trim() ? sentimentScore(text, detectLanguage(text)) : null),
    [text],
  );
  // E-3 parity: chips are seed text for the user's own journal — they must
  // follow the app locale, not default to English.
  const chips = useMemo(() => promptChipsFor(new Date(), 3, getLocale()), []);

  // The streak is device-local value (never synced) — load once per mount.
  useEffect(() => {
    if (!userId || !vault.isUnlocked()) return;
    void localStreak(vault.get().dataKey, userId).then(setStreak).catch(() => undefined);
    void queueLength(userId).then(setQueuedCount).catch(() => undefined);
  }, [userId]);

  const toggleTag = (tag: string): void => {
    setTags((current) => (current.includes(tag) ? current.filter((x) => x !== tag) : [...current, tag]));
  };

  const save = async (): Promise<void> => {
    if (!text.trim()) {
      setError(t("entry.empty"));
      return;
    }
    const keys = vault.get();
    const owner = vault.ownerUserId();
    if (!owner) {
      setError(t("common.sessionLocked"));
      return;
    }
    const date = localDateISO();
    // The crisis dialog tier runs PRE-encryption, on what was just typed:
    // the resource prompt must precede any encrypt/send call. Throttled to
    // once per (account, calendar day) — LOW c (audit 2026-09-26), mobile
    // crisisDialog parity: a prompt on every draft trains dismissal. The
    // stamp records BEFORE the prompt so sequential saves cannot
    // double-fire; a storage failure fails toward showing.
    if (detectCrisisLanguage(text) && !crisisPrompt) {
      const shownToday = await crisisDialogShownOn(owner, date).catch(() => false);
      if (!shownToday) {
        await recordCrisisDialogShown(owner, date).catch(() => undefined);
        setCrisisPrompt(true);
        return; // the user confirms once; the next Save proceeds
      }
      // Already acknowledged today (or the stamp is unreadable): the save
      // proceeds without re-prompting.
    }
    setBusy(true);
    setError("");
    try {
      const entryDate = date; // WEB_PLAN D-7: creation is today-only
      const clientEntryId = newClientEntryId(entryDate);
      const createdAt = new Date().toISOString();
      // H-5 (audit 2026-09-26): ONLY the explicit pick rides in the
      // encrypted payload's sentiment slot — null when no pick was made.
      // The machine estimate is never written where the backend/therapist
      // would read it as the user's own report.
      const { blobB64 } = await encryptEntry(
        keys.dataKey,
        owner,
        clientEntryId,
        text,
        createdAt,
        moodPick,
        {
          ...(energyPick !== null ? { energy: energyPick } : {}),
          ...(sleepPick !== null ? { sleep: sleepPick } : {}),
          ...(tags.length > 0 ? { tags } : {}),
          tod: timeOfDayBucket(new Date().getHours()),
        },
        1,
      );
      // The mood log is device-local metadata recorded on EVERY save
      // (mobile EntryScreen parity): the explicit pick wins, the quick
      // text estimate fills in when there is none.
      await recordMood(keys.dataKey, owner, date, moodPick ?? sentimentScore(text, detectLanguage(text)), energyPick).catch(() => undefined);

      let result: SaveResult = "queued";
      if (isOnline()) {
        try {
          await api.createEntry(clientEntryId, blobB64, entryDate, 1);
          result = "sent";
        } catch {
          // EVERY failure while online parks the entry in the queue —
          // including a 409 (audit 2026-09-25): this id carries 72 random
          // bits, so a genuine duplicate is practically impossible, and an
          // unverified "already exists" is exactly the lying-server case
          // the queue's M-5 GET-verification exists to referee. The entry
          // stays safe locally either way; the queue proves or refutes the
          // 409 before dropping anything.
          await enqueue({ userId: owner, clientEntryId, blobB64, entryDate });
        }
      } else {
        await enqueue({ userId: owner, clientEntryId, blobB64, entryDate });
      }
      setText("");
      setMoodPick(null);
      setEnergyPick(null);
      setSleepPick(null);
      setTags([]);
      setCrisisPrompt(false);
      props.onSaved(result, date);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("entry.couldNotSave"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {crisisPrompt && (
        <Card title={t("entry.crisisPromptTitle")}>
          <Note tone="danger">{t("entry.crisisPromptBody")}</Note>
          <Note tone="muted">{t("entry.crisisPromptProceed")}</Note>
        </Card>
      )}
      <Card title={t("entry.title")}>
        {streak !== null && streak > 0 && <Note role="status">{t(streak === 1 ? "common.streakOne" : "common.streakMany", { count: streak })}</Note>}
        {queuedCount > 0 && <Note tone="warn">{t(queuedCount === 1 ? "entry.queuedOne" : "entry.queuedMany", { count: queuedCount })}</Note>}
        <TextArea
          label={t("entry.question")}
          value={text}
          onChange={setText}
          placeholder={t("entry.placeholderWeb")}
          rows={8}
        />
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {chips.map((chip) => (
            <Button key={chip} label={chip} small onPress={() => setText(`${text}${text && !text.endsWith(" ") ? " " : ""}${chip} `)} />
          ))}
        </div>
        {sentiment !== null && (
          <Note tone="muted">{t("entry.onDeviceRead", { leaning: sentiment > 0.05 ? t("entry.leanLighter") : sentiment < -0.05 ? t("entry.leanHeavier") : t("entry.leanEven") })}</Note>
        )}

        <Button label={detailsOpen ? t("entry.hideDetails") : t("entry.showDetailsWeb")} onPress={() => setDetailsOpen(!detailsOpen)} small />
        {detailsOpen && (
          <>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {MOOD_OPTIONS.map((option) => (
                <Button
                  key={option.label}
                  label={optionLabel(option)}
                  small
                  danger={moodPick === option.value}
                  onPress={() => setMoodPick(moodPick === option.value ? null : option.value)}
                />
              ))}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {ENERGY_OPTIONS.map((option) => (
                <Button
                  key={option.label}
                  label={optionLabel(option)}
                  small
                  danger={energyPick === option.value}
                  onPress={() => setEnergyPick(energyPick === option.value ? null : option.value)}
                />
              ))}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {SLEEP_OPTIONS.map((option) => (
                <Button
                  key={option.label}
                  label={optionLabel(option)}
                  small
                  danger={sleepPick === option.value}
                  onPress={() => setSleepPick(sleepPick === option.value ? null : option.value)}
                />
              ))}
            </div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {ACTIVITY_TAGS.map((tag) => (
                <Button key={tag} label={activityTagLabel(tag)} small danger={tags.includes(tag)} onPress={() => toggleTag(tag)} />
              ))}
            </div>
            <Note tone="muted">{t("entry.detailsNote")}</Note>
          </>
        )}

        <ErrorBanner message={error} />
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Button label={busy ? t("entry.saving") : t("entry.save")} onPress={() => void save()} disabled={busy} />
          <Note tone="muted">{isOnline() ? t("entry.draftMemoryNote") : t("entry.offlineQueueNote")}</Note>
        </div>
      </Card>
    </>
  );
}
