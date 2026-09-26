/**
 * The daily journal editor (WEB_PLAN P4.1). Everything happens on-device
 * first: the crisis dialog tier runs PRE-encryption over what was just
 * typed; sentiment comes from the on-device brain; the mood check-in and
 * streak live in the device-local encrypted mood log. On save, the payload
 * is encrypted and either uploaded or parked in the ciphertext-only
 * offline queue (open-tab offline, WEB_PLAN D-6).
 *
 * Drafts are memory-only: no plaintext at rest, ever (disclosed in the UI).
 */
import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api/client";
import { encryptEntry, timeOfDayBucket } from "../crypto/patient";
import { detectCrisisLanguage } from "../crisisDetect";
import { localDateISO } from "../dates";
import { newClientEntryId } from "../entryId";
import { recordMood, localStreak } from "../moodLog";
import { ENERGY_OPTIONS, MOOD_OPTIONS, SLEEP_OPTIONS, ACTIVITY_TAGS, activityTagLabel, optionLabel } from "../mood";
import { enqueue, queueLength } from "../offlineQueue";
import { promptChipsFor } from "../promptChips";
import { isOnline } from "../platform";
import { sentimentScore } from "../brain/sentiment";
import { t } from "../strings";
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
  const sentiment = useMemo(() => (text.trim() ? sentimentScore(text) : null), [text]);
  const chips = useMemo(() => promptChipsFor(new Date(), 3), []);

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
      setError("Write something first — even one honest sentence counts.");
      return;
    }
    const keys = vault.get();
    const owner = vault.ownerUserId();
    if (!owner) {
      setError("Your session locked — sign in again.");
      return;
    }
    // The crisis dialog tier runs PRE-encryption, on what was just typed:
    // the resource prompt must precede any encrypt/send call.
    if (detectCrisisLanguage(text) && !crisisPrompt) {
      setCrisisPrompt(true);
      return; // the user confirms once; the next Save proceeds
    }
    setBusy(true);
    setError("");
    try {
      const date = localDateISO();
      const entryDate = date; // WEB_PLAN D-7: creation is today-only
      const clientEntryId = newClientEntryId(entryDate);
      const createdAt = new Date().toISOString();
      const { blobB64 } = await encryptEntry(
        keys.dataKey,
        owner,
        clientEntryId,
        text,
        createdAt,
        sentiment,
        {
          ...(energyPick !== null ? { energy: energyPick } : {}),
          ...(sleepPick !== null ? { sleep: sleepPick } : {}),
          ...(tags.length > 0 ? { tags } : {}),
          tod: timeOfDayBucket(new Date().getHours()),
        },
        1,
      );
      if (moodPick !== null) {
        await recordMood(keys.dataKey, owner, date, moodPick, energyPick).catch(() => undefined);
      }

      let result: SaveResult = "queued";
      if (isOnline()) {
        try {
          await api.createEntry(clientEntryId, blobB64, entryDate, 1);
          result = "sent";
        } catch (err) {
          // A genuine duplicate (this id already lives server-side) is
          // success; everything else parks in the offline queue.
          if (!(err instanceof ApiError && err.status === 409)) {
            await enqueue({ userId: owner, clientEntryId, blobB64, entryDate });
          } else {
            result = "sent";
          }
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
      setError(err instanceof Error ? err.message : "Could not save — try again.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      {crisisPrompt && (
        <Card title="Before you save">
          <Note tone="danger">{"What you wrote sounds heavy. You deserve support — the resources below are one tap away, any time."}</Note>
          <Note tone="muted">{"You can still save this entry. Press Save again to continue."}</Note>
        </Card>
      )}
      <Card title="Today's entry">
        {streak !== null && streak > 0 && <Note role="status">{`Writing streak: ${streak} day${streak === 1 ? "" : "s"}`}</Note>}
        {queuedCount > 0 && <Note tone="warn">{`${queuedCount} entr${queuedCount === 1 ? "y" : "ies"} waiting to sync — saved on this device, encrypted.`}</Note>}
        <TextArea
          label="How was today?"
          value={text}
          onChange={setText}
          placeholder="Write freely. Only you can read this."
          rows={8}
        />
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {chips.map((chip) => (
            <Button key={chip} label={chip} small onPress={() => setText(`${text}${text && !text.endsWith(" ") ? " " : ""}${chip} `)} />
          ))}
        </div>
        {sentiment !== null && (
          <Note tone="muted">On-device read: this entry leans {sentiment > 0.05 ? "lighter" : sentiment < -0.05 ? "heavier" : "even"}.</Note>
        )}

        <Button label={detailsOpen ? "Hide details" : "Add details (mood, sleep, energy, tags)"} onPress={() => setDetailsOpen(!detailsOpen)} small />
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
            <Note tone="muted">Details are optional and travel inside the entry's encryption — the server sees only ciphertext.</Note>
          </>
        )}

        <ErrorBanner message={error} />
        <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
          <Button label={busy ? "Saving…" : "Save entry"} onPress={() => void save()} disabled={busy} />
          <Note tone="muted">{isOnline() ? "Drafts live in this tab's memory only — nothing readable is stored." : "Offline — the entry will queue, encrypted, and sync when you're back."}</Note>
        </div>
      </Card>
    </>
  );
}
