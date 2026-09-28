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
 * Drafts live in this tab's memory while the session is live; a lock
 * (hidden tab / idle / expiry) SEALS the in-progress draft under the data
 * key before the keys die and the editor unmounts (entryDraft.ts, audit
 * 2026-09-26) — no plaintext at rest, ever, and no lost half-written
 * entry either (disclosed in the UI).
 *
 * Redesign 2026-09-26: the check-in is a visible one-tap visual card
 * (faces for mood and energy, dots for sleep, chips for activities) —
 * no longer hidden behind a "Show details" toggle — and selection is
 * aria-pressed sage, never the danger color. A time-aware greeting and
 * streak chip open the screen.
 */
import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../api/client";
import { encryptEntry, timeOfDayBucket } from "../crypto/patient";
import { detectCrisisLanguage } from "../crisisDetect";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { clearActiveDraft, loadActiveDraft, registerDraftSource, type EntryDraft } from "../entryDraft";
import { localDateISO } from "../dates";
import { newClientEntryId } from "../entryId";
import { recordMood, localStreak } from "../moodLog";
import { ENERGY_OPTIONS, MOOD_OPTIONS, SLEEP_OPTIONS, ACTIVITY_TAGS, activityTagLabel } from "../mood";
import { enqueue, queueLength } from "../offlineQueue";
import { promptChipsFor } from "../promptChips";
import { isOnline } from "../platform";
import { zeroize } from "../crypto/core";
import { detectLanguage, sentimentScore } from "../brain/sentiment";
import { dateLocaleTag, getLocale, t } from "../strings";
import { vault } from "../vault";
import { Button, Card, Chip, DotScale, BarScale, ErrorBanner, Icon, MoodScale, Note, PillNote, TextArea } from "../ui";

export type SaveResult = "sent" | "queued";

/** The client-side entry length cap (2026-09-28 audit MEDIUM): the
 *  server's blob ceiling is far higher, so without a client gate a
 *  pathological paste could park a megabyte of ciphertext in the queue
 *  and silently die against entryDraft.ts's 100k parse bound. Mobile's
 *  EntryScreen.tsx contract — the same constant, the same honest copy. */
const MAX_ENTRY_CHARS = 100_000;

function greetingKey(hour: number): string {
  if (hour < 12) return "entry.greetingMorning";
  if (hour < 18) return "entry.greetingAfternoon";
  return "entry.greetingEvening";
}

export function EntryView(props: { onSaved: (result: SaveResult, date: string) => void }): React.JSX.Element {
  const [text, setText] = useState("");
  const [moodPick, setMoodPick] = useState<number | null>(null);
  const [energyPick, setEnergyPick] = useState<number | null>(null);
  const [sleepPick, setSleepPick] = useState<number | null>(null);
  const [tags, setTags] = useState<string[]>([]);
  const [crisisPrompt, setCrisisPrompt] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [streak, setStreak] = useState<number | null>(null);
  const [queuedCount, setQueuedCount] = useState(0);

  const userId = vault.ownerUserId();
  const [draftRestored, setDraftRestored] = useState(false);

  // The live draft, as a ref: App's lockDown reads it through
  // registerDraftSource the instant a lock fires, BEFORE the vault
  // zeroizes — a hidden-tab/idle lock must seal the half-written entry,
  // not destroy it (entryDraft.ts, audit 2026-09-26).
  const draftRef = useRef<EntryDraft>({ text, mood: moodPick, energy: energyPick, sleep: sleepPick, tags });
  draftRef.current = { text, mood: moodPick, energy: energyPick, sleep: sleepPick, tags };
  useEffect(() => registerDraftSource(() => draftRef.current), []);

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

  // Restore a draft sealed at lock time (audit 2026-09-26): the editor's
  // whole multi-field state comes back exactly as it was left. The SLOT
  // deliberately stays until save/discard — switching views and back must
  // not lose the draft, and the next lock re-seals whatever is on screen.
  useEffect(() => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) return;
    let cancelled = false;
    loadActiveDraft(vault.get().dataKey, owner)
      .then((draft) => {
        if (cancelled || !draft) return;
        // Never clobber typing that raced the restore: the slot keeps the
        // draft either way.
        const live = draftRef.current;
        if (live.text !== "" || live.mood !== null || live.energy !== null || live.sleep !== null || live.tags.length > 0) return;
        setText(draft.text);
        setMoodPick(draft.mood);
        setEnergyPick(draft.energy);
        setSleepPick(draft.sleep);
        setTags(draft.tags);
        setDraftRestored(true);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, []);

  const toggleTag = (tag: string): void => {
    setTags((current) => (current.includes(tag) ? current.filter((x) => x !== tag) : [...current, tag]));
  };

  const save = async (): Promise<void> => {
    if (!text.trim()) {
      setError(t("entry.empty"));
      return;
    }
    // 2026-09-28 audit MEDIUM: the editor itself enforces the entry cap —
    // mobile EntryScreen parity. entryDraft.ts silently rejects a sealed
    // draft over 100k, so an over-cap save would pass the server and then
    // lose its own lock-time draft; the cap keeps both sides consistent.
    if (text.trim().length > MAX_ENTRY_CHARS) {
      setError(t("entry.tooLongBody", { max: MAX_ENTRY_CHARS.toLocaleString(dateLocaleTag()) }));
      return;
    }
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      // The owner/isUnlocked re-check BEFORE the key fetch (audit 2026-09-26
      // LOW): a lock that landed between the last render and this press
      // used to hit vault.get()'s throw as an unhandled rejection — now it
      // is the honest locked message, quietly.
      setError(t("common.sessionLocked"));
      return;
    }
    const date = localDateISO();
    // The crisis dialog tier runs PRE-encryption, on what was just typed:
    // the resource prompt must precede any encrypt/send call. Throttled to
    // once per (account, calendar day) — LOW c (audit 2026-09-26), mobile
    // crisisDialog parity: a prompt on every draft trains dismissal. The
    // stamp records BEFORE the prompt so sequential saves cannot
    // double-fire; it is session-scoped in memory only (audit 2026-09-27),
    // so a reload fails toward showing.
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
      // Immediate re-check inside the try (audit 2026-09-26 LOW, the
      // Patterns guard pattern): a lock during the crisis-tier awaits must
      // not turn vault.get() into an unhandled rejection.
      if (!vault.isUnlocked()) return;
      const keys = vault.get();
      const entryDate = date; // WEB_PLAN D-7: creation is today-only
      const clientEntryId = newClientEntryId(entryDate);
      const createdAt = new Date().toISOString();
      // M-3 (2026-09-28 audit): snapshot the data key BEFORE the encrypt
      // await — vault.get()'s buffers are SHARED, and a lock landing during
      // that await zeroizes them. The Measures P1 fix closed this for the
      // questionnaire submit; the entry save had the same hole one screen
      // over: recordMood read the log under the (now zero) shared buffer
      // and REPLACED it with ciphertext under 32 zero bytes, destroying
      // the device-local mood history. The snapshot (plus the re-check
      // below) closes both halves; the copy dies in the finally.
      const dataKey = new Uint8Array(new ArrayBuffer(keys.dataKey.length));
      dataKey.set(keys.dataKey);
      try {
        // H-5 (audit 2026-09-26): ONLY the explicit pick rides in the
        // encrypted payload's sentiment slot — null when no pick was made.
        // The machine estimate is never written where the backend/therapist
        // would read it as the user's own report.
        const { blobB64 } = await encryptEntry(
          dataKey,
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
        // A lock during the encrypt await: the snapshot kept the blob safe,
        // but nothing more may be written this submit — abort honestly (the
        // draft is still on screen for a post-unlock re-save) instead of
        // recording the mood log under a dead key.
        if (!vault.isUnlocked()) {
          setError(t("common.sessionLocked"));
          return;
        }
        // The mood log is device-local metadata recorded on EVERY save
        // (mobile EntryScreen parity): the explicit pick wins, the quick
        // text estimate fills in when there is none.
        await recordMood(dataKey, owner, date, moodPick ?? sentimentScore(text, detectLanguage(text)), energyPick).catch(() => undefined);

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
        setDraftRestored(false);
        // The entry is safe (server or ciphertext queue) — the sealed draft's
        // custody ends here (entryDraft.ts, audit 2026-09-26).
        await clearActiveDraft(owner).catch(() => undefined);
        props.onSaved(result, date);
      } finally {
        zeroize(dataKey);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : t("entry.couldNotSave"));
    } finally {
      setBusy(false);
    }
  };

  const editorEmpty =
    text.trim() === "" && moodPick === null && energyPick === null && sleepPick === null && tags.length === 0;

  /** Explicit discard (audit 2026-09-26): wipe the editor AND the sealed
   *  draft — the user said this entry is not happening. */
  const discard = (): void => {
    setText("");
    setMoodPick(null);
    setEnergyPick(null);
    setSleepPick(null);
    setTags([]);
    setCrisisPrompt(false);
    setDraftRestored(false);
    const owner = vault.ownerUserId();
    if (owner) void clearActiveDraft(owner).catch(() => undefined);
  };

  const now = new Date();
  const dateLine = new Intl.DateTimeFormat(dateLocaleTag(), { weekday: "long", month: "long", day: "numeric" }).format(now);

  return (
    <>
      {/* Time-aware greeting + date + streak chip — the calm opening beat. */}
      <div className="stack" style={{ gap: 6, padding: "6px 20px 0" }}>
        <span className="note note--lead" style={{ fontSize: "var(--text-2xl)", fontWeight: 800, letterSpacing: "-0.02em" }}>
          {t(greetingKey(now.getHours()))}
        </span>
        <span className="row row--wrap" style={{ gap: 10 }}>
          <span className="note note--muted">{dateLine}</span>
          {streak !== null && streak > 0 && (
            <PillNote role="status" icon="flame">{t(streak === 1 ? "common.streakOne" : "common.streakMany", { count: streak })}</PillNote>
          )}
          {queuedCount > 0 && (
            <PillNote role="status" tone="warn" icon="alert">{t(queuedCount === 1 ? "entry.queuedOne" : "entry.queuedMany", { count: queuedCount })}</PillNote>
          )}
        </span>
      </div>

      {crisisPrompt && (
        <Card title={t("entry.crisisPromptTitle")} tone="sensitive">
          <Note tone="danger">{t("entry.crisisPromptBody")}</Note>
          <Note tone="muted">{t("entry.crisisPromptProceed")}</Note>
        </Card>
      )}

      {/* Check-in and journal side by side on wide screens — the old
          single column left ~500px of dead space beside the check-in
          (audit 2026-09-26 fix; stacks normally below 1000px). */}
      <div className="today-grid">
      {/* The one-tap check-in — visible by default (Daylio-style
          frictionless); every dimension is optional and never blocks saving. */}
      <Card title={t("entry.checkinTitle")}>
        <span className="checkin-optional">{t("entry.optionalHint")}</span>
        <div className="checkin-grid">
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.moodQuestion")}</span>
            <MoodScale options={MOOD_OPTIONS} value={moodPick} onChange={setMoodPick} />
          </div>
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.energyQuestion")}</span>
            <BarScale options={ENERGY_OPTIONS} value={energyPick} onChange={setEnergyPick} groupLabel={t("entry.energyQuestion")} />
          </div>
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.sleepQuestion")}</span>
            <DotScale options={SLEEP_OPTIONS} value={sleepPick} onChange={setSleepPick} />
          </div>
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.activitiesQuestion")}</span>
            <div className="row row--wrap">
              {ACTIVITY_TAGS.map((tag) => (
                <Chip key={tag} label={activityTagLabel(tag)} selected={tags.includes(tag)} onPress={() => toggleTag(tag)} />
              ))}
            </div>
          </div>
        </div>
        <Note tone="muted">{t("entry.detailsNote")}</Note>
      </Card>

      <Card title={t("entry.title")}>
        <TextArea
          label={t("entry.question")}
          value={text}
          onChange={setText}
          placeholder={t("entry.placeholderWeb")}
          rows={8}
        />
        <div className="row row--wrap">
          {chips.map((chip) => (
            <Chip key={chip} label={chip} toggle={false} onPress={() => setText(`${text}${text && !text.endsWith(" ") ? " " : ""}${chip} `)} />
          ))}
        </div>
        {sentiment !== null && (
          <PillNote role="status" icon="info">
            {t("entry.onDeviceRead", { leaning: sentiment > 0.05 ? t("entry.leanLighter") : sentiment < -0.05 ? t("entry.leanHeavier") : t("entry.leanEven") })}
          </PillNote>
        )}

        {draftRestored && !editorEmpty && (
          <PillNote role="status" icon="info">{t("entry.draftRestoredNote")}</PillNote>
        )}
        <ErrorBanner message={error} />
        <div className="stack" style={{ gap: "var(--space-2)" }}>
          <Button label={busy ? t("entry.saving") : t("entry.save")} icon="check" onPress={() => void save()} disabled={busy} block />
          <span className="row" style={{ justifyContent: "center" }}>
            <Button label={t("entry.discard")} icon="x" onPress={discard} small variant="ghost" disabled={busy || editorEmpty} />
          </span>
          <span className="row" style={{ gap: 6, justifyContent: "center" }}>
            <Icon name={isOnline() ? "shield" : "alert"} size={14} />
            <span className="note note--muted">{isOnline() ? t("entry.draftMemoryNote") : t("entry.offlineQueueNote")}</span>
          </span>
        </div>
      </Card>
      </div>
    </>
  );
}
