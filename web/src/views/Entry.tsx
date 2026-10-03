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
import { api, ApiError } from "../api/client";
import { encryptAudio, encryptEntry, timeOfDayBucket } from "../crypto/patient";
import { toBase64, type Bytes } from "../crypto/core";
import { useRecorder } from "../audio/recorder";
import { detectCrisisLanguage } from "../crisisDetect";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import { clearActiveDraft, loadActiveDraft, saveActiveDraft, preserveActiveDraft, registerDraftSource, type EntryDraft } from "../entryDraft";
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
import { kv } from "../kvstore";
import { Button, Card, Chip, DotScale, BarScale, ErrorBanner, Icon, MoodScale, Note, PillNote, TextArea, Toggle } from "../ui";

export type SaveResult = "sent" | "queued";

/** A confirmed voice session riding the pending entry (VOICE_PLAN
 *  2026-09-29): the transcript was written into the editor, the original
 *  recorded take is held in memory (kept ⇒ encrypted + uploaded after the
 *  entry lands), and the payload will carry the v3 voice channels. */
interface VoiceSession {
  audioBlob: Blob | null;
  normalizedMime: string;
  durationSeconds: number;
  language: string | null;
  languageRaw: string;
  transcribedOriginal: string;
  englishText: string | null;
  keepAudio: boolean;
}

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

export function EntryView(props: {
  onSaved: (result: SaveResult, date: string) => void;
  /** 2026-10-01 audit M3: the crisis prompt is a dead-end card without
   *  this — its copy promises "resources below" while nothing follows. */
  onCrisis?: () => void;
}): React.JSX.Element {
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
  // --- voice session (VOICE_PLAN 2026-09-29) ---
  const [voice, setVoice] = useState<VoiceSession | null>(null);
  const [transcribing, setTranscribing] = useState(false);
  const [voiceError, setVoiceError] = useState("");
  const [audioAvailable, setAudioAvailable] = useState<boolean | null>(null);
  // M-1 (audit 2026-09-29): the mic button stays disabled while the
  // pre-flight meta/consent fetch (and the getUserMedia prompt) is in
  // flight — a second press in that window cannot start a second flow.
  const [micBusy, setMicBusy] = useState(false);
  const recorder = useRecorder({
    unsupported: t("entry.voiceMicUnsupported"),
    permissionDenied: t("entry.voiceMicDenied"),
    failed: t("entry.voiceRecordFailed"),
  });

  /** Lazy feature discovery (VOICE_PLAN): the mic renders on recorder
   *  capability alone, and the FIRST press resolves the server's
   *  audio_available once — a deployment without the feature gets the
   *  honest unavailable note, and no background fetch ever shifts the
   *  save path's request sequence.
   *
   *  M-5 (audit 2026-09-29): a TRANSIENT meta failure no longer caches
   *  audioAvailable=false — only a definitive meta answer may (the old
   *  catch permanently hid the mic behind one offline blip) — and the
   *  consent pre-check runs BEFORE any take is recorded: a 403 after the
   *  take used to record the user's voice and then lose it. */
  const micPress = async (): Promise<void> => {
    if (micBusy) return;
    setMicBusy(true);
    try {
      if (audioAvailable === null) {
        try {
          const meta = await api.meta();
          setAudioAvailable(meta.audio_available === true);
          if (meta.audio_available !== true) {
            setVoiceError(t("entry.voiceUnavailable"));
            return;
          }
        } catch {
          // Transient failure — NOT a definitive answer: leave the state
          // unknown so the next press retries instead of hiding the mic.
          setVoiceError(t("entry.voiceCheckFailed"));
          return;
        }
      } else if (audioAvailable !== true) {
        setVoiceError(t("entry.voiceUnavailable"));
        return;
      }
      // Consent pre-check (M-5): recording without the account's voice
      // consent would only die to a 403 AFTER the take exists.
      try {
        const consent = await api.getVoiceConsent();
        if (!consent.enabled) {
          setVoiceError(t("entry.voiceConsentNeeded"));
          return;
        }
      } catch {
        setVoiceError(t("entry.voiceCheckFailed"));
        return;
      }
      await recorder.start();
    } finally {
      setMicBusy(false);
    }
  };

  const userId = vault.ownerUserId();
  const [draftRestored, setDraftRestored] = useState(false);

  // The live draft, as a ref: App's lockDown reads it through
  // registerDraftSource the instant a lock fires, BEFORE the vault
  // zeroizes — a hidden-tab/idle lock must seal the half-written entry,
  // not destroy it (entryDraft.ts, audit 2026-09-26).
  const draftRef = useRef<EntryDraft>({ text, mood: moodPick, energy: energyPick, sleep: sleepPick, tags });
  draftRef.current = { text, mood: moodPick, energy: energyPick, sleep: sleepPick, tags };
  useEffect(() => {
    const unregister = registerDraftSource(() => draftHydrated.current ? draftRef.current : null);
    return () => { void preserveActiveDraft(); unregister(); };
  }, []);
  const draftHydrated = useRef(false);
  const [draftReady,setDraftReady] = useState(false);
  const [restoreAttempt,setRestoreAttempt] = useState(0);
  const [draftStatus,setDraftStatus] = useState<string | null>(null);
  useEffect(() => {
    if (!draftHydrated.current || !userId || !vault.isUnlocked()) return;
    const timer = setTimeout(() => {
      if (!vault.isUnlocked()) return;
      const key = new Uint8Array(vault.get().dataKey);
      void saveActiveDraft(key,userId,draftRef.current).then(() => setDraftStatus(t("entry.draftSaved"))).catch(err => setDraftStatus(err instanceof Error ? err.message : t("entry.draftFailed"))).finally(() => key.fill(0));
    },300);
    return () => clearTimeout(timer);
  },[text,moodPick,energyPick,sleepPick,tags,userId]);

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
        if (cancelled) return;
        draftHydrated.current = true; setDraftReady(true);
        if (!draft) return;
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
      .catch(err => { if (!cancelled) setDraftStatus(err instanceof Error ? err.message : t("entry.draftFailed")); });
    return () => {
      cancelled = true;
    };
  }, [restoreAttempt]);

  const toggleTag = (tag: string): void => {
    setTags((current) => (current.includes(tag) ? current.filter((x) => x !== tag) : [...current, tag]));
  };

  // --- voice flow (VOICE_PLAN 2026-09-29) ---------------------------------
  // Auto-transcribe each finished take exactly once: the ref holds the last
  // Blob handled, so a re-render with the same recording never re-fires
  // (and a re-record produces a new Blob → a new transcription).
  // M-3 (audit 2026-09-29): the effect TOKEN owns the spinner — the old
  // `cancelled` flag skipped the finally's setTranscribing(false) whenever
  // the deps changed, but an early-returning successor effect never set it
  // true again either, parking the UI on "Transcribing…" forever. A token
  // is minted ONLY by an effect that starts real work, so the finally
  // clears unless a NEWER transcription genuinely owns the state.
  const lastTranscribedRef = useRef<Blob | null>(null);
  const transcribeTokenRef = useRef(0);
  useEffect(() => {
    const take = recorder.recording;
    if (!take || lastTranscribedRef.current === take.blob) return;
    lastTranscribedRef.current = take.blob;
    const token = ++transcribeTokenRef.current;
    void (async () => {
      setTranscribing(true);
      setVoiceError("");
      try {
        const plain = new Uint8Array(await take.blob.arrayBuffer());
        const result = await api.transcribeAudio(
          toBase64(plain),
          take.normalizedMime,
          take.durationSeconds,
        );
        if (transcribeTokenRef.current !== token) return;
        setVoice({
          audioBlob: take.blob,
          normalizedMime: take.normalizedMime,
          durationSeconds: take.durationSeconds,
          language: result.language,
          languageRaw: result.language_raw,
          transcribedOriginal: result.original_text,
          englishText: result.english_text,
          // L-7 (audit 2026-09-29): retention is OPT-IN — the recording is
          // dropped on save unless the user flips the keep toggle.
          keepAudio: false,
        });
        // The transcript lands in the ordinary editor: the user edits it
        // like any text, and the check-in channels apply as usual.
        setText(result.original_text);
      } catch (err) {
        if (transcribeTokenRef.current !== token) return;
        if (err instanceof ApiError && err.code === "voice_consent_required") {
          setVoiceError(t("entry.voiceConsentNeeded"));
        } else if (err instanceof ApiError && err.code === "stt_unconfigured") {
          setVoiceError(t("entry.voiceUnavailable"));
        } else if (err instanceof ApiError && err.code === "audio_too_large") {
          setVoiceError(t("entry.voiceTooLarge"));
        } else {
          // Localized honesty (audit 2026-09-29): upstream/provider detail
          // is implementation English — the user gets the honest retry copy.
          setVoiceError(t("entry.voiceTranscribeFailed"));
        }
      } finally {
        if (transcribeTokenRef.current === token) setTranscribing(false);
      }
    })();
  }, [recorder.recording]);

  /** Object URL for reviewing the pending take (L-5, audit 2026-09-29):
   *  minted in an EFFECT with revoke on change/unmount — a useMemo is not
   *  allowed to release, so the old shape leaked a fresh URL per blob for
   *  the tab's lifetime (nothing decrypted or recorded is ever cached at
   *  rest). */
  const [takeUrl, setTakeUrl] = useState<string | null>(null);
  useEffect(() => {
    const blob = voice?.audioBlob;
    if (!blob) {
      setTakeUrl(null);
      return;
    }
    const url = URL.createObjectURL(blob);
    setTakeUrl(url);
    return () => URL.revokeObjectURL(url);
  }, [voice?.audioBlob]);

  const discardVoice = (): void => {
    setVoice(null);
    setVoiceError("");
    recorder.reset();
  };

  /** Best-effort kept-recording upload: the ENTRY already stands, so this
   *  never fails the save — it warns. Terminal errors (413/404/403) skip
   *  the retries; transient ones get three attempts. */
  const uploadKeptAudio = async (
    dataKey: Bytes,
    owner: string,
    clientEntryId: string,
    session: VoiceSession,
  ): Promise<boolean> => {
    if (!session.audioBlob || !session.keepAudio) return true;
    const plain = new Uint8Array(await session.audioBlob.arrayBuffer());
    try {
      const { blobB64 } = await encryptAudio(dataKey, owner, clientEntryId, plain);
      for (let attempt = 1; attempt <= 3; attempt++) {
        try {
          await api.uploadAudioAttachment(
            clientEntryId,
            blobB64,
            session.normalizedMime,
            session.durationSeconds,
          );
          return true;
        } catch (err) {
          if (err instanceof ApiError && [403, 404, 413].includes(err.status)) return false;
          if (attempt === 3) return false;
          await new Promise((resolve) => setTimeout(resolve, 400 * attempt));
        }
      }
      return false;
    } finally {
      zeroize(plain);
    }
  };

  const save = async (): Promise<void> => {
    if (!draftReady) { setError(t("entry.draftFailed")); return; }
    if (!text.trim() && moodPick === null && energyPick === null && sleepPick === null && tags.length === 0) {
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
    const submitted = JSON.stringify(draftRef.current);
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
        const writePermit=await kv.captureWritePermit(owner,dataKey);
        // Voice sessions keep english_text in sync with the SAVED text
        // (the v3 contract): an edited transcript re-translates before
        // encryption; a failed/offline re-translation degrades to null
        // (the original transcript stands alone).
        let englishForSave: string | null = voice ? voice.englishText : null;
        if (voice && text.trim() !== voice.transcribedOriginal.trim()) {
          try {
            const translated = await api.translateText(text, voice.language);
            englishForSave = translated.english_text;
          } catch {
            englishForSave = null;
          }
        }
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
          voice
            ? {
                inputMode: "voice",
                transcriptLang: voice.language ?? undefined,
                englishText: englishForSave,
              }
            : undefined,
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
            await enqueue({ userId: owner, clientEntryId, blobB64, entryDate },writePermit);
          }
        } else {
          await enqueue({ userId: owner, clientEntryId, blobB64, entryDate },writePermit);
        }
        const unchanged = JSON.stringify(draftRef.current) === submitted;
        if (unchanged) {
          draftRef.current = { text: "",mood:null,energy:null,sleep:null,tags:[] };
          setText("");
          setMoodPick(null);
          setEnergyPick(null);
          setSleepPick(null);
          setTags([]);
        }
        // 2026-10-01 audit M3: the crisis prompt is NOT cleared here — it
        // rides past the save and stays until dismissed from the card.
        setDraftRestored(false);
        // The kept recording rides only a SENT entry (the offline queue is
        // the text ciphertext's safety net, not an audio transport —
        // O-5); a dropped recording warns and never fails the save.
        if (voice) {
          const kept =
            result === "sent" ? await uploadKeptAudio(dataKey, owner, clientEntryId, voice) : false;
          if (!kept && voice.keepAudio && voice.audioBlob) {
            setVoiceError(
              result === "queued" ? t("entry.voiceAudioQueuedNote") : t("entry.voiceAudioNotKept"),
            );
          }
          setVoice(null);
          recorder.reset();
        }
        // The entry is safe (server or ciphertext queue) — the sealed draft's
        // custody ends here (entryDraft.ts, audit 2026-09-26).
        if (unchanged && draftHydrated.current) await clearActiveDraft(owner,writePermit).catch(err => setDraftStatus(err instanceof Error ? err.message : t("entry.draftFailed")));
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
   *  draft — the user said this entry is not happening. A pending voice
   *  session (take + transcript) dies with it. */
  const discard = (): void => {
    setText("");
    setMoodPick(null);
    setEnergyPick(null);
    setSleepPick(null);
    setTags([]);
    setCrisisPrompt(false);
    setDraftRestored(false);
    discardVoice();
    const owner = vault.ownerUserId();
    if (owner && vault.isUnlocked()) void kv.captureWritePermit(owner,vault.get().dataKey).then(permit=>clearActiveDraft(owner,permit)).catch(err=>setDraftStatus(err instanceof Error?err.message:t("entry.draftFailed")));
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
          {/* 2026-10-01 audit M3: the promised resources, one tap away,
              plus the mobile dialog's not-now dismissal. */}
          {props.onCrisis && (
            <Button label={t("measures.getSupport")} onPress={props.onCrisis} small />
          )}
          <Button label={t("common.notNow")} onPress={() => setCrisisPrompt(false)} small variant="ghost" />
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
        <fieldset disabled={!draftReady} className="checkin-fields"><div className="checkin-grid">
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.moodQuestion")}</span>
            <MoodScale groupLabel={t("entry.moodQuestion")} options={MOOD_OPTIONS} value={moodPick} onChange={setMoodPick} />
          </div>
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.energyQuestion")}</span>
            <BarScale options={ENERGY_OPTIONS} value={energyPick} onChange={setEnergyPick} groupLabel={t("entry.energyQuestion")} />
          </div>
          <div className="stack" style={{ gap: "var(--space-2)" }}>
            <span className="checkin-label">{t("entry.sleepQuestion")}</span>
            <DotScale groupLabel={t("entry.sleepQuestion")} options={SLEEP_OPTIONS} value={sleepPick} onChange={setSleepPick} />
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
        </fieldset><Note tone="muted">{t("entry.detailsNote")}</Note>
      </Card>

      <Card title={t("entry.title")}>
        <TextArea
          label={t("entry.question")}
          maxLength={100_000}
          disabled={!draftReady}
          value={text}
          onChange={setText}
          placeholder={t("entry.placeholderWeb")}
          rows={8}
        />
        {draftStatus && <Note role="status">{draftStatus}</Note>}
        {!draftReady && <Button label={t("entry.retryDraft")} onPress={() => setRestoreAttempt(value => value + 1)} small />}
        {/* Voice capture (VOICE_PLAN 2026-09-29): the mic renders on
            recorder capability; the first press confirms the server has
            the feature before any recording starts. */}
        {typeof MediaRecorder !== "undefined" && recorder.state !== "recording" && !voice && (
          <div className="row">
            <Button
              label={t("entry.micRecord")}
              icon="mic"
              small
              variant="ghost"
              disabled={busy || transcribing || micBusy || !isOnline()}
              onPress={() => void micPress()}
            />
          </div>
        )}
        {recorder.state === "recording" && (
          <Card title={t("entry.micRecording")} tone="sensitive">
            <span className="row row--between">
              <span className="note note--lead" role="timer" aria-live="off">
                {String(Math.floor(recorder.elapsedSeconds / 60)).padStart(2, "0")}:
                {String(recorder.elapsedSeconds % 60).padStart(2, "0")}
              </span>
              <span
                aria-hidden
                style={{
                  display: "inline-block",
                  width: 12,
                  height: 12,
                  borderRadius: "50%",
                  background: "var(--danger, #c0392b)",
                  opacity: 0.35 + recorder.level * 0.65,
                }}
              />
            </span>
            <Note tone="muted">{t("entry.micRecordingNote")}</Note>
            <Button label={t("entry.micStop")} icon="check" onPress={recorder.stop} disabled={busy} block />
          </Card>
        )}
        {transcribing && <PillNote role="status" icon="info">{t("entry.voiceTranscribing")}</PillNote>}
        {voice && (
          <Card title={t("entry.voiceReviewTitle")}>
            {takeUrl && (
              <audio
                controls
                src={takeUrl}
                style={{ width: "100%" }}
                onError={() => setVoiceError(t("entry.voicePlaybackFailed"))}
              />
            )}
            <Note>{t("entry.voiceLanguage", { lang: voice.language ?? voice.languageRaw })}</Note>
            {voice.englishText !== null && (
              <Note tone="muted">{t("entry.voiceEnglishPreview")}: {voice.englishText}</Note>
            )}
            <Toggle
              checked={voice.keepAudio}
              onChange={(keep) => setVoice((current) => (current ? { ...current, keepAudio: keep } : current))}
              label={voice.keepAudio ? t("entry.voiceKeepOn") : t("entry.voiceKeepOff")}
            />
            <div className="row row--wrap">
              <Button
                label={t("entry.micRerecord")}
                icon="mic"
                small
                variant="ghost"
                disabled={busy || transcribing || micBusy || !isOnline()}
                onPress={() => {
                  discardVoice();
                  void micPress();
                }}
              />
              <Button label={t("entry.voiceDiscardTake")} icon="x" small variant="ghost" disabled={busy} onPress={discardVoice} />
            </div>
          </Card>
        )}
        {voiceError && <ErrorBanner message={voiceError} />}
        {/* L-6 (audit 2026-09-29): the recorder's own failures (permission
            denied, a dead recorder's onerror) surface beside the flow's
            errors — the hook set them, but nothing rendered them. */}
        {recorder.error && !voiceError && <ErrorBanner message={recorder.error} />}
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
          {/* M-3/M-5 (audit 2026-09-29): Save is disabled while a take is
              still recording or a transcription is in flight — the old
              path could submit mid-take and strand the session. */}
          <Button
            label={busy ? t("entry.saving") : t("entry.save")}
            icon="check"
            onPress={() => void save()}
            disabled={busy || !draftReady || transcribing || recorder.state === "recording"}
            block
          />
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
