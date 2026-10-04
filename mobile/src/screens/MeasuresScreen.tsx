/**
 * Wellbeing measures (MBC, 2026-09-19): a standard questionnaire the
 * patient completes, stored as an opaque encrypted blob and — when
 * therapist sharing is active — readable by their clinician through the
 * same consent as patterns and entries.
 *
 * The app's charter holds on this screen: no severity bands, no
 * interpretation, no advice. The score travels encrypted; the patient
 * sees their own recorded history and the plain statement that a
 * clinician reads and interprets.
 *
 * SAFETY: item 9 (self-harm thoughts) endorsement gently points at the
 * offline crisis resources AFTER the response is safely saved — the same
 * never-before-saving discipline as the entry crisis dialog, throttled
 * through the same per-day stamp.
 *
 * i18n (audit M-16, 2026-09-20): every string on this screen — including
 * the PHQ-9 item and option labels (measures.phq9.*) — resolves through
 * t(); nothing is hardcoded English anymore. The structural item list and
 * option values live in src/phq9.ts; only their display copy is local.
 */
import React, { useCallback, useEffect, useRef, useState } from "react";
import { ActivityIndicator, Alert, ScrollView, StyleSheet, Text, TouchableOpacity, View } from "react-native";
import { api, ApiError } from "../api/client";
import { buildAad, decrypt, encrypt } from "../crypto/envelope";
import { engine } from "../crypto/engine";
import { vault } from "../vault";
import { assertLocalWritePermit, captureLocalWritePermit, type LocalWritePermit } from "../localRekey";
import { localWriteScopeEpoch } from "../localWriteGuard";
import { useSession } from "../store";
import { localDateISO } from "../moodLog";
import { crisisDialogShownOn, recordCrisisDialogShown } from "../crisisDialog";
import {
  INSTRUMENTS,
  MEASURE_IDS,
  measureComplete,
  measurePayload,
  safetyItemEndorsed,
  maxScoreForMeasure,
  type MeasureId,
} from "../measures";
import {
  clearPendingMeasure,
  loadPendingMeasure,
  savePendingMeasure,
  type PendingMeasure,
} from "../pendingMeasure";
import { recordMeasureCompleted } from "../measureReminders";
import { syncMeasureReminderSchedule } from "../reminderSync";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { InlineStatus, InlineStatusTone } from "../components/InlineStatus";
import { MainShell } from "../components/BottomNav";
import { requestFailureCopy } from "../components/errors";
import { t as tr } from "../strings";
import { formatEntryDate } from "./HistoryScreen";

/** 2026-09-26 audit LOW: the transient status line auto-clears after the
 *  app-wide 2.6s idiom (EntryScreen/HistoryScreen STATUS_MS) — before, the
 *  first status stayed on screen forever, going stale beside newer state. */
const STATUS_MS = 2_600;

interface MeasureRow {
  client_measure_id: string;
  blob: string;
  measure_date: string;
}

interface Reading {
  instrument: string;
  date: string;
  score: number;
}

function newMeasureId(date: string): string {
  const suffix = engine.randomBytes(9).toString("base64url");
  return `m-${date}-${suffix}`;
}

/** Decrypt one history row (the patient's own key). Wrong shapes degrade
 *  to a skipped row — history is honest about what it can read. */
function decryptReading(dataKey: Buffer, userId: string, row: MeasureRow): Reading | null {
  try {
    const plain = decrypt(
      dataKey,
      Buffer.from(row.blob, "base64"),
      buildAad("measure", userId, row.client_measure_id),
    );
    const parsed = JSON.parse(plain.toString("utf8")) as { measure?: unknown; score?: unknown };
    if (typeof parsed.score !== "number" || !Number.isFinite(parsed.score)) return null;
    // P3 (2026-09-21): clamp per instrument — a phq2 row must never render
    // on a phq9 scale. Unknown instrument names (future payloads) skip
    // the row rather than mis-scale it.
    const max = maxScoreForMeasure(parsed.measure);
    if (max === null) return null;
    return { instrument: String(parsed.measure), date: row.measure_date, score: Math.max(0, Math.min(max, Math.round(parsed.score))) };
  } catch {
    return null;
  }
}

export function MeasuresScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const [readings, setReadings] = useState<Reading[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** P3 (2026-09-21): which instrument is in progress — PHQ-9, GAD-7 or
   *  PHQ-2 all ride this screen and the same encrypted measure path. */
  const [active, setActive] = useState<MeasureId>("phq9");
  const instrument = INSTRUMENTS[active];
  /** The in-progress questionnaire: one pick per item, null = unanswered. */
  const [responses, setResponses] = useState<Array<number | null>>(
    () => INSTRUMENTS.phq9.items !== null ? Array.from({ length: INSTRUMENTS.phq9.items }, () => null) : [],
  );
  const switchInstrument = (id: MeasureId): void => {
    touchActivity();
    setActive(id);
    setResponses(Array.from({ length: INSTRUMENTS[id].items }, () => null));
  };
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [statusTone, setStatusTone] = useState<InlineStatusTone>("ok");
  const statusTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** The pending record the current in-progress answers belong to (audit
   *  LOW, 2026-09-26): completed answers are persisted BEFORE their send
   *  (client_measure_id is the server's idempotency key) and every retry —
   *  a manual re-tap after an offline status, or the mount retry below —
   *  reuses the SAME id, so a send that landed-but-was-never-acked can
   *  never be recorded twice. */
  const pendingRef = useRef<PendingMeasure | null>(null);
  /** The mount-retry runs exactly once per mount (a ref, not state: this
   *  is a flow flag, not render input). */
  const retriedRef = useRef(false);

  /** Element-wise equality for the guarded post-send reset: answers the
   *  user changed while a send was in flight are NOT wiped by it. */
  const samePicks = (a: ReadonlyArray<number | null>, b: ReadonlyArray<number | null>): boolean =>
    a.length === b.length && a.every((value, index) => value === b[index]);

  /** Transient status; replaces itself cleanly and never stacks (the
   *  EntryScreen/HistoryScreen idiom, 2026-09-26 audit LOW). */
  const showStatus = (message: string, tone: InlineStatusTone) => {
    if (statusTimer.current) clearTimeout(statusTimer.current);
    setStatusTone(tone);
    setStatus(message);
    statusTimer.current = setTimeout(() => setStatus(null), STATUS_MS);
  };

  useEffect(() => {
    return () => {
      if (statusTimer.current) clearTimeout(statusTimer.current);
    };
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const userId = await api.getUserId();
      if (!userId) throw new Error(tr("common.accountMissing"));
      const rows = (await api.listMeasures()) as MeasureRow[];
      if (!vault.isUnlocked()) throw new Error(tr("measures.lockedBody"));
      const dataKey = vault.get().dataKey;
      const decrypted: Reading[] = [];
      for (const row of rows) {
        const reading = decryptReading(dataKey, userId, row);
        if (reading) decrypted.push(reading);
      }
      setReadings(decrypted); // newest first from the server
      setOffline(false);
    } catch (err) {
      if (err instanceof ApiError && err.status === 0) {
        setOffline(true);
        setReadings(null);
      } else {
        setError(err instanceof ApiError ? requestFailureCopy(err) : tr("measures.loadFailed"));
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  /** Record the completed questionnaire. `retryOf` (the mount-retry path)
   *  sends a specific persisted record; a plain tap reuses the pending
   *  record when the on-screen answers still match it, so the SAME
   *  client_measure_id rides every attempt of one questionnaire. */
  const submit = async (retryOf?: PendingMeasure) => {
    if (busy) return;
    const reusable =
      retryOf ??
      (pendingRef.current !== null &&
        pendingRef.current.kind === active &&
        samePicks(pendingRef.current.picks, responses)
        ? pendingRef.current
        : undefined);
    if (reusable === undefined && !measureComplete(active, responses)) return;
    setBusy(true);
    // Hoisted for the catch paths (try and catch are separate scopes): the
    // 409 branch must clear the very pending record this send used.
    let finishSent: () => void = () => {};
    let sentUserId: string | null = null;
    // Re-audit 2026-09-27 (L): the data key SNAPSHOT for this submit —
    // zeroized in the finally below. vault.get() shares its buffers with
    // the vault, so re-reading it after each await means a lock that lands
    // mid-submit (a backgrounding app) zeroizes the key BETWEEN the
    // isUnlocked check and the payload encrypt — the record would then
    // persist and ship sealed under all-zero bytes, permanently unreadable.
    // One copy taken at the check, used for both the persistence and the
    // encrypt, closes that window (the savePendingMeasure keyCopy idiom).
    let keyCopy: Buffer | null = null;
    let writePermit: LocalWritePermit | null = null;
    const submitEpoch = localWriteScopeEpoch();
    try {
      const userId = await api.getUserId();
      if (submitEpoch !== localWriteScopeEpoch()) throw new Error(tr("common.sessionDamagedTitle"));
      if (!userId) {
        Alert.alert(tr("measures.sessionDamagedTitle"), tr("measures.sessionDamagedBody"));
        return;
      }
      sentUserId = userId;
      if (!vault.isUnlocked()) {
        Alert.alert(tr("measures.lockedTitle"), tr("measures.lockedBody"));
        return;
      }
      if (vault.ownerUserId() !== userId) throw new Error(tr("common.sessionDamagedTitle"));
      keyCopy = Buffer.from(vault.get().dataKey);
      writePermit = captureLocalWritePermit(userId, keyCopy);
      const today = localDateISO();
      // 2026-09-26 audit LOW: persist BEFORE the send (a status-0 failure
      // can be a timeout AFTER the server committed; the stable id is what
      // makes every retry idempotent). A persistence failure never blocks
      // the send — the answers are also still on screen.
      const record: PendingMeasure =
        reusable ?? { kind: active, clientMeasureId: newMeasureId(today), picks: [...responses] as number[], date: today };
      pendingRef.current = record;
      await savePendingMeasure(keyCopy, userId, record).catch(() => {});
      const safetyFlagged = safetyItemEndorsed(record.kind, record.picks);
      assertLocalWritePermit(writePermit);
      const blob = encrypt(
        keyCopy,
        Buffer.from(measurePayload(record.kind, record.picks, record.date), "utf8"),
        buildAad("measure", userId, record.clientMeasureId),
      ).toString("base64");
      // The post-send reset, guarded like EntryScreen's editor clear: only
      // reset when the on-screen answers are still the ones that shipped —
      // answers changed while the send was in flight are kept for a fresh
      // Record tap.
      finishSent = () => {
        pendingRef.current = null;
        setResponses((previous) =>
          samePicks(previous, record.picks)
            ? Array.from({ length: INSTRUMENTS[record.kind].items }, () => null)
            : previous,
        );
      };
      assertLocalWritePermit(writePermit);
      await api.createMeasure(record.clientMeasureId, blob, record.date, writePermit);
      await clearPendingMeasure(userId, writePermit).catch(() => {});
      finishSent();
      showStatus(tr("measures.recordedStatus"), "ok");
      // The MBC cadence clock (2026-09-27): a completed questionnaire
      // restarts the check-in countdown AND retires any nudge scheduled
      // before it landed (syncMeasureReminderSchedule cancels what is no
      // longer due). Best-effort by design — a lost stamp only ever means
      // one slightly-early nudge.
      await recordMeasureCompleted(userId, record.date).catch(() => {});
      void syncMeasureReminderSchedule(userId).catch(() => {});
      await load();
      // SAFETY: only after the response is safely stored. Item-9 uses its
      // own trigger-specific throttle so a journal prompt shown earlier
      // today cannot suppress this clinically distinct safety check-in.
      if (safetyFlagged) {
        const flagged = await crisisDialogShownOn(userId, record.date, "phq9-item9").catch(() => false);
        if (!flagged) {
          await recordCrisisDialogShown(userId, record.date, "phq9-item9").catch(() => {});
          Alert.alert(
            tr("measures.crisisTitle"),
            tr("measures.crisisBody"),
            [
              // Resources FIRST (the same offline static list as ever); the
              // personal safety plan is offered beside them, never instead.
              { text: tr("measures.viewResources"), onPress: () => navigation.navigate("Crisis") },
              { text: tr("common.makeSafetyPlan"), onPress: () => navigation.navigate("SafetyPlan") },
              { text: tr("common.notNow"), style: "cancel" },
            ],
          );
        }
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        // Idempotent retry of a send that already landed: the record dies
        // here too (under its OWN account id — never a fallback ""), or
        // every mount would retry it forever.
        if (sentUserId && writePermit) await clearPendingMeasure(sentUserId, writePermit).catch(() => {});
        finishSent();
        showStatus(tr("measures.alreadyRecorded"), "neutral");
        await load();
        return;
      }
      // 2026-09-26 audit LOW: an OFFLINE submit failure is now a quiet
      // inline status, not a modal. The picks deliberately stay selected and
      // the Record button stays enabled (the completion gate drives it) —
      // that IS the retry affordance: when connectivity returns, the same
      // tap re-submits the same picks under the same id. The pending record
      // stays persisted, so the answers also survive a remount (app
      // backgrounding locks the vault and unmounts this screen; the next
      // mount restores and retries them — see the effect below).
      if (err instanceof ApiError && err.status === 0) {
        // 2026-10-01 audit M4: offline is not a reason to withhold the
        // support pointer — the answers ARE safely stored (the encrypted
        // pending record was saved before the send), so an item-9
        // endorsement shows the dialog now, with the same per-day throttle
        // as the online path. Without this, a self-harm endorsement with
        // no network got nothing in the moment.
        const offlinePending = pendingRef.current; // still set: only success/409 clear it
        if (offlinePending !== null && safetyItemEndorsed(offlinePending.kind, offlinePending.picks)) {
          const owner = sentUserId;
          const flagged =
            owner !== null
              ? await crisisDialogShownOn(owner, offlinePending.date, "phq9-item9").catch(() => false)
              : false;
          if (!flagged && owner !== null) {
            await recordCrisisDialogShown(owner, offlinePending.date, "phq9-item9").catch(() => {});
            Alert.alert(
              tr("measures.crisisTitle"),
              tr("measures.crisisBody"),
              [
                { text: tr("measures.viewResources"), onPress: () => navigation.navigate("Crisis") },
                { text: tr("common.makeSafetyPlan"), onPress: () => navigation.navigate("SafetyPlan") },
                { text: tr("common.notNow"), style: "cancel" },
              ],
            );
          }
        }
        showStatus(tr("measures.recordOfflineBody"), "neutral");
        return;
      }
      Alert.alert(tr("measures.notRecordedTitle"), tr("measures.recordFailedBody"));
    } finally {
      // The snapshot dies with the submit, success or failure.
      if (keyCopy) keyCopy.fill(0);
      setBusy(false);
    }
  };

  // 2026-09-26 audit LOW: restore + retry a persisted pending questionnaire
  // once per mount. The answers come back on screen (the honest restore)
  // and the send uses the SAME client_measure_id (idempotent by contract).
  // Offline again → the record simply stays for the next mount; the
  // restored picks keep the Record button enabled either way.
  useEffect(() => {
    if (retriedRef.current) return;
    retriedRef.current = true;
    void (async () => {
      try {
        const userId = await api.getUserId();
        if (!userId || !vault.isUnlocked()) return;
        const pending = await loadPendingMeasure(vault.get().dataKey, userId);
        if (pending === null) return;
        setActive(pending.kind);
        setResponses(pending.picks);
        await submit(pending);
      } catch {
        // Locked vault / dead storage: the record stays; nothing to show.
      }
    })();
  }, // Stryker disable next-line ArrayDeclaration: a mount-once flow guarded by retriedRef — the effect body is idempotent under a double fire
     []);

  return (
    <MainShell current="Settings" navigation={navigation}>
      <ScrollView
        style={{ flex: 1, backgroundColor: t.colors.bg }}
        contentContainerStyle={{ padding: t.spacing.xl, gap: t.spacing.lg }}
        keyboardShouldPersistTaps="handled"
      >
        <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
          {tr("measures.intro")}
        </Text>
        <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
          {tr("measures.unmonitored")}
        </Text>

        {loading && <ActivityIndicator color={t.colors.primaryBright} />}
        {offline && (
          <Text style={{ color: t.colors.muted, fontSize: t.type.bodySmall.fontSize }}>
            {tr("measures.offlineNote")}
          </Text>
        )}
        {error && (
          <Text style={{ color: t.colors.error, fontSize: t.type.bodySmall.fontSize }} accessibilityRole="alert">
            {error}
          </Text>
        )}
        {readings !== null && readings.length > 0 && (
          <View style={[styles.historyCard, { backgroundColor: t.colors.card, borderRadius: t.radius.lg }]}>
            <Text style={{ color: t.colors.text, fontSize: t.type.body.fontSize, fontWeight: "600" }}>
              {tr("measures.historyTitle")}
            </Text>
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
              {/* 2026-09-26 audit LOW: instrument ids map through the
                  measures.select.* locale labels (a bare "phq9" was raw
                  implementation vocabulary), and the date formats like every
                  other date on the app (locale-aware, not raw ISO). */}
              {readings
                .map((r) => `${tr(`measures.select.${r.instrument}`)} ${formatEntryDate(r.date)}: ${r.score}`)
                .join("   ·   ")}
            </Text>
          </View>
        )}
        {readings !== null && readings.length === 0 && !loading && (
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("measures.emptyNote")}
          </Text>
        )}

        {/* P3 (2026-09-21): the instrument selector — PHQ-9 (depression),
            GAD-7 (anxiety) and PHQ-2 (brief screen) share this screen and
            the same encrypted path. No interpretation, ever. */}
        <View style={{ flexDirection: "row", gap: t.spacing.sm, flexWrap: "wrap" }}>
          {MEASURE_IDS.map((id) => (
            <TouchableOpacity
              key={id}
              style={[
                styles.option,
                {
                  backgroundColor: active === id ? t.colors.primary : t.colors.card,
                  borderRadius: t.radius.md,
                  minHeight: t.minTouch,
                },
              ]}
              onPress={() => switchInstrument(id)}
              accessibilityRole="tab"
              accessibilityState={{ selected: active === id }}
              accessibilityLabel={tr(`measures.select.${id}`)}
            >
              <Text
                style={{
                  color: active === id ? t.colors.onPrimary : t.colors.body,
                  fontSize: t.type.meta.fontSize,
                  textAlign: "center",
                }}
              >
                {tr(`measures.select.${id}`)}
              </Text>
            </TouchableOpacity>
          ))}
        </View>

        <Text style={{ color: t.colors.text, fontSize: t.type.body.fontSize, fontWeight: "600" }}>
          {tr("measures.stemsHeader")}
        </Text>
        {Array.from({ length: instrument.items }, (_item, index) => (
          <View key={index} style={{ gap: t.spacing.sm }}>
            <Text style={{ color: t.colors.body, fontSize: t.type.bodySmall.fontSize }}>
              {index + 1}. {tr(`measures.${active}.item${index + 1}`)}
              {instrument.safetyItemIndex === index ? tr("measures.item9Note") : ""}
            </Text>
            <View style={styles.optionRow} accessibilityLabel={tr("measures.questionA11y", { index: index + 1 })}>
              {instrument.options.map((value) => {
                const selected = responses[index] === value;
                const optionLabel = tr(instrument.optionKey(value));
                return (
                  <TouchableOpacity
                    key={value}
                    style={[
                      styles.option,
                      {
                        backgroundColor: selected ? t.colors.primary : t.colors.card,
                        borderRadius: t.radius.md,
                      },
                    ]}
                    onPress={() => {
                      touchActivity();
                      const next = [...responses];
                      next[index] = value;
                      setResponses(next);
                    }}
                    accessibilityRole="radio"
                    accessibilityState={{ selected }}
                    accessibilityLabel={tr("measures.questionOptionA11y", { index: index + 1, label: optionLabel })}
                  >
                    <Text
                      numberOfLines={2}
                      style={{
                        color: selected ? t.colors.onPrimary : t.colors.body,
                        fontSize: t.type.meta.fontSize,
                        textAlign: "center",
                      }}
                    >
                      {optionLabel}
                    </Text>
                  </TouchableOpacity>
                );
              })}
            </View>
          </View>
        ))}

        <PrimaryButton
          label={tr("measures.recordButton")}
          onPress={() => void submit()}
          disabled={!measureComplete(active, responses)}
          busy={busy}
        />
        <InlineStatus message={status} tone={statusTone} />
        <GhostButton label={tr("measures.backToSettings")} onPress={() => navigation.goBack()} center={false} />
        <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </ScrollView>
    </MainShell>
  );
}

const styles = StyleSheet.create({
  historyCard: { padding: 16, gap: 8 },
  optionRow: { flexDirection: "row", gap: 6 },
  option: { flex: 1, alignItems: "center", justifyContent: "center", paddingVertical: 10, paddingHorizontal: 4, minHeight: 44 },
});
