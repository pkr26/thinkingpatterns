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

  const submit = async () => {
    if (busy || !measureComplete(active, responses)) return;
    setBusy(true);
    const safetyFlagged = safetyItemEndorsed(active, responses);
    try {
      const userId = await api.getUserId();
      if (!userId) {
        Alert.alert(tr("measures.sessionDamagedTitle"), tr("measures.sessionDamagedBody"));
        return;
      }
      if (!vault.isUnlocked()) {
        Alert.alert(tr("measures.lockedTitle"), tr("measures.lockedBody"));
        return;
      }
      const today = localDateISO();
      const clientMeasureId = newMeasureId(today);
      const blob = encrypt(
        vault.get().dataKey,
        Buffer.from(measurePayload(active, responses, today), "utf8"),
        buildAad("measure", userId, clientMeasureId),
      ).toString("base64");
      await api.createMeasure(clientMeasureId, blob, today);
      setResponses(Array.from({ length: instrument.items }, () => null));
      showStatus(tr("measures.recordedStatus"), "ok");
      await load();
      // SAFETY: only after the response is safely stored. Same throttle
      // stamp and calm copy as the entry crisis dialog.
      if (safetyFlagged) {
        const flagged = await crisisDialogShownOn(userId, today).catch(() => false);
        if (!flagged) {
          await recordCrisisDialogShown(userId, today).catch(() => {});
          Alert.alert(
            tr("measures.crisisTitle"),
            tr("measures.crisisBody"),
            [
              { text: tr("measures.viewResources"), onPress: () => navigation.navigate("Crisis") },
              { text: tr("common.notNow"), style: "cancel" },
            ],
          );
        }
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        showStatus(tr("measures.alreadyRecorded"), "neutral");
        await load();
        return;
      }
      // 2026-09-26 audit LOW: an OFFLINE submit failure is now a quiet
      // inline status, not a modal. The picks deliberately stay selected and
      // the Record button stays enabled (the completion gate drives it) —
      // that IS the retry affordance: when connectivity returns, the same
      // tap re-submits the same picks. A modal here interrupted the screen
      // for a condition the user can do nothing about right now.
      if (err instanceof ApiError && err.status === 0) {
        showStatus(tr("measures.recordOfflineBody"), "neutral");
        return;
      }
      Alert.alert(tr("measures.notRecordedTitle"), tr("measures.recordFailedBody"));
    } finally {
      setBusy(false);
    }
  };

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
          onPress={submit}
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
