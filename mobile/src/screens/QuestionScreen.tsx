/**
 * Today's single reflective question.
 *
 * PRE-THRESHOLD (day one onward): the card shows today's question from the
 * built-in generic pool (genericQuestions.ts) — computed on-device, so
 * NOTHING leaves the phone for it: no processing session, no key shipment,
 * and therefore no consent explainer. The pool hands over to the server's
 * pattern-based questions after the threshold, and the card says so. If the
 * phase check itself fails OFFLINE (status 0 — no response at all), the
 * same on-device pool still answers: an offline user gets a question with
 * the baseline caption, never an error card for a question that never
 * needed the network. Server errors (401/500) keep the honest error path.
 *
 * POST-THRESHOLD: unchanged. Order of operations (fixed after the audit):
 * the phase is checked FIRST — GET /api/insights needs no key. A stored
 * question decrypts locally. Only when there is none does step 3 open a
 * processing session — the ONE moment the data key travels to the server
 * (single-use, memory-only, destroyed within minutes). That step is
 * consent-gated: the first time per account a plain explainer appears
 * BEFORE anything is sent (components/keyConsent.ts), and a shorter
 * version of the same honesty sits under the button in the insight phase.
 * Errors are surfaced, never swallowed.
 *
 * "Write about this" bridges question → journal: the text is stashed as
 * the draft (account-bound, memory-only) and EntryScreen's focus listener
 * restores it even while the editor stays mounted underneath.
 */
import React, { useState } from "react";
import { ActivityIndicator, Alert, StyleSheet, Text, View } from "react-native";
import { api, ApiError } from "../api/client";
import { decryptQuestion } from "../crypto/MindPatternCrypto";
import { vault } from "../vault";
import { useSession, stashDraft } from "../store";
import { genericQuestionForDate } from "../genericQuestions";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { hasKeyShipConsent, recordKeyShipConsent } from "../components/keyConsent";
import { requestFailureCopy } from "../components/errors";

/** Calm copy for a failed load: calm request copy for ApiErrors, our own
 *  sentence for local Errors, one generic line for anything else. */
function failureCopy(err: unknown): string {
  if (err instanceof ApiError) return requestFailureCopy(err);
  if (err instanceof Error) return err.message;
  return "Something went wrong — try again.";
}

export function QuestionScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  const [phase, setPhase] = useState<"unknown" | "baseline" | "insight">("unknown");
  const [dayProgress, setDayProgress] = useState<{ active: number; total: number } | null>(null);
  const [question, setQuestion] = useState<string | null>(null);
  /** The pre-threshold day-one question (on-device generic pool). */
  const [generic, setGeneric] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  /** The "no pattern has enough evidence yet" note — a normal state. */
  const [notice, setNotice] = useState<string | null>(null);

  const decryptToday = async () => {
    const userId = await api.getUserId();
    if (!userId) throw new Error("account id missing — sign in again");
    const direct = await api.questionToday();
    // The blob's AAD is bound to the server's calendar date — always
    // decrypt with the for_date the server reported, never a locally
    // computed "today" (timezones would break authentication).
    return decryptQuestion(vault.get(), userId, direct.for_date, direct.blob);
  };

  const reportFailure = (err: unknown) => {
    const message = failureCopy(err);
    setError(message);
    if (!(err instanceof ApiError)) {
      // Local crypto failures are unexpected enough to be worth a dialog.
      Alert.alert("Could not load question", message);
    }
  };

  /** Step 3 of the load: the key-bearing recompute. Only ever runs in the
   *  insight phase, and only after the consent check in load(). */
  const computeQuestion = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      const session = await api.openProcessingSession(vault.get().dataKey.toString("base64"));
      const result = await api.recompute(session.session_token);
      if (!result.question_stored) {
        setNotice("No recurring pattern has enough evidence yet — keep writing.");
        return;
      }
      const payload = await decryptToday();
      setQuestion(payload.question);
    } catch (err) {
      reportFailure(err);
    } finally {
      setBusy(false);
    }
  };

  const load = async () => {
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      // 1) Is the account even in the insight phase? No key required.
      //    Offline (status 0 = the request never got a response) the phase
      //    is unknowable — but the on-device generic pool never needed the
      //    network, so the user gets today's question with the baseline
      //    caption instead of an error card. SERVER errors (401/500) carry
      //    information the user must see: they stay on the error path.
      let summary: Awaited<ReturnType<typeof api.insights>>;
      try {
        summary = await api.insights();
      } catch (err) {
        if (err instanceof ApiError && err.status === 0) {
          setPhase("baseline");
          setDayProgress(null); // unknown offline — the card omits the day counter
          setGeneric(genericQuestionForDate());
          return;
        }
        throw err;
      }
      if (summary.phase !== "insight") {
        setPhase("baseline");
        const active = typeof summary.active_days === "number" && Number.isFinite(summary.active_days)
          ? summary.active_days
          : 0;
        const total = Number.isFinite(summary.days_remaining) && Number.isFinite(summary.active_days)
          ? summary.days_remaining + summary.active_days
          : 0;
        setDayProgress(total > 0 ? { active, total } : null);
        // Day-one value: a reflective question TODAY from the built-in
        // pool, computed on-device — nothing leaves the phone for it, so
        // no key ships and no consent explainer belongs here.
        setGeneric(genericQuestionForDate());
        return;
      }
      setPhase("insight");
      // 2) A question may already exist for today — no key required either.
      try {
        const payload = await decryptToday();
        setQuestion(payload.question);
        return;
      } catch (err) {
        // 404 = none stored yet (expected, continue to recompute). Anything
        // else is a real failure and must NOT silently fall through to
        // opening a processing session.
        if (!(err instanceof ApiError && err.status === 404)) throw err;
      }
      // 3) Insight phase, no question yet: this step sends the data key in
      // a single-use processing session. The vault must hold THIS account's
      // keys — a session/vault desync must never ship one account's key
      // into another's session — and the first time per account the user
      // is told plainly what happens BEFORE anything is sent.
      const sessionUserId = await api.getUserId();
      if (!sessionUserId || vault.ownerUserId() !== sessionUserId) {
        throw new Error("session and unlocked keys do not match — sign in again");
      }
      // A failed consent READ errs toward showing the explainer again (the
      // user may never have been told), never toward skipping it silently.
      if (!(await hasKeyShipConsent(sessionUserId).catch(() => false))) {
        Alert.alert(
          "Your key, briefly",
          "To compute your patterns, your encryption key is sent to the server once — held in memory for up to 5 minutes, then destroyed. It is never stored, and it is only ever sent when you ask from this screen.",
          [
            { text: "Not now", style: "cancel" },
            {
              text: "Continue",
              onPress: () => {
                // Losing this write just shows the explainer again — never
                // block the load on it.
                void recordKeyShipConsent(sessionUserId).catch(() => {});
                void computeQuestion();
              },
            },
          ],
        );
        return;
      }
      await computeQuestion();
    } catch (err) {
      reportFailure(err);
    } finally {
      setBusy(false);
    }
  };

  const onShowQuestion = () => {
    // A second tap while a load is in flight is a no-op.
    if (busy) return;
    void load();
  };

  /** The question → journal bridge: the question becomes the start of
   *  today's entry via the account-bound draft stash. */
  const writeAbout = async (text: string) => {
    const userId = await api.getUserId().catch(() => null);
    if (!userId) {
      Alert.alert("Session damaged", "Account id missing — please sign in again.");
      return;
    }
    stashDraft(userId, text);
    navigation.navigate("Entry");
  };

  return (
    // Any touch on this screen is real interaction: restart the inactivity
    // countdown so the auto-lock only fires on a genuinely idle session.
    <View
      style={[styles.container, { backgroundColor: t.colors.bg, padding: t.spacing.xxl, gap: 18 }]}
      onTouchStart={touchActivity}
    >
      {busy && <ActivityIndicator color={t.colors.primaryBright} size="large" />}
      {error && (
        <Text style={[styles.error, { color: t.colors.error }]} accessibilityRole="alert">
          {error}
        </Text>
      )}
      {notice && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.xl }]}>
          <Text style={{ color: t.colors.body, fontSize: t.type.body.fontSize, lineHeight: 22 }}>{notice}</Text>
        </View>
      )}
      {phase === "baseline" && generic && !question && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.xl }]}>
          <Text style={[styles.cardTitle, { color: t.colors.accent }]}>Today</Text>
          <Text style={[styles.question, { color: t.colors.text }]}>{generic}</Text>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, lineHeight: 17 }}>
            For now, one question a day. After {dayProgress?.total ?? 30} days of writing, your
            questions start coming from YOUR patterns.
          </Text>
          {dayProgress && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
              Day {dayProgress.active} of {dayProgress.total}
            </Text>
          )}
          <GhostButton
            label="Write about this"
            center={false}
            onPress={() => void writeAbout(generic)}
            accessibilityLabel="Write about this question"
          />
        </View>
      )}
      {question && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.xl }]}>
          <Text style={[styles.cardTitle, { color: t.colors.accent }]}>Today</Text>
          <Text style={[styles.question, { color: t.colors.text }]}>{question}</Text>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            One question a day. No advice — just something to sit with.
          </Text>
          <GhostButton
            label="Write about this"
            center={false}
            onPress={() => void writeAbout(question)}
            accessibilityLabel="Write about this question"
          />
        </View>
      )}
      <View>
        <PrimaryButton
          label={question ?? generic ? "Refresh" : "Show today's question"}
          onPress={onShowQuestion}
          busy={busy}
        />
        <Text style={[styles.caption, { color: t.colors.muted, fontSize: t.type.meta.fontSize }]}>
          {phase === "baseline"
            ? "Today's question comes from a small built-in set — nothing leaves this device for it."
            : "Computing your question can send your encryption key to the server once — held in memory for up to 5 minutes, never stored."}
        </Text>
      </View>
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, justifyContent: "center" },
  card: { padding: 22, gap: 12 },
  cardTitle: { fontSize: 12, fontWeight: "700", letterSpacing: 1.5 },
  question: { fontSize: 22, fontWeight: "600", lineHeight: 30 },
  error: { fontSize: 13, textAlign: "center" },
  caption: { textAlign: "center", marginTop: 8, lineHeight: 16 },
});
