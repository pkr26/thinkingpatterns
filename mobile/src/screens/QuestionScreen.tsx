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
 * AUTO-LOAD (2026-09-19): the screen loads on mount — but only the
 * key-free steps (phase check, stored question, baseline generic). When
 * the load would reach the key-bearing step 3 it STOPS and leaves the
 * "Show today's question" button: shipping the data key stays an explicit
 * act of the user's finger (the red-team contract — no screen ships it
 * automatically), so the mount effect never fires the consent explainer
 * or a processing session either.
 *
 * "Write about this" bridges question → journal: the text is stashed as
 * the draft (account-bound, memory-only) and EntryScreen's focus listener
 * restores it even while the editor stays mounted underneath.
 */
import React, { useEffect, useState } from "react";
import { ActivityIndicator, Alert, ScrollView, StyleSheet, Text, View } from "react-native";
import { api, ApiError } from "../api/client";
import { decryptQuestion } from "../crypto/MindPatternCrypto";
import { buildFeedbackBlob, clearFeedback, recordFeedbackTap } from "../questionFeedback";
import { lightHaptic } from "../haptics";
import { vault } from "../vault";
import { useSession, stashDraft } from "../store";
import { genericQuestionForDate } from "../genericQuestions";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { hasKeyShipConsent, recordKeyShipConsent } from "../components/keyConsent";
import { requestFailureCopy } from "../components/errors";
import { t as tr } from "../strings";

/** Calm copy for a failed load: calm request copy for ApiErrors, our own
 *  sentence for local Errors, one generic line for anything else. */
function failureCopy(err: unknown): string {
  // Stryker disable next-line ConditionalExpression: requestFailureCopy implements the identical three-way mapping (ApiError→status copy, Error→message, else generic) — delegating every error to it is behavior-preserving
  if (err instanceof ApiError) return requestFailureCopy(err);
  if (err instanceof Error) return err.message;
  return tr("errors.generic");
}

export function QuestionScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  const { touchActivity } = useSession();
  // Stryker disable next-line StringLiteral: "unknown" is never rendered or compared — only phase === "baseline" is ever tested, and "" fails that test identically
  const [phase, setPhase] = useState<"unknown" | "baseline" | "insight">("unknown");
  /** True when the phase is ASSUMED because the server was unreachable
   *  (status 0: offline, timeout, local refusal — audit L-57). The card
   *  still renders the on-device generic question, but every caption says
   *  "can't reach the server" instead of asserting the baseline program:
   *  an insight-phase user offline must not read "after {days} days your
   *  questions start coming from your patterns" about an account that
   *  already unlocked them. */
  const [phaseAssumedOffline, setPhaseAssumedOffline] = useState(false);
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
    if (!userId) throw new Error(tr("common.accountMissing"));
    const direct = await api.questionToday();
    // The blob's AAD is bound to the server's calendar date — always
    // decrypt with the for_date the server reported, never a locally
    // computed "today" (timezones would break authentication).
    return decryptQuestion(vault.get(), userId, direct.for_date, direct.blob);
  };

  /** The pattern behind today's question (null on generic days): powers
   *  the "did this land?" taps (2026-09-17). */
  const [patternPid, setPatternPid] = useState<string | null>(null);
  const [feedbackGiven, setFeedbackGiven] = useState(false);
  const recordTap = async (resonated: boolean) => {
    const pid = patternPid;
    if (!pid || feedbackGiven) return;
    setFeedbackGiven(true);
    lightHaptic();
    try {
      const userId = await api.getUserId();
      if (userId) {
        await recordFeedbackTap(vault.get().dataKey, userId, pid, resonated);
        setNotice(resonated ? tr("question.noticedMore") : tr("question.noticedLess"));
      }
    } catch {
      setNotice(tr("question.feedbackSaveFailed"));
      setFeedbackGiven(false);
    }
  };

  const reportFailure = (err: unknown) => {
    const message = failureCopy(err);
    setError(message);
    if (!(err instanceof ApiError)) {
      // Local crypto failures are unexpected enough to be worth a dialog.
      Alert.alert(tr("question.loadFailedTitle"), message);
    }
  };

  /** Step 3 of the load: the key-bearing recompute. Only ever runs in the
   *  insight phase, and only after the consent check in load(). */
  const computeQuestion = async () => {
    setBusy(true);
    // Stryker disable next-line CallExpression: redundant reset — both callers run inside load(), which cleared the error first with no setter in between
    setError(null);
    // Stryker disable next-line CallExpression: redundant reset — both callers run inside load(), which cleared the notice first with no setter in between
    setNotice(null);
    try {
      const session = await api.openProcessingSession(vault.get().dataKey.toString("base64"));
      // Pending question-feedback taps ride along, encrypted like every
      // other payload (2026-09-17); cleared once the server consumed them.
      const userId = await api.getUserId();
      const feedbackBlob = userId ? await buildFeedbackBlob(vault.get().dataKey, userId) : null;
      let result: Awaited<ReturnType<typeof api.recompute>>;
      try {
        result = await api.recompute(session.session_token, feedbackBlob ?? undefined);
      } catch (err) {
        // A feedback blob that failed AEAD can never authenticate again —
        // quarantine it (drop the queue) and finish the recompute without
        // it, instead of failing every question load from now on.
        if (err instanceof ApiError && err.code === "feedback_blob_invalid" && userId) {
          await clearFeedback(userId).catch(() => {});
          // M-12: the failed feedback pre-flight already CONSUMED the
          // single-use processing token server-side (the key is popped
          // before the pre-flight raises) — replaying it is a guaranteed
          // 403 processing_session_invalid and the "transparent recovery"
          // below was dead code. Open a FRESH session — the data key ships
          // once more under the same consent already given for this flow —
          // so the retry can actually run.
          const fresh = await api.openProcessingSession(vault.get().dataKey.toString("base64"));
          result = await api.recompute(fresh.session_token);
        } else {
          throw err;
        }
      }
      if (feedbackBlob && userId) await clearFeedback(userId).catch(() => {});
      if (!result.question_stored) {
        setNotice(tr("question.noEvidenceYet"));
        return;
      }
      const payload = await decryptToday();
      setQuestion(payload.question);
      setPatternPid(typeof payload.pattern_pid === "string" ? payload.pattern_pid : null);
      setFeedbackGiven(false);
    } catch (err) {
      reportFailure(err);
    } finally {
      setBusy(false);
    }
  };

  const load = async (allowKeyShip: boolean) => {
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
        setPhaseAssumedOffline(false); // a real answer replaces any assumption
      } catch (err) {
        if (err instanceof ApiError && err.status === 0) {
          // Status 0 means NO RESPONSE (offline, timeout, local refusal) —
          // the phase is unknowable, not "baseline" (audit L-57). The
          // generic question still renders; the captions say what is true.
          setPhase("baseline"); // display path only — see phaseAssumedOffline
          setPhaseAssumedOffline(true);
          setDayProgress(null); // unknown offline — the card omits the day counter
          setGeneric(genericQuestionForDate());
          return;
        }
        throw err;
      }
      if (summary.phase !== "insight") {
        setPhase("baseline");
        // Stryker disable next-line ConditionalExpression,LogicalOperator: Number.isFinite(x) ⇒ typeof x === "number" for JSON-parsed values, and `active` is only consumed when total > 0 — which itself requires Number.isFinite(active_days)
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
      // Stryker disable next-line StringLiteral: phase is only ever compared to "baseline" (the card guard and the caption) — "" and "insight" both fail that test identically
      setPhase("insight");
      // 2) A question may already exist for today — no key required either.
      try {
        const payload = await decryptToday();
        setQuestion(payload.question);
        // The pid must follow every question swap (a refresh after a
        // recompute would otherwise keep the PREVIOUS question's pid and
        // attribute the taps to the wrong pattern); no pid → none offered.
        setPatternPid(typeof payload.pattern_pid === "string" ? payload.pattern_pid : null);
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
      // The mount auto-load stops HERE (allowKeyShip=false): the button
      // below is the explicit act that may continue.
      if (!allowKeyShip) return;
      const sessionUserId = await api.getUserId();
      if (!sessionUserId || vault.ownerUserId() !== sessionUserId) {
        throw new Error(tr("question.sessionMismatch"));
      }
      // A failed consent READ errs toward showing the explainer again (the
      // user may never have been told), never toward skipping it silently.
      // Stryker disable next-line ArrowFunction: !undefined ≡ !false — a failed consent read shows the explainer either way
      if (!(await hasKeyShipConsent(sessionUserId).catch(() => false))) {
        Alert.alert(tr("question.keyShipTitle"), tr("question.keyShipBody"), [
          { text: tr("common.notNow"), style: "cancel" },
          {
            text: tr("common.continue"),
            onPress: () => {
              // Losing this write just shows the explainer again — never
              // block the load on it.
              void recordKeyShipConsent(sessionUserId).catch(() => {});
              void computeQuestion();
            },
          },
        ]);
        return;
      }
      await computeQuestion();
    } catch (err) {
      reportFailure(err);
    } finally {
      setBusy(false);
    }
  };

  // Key-free auto-load on mount: the baseline generic or an already-stored
  // question becomes visible without a tap. The key-bearing step 3 never
  // runs from here (see load's allowKeyShip guard) — mounting a screen
  // must not ship the data key or fire the consent dialog at the user.
  useEffect(() => {
    void load(false);
    // Stryker disable next-line ArrayDeclaration: the mount effect must run exactly once — load closes over stable setters and a boolean flag, so a literal dep array and [] are behaviorally identical
  }, []);

  const onShowQuestion = () => {
    // A second tap while a load is in flight is a no-op.
    if (busy) return;
    void load(true);
  };

  /** The question → journal bridge: the question becomes the start of
   *  today's entry via the account-bound draft stash. */
  const writeAbout = async (text: string) => {
    // Stryker disable next-line ArrowFunction: null and undefined are both falsy in the !userId branch directly below
    const userId = await api.getUserId().catch(() => null);
    if (!userId) {
      Alert.alert(tr("common.sessionDamagedTitle"), tr("question.accountMissingPlain"));
      return;
    }
    stashDraft(userId, text);
    navigation.navigate("Entry");
  };

  return (
    // Any touch on this screen is real interaction: restart the inactivity
    // countdown so the auto-lock only fires on a genuinely idle session.
    <ScrollView
      style={{ flex: 1, backgroundColor: t.colors.bg }}
      contentContainerStyle={{ flexGrow: 1, paddingBottom: t.spacing.xxxl }}
    >
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
          <Text style={[styles.cardTitle, { color: t.colors.accent }]}>{tr("question.today")}</Text>
          <Text style={[styles.question, { color: t.colors.text }]}>{generic}</Text>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize, lineHeight: 17 }}>
            {phaseAssumedOffline
              ? tr("question.captionOffline")
              : tr("question.baselineCaption", { days: dayProgress?.total ?? 30 })}
          </Text>
          {dayProgress && (
            <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
              {tr("question.dayOf", { active: dayProgress.active, total: dayProgress.total })}
            </Text>
          )}
<GhostButton
            label={tr("question.writeAbout")}
            center={false}
            onPress={() => void writeAbout(generic)}
            accessibilityLabel={tr("question.writeAboutA11y")}
          />
        </View>
      )}
      {question && (
        <View style={[styles.card, { backgroundColor: t.colors.card, borderRadius: t.radius.xl }]}>
          <Text style={[styles.cardTitle, { color: t.colors.accent }]}>{tr("question.today")}</Text>
          <Text style={[styles.question, { color: t.colors.text }]}>{question}</Text>
          <Text style={{ color: t.colors.muted, fontSize: t.type.meta.fontSize }}>
            {tr("question.oneADay")}
          </Text>
                    {patternPid !== null && !feedbackGiven && (
            <View style={{ flexDirection: "row", gap: 8, justifyContent: "center" }}>
              <GhostButton
                label={tr("question.resonated")}
                center={false}
                onPress={() => void recordTap(true)}
                accessibilityLabel={tr("question.resonatedA11y")}
              />
              <GhostButton
                label={tr("question.notMe")}
                center={false}
                onPress={() => void recordTap(false)}
                accessibilityLabel={tr("question.notMeA11y")}
              />
            </View>
          )}
<GhostButton
            label={tr("question.writeAbout")}
            center={false}
            onPress={() => void writeAbout(question)}
            accessibilityLabel={tr("question.writeAboutA11y")}
          />
        </View>
      )}
      <View>
        <PrimaryButton
          label={question ?? generic ? tr("question.refresh") : tr("question.showToday")}
          onPress={onShowQuestion}
          busy={busy}
        />
        <Text style={[styles.caption, { color: t.colors.muted, fontSize: t.type.meta.fontSize }]}>
          {phaseAssumedOffline
            ? tr("question.captionOffline")
            : phase === "baseline"
              ? tr("question.captionBaseline")
              : tr("question.captionInsight")}
        </Text>
      </View>
      <CrisisHelpButton onPress={() => navigation.navigate("Crisis")} />
      </View>
    </ScrollView>
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
