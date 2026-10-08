/**
 * Daily reflective questions with explicit consent for server processing.
 * Before the analysis threshold, the built-in pool answers on-device. An
 * offline phase check uses the same pool; authentication and server errors
 * remain visible.
 *
 * Mounting may fetch phase information and decrypt a stored question, but
 * never opens a processing session. Creating a personalized question needs
 * an explicit button press and per-account consent before the data key is
 * sent to the server's single-use, memory-only processing session.
 *
 * "Write about this" stashes an account-bound draft for EntryScreen.
 */
import React, { useEffect, useRef, useState } from "react";
import { ActivityIndicator, Alert, ScrollView, StyleSheet, Text, View } from "react-native";
import { api, ApiError } from "../api/client";
import { decryptQuestion } from "../crypto/journalCrypto";
import { buildFeedbackBlob, clearFeedback, recordFeedbackTap, type FeedbackReceipt } from "../questionFeedback";
import { lightHaptic } from "../haptics";
import { vault } from "../vault";
import { assertLocalWritePermit, captureLocalWritePermit, type LocalWritePermit } from "../localRekey";
import { localWriteScopeEpoch } from "../localWriteGuard";
import { useSession, stashDraft } from "../store";
import { genericQuestionForDate } from "../genericQuestions";
import { localDateISO } from "../moodLog";
import { useTheme } from "../theme";
import { PrimaryButton, GhostButton, CrisisHelpButton } from "../components/buttons";
import { hasKeyShipConsent, recordKeyShipConsent } from "../components/keyConsent";
import { requestFailureCopy } from "../components/errors";
import { getLocale, t as tr } from "../strings";

/** Calm copy for a failed load: calm request copy for ApiErrors, our own
 *  sentence for local Errors, one generic line for anything else. */
function failureCopy(err: unknown): string {
  if (err instanceof ApiError) return requestFailureCopy(err);
  if (err instanceof Error) return err.message;
  return tr("errors.generic");
}
type QuestionOwnership = { scope: number; owner: string | null; dataKey: Buffer | null; view: number };

export function QuestionScreen({ navigation }: { navigation: any }): React.JSX.Element {
  const t = useTheme();
  // Audit 2026-09-28 (INFO): unlockDays rides along for the baseline
  // caption's fallback (below) — the store's sanitized server value, not a
  // hardcoded 30 (a server configured for a different threshold rendered
  // the wrong count whenever dayProgress had not loaded yet).
  const { touchActivity, unlockDays } = useSession();
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
  const viewGeneration = useRef(0);
  const loadingOperation = useRef<QuestionOwnership | null>(null);
  const computingOperation = useRef<QuestionOwnership | null>(null);
  const captureOwnership = (): QuestionOwnership => ({ scope: localWriteScopeEpoch(), owner: vault.ownerUserId(), dataKey: vault.isUnlocked() ? vault.get().dataKey : null, view: viewGeneration.current });
  const renderedOwnership = captureOwnership();
  const ownsOperation = (operation: QuestionOwnership) => operation.view === viewGeneration.current && operation.scope === localWriteScopeEpoch()
    && operation.owner === vault.ownerUserId() && vault.isUnlocked() && operation.dataKey === vault.get().dataKey;
  const ownsView = (operation: QuestionOwnership) => operation.view === viewGeneration.current
    && operation.owner === vault.ownerUserId() && vault.isUnlocked() && operation.dataKey === vault.get().dataKey;
  const finishBusy = (operation: QuestionOwnership) => {
    if (!ownsView(operation)) return;
    if ((loadingOperation.current && ownsOperation(loadingOperation.current)) || (computingOperation.current && ownsOperation(computingOperation.current))) return;
    setBusy(false);
  };
  const assertOwnership = (operation: QuestionOwnership) => { if (!ownsOperation(operation)) throw new Error(tr("common.sessionDamagedTitle")); };

  const decryptToday = async (operation: QuestionOwnership) => {
    const userId = await api.getUserId();
    assertOwnership(operation);
    if (!userId) throw new Error(tr("common.accountMissing"));
    const direct = await api.questionToday(() => ownsOperation(operation));
    assertOwnership(operation);
    // The blob's AAD is bound to the server's calendar date — always
    // decrypt with the for_date the server reported, never a locally
    // computed "today" (timezones would break authentication).
    return decryptQuestion(vault.get(), userId, direct.for_date, direct.blob);
  };

  /** The pattern behind today's question (null on generic days): powers
   *  the "did this land?" taps (2026-09-17). */
  const [patternPid, setPatternPid] = useState<string | null>(null);
  const [feedbackGiven, setFeedbackGiven] = useState(false);
  const feedbackLatched = useRef(false);
  const feedbackGeneration = useRef(0);
  const renderedFeedbackGeneration = feedbackGeneration.current;
  const displayedQuestion = useRef<{ question: string | null; pid: string | null }>({ question: null, pid: null });
  const showQuestion = (payload: Awaited<ReturnType<typeof decryptToday>>, fresh = false) => {
    const pid = typeof payload.pattern_pid === "string" ? payload.pattern_pid : null;
    if (fresh || displayedQuestion.current.question !== payload.question || displayedQuestion.current.pid !== pid) {
      feedbackGeneration.current++;
      feedbackLatched.current = false;
      setFeedbackGiven(false);
    }
    displayedQuestion.current = { question: payload.question, pid };
    setQuestion(payload.question);
    setPatternPid(pid);
  };
  const recordTap = async (resonated: boolean) => {
    const pid = patternPid;
    if (!pid || feedbackGiven || feedbackLatched.current || renderedFeedbackGeneration !== feedbackGeneration.current) return;
    feedbackLatched.current = true;
    const operation = captureOwnership();
    const feedbackEpoch = feedbackGeneration.current;
    const current = () => ownsOperation(operation) && feedbackEpoch === feedbackGeneration.current;
    const sameQuestionView = () => feedbackEpoch === feedbackGeneration.current && ownsView(operation);
    const assertCurrent = () => { assertOwnership(operation); if (feedbackEpoch !== feedbackGeneration.current) throw new Error(tr("common.sessionDamagedTitle")); };
    setFeedbackGiven(true);
    lightHaptic();
    try {
      const userId = await api.getUserId();
      assertCurrent();
      if (userId && userId === operation.owner) {
        await recordFeedbackTap(operation.dataKey!, userId, pid, resonated, current);
        assertCurrent();
        setNotice(resonated ? tr("question.noticedMore") : tr("question.noticedLess"));
      } else throw new Error(tr("common.sessionDamagedTitle"));
    } catch {
      if (!current() && !sameQuestionView()) return;
      setNotice(tr("question.feedbackSaveFailed"));
      feedbackLatched.current = false;
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
  const computeQuestion = async (operation: QuestionOwnership) => {
    if (!ownsOperation(operation)) return;
    if (computingOperation.current && ownsOperation(computingOperation.current)) return;
    computingOperation.current = operation;
    setBusy(true);
    setError(null);
    setNotice(null);
    let keyCopy: Buffer | null = null;
    let writePermit: LocalWritePermit | null = null;
    const current = () => {
      if (!ownsOperation(operation)) return false;
      if (!writePermit) return true;
      try { assertLocalWritePermit(writePermit); return true; } catch { return false; }
    };
    const submitEpoch = localWriteScopeEpoch();
    try {
      const userId = await api.getUserId();
      assertOwnership(operation);
      if (submitEpoch !== localWriteScopeEpoch()) throw new Error(tr("common.sessionDamagedTitle"));
      if (!userId) throw new Error(tr("common.sessionDamagedTitle"));
      if (vault.ownerUserId() !== userId) throw new Error(tr("common.sessionDamagedTitle"));
      keyCopy = Buffer.from(vault.get().dataKey);
      writePermit = captureLocalWritePermit(userId, keyCopy);
      const assertCurrent = () => { assertOwnership(operation); assertLocalWritePermit(writePermit!); };
      const session = await api.openProcessingSession(keyCopy.toString("base64"), writePermit, current);
      // Pending question-feedback taps ride along, encrypted like every
      // other payload (2026-09-17); cleared once the server consumed them.
      assertCurrent();
      let feedbackReceipt: FeedbackReceipt | undefined;
      const feedbackBlob = await buildFeedbackBlob(keyCopy, userId, receipt => { feedbackReceipt = receipt; }, current);
      assertCurrent();
      let result: Awaited<ReturnType<typeof api.recompute>>;
      try {
        result = await api.recompute(session.session_token, feedbackBlob ?? undefined, current);
      } catch (err) {
        // A feedback blob that failed AEAD can never authenticate again —
        // quarantine it (drop the queue) and finish the recompute without
        // it, instead of failing every question load from now on.
        if (err instanceof ApiError && err.code === "feedback_blob_invalid" && userId) {
          assertCurrent();
          if (feedbackBlob) await clearFeedback(userId, writePermit, feedbackReceipt ? { dataKey: keyCopy, receipt: feedbackReceipt } : undefined, current).catch(() => {});
          // M-12: the failed feedback pre-flight already CONSUMED the
          // single-use processing token server-side (the key is popped
          // before the pre-flight raises) — replaying it is a guaranteed
          // 403 processing_session_invalid and the "transparent recovery"
          // below was dead code. Open a FRESH session — the data key ships
          // once more under the same consent already given for this flow —
          // so the retry can actually run.
          assertCurrent();
          const fresh = await api.openProcessingSession(keyCopy.toString("base64"), writePermit, current);
          assertCurrent();
          result = await api.recompute(fresh.session_token, undefined, current);
        } else {
          throw err;
        }
      }
      assertCurrent();
      if (feedbackBlob) await clearFeedback(userId, writePermit, feedbackReceipt ? { dataKey: keyCopy, receipt: feedbackReceipt } : undefined, current).catch(() => {});
      assertCurrent();
      if (!result.question_stored) {
        setNotice(tr("question.noEvidenceYet"));
        return;
      }
      const payload = await decryptToday(operation);
      assertCurrent();
      showQuestion(payload, true);
    } catch (err) {
      if (current()) reportFailure(err);
    } finally {
      keyCopy?.fill(0);
      if (computingOperation.current === operation) computingOperation.current = null;
      finishBusy(operation);
    }
  };

  const load = async (allowKeyShip: boolean) => {
    if (loadingOperation.current && ownsOperation(loadingOperation.current)) return;
    const operation = captureOwnership();
    loadingOperation.current = operation;
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
        summary = await api.insights(() => ownsOperation(operation));
        assertOwnership(operation);
        setPhaseAssumedOffline(false); // a real answer replaces any assumption
      } catch (err) {
        if (!ownsOperation(operation)) return;
        if (err instanceof ApiError && err.status === 0) {
          // Status 0 means NO RESPONSE (offline, timeout, local refusal) —
          // the phase is unknowable, not "baseline" (audit L-57). The
          // generic question still renders; the captions say what is true.
          setPhase("baseline"); // display path only — see phaseAssumedOffline
          setPhaseAssumedOffline(true);
          setDayProgress(null); // unknown offline — the card omits the day counter
          setGeneric(genericQuestionForDate(localDateISO(), getLocale()));
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
        setDayProgress(Number.isFinite(total) && total > 0 ? { active, total } : null);
        // Day-one value: a reflective question TODAY from the built-in
        // pool, computed on-device — nothing leaves the phone for it, so
        // no key ships and no consent explainer belongs here.
        setGeneric(genericQuestionForDate(localDateISO(), getLocale()));
        return;
      }
      setPhase("insight");
      // 2) A question may already exist for today — no key required either.
      try {
        const payload = await decryptToday(operation);
        assertOwnership(operation);
        // The pid must follow every question swap (a refresh after a
        // recompute would otherwise keep the PREVIOUS question's pid and
        // attribute the taps to the wrong pattern); no pid → none offered.
        showQuestion(payload);
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
      assertOwnership(operation);
      if (!sessionUserId || vault.ownerUserId() !== sessionUserId) {
        throw new Error(tr("question.sessionMismatch"));
      }
      // A failed consent READ errs toward showing the explainer again (the
      // user may never have been told), never toward skipping it silently.
      const consent = await hasKeyShipConsent(sessionUserId).catch(() => false);
      assertOwnership(operation);
      if (!consent) {
        Alert.alert(tr("question.keyShipTitle"), tr("question.keyShipBody"), [
          { text: tr("common.notNow"), style: "cancel" },
          {
            text: tr("common.continue"),
            onPress: () => {
              if (!ownsOperation(operation)) return;
              // Losing this write just shows the explainer again — never
              // block the load on it.
              void recordKeyShipConsent(sessionUserId).catch(() => {});
              void computeQuestion(operation);
            },
          },
        ]);
        return;
      }
      await computeQuestion(operation);
    } catch (err) {
      if (ownsOperation(operation)) reportFailure(err);
    } finally {
      if (loadingOperation.current === operation) loadingOperation.current = null;
      finishBusy(operation);
    }
  };

  // Key-free auto-load on mount: the baseline generic or an already-stored
  // question becomes visible without a tap. The key-bearing step 3 never
  // runs from here (see load's allowKeyShip guard) — mounting a screen
  // must not ship the data key or fire the consent dialog at the user.
  useEffect(() => {
    let owner = vault.ownerUserId(), dataKey = vault.isUnlocked() ? vault.get().dataKey : null;
    const unsubscribe = vault.subscribe(() => {
      const nextOwner = vault.ownerUserId(), nextKey = vault.isUnlocked() ? vault.get().dataKey : null;
      if (owner === nextOwner && dataKey === nextKey) return;
      owner = nextOwner; dataKey = nextKey; viewGeneration.current++;
      feedbackGeneration.current++; feedbackLatched.current = false; displayedQuestion.current = { question: null, pid: null };
      setBusy(false); setQuestion(null); setPatternPid(null); setFeedbackGiven(false); setGeneric(null); setError(null); setNotice(null); setPhase("unknown");
    });
    void load(false);
    return () => { viewGeneration.current++; unsubscribe(); };
  }, []);

  const onShowQuestion = () => {
    // A second tap while a load is in flight is a no-op.
    if (busy) return;
    void load(true);
  };

  /** The question → journal bridge: the question becomes the start of
   *  today's entry via the account-bound draft stash. */
  const writeAbout = async (text: string) => {
    if (!ownsView(renderedOwnership)) return;
    const operation = captureOwnership();
    const userId = await api.getUserId().catch(() => null);
    if (!ownsOperation(operation)) return;
    if (!userId) {
      Alert.alert(tr("common.sessionDamagedTitle"), tr("question.accountMissingPlain"));
      return;
    }
    if (userId !== operation.owner) {
      Alert.alert(tr("common.sessionDamagedTitle"), tr("question.sessionMismatch"));
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
              : tr("question.baselineCaption", { days: dayProgress?.total ?? unlockDays })}
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
