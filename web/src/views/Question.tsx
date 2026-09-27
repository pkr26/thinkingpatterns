/**
 * The daily reflective question + the EXPLICIT recompute (WEB_PLAN P6.4).
 * Nothing ships the data key automatically, ever: the "Refresh patterns"
 * button is the only path that opens the single-use processing session —
 * the posture mobile settled after the red-team audit. Question feedback
 * ("resonated / not me") is encrypted locally and rides the next
 * recompute as an opaque blob.
 *
 * M-W5 (audit 2026-09-26): the built-in generic question pool finally has
 * a consumer — the 404 (baseline, no question yet) and offline branches
 * render today's on-device question (localized) instead of dead code,
 * exactly like mobile QuestionScreen's baseline/offline captions.
 *
 * Redesign 2026-09-26: the question renders as a calm hero card; the
 * feedback buttons are real aria-pressed toggles with check icons (the
 * "✓ " label-prefix hack is retired); the refresh consent card leads
 * with a shield cue.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { toBase64 } from "../crypto/core";
import { decryptQuestion } from "../crypto/patient";
import { genericQuestionForDate } from "../genericQuestions";
import { localDateISO } from "../dates";
import { buildFeedbackBlob, clearFeedback, recordFeedbackTap } from "../questionFeedback";
import { reconcile } from "../sync";
import { isOnline } from "../platform";
import { getLocale, t } from "../strings";
import { vault } from "../vault";
import { Button, Card, Chip, ErrorBanner, Icon, Note } from "../ui";

export function QuestionView(props: { onRefreshed: (message: string) => void }): React.JSX.Element {
  const [question, setQuestion] = useState<{ text: string; pid?: string; forDate: string } | null>(null);
  const [answered, setAnswered] = useState<"resonated" | "not-me" | null>(null);
  // The on-device fallback question (M-W5): `offline` picks the honest
  // caption — status 0 never claims to know the account's phase (L-57).
  const [generic, setGeneric] = useState<{ text: string; offline: boolean } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    setError("");
    // Keys snapshotted at entry, AFTER the guard (audit 2026-09-26 LOW):
    // vault.get() used to sit after the network await, where a lock landing
    // mid-flight turned its throw into a reject-shaped banner. A zeroized
    // shared buffer simply fails the decrypt below — handled, quiet.
    const keys = vault.get();
    try {
      const today = await api.questionToday();
      if (generation.current !== run) return;
      const payload = await decryptQuestion(keys.dataKey, owner, today.for_date, today.blob);
      setQuestion({ text: payload.question, pid: payload.pattern_pid, forDate: today.for_date });
      setGeneric(null);
    } catch (err) {
      if (generation.current !== run) return;
      if (err instanceof ApiError && err.status === 404) {
        // Baseline phase: 404 is the honest "no question yet" — today's
        // reflective question comes from the built-in LOCALIZED pool,
        // computed on-device; nothing leaves this device for it.
        setQuestion(null);
        setGeneric({ text: genericQuestionForDate(localDateISO(), getLocale()), offline: false });
        return;
      }
      if (err instanceof ApiError && err.status === 0) {
        // Offline/timeout: the phase is unknowable, but the generic pool
        // never needed the network — the user still gets today's question
        // with the caption that says what is true (mobile L-57 parity).
        setQuestion(null);
        setGeneric({ text: genericQuestionForDate(localDateISO(), getLocale()), offline: true });
        return;
      }
      setError(err instanceof Error ? err.message : t("question.loadFailed"));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const tap = useCallback(async (resonated: boolean): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked() || !question?.pid) return;
    setAnswered(resonated ? "resonated" : "not-me");
    await recordFeedbackTap(vault.get().dataKey, owner, question.pid, resonated).catch(() => undefined);
  }, [question]);

  const refreshPatterns = useCallback(async (): Promise<void> => {
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError(t("common.sessionLocked"));
      return;
    }
    if (!isOnline()) {
      setError(t("question.refreshOffline"));
      return;
    }
    setBusy(true);
    setError("");
    const keys = vault.get();
    try {
      // The ONLY place the data key leaves the client: a single-use,
      // TTL-bounded processing session opened by this explicit button.
      const session = await api.openProcessingSession(toBase64(keys.dataKey));
      const feedback = await buildFeedbackBlob(keys.dataKey, owner).catch(() => null);
      const result = await api.recompute(session.session_token, feedback ?? undefined);
      if (feedback) await clearFeedback(owner).catch(() => undefined);
      await reconcile().catch(() => undefined);
      props.onRefreshed(
        result.phase === "baseline"
          ? result.days_remaining === undefined
            ? t("question.refreshBaselineUnknown")
            : t(result.days_remaining === 1 ? "question.refreshBaselineOne" : "question.refreshBaselineMany", { days: result.days_remaining })
          : t("question.refreshDone"),
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("question.refreshFailed"));
    } finally {
      setBusy(false);
    }
  }, [load, props]);

  return (
    <>
      <Card title={t("question.titleWeb")}>
        {question ? (
          <>
            <Note tone="lead">{question.text}</Note>
            {question.pid ? (
              <div className="row row--wrap">
                <Chip label={t("question.resonated")} icon="heart" selected={answered === "resonated"} disabled={answered !== null} onPress={() => void tap(true)} />
                <Chip label={t("question.notMe")} icon="x" selected={answered === "not-me"} disabled={answered !== null} onPress={() => void tap(false)} />
              </div>
            ) : (
              <Note tone="muted">{t("question.noPidNote")}</Note>
            )}
            {answered && <Note role="status" tone="ok">{t("question.noted")}</Note>}
          </>
        ) : generic ? (
          <>
            <Note tone="lead">{generic.text}</Note>
            <Note tone="muted">{t(generic.offline ? "question.captionOffline" : "question.captionBaseline")}</Note>
          </>
        ) : (
          <Note role="status">{t("common.loading")}</Note>
        )}
        <ErrorBanner message={error} />
      </Card>

      <Card title={t("question.refreshTitle")}>
        <span className="row" style={{ gap: 10, alignItems: "flex-start" }}>
          <span style={{ color: "var(--primary-strong)", flex: "none", paddingTop: 2 }}><Icon name="shield" size={22} /></span>
          <Note>{t("question.refreshBody")}</Note>
        </span>
        <Button label={busy ? t("question.refreshing") : t("question.refreshPatterns")} icon="refresh" onPress={() => void refreshPatterns()} disabled={busy} />
      </Card>
    </>
  );
}
