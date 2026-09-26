/**
 * The daily reflective question + the EXPLICIT recompute (WEB_PLAN P6.4).
 * Nothing ships the data key automatically, ever: the "Refresh patterns"
 * button is the only path that opens the single-use processing session —
 * the posture mobile settled after the red-team audit. Question feedback
 * ("resonated / not me") is encrypted locally and rides the next
 * recompute as an opaque blob.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, ApiError } from "../api/client";
import { decryptQuestion } from "../crypto/patient";
import { buildFeedbackBlob, clearFeedback, recordFeedbackTap } from "../questionFeedback";
import { reconcile } from "../sync";
import { isOnline } from "../platform";
import { vault } from "../vault";
import { Button, Card, ErrorBanner, Note } from "../ui";

export function QuestionView(props: { onRefreshed: (message: string) => void }): React.JSX.Element {
  const [question, setQuestion] = useState<{ text: string; pid?: string; forDate: string } | null>(null);
  const [answered, setAnswered] = useState<"resonated" | "not-me" | null>(null);
  const [absent, setAbsent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const generation = useRef(0);

  const load = useCallback(async (): Promise<void> => {
    const run = generation.current + 1;
    generation.current = run;
    const owner = vault.ownerUserId();
    if (!owner || !vault.isUnlocked()) {
      setError("Your session locked — sign in again.");
      return;
    }
    setError("");
    try {
      const today = await api.questionToday();
      if (generation.current !== run) return;
      const payload = await decryptQuestion(vault.get().dataKey, owner, today.for_date, today.blob);
      setQuestion({ text: payload.question, pid: payload.pattern_pid, forDate: payload.for_date });
      setAbsent(false);
    } catch (err) {
      if (generation.current !== run) return;
      if (err instanceof ApiError && err.status === 404) {
        setAbsent(true); // baseline phase: 404 is the honest "no question yet"
        setQuestion(null);
        return;
      }
      setError(err instanceof Error ? err.message : "Could not load today's question.");
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
      setError("Your session locked — sign in again.");
      return;
    }
    if (!isOnline()) {
      setError("Refreshing patterns needs a connection.");
      return;
    }
    setBusy(true);
    setError("");
    const keys = vault.get();
    try {
      // The ONLY place the data key leaves the client: a single-use,
      // TTL-bounded processing session opened by this explicit button.
      let dataKeyB64 = "";
      let raw = "";
      let binary = "";
      for (const byte of keys.dataKey) binary += String.fromCharCode(byte);
      raw = binary;
      dataKeyB64 = btoa(raw);
      const session = await api.openProcessingSession(dataKeyB64);
      const feedback = await buildFeedbackBlob(keys.dataKey, owner).catch(() => null);
      const result = await api.recompute(session.session_token, feedback ?? undefined);
      if (feedback) await clearFeedback(owner).catch(() => undefined);
      await reconcile().catch(() => undefined);
      props.onRefreshed(
        result.phase === "baseline"
          ? `Baseline updated — ${result.days_remaining ?? "…"} active day${(result.days_remaining ?? 1) === 1 ? "" : "s"} to go.`
          : "Patterns refreshed.",
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not refresh patterns.");
    } finally {
      setBusy(false);
    }
  }, [load, props]);

  return (
    <>
      <Card title="Today's question">
        {question ? (
          <>
            <Note>{question.text}</Note>
            {question.pid ? (
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <Button label={answered === "resonated" ? "✓ This resonated" : "This resonated"} onPress={() => void tap(true)} small disabled={answered !== null} />
                <Button label={answered === "not-me" ? "✓ Not me" : "Not me"} onPress={() => void tap(false)} small disabled={answered !== null} />
              </div>
            ) : (
              <Note tone="muted">A reflective question from today's writing rhythm — no answer is required.</Note>
            )}
            {answered && <Note role="status" tone="ok">Noted — it shapes future questions, privately.</Note>}
          </>
        ) : absent ? (
          <Note>Questions begin with your patterns. Keep journaling — thirty active days unlock them.</Note>
        ) : (
          <Note role="status">Loading…</Note>
        )}
        <ErrorBanner message={error} />
      </Card>

      <Card title="Refresh patterns">
        <Note>{"Runs the analysis over your encrypted journal. This is the ONLY action that sends your key to the server — inside a single-use session that is destroyed the moment the analysis finishes."}</Note>
        <Button label={busy ? "Refreshing…" : "Refresh patterns"} onPress={() => void refreshPatterns()} disabled={busy} />
      </Card>
    </>
  );
}
