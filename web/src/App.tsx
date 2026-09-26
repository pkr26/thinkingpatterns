/**
 * App shell: a state machine — booting → login → (onboarding) → the app
 * views (today / history / privacy), with the crisis overlay reachable
 * from every state. All key material lives in the memory-only vault
 * (WEB_PLAN D-4): refresh or a new tab forgets everything and asks for the
 * password again.
 *
 * Account-wide death is lazy and honest (D-8): a 401 (token expired, or
 * signed out / password rotated on ANOTHER device) and a 410 (account
 * deleted from another device) each funnel the whole UI back to sign-in
 * with an explanation — never a banner over live keys.
 */
import { useCallback, useEffect, useState } from "react";
import { api, clearSession, setSessionExpiredHandler } from "./api/client";
import { abortInFlightFlush, flushQueueOnReconnect } from "./offlineQueue";
import { useBfcacheGuard, useIdleLock, type LockReason } from "./sessionLock";
import { localStore, onWindowEvent } from "./platform";
import { AppFrame, Button, Card, ErrorBanner, Note } from "./ui";
import { CrisisCard } from "./crisis";
import { LoginView } from "./views/LoginView";
import { hasSeenOnboarding, markOnboardingSeen, Onboarding } from "./views/Onboarding";
import { Privacy } from "./views/Privacy";
import { EntryView } from "./views/Entry";
import { HistoryView } from "./views/History";
import { PatternsView } from "./views/Patterns";
import { QuestionView } from "./views/Question";
import { MeasuresView } from "./views/Measures";
import { ShareView } from "./views/Share";
import { SettingsView } from "./views/Settings";
import { vault } from "./vault";
import { reconcile, type ReconcileOutcome } from "./sync";

type View =
  | { kind: "booting" }
  | { kind: "login"; notice?: string }
  | { kind: "onboarding" }
  | { kind: "today"; savedNote?: string }
  | { kind: "history" }
  | { kind: "patterns" }
  | { kind: "question"; refreshedNote?: string }
  | { kind: "measures" }
  | { kind: "share" }
  | { kind: "settings" }
  | { kind: "privacy" };

/** Brief boot beat so the first paint is never a flash of the wrong state. */
const BOOT_MS = 40;

function noticeFor(reason: "idle" | "bfcache" | "expired" | "deleted"): string {
  switch (reason) {
    case "idle":
      return "Locked after inactivity — sign in again to continue.";
    case "bfcache":
      return "Locked — the page was restored from the browser's back/forward cache.";
    case "expired":
      return "Your session ended — the token expired, or the password was changed / signed out on another device. Sign in again.";
    case "deleted":
      return "This account was deleted.";
  }
}

export function App(): React.JSX.Element {
  const [view, setView] = useState<View>({ kind: "booting" });
  const [crisisOpen, setCrisisOpen] = useState(false);
  const [username, setUsername] = useState("");
  const [errorNote, setErrorNote] = useState<string | null>(null);

  // Boot: this client has no persisted session (D-4) — after the beat, the
  // only honest state is sign-in.
  useEffect(() => {
    const timer = setTimeout(() => setView({ kind: "login" }), BOOT_MS);
    return () => clearTimeout(timer);
  }, []);

  const lockDown = useCallback((notice: string | null): void => {
    // Fence any in-flight queue commit; the ciphertext itself stays parked
    // for the account (sign-out keeps it, D-9).
    abortInFlightFlush();
    clearSession();
    vault.lock();
    setUsername("");
    setView({ kind: "login", ...(notice ? { notice } : {}) });
  }, []);

  // Session-expiry funnel: any 401/410 from the client fires once per
  // session and lands here with the reason.
  useEffect(() => {
    setSessionExpiredHandler((err) => {
      lockDown(err.status === 410 ? noticeFor("deleted") : noticeFor("expired"));
    });
    return () => setSessionExpiredHandler(null);
  }, [lockDown]);

  // Idle auto-lock + bfcache guard are armed exactly while a session
  // exists (anything past login).
  const sessionActive =
    view.kind === "onboarding" || view.kind === "today" || view.kind === "history"
    || view.kind === "patterns" || view.kind === "question" || view.kind === "privacy";
  const onLock = useCallback((reason: LockReason) => lockDown(noticeFor(reason)), [lockDown]);
  useIdleLock(sessionActive, onLock);
  useBfcacheGuard(sessionActive, onLock);

  // Reconnect: flush the offline queue (throttled + Web Locks-serialized
  // inside flushQueueOnReconnect), only while a session exists.
  useEffect(() => {
    if (!sessionActive) return;
    return onWindowEvent("online", () => void flushQueueOnReconnect());
  }, [sessionActive]);

  // Multi-device reconciliation (P5/S-1): pull fresh truth on regained
  // focus and connectivity. The outcomes are honest funnels, not banners.
  const onReconcile = useCallback((outcome: ReconcileOutcome): void => {
    if (outcome.kind === "credentialRotated") {
      lockDown("Your password was changed on another device and your journal was re-encrypted — sign in again with the new password.");
      return;
    }
    if (outcome.kind === "freshness") {
      setErrorNote("Your pattern data failed its freshness check — it may have been replayed. Pull again in a moment.");
      return;
    }
    if (outcome.kind === "error") setErrorNote(outcome.message);
  }, [lockDown]);
  useEffect(() => {
    if (!sessionActive) return;
    const offOnline = onWindowEvent("online", () => void reconcile().then(onReconcile).catch(() => undefined));
    const offVisible = onWindowEvent("visibilitychange", () => {
      try {
        if (document.visibilityState === "visible") void reconcile().then(onReconcile).catch(() => undefined);
      } catch {
        // No document (node runtime): focus reconciliation is browser-only.
      }
    });
    return () => {
      offOnline();
      offVisible();
    };
  }, [sessionActive, onReconcile]);

  const onLoginSuccess = useCallback((success: { userId: string; username: string }) => {
    setUsername(success.username);
    if (hasSeenOnboarding(success.userId, localStore.get)) {
      setView({ kind: "today" });
    } else {
      setView({ kind: "onboarding" });
    }
  }, []);

  const onOnboardingDone = useCallback(() => {
    const userId = vault.ownerUserId();
    if (userId) markOnboardingSeen(userId, localStore.set);
    setView({ kind: "today" });
  }, []);

  const signOut = useCallback(() => {
    // Logout bumps the token epoch account-wide (every device, including
    // the mobile app, signs out too) — the button copy says so.
    void api.logout().catch(() => undefined);
    lockDown(null);
  }, [lockDown]);

  const onSaved = useCallback((result: "sent" | "queued", _date: string): void => {
    setView((current) =>
      current.kind === "today"
        ? { ...current, savedNote: result === "sent" ? "Saved." : "Saved offline — it will sync when you're back." }
        : current,
    );
  }, []);

  const inApp =
    view.kind === "today" || view.kind === "history" || view.kind === "patterns"
    || view.kind === "question" || view.kind === "measures" || view.kind === "share" || view.kind === "settings";

  return (
    <AppFrame title="MindPattern" onCrisis={() => setCrisisOpen(true)}>
      {crisisOpen ? (
        <CrisisCard onClose={() => setCrisisOpen(false)} />
      ) : view.kind === "booting" ? (
        <Card>
          <Note role="status">Starting…</Note>
        </Card>
      ) : view.kind === "login" ? (
        <>
          {view.notice && <ErrorBanner message={view.notice} />}
          <LoginView onSuccess={onLoginSuccess} />
        </>
      ) : view.kind === "onboarding" ? (
        <Onboarding onDone={onOnboardingDone} />
      ) : view.kind === "privacy" ? (
        <Privacy onBack={() => setView({ kind: "today" })} />
      ) : (
        <>
          {errorNote && <ErrorBanner message={errorNote} />}
          <nav style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center", marginBottom: 12 }}>
            <Button label="Today" onPress={() => setView({ kind: "today" })} small={view.kind !== "today"} disabled={view.kind === "today"} />
            <Button label="History" onPress={() => setView({ kind: "history" })} small disabled={view.kind === "history"} />
            <Button label="Patterns" onPress={() => setView({ kind: "patterns" })} small disabled={view.kind === "patterns"} />
            <Button label="Question" onPress={() => setView({ kind: "question" })} small disabled={view.kind === "question"} />
            <Button label="Measures" onPress={() => setView({ kind: "measures" })} small disabled={view.kind === "measures"} />
            <Button label="Share" onPress={() => setView({ kind: "share" })} small disabled={view.kind === "share"} />
            <Button label="Settings" onPress={() => setView({ kind: "settings" })} small disabled={view.kind === "settings"} />
            <span style={{ flex: 1 }} />
            <Button label="Privacy" onPress={() => setView({ kind: "privacy" })} small />
            <Button label="Sign out (all devices)" onPress={signOut} small danger />
          </nav>
          {view.kind === "today" ? (
            <>
              {view.savedNote && <Note role="status" tone="ok">{view.savedNote}</Note>}
              <EntryView onSaved={onSaved} />
            </>
          ) : view.kind === "patterns" ? (
            <PatternsView onCrisis={() => setCrisisOpen(true)} />
          ) : view.kind === "question" ? (
            <>
              {view.refreshedNote && <Note role="status" tone="ok">{view.refreshedNote}</Note>}
              <QuestionView onRefreshed={(message) => setView({ kind: "question", refreshedNote: message })} />
            </>
          ) : view.kind === "measures" ? (
            <MeasuresView onCrisis={() => setCrisisOpen(true)} />
          ) : view.kind === "share" ? (
            <ShareView />
          ) : view.kind === "settings" ? (
            <SettingsView onLockdown={(notice) => lockDown(notice)} />
          ) : (
            <HistoryView />
          )}
        </>
      )}
      {inApp && username && <Note tone="muted">{`Signed in as ${username}`}</Note>}
    </AppFrame>
  );
}
