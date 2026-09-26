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
import { useBfcacheGuard, useHiddenTabLock, useIdleLock, type LockReason } from "./sessionLock";
import { isOnline, localStore, onWindowEvent } from "./platform";
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
import { t } from "./strings";

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
/** How often a live session re-attempts the offline queue. Bounds the
 * stranding window for entries parked while the browser still believed it
 * was online (audit 2026-09-25); the flush itself is throttled further and
 * Web-Locks-serialized inside flushQueueOnReconnect. */
const QUEUE_FLUSH_INTERVAL_MS = 30_000;

function noticeFor(reason: LockReason | "expired" | "deleted"): string {
  switch (reason) {
    case "idle":
      return t("app.noticeIdle");
    case "bfcache":
      return t("app.noticeBfcache");
    case "hidden":
      return t("app.noticeHidden");
    case "expired":
      return t("app.noticeExpired");
    case "deleted":
      return t("app.noticeDeleted");
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

  // The views that hold a live session: everything past login. This is ONE
  // list on purpose (audit 2026-09-25: it had drifted to miss measures/
  // share/settings, leaving keys in memory with no idle lock there).
  const inApp =
    view.kind === "today" || view.kind === "history" || view.kind === "patterns"
    || view.kind === "question" || view.kind === "measures" || view.kind === "share" || view.kind === "settings";
  const sessionActive = inApp || view.kind === "onboarding" || view.kind === "privacy";
  const onLock = useCallback((reason: LockReason) => lockDown(noticeFor(reason)), [lockDown]);
  useIdleLock(sessionActive, onLock);
  useBfcacheGuard(sessionActive, onLock);
  // W-1 (audit 2026-09-25): mobile locks the vault the moment the app is
  // backgrounded; the web equivalent — the tab going hidden — must do the
  // same, or decrypted text stays rendered (and readable in tab previews)
  // indefinitely while the user is elsewhere.
  useHiddenTabLock(sessionActive, onLock);

  // Reconnect: flush the offline queue (throttled + Web Locks-serialized
  // inside flushQueueOnReconnect), only while a session exists.
  useEffect(() => {
    if (!sessionActive) return;
    return onWindowEvent("online", () => void flushQueueOnReconnect());
  }, [sessionActive]);

  // The `online` event only fires on an offline→online TRANSITION: entries
  // parked while the browser still believed it was online (server 5xx,
  // timeouts — audit 2026-09-25) would otherwise wait forever. A periodic
  // flush attempt while a session exists bounds that wait; it is free when
  // the queue is empty (flushQueueOnReconnect checks the length first).
  useEffect(() => {
    if (!sessionActive) return;
    const timer = setInterval(() => {
      if (isOnline()) void flushQueueOnReconnect();
    }, QUEUE_FLUSH_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [sessionActive]);

  // Multi-device reconciliation (P5/S-1): pull fresh truth on regained
  // focus and connectivity. The outcomes are honest funnels, not banners.
  const onReconcile = useCallback((outcome: ReconcileOutcome): void => {
    if (outcome.kind === "credentialRotated") {
      lockDown(t("app.noticeRotatedElsewhere"));
      return;
    }
    if (outcome.kind === "freshness") {
      setErrorNote(t("app.freshnessNote"));
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
    // Sign-in is an honest moment to drain anything this browser parked
    // earlier (D-9 keeps ciphertext across sign-out) — one entry point of
    // the anti-stranding contract alongside the periodic flush above.
    void flushQueueOnReconnect();
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
    // W-6 (audit 2026-09-25): sign-out wipes this browser's non-content
    // mindpattern.* flags (onboarding/mute/threshold stamps) like mobile
    // wipes its origin-bound state — a shared computer keeps no trace that
    // an account used it. Idle/expiry locks deliberately keep them.
    localStore.removePrefix("mindpattern.");
    lockDown(null);
  }, [lockDown]);

  const onSaved = useCallback((result: "sent" | "queued", _date: string): void => {
    // A direct save that reached the server proves connectivity RIGHT NOW:
    // drain anything parked earlier immediately instead of waiting for the
    // periodic flush (the `online` event may never have fired).
    if (result === "sent") void flushQueueOnReconnect();
    setView((current) =>
      current.kind === "today"
        ? { ...current, savedNote: result === "sent" ? t("app.saved") : t("app.savedOffline") }
        : current,
    );
  }, []);

  return (
    <AppFrame title="MindPattern" onCrisis={() => setCrisisOpen(true)}>
      {crisisOpen ? (
        <CrisisCard onClose={() => setCrisisOpen(false)} />
      ) : view.kind === "booting" ? (
        <Card>
          <Note role="status">{t("app.starting")}</Note>
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
            <Button label={t("nav.today")} onPress={() => setView({ kind: "today" })} small={view.kind !== "today"} disabled={view.kind === "today"} />
            <Button label={t("nav.history")} onPress={() => setView({ kind: "history" })} small disabled={view.kind === "history"} />
            <Button label={t("nav.patterns")} onPress={() => setView({ kind: "patterns" })} small disabled={view.kind === "patterns"} />
            <Button label={t("nav.question")} onPress={() => setView({ kind: "question" })} small disabled={view.kind === "question"} />
            <Button label={t("nav.measures")} onPress={() => setView({ kind: "measures" })} small disabled={view.kind === "measures"} />
            <Button label={t("nav.share")} onPress={() => setView({ kind: "share" })} small disabled={view.kind === "share"} />
            <Button label={t("nav.settings")} onPress={() => setView({ kind: "settings" })} small disabled={view.kind === "settings"} />
            <span style={{ flex: 1 }} />
            <Button label={t("nav.privacy")} onPress={() => setView({ kind: "privacy" })} small />
            <Button label={t("nav.signOutAll")} onPress={signOut} small danger />
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
      {inApp && username && <Note tone="muted">{t("app.signedInAs", { name: username })}</Note>}
    </AppFrame>
  );
}
