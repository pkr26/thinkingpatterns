/**
 * App shell: a state machine — booting → login → (onboarding) → the app
 * views (today / history / privacy), with the crisis overlay reachable
 * from every state. All key material lives in the memory-only vault
 * (WEB_PLAN D-4): refresh or a new tab forgets everything and asks for
 * the password again.
 *
 * Account-wide death is lazy and honest (D-8): a 401 (token expired, or
 * signed out / password rotated on ANOTHER device) and a 410 (account
 * deleted from another device) each funnel the whole UI back to sign-in
 * with an explanation — never a banner over live keys.
 *
 * Redesign 2026-09-26: navigation is real tabs on desktop (Today /
 * History / Patterns / Question + a More menu) and a bottom tab bar on
 * phones; save/refresh confirmations surface as gentle toasts; the
 * crisis resources open as an overlay dialog. The view state machine,
 * session funnels, and privacy posture are untouched.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { api, clearSession, setSessionExpiredHandler } from "./api/client";
import { abortInFlightFlush, flushQueueOnReconnect } from "./offlineQueue";
import { preserveActiveDraft } from "./entryDraft";
import { adoptLegacyPlaintextMutes } from "./patternMutes";
import { useBfcacheGuard, useHiddenTabLock, useIdleLock, type LockReason } from "./sessionLock";
import { subscribeTabLockdown } from "./tabLockdown";
import { sweepLegacyCrisisStamps } from "./crisisDialog";
import { isOnline, localStore, onWindowEvent } from "./platform";
import { AppFrame, BottomNav, Card, ErrorBanner, MoreMenu, NavTabs, Note, ToastHost, type IconName, type NavItem, type ToastItem } from "./ui";
import { CrisisCard } from "./crisis";
import { LoginView } from "./views/LoginView";
import { hasSeenOnboarding, markOnboardingSeen, Onboarding } from "./views/Onboarding";
import { Privacy } from "./views/Privacy";
import { EntryView } from "./views/Entry";
import { HistoryView } from "./views/History";
import { PatternsView } from "./views/Patterns";
import { QuestionView } from "./views/Question";
import { MeasuresView } from "./views/Measures";
import { SafetyPlanView } from "./views/SafetyPlan";
import { ShareView } from "./views/Share";
import { SettingsView } from "./views/Settings";
import { vault } from "./vault";
import { reconcile, type ReconcileOutcome } from "./sync";
import { subscribeLanguage, t } from "./strings";
import { ViewBoundary } from "./ErrorBoundary";

type View =
  | { kind: "booting" }
  | { kind: "login"; notice?: string }
  | { kind: "onboarding" }
  | { kind: "today" }
  | { kind: "history" }
  | { kind: "patterns" }
  | { kind: "question" }
  | { kind: "measures" }
  | { kind: "safetyplan" }
  | { kind: "share" }
  | { kind: "settings" }
  | { kind: "privacy" };

/** Brief boot beat so the first paint is never a flash of the wrong state. */
const BOOT_MS = 40;
/** How often a live session re-attempts the offline queue. Bounds the
 *  stranding window for entries parked while the browser still believed it
 *  was online (audit 2026-09-25); the flush itself is throttled further and
 *  Web-Locks-serialized inside flushQueueOnReconnect. */
const QUEUE_FLUSH_INTERVAL_MS = 30_000;
/** Gentle toast lifetime — enough to read, never in the way. */
const TOAST_MS = 4200;

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

const PRIMARY_VIEWS: { kind: View["kind"]; labelKey: string; icon: IconName }[] = [
  { kind: "today", labelKey: "nav.today", icon: "home" },
  { kind: "history", labelKey: "nav.history", icon: "book" },
  { kind: "patterns", labelKey: "nav.patterns", icon: "sparkles" },
  { kind: "question", labelKey: "nav.question", icon: "help" },
];
const MORE_VIEWS: { kind: View["kind"]; labelKey: string; icon: IconName; danger?: boolean }[] = [
  { kind: "measures", labelKey: "nav.measures", icon: "clipboard" },
  // The local safety plan (clinical review 2026-09-27): reachable from
  // the More menu AND from the crisis dialog / Settings — and listed here
  // so the idle/hidden-tab lock stays armed on the view (the audit
  // 2026-09-25 rule: every live-session view must lock).
  { kind: "safetyplan", labelKey: "nav.safetyPlan", icon: "heart" },
  { kind: "share", labelKey: "nav.share", icon: "share" },
  { kind: "settings", labelKey: "nav.settings", icon: "sliders" },
  { kind: "privacy", labelKey: "nav.privacy", icon: "shield" },
];

const PRIMARY_KINDS = new Set(PRIMARY_VIEWS.map((item) => item.kind));
const MORE_KINDS = new Set(MORE_VIEWS.map((item) => item.kind));

export function App(): React.JSX.Element {
  const [view, setView] = useState<View>({ kind: "booting" });
  const [crisisOpen, setCrisisOpen] = useState(false);
  const [username, setUsername] = useState("");
  const [errorNote, setErrorNote] = useState<string | null>(null);
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextToastId = useRef(0);

  const notify = useCallback((message: string, tone: ToastItem["tone"] = "ok"): void => {
    const id = (nextToastId.current += 1);
    setToasts((current) => [...current.slice(-2), { id, message, tone }]);
    setTimeout(() => setToasts((current) => current.filter((toast) => toast.id !== id)), TOAST_MS);
  }, []);

  // Boot: this client has no persisted session (D-4) — after the beat, the
  // only honest state is sign-in.
  useEffect(() => {
    const timer = setTimeout(() => setView({ kind: "login" }), BOOT_MS);
    return () => clearTimeout(timer);
  }, []);

  // L-8 (2026-09-28 audit): sweep the pre-2026-09-27 plaintext crisis
  // stamps for EVERY visitor at mount — the module-scoped trigger only
  // fired when a crisis-flagged save first consulted it.
  useEffect(() => {
    sweepLegacyCrisisStamps();
  }, []);

  const lockDown = useCallback((notice: string | null): void => {
    // FIRST, seal the in-progress journal draft under the data key while it
    // still exists (audit 2026-09-26, MEDIUM user-data-loss): the hidden-
    // tab/idle locks unmount the editor, and the draft used to die with it.
    // Fire-and-forget by contract — the key bytes are snapshotted
    // synchronously and a failed seal never blocks the lock.
    void preserveActiveDraft();
    // Fence any in-flight queue commit; the ciphertext itself stays parked
    // for the account (sign-out keeps it, D-9).
    abortInFlightFlush();
    clearSession();
    vault.lock();
    setUsername("");
    setView({ kind: "login", ...(notice ? { notice } : {}) });
  }, []);

  // Language preference (audit 2026-09-26 LOW): a change in Settings
  // applies LIVE — the strings seam notifies and the shell re-renders, so
  // every t() on screen re-resolves without waiting for the next load.
  const [, setLanguageTick] = useState(0);
  useEffect(() => subscribeLanguage(() => setLanguageTick((tick) => tick + 1)), []);

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
  const inApp = PRIMARY_KINDS.has(view.kind) || MORE_KINDS.has(view.kind);
  const sessionActive = inApp || view.kind === "onboarding" || view.kind === "privacy";
  const onLock = useCallback((reason: LockReason) => lockDown(noticeFor(reason)), [lockDown]);
  useIdleLock(sessionActive, onLock);
  useBfcacheGuard(sessionActive, onLock);
  // W-1 (audit 2026-09-25): mobile locks the vault the moment the app is
  // backgrounded; the web equivalent — the tab going hidden — must do the
  // same, or decrypted text stays rendered (and readable in tab previews)
  // indefinitely while the user is elsewhere.
  useHiddenTabLock(sessionActive, onLock);
  // M-4 (2026-09-28 audit): another tab starting a password rotation
  // broadcasts a lockdown BEFORE its first server step — this tab's old
  // key + live bearer must not upload old-key blobs to a rekeyed corpus.
  // Same funnel as every other lock, with the rotated-elsewhere copy.
  useEffect(() => {
    if (!sessionActive) return;
    return subscribeTabLockdown(() => lockDown(t("app.noticeRotatedElsewhere")));
  }, [sessionActive, lockDown]);

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
    // 2026-09-26 audit follow-up (B-6): adopt any pre-fix plaintext mute
    // list the moment the vault holds THIS account's keys — the plaintext
    // copy must not survive until the user happens to visit Patterns (the
    // idempotent Patterns mount call stays). Best-effort by contract: it
    // never blocks app start.
    if (vault.ownerUserId() === success.userId && vault.isUnlocked()) {
      void adoptLegacyPlaintextMutes(vault.get().dataKey, success.userId).catch(() => undefined);
    }
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
    // Logout is PER-DEVICE since the 2026-09-26 wave: the server records
    // this bearer's jti and only this session's token dies — other signed-
    // in devices stay live (the button copy says exactly that). Legacy
    // jti-less bearers still trigger the account-wide epoch bump
    // server-side; this client always holds a jti-bearing token.
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
    notify(result === "sent" ? t("app.saved") : t("app.savedOffline"), result === "sent" ? "ok" : "warn");
  }, [notify]);

  const navItems: NavItem[] = PRIMARY_VIEWS.map((item) => ({ id: item.kind, label: t(item.labelKey), icon: item.icon }));
  const moreItems = [
    ...MORE_VIEWS.map((item) => ({ id: item.kind, label: t(item.labelKey), icon: item.icon })),
    { id: "signout", label: t("nav.signOut"), icon: "logout" as IconName, danger: true },
  ];
  const onNavSelect = useCallback((id: string) => {
    if (id === "signout") {
      signOut();
      return;
    }
    setView({ kind: id as View["kind"] });
  }, [signOut]);
  const activeMore = MORE_KINDS.has(view.kind) ? [view.kind as string] : [];

  return (
    <AppFrame title="MindPattern" onCrisis={() => setCrisisOpen(true)}>
      {view.kind === "booting" ? (
        <div className="view-enter">
          <Card>
            <Note role="status">{t("app.starting")}</Note>
          </Card>
        </div>
      ) : view.kind === "login" ? (
        <div className="view-enter">
          {view.notice && <ErrorBanner message={view.notice} />}
          <LoginView onSuccess={onLoginSuccess} />
        </div>
      ) : view.kind === "onboarding" ? (
        <div className="view-enter">
          <Onboarding onDone={onOnboardingDone} />
        </div>
      ) : view.kind === "privacy" ? (
        <div className="view-enter">
          <Privacy onBack={() => setView({ kind: "today" })} />
        </div>
      ) : (
        // The crisis overlay renders ON TOP of this content (below), so
        // opening help never loses the user's place in the app.
        <div className="view-enter" key={view.kind} style={{ display: "flex", flexDirection: "column", gap: "var(--space-4)" }}>
          {errorNote && <ErrorBanner message={errorNote} />}
          {/* Desktop chrome: tabs + More. Hidden on phones, where the
              bottom bar (with its own More) takes over. */}
          <div className="nav-row row row--wrap row--between">
            <NavTabs items={navItems} activeId={PRIMARY_KINDS.has(view.kind) ? view.kind : null} onSelect={onNavSelect} />
            <MoreMenu label={t("nav.more")} items={moreItems} activeIds={activeMore} onSelect={onNavSelect} />
          </div>
          {/* 2026-09-29 audit HIGH: one view crashing must not take the
              whole app with it — the boundary keeps the frame, nav and the
              crisis overlay alive, and seals the on-screen draft before
              showing the calm panel. Keyed by view so navigating away from
              a crashed view recovers without a reload. */}
          <ViewBoundary resetKey={view.kind}>
          {view.kind === "today" ? (
            <EntryView onSaved={onSaved} />
          ) : view.kind === "patterns" ? (
            <PatternsView onCrisis={() => setCrisisOpen(true)} />
          ) : view.kind === "question" ? (
            <QuestionView onRefreshed={(message) => notify(message)} />
          ) : view.kind === "measures" ? (
            <MeasuresView onCrisis={() => setCrisisOpen(true)} />
          ) : view.kind === "safetyplan" ? (
            <SafetyPlanView onCrisis={() => setCrisisOpen(true)} />
          ) : view.kind === "share" ? (
            <ShareView />
          ) : view.kind === "settings" ? (
            <SettingsView onLockdown={(notice) => lockDown(notice)} onOpenSafetyPlan={() => setView({ kind: "safetyplan" })} />
          ) : (
            <HistoryView />
          )}
          </ViewBoundary>
          {username && <Note tone="muted">{t("app.signedInAs", { name: username })}</Note>}
        </div>
      )}
      {/* The crisis overlay's plan link closes the overlay and opens the
          plan view; CrisisCard itself renders the link ONLY while the
          vault is unlocked (the plan is data-key-encrypted), and always
          BELOW the static crisis resources — the numbers stay first in
          every state. */}
      {crisisOpen && (
        <CrisisCard
          onClose={() => setCrisisOpen(false)}
          onMakeSafetyPlan={() => {
            setCrisisOpen(false);
            setView({ kind: "safetyplan" });
          }}
        />
      )}
      {inApp && (
        <BottomNav
          items={navItems}
          activeId={PRIMARY_KINDS.has(view.kind) ? view.kind : null}
          onSelect={onNavSelect}
          more={<MoreMenu label={t("nav.more")} items={moreItems} activeIds={activeMore} onSelect={onNavSelect} up />}
        />
      )}
      <ToastHost items={toasts} />
    </AppFrame>
  );
}
