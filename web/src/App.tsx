/**
 * Patient app navigation, session lifecycle, and crisis resources.
 *
 * Keys remain in the memory-only vault. Session expiry and remote account
 * deletion lock the interface and clear keys before returning to sign-in.
 * Crisis resources remain reachable from every state.
 */
import { lazy, Suspense, useCallback, useEffect, useRef, useState } from "react";
import { api, clearSession, setSessionExpiredHandler } from "./api/client";
import { abortInFlightFlush, flushQueueOnReconnect } from "./offlineQueue";
import { preserveActiveDraft } from "./entryDraft";
import { preserveSafetyPlan } from "./safetyPlan";
import { adoptLegacyPlaintextMutes } from "./patternMutes";
import { useBfcacheGuard, useHiddenTabLock, useIdleLock, type LockReason } from "./sessionLock";
import { subscribeTabLockdown } from "./tabLockdown";
import { sweepLegacyCrisisStamps } from "./crisisDialog";
import { isOnline, localStore, onWindowEvent, withLock } from "./platform";
import { AppFrame, BottomNav, Button, Card, ErrorBanner, MoreMenu, NavTabs, Note, ToastHost, type IconName, type NavItem, type ToastItem } from "./ui";
import { CrisisCard } from "./crisis";
import { LoginView } from "./views/LoginView";
import { clearOnboardingSeen, hasSeenOnboarding, markOnboardingSeen, Onboarding } from "./views/Onboarding";
import { Privacy } from "./views/Privacy";
const EntryView = lazy(() => import("./views/Entry").then(module => ({ default: module.EntryView })));
const HistoryView = lazy(() => import("./views/History").then(module => ({ default: module.HistoryView })));
const PatternsView = lazy(() => import("./views/Patterns").then(module => ({ default: module.PatternsView })));
const QuestionView = lazy(() => import("./views/Question").then(module => ({ default: module.QuestionView })));
const MeasuresView = lazy(() => import("./views/Measures").then(module => ({ default: module.MeasuresView })));
const SafetyPlanView = lazy(() => import("./views/SafetyPlan").then(module => ({ default: module.SafetyPlanView })));
const ShareView = lazy(() => import("./views/Share").then(module => ({ default: module.ShareView })));
const SettingsView = lazy(() => import("./views/Settings").then(module => ({ default: module.SettingsView })));
import { vault } from "./vault";
import { reconcile, type ReconcileOutcome } from "./sync";
import { loadFullCatalogs, subscribeLanguage, t } from "./strings";
import { ViewBoundary } from "./ErrorBoundary";
import { readBrowserView, writeBrowserView } from "./browserRoute";
import { hasLocalRotation, resumeLocalRotation } from "./localRotation";
import { confirmLocalErasure, confirmRemoteLocalErasure, pendingLocalErasures, resumeConfirmedErasures, type ErasureTombstone } from "./localErasure";
import { kv } from "./kvstore";

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
  const adoptionGeneration = useRef(0);
  const [erasures,setErasures] = useState<ErasureTombstone[]>([]);
  const [erasureError,setErasureError] = useState("");
  const [accountTransitioning,setAccountTransitioning] = useState(false);
  const retryErasure = async (): Promise<void> => {
    try { setErasures(await resumeConfirmedErasures()); setErasureError(""); }
    catch (error) {
      setErasureError(error instanceof Error ? error.message : t("app.erasureIncomplete"));
      try { setErasures(await pendingLocalErasures()); } catch { /* Keep the visible storage failure. */ }
    }
  };
  useEffect(() => { void retryErasure(); }, []);
  useEffect(() => () => { adoptionGeneration.current += 1; }, []);

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
    adoptionGeneration.current += 1;
    // FIRST, seal the in-progress journal draft under the data key while it
    // still exists (audit 2026-09-26, MEDIUM user-data-loss): the hidden-
    // tab/idle locks unmount the editor, and the draft used to die with it.
    // Fire-and-forget by contract — the key bytes are snapshotted
    // synchronously and a failed seal never blocks the lock.
    void preserveActiveDraft();
    // 2026-10-01 audit M11: the safety plan rides the same lock path —
    // half-written Stanley-Brown text must survive the lock, not die with
    // the unmounted view.
    void preserveSafetyPlan();
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
    setSessionExpiredHandler((_error, context) => {
      if (!context.accountDeleted) {
        lockDown(noticeFor("expired"));
        return;
      }
      // Do not seal a new draft after authoritative account death. Lock all
      // plaintext synchronously, then persist/finalize the retryable cleanup
      // job for the exact owner captured at request dispatch.
      adoptionGeneration.current += 1;
      abortInFlightFlush();
      clearSession();
      vault.lock();
      setUsername("");
      setView({ kind: "login", notice: noticeFor("deleted") });
      void confirmRemoteLocalErasure(context.userId).then(retryErasure).catch(async error => {
        setErasureError(error instanceof Error ? error.message : t("app.erasureIncomplete"));
        try { setErasures(await pendingLocalErasures()); } catch { /* Keep the visible storage failure. */ }
      });
    });
    return () => setSessionExpiredHandler(null);
  }, [lockDown]);

  // The views that hold a live session: everything past login. This is ONE
  // list on purpose (audit 2026-09-25: it had drifted to miss measures/
  // share/settings, leaving keys in memory with no idle lock there).
  const inApp = PRIMARY_KINDS.has(view.kind) || MORE_KINDS.has(view.kind);
  const sessionActive = inApp || view.kind === "onboarding" || view.kind === "privacy";
  useEffect(() => {
    if (inApp) writeBrowserView(view.kind);
  }, [inApp, view.kind]);
  useEffect(() => {
    if (!inApp) return;
    const followHistory = (): void => {
      void preserveActiveDraft().catch(() => undefined);
      void preserveSafetyPlan().catch(() => undefined);
      setView({ kind: readBrowserView() as View["kind"] });
    };
    const offPop = onWindowEvent("popstate", followHistory);
    const offHash = onWindowEvent("hashchange", followHistory);
    return () => { offPop(); offHash(); };
  }, [inApp]);
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

  const onLoginSuccess = useCallback(async (success: { userId: string; username: string }) => withLock("account-transition", async () => {
    const attempt = ++adoptionGeneration.current;
    const current = (): boolean => attempt === adoptionGeneration.current && vault.isUnlocked() && vault.ownerUserId() === success.userId;
    if (!current()) return;
    const keyCopy = new Uint8Array(vault.get().dataKey);
    try {
      await loadFullCatalogs();
      if (!current()) return;
      const pendingMigration = await hasLocalRotation(success.userId);
      if (!current()) return;
      if (pendingMigration) {
        const envelope = await api.keyEnvelope();
        if (!current()) return;
        await resumeLocalRotation(success.userId,keyCopy,envelope.salt);
      }
      if(!current())return;
      await kv.adoptVerifiedWriteGeneration(success.userId,keyCopy,current);
    } catch (error) {
      if (!current()) return;
      setErrorNote(error instanceof Error ? error.message : "Local key migration needs recovery. Your encrypted originals are retained.");
      setView({kind:"settings"});
      return;
    } finally { keyCopy.fill(0); }
    if (!current()) return;
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
    const seenOnboarding = await hasSeenOnboarding(success.userId).catch(() => false);
    if (!current()) return;
    if (seenOnboarding) {
      setView({ kind: readBrowserView() as View["kind"] });
    } else {
      setView({ kind: "onboarding" });
    }
  }), []);

  const onOnboardingDone = useCallback(async () => {
    const userId = vault.ownerUserId();
    if (userId) await markOnboardingSeen(userId).catch(() => undefined);
    setView({ kind: readBrowserView() as View["kind"] });
  }, []);

  const signOut = useCallback(() => {
    // Logout is PER-DEVICE since the 2026-09-26 wave: the server records
    // this bearer's jti and only this session's token dies — other signed-
    // in devices stay live (the button copy says exactly that). Legacy
    // jti-less bearers still trigger the account-wide epoch bump
    // server-side; this client always holds a jti-bearing token.
    void api.logout().catch(() => undefined);
    const owner = vault.ownerUserId();
    // W-6 (audit 2026-09-25): sign-out wipes this browser's non-content
    // mindpattern.* flags (onboarding/mute/threshold stamps) like mobile
    // wipes its origin-bound state — a shared computer keeps no trace that
    // an account used it. Idle/expiry locks deliberately keep them.
    localStore.removePrefix("mindpattern.");
    lockDown(null);
    if (!owner) return;
    // Keep the login surface closed until this origin-wide transition owns
    // and finishes its cleanup. A fast same-account successor (including a
    // second tab) waits on the same Web Lock before reading or publishing
    // onboarding/rekey metadata, so an old sign-out cannot erase new state.
    setAccountTransitioning(true);
    void withLock("account-transition", async () => {
      await clearOnboardingSeen(owner);
      await kv.removeItem(`mindpattern.rekeyHint.${owner}`);
    }).catch(error => {
      setErrorNote(error instanceof Error ? error.message : t("app.erasureIncomplete"));
    }).finally(() => setAccountTransitioning(false));
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
    // 2026-10-01 audit M10/M11: seal the live entry draft AND safety plan
    // BEFORE the view unmounts — plain navigation used to destroy both
    // (the draft's own copy promised "until you save or discard it").
    void preserveActiveDraft().catch(() => undefined);
    void preserveSafetyPlan().catch(() => undefined);
    setView({ kind: id as View["kind"] });
  }, [signOut]);
  const activeMore = MORE_KINDS.has(view.kind) ? [view.kind as string] : [];

  return (
    <AppFrame title="Fathom" onCrisis={() => setCrisisOpen(true)}>
      {(erasures.length > 0 || erasureError) && <Card title={t("app.erasureTitle")}>
        <Note>{t("app.erasureExplanation")}</Note><ErrorBanner message={erasureError} />
        <Button label={t("app.erasureRetry")} onPress={() => void retryErasure()} />
        {erasures.filter(row=>!row.remoteConfirmed).map(row => <div key={row.owner}>
          <Note>{t("app.erasureUnconfirmed",{account:row.owner})}</Note>
          <Button danger label={t("app.erasureConfirm")} onPress={() => { void confirmLocalErasure(row.owner).then(retryErasure).catch(error=>setErasureError(error instanceof Error ? error.message : t("app.erasureIncomplete"))); }} />
        </div>)}
      </Card>}
      {view.kind === "booting" || accountTransitioning ? (
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
          <Suspense fallback={<Note role="status">{t("common.loading")}</Note>}>
          {view.kind === "today" ? (
            <EntryView onSaved={onSaved} onCrisis={() => setCrisisOpen(true)} />
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
          </Suspense>
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
