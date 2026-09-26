/**
 * Session-lock machinery (WEB_PLAN P2.7, portal App.tsx patterns lifted
 * into testable hooks): a 5-minute idle auto-lock that resets on real
 * interaction, a back/forward-cache guard that locks synchronously when
 * the browser restores a persisted page, and a hidden-tab guard that locks
 * the moment the tab goes to the background — the web equivalent of the
 * mobile app locking its vault on AppState "background" (parity fix W-1,
 * audit 2026-09-25). All are inert until a session exists (`active`), and
 * all route every event through the platform seam so the node test
 * runtime can drive them.
 */
import { useEffect } from "react";
import { onWindowEvent, pageHidden } from "./platform";

/** Idle auto-lock: 5 minutes without interaction drops every key from
 *  memory — a journal left open on a shared laptop shows decrypted text
 *  exactly until the user walks away. (Mobile parity: the app uses the
 *  same 5-minute inactivity window.) */
export const IDLE_LOCK_MS = 5 * 60 * 1000;

/** Interaction events that reset the idle timer. Deliberately excludes
 *  `mousemove` (W-1): a mouse jiggler must not defeat the lock — only
 *  events that can actually operate the app count as activity. */
const ACTIVITY_EVENTS = ["click", "keydown", "scroll", "touchstart"] as const;

export type LockReason = "idle" | "bfcache" | "hidden";

export function useIdleLock(active: boolean, onLock: (reason: LockReason) => void): void {
  useEffect(() => {
    if (!active) return;
    let timer = setTimeout(() => onLock("idle"), IDLE_LOCK_MS);
    const bump = (): void => {
      clearTimeout(timer);
      timer = setTimeout(() => onLock("idle"), IDLE_LOCK_MS);
    };
    const offs = ACTIVITY_EVENTS.map((event) => onWindowEvent(event, bump));
    return () => {
      clearTimeout(timer);
      offs.forEach((off) => off());
    };
  }, [active, onLock]);
}

export function useBfcacheGuard(active: boolean, onLock: (reason: LockReason) => void): void {
  useEffect(() => {
    if (!active) return;
    return onWindowEvent("pageshow", (event) => {
      // A persisted pageshow is the browser restoring this page from the
      // back/forward cache — the user navigated away and came Back,
      // possibly long after the idle window. Lock before first paint.
      const persisted = (event as { persisted?: unknown } | undefined)?.persisted === true;
      if (persisted) onLock("bfcache");
    });
  }, [active, onLock]);
}

export function useHiddenTabLock(active: boolean, onLock: (reason: LockReason) => void): void {
  useEffect(() => {
    if (!active) return;
    return onWindowEvent("visibilitychange", (event) => {
      // Mobile locks the vault the instant the app leaves the foreground;
      // the web equivalent is the tab (or window) becoming hidden. Until
      // this fires, decrypted text stays rendered — readable in tab-hover
      // previews and screen recordings long after the user walked away.
      // Lock immediately, exactly like the mobile background lock: keys
      // never outlive the user's attention invisibly.
      if (pageHidden(event)) onLock("hidden");
    });
  }, [active, onLock]);
}
