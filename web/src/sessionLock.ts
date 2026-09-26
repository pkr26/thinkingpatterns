/**
 * Session-lock machinery (WEB_PLAN P2.7, portal App.tsx patterns lifted
 * into testable hooks): a 10-minute idle auto-lock that resets on real
 * interaction, and a back/forward-cache guard that locks synchronously
 * when the browser restores a persisted page (the tab's keys must never
 * outlive the user's attention invisibly). Both are inert until a session
 * exists (`active`), and both route every event through the platform seam
 * so the node test runtime can drive them.
 */
import { useEffect } from "react";
import { onWindowEvent } from "./platform";

/** Idle auto-lock: 10 minutes without interaction drops every key from
 *  memory — a journal left open on a shared laptop shows decrypted text
 *  exactly until the user walks away. */
export const IDLE_LOCK_MS = 10 * 60 * 1000;

const ACTIVITY_EVENTS = ["click", "keydown", "mousemove", "scroll", "touchstart"] as const;

export type LockReason = "idle" | "bfcache";

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
