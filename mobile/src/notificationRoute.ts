/**
 * Notification-tap routing (2026-09-27): the seam between a tapped LOCAL
 * notification and the screen the app should open on.
 *
 * The daily journaling reminder has never routed anywhere — a tap just
 * opened the app on the journal. The measure check-in reminder is
 * different: its promise is "tapping opens the Measures screen", so a tap
 * must carry a DESTINATION. Native notifee events cannot be exercised in
 * the node test environment (and the module is unlinked in this build),
 * so the mapping and the queue live HERE as pure state that the native
 * seam (nativeFeatures.ts) feeds and the navigator (navigation.tsx)
 * consumes when the main flow is entered — the takePendingOnboarding()
 * idiom: queued before React mounts, consumed exactly once.
 */

/** The measure reminder's stable notification id (mirrored from
 *  nativeFeatures.ts, which owns the scheduling contract; re-declared here
 *  so this module stays dependency-free and testable in isolation). */
const MEASURE_REMINDER_NOTIFICATION_ID = "mindpattern-measure-reminder";

/** Maps a scheduled notification id to the screen a tap should open.
 *  Unknown ids (the OS, other apps' notifications, a hostile value) map
 *  to null — a tap on an unknown notification is just "open the app". */
export function screenForNotificationId(id: unknown): string | null {
  if (id === MEASURE_REMINDER_NOTIFICATION_ID) return "Measures";
  return null;
}

/** The queued destination, consumed once at main-flow entry. */
let pendingScreen: string | null = null;
const listeners = new Set<() => void>();
export function notifyNavigationReady(): void { if (pendingScreen) for (const listener of listeners) listener(); }
export function subscribeNotificationRoutes(listener: () => void): () => void {
  listeners.add(listener); return () => { listeners.delete(listener); };
}

/** Queue the destination a tapped notification should open. Idempotent:
 *  a second tap before the app opens REPLACES the first (the most recent
 *  user intent wins). Unknown ids are ignored, never routed. */
export function queueNotificationRoute(notificationId: unknown): void {
  const screen = screenForNotificationId(notificationId);
  if (screen !== null) { pendingScreen = screen; for (const listener of listeners) listener(); }
}

/** True when a tapped notification is waiting to route (test/observer seam). */
export function hasPendingNotificationRoute(): boolean {
  return pendingScreen !== null;
}

/** Consume the queued destination exactly once — null when no notification
 *  tap is pending (the ordinary cold start). */
export function takePendingNotificationRoute(): string | null {
  const screen = pendingScreen;
  pendingScreen = null;
  return screen;
}
