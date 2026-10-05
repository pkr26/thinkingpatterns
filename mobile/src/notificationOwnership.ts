/** Ownership of device-global reminder IDs across account and preference changes. */
import {
  assertLocalWritePermit, captureLocalWritePermit, commitLocalWrite,
  commitOriginErasureWrite, localWriteScopeEpoch, type LocalWritePermit,
} from "./localWriteGuard";

export type ReminderKind = "daily" | "measure";
const revisions: Record<ReminderKind, number> = { daily: 0, measure: 0 };
let nativeLane: Promise<unknown> = Promise.resolve();

export interface NotificationOwner {
  readonly permit: LocalWritePermit;
  readonly daily: number;
  readonly measure: number;
}

/** Capture before any preference/native await; the newest intent wins. */
export function beginNotificationUpdate(userId: string, kind: ReminderKind): NotificationOwner {
  const permit = captureLocalWritePermit(userId);
  revisions[kind]++;
  return { permit, ...revisions };
}

export function assertNotificationOwner(owner: NotificationOwner, kind?: ReminderKind): void {
  assertLocalWritePermit(owner.permit);
  if (kind && owner[kind] !== revisions[kind]) throw new Error("The reminder preference changed");
}

function serialized<T>(run: () => Promise<T>): Promise<T> {
  const pending = nativeLane.then(run, run);
  nativeLane = pending.catch(() => {});
  return pending;
}

/** Track even queued native work so deletion/rekey cannot race its dispatch. */
export async function runOwnedNotification<T>(owner: NotificationOwner, run: () => Promise<T>): Promise<T> {
  assertNotificationOwner(owner);
  return commitLocalWrite(owner.permit, () => serialized(async () => {
    assertNotificationOwner(owner);
    return run();
  }));
}

/** Cancellation retires prior producers immediately, then follows any native
 * write already dispatched. A stale admin task cannot cancel a new session. */
export async function runNotificationCancellation<T>(kinds: readonly ReminderKind[], run: (check: () => void) => Promise<T>): Promise<T> {
  const epoch = localWriteScopeEpoch();
  for (const kind of kinds) revisions[kind]++;
  const admitted = { ...revisions };
  const check = () => {
    if (epoch !== localWriteScopeEpoch() || kinds.some(kind => admitted[kind] !== revisions[kind])) {
      throw new Error("The notification cancellation belongs to a retired session");
    }
  };
  return commitOriginErasureWrite(epoch, () => serialized(async () => { check(); return run(check); }));
}
