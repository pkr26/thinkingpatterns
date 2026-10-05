/** Reminder preference/cadence read-modify-write operations share custody
 * from admission through storage. Native reconciliation has its own lane. */
import { assertLocalWritePermit, captureLocalWritePermit, commitLocalWrite } from "./localWriteGuard";
import { useEffect, useRef } from "react";
import { vault } from "./vault";

let writes: Promise<unknown> = Promise.resolve();

export function commitReminderPreferenceWrite(userId: string, run: (check: () => void) => Promise<void>): Promise<void> {
  const permit = captureLocalWritePermit(userId);
  const check = () => assertLocalWritePermit(permit);
  // Register queued work immediately so retirement drains its storage write.
  return commitLocalWrite(permit, () => {
    const pending = writes.then(async () => { check(); await run(check); check(); });
    writes = pending.catch(() => {});
    return pending;
  });
}

/** Admit UI intent before account lookup: an old control callback must not
 * adopt a replacement account or overtake a newer choice while it awaits. */
export function useReminderPreferenceIntent() {
  const lifetime = useRef<object | null>({});
  const revisions = useRef(new Map<string, number>());
  useEffect(() => {
    lifetime.current = {};
    return () => { lifetime.current = null; };
  }, []);
  return (control: string, userId = vault.ownerUserId()) => {
    const view = lifetime.current;
    if (!view || !userId) return null;
    const revision = (revisions.current.get(control) ?? 0) + 1;
    revisions.current.set(control, revision);
    try {
      const permit = captureLocalWritePermit(userId);
      const key = vault.isUnlocked() ? vault.get().dataKey : null;
      return { owner: userId, current: (): boolean => {
        try {
          assertLocalWritePermit(permit);
          return lifetime.current === view && revisions.current.get(control) === revision &&
            (key === null || (vault.isUnlocked() && vault.ownerUserId() === userId && vault.get().dataKey === key));
        } catch { return false; }
      } };
    } catch { return null; }
  };
}
