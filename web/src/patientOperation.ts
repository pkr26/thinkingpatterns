import { useCallback, useEffect, useRef } from "react";
import { sessionAbortSignal, sessionUserId } from "./api/client";
import { vault } from "./vault";

/** Bind asynchronous work to the view, login, and unlocked key that started it.
 * API response fencing alone cannot protect a request dispatched after an await. */
export function usePatientOperation() {
  const lifetime = useRef<object | null>({});
  useEffect(() => {
    lifetime.current = {};
    return () => { lifetime.current = null; };
  }, []);
  return useCallback(() => {
    const mounted = lifetime.current;
    const owner = vault.ownerUserId();
    const signal = sessionAbortSignal();
    if (!mounted || !owner || !vault.isUnlocked() || sessionUserId() !== owner || !signal || signal.aborted) return null;
    const keys = vault.get();
    return {
      owner, keys,
      viewCurrent: () => lifetime.current === mounted && !signal.aborted && sessionAbortSignal() === signal && sessionUserId() === owner,
      current: () => lifetime.current === mounted && !signal.aborted &&
        sessionAbortSignal() === signal && sessionUserId() === owner &&
        vault.ownerUserId() === owner && vault.isUnlocked() &&
        vault.get().dataKey === keys.dataKey,
    };
  }, []);
}

export type PatientOperation = NonNullable<ReturnType<ReturnType<typeof usePatientOperation>>>;
