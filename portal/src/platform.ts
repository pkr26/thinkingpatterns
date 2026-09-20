/**
 * Browser-platform seam. The views never touch `window` directly: under
 * the node test runtime there is no DOM, and a private-mode browser can
 * throw on localStorage access — both degrade to inert defaults instead
 * of crashing the view.
 */

export function currentOrigin(): string {
  try {
    return typeof window !== "undefined" ? window.location.origin : "";
  } catch {
    return "";
  }
}

export const localStore = {
  get(key: string): string | null {
    try {
      return typeof window !== "undefined" ? window.localStorage.getItem(key) : null;
    } catch {
      return null;
    }
  },
  set(key: string, value: string): void {
    try {
      if (typeof window !== "undefined") window.localStorage.setItem(key, value);
    } catch {
      // Private mode / storage disabled: the visit stamp is cosmetic.
    }
  },
  /** Remove only this portal's non-content visit metadata at logout. */
  removePrefix(prefix: string): void {
    try {
      if (typeof window === "undefined") return;
      const keys: string[] = [];
      for (let index = 0; index < window.localStorage.length; index += 1) {
        const key = window.localStorage.key(index);
        if (key?.startsWith(prefix)) keys.push(key);
      }
      keys.forEach((key) => window.localStorage.removeItem(key));
    } catch {
      // Storage is optional; never make sign-out fail on a private-mode DOM.
    }
  },
};

/** Per-tab storage seam: identical degradation contract to localStore,
 *  over window.sessionStorage.  Accessing the property itself can throw in
 *  locked-down privacy modes, so every method keeps its own try/catch and
 *  degrades to an inert default instead of crashing the view. */
export const sessionStore = {
  get(key: string): string | null {
    try {
      return typeof window !== "undefined" ? window.sessionStorage.getItem(key) : null;
    } catch {
      return null;
    }
  },
  set(key: string, value: string): void {
    try {
      if (typeof window !== "undefined") window.sessionStorage.setItem(key, value);
    } catch {
      // Per-tab storage is optional; the visit stamp is cosmetic.
    }
  },
  removePrefix(prefix: string): void {
    try {
      if (typeof window === "undefined") return;
      const keys: string[] = [];
      for (let index = 0; index < window.sessionStorage.length; index += 1) {
        const key = window.sessionStorage.key(index);
        if (key?.startsWith(prefix)) keys.push(key);
      }
      keys.forEach((key) => window.sessionStorage.removeItem(key));
    } catch {
      // Storage is optional; never make sign-out fail on a hostile DOM.
    }
  },
};

/** Prove sessionStorage is WRITABLE, not merely present: a readable but
 *  quota-denied storage would otherwise claim the session-backed path while
 *  silently dropping every anchor.  Re-probed on every call (no memo) so a
 *  swapped or removed window — as the tests do — changes the answer. */
function sessionStorageWorks(): boolean {
  try {
    if (typeof window === "undefined" || !window.sessionStorage) return false;
    window.sessionStorage.setItem("mindpattern.probe", "1");
    window.sessionStorage.removeItem("mindpattern.probe");
    return true;
  } catch {
    return false;
  }
}

/** "Mark reviewed" delta-anchor storage — an explicit privacy decision
 *  (2026-09-20, audit L-75).  The anchors are per-patient DATE STAMPS,
 *  never content.  Two earlier postures both failed clinically:
 *  memory-only anchors died at every idle lock / token expiry (a chart
 *  left open through lunch lost the clinician's delta baseline), while
 *  localStorage anchors survived browser restarts — which is exactly what
 *  the lock-boundary scrub was written to prevent.  The settled trade-off
 *  is sessionStorage: deltas survive idle locks within one browser
 *  session and disappear when the tab/session ends.  Where sessionStorage
 *  is unavailable (locked-down privacy modes), the store keeps the OLD
 *  behavior exactly: localStorage anchors that App scrubs at every lock
 *  boundary — see visitAnchorStore.sessionBacked(). */
export const visitAnchorStore = {
  get(key: string): string | null {
    return sessionStorageWorks() ? sessionStore.get(key) : localStore.get(key);
  },
  set(key: string, value: string): void {
    if (sessionStorageWorks()) sessionStore.set(key, value);
    else localStore.set(key, value);
  },
  /** Whether anchors currently live in per-tab sessionStorage (true) or in
   *  the lock-scrubbed localStorage fallback (false).  App consults this
   *  to decide whether a lock boundary must scrub. */
  sessionBacked(): boolean {
    return sessionStorageWorks();
  },
};
