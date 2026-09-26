/**
 * Browser-platform seam. Views and services never touch `window`,
 * `document`, `navigator` or `URL` directly: under the node test runtime
 * there is no DOM, and a private-mode browser can throw on storage or
 * downloads — every capability degrades to an inert default instead of
 * crashing the app (WEB_PLAN P1.3, R-7).
 */

/** Randomness goes through the seam so tests can observe (and a future
 *  non-browser host can override) it. */
export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

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
      // Private mode / storage disabled: non-content preferences are
      // cosmetic (WEB_PLAN D-4 — nothing sensitive is ever stored).
    }
  },
  /** Remove only this app's non-content namespace at lock/logout. */
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

/** Save a text file (the encrypted export bundle — WEB_PLAN P7.5).
 *  Returns true when a download was actually initiated, so callers can
 *  offer a copy-to-clipboard fallback in browsers that block programmatic
 *  downloads. Blob URLs are revoked on the next macrotask; the anchor is
 *  never attached to the DOM. */
export function downloadTextFile(filename: string, contents: string, mime: string): boolean {
  try {
    if (typeof window === "undefined" || typeof window.document === "undefined") return false;
    const urlFactory = (
      globalThis as {
        URL?: {
          createObjectURL?: (blob: Blob) => string;
          revokeObjectURL?: (url: string) => void;
        };
      }
    ).URL;
    if (!urlFactory?.createObjectURL || !urlFactory.revokeObjectURL) return false;
    const blob = new Blob([contents], { type: mime });
    const url = urlFactory.createObjectURL(blob);
    const anchor = window.document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    anchor.rel = "noopener";
    anchor.click();
    setTimeout(() => urlFactory.revokeObjectURL?.(url), 0);
    return true;
  } catch {
    return false;
  }
}

type LocksLike = {
  locks?: {
    request: <T>(name: string, callback: () => Promise<T>) => Promise<T>;
  };
};

/** Serialize an async section across SAME-ORIGIN tabs via the Web Locks
 *  API (WEB_PLAN P4/P5, R-4: two tabs must not double-flush the offline
 *  queue or double-run reconciliation). Where the API is absent the
 *  single-tab fallback simply runs the section — correctness there is
 *  carried by server-side idempotency, not by the lock. */
export async function withLock<T>(name: string, run: () => Promise<T>): Promise<T> {
  const locks = (globalThis as { navigator?: LocksLike }).navigator?.locks;
  if (locks?.request) return locks.request(name, run);
  return run();
}

/** Connectivity probe. Unknown (node, or a stripped browser) reads as
 *  online: a false "offline" would disable journaling unnecessarily. */
export function isOnline(): boolean {
  try {
    const nav = (globalThis as { navigator?: { onLine?: boolean } }).navigator;
    return nav?.onLine !== false;
  } catch {
    return true;
  }
}

/** Subscribe to a window event through the seam (online / offline /
 *  visibilitychange / pageshow). Returns an unsubscribe function; a
 *  no-op when there is no usable window. */
export function onWindowEvent(type: string, listener: (event?: unknown) => void): () => void {
  try {
    if (typeof window === "undefined" || typeof window.addEventListener !== "function") {
      return () => undefined;
    }
    window.addEventListener(type, listener);
    return () => window.removeEventListener(type, listener);
  } catch {
    return () => undefined;
  }
}
