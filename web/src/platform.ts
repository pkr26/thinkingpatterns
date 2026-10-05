/**
 * Browser capability adapters for storage, events, locks, and downloads.
 * DOM-free tests and restricted browser contexts use explicit fallback behavior
 * at each adapter. Durable record storage is handled separately by kvstore.
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

/** Hand a small, single-use capability to the browser's native download
 * manager. The journal never becomes a JavaScript string, Blob, or buffer.
 * A successful attachment response keeps this document open. */
export function requestAccountDownload(ticket: string): boolean {
  if (!/^[A-Za-z0-9_-]{43}$/.test(ticket)) return false;
  let form: HTMLFormElement | undefined;
  try {
    form = document.createElement("form");
    form.method = "POST";
    form.action = "/api/v1/account/export-download";
    form.target = "_self";
    form.enctype = "application/x-www-form-urlencoded";
    form.acceptCharset = "UTF-8";
    form.hidden = true;
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = "ticket";
    input.value = ticket;
    form.appendChild(input);
    document.body.appendChild(form);
    form.submit();
    return true;
  } catch {
    return false;
  } finally {
    form?.remove();
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
  remove(key: string): void {
    try {
      if (typeof window !== "undefined") window.localStorage.removeItem(key);
    } catch {
      // Storage is optional; never let a cleanup write fail a flow.
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
    // 2026-10-01 audit L-5: revoke on a DELAY — the next-macrotask revoke
    // could abort an in-progress download of a multi-MB export in some
    // engines (the download only holds a reference, not the bytes).
    setTimeout(() => urlFactory.revokeObjectURL?.(url), 60_000);
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

/** Shared durable read-modify-write requires the browser's origin-wide
 * Web Locks primitive. Time-based localStorage leases cannot distinguish a
 * suspended owner from a crashed tab and must not acknowledge unsafe writes.
 */
export async function withLock<T>(name: string, run: () => Promise<T>): Promise<T> {
  const locks = (globalThis as { navigator?: LocksLike }).navigator?.locks;
  if (locks?.request) return locks.request(name, run);
  throw new Error("Safe shared storage locking is unavailable. Keep your writing open and retry in a current browser with Web Locks enabled.");
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
/** Is the page currently hidden? The browser truth is
 * `document.visibilityState`; the node test runtime has no document, so
 * the seam also accepts the state carried on the synthetic event the
 * test shim dispatches (the same pattern the bfcache guard uses for
 * `persisted`). A missing/unknown state reads as visible — never locks
 * on a guess. */
export function pageHidden(event?: unknown): boolean {
  try {
    const doc = (globalThis as { document?: { visibilityState?: unknown } }).document;
    if (doc && typeof doc.visibilityState === "string") {
      return doc.visibilityState === "hidden";
    }
  } catch {
    // Fall through to the event-borne state.
  }
  return (event as { visibilityState?: unknown } | undefined)?.visibilityState === "hidden";
}

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
