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
};
