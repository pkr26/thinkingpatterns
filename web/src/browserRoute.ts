// @ts-nocheck
const VIEWS = new Set(["today", "history", "patterns", "question", "measures", "safetyplan", "share", "settings", "privacy"]);

export function readBrowserView(): string {
  try {
    const kind = window.location.hash.replace(/^#\/?/, "");
    return VIEWS.has(kind) ? kind : "today";
  } catch { return "today"; }
}

export function writeBrowserView(kind: string): void {
  if (!VIEWS.has(kind)) return;
  try {
    const hash = `#/${kind}`;
    if (window.location.hash !== hash) window.history.pushState(null, "", hash);
  } catch { /* Hosts without browser history still support in-app navigation. */ }
}
