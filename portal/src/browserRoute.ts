export function readPatientRoute(): string | null {
  try {
    const match = /^#\/patient\/([A-Za-z0-9_-]{1,128})$/.exec(window.location.hash);
    return match?.[1] ?? null;
  } catch { return null; }
}

export function writePatientRoute(id: string | null): void {
  if (id !== null && !/^[A-Za-z0-9_-]{1,128}$/.test(id)) return;
  try {
    const hash = id === null ? "#/patients" : `#/patient/${id}`;
    if (window.location.hash !== hash) window.history.pushState(null, "", hash);
  } catch { /* In-app navigation remains usable without browser history. */ }
}
