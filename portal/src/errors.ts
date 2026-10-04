import { ApiError } from "./api";

/** API detail is server-controlled and may be in an arbitrary language.
 * User surfaces use stable client copy; local client errors retain detail. */
export function displayError(error: unknown, fallback: string): string {
  if (error instanceof ApiError) {
    // These are client-owned, stable explanations for machine-readable
    // outcomes. Never render the server-controlled detail string: it can be
    // unlocalized, overly technical, or contain hostile text.
    if (error.code === "collection_changed") return "rows changed while paging; retry the request";
    if (error.code === "conflict") return "note id already used for another patient";
    if (error.code === "version_conflict") return "a different note with this client_note_id already exists";
    if (error.status === 0) return "server unreachable — check your connection";
    if (error.status >= 500) return "server is busy — try again";
    return fallback;
  }
  return error instanceof Error ? error.message : fallback;
}
