/**
 * Calm error copy — the audit's "no raw err.message in Alerts" fix.
 *
 * ApiError.message is technical text assembled from server detail (even
 * sanitized, it reads like a stack trace to a vulnerable user at 2am), so
 * it never reaches a dialog: the STATUS decides the sentence. Local Errors
 * thrown by our own code carry copy we wrote and may pass through; unknown
 * non-Error failures degrade to a calm generic line. Every sentence here
 * follows the app voice — honest, non-prescriptive, no blame.
 */
import { ApiError } from "../api/client";

/** Human copy for a failed request, keyed on status — never on detail. */
export function requestFailureCopy(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 0) return "Couldn't reach the server — check your connection.";
    if (err.status === 401) return "Session expired — please unlock again.";
    if (err.status === 403) return "The server refused that request.";
    if (err.status === 404) return "That isn't on the server (anymore).";
    if (err.status === 409) return "That conflicts with something the server already has.";
    if (err.status === 413) return "That's more data than the server can accept.";
    if (err.status === 429) return "Too many attempts — wait a moment, then try again.";
    if (err.status >= 500) return "The server hit a problem — try again in a moment.";
    return "The server didn't accept that request.";
  }
  if (err instanceof Error) return err.message; // our own copy, not server text
  return "Something went wrong — try again.";
}

/** For failures where even our local Error text would mislead (or where the
 *  catch can see library internals): one calm sentence, no technical echo. */
export function calmFallbackCopy(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return requestFailureCopy(err);
  return fallback;
}
