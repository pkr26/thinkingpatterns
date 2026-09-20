/**
 * Calm error copy — the audit's "no raw err.message in Alerts" fix.
 *
 * ApiError.message is technical text assembled from server detail (even
 * sanitized, it reads like a stack trace to a vulnerable user at 2am), so
 * it never reaches a dialog: the STATUS decides the sentence. Local Errors
 * thrown by our own code carry copy we wrote and may pass through; unknown
 * non-Error failures degrade to a calm generic line. Every sentence here
 * follows the app voice — honest, non-prescriptive, no blame. Catalog
 * lookups (2026-09-19) keep both languages calm.
 */
import { ApiError } from "../api/client";
import { t } from "../strings";

/** Human copy for a failed request, keyed on status — never on detail. */
export function requestFailureCopy(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 0) return t("errors.offline");
    if (err.status === 401) return t("errors.sessionExpired");
    if (err.status === 403) return t("errors.forbidden");
    if (err.status === 404) return t("errors.notFound");
    if (err.status === 409) return t("errors.conflict");
    if (err.status === 413) return t("errors.tooLarge");
    if (err.status === 429) return t("errors.rateLimited");
    if (err.status >= 500) return t("errors.serverError");
    return t("errors.rejected");
  }
  if (err instanceof Error) return err.message; // our own copy, not server text
  return t("errors.generic");
}

/** For failures where even our local Error text would mislead (or where the
 *  catch can see library internals): one calm sentence, no technical echo. */
export function calmFallbackCopy(err: unknown, fallback: string): string {
  if (err instanceof ApiError) return requestFailureCopy(err);
  return fallback;
}
