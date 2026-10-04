/**
 * Localized request-error copy, selected by HTTP status rather than server
 * detail. Local Error messages may pass through when the caller owns their
 * copy; use calmFallbackCopy when errors can contain library internals.
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
