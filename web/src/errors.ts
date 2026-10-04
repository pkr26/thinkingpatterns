// @ts-nocheck
import { ApiError } from "./api/client";
import { t } from "./strings";

/** Never render server-controlled detail directly. Local storage/crypto
 * errors may retain their client-authored explanation. */
export function displayError(error: unknown, localizedFallback: string): string {
  if (error instanceof ApiError) {
    if (error.status === 0) return t("errors.offline");
    if (error.status === 401) return t("errors.sessionExpired");
    if (error.status === 403) return t("errors.forbidden");
    if (error.status === 404) return t("errors.notFound");
    if (error.status === 409) return t("errors.conflict");
    if (error.status === 413) return t("errors.tooLarge");
    if (error.status === 429) return t("errors.rateLimited");
    if (error.status >= 500) return t("errors.serverError");
    return localizedFallback;
  }
  return error instanceof Error ? error.message : localizedFallback;
}
