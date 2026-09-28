/**
 * RFC 9116 placeholder gate (audit 2026-09-28, INFO): the shipped
 * security.txt carries EXAMPLE contact/URL markers so operators fill them
 * in per deployment — but a placeholder contact is worse than none
 * (it looks like a channel nobody reads), and nothing reminded a build
 * that shipped with them still in. This module is the single check both
 * `npm run build` (via add-sri.mjs) and the unit test import: the build
 * FAILS while any placeholder marker survives in
 * public/.well-known/security.txt.
 */

/** The example markers the template ships with — a finding for each one
 *  still present verbatim in the file. */
export const SECURITY_TXT_PLACEHOLDERS = ["security@example.com", "app.example.com"];

/** Which placeholder markers `text` still carries (empty = clean). */
export function securityTxtPlaceholderFindings(text) {
  return SECURITY_TXT_PLACEHOLDERS.filter((marker) => text.includes(marker));
}

/** Throw with the honest operator-facing message when any placeholder
 *  survives; return silently when the file is deployment-ready. */
export function assertNoSecurityTxtPlaceholders(text) {
  const findings = securityTxtPlaceholderFindings(text);
  if (findings.length > 0) {
    throw new Error(
      `public/.well-known/security.txt still contains placeholder marker(s): ${findings.join(", ")} — ` +
        "replace the example contact and canonical URL with the real operator values before shipping.",
    );
  }
}
