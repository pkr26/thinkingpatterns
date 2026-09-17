/**
 * The string catalog seam (2026-09-17).
 *
 * The audit found every user-facing string hard-coded inline (~400+ across
 * the app) including SAFETY-CRITICAL crisis copy — a full translation
 * pass is a large, separate project. This module is the seam that makes
 * it possible: the strings most likely to appear in front of a person in
 * distress (crisis resources, unlock/auth failures) centralize here
 * behind t(); migrating the rest is mechanical once a second locale
 * exists.
 *
 * Rules:
 *  - `t()` is synchronous and total: a missing key returns the key itself
 *    (visible in review, never a crash, never silent English fallback in
 *    a translated build).
 *  - The `en` catalog is the source of truth; locale selection is a later
 *    feature (it needs pluralization + date formatting infrastructure
 *    this pass deliberately does not guess at).
 */

export type StringKey =
  | "crisis.title"
  | "crisis.subtitle"
  | "crisis.call988"
  | "crisis.call988.detail"
  | "crisis.call988.fallback"
  | "crisis.text741741"
  | "crisis.text741741.detail"
  | "crisis.chat"
  | "crisis.chat.detail"
  | "crisis.emergency"
  | "crisis.emergency.detail"
  | "crisis.findhelpline"
  | "crisis.findhelpline.detail"
  | "crisis.localeNote"
  | "unlock.title"
  | "unlock.body";

const en: Record<StringKey, string> = {
  "crisis.title": "Support is always one tap away",
  "crisis.subtitle":
    "Free, confidential, open 24/7. Talking to someone is never a wrong move — these lines exist for exactly this.",
  "crisis.call988": "Call or text 988",
  "crisis.call988.detail": "988 Suicide & Crisis Lifeline — call 988 or text it, any time",
  "crisis.call988.fallback": "You can still dial or text 988 from your phone — it is free and answers 24/7.",
  "crisis.text741741": "Text HOME to 741741",
  "crisis.text741741.detail": "Crisis Text Line — text conversation with a trained counselor",
  "crisis.chat": "Chat with a counselor",
  "crisis.chat.detail": "Crisis Text Line web chat — no phone needed",
  "crisis.emergency": "Immediate danger",
  "crisis.emergency.detail": "If you are thinking of acting on thoughts of ending your life, call 911 or go to an emergency room now",
  "crisis.findhelpline": "Find help outside the US",
  "crisis.findhelpline.detail": "findahelpline.com lists free, local crisis lines for most countries",
  "crisis.localeNote": "These numbers are US-based; your region may have its own line.",
  "unlock.title": "Welcome back",
  "unlock.body": "Enter your password to unlock your journal on this device.",
};

export function t(key: StringKey): string {
  return en[key] ?? key;
}
