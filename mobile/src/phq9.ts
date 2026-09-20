/**
 * The PHQ-9 self-report questionnaire (MBC module, 2026-09-19).
 *
 * The PHQ-9 (Kroenke, Spitzer & Williams 2001) is a public-domain
 * instrument (the authors' no-permission-required note covers exactly
 * this use). The patient completes it in the app; the score is stored as
 * an opaque encrypted blob (AAD "measure") and shared with their
 * therapist through the existing consent — the same zero-knowledge path
 * as entries and patterns.
 *
 * The app's charter holds: MindPattern never interprets a score. No
 * severity bands are computed or displayed to the patient, no advice is
 * given — the screen says plainly that interpretation belongs to a
 * clinician. Item 9 (self-harm thoughts) is a SAFETY item: any non-zero
 * response gently points at the offline crisis resources after the
 * response is safely saved (the same discipline as the entry crisis
 * dialog — never before saving, never blocking).
 */

export interface Phq9Item {
  /** The standard item wording. */
  text: string;
}

export const PHQ9_ITEMS: readonly Phq9Item[] = [
  { text: "Little interest or pleasure in doing things" },
  { text: "Feeling down, depressed, or hopeless" },
  { text: "Trouble falling or staying asleep, or sleeping too much" },
  { text: "Feeling tired or having little energy" },
  { text: "Poor appetite or overeating" },
  { text: "Feeling bad about yourself — or that you are a failure or have let yourself or your family down" },
  { text: "Trouble concentrating on things, such as reading or watching television" },
  { text: "Moving or speaking so slowly that other people could have noticed — or being so fidgety or restless that you have been moving a lot more than usual" },
  { text: "Thoughts that you would be better off dead, or of hurting yourself in some way" },
];

/** The standard response options, "over the last 2 weeks". */
export const PHQ9_OPTIONS: readonly { value: number; label: string }[] = [
  { value: 0, label: "Not at all" },
  { value: 1, label: "Several days" },
  { value: 2, label: "More than half the days" },
  { value: 3, label: "Nearly every day" },
];

export const PHQ9_ITEM9_INDEX = 8;

/** Sum of the nine responses (0–27). Unanswered items count as 0 — the
 * completion UI requires every item before submitting, so this leniency
 * only guards the scorer itself. */
export function phq9Score(responses: readonly (number | null)[]): number {
  let total = 0;
  for (let i = 0; i < PHQ9_ITEMS.length; i++) {
    const value = responses[i];
    if (typeof value === "number" && Number.isFinite(value)) {
      total += Math.max(0, Math.min(3, Math.round(value)));
    }
  }
  return Math.min(27, total);
}

/** True when the safety item (9) was endorsed at any level. Powers the
 * post-save support pointer — the score itself is never interpreted. */
export function phq9Item9Endorsed(responses: readonly (number | null)[]): boolean {
  const value = responses[PHQ9_ITEM9_INDEX];
  return typeof value === "number" && value > 0;
}

/** True when every item has a pick — the submit button's enabled gate. */
export function phq9Complete(responses: readonly (number | null)[]): boolean {
  return responses.length === PHQ9_ITEMS.length && responses.every((r) => typeof r === "number");
}

/** The encrypted-payload contract (consumed by the therapist portal):
 * {"v":1,"measure":"phq9","score":N,"completed_at":ISO-date}. */
export function phq9Payload(responses: readonly (number | null)[], completedAt: string): string {
  return JSON.stringify({
    v: 1,
    measure: "phq9",
    score: phq9Score(responses),
    completed_at: completedAt,
  });
}
