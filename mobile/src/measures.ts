/**
 * The measurement-based-care instrument registry (Phase 3, 2026-09-21).
 *
 * PHQ-9 shipped first (2026-09-19); the audit's Phase 3 MBC-depth item
 * adds GAD-7 (anxiety, 7 items, 0-21) and PHQ-2 (the two-item depression
 * core, 0-6) alongside it. All three are public-domain-style instruments
 * (the Kroenke/Spitzer Pfizer no-permission-required note) and all three
 * ride the EXISTING zero-knowledge measure path: the score (plus, for the
 * PHQ-9 only, the raw item-9 response — see measurePayload) is the whole
 * payload ({"v":1,"measure":id,"score":N[,"item9":M],"completed_at":date}),
 * stored as an encrypted blob and shared per consent — the server and portal
 * remain unable to interpret anything (and so does this app: no severity
 * bands, no advice; interpretation belongs to a clinician).
 *
 * STRUCTURE vs COPY (audit M-16 discipline): this module owns structure
 * only — item counts, option values, score ceilings, the one safety
 * item. Display copy lives in the locale catalogs
 * (measures.<id>.itemN / shared optionN).
 */

export type MeasureId = "phq9" | "gad7" | "phq2";

export interface Instrument {
  id: MeasureId;
  /** Structural item count (display copy resolves per locale). */
  items: number;
  /** Response option values: the standard 0-3 frequency scale. */
  options: readonly number[];
  /** Maximum total score (items × max option). */
  maxScore: number;
  /** Index of the safety item (post-save crisis pointer), if any. */
  safetyItemIndex?: number;
  /** Locale key for the response-option labels (shared across instruments). */
  optionKey: (value: number) => string;
}

const FREQUENCY_OPTIONS: readonly number[] = [0, 1, 2, 3];

function optionKeyFor(value: number): string {
  return `measures.option${value}`;
}

export const INSTRUMENTS: Readonly<Record<MeasureId, Instrument>> = {
  phq9: {
    id: "phq9",
    items: 9,
    options: FREQUENCY_OPTIONS,
    maxScore: 27,
    safetyItemIndex: 8,
    optionKey: optionKeyFor,
  },
  gad7: {
    id: "gad7",
    items: 7,
    options: FREQUENCY_OPTIONS,
    maxScore: 21,
    optionKey: optionKeyFor,
  },
  phq2: {
    id: "phq2",
    items: 2,
    options: FREQUENCY_OPTIONS,
    maxScore: 6,
    optionKey: optionKeyFor,
  },
};

export const MEASURE_IDS: readonly MeasureId[] = ["phq9", "gad7", "phq2"];

function instrumentOf(id: MeasureId): Instrument {
  return INSTRUMENTS[id];
}

/** Sum of the responses (clamped per item to the option scale, capped at
 *  the instrument ceiling). Unanswered items count as 0 — the completion
 *  UI requires every item before submitting; this guards the scorer. */
export function measureScore(id: MeasureId, responses: readonly (number | null)[]): number {
  const instrument = instrumentOf(id);
  const maxOption = Math.max(...instrument.options);
  let total = 0;
  for (let i = 0; i < instrument.items; i++) {
    const value = responses[i];
    if (typeof value === "number" && Number.isFinite(value)) {
      total += Math.max(0, Math.min(maxOption, Math.round(value)));
    }
  }
  return Math.min(instrument.maxScore, total);
}

/** True when every item has a pick — the submit button's enabled gate. */
export function measureComplete(id: MeasureId, responses: readonly (number | null)[]): boolean {
  const instrument = instrumentOf(id);
  return responses.length === instrument.items && responses.every((r) => typeof r === "number");
}

/** True when the instrument's safety item (if any) was endorsed at any
 *  level — powers the post-save support pointer. The score itself is
 *  never interpreted. */
export function safetyItemEndorsed(id: MeasureId, responses: readonly (number | null)[]): boolean {
  const index = instrumentOf(id).safetyItemIndex;
  if (index === undefined) return false;
  const value = responses[index];
  return typeof value === "number" && value > 0;
}

/** Item 9 in the PHQ-9 payload (clinical follow-up contract, 2026-09-27):
 *  the RAW response to the safety item, clamped to the option scale, or
 *  null when unanswered. An endorsed item 9 mandates clinical follow-up
 *  regardless of the total score — a total alone can read "mild" while
 *  item 9 says otherwise — so the portal must see it as its own field.
 *  The app itself still never interprets it (no bands, no advice): the
 *  field exists for the clinician, exactly like the score. */
export function measureSafetyItemValue(
  id: MeasureId,
  responses: readonly (number | null)[],
): number | null {
  const index = instrumentOf(id).safetyItemIndex;
  if (index === undefined) return null;
  const value = responses[index];
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  const maxOption = Math.max(...instrumentOf(id).options);
  return Math.max(0, Math.min(maxOption, Math.round(value)));
}

/** The encrypted-payload contract (consumed by the therapist portal):
 *  {"v":1,"measure":<id>,"score":N,"completed_at":ISO-date} — and, for
 *  the PHQ-9 ONLY, "item9": the raw safety-item response rides next to
 *  the score (see measureSafetyItemValue). GAD-7/PHQ-2 payloads carry no
 *  item9 field (they have no safety item), and older payloads without it
 *  remain valid on every reader. */
export function measurePayload(
  id: MeasureId,
  responses: readonly (number | null)[],
  completedAt: string,
): string {
  // Key ORDER is the wire contract (the portal parses positionally in its
  // fixture tests): v, measure, score, [item9], completed_at.
  const payload: Record<string, unknown> = {
    v: 1,
    measure: id,
    score: measureScore(id, responses),
  };
  const item9 = measureSafetyItemValue(id, responses);
  if (item9 !== null) payload.item9 = item9;
  payload.completed_at = completedAt;
  return JSON.stringify(payload);
}

/** The score ceiling for a payload's measure name — used to clamp the
 *  patient's own history rows per instrument (a phq2 row must never
 *  render a phq9-scale number). Unknown names (future instruments)
 *  return null so callers skip the row rather than mis-scale it.
 *  2026-09-26 audit LOW: the lookup is an OWN-property check. The old
 *  `in` operator leaked Object.prototype — `maxScoreForMeasure("constructor")`
 *  returned undefined (≠ null), which falsified the caller's null gate and
 *  produced a NaN share in the history render. */
export function maxScoreForMeasure(measure: unknown): number | null {
  if (typeof measure !== "string") return null;
  return Object.prototype.hasOwnProperty.call(INSTRUMENTS, measure)
    ? INSTRUMENTS[measure as MeasureId]!.maxScore
    : null;
}
