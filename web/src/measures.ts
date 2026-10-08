/**
 * PHQ-9, GAD-7, and PHQ-2 structure and score calculation.
 *
 * Display copy lives in the locale catalogs; this module owns item counts,
 * option values, score ceilings, and PHQ-9's safety item. Completed responses
 * travel as encrypted measure payloads. The UI presents scores without
 * severity bands, diagnosis, or treatment advice.
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
  return responses.length === instrument.items && Array.from(responses).every((r) => typeof r === "number" && instrument.options.includes(r));
}

/** The chip-selection contract (audit 2026-09-26 LOW): a stored response
 *  is the option's VALUE and selection compares VALUES — correct for any
 *  response scale, contiguous or not. The shipped scale is [0,1,2,3],
 *  where value and index coincide, which is exactly why the index-based
 *  comparison went unnoticed; a hypothetical [0,2,4] scale must never
 *  silently regress to index semantics (the second chip records 2, not 1,
 *  and a stored 1 selects nothing). */
export function optionSelected(
  responses: readonly (number | null)[],
  itemIndex: number,
  optionValue: number,
): boolean {
  return responses[itemIndex] === optionValue;
}

/** True when the instrument's safety item (if any) was endorsed at any
 *  level — powers the post-save support pointer. The score itself is
 *  never interpreted. */
export function safetyItemEndorsed(id: MeasureId, responses: readonly (number | null)[]): boolean {
  return (safetyItemValue(id, responses) ?? 0) > 0;
}

/** The RAW response to the instrument's safety item (if any), clamped to
 *  the option scale exactly like the scorer — or null when the instrument
 *  has no safety item or the response is not a number. This is the value
 *  the payload's item9 field carries: the clinician's follow-up rule
 *  fires on the ITEM response regardless of the total, so it is stored
 *  verbatim, never folded into the score. */
export function safetyItemValue(id: MeasureId, responses: readonly (number | null)[]): number | null {
  const instrument = instrumentOf(id);
  const index = instrument.safetyItemIndex;
  if (index === undefined) return null;
  const value = responses[index];
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.max(0, Math.min(Math.max(...instrument.options), Math.round(value)));
}

/** The encrypted-payload contract (consumed by the therapist portal):
 *  {"v":1,"measure":<id>,"score":N,"item9":R,"completed_at":ISO-date}.
 *
 *  item9 (clinical review 2026-09-27) rides ONLY phq9 payloads — the RAW
 *  0-3 response to item 9 — because an endorsed PHQ-9 item 9 mandates
 *  clinical follow-up REGARDLESS of the total score, and the total alone
 *  hid it. gad7/phq2 never carry the field, and payloads written before
 *  the field existed remain exactly as valid (the portal renders nothing
 *  extra for them). The score is byte-identical to the pre-field
 *  contract. */
export function measurePayload(
  id: MeasureId,
  responses: readonly (number | null)[],
  completedAt: string,
): string {
  const item9 = safetyItemValue(id, responses);
  return JSON.stringify({
    v: 1,
    measure: id,
    score: measureScore(id, responses),
    ...(id === "phq9" && item9 !== null ? { item9 } : {}),
    completed_at: completedAt,
  });
}

/** The score ceiling for a payload's measure name — used to clamp the
 *  patient's own history rows per instrument (a phq2 row must never
 *  render a phq9-scale number). Unknown names (future instruments)
 *  return null so callers skip the row rather than mis-scale it. */
export function maxScoreForMeasure(measure: unknown): number | null {
  if (typeof measure !== "string") return null;
  return Object.hasOwn(INSTRUMENTS, measure) ? INSTRUMENTS[measure as MeasureId].maxScore : null;
}
