import { expect, it } from "vitest";
import { decryptEntry, decryptInsights } from "../src/crypto/patient";
import { decrypt, encrypt, toBase64 } from "../src/crypto/core";

const key = new Uint8Array(32).fill(11);
let identifier = 0;
async function openEntry(payload: unknown) {
  const id = `schema-boundary-${++identifier}`;
  const aad = new TextEncoder().encode(JSON.stringify(["entry", "patient-schema", id, "1"]));
  const blob = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(payload)), aad));
  return decryptEntry(key, "patient-schema", id, blob, 1);
}
async function openInsights(payload: unknown) {
  const aad = new TextEncoder().encode('["insights","patient-schema","patterns"]');
  const blob = toBase64(await encrypt(key, new TextEncoder().encode(JSON.stringify(payload)), aad));
  return decryptInsights(key, "patient-schema", blob);
}

it("authenticates an empty AES-256-GCM message at the minimum envelope size", async () => {
  const aad = new TextEncoder().encode("empty-message-contract");
  const sealed = await encrypt(key, new Uint8Array(), aad);
  expect(sealed).toHaveLength(28);
  await expect(decrypt(key, sealed, aad)).resolves.toEqual(new Uint8Array());
});

it.each([16, 24, 31, 33])("refuses an AES key of %s bytes instead of silently selecting another strength", async length => {
  await expect(encrypt(new Uint8Array(length), new Uint8Array())).rejects.toThrow("key must be 32 bytes");
  await expect(decrypt(new Uint8Array(length), new Uint8Array(28))).rejects.toThrow("key must be 32 bytes");
});

it("preserves the supported entry schema boundaries and multilingual voice channels", async () => {
  const payload = { v: 3, text: "t".repeat(100000), sentiment: -1, energy: 5, sleep: 1, tags: Array.from({ length: 200 }, () => "t".repeat(200)), created_at: "2026-09-30T12:00:00Z", input_mode: "voice", transcript_lang: "abc-AbCdEfGh", english_text: "e".repeat(100000), tod: "night" };
  await expect(openEntry(payload)).resolves.toEqual(payload);
  await expect(openEntry({ v: 1, text: "", sentiment: 1, energy: -1, sleep: 5 })).resolves.toMatchObject({ text: "", sentiment: 1, energy: -1, sleep: 5 });
  await expect(openEntry({ v: 2, text: "typed", input_mode: "typed", transcript_lang: "en-US", english_text: null, tod: "morning" })).resolves.toMatchObject({ input_mode: "typed", english_text: null });
});

const invalidEntries = [
  null, [], {}, { v: 0, text: "text" }, { v: 4, text: "text" }, { v: "1", text: "text" },
  { v: 1, text: 42 }, { v: 1, text: "t".repeat(100001) },
  ...[{ sentiment: -1.001 }, { sentiment: 1.001 }, { sentiment: "0" }, { energy: -1.001 }, { energy: 5.001 }, { sleep: 0.999 }, { sleep: 5.001 }, { created_at: 42 }, { created_at: "not-a-date" }, { tags: {} }, { tags: Array(201).fill("tag") }, { tags: [42] }, { tags: ["t".repeat(201)] }, { english_text: 42 }, { english_text: "e".repeat(100001) }, { input_mode: "camera" }, { transcript_lang: 42 }, { transcript_lang: "e" }, { transcript_lang: "abcd" }, { transcript_lang: "EN" }, { transcript_lang: "en-u" }, { transcript_lang: "en-abcdefghi" }, { transcript_lang: "en_US" }, { tod: "noon" }].map(field => ({ v: 3, text: "entry", ...field })),
];
const entryMessages = [
  "Encrypted payload must be an object.", "Encrypted payload must be an object.",
  "unsupported entry payload version: undefined", "unsupported entry payload version: 0", "unsupported entry payload version: 4", "unsupported entry payload version: 1",
  "entry payload malformed", "entry payload malformed",
  ...Array(3).fill("Invalid encrypted sentiment."), ...Array(2).fill("Invalid encrypted energy."), ...Array(2).fill("Invalid encrypted sleep."),
  ...Array(2).fill("Invalid encrypted entry date."), ...Array(4).fill("Invalid encrypted tags."), ...Array(2).fill("Invalid encrypted translation."),
  "Invalid encrypted input mode.", ...Array(7).fill("Invalid encrypted transcript language."), "Invalid encrypted time bucket.",
];
if (entryMessages.length !== invalidEntries.length) throw new Error("Entry fixture message count mismatch");
it.each(invalidEntries.map((payload, index) => ({ payload, index, message: entryMessages[index]! })))("rejects authenticated unsupported entry shape $index with actionable copy", async ({ payload, message }) => {
  await expect(openEntry(payload)).rejects.toMatchObject({ message });
});

it.each([42, "entry"])("rejects a primitive authenticated entry %s with shape-specific copy", async payload => {
  await expect(openEntry(payload)).rejects.toMatchObject({ message: "Encrypted payload must be an object." });
});
it("rejects mixed unsafe and safe arrays instead of accepting the safe member", async () => {
  await expect(openEntry({ v: 1, text: "entry", tags: ["safe", 42] })).rejects.toMatchObject({ message: "Invalid encrypted tags." });
  await expect(openInsights({ v: 2, stats: { patterns: [{ kind: "topic", label: "topic", confidence: 0.5, occurrences: 2, detail: { evidence_dates: ["2026-09-30", 42] } }] } })).rejects.toMatchObject({ message: "Invalid encrypted evidence dates." });
});
it("rejects date/language arrays that a regular expression could silently coerce into valid-looking text", async () => {
  await expect(openEntry({ v: 3, text: "entry", transcript_lang: ["en-US"] })).rejects.toMatchObject({ message: "Invalid encrypted transcript language." });
  await expect(openInsights({ v: 2, stats: { first_date: ["2026-09-30"] } })).rejects.toMatchObject({ message: "Invalid encrypted chart date." });
  await expect(openInsights({ v: 2, stats: { patterns: [{ kind: "topic", label: "topic", confidence: 0.5, occurrences: 2, detail: { evidence_dates: [["2026-09-30"]] } }] } })).rejects.toMatchObject({ message: "Invalid encrypted evidence dates." });
});
it.each(["prefix2026-09-30", "2026-09-30suffix"])("rejects extra date text %s in charts and pattern evidence", async date => {
  await expect(openInsights({ v: 2, stats: { first_date: date } })).rejects.toMatchObject({ message: "Invalid encrypted chart date." });
  await expect(openInsights({ v: 2, stats: { patterns: [{ kind: "topic", label: "topic", confidence: 0.5, occurrences: 2, detail: { evidence_dates: [date] } }] } })).rejects.toMatchObject({ message: "Invalid encrypted evidence dates." });
});
it.each(["afternoon", "evening"])("keeps the supported %s time bucket", async tod => {
  await expect(openEntry({ v: 1, text: "entry", tod })).resolves.toEqual({ v: 1, text: "entry", tod });
});
it("preserves earlier additive insight schemas without stats or pattern fields", async () => {
  await expect(openInsights({ v: 2 })).resolves.toEqual({ v: 2 });
  await expect(openInsights({ v: 2, stats: { avg_sentiment: 0 } })).resolves.toEqual({ v: 2, stats: { avg_sentiment: 0 } });
});

const coverage = { observations: 1, explicit_mood: 1, text_estimates: 0, excluded_entries: 0, source: "explicit_mood" };
it.each([
  { avg_sentiment: null, total_entries: 10000000, mood_summary: { observations: 0, explicit_mood: 0, text_estimates: 0, excluded_entries: 10000000, source: "unavailable" } },
  { avg_sentiment: 0, total_entries: 10000000, mood_summary: { observations: 10000000, explicit_mood: 10000000, text_estimates: 0, excluded_entries: 0, source: "explicit_mood" } },
  { avg_sentiment: 1, total_entries: 10000000, mood_summary: { observations: 10000000, explicit_mood: 0, text_estimates: 10000000, excluded_entries: 0, source: "text_estimate" } },
  { avg_sentiment: -1, mood_summary: { observations: 2, explicit_mood: 1, text_estimates: 1, excluded_entries: 0, source: "mixed" } },
])("preserves honest mood coverage including the maximum supported boundary $mood_summary.source", async stats => {
  await expect(openInsights({ v: 2, stats })).resolves.toEqual({ v: 2, stats });
});
it.each([
  ...["observations", "explicit_mood", "text_estimates", "excluded_entries"].flatMap(field => ["1", -1, 0.5, 10000001].map(value => ({ avg_sentiment: 0, mood_summary: { ...coverage, [field]: value } }))),
  { avg_sentiment: 0, mood_summary: { ...coverage, explicit_mood: 2 } },
  { avg_sentiment: null, mood_summary: coverage },
])("rejects malformed mood coverage with precise copy %#", async stats => {
  await expect(openInsights({ v: 2, stats })).rejects.toMatchObject({ message: stats.avg_sentiment === null || stats.mood_summary.explicit_mood === 2 ? "Inconsistent encrypted mood coverage." : "Invalid encrypted mood coverage." });
});

it("accepts insight labels, coverage and evidence exactly at the supported boundaries", async () => {
  const payload = { v: 2, state_seq: 0, stats: { avg_sentiment: 1, total_entries: 10000000, active_days: 0, first_date: null, last_date: "2026-09-30", patterns: [{ kind: "k".repeat(100), label: "l".repeat(1000), confidence: 1, occurrences: 10000000, detail: { strength: 0, sample_days: 10000000, sample_entries: 0, evidence_dates: Array(10000).fill("2026-09-30"), pattern_pid: "pattern-1", pattern_state: "confirmed", first_seen: "2026-09-01", last_seen: "2026-09-30", sensitive: false, is_new: true } }] } };
  await expect(openInsights(payload)).resolves.toEqual(payload);
  const low = { v: 2, state_seq: Number.MAX_SAFE_INTEGER, stats: { avg_sentiment: -1, total_entries: 0, active_days: 10000000, patterns: [{ kind: "topic", label: "", confidence: 0, occurrences: 0, detail: { strength: 1 } }] } };
  await expect(openInsights(low)).resolves.toEqual(low);
  const full = { v: 2, stats: { patterns: Array(1000).fill({ kind: "topic", label: "", confidence: 0, occurrences: 0, detail: {} }) } };
  await expect(openInsights(full)).resolves.toEqual(full);
});

const pattern = { kind: "topic", label: "topic", confidence: 0.5, occurrences: 2, detail: {} };
const invalidInsights = [
  null, [], { v: 1 }, { v: "2" }, { v: 2, state_seq: -1 }, { v: 2, state_seq: 0.5 }, { v: 2, state_seq: Number.MAX_SAFE_INTEGER + 1 },
  ...[{ avg_sentiment: -1.001 }, { avg_sentiment: 1.001 }, { total_entries: -0.001 }, { total_entries: 10000001 }, { active_days: -1 }, { active_days: 10000001 }, { first_date: 42 }, { first_date: "2026-9-30" }, { last_date: "2026/09/30" }, { patterns: {} }, { patterns: Array(1001).fill(pattern) }].map(stats => ({ v: 2, stats })),
  ...[null, [], { ...pattern, label: 42 }, { ...pattern, label: "l".repeat(1001) }, { ...pattern, kind: 42 }, { ...pattern, kind: "k".repeat(101) }, { ...pattern, confidence: null }, { ...pattern, confidence: -0.001 }, { ...pattern, confidence: 1.001 }, { ...pattern, occurrences: null }, { ...pattern, occurrences: -1 }, { ...pattern, occurrences: 10000001 }, { ...pattern, detail: [] }, { ...pattern, detail: null }, ...[{ strength: -0.001 }, { strength: 1.001 }, { sample_days: -1 }, { sample_days: 10000001 }, { sample_entries: -1 }, { sample_entries: 10000001 }, { evidence_dates: {} }, { evidence_dates: Array(10001).fill("2026-09-30") }, { evidence_dates: [42] }, { evidence_dates: ["2026-9-30"] }, { pattern_pid: 42 }, { pattern_state: 42 }, { first_seen: 42 }, { last_seen: 42 }, { sensitive: "true" }, { is_new: 1 }].map(detail => ({ ...pattern, detail }))].map(row => ({ v: 2, stats: { patterns: [row] } })),
];
const insightMessages = [
  "Encrypted payload must be an object.", "Encrypted payload must be an object.",
  "unsupported insights payload version: 1", "unsupported insights payload version: 2", ...Array(3).fill("Invalid encrypted analysis generation."),
  ...Array(2).fill("Invalid encrypted avg_sentiment."), ...Array(2).fill("Invalid encrypted total_entries."), ...Array(2).fill("Invalid encrypted active_days."),
  ...Array(3).fill("Invalid encrypted chart date."), ...Array(2).fill("Invalid encrypted patterns."),
  ...Array(2).fill("Encrypted payload must be an object."), ...Array(4).fill("Invalid encrypted pattern label."),
  "Invalid encrypted pattern evidence.", ...Array(2).fill("Invalid encrypted confidence."), "Invalid encrypted pattern evidence.", ...Array(2).fill("Invalid encrypted occurrences."),
  ...Array(2).fill("Encrypted payload must be an object."), ...Array(2).fill("Invalid encrypted strength."), ...Array(2).fill("Invalid encrypted sample_days."), ...Array(2).fill("Invalid encrypted sample_entries."),
  ...Array(4).fill("Invalid encrypted evidence dates."), ...Array(4).fill("Invalid encrypted pattern detail."), ...Array(2).fill("Invalid encrypted pattern flags."),
];
if (insightMessages.length !== invalidInsights.length) throw new Error("Insight fixture message count mismatch");
it.each(invalidInsights.map((payload, index) => ({ payload, index, message: insightMessages[index]! })))("rejects authenticated unsafe insight shape $index with actionable copy", async ({ payload, message }) => {
  await expect(openInsights(payload)).rejects.toMatchObject({ message });
});
