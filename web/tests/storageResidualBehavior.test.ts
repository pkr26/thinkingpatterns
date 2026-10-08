import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { readMutedPids, writeMutedPids, adoptLegacyPlaintextMutes } from "../src/patternMutes";
import { buildFeedbackBlob, recordFeedbackTap, recordPatternMute } from "../src/questionFeedback";
import { savePendingMeasure, loadPendingMeasure, clearPendingMeasure, type PendingMeasure } from "../src/pendingMeasure";
import { cadenceDue, parseCadence } from "../src/measureCadence";
import { resetTestState } from "./helpers/api";
import { checkAnalysisGeneration, forgetAnalysisGeneration } from "../src/stateSeqGuard";

vi.mock("../src/crypto/core", async original => {
  const actual = await original<typeof import("../src/crypto/core")>();
  return { ...actual, encrypt: vi.fn(actual.encrypt), decrypt: vi.fn(actual.decrypt) };
});
const owner = "storage-residual-owner", other = "storage-residual-other";
let key: Uint8Array<ArrayBuffer>, records: Map<string, string>;
beforeEach(async () => {
  resetTestState(); key = new Uint8Array(new ArrayBuffer(32)).fill(17); records = new Map();
  setKvBackendForTests({ getItem: async slot => records.get(slot) ?? null, setItem: async (slot, value) => { records.set(slot, value); }, removeItem: async slot => { records.delete(slot); }, keys: async () => [...records.keys()], compareAndSet: async (slot, expected, value, _permit, current) => { if (current && !current()) return false; if ((records.get(slot) ?? null) !== expected) return false; records.set(slot, value); return true; } });
  vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
  await forgetAnalysisGeneration(owner);
});
afterEach(() => { vi.restoreAllMocks(); setKvBackendForTests(null); });
async function seal(domain: string, plaintext: string) { return toBase64(await encrypt(key, new TextEncoder().encode(plaintext), buildAad(domain, owner))); }
const valid: PendingMeasure = { kind: "phq2", clientMeasureId: "stable-retry", picks: [0, 3], date: "2026-10-05" };

it("retains each account's unsent questionnaire when a different account saves and clears its own record", async () => {
  const otherKey = new Uint8Array(new ArrayBuffer(32)).fill(23), second = { ...valid, clientMeasureId: "other-stable-retry", picks: [2, 1] };
  await savePendingMeasure(key, owner, valid); await savePendingMeasure(otherKey, other, second);
  expect(await loadPendingMeasure(key, owner)).toEqual(valid); expect(await loadPendingMeasure(otherKey, other)).toEqual(second);
  await clearPendingMeasure(other); expect(await loadPendingMeasure(key, owner)).toEqual(valid); expect(await loadPendingMeasure(otherKey, other)).toBeNull();
});
it.each([{ kind: ["phq2"] }, { date: ["2026-10-05"] }, { date: { toString: "2026-10-05" } }])("refuses authenticated questionnaire fields that coerce into an allowed spelling: %j", async fields => {
  records.set(`mindpattern.pendingMeasure.${owner}`, await seal("pending-measure", JSON.stringify({ ...valid, ...fields })));
  expect(await loadPendingMeasure(key, owner)).toBeNull();
});
it.each(["invalid plaintext JSON", "ciphertext authentication", "wrong account key"] as const)("returns the declared absent questionnaire for %s", async fault => {
  records.set(`mindpattern.pendingMeasure.${owner}`, fault === "ciphertext authentication" ? "broken ciphertext" : await seal("pending-measure", fault === "invalid plaintext JSON" ? "not JSON" : JSON.stringify(valid)));
  expect(await loadPendingMeasure(fault === "wrong account key" ? new Uint8Array(32).fill(99) : key, owner)).toBeNull();
});
it("treats an authenticated string as absent mute metadata instead of muting its individual characters", async () => {
  records.set(`mindpattern.patternMutes.v1.${owner}`, await seal("pattern-mutes", JSON.stringify("not a list of pattern identifiers")));
  expect(await readMutedPids(key, owner)).toEqual(new Set());
});
it("adopts one account's legacy mutes without deleting a different account whose identifier shares its prefix", async () => {
  const nestedOwner = `${owner}-other`; window.localStorage.setItem(`mindpattern.mutedPids.v1.${owner}`, JSON.stringify(["this-account"])); window.localStorage.setItem(`mindpattern.mutedPids.v1.${nestedOwner}`, JSON.stringify(["other-account"]));
  expect(await adoptLegacyPlaintextMutes(key, owner)).toEqual(new Set(["this-account"])); expect(await adoptLegacyPlaintextMutes(new Uint8Array(32).fill(31), nestedOwner)).toEqual(new Set(["other-account"]));
});
it.each(["broken ciphertext", "not JSON"]) ("keeps an unreadable feedback record absent from the next recompute: %s", async value => {
  records.set(`mindpattern.feedback.${owner}`, value === "broken ciphertext" ? value : await seal("feedback-local", value)); expect(await buildFeedbackBlob(key, owner)).toBeNull();
});
it("filters authenticated scalar feedback events while retaining the admitted tap", async () => {
  const event = { pid: "retained", resonated: true };
  records.set(`mindpattern.feedback.${owner}`, await seal("feedback-local", JSON.stringify(["scalar", 4, false, null, event])));
  const blob = await buildFeedbackBlob(key, owner); expect(blob).not.toBeNull();
  const output = JSON.parse(new TextDecoder().decode(await decrypt(key, fromBase64(blob!), buildAad("feedback", owner, new Date().toISOString().slice(0, 10)))));
  expect(output).toEqual({ feedback: [event], muted: [], unmuted: [] });
});
it.each(["mute read", "mute write", "feedback append", "feedback recompute", "failed mute write", "failed feedback append"] as const)("erases actual cryptographic boundary key and plaintext buffers after a public %s", async operation => {
  if (operation === "mute read") await writeMutedPids(key, owner, ["retained"]);
  if (operation === "feedback recompute") await recordFeedbackTap(key, owner, "retained", true);
  vi.mocked(encrypt).mockClear(); vi.mocked(decrypt).mockClear();
  if (operation.startsWith("failed")) vi.spyOn(kv, "setItem").mockRejectedValue(new Error("actual local commit refused"));
  const run = operation === "mute read" ? readMutedPids(key, owner) : operation.includes("mute write") ? writeMutedPids(key, owner, ["retained"]) : operation === "feedback recompute" ? buildFeedbackBlob(key, owner) : recordPatternMute(key, owner, "retained", true);
  if (operation.startsWith("failed")) await expect(run).rejects.toThrow("actual local commit refused"); else await run;
  const physicalKeys = [...vi.mocked(encrypt).mock.calls, ...vi.mocked(decrypt).mock.calls].map(args => args[0]).filter(bytes => bytes.buffer !== key.buffer);
  expect(physicalKeys.length).toBeGreaterThan(0); physicalKeys.forEach(bytes => expect(bytes).toEqual(new Uint8Array(bytes.length)));
  vi.mocked(encrypt).mock.calls.forEach(([, plaintext]) => expect(plaintext).toEqual(new Uint8Array(plaintext.length)));
  for (const result of await Promise.allSettled(vi.mocked(decrypt).mock.results.map(row => row.value as Promise<Uint8Array>))) if (result.status === "fulfilled") expect(result.value).toEqual(new Uint8Array(result.value.length));
  expect(key).toEqual(new Uint8Array(32).fill(17));
});
it("rejects a coercible array snooze and keeps unknown questionnaire history suppressed", () => {
  const pref = parseCadence(JSON.stringify({ enabled: true, intervalWeeks: 4, snoozedUntil: ["2026-10-05"] })); expect(pref.snoozedUntil).toBeNull();
  expect(cadenceDue(pref, undefined, "2026-10-06")).toBe(false);
});
it.each(["already stored", "first observed"] as const)("remembers a %s authenticated generation when local storage subsequently fails", async origin => {
  if (origin === "already stored") records.set(`mindpattern.stateSeq.${owner}`, "5"); await checkAnalysisGeneration(owner, 5, 5);
  records.delete(`mindpattern.stateSeq.${owner}`); vi.spyOn(kv, "getItem").mockRejectedValue(new Error("metadata temporarily unreadable"));
  await expect(checkAnalysisGeneration(owner, 4, 4)).rejects.toThrow("freshness check");
});
it.each(["equal durable generation", "unreadable durable generation"] as const)("accepts the current authenticated generation without requiring a redundant unavailable write: %s", async storage => {
  await checkAnalysisGeneration(owner, 5, 5); if (storage === "unreadable durable generation") vi.spyOn(kv, "getItem").mockRejectedValue(new Error("metadata temporarily unreadable"));
  vi.spyOn(kv, "setItem").mockRejectedValue(new Error("metadata write temporarily refused")); await expect(checkAnalysisGeneration(owner, 5, 5)).resolves.toBeUndefined();
});
it("accepts an already-current generation when the host cannot grant new Web Locks", async () => {
  await checkAnalysisGeneration(owner, 5, 5); vi.stubGlobal("navigator", { ...navigator, locks: { request: async () => { throw new Error("browser lock service unavailable"); } } });
  try { await expect(checkAnalysisGeneration(owner, 5, 5)).resolves.toBeUndefined(); } finally { vi.unstubAllGlobals(); }
});
it.each([[undefined, 1], [1, undefined], [NaN, 0], [Infinity, 0]] as const)("allows a fresh legacy account with absent generation data (%s,%s) before any high-water mark exists", async (payload, echoed) => {
  await expect(checkAnalysisGeneration(owner, payload, echoed)).resolves.toBeUndefined();
});
it("allows an unnumbered fresh account with a meaningless negative stored marker when metadata writes are unavailable", async () => {
  records.set(`mindpattern.stateSeq.${owner}`, "-1"); vi.spyOn(kv, "setItem").mockRejectedValue(new Error("metadata cannot currently be rewritten"));
  await expect(checkAnalysisGeneration(owner, undefined, undefined)).resolves.toBeUndefined();
});
it.each([6, 7])("honors a sibling tab's generation %i published before the browser grants this operation's lock", async sibling => {
  records.set(`mindpattern.stateSeq.${owner}`, "5");
  vi.stubGlobal("navigator", { ...navigator, locks: { request: async (_name: string, operation: () => Promise<void>) => { records.set(`mindpattern.stateSeq.${owner}`, String(sibling)); await operation(); } } });
  try { await checkAnalysisGeneration(owner, 6, 6); if (sibling > 6) await expect(checkAnalysisGeneration(owner, 6, 6)).rejects.toThrow("freshness check"); }
  finally { vi.unstubAllGlobals(); }
});
it("accepts a sibling-confirmed equal generation without rewriting it during a quota failure", async () => {
  records.set(`mindpattern.stateSeq.${owner}`, "5"); vi.spyOn(kv, "setItem").mockRejectedValue(new Error("metadata write quota refused"));
  vi.stubGlobal("navigator", { ...navigator, locks: { request: async (_name: string, operation: () => Promise<void>) => { records.set(`mindpattern.stateSeq.${owner}`, "6"); await operation(); } } });
  try { await expect(checkAnalysisGeneration(owner, 6, 6)).resolves.toBeUndefined(); } finally { vi.unstubAllGlobals(); }
});
it("waits for a sibling's public browser-lock transaction before accepting its own analysis generation", async () => {
  const tails = new Map<string, Promise<unknown>>();
  const locks = { request: async <T>(name: string, operation: () => Promise<T>) => { const prior = tails.get(name) ?? Promise.resolve(); const work = prior.then(operation, operation); tails.set(name, work.catch(() => undefined)); return work; } };
  vi.stubGlobal("navigator", { ...navigator, locks }); let release!: () => void; const held = new Promise<void>(resolve => { release = resolve; });
  // This is the persistent browser coordination protocol used by another tab,
  // independently of the currently loaded frontend module.
  const sibling = locks.request(`mindpattern-stateSeq.${owner}`, async () => { await held; records.set(`mindpattern.stateSeq.${owner}`, "7"); });
  records.set(`mindpattern.stateSeq.${owner}`, "5"); let accepted = false; const own = checkAnalysisGeneration(owner, 6, 6).then(() => { accepted = true; });
  try { await new Promise<void>(resolve => setTimeout(resolve, 0)); expect(accepted).toBe(false); release(); await sibling; await own; await expect(checkAnalysisGeneration(owner, 6, 6)).rejects.toThrow("freshness check"); }
  finally { release(); await Promise.allSettled([sibling, own]); vi.unstubAllGlobals(); }
});
