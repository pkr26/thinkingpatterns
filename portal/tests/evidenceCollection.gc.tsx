/** Ordinary Node heap-lifetime contract. Public App/Login/MFA and evidence
 * controls produce the real decrypted row; the external V8 heap graph only
 * counts its public data fields. No React queue/ref or application source is
 * inspected. Snapshot files contain synthetic data and are removed immediately. */
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeHeapSnapshot } from "node:v8";
import { act } from "react";
import { expect, it, vi } from "vitest";
import { openNativeChart } from "./helpers/prospectiveNativeChart";

const EVIDENCE = "Authenticated audio evidence", ROW_ID = "native-evidence-row";
const POSITIVE = "evidence-owner-positive-control", NEGATIVE = "evidence-owner-negative-control";
const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
const retained = new Map<string, object>();
let witness: Record<string, unknown> = {};
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const save = () => { const path = process.env.FRONTEND_PORTAL_EVIDENCE_COLLECTION_RECEIPT; if (path) writeFileSync(path, JSON.stringify(witness, null, 2) + "\n"); };
type Heap = { snapshot: { meta: { node_fields: string[]; node_types: string[][]; edge_fields: string[]; edge_types: string[][] } }; nodes: number[]; edges: number[]; strings: string[] };

function ownerCensus(): Record<string, number> {
  const directory = mkdtempSync(join(tmpdir(), "portal-synthetic-evidence-heap-")), path = join(directory, "owned.heapsnapshot");
  let heap: Heap;
  try { writeHeapSnapshot(path); heap = JSON.parse(readFileSync(path, "utf8")) as Heap; }
  finally { try { unlinkSync(path); } finally { rmdirSync(directory); } }
  const meta = heap.snapshot.meta, nodeWidth = meta.node_fields.length, edgeWidth = meta.edge_fields.length;
  const nameIndex = meta.node_fields.indexOf("name"), typeIndex = meta.node_fields.indexOf("type"), countIndex = meta.node_fields.indexOf("edge_count");
  const edgeTypeIndex = meta.edge_fields.indexOf("type"), edgeNameIndex = meta.edge_fields.indexOf("name_or_index"), targetIndex = meta.edge_fields.indexOf("to_node");
  if ([nameIndex, typeIndex, countIndex, edgeTypeIndex, edgeNameIndex, targetIndex].some(index => index < 0)) throw new Error("SetupError: native heap schema lacks public object/property census fields");
  const counts: Record<string, number> = { [ROW_ID]: 0, [POSITIVE]: 0, [NEGATIVE]: 0 }; let edge = 0;
  for (let node = 0; node < heap.nodes.length; node += nodeWidth) {
    const properties = new Map<string, string>();
    for (let index = 0; index < heap.nodes[node + countIndex]!; index++, edge += edgeWidth) {
      if (meta.edge_types[edgeTypeIndex]![heap.edges[edge + edgeTypeIndex]!] !== "property") continue;
      const name = heap.strings[heap.edges[edge + edgeNameIndex]!]!, target = heap.edges[edge + targetIndex]!;
      if (name === "id" || name === "text" || name === "entry_date") properties.set(name, heap.strings[heap.nodes[target + nameIndex]!]!);
    }
    const id = properties.get("id");
    if (meta.node_types[typeIndex]![heap.nodes[node + typeIndex]!] === "object" && id !== undefined && Object.hasOwn(counts, id) && properties.get("text") === EVIDENCE && properties.has("entry_date")) counts[id]!++;
  }
  return counts;
}
function releasedOwner(): WeakRef<object> { return new WeakRef({ id: NEGATIVE, text: EVIDENCE, entry_date: "2026-10-01" }); }
async function collectorControl(stage: string): Promise<void> {
  const positive = { id: POSITIVE, text: EVIDENCE, entry_date: "2026-10-01" }, negative = releasedOwner(); retained.set(stage, positive);
  try {
    if (typeof gc !== "function") throw new Error("SetupError: evidence collection requires an explicit Node --expose-gc provider");
    for (let attempt = 0; attempt < 20; attempt++) {
      await turn(); gc(); await turn();
      if (negative.deref() !== undefined) continue;
      const census = ownerCensus();
      if (census[POSITIVE] !== 1 || census[NEGATIVE] !== 0 || retained.get(stage) !== positive) throw new Error("SetupError: same-shape native evidence collector controls disagree");
      witness.collectorControls = [...(witness.collectorControls as unknown[] ?? []), { stage, attempts: attempt + 1, positiveRetained: true, negativeCollected: true, resource: "plain-authenticated-entry-owner", retainedOwners: census[POSITIVE], releasedOwners: census[NEGATIVE] }]; save(); return;
    }
    throw new Error("SetupError: released same-shape evidence control was not collected within its finite budget");
  } finally { retained.delete(stage); }
}

it("releases decrypted evidence owners after public Back and current chart interactions", async () => {
  vi.useRealTimers(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  witness = { stage: "collector-setup", nodeVersion: process.version, gcCapability: typeof gc === "function", limits: ["Actual frozen Node22 V8 plain-object lifetime; no browser/device heap guarantee or unbounded-growth claim.", "Only the synthetic authenticated EntryRow public id/text/date data shape is counted; no React-private state, queue, ref or variable-name inspection.", "Public Back plus subsequent legitimate current writing retires React's preceding commit before collection."] }; save();
  await collectorControl("before-public-producer");
  witness.stage = "public-producer"; save();
  const chart = await openNativeChart();
  try {
    await chart.evidence(); expect(chart.text()).toContain(EVIDENCE);
    const before = ownerCensus()[ROW_ID]!;
    if (before !== 1) throw new Error("SetupError: the completed genuine evidence producer did not expose one authenticated public row owner");
    await chart.press("Back to all patterns"); expect(chart.text()).not.toContain(EVIDENCE); expect(chart.text()).toContain("See the evidence");
    for (const value of ["Current general writing one", "Current general writing two", "Current general writing three"]) {
      await act(async () => chart.composer().props.onChange({ target: { value } })); expect(chart.composer().props.value).toBe(value);
    }
    witness.publicProducer = { complete: true, authenticatedChart: true, evidenceVisible: true, backCompleted: true, currentWritingCompleted: true }; witness.observedEvidenceOwners = before; save();
    await collectorControl("after-public-producer");
    await turn(); gc!(); await turn();
    const after = ownerCensus()[ROW_ID]!;
    witness.stage = "behavior-resource-assertion"; witness.retainedEvidenceOwnerCount = after; save();
    expect(after, "Completed public Back must release decrypted evidence from its mounted owner after current interactions retire the preceding React commit").toBe(0);
    chart.clean(); witness.stage = "passed"; save();
  } finally { await chart.retire(); retained.clear(); save(); }
}, 60_000);

it("releases decrypted evidence owners after public Retry and current chart interactions", async () => {
  vi.useRealTimers(); (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  witness = { stage: "collector-setup", nodeVersion: process.version, gcCapability: typeof gc === "function", limits: ["Actual frozen Node22 V8 plain-object lifetime; no browser/device heap guarantee or unbounded-growth claim.", "Only the synthetic authenticated EntryRow public id/text/date data shape is counted; no React-private state, queue, ref or variable-name inspection.", "Public Retry plus subsequent legitimate current writing retires React's preceding commit before collection."] }; save();
  await collectorControl("before-public-producer");
  witness.stage = "public-producer"; save();
  const chart = await openNativeChart({ gcRetry: true });
  try {
    await chart.evidence(); expect(chart.text()).toContain(EVIDENCE);
    const before = ownerCensus()[ROW_ID]!;
    if (before !== 1) throw new Error("SetupError: the completed genuine evidence producer did not expose one authenticated public row owner");
    await chart.press("Retry loading this patient"); await chart.completed("healthy current chart after retry", () => chart.text().includes("See the evidence") && !chart.text().includes("Retry loading this patient")); expect(chart.text()).not.toContain(EVIDENCE);
    for (const value of ["Current general writing one", "Current general writing two", "Current general writing three"]) {
      await act(async () => chart.composer().props.onChange({ target: { value } })); expect(chart.composer().props.value).toBe(value);
    }
    witness.publicProducer = { complete: true, authenticatedChart: true, evidenceVisible: true, retryCompleted: true, currentWritingCompleted: true }; witness.observedEvidenceOwners = before; save();
    await collectorControl("after-public-producer");
    await turn(); gc!(); await turn();
    const after = ownerCensus()[ROW_ID]!;
    witness.stage = "behavior-resource-assertion"; witness.retainedEvidenceOwnerCount = after; save();
    expect(after, "Completed public Retry must release decrypted evidence from its mounted owner after current interactions retire the preceding React commit").toBe(0);
    chart.clean(); witness.stage = "passed"; save();
  } finally { await chart.retire(); retained.clear(); save(); }
}, 60_000);
