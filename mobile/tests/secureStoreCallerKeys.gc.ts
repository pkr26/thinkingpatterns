/** Actual finite V8 lifetime of caller-created public secureStore slot keys.
 * The heap census reads string values only, never application/Map internals. */
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeHeapSnapshot } from "node:v8";
import { expect, it } from "vitest";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
import { runTestControl } from "./helpers/testControl";

type Heap = { snapshot: { meta: { node_fields: string[]; node_types: string[][] } }; nodes: number[]; strings: string[] };
const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
const controls = new Map<string, string>();
let witness: Record<string, unknown> = {};
function save() { const p = process.env.SECURESTORE_CALLER_KEYS_RECEIPT; if (p) writeFileSync(p, JSON.stringify(witness, null, 2) + "\n"); }
function flatSubject(prefix: string) { return Buffer.from(prefix + "::" + randomUUID() + ":caller-owned-finite-key-data", "utf8").toString("utf8"); }
function census(prefixes: Record<string, string>): Record<string, number> {
  const directory = mkdtempSync(join(tmpdir(), "secure-store-synthetic-key-heap-")), path = join(directory, "keys.heapsnapshot");
  let heap: Heap;
  try { writeHeapSnapshot(path); heap = JSON.parse(readFileSync(path, "utf8")) as Heap; }
  finally { try { unlinkSync(path); } finally { rmdirSync(directory); } }
  const meta = heap.snapshot.meta, width = meta.node_fields.length, type = meta.node_fields.indexOf("type"), name = meta.node_fields.indexOf("name");
  if (type < 0 || name < 0) throw new Error("SetupError: native V8 string census fields unavailable");
  const counts = Object.fromEntries(Object.keys(prefixes).map(key => [key, 0]));
  for (let node = 0; node < heap.nodes.length; node += width) {
    if (meta.node_types[type]![heap.nodes[node + type]!] !== "string") continue;
    const value = heap.strings[heap.nodes[node + name]!]!;
    for (const [kind, prefix] of Object.entries(prefixes)) if (value.startsWith(prefix + "::") && value.length > prefix.length + 30) counts[kind]!++;
  }
  return counts;
}
async function collectorControls(prefixes: Record<string, string>, phase: string) {
  controls.set("positive", flatSubject(prefixes.positive!)); controls.set("negative", flatSubject(prefixes.negative!));
  const live = census(prefixes);
  if (live.positive !== 1 || live.negative !== 1) throw new Error("SetupError: same-shape live string controls not observed");
  controls.delete("negative");
  for (let attempt = 0; attempt < 10; attempt++) {
    await turn(); gc!(); await turn();
    const after = census(prefixes);
    if (after.positive === 1 && after.negative === 0) {
      witness.collectorControls = [...(witness.collectorControls as unknown[] ?? []), { phase, attempt: attempt + 1, live, after }]; save(); return;
    }
  }
  throw new Error("SetupError: released same-shape string did not collect within finite observation budget");
}
async function publicCredentialRoundTrip(prefix: string) {
  let key: string | null = flatSubject(prefix);
  try {
    await secureStore.setItem(key, "synthetic credential value");
    expect(await secureStore.getItem(key)).toBe("synthetic credential value");
    await secureStore.removeItem(key);
    expect(await secureStore.getItem(key)).toBeNull();
  } finally { key = null; }
}

it("completed public credential removals release caller-owned native slot-key data", async () => {
  if (typeof gc !== "function") throw new Error("SetupError: explicit Node --expose-gc provider required");
  storage.__reset(); keychain.__reset(); runTestControl(setSecureStoreBackend, null);
  const run = randomUUID(), prefixes = { positive: "native-retained-control-" + run, negative: "native-released-control-" + run, subject: "native-public-slot-" + run };
  witness = { node: process.version, prefixes, limits: ["Finite actual frozen Node22/V8 string lifetime only, no native hardware/storage/latency or unbounded-growth guarantee.", "Subjects are dynamically created caller key values admitted through actual exported secureStore operations; no private Map/fiber/source/variable name or count is inspected."] }; save();
  try {
    await collectorControls(prefixes, "before-public-producer");
    for (let index = 0; index < 8; index++) await publicCredentialRoundTrip(prefixes.subject);
    await turn(); await turn();
    if ((await storage.getAllKeys()).some(key => key.startsWith(prefixes.subject))) throw new Error("SetupError: actual public slot removals did not complete");
    await collectorControls(prefixes, "after-public-producer");
    await turn(); gc(); await turn();
    const after = census(prefixes); witness.afterPublicRemovals = after; save();
    expect(after.subject, "Actual native heap must release the caller's removed public slot-key data after completed credential operations").toBe(0);
  } finally { controls.clear(); save(); }
}, 120_000);
