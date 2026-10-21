/** Node-only retained-resource oracle after actual public UI producers.
 * Requires --expose-gc. It observes weak host Promise allocations inside
 * synchronous public storage calls, never the private production Map. */
import "./frontendMemoOwnerWitness.test";
import { createHook } from "node:async_hooks";
import fs from "node:fs";
import { beforeAll, afterAll, expect, it } from "vitest";
import { secureStore } from "../src/secureStore";

type Allocation = { operation: string; key: string; weak: WeakRef<object> };
const allocations: Allocation[] = [];
const controls = new Map<string, object>();
const gc = (globalThis as typeof globalThis & { gc?: () => void }).gc;
const receiptFile = process.env.SETTLED_SLOT_RETENTION_RECEIPT_FILE;
let current: { operation: string; key: string } | null = null;
let observation: Record<string, unknown> = {};
const originalSet = secureStore.setItem, originalRemove = secureStore.removeItem;
const hook = createHook({
  init(_id, type, _trigger, resource) {
    if (current && type === "PROMISE" && resource && typeof resource === "object") {
      allocations.push({ ...current, weak: new WeakRef(resource) });
    }
  },
});
function save() {
  if (receiptFile) fs.writeFileSync(receiptFile, JSON.stringify(observation, null, 2) + "\n");
}
const turn = () => new Promise<void>(resolve => setImmediate(resolve));
function unownedPromise() { return new WeakRef(Promise.resolve()); }
async function collect() {
  await turn(); gc!(); await turn();
}
async function validateCollector(stage: string) {
  if (typeof gc !== "function") throw new Error("SetupError: RetentionWitnessSetupFault: real Node --expose-gc capability is unavailable");
  const kept = Promise.resolve(); controls.set(stage, kept);
  const positive = new WeakRef(kept), negative = unownedPromise();
  for (let attempt = 0; attempt < 20; attempt++) {
    await collect();
    if (negative.deref() === undefined && positive.deref() === controls.get(stage)) {
      const checks = observation.collectorControls as unknown[] | undefined;
      observation.collectorControls = [...(checks ?? []), { stage, attempts: attempt + 1, positiveRetained: true, negativeCollected: true }];
      controls.delete(stage); return;
    }
  }
  controls.delete(stage); save();
  throw new Error("SetupError: RetentionWitnessSetupFault: positive/negative host Promise collector controls did not complete");
}
function stop() {
  hook.disable(); secureStore.setItem = originalSet; secureStore.removeItem = originalRemove;
}
beforeAll(async () => {
  observation = { evidenceClass: "Node host Promise retention after real public UI/rotation producers", stage: "collector-setup", nodeVersion: process.version, gcCapability: typeof gc === "function", limits: ["No private Map inspection or source-text equality.", "Injected native/HTTP transports; no Android/iOS heap or hardware OOM claim.", "Collector controls and complete public producer witnesses are mandatory before retention assertions."] };
  await validateCollector("before-public-producer");
  hook.enable();
  secureStore.setItem = (key, value) => {
    current = { operation: "setItem", key };
    try { return originalSet(key, value); } finally { current = null; }
  };
  secureStore.removeItem = key => {
    current = { operation: "removeItem", key };
    try { return originalRemove(key); } finally { current = null; }
  };
});
afterAll(() => { stop(); controls.clear(); save(); });

it("releases fulfilled public slot-write Promise allocations after the real UI rotation and erasure flow", async () => {
  stop(); observation.stage = "public-producer-validation";
  const publicFile = process.env.MEMO_OWNER_RECEIPT_FILE;
  if (!publicFile || !fs.existsSync(publicFile)) throw new Error("SetupError: RetentionWitnessSetupFault: public producer receipt is missing");
  const publicReceipt = JSON.parse(fs.readFileSync(publicFile, "utf8"));
  if (publicReceipt.result !== "PristinePublicWitnessPassed" || publicReceipt.events.some((event: any) => event.name.startsWith("producer-barrier-"))) {
    throw new Error("SetupError: RetentionWitnessSetupFault: required public UI/rotation/erasure witness did not complete");
  }
  const chunkKeys = [...new Set(allocations.filter(value => value.key.includes(".chunk.")).map(value => value.key))];
  if (chunkKeys.length < 29 || allocations.length < 100) throw new Error("SetupError: RetentionWitnessSetupFault: bounded real rotation chunk allocation producer was not observed");
  observation.publicProducer = { complete: true, uniqueGeneratedChunkKeys: chunkKeys.length, boundedTypedEntries: 7, charactersPerTypedEntry: 99000, voiceEntries: 1, registeredReplacement: true, verifiedReplacementUnlock: true };
  observation.capturedPromiseAllocations = allocations.length;
  await validateCollector("after-public-producer");
  // Every dereference occurs after a fresh host turn/GC. Positive and
  // negative controls above prove both live retention and actual collection.
  // Existing live app promises created outside the public storage factory
  // are outside this oracle; returned storage operations have all settled.
  for (let attempt = 0; attempt < 20; attempt++) {
    await collect();
    if (allocations.every(value => value.weak.deref() === undefined)) break;
  }
  const retained = allocations.filter(value => value.weak.deref() !== undefined);
  observation.stage = "behavior-resource-assertion";
  observation.retainedPromiseCount = retained.length;
  observation.retainedSlots = retained.map(value => ({ operation: value.operation, key: value.key }));
  save();
  expect(retained.length).toBe(0);
  observation.stage = "passed"; save();
}, 15000);
