import { expect, it, vi } from "vitest";

async function freshGuardWithStorage(records: Map<string, string>) {
  vi.resetModules();
  const { kv, setKvBackendForTests } = await import("../src/kvstore");
  const { checkAnalysisGeneration } = await import("../src/stateSeqGuard");
  setKvBackendForTests({
    getItem: async key => records.get(key) ?? null,
    setItem: async (key, value) => { records.set(key, value); },
    removeItem: async key => { records.delete(key); },
    keys: async () => [...records.keys()],
  });
  return { kv, checkAnalysisGeneration, close: () => setKvBackendForTests(null) };
}

it("retains an observed durable generation when its stored copy disappears", async () => {
  const owner = "previously-stored-generation-owner";
  const slot = `mindpattern.stateSeq.${owner}`;
  const guard = await freshGuardWithStorage(new Map([[slot, "9"]]));
  try {
    await guard.checkAnalysisGeneration(owner, 9, 9);
    await guard.kv.removeItem(slot);
    // Removing the durable copy cannot authorize an older authenticated
    // response during the same process lifetime.
    await expect(guard.checkAnalysisGeneration(owner, 8, 8)).rejects.toThrow();
  } finally {
    guard.close();
  }
});

it("retains a newly accepted generation when its stored copy disappears", async () => {
  const owner = "newly-accepted-generation-owner";
  const slot = `mindpattern.stateSeq.${owner}`;
  const guard = await freshGuardWithStorage(new Map());
  try {
    await guard.checkAnalysisGeneration(owner, 9, 9);
    expect(await guard.kv.getItem(slot)).toBe("9");
    await guard.kv.removeItem(slot);
    await expect(guard.checkAnalysisGeneration(owner, 8, 8)).rejects.toThrow();
  } finally {
    guard.close();
  }
});
