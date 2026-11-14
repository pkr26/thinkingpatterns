import { setImmediate as nextTurn } from "node:timers";
import { expect, it, vi } from "vitest";
import type { SafetyPlan } from "../src/safetyPlan";

const turn = (): Promise<void> => new Promise(resolve => nextTurn(resolve));

it("releases completed account queue ownership while overlapping saves and clears remain ordered", async () => {
  vi.resetModules();
  const NativeMap = Map;
  const observed = new Set<Map<unknown, unknown>>();
  // Observe resource custody in maps allocated while loading the real
  // producer. The assertion uses retained owner values after public work,
  // without inspecting a private variable or prescribing cleanup calls.
  const Observer = new Proxy(NativeMap, {
    construct(target, argumentsList) {
      const value = Reflect.construct(target, argumentsList) as Map<unknown, unknown>;
      observed.add(value);
      return value;
    },
  });
  let plan: typeof import("../src/safetyPlan");
  vi.stubGlobal("Map", Observer);
  try { plan = await import("../src/safetyPlan"); }
  finally { vi.stubGlobal("Map", NativeMap); }
  const { setKvBackendForTests, StorageCommitError } = await import("../src/kvstore");
  const { vault } = await import("../src/vault");
  const owner = "settled-safety-plan-queue-owner";
  const slot = `mindpattern.safetyPlan.${owner}`;
  const records = new NativeMap<string, string>();
  const key = new Uint8Array(32).fill(91);
  const first: SafetyPlan = { warningSigns: "earlier writing", coping: "", peoplePlaces: "", helpers: "", professionals: "", saferEnvironment: "" };
  const latest = { ...first, warningSigns: "latest writing after a clear" };
  let admit!: () => void, release!: () => void;
  const admitted = new Promise<void>(resolve => { admit = resolve; });
  const gate = new Promise<void>(resolve => { release = resolve; });
  let holdFirst = true, refuseNext = false;
  const owned: Promise<unknown>[] = [];
  setKvBackendForTests({
    getItem: async name => records.get(name) ?? null,
    async setItem(name, value) {
      if (name === slot && holdFirst) { holdFirst = false; admit(); await gate; }
      if (name === slot && refuseNext) { refuseNext = false; throw new Error("quota refused synthetic writing"); }
      records.set(name, value);
    },
    removeItem: async name => { records.delete(name); },
    keys: async () => [...records.keys()],
  });
  vault.unlock({ dataKey: key, authKey: new Uint8Array(32).fill(92) }, owner);
  try {
    const saving = plan.saveSafetyPlan(key, owner, first); owned.push(saving);
    // A public save failure is a behavioral failure. Propagate it directly
    // instead of waiting forever for a backend admission it cannot reach.
    await Promise.race([admitted, saving]);
    expect([...observed].some(resource => resource.has(owner))).toBe(true);
    const clearing = plan.clearSafetyPlan(owner); owned.push(clearing);
    const replacing = plan.saveSafetyPlan(key, owner, latest); owned.push(replacing);
    await turn(); await turn();
    expect(records.has(slot)).toBe(false);
    release();
    await Promise.all([saving, clearing, replacing]);
    expect(await plan.loadSafetyPlan(key, owner)).toEqual(latest);

    refuseNext = true;
    const refused = plan.saveSafetyPlan(key, owner, first); owned.push(refused);
    await expect(refused).rejects.toBeInstanceOf(StorageCommitError);
    expect(await plan.loadSafetyPlan(key, owner)).toEqual(latest);
    const recovered = plan.saveSafetyPlan(key, owner, first); owned.push(recovered);
    await recovered;
    expect(await plan.loadSafetyPlan(key, owner)).toEqual(first);
    const erased = plan.clearSafetyPlan(owner); owned.push(erased);
    await erased;
    expect(await plan.loadSafetyPlan(key, owner)).toBeNull();
    await turn(); await turn();
    // Queue ownership is temporary account metadata. Settled work must
    // release its owner identifiers, including after refusal and recovery.
    expect([...observed].filter(resource => resource.has(owner))).toEqual([]);
  } finally {
    release();
    await Promise.allSettled(owned);
    vault.lock(); setKvBackendForTests(null); vi.unstubAllGlobals(); vi.resetModules();
  }
}, 10_000);
