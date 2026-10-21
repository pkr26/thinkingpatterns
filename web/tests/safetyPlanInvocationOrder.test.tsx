/** Public-view/storage ordering regression.
 * A finite host timer releases the exact installed backend read on BOTH source
 * versions. It supplies no timing/timeout oracle. Final durable/restored text
 * is the behavior oracle. A real original failure is NOT promised in advance.
 * Scope: RTR SafetyPlanView + exported navigation-seal contract, declared Map
 * storage, original native WebCrypto; no actual App Login/physical IDB claim.
 */


import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import * as safety from "../src/safetyPlan";
import * as cryptoCore from "../src/crypto/core";
import { kv, newWriteGeneration, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { SafetyPlanView } from "../src/views/SafetyPlan";
import { applyLanguagePref } from "../src/strings";
import { vault } from "../src/vault";
import { installSession, resetTestState } from "./helpers/api";
import { buttonByLabel, press, render, textOf, typeArea } from "./helpers/rtr";

const OWNER = "0123456789abcdef0123456789abcdef";

const GENERATION = writeGenerationKey(OWNER);
const RELEASE_MS = 250; // Finite authored setup control, never an assertion.
let key: Uint8Array<ArrayBuffer>, records: Map<string, string>, root: ReactTestRenderer | undefined;
let originals: Promise<unknown>[], faults: unknown[], restores: (() => void)[];
let armed: boolean, held: boolean, release: () => void;
let retired: boolean;
let timer: ReturnType<typeof setTimeout> | undefined;

const setup = (message: string, cause?: unknown): Error => new Error(`SetupError: safety-plan order producer: ${message}`, { cause });


function own<T>(promise: Promise<T>): Promise<T> {
  originals.push(promise);
  void promise.then(() => {  }, cause => { faults.push(cause);  });
  return promise; // EXACT originally returned Promise, no async wrapper.
}
async function drain(): Promise<void> {
  let count = -1;
  while (count !== originals.length) {
    count = originals.length;
    const settled = await Promise.allSettled(originals);
    const failure = settled.find(result => result.status === "rejected");
    if (failure?.status === "rejected") throw setup("owned original producer rejected", failure.reason);
  }
  if (faults.length) throw setup("unknown native/provider rejection", faults[0]);
}
async function until(label: string, ready: () => boolean): Promise<void> {
  const deadline = Date.now() + 15000;
  while (!ready()) {
    if (Date.now() >= deadline) throw setup(label + " was not admitted before fixture deadline");
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
}
async function retire(): Promise<void> {
  if (retired) return;
  retired = true;
  const cleanupFaults: unknown[] = [];
  if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
  try { release(); } catch (cause) { cleanupFaults.push(cause); }
  try { await drain(); } catch (cause) { cleanupFaults.push(cause); }
  if (root) {
    const current = root; root = undefined;
    try { await act(async () => { current.unmount(); }); } catch (cause) { cleanupFaults.push(cause); }
  }
  for (const restore of restores.splice(0).reverse()) {
    try { restore(); } catch (cause) { cleanupFaults.push(cause); }
  }
  try { resetTestState(); } catch (cause) { cleanupFaults.push(cause); }
  try { key.fill(0); } catch (cause) { cleanupFaults.push(cause); }
  try { vi.restoreAllMocks(); } catch (cause) { cleanupFaults.push(cause); }
  try { vi.unstubAllGlobals(); } catch (cause) { cleanupFaults.push(cause); }
  if (cleanupFaults.length) throw setup("owned producer/cleanup failed during retirement", cleanupFaults[0]);
}

beforeEach(async () => {
  resetTestState(); vi.useRealTimers(); applyLanguagePref("en"); installSession(OWNER);
  key = new Uint8Array(new ArrayBuffer(32)).fill(19);
  vault.unlock({ dataKey: key, authKey: new Uint8Array(32).fill(20) }, OWNER);
  records = new Map(); originals = []; faults = []; restores = [];
  armed = false; held = false; retired = false; release = () => undefined; timer = undefined; root = undefined;
  // This is the original declared storage producer implementation, installed
  // once. Its getItem returns its OWN original native Promise unchanged.
  setKvBackendForTests({
    getItem(slot) {
      const value = records.get(slot) ?? null;
      const original = new Promise<string | null>(resolve => {
        if (armed && !held && slot === GENERATION) {
          held = true;
          let released = false;
          release = () => { if (!released) { released = true;  resolve(value); } };
        } else resolve(value);
      });
      return own(original);
    },
    setItem(slot, value) {
      const original = new Promise<void>(resolve => {
        records.set(slot, value);

        resolve();
      });
      return own(original);
    },
    removeItem(slot) {
      const original = new Promise<void>(resolve => { records.delete(slot);  resolve(); });
      return own(original);
    },
    keys() { return own(Promise.resolve([...records.keys()])); },
  });
  const subtle = globalThis.crypto.subtle;
  for (const name of ["importKey", "deriveBits", "encrypt", "decrypt"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(subtle, name), original = subtle[name];
    Object.defineProperty(subtle, name, { configurable: true, writable: true, value: (...args: unknown[]) => {
      try { return own(Reflect.apply(original, subtle, args) as Promise<unknown>); }
      catch (cause) { throw setup(`native ${name} threw before returning`, cause); }
    } });
    restores.push(() => { if (descriptor) Object.defineProperty(subtle, name, descriptor); else Reflect.deleteProperty(subtle, name); });
  }
  const nativeCrypto = globalThis.crypto;
  const randomDescriptor = Object.getOwnPropertyDescriptor(nativeCrypto, "getRandomValues");
  const nativeRandom = nativeCrypto.getRandomValues;
  Object.defineProperty(nativeCrypto, "getRandomValues", { configurable: true, writable: true, value: (...args: unknown[]) => {
    try { return Reflect.apply(nativeRandom, nativeCrypto, args); }
    catch (cause) { faults.push(cause); throw setup("native getRandomValues threw", cause); }
  } });
  restores.push(() => { if (randomDescriptor) Object.defineProperty(nativeCrypto, "getRandomValues", randomDescriptor); else Reflect.deleteProperty(nativeCrypto, "getRandomValues"); });
  const save = safety.saveSafetyPlan, preserve = safety.preserveSafetyPlan;
  vi.spyOn(safety, "saveSafetyPlan").mockImplementation((...args) => {
    const original = save(...args);
    return own(original); // EXACT original exported save Promise.
  });
  vi.spyOn(safety, "preserveSafetyPlan").mockImplementation(() => own(preserve()));
  // Same real key-bound generation on both source versions, not a fabricated
  // permit or decrypted object. No rotation/deletion is scheduled here.
  await kv.setItem(GENERATION, await newWriteGeneration(OWNER, key));
});
afterEach(async () => { await retire(); });

it.each(["healthy-sequential-control", "newer-navigation-text", "intentional-erase-navigation"] as const)(
  "a public safety-plan save cannot overwrite its later navigation seal: %s", async scenario => {
    try {
      root = await render(<SafetyPlanView onCrisis={() => undefined} />);
      await until("actual hydration", () => !!root && !buttonByLabel(root, "Retry restoring saved plan"));
      await typeArea(root, "My warning signs", "Earlier save A");
      armed = scenario !== "healthy-sequential-control";
      await press(root, "Save my plan");
      if (armed) await until("original A backend generation read", () => held);
      else await until("healthy save A public completion", () => !!root && textOf(root).includes("Saved — encrypted"));
      const later = scenario === "intentional-erase-navigation" ? "" : "Later navigation B";
      await typeArea(root, "My warning signs", later);

      const preserved = safety.preserveSafetyPlan(); // Same exported call App uses before unmount.
      // Release is source-independent and unconditional. B is NEVER awaited
      // while A is held; the correct queue therefore cannot fixture-deadlock.
      timer = setTimeout(() => {  release(); }, RELEASE_MS);
      const mounted = root; root = undefined;
      await act(async () => { mounted.unmount(); });
      await preserved;
      await drain();
      const durable = await safety.loadSafetyPlan(key, OWNER);
      await drain();
      // Sole behavior oracles: durable result and actually restored text.
      if (scenario === "intentional-erase-navigation") expect(durable).toBeNull();
      else expect(durable).toEqual({ ...safety.EMPTY_SAFETY_PLAN, warningSigns: later });
      root = await render(<SafetyPlanView onCrisis={() => undefined} />);
      await until("actual restored editor", () => !!root && !buttonByLabel(root, "Retry restoring saved plan"));
      const restored = root;
      expect(restored.root.findAllByType("textarea")[0]!.props.value).toBe(later);
      // Keep the latest pending per-owner queue tail when an earlier save
      // settles. A/B/C are direct original exported saves with real crypto;
      // no test reads or changes the module's private queue Map.
      if (scenario === "healthy-sequential-control") {
        await drain();
        if (timer !== undefined) { clearTimeout(timer); timer = undefined; }
        const slot = `mindpattern.safetyPlan.${OWNER}`;
        const firstPlan = { ...safety.EMPTY_SAFETY_PLAN, warningSigns: "Earlier safety-plan A" };
        const secondPlan = { ...safety.EMPTY_SAFETY_PLAN, warningSigns: "Pending safety-plan B" };
        const latestPlan = { ...safety.EMPTY_SAFETY_PLAN, warningSigns: "Newest safety-plan C" };
        let openA!: () => void, openB!: () => void;
        const gateA = new Promise<void>(resolve => { openA = resolve; }), gateB = new Promise<void>(resolve => { openB = resolve; });
        let arrivedA = false, arrivedB = false, writes = 0, generationReads = 0;
        let heldBOriginal: Promise<void> | undefined;
        const captures: Array<ReturnType<typeof kv.captureWritePermit>> = [];
        const encryptOriginals: Array<ReturnType<typeof cryptoCore.encrypt>> = [];
        release = () => { openA(); openB(); };
        setKvBackendForTests({
          getItem(name) {
            if (name === GENERATION) generationReads += 1;
            return own(Promise.resolve(records.get(name) ?? null));
          },
          setItem(name, value) {
            // The backend owns these original declared Map-storage Promises.
            // Capture each input before waiting; release changes no ciphertext.
            const ordinal = name === slot ? ++writes : 0;
            const original = (async () => {
              if (ordinal === 1) { arrivedA = true; await gateA; }
              else if (ordinal === 2) { arrivedB = true; await gateB; }
              records.set(name, value);
            })();
            if (ordinal === 2) heldBOriginal = original;
            return own(original);
          },
          removeItem(name) { return own((async () => { records.delete(name); })()); },
          keys() { return own(Promise.resolve([...records.keys()])); },
        });
        const originalCapture = kv.captureWritePermit;
        const captureObserver = vi.spyOn(kv, "captureWritePermit").mockImplementation((...args) => {
          const original = originalCapture(...args); captures.push(original); return own(original);
        });
        restores.push(() => captureObserver.mockRestore());
        const originalEncrypt = cryptoCore.encrypt;
        const encryptObserver = vi.spyOn(cryptoCore, "encrypt").mockImplementation((...args) => {
          const original = originalEncrypt(...args); encryptOriginals.push(original); return own(original);
        });
        restores.push(() => encryptObserver.mockRestore());
        const first = safety.saveSafetyPlan(key, OWNER, firstPlan);
        await until("original public A native ciphertext held at its Map commit", () => arrivedA);
        const second = safety.saveSafetyPlan(key, OWNER, secondPlan);
        // Enqueue B synchronously before A is permitted to finish. Awaiting
        // this identical original save proves A's complete public settlement.
        openA(); await first;
        await until("original public B native ciphertext held at its Map commit", () => arrivedB);
        const third = safety.saveSafetyPlan(key, OWNER, latestPlan);
        // This actual C capture storage read follows its genuine native
        // key-tag derivation. An independently admitted serialized C operation
        // has registered its permit await before this endpoint; it is neither
        // a fixed-turn nor a pending-state/duration result oracle.
        await until("original public C native key-tag generation read", () => generationReads === 3);
        if (captures.length !== 3 || !heldBOriginal) throw setup("original C capture or actual held B backend producer missing");
        await captures[2]!;
        // If C was admitted, its same-original exported encrypt Promise was
        // created before this capture observer resumes and owns every native
        // AES import/encrypt continuation. Drain all expanding original work
        // except exactly B's held backend Promise and the public B/C saves.
        // The baseline C remains queued behind B and creates no encrypt yet.
        for (;;) {
          const census = [...originals];
          const independent = census.filter(value => value !== heldBOriginal && value !== second && value !== third);
          const settled = await Promise.allSettled(independent);
          const rejected = settled.find(value => value.status === "rejected");
          if (rejected?.status === "rejected") throw setup("independent original native/storage producer rejected", rejected.reason);
          if (census.length === originals.length) break;
        }
        if (faults.length) throw setup("unknown independent native/provider rejection", faults[0]);
        openB();
        await Promise.all([second, third]); await drain();
        const newestDurable = await safety.loadSafetyPlan(key, OWNER); await drain();
        expect(newestDurable, "A completed earlier save cannot detach pending B and let it overwrite the later public C save").toEqual(latestPlan);
        expect(writes).toBe(3);
        expect(encryptOriginals).toHaveLength(3);
        expect([...key]).toEqual(Array(32).fill(19));
      }

    } finally {
      // Also releases/drains on expected ORIGINAL assertion failures and any
      // early unknown fault; unknown rejection becomes SetupError quarantine.
      await retire();


    }
  },
);
