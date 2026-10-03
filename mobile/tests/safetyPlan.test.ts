/**
 * The local safety plan (2026-09-27): encrypted round-trip under the data
 * key, the hostile/oversized-record discipline (a plan that cannot be
 * validated reads as ABSENT, never as a partial plan), the locked/wrong-key
 * fallback, deletion hygiene, and per-user slot isolation. Idiom:
 * tests/measures.test.tsx / the pendingMeasure discipline — REAL envelope
 * crypto, the in-memory AsyncStorage mock, no module mocks.
 */
import { beforeEach, describe, expect, it } from "vitest";
import { buildAad, encrypt } from "../src/crypto/envelope";
import {
  SAFETY_PLAN_FIELDS,
  clearSafetyPlan,
  emptySafetyPlan,
  loadSafetyPlan,
  saveSafetyPlan,
  type SafetyPlan,
} from "../src/safetyPlan";
const storage = (await import("./helpers/storageMock")).default;

const USER = "user-1";
const OTHER_USER = "user-2";
const dataKey = Buffer.alloc(32, 7);
const otherKey = Buffer.alloc(32, 11);

const aPlan = (): SafetyPlan => ({
  warningSigns: "Sleep slipping, skipping meals, canceling plans",
  copingStrategies: "Cold water, a walk around the block, the breathing count",
  peoplePlaces: "The library; my sister's kitchen",
  askForHelp: "Ana — 555-0142",
  professionals: "Dr. Okafor (Tue/Thu), the 988 line",
  environmentSafer: "Meds stay at a friend's; no cords in my room",
});

/** Seed the slot directly, the way a hostile or half-written record would
 *  look: any blob "encrypted" under the given key and AAD. */
async function seedSlot(userId: string, key: Buffer, plaintext: string, aadUser = userId): Promise<void> {
  const blob = encrypt(key, Buffer.from(plaintext, "utf8"), buildAad("safety-plan", aadUser));
  await storage.setItem(`@mindpattern/safety_plan_${userId}`, blob.toString("base64"));
}

beforeEach(() => {
  storage.__reset();
});

describe("safetyPlan: encrypted round-trip", () => {
  it("saves and loads the plan under the account's data key", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    const loaded = await loadSafetyPlan(dataKey, USER);
    expect(loaded).toEqual(aPlan());
  });

  it("an absent plan reads as null", async () => {
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();
  });

  it("the persisted slot is ciphertext — no field name or value ever hits storage", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    const raw = await storage.getItem(`@mindpattern/safety_plan_${USER}`);
    expect(raw).not.toBeNull();
    expect(raw!).not.toContain("warningSigns");
    expect(raw!).not.toContain("Ana");
    expect(raw!).not.toContain("988");
  });

  it("every field survives the round trip, in the fixed display order", async () => {
    const plan = aPlan();
    await saveSafetyPlan(dataKey, USER, plan);
    const loaded = await loadSafetyPlan(dataKey, USER);
    expect(Object.keys(loaded ?? {})).toEqual([...SAFETY_PLAN_FIELDS]);
    for (const field of SAFETY_PLAN_FIELDS) {
      expect(loaded![field]).toBe(plan[field]);
    }
  });

  it("the key is snapshotted at call time — zeroizing the caller's buffer afterwards cannot corrupt the saved plan", async () => {
    // The moodLog/pendingMeasure idiom: the vault may lock (zeroizing the
    // SHARED buffer) between the call and the serialized write; the save
    // must have taken its own copy.
    const volatileKey = Buffer.alloc(32, 7);
    await saveSafetyPlan(volatileKey, USER, aPlan());
    volatileKey.fill(0); // the vault.lock() shape
    expect(await loadSafetyPlan(dataKey, USER)).toEqual(aPlan());
  });
});

describe("safetyPlan: hostile and oversized records", () => {
  it("a legacy plan above the new write bound remains readable for repair", async () => {
    const hostile = JSON.stringify({ ...emptySafetyPlan(), copingStrategies: "x".repeat(4001) });
    await seedSlot(USER, dataKey, hostile);
    expect((await loadSafetyPlan(dataKey, USER))?.copingStrategies).toHaveLength(4001);
    await expect(saveSafetyPlan(dataKey, USER, { ...emptySafetyPlan(), copingStrategies: "x".repeat(4001) })).rejects.toThrow("4000");
    expect((await loadSafetyPlan(dataKey, USER))?.copingStrategies).toHaveLength(4001);
  });

  it("a field of exactly 4000 characters is accepted (the inclusive bound)", async () => {
    const maximal = JSON.stringify({ ...emptySafetyPlan(), copingStrategies: "x".repeat(4000) });
    await seedSlot(USER, dataKey, maximal);
    const loaded = await loadSafetyPlan(dataKey, USER);
    expect(loaded?.copingStrategies).toHaveLength(4000);
  });

  it("a non-object record, a wrong-typed field, a missing field, and garbage bytes all read as absent", async () => {
    await seedSlot(USER, dataKey, JSON.stringify(["not", "an", "object"]));
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();

    await seedSlot(USER, dataKey, JSON.stringify({ ...emptySafetyPlan(), askForHelp: 42 }));
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();

    const missing = emptySafetyPlan();
    delete (missing as Record<string, unknown>).professionals;
    await seedSlot(USER, dataKey, JSON.stringify(missing));
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();

    await seedSlot(USER, dataKey, "not json at all {{");
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();
  });

  it("extra unknown fields are ignored, never trusted into the plan", async () => {
    await seedSlot(USER, dataKey, JSON.stringify({ ...aPlan(), crisisAdvice: "take these pills" }));
    const loaded = await loadSafetyPlan(dataKey, USER);
    expect(loaded).toEqual(aPlan());
    expect(loaded && "crisisAdvice" in loaded).toBe(false);
  });
});

describe("safetyPlan: locked / wrong-key fallback", () => {
  it("a DIFFERENT key (account switch / rotation) reads as absent, never as a partial plan", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    expect(await loadSafetyPlan(otherKey, USER)).toBeNull();
  });

  it("a blob bound to a DIFFERENT user (cross-account AAD) reads as absent", async () => {
    await seedSlot(USER, dataKey, JSON.stringify(aPlan()), OTHER_USER);
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();
  });

  it("a tampered blob reads as absent (GCM authentication fails)", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    const slotKey = `@mindpattern/safety_plan_${USER}`;
    const raw = Buffer.from((await storage.getItem(slotKey))!, "base64");
    raw[5] = raw[5]! ^ 0xff; // flip one ciphertext byte
    await storage.setItem(slotKey, raw.toString("base64"));
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();
  });

  it("a zeroized (locked-vault) key buffer reads as absent and never throws", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    const lockedKey = Buffer.alloc(32); // all zeros — the vault.lock() aftermath
    expect(await loadSafetyPlan(lockedKey, USER)).toBeNull();
  });

  it("the empty plan shape is fully blanked", () => {
    expect(emptySafetyPlan()).toEqual({
      warningSigns: "",
      copingStrategies: "",
      peoplePlaces: "",
      askForHelp: "",
      professionals: "",
      environmentSafer: "",
    });
  });
});

describe("safetyPlan: deletion hygiene and per-user isolation", () => {
  it("clearSafetyPlan wipes the slot — the plan does not outlive its account", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    expect(await loadSafetyPlan(dataKey, USER)).toEqual(aPlan());
    await clearSafetyPlan(USER);
    expect(await storage.getItem(`@mindpattern/safety_plan_${USER}`)).toBeNull();
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();
  });

  it("plans live in per-user slots: another account's plan is untouched by this one", async () => {
    await saveSafetyPlan(dataKey, USER, aPlan());
    const otherPlan = { ...aPlan(), askForHelp: "Miguel — 555-0199" };
    await saveSafetyPlan(otherKey, OTHER_USER, otherPlan);

    expect(await loadSafetyPlan(dataKey, USER)).toEqual(aPlan());
    expect(await loadSafetyPlan(otherKey, OTHER_USER)).toEqual(otherPlan);

    await clearSafetyPlan(USER);
    expect(await loadSafetyPlan(dataKey, USER)).toBeNull();
    expect(await loadSafetyPlan(otherKey, OTHER_USER)).toEqual(otherPlan);
    expect(await storage.getItem(`@mindpattern/safety_plan_${OTHER_USER}`)).not.toBeNull();
  });
});
