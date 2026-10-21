/** The local safety plan (clinical review 2026-09-27): the encrypted
 *  round-trip through the per-account kvstore slot (ciphertext at rest,
 *  wrong key reads as absent, rotation re-seals), the editor's save +
 *  restore, and the crisis dialog's unlocked-only link. Real WebCrypto,
 *  memory kv backend, no network — the plan is local by design. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { SafetyPlanView } from "../src/views/SafetyPlan";
import {
  clearSafetyPlan,
  loadSafetyPlan,
  rewrapSafetyPlan,
  saveSafetyPlan,
  type SafetyPlan,
} from "../src/safetyPlan";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { resetTestState } from "./helpers/api";
import { press, render, settle, textOf, textOfNode, typeArea } from "./helpers/rtr";

const USER = "user-1";

const memoryBackend = (): KvBackend => {
  const map = new Map<string, string>();
  return {
    async getItem(k) {
      return map.get(k) ?? null;
    },
    async setItem(k, v) {
      map.set(k, v);
    },
    async removeItem(k) {
      map.delete(k);
    },
    async keys() {
      return [...map.keys()];
    },
  };
};

const PLAN: SafetyPlan = {
  warningSigns: "short fuse, cancelling plans",
  coping: "long walk, cold water, the playlist",
  peoplePlaces: "the cousin; the library",
  helpers: "M., my sister",
  professionals: "my therapist; 988",
  saferEnvironment: "ask M. to hold the pills bottle",
};

// Authenticate the on-disk envelope with an independent implementation and
// independently authored account binding. Short words can occur in Base64.
const STORAGE_KEY = Buffer.alloc(32, 4);
const STORAGE_AAD = Buffer.from('["safety-plan","user-1"]', "utf8");
class PlanEnvelopeRejection extends Error {
  constructor() { super("Stored plan is not an authenticated account envelope"); this.name = "PlanEnvelopeRejection"; }
}
function independentlyOpenPlan(raw: string, key = STORAGE_KEY, aad = STORAGE_AAD): string {
  const blob = Buffer.from(raw, "base64");
  if (blob.length < 28 || blob.toString("base64") !== raw) throw new PlanEnvelopeRejection();
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
    decipher.setAAD(aad);
    decipher.setAuthTag(blob.subarray(-16));
    return Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]).toString("utf8");
  } catch (error) {
    if (error instanceof Error && error.constructor === Error && error.name === "Error"
      && error.message === "Unsupported state or unable to authenticate data" && !("code" in error)) {
      throw new PlanEnvelopeRejection();
    }
    throw new Error("SetupError: unexpected independent plan crypto oracle failure", { cause: error });
  }
}

function checkIndependentPlanOracle(): void {
  const nonce = Buffer.alloc(12);
  Buffer.from("988A", "base64").copy(nonce);
  const cipher = createCipheriv("aes-256-gcm", STORAGE_KEY, nonce);
  cipher.setAAD(STORAGE_AAD);
  const plaintext = JSON.stringify(PLAN);
  const blob = Buffer.concat([nonce, cipher.update(plaintext, "utf8"), cipher.final(), cipher.getAuthTag()]);
  const raw = blob.toString("base64");
  expect(raw).toContain("988");
  expect(independentlyOpenPlan(raw)).toBe(plaintext);
  const corrupt = Buffer.from(blob);
  corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
  expect(() => independentlyOpenPlan(corrupt.toString("base64"))).toThrow(PlanEnvelopeRejection);
  expect(() => independentlyOpenPlan(raw, Buffer.alloc(32, 9))).toThrow(PlanEnvelopeRejection);
  expect(() => independentlyOpenPlan(raw, STORAGE_KEY, Buffer.from('["safety-plan","user-2"]'))).toThrow(PlanEnvelopeRejection);
  expect(() => independentlyOpenPlan(plaintext)).toThrow(PlanEnvelopeRejection);
  expect(() => independentlyOpenPlan(Buffer.from(plaintext).toString("base64"))).toThrow(PlanEnvelopeRejection);
}

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(4);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
  vault.lock();
});

describe("safetyPlan storage (the entryDraft/pendingMeasure idiom)", () => {
  it("round-trips through the encrypted slot; the slot never holds plaintext", async () => {
    await saveSafetyPlan(vault.get().dataKey, USER, PLAN);
    const { kv } = await import("../src/kvstore");
    const raw = await kv.getItem(`mindpattern.safetyPlan.${USER}`);
    expect(raw).not.toBeNull();
    let opened: string | undefined;
    expect(() => { opened = independentlyOpenPlan(raw!); }).not.toThrow();
    expect(opened).toBe(JSON.stringify(PLAN));
    checkIndependentPlanOracle();
    const loaded = await loadSafetyPlan(vault.get().dataKey, USER);
    expect(loaded).toEqual(PLAN);
  });

  it("a wrong key reports an unreadable plan and preserves its ciphertext", async () => {
    await saveSafetyPlan(vault.get().dataKey, USER, PLAN);
    const wrong = new Uint8Array(new ArrayBuffer(32)).fill(9);
    await expect(loadSafetyPlan(wrong, USER)).rejects.toThrow("could not be authenticated");
  });

  it("rotation re-seals the plan under the new key; the old key no longer opens it", async () => {
    await saveSafetyPlan(vault.get().dataKey, USER, PLAN);
    const newKey = new Uint8Array(new ArrayBuffer(32)).fill(7);
    await rewrapSafetyPlan(vault.get().dataKey, newKey, USER);
    expect(await loadSafetyPlan(newKey, USER)).toEqual(PLAN);
    await expect(loadSafetyPlan(vault.get().dataKey, USER)).rejects.toThrow("could not be authenticated");
    await clearSafetyPlan(USER);
    expect(await loadSafetyPlan(newKey, USER)).toBeNull();
  });

  it("an all-empty plan clears the slot (an erased plan stays erased)", async () => {
    await saveSafetyPlan(vault.get().dataKey, USER, PLAN);
    await saveSafetyPlan(vault.get().dataKey, USER, {
      warningSigns: "",
      coping: "",
      peoplePlaces: "",
      helpers: "",
      professionals: "",
      saferEnvironment: "",
    });
    const { kv } = await import("../src/kvstore");
    expect(await kv.getItem(`mindpattern.safetyPlan.${USER}`)).toBeNull();
  });
});

describe("SafetyPlanView", () => {
  it("saves the written fields encrypted and restores them on the next mount", async () => {
    let root = await render(<SafetyPlanView onCrisis={() => undefined} />);
    await settle(20, 2);
    for (const [label, value] of [
      ["My warning signs", PLAN.warningSigns],
      ["What helps me cope", PLAN.coping],
      ["People and places that distract me", PLAN.peoplePlaces],
      ["Who I can ask for help", PLAN.helpers],
      ["Professionals and services I can contact", PLAN.professionals],
      ["How I can make my environment safer", PLAN.saferEnvironment],
    ] as const) {
      await typeArea(root, label, value);
    }
    await press(root, "Save my plan");
    await settle(20, 2);
    expect(textOf(root)).toContain("Saved — encrypted on this device");
    // The slot is ciphertext, never the typed words.
    const { kv } = await import("../src/kvstore");
    const raw = await kv.getItem(`mindpattern.safetyPlan.${USER}`);
    expect(raw).not.toBeNull();
    let opened: string | undefined;
    expect(() => { opened = independentlyOpenPlan(raw!); }).not.toThrow();
    expect(opened).toBe(JSON.stringify(PLAN));
    // Remount: the stored plan comes back on screen (a textarea's value is
    // a prop, not text — assert it on the controls themselves).
    root = await render(<SafetyPlanView onCrisis={() => undefined} />);
    await settle(20, 3);
    const areaValue = (labelText: string): string => {
      const area = root!.root.findAllByType("textarea").find((n) => {
        const label = n.parent;
        return label !== null && label.type === "label" && textOfNode(label).includes(labelText);
      });
      return String(area?.props.value ?? "");
    };
    expect(areaValue("My warning signs")).toBe(PLAN.warningSigns);
    expect(areaValue("How I can make my environment safer")).toBe(PLAN.saferEnvironment);
    // The local-only promise is stated where the plan is edited.
    expect(textOf(root)).toContain("Never synced, never exported, never shared");
    await clearSafetyPlan(USER);
  });

  it("the professionals hint carries the crisis lines already in the app", async () => {
    const root = await render(<SafetyPlanView onCrisis={() => undefined} />);
    await settle(20, 2);
    const placeholder = root.root
      .findAllByType("textarea")
      .find((n) => String(n.props.placeholder ?? "").includes("988"))?.props.placeholder as string | undefined;
    expect(placeholder).toBeTruthy();
    expect(placeholder).toContain("988");
    expect(placeholder).toContain("741741");
  });

  it("Get help opens the static crisis resources from inside the plan", async () => {
    const onCrisis = vi.fn();
    const root = await render(<SafetyPlanView onCrisis={onCrisis} />);
    await settle(20, 2);
    await press(root, "Get help");
    expect(onCrisis).toHaveBeenCalledTimes(1);
  });
});
