/** MeasuresView load-path hardening (audit 2026-09-26): M-W1 — every
 *  terminal failure (500/429/409) must leave the screen honest with the
 *  history emptied, never a permanent "Loading…" wedge; LOW a — the walk's
 *  20-page cap gets the entries-walk terminal probe, so a hostile server
 *  feeding endless continuations surfaces a loud error instead of a
 *  silent stop; LOW (offline gap) — a completed questionnaire that fails
 *  to send persists data-key-encrypted and retries on the next mount
 *  under the SAME client_measure_id; LOW (values, not indexes) — answers
 *  store option VALUES and selection compares values. */
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createCipheriv, createDecipheriv } from "node:crypto";
import { MeasuresView } from "../src/views/Measures";
import { measurePayload, measureScore, optionSelected } from "../src/measures";
import { clearPendingMeasure, loadPendingMeasure, savePendingMeasure, type PendingMeasure } from "../src/pendingMeasure";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import {
  cadenceDue,
  parseCadence,
  readMeasureCadence,
  snoozeCadence,
  writeMeasureCadence,
  DEFAULT_CADENCE,
} from "../src/measureCadence";
import { localDateISO } from "../src/dates";
import { vault } from "../src/vault";
// BEGIN measures retired operation import
import { clearSession, setSession, sessionAbortSignal } from "../src/api/client";
// END measures retired operation import
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, textOfNode } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const USER = "user-1";

// Independently authenticate nonce(12)||ciphertext||tag(16); short Base64
// substrings have no plaintext meaning. Account/context bindings are literal.
class CiphertextOracleRejection extends Error {}
function independentlyOpenMeasureBlob(raw: string, key: Buffer, aad: Buffer): string {
  try {
    const blob = Buffer.from(raw, "base64");
    if (blob.length < 28 || blob.toString("base64") !== raw) throw new CiphertextOracleRejection("Invalid encrypted envelope");
    const decipher = createDecipheriv("aes-256-gcm", key, blob.subarray(0, 12));
    decipher.setAAD(aad);
    decipher.setAuthTag(blob.subarray(-16));
    return Buffer.concat([decipher.update(blob.subarray(12, -16)), decipher.final()]).toString("utf8");
  } catch (error) {
    if (error instanceof CiphertextOracleRejection) throw error;
    if (error instanceof Error && error.constructor === Error && error.name === "Error" && !("code" in error)
        && error.message === "Unsupported state or unable to authenticate data") {
      throw new CiphertextOracleRejection("Native AES-GCM authentication refused the envelope", { cause: error });
    }
    throw new Error("SetupError: unexpected native AES-GCM oracle failure", { cause: error });
  }
}

function checkIndependentMeasureOracle(literal: "phq2" | "phq9", key: Buffer, aad: Buffer, plaintext: string): void {
  const nonce = Buffer.alloc(12);
  Buffer.from(literal, "base64").copy(nonce);
  const seal = (text: string): Buffer => {
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    return Buffer.concat([nonce, cipher.update(text, "utf8"), cipher.final(), cipher.getAuthTag()]);
  };
  const blob = seal(plaintext); const raw = blob.toString("base64");
  expect(raw).toContain(literal);
  expect(independentlyOpenMeasureBlob(raw, key, aad)).toBe(plaintext);
  const corrupt = Buffer.from(blob);
  corrupt[corrupt.length - 1] = corrupt[corrupt.length - 1]! ^ 1;
  expect(() => independentlyOpenMeasureBlob(corrupt.toString("base64"), key, aad)).toThrow(CiphertextOracleRejection);
  expect(() => independentlyOpenMeasureBlob(raw, Buffer.alloc(32, 9), aad)).toThrow(CiphertextOracleRejection);
  expect(() => independentlyOpenMeasureBlob(raw, key, Buffer.from('["wrong-context","user-1"]'))).toThrow(CiphertextOracleRejection);
  expect(() => independentlyOpenMeasureBlob(raw, key, Buffer.from(aad.toString("utf8").replace("user-1", "user-2")))).toThrow(CiphertextOracleRejection);
  expect(() => independentlyOpenMeasureBlob(plaintext, key, aad)).toThrow(CiphertextOracleRejection);
  expect(() => independentlyOpenMeasureBlob(Buffer.from(plaintext).toString("base64"), key, aad)).toThrow(CiphertextOracleRejection);
  expect(() => independentlyOpenMeasureBlob(raw, Buffer.alloc(31, 4), aad)).toThrow(/^SetupError:/);
  const otherPlaintext = plaintext + " ";
  expect(independentlyOpenMeasureBlob(seal(otherPlaintext).toString("base64"), key, aad)).not.toBe(plaintext);
}

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

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(4);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("MeasuresView terminal failures (M-W1, audit 2026-09-26)", () => {
  it("a 500 surfaces an honest error and empties the history — never a permanent Loading wedge", async () => {
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse({ detail: "database on fire" }, { status: 500 });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 4);
    expect(textOf(root)).toContain("The server hit a problem — try again in a moment.");
    expect(textOf(root)).not.toContain("database on fire");
    // Unstuck: the loading state resolved to the honest empty history.
    expect(textOf(root)).not.toContain("Loading…");
    expect(textOf(root)).toContain("Nothing recorded yet.");
  });

  it("a 429 (throttled) and a 409 (collection changed mid-walk) also resolve honestly", async () => {
    for (const status of [429, 409]) {
      stubFetch((url) => {
        if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse({ detail: `slow down (${status})` }, { status });
        return jsonResponse({}, { status: 404 });
      });
      const root = await render(<MeasuresView onCrisis={() => undefined} />);
      await settle(60, 4);
      expect(textOf(root)).toContain(status === 429
        ? "Too many attempts — wait a moment, then try again."
        : "That conflicts with something the server already has.");
      expect(textOf(root)).not.toContain(`slow down (${status})`);
      expect(textOf(root)).not.toContain("Loading…");
    }
  });
});

describe("MeasuresView walk limit (LOW a, audit 2026-09-26)", () => {
  it("a hostile server with endless continuations hits the 21st-page probe and a loud error, not a silent stop", async () => {
    let pages = 0;
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        pages += 1;
        const offset = new URL(url, ORIGIN).searchParams.get("offset") ?? "0";
        // One (garbage-blob) row per page and a continuation that never
        // ends — exactly the lying-server shape the entries walk defends
        // against.
        return jsonResponse(
          [{ id: `r${pages}`, client_measure_id: `m-${pages}`, blob: "QUJD", measure_date: "2026-09-01", received_at: "r" }],
          { headers: { "X-Next-Offset": String(Number(offset) + 1), "X-Measures-Revision": "9" } },
        );
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 8);
    // 20 walk pages + the one terminal probe:
    expect(pages).toBe(21);
    expect(textOf(root)).toContain("safe limit");
    expect(textOf(root)).not.toContain("Loading…");
  });

  it("a clean single page never probes again (the probe runs only at the cap)", async () => {
    let pages = 0;
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        pages += 1;
        return jsonResponse([], { headers: { "X-Measures-Revision": "3" } });
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 4);
    expect(pages).toBe(1);
    expect(textOf(root)).toContain("Nothing recorded yet.");
    expect(textOf(root)).not.toContain("safe limit");
  });
});

/** Press the NTH button carrying a label — every measure item renders the
 *  same four option chips, so a plain label press would only ever hit
 *  item 1. */
const pressNth = async (root: Awaited<ReturnType<typeof render>>, label: string, n: number): Promise<void> => {
  const matches = root.root.findAllByType("button").filter((node) => textOfNode(node) === label);
  const target = matches[n];
  if (!target || typeof target.props.onClick !== "function") {
    throw new Error(`no clickable button ${n}-th labeled ${JSON.stringify(label)}`);
  }
  await act(async () => {
    target.props.onClick();
  });
};

describe("MeasuresView offline persistence (audit 2026-09-26 LOW: the offline gap)", () => {
  it("a completed measure that fails offline persists, then a remount retries it under the SAME client_measure_id and clears on success", async () => {
    const posted: { id: string; date: string }[] = [];
    // First mount: the network is DOWN (a throwing fetch surfaces as
    // ApiError status 0 — the offline shape).
    stubFetch(() => {
      throw new Error("network is down");
    });
    let root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "PHQ-2"); // the two-item instrument
    await pressNth(root, "Several days", 0); // item 1 → value 1
    await pressNth(root, "Nearly every day", 1); // item 2 → value 3
    await press(root, "Save measure");
    await settle(60, 4);
    // The honest offline note — not a dead-end error banner.
    expect(textOf(root)).toContain("saved on this device, encrypted");
    // The pending record is sealed under the data key, with the exact picks.
    const dataKey = vault.get().dataKey;
    const pending = await loadPendingMeasure(dataKey, USER);
    expect(pending).toMatchObject<Partial<PendingMeasure>>({ kind: "phq2", picks: [1, 3] });
    expect(pending!.clientMeasureId).toMatch(/^m-/);
    await act(async () => {
      root.unmount();
    });

    // Remount with the network back: the restore effect retries the SAME
    // record (same id — the server's idempotency key).
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        const body = JSON.parse(String(init.body)) as { client_measure_id: string; measure_date: string };
        posted.push({ id: body.client_measure_id, date: body.measure_date });
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 6);
    expect(posted).toHaveLength(1);
    expect(posted[0]!.id).toBe(pending!.clientMeasureId);
    // Success clears the record — the questionnaire cannot outlive its send.
    expect(await loadPendingMeasure(vault.get().dataKey, USER)).toBeNull();
    expect(textOf(root)).toContain("Saved — encrypted like everything else.");
  });

  it("pressing Save again after the offline note reuses the SAME id (the on-screen retry path)", async () => {
    const posted: string[] = [];
    let online = false;
    stubFetch((url, init) => {
      if (!online) throw new Error("down");
      if (url.endsWith("/measures") && init.method === "POST") {
        const body = JSON.parse(String(init.body)) as { client_measure_id: string };
        posted.push(body.client_measure_id);
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "PHQ-2");
    await pressNth(root, "Several days", 0);
    await pressNth(root, "More than half the days", 1);
    await press(root, "Save measure");
    await settle(60, 4);
    expect(textOf(root)).toContain("saved on this device, encrypted");
    // Connectivity returns; the same tap must NOT mint a second id — the
    // answers still on screen are the same questionnaire.
    online = true;
    await press(root, "Save measure");
    await settle(60, 5);
    expect(posted).toHaveLength(1);
    expect(await loadPendingMeasure(vault.get().dataKey, USER)).toBeNull();
  });

  it("a 409 on the retry (already landed, never acked) also clears the record", async () => {
    await savePendingMeasure(vault.get().dataKey, USER, { kind: "phq2", clientMeasureId: "m-phq2-retry", picks: [0, 0], date: "2026-09-26" });
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        return jsonResponse({ detail: "exists", code: "conflict" }, { status: 409 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(60, 6);
    // Re-audit 2026-09-27: a 409 means "already recorded" (the idempotent
    // retry of a send that landed) — it does NOT necessarily mean today,
    // so the copy no longer claims it.
    expect(textOf(root)).toContain("Already recorded.");
    expect(await loadPendingMeasure(vault.get().dataKey, USER)).toBeNull();
    await clearPendingMeasure(USER);
  });

  it("the persisted record is ciphertext in the slot, never plaintext picks", async () => {
    let attempted: { client_measure_id: string; measure_date: string } | null = null;
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        attempted = JSON.parse(String(init.body)) as { client_measure_id: string; measure_date: string };
      }
      throw new Error("down");
    });
    const { kv } = await import("../src/kvstore");
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "PHQ-2");
    await pressNth(root, "Several days", 0);
    await pressNth(root, "Nearly every day", 1);
    await press(root, "Save measure");
    await settle(60, 4);
    const keys = await kv.keys();
    const slotKey = keys.find((k) => k.startsWith("mindpattern.pendingMeasure."));
    expect(slotKey).toBeTruthy();
    const raw = await kv.getItem(slotKey!);
    expect(raw).not.toBeNull();
    expect(attempted).not.toBeNull();
    expect(attempted!.client_measure_id).toMatch(/^m-\d{4}-\d{2}-\d{2}-[A-Za-z0-9]{1,8}$/);
    expect(attempted!.measure_date).toBe(localDateISO());
    const expectedPlaintext = JSON.stringify({
      kind: "phq2", clientMeasureId: attempted!.client_measure_id,
      picks: [1, 3], date: attempted!.measure_date,
    });
    const key = Buffer.alloc(32, 4);
    const aad = Buffer.from('["pending-measure","user-1"]', "utf8");
    let opened: string | null = null;
    expect(() => { opened = independentlyOpenMeasureBlob(raw!, key, aad); }).not.toThrow();
    expect(opened).toBe(expectedPlaintext);
    checkIndependentMeasureOracle("phq2", key, aad, expectedPlaintext);
  });
});

/** independent audit 2026-09-27 (P1): vault.get()'s key buffers are
 *  SHARED, and a lock landing during the pre-send persist await zeroizes
 *  them — the questionnaire used to be encrypted under 32 zero bytes,
 *  POSTed, and the pending retry record destroyed. The snapshot + the
 *  post-await re-check close both halves. */
describe("MeasuresView zeroized-key race (audit 2026-09-27)", () => {
  it("a lock landing during the persist await sends NOTHING, keeps the pending record, and says so honestly", async () => {
    // A STABLE key reference: the record must stay readable under the key
    // the session actually held, proving the SNAPSHOT (not the zeroized
    // shared buffer) sealed it. (The assertion copy is NEVER handed to the
    // vault — vault.lock() zeroizes the buffer it was given.)
    const heldKey = new Uint8Array(new ArrayBuffer(32)).fill(4);
    const originalKey = new Uint8Array(new ArrayBuffer(32));
    originalKey.set(heldKey);
    vault.unlock({ authKey: heldKey, dataKey: heldKey }, USER);
    // The lock lands exactly at the persistence write — inside
    // savePendingMeasure's kv.setItem, after the snapshot was taken.
    const base = memoryBackend();
    const innerSet = base.setItem;
    base.setItem = async (k: string, v: string) => {
      if (k.startsWith("mindpattern.pendingMeasure.")) vault.lock();
      return innerSet(k, v);
    };
    setKvBackendForTests(base);
    const posted: string[] = [];
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        posted.push(String(init.body));
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "PHQ-2");
    await pressNth(root, "Several days", 0);
    await pressNth(root, "Nearly every day", 1);
    await press(root, "Save measure");
    await settle(60, 5);
    // Nothing was POSTed — and certainly not under an all-zero key.
    expect(posted).toEqual([]);
    // The honest locked message, not a dead end...
    expect(textOf(root)).toContain("session locked while saving");
    // ...and the pending record SURVIVES, readable under the ORIGINAL key
    // (it will retry after the next unlock, under the same id).
    const pending = await loadPendingMeasure(originalKey, USER);
    expect(pending).toMatchObject<Partial<PendingMeasure>>({ kind: "phq2", picks: [1, 3] });
    // BEGIN measures retired operation regression
    // The real native crypto result waits before delivery to the old view.
    await act(async () => { root.unmount(); });
    const escapes: boolean[] = [];
    const observations: Array<Record<string, unknown>> = [];
    for (const phase of ["save-encrypt", "restore-decrypt"] as const) {
      resetTestState();
      const ownerA = "measure-retired-owner-a", ownerB = "measure-replacement-owner-b";
      const keyA = new Uint8Array(new ArrayBuffer(32)).fill(31);
      const keyB = new Uint8Array(new ArrayBuffer(32)).fill(47);
      const vaultA = new Uint8Array(keyA);
      installSession(ownerA);
      vault.unlock({ authKey: new Uint8Array(keyA), dataKey: vaultA }, ownerA);
      const backend = memoryBackend(); setKvBackendForTests(backend);
      const preservedB = "replacement account retained opaque record";
      await backend.setItem(`mindpattern.pendingMeasure.${ownerB}`, preservedB);
      const record: PendingMeasure = { kind: "phq2", clientMeasureId: "m-retired-restoration", picks: [1, 3], date: "2026-10-05" };
      if (phase === "restore-decrypt") await savePendingMeasure(keyA, ownerA, record);
      const native = globalThis.crypto;
      let release!: () => void, entered = false, admitted = 0;
      const gate = new Promise<void>(resolve => { release = resolve; });
      const temporary: Uint8Array[] = [];
      const nativePromises: Promise<unknown>[] = [];
      const returnedPromises: Promise<unknown>[] = [];
      const remember = <T,>(promise: Promise<T>, list: Promise<unknown>[]): Promise<T> => {
        list.push(promise);
        void promise.catch(() => undefined); // The stable drain retains and rethrows the original fault.
        return promise;
      };
      const drainCrypto = async () => {
        release();
        let count = -1;
        let failure: PromiseRejectedResult | undefined;
        while (count !== nativePromises.length + returnedPromises.length) {
          count = nativePromises.length + returnedPromises.length;
          const results = await Promise.allSettled([...nativePromises, ...returnedPromises]);
          failure ??= results.find((result): result is PromiseRejectedResult => result.status === "rejected");
          await settle(2, 1); // Flush the public consumers that may begin another native operation.
        }
        if (failure) throw failure.reason;
      };
      const posted: Array<{ owner: string; body: { client_measure_id: string; blob: string } }> = [];
      const subtle = new Proxy(native.subtle, { get(target, property) {
        if (property === "encrypt") return (...args: Parameters<SubtleCrypto["encrypt"]>) => {
          const nativePromise = remember(target.encrypt(...args), nativePromises);
          return remember((async () => {
            const result = await nativePromise;
            const aad = (args[0] as AesGcmParams).additionalData;
            if (phase === "save-encrypt" && aad && new TextDecoder().decode(aad).startsWith(`["measure","${ownerA}",`)) {
              const input = args[2];
              temporary.push(input instanceof ArrayBuffer ? new Uint8Array(input) : new Uint8Array(input.buffer, input.byteOffset, input.byteLength));
              admitted++; entered = true; await gate;
            }
            return result;
          })(), returnedPromises);
        };
        if (property === "decrypt") return (...args: Parameters<SubtleCrypto["decrypt"]>) => {
          const nativePromise = remember(target.decrypt(...args), nativePromises);
          return remember((async () => {
            const result = await nativePromise;
            const aad = (args[0] as AesGcmParams).additionalData;
            if (phase === "restore-decrypt" && aad && new TextDecoder().decode(aad) === `["pending-measure","${ownerA}"]`) {
              temporary.push(new Uint8Array(result)); admitted++; entered = true; await gate;
            }
            return result;
          })(), returnedPromises);
        };
        const value = Reflect.get(target, property, target);
        if (typeof value !== "function") return value;
        return (...args: unknown[]) => {
          const result = value.apply(target, args);
          return result && typeof result.then === "function" ? remember(result, nativePromises) : result;
        };
      } });
      vi.stubGlobal("crypto", new Proxy(native, { get(target, property) {
        if (property === "subtle") return subtle;
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      } }));
      stubFetch((url, init) => {
        if (new URL(url).pathname.endsWith("/measures") && init.method === "POST") {
          posted.push({ owner: String((init.headers as Record<string, string>).Authorization), body: JSON.parse(String(init.body)) });
          return jsonResponse({ id: "accepted" }, { status: 201 });
        }
        return jsonResponse([], { headers: { "X-Measures-Revision": "1" } });
      });
      const retiredSignal = sessionAbortSignal()!;
      let retired: Awaited<ReturnType<typeof render>> | undefined;
      try {
        retired = await render(<MeasuresView onCrisis={() => undefined} />);
        if (phase === "save-encrypt") {
          await settle(20, 3); await press(retired, "PHQ-2");
          await pressNth(retired, "Several days", 0); await pressNth(retired, "Nearly every day", 1);
          await press(retired, "Save measure");
        }
        await vi.waitFor(() => expect(entered).toBe(true), { timeout: 2000 });
        expect(admitted).toBe(1);
        clearSession(); vault.lock();
        await act(async () => { retired!.unmount(); });
        setSession("replacement-measure-token", ownerB, "replacement-measure-user");
        vault.unlock({ authKey: new Uint8Array(keyB), dataKey: new Uint8Array(keyB) }, ownerB);
        expect(retiredSignal.aborted).toBe(true);
        expect(vaultA.every(byte => byte === 0)).toBe(true);
        await drainCrypto();
        expect(temporary).toHaveLength(1);
        expect(temporary[0]!.every(byte => byte === 0)).toBe(true);
        const retainedA = await backend.getItem(`mindpattern.pendingMeasure.${ownerA}`) !== null;
        const untouchedB = await backend.getItem(`mindpattern.pendingMeasure.${ownerB}`) === preservedB;
        let ciphertextOwner: string | null = null;
        if (posted.length > 0) {
          expect(posted).toHaveLength(1);
          expect(posted[0]!.owner).toBe("Bearer replacement-measure-token");
          const expectedOwner = phase === "save-encrypt" ? ownerA : ownerB;
          const expectedKey = phase === "save-encrypt" ? keyA : keyB;
          const opened = independentlyOpenMeasureBlob(posted[0]!.body.blob, Buffer.from(expectedKey), Buffer.from(buildAad("measure", expectedOwner, posted[0]!.body.client_measure_id)));
          expect(JSON.parse(opened)).toMatchObject({ measure: "phq2", score: 4 });
          ciphertextOwner = expectedOwner;
        }
        observations.push({ phase, admitted, postCount: posted.length, ciphertextOwner, retainedA, untouchedB, temporaryErased: true });
        escapes.push(posted.length > 0 || !retainedA || !untouchedB);
      } finally {
        try {
          await drainCrypto();
        } finally {
          vi.stubGlobal("crypto", native);
          if (retired) await act(async () => { retired!.unmount(); });
        }
      }
    }
    console.info("MEASURES_RETIRED_OPERATION_CUSTODY", JSON.stringify(observations));
    expect(escapes.some(Boolean), "retired questionnaire work cannot publish or acknowledge through the replacement session").toBe(false);
    // END measures retired operation regression
  });
});

describe("MeasuresView answer values (audit 2026-09-26 LOW: values, not indexes)", () => {
  it("a completed PHQ-2 posts an encrypted blob whose score is the sum of the picked VALUES", async () => {
    let posted: { id: string; blob: string } | null = null;
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        const body = JSON.parse(String(init.body)) as { client_measure_id: string; blob: string };
        posted = { id: body.client_measure_id, blob: body.blob };
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    await press(root, "PHQ-2");
    await pressNth(root, "Several days", 0); // item 1 → VALUE 1
    await pressNth(root, "Nearly every day", 1); // item 2 → VALUE 3
    await press(root, "Save measure");
    await settle(60, 5);
    expect(posted).not.toBeNull();
    const keys = vault.get();
    const plain = await decrypt(keys.dataKey, fromBase64(posted!.blob), buildAad("measure", USER, posted!.id));
    const payload = JSON.parse(new TextDecoder().decode(plain)) as { measure: string; score: number };
    expect(payload.measure).toBe("phq2");
    expect(payload.score).toBe(4); // 1 + 3 — values, not chip indexes
  });

  it("optionSelected is value-based: a hypothetical non-contiguous scale never reads an index as selected", () => {
    // A scale like [0, 2, 4]: answering with the SECOND chip records the
    // VALUE 2. Index semantics would store 1 — which must select nothing.
    const NONCONTIGUOUS = [0, 2, 4];
    const responses: (number | null)[] = [null, NONCONTIGUOUS[1]!];
    expect(optionSelected(responses, 1, NONCONTIGUOUS[1]!)).toBe(true);
    expect(optionSelected(responses, 1, NONCONTIGUOUS[0]!)).toBe(false);
    expect(optionSelected(responses, 1, 1)).toBe(false); // the INDEX is not a value
    expect(optionSelected(responses, 0, NONCONTIGUOUS[2]!)).toBe(false); // unanswered item
    // The scorer agrees on the same value semantics for a shipped instrument.
    expect(measureScore("phq9", [1, 1, 1, 1, 1, 1, 1, 1, 1])).toBe(9);
  });
});

/** The payload contract's item9 field (clinical review 2026-09-27): an
 *  endorsed PHQ-9 item 9 mandates clinical follow-up REGARDLESS of the
 *  total, so the RAW item-9 response rides the phq9 payload next to an
 *  unchanged score. gad7/phq2 never carry it; old payloads without it
 *  stay valid. */
describe("measure payload item9 (clinical review 2026-09-27)", () => {
  it("a phq9 payload carries the RAW item-9 response after score, before completed_at — the score is unchanged", () => {
    const payload = JSON.parse(measurePayload("phq9", [0, 0, 0, 0, 0, 0, 0, 0, 2], "2026-09-27T10:00:00Z")) as Record<string, unknown>;
    expect(payload).toEqual({ v: 1, measure: "phq9", score: 2, item9: 2, completed_at: "2026-09-27T10:00:00Z" });
    expect(Object.keys(payload)).toEqual(["v", "measure", "score", "item9", "completed_at"]);
    // The total is byte-identical to the pre-field contract.
    expect(payload.score).toBe(measureScore("phq9", [0, 0, 0, 0, 0, 0, 0, 0, 2]));
  });

  it("an unendorsed item 9 still carries the field, as the raw 0", () => {
    const payload = JSON.parse(measurePayload("phq9", [1, 1, 1, 1, 1, 1, 1, 1, 0], "2026-09-27T10:00:00Z")) as Record<string, unknown>;
    expect(payload.item9).toBe(0);
    expect(payload.score).toBe(8);
  });

  it("gad7 and phq2 NEVER carry item9 — the field names a phq9 question", () => {
    for (const id of ["gad7", "phq2"] as const) {
      const responses = new Array(id === "gad7" ? 7 : 2).fill(1) as number[];
      const payload = JSON.parse(measurePayload(id, responses, "2026-09-27T10:00:00Z")) as Record<string, unknown>;
      expect("item9" in payload).toBe(false);
    }
  });

  it("a completed PHQ-9 posts an encrypted blob whose item9 is the picked 9th answer", async () => {
    let posted: { id: string; blob: string } | null = null;
    stubFetch((url, init) => {
      if (url.endsWith("/measures") && init.method === "POST") {
        const body = JSON.parse(String(init.body)) as { client_measure_id: string; blob: string };
        posted = { id: body.client_measure_id, blob: body.blob };
        return jsonResponse({ id: "row" }, { status: 201 });
      }
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 3);
    // phq9 is the default instrument: eight "Not at all" answers and a
    // "Nearly every day" on the 9th (the safety item).
    for (let item = 0; item < 8; item += 1) await pressNth(root, "Not at all", item);
    await pressNth(root, "Nearly every day", 8);
    await press(root, "Save measure");
    await settle(60, 5);
    expect(posted).not.toBeNull();
    const keys = vault.get();
    const plain = await decrypt(keys.dataKey, fromBase64(posted!.blob), buildAad("measure", USER, posted!.id));
    const payload = JSON.parse(new TextDecoder().decode(plain)) as { measure: string; score: number; item9: number };
    expect(payload.measure).toBe("phq9");
    expect(payload.score).toBe(3); // only the endorsed item contributes
    expect(payload.item9).toBe(3); // the RAW response, not a boolean
  });
});

/** The opt-in check-in cadence (clinical review 2026-09-27): a gentle,
 *  non-shaming banner in the Measures view when the chosen interval has
 *  passed, computed locally from the decrypted history, snoozed for three
 *  days by "Not now". */
describe("check-in cadence banner (2026-09-27)", () => {
  it("cadenceDue is a fact, not a judgment: off never due; unknown history never due; no history yet is due", () => {
    expect(cadenceDue({ ...DEFAULT_CADENCE, enabled: false }, null)).toBe(false);
    expect(cadenceDue({ ...DEFAULT_CADENCE, enabled: true }, undefined)).toBe(false);
    expect(cadenceDue({ ...DEFAULT_CADENCE, enabled: true }, null)).toBe(true);
    expect(cadenceDue({ ...DEFAULT_CADENCE, enabled: true, intervalWeeks: 4 }, "2026-09-26", "2026-09-27")).toBe(false);
    expect(cadenceDue({ ...DEFAULT_CADENCE, enabled: true, intervalWeeks: 4 }, "2026-08-30", "2026-09-27")).toBe(true);
    // A snooze hides the banner until its date lapses.
    const snoozed = snoozeCadence({ ...DEFAULT_CADENCE, enabled: true }, "2026-09-27");
    expect(snoozed.snoozedUntil).toBe("2026-09-30");
    expect(cadenceDue(snoozed, null, "2026-09-28")).toBe(false);
    expect(cadenceDue(snoozed, null, "2026-09-30")).toBe(true);
  });

  it("a hostile or half-written preference reads as the honest OFF default", () => {
    expect(parseCadence(null)).toEqual(DEFAULT_CADENCE);
    expect(parseCadence("not json")).toEqual(DEFAULT_CADENCE);
    expect(parseCadence(JSON.stringify({ enabled: true, intervalWeeks: 3, snoozedUntil: "tomorrow" })))
      .toEqual({ enabled: true, intervalWeeks: 4, snoozedUntil: null });
  });

  it("renders when due (no completed check-in yet, opted in) and 'Not now' hides it for three days — persisted in the slot", async () => {
    await writeMeasureCadence(USER, { enabled: true, intervalWeeks: 4, snoozedUntil: null });
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    let root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("A check-in is available");
    expect(textOf(root)).toContain("skipping it is always fine"); // non-shaming, no streak language
    await press(root, "Not now");
    await settle(20, 2);
    expect(textOf(root)).not.toContain("A check-in is available");
    const pref = await readMeasureCadence(USER);
    expect(pref.enabled).toBe(true);
    expect(pref.snoozedUntil).toBe(localDateISO(new Date(Date.now() + 3 * 86_400_000)));
    // The snooze survives a remount (the banner is not a nag in disguise).
    root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).not.toContain("A check-in is available");
    await act(async () => {
      root.unmount();
    });
  });

  it("a completed measure INSIDE the interval suppresses the banner", async () => {
    await writeMeasureCadence(USER, { enabled: true, intervalWeeks: 2, snoozedUntil: null });
    const recent = localDateISO(new Date(Date.now() - 5 * 86_400_000));
    const blob = toBase64(
      await encrypt(vault.get().dataKey, new TextEncoder().encode(measurePayload("phq9", [0, 0, 0, 0, 0, 0, 0, 0, 0], `${recent}T10:00:00Z`)), buildAad("measure", USER, "m-recent")),
    );
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) {
        return jsonResponse([{ id: "r1", client_measure_id: "m-recent", blob, measure_date: recent, received_at: "r" }], { headers: { "X-Measures-Revision": "3" } });
      }
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).not.toContain("A check-in is available");
  });

  it("off by default: no banner without the opt-in, even with nothing recorded", async () => {
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).not.toContain("A check-in is available");
  });
});
