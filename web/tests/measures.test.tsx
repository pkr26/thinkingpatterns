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
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, render, settle, textOf, textOfNode } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
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
    expect(textOf(root)).toContain("database on fire");
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
      expect(textOf(root)).toContain(`slow down (${status})`);
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
    stubFetch(() => {
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
    expect(raw!).not.toContain("phq2");
    expect(raw!).not.toMatch(/clientMeasureId/);
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
