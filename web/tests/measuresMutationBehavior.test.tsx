import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MeasuresView } from "../src/views/Measures";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { loadPendingMeasure, savePendingMeasure } from "../src/pendingMeasure";
import { readMeasureCadence, writeMeasureCadence } from "../src/measureCadence";
import { __setLocaleForTests, t } from "../src/strings";
import { vault } from "../src/vault";
import { installSession, jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { publicSurface } from "./helpers/publicSurface";
import { press, render, settle, textOf, textOfNode } from "./helpers/rtr";

const OWNER = "measures-consumer";
const key = () => new Uint8Array(new ArrayBuffer(32)).fill(21);
async function row(id: string, payload: unknown, date: string): Promise<Record<string, string>> {
  const blob = await encrypt(key(), new TextEncoder().encode(JSON.stringify(payload)), buildAad("measure", OWNER, id));
  return { id: `row-${id}`, client_measure_id: id, blob: toBase64(blob), measure_date: date };
}
function server(rows: unknown[], post?: (init: RequestInit) => Response | Promise<Response>): void {
  stubFetch((url, init) => {
    if (new URL(url).pathname.endsWith("/measures")) {
      if (init.method === "POST") return post ? post(init) : jsonResponse({ id: "created" }, { status: 201 });
      return jsonResponse(rows, { headers: { "X-Measures-Revision": "8" } });
    }
    return jsonResponse({}, { status: 404 });
  });
}
async function ready(onCrisis = () => {}): Promise<Awaited<ReturnType<typeof render>>> {
  const root = await render(<MeasuresView onCrisis={onCrisis} />); await settle(15, 3); return root;
}
async function pick(root: Awaited<ReturnType<typeof render>>, index: number, value: number): Promise<void> {
  const labels = ["Not at all", "Several days", "More than half the days", "Nearly every day"];
  const control = root.root.findAllByType("button").filter(n => textOfNode(n) === labels[value])[index];
  if (!control || control.props.disabled || typeof control.props.onClick !== "function") throw new Error("answer control unavailable");
  await act(async () => { control.props.onClick(); });
}
beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
  resetTestState(); __setLocaleForTests("en"); setKvBackendForTests(memoryKvBackend());
  installSession(OWNER); vault.unlock({ authKey: key(), dataKey: key() }, OWNER);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); setKvBackendForTests(null); __setLocaleForTests("en"); });

it.each([1, 2, 8])("renders %i real authenticated history rows per instrument with quantitative trend geometry", async count => {
  const rows = [];
  for (const [kind, max] of [["phq9", 27], ["gad7", 21], ["phq2", 6]] as const) {
    for (let i = count - 1; i >= 0; i--) rows.push(await row(`${kind}-${i}`, { measure: kind, score: i % 2 ? max : 0 }, `2026-09-${String(i + 1).padStart(2, "0")}`));
  }
  server(rows); const root = await ready();
  expect(root.root.findAllByType("rect")).toHaveLength(count > 1 ? count * 3 : 0);
  expect(root.root.findAll(n => n.props.role === "img")).toHaveLength(3);
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it.each([
  { measure: "phq2", score: -1 }, { measure: "phq2", score: 7 }, { measure: "gad7", score: 22 },
  { measure: "phq9", score: 28 }, { measure: "phq2", score: "3" }, { measure: "phq2", score: null },
  { measure: "unknown", score: 3 }, { measure: null, score: 3 },
])("does not render an authenticated invalid measurement %j", async payload => {
  server([await row("invalid", payload, "2026-09-30")]); const root = await ready();
  expect(root.root.findAll(n => n.props.role === "img")).toHaveLength(0);
  expect(textOf(root)).toContain(t("measures.emptyNote"));
});

it.each(["phq9", "gad7", "phq2"] as const)("answers %s through its native questionnaire controls and clears old status on instrument change", async kind => {
  const accepted: { id: string; payload: { measure: string; score: number } }[] = [];
  server([], async init => {
    const body = JSON.parse(String(init.body));
    const opened = await decrypt(key(), fromBase64(body.blob), buildAad("measure", OWNER, body.client_measure_id));
    accepted.push({ id: body.client_measure_id, payload: JSON.parse(new TextDecoder().decode(opened)) });
    return jsonResponse({ id: "saved" }, { status: 201 });
  });
  const root = await ready(); await press(root, kind === "phq9" ? "PHQ-9" : kind === "gad7" ? "GAD-7" : "PHQ-2");
  const count = kind === "phq9" ? 9 : kind === "gad7" ? 7 : 2;
  for (let i = 0; i < count; i++) await pick(root, i, i % 4);
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  await press(root, "Save measure"); await settle(15, 4);
  expect(accepted).toHaveLength(1); expect(accepted[0]!.payload.measure).toBe(kind);
  expect(accepted[0]!.payload.score).toBe(Array.from({ length: count }, (_, i) => i % 4).reduce((a, b) => a + b, 0));
  expect(await loadPendingMeasure(key(), OWNER)).toBeNull();
  expect(textOf(root)).toContain(t("measures.savedNote"));
  await press(root, kind === "phq2" ? "PHQ-9" : "PHQ-2");
  expect(textOf(root)).not.toContain(t("measures.savedNote"));
});

it("changing only one answer after an offline attempt mints a fresh id; an unchanged retry reuses it", async () => {
  const attempts: string[] = [];
  server([], init => { attempts.push(JSON.parse(String(init.body)).client_measure_id); return Promise.reject(new TypeError("offline")); });
  const root = await ready(); await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 3);
  await press(root, "Save measure"); await settle(15, 4);
  const first = await loadPendingMeasure(key(), OWNER); expect(first!.picks).toEqual([1, 3]);
  await press(root, "Save measure"); await settle(15, 4);
  expect(attempts[1]).toBe(attempts[0]);
  await pick(root, 1, 2); await press(root, "Save measure"); await settle(15, 4);
  expect(attempts[2]).not.toBe(attempts[0]);
  expect((await loadPendingMeasure(key(), OWNER))!.picks).toEqual([1, 2]);
});

it("switching instruments after an offline attempt sends the current instrument and its current picks", async () => {
  const attempts: { id: string; payload: Record<string, unknown> }[] = [];
  server([], async init => {
    const body = JSON.parse(String(init.body)); const plain = await decrypt(key(), fromBase64(body.blob), buildAad("measure", OWNER, body.client_measure_id));
    attempts.push({ id: body.client_measure_id, payload: JSON.parse(new TextDecoder().decode(plain)) });
    throw new TypeError("offline");
  });
  const root = await ready(); await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 3);
  await press(root, "Save measure"); await settle(15, 4);
  await press(root, "GAD-7"); for (let i = 0; i < 7; i++) await pick(root, i, 2);
  await press(root, "Save measure"); await settle(15, 4);
  expect(attempts[1]!.id).not.toBe(attempts[0]!.id);
  expect(attempts[1]!.payload).toMatchObject({ measure: "gad7", score: 14 });
});

it.each([false, true])("offline PHQ-9 item nine support is honest for endorsement=%s and resets on instrument switch", async endorsed => {
  server([], () => Promise.reject(new TypeError("offline"))); const crisis = vi.fn(); const root = await ready(crisis);
  for (let i = 0; i < 9; i++) await pick(root, i, i === 8 && endorsed ? 1 : 0);
  await press(root, "Save measure"); await settle(15, 4);
  expect(textOf(root).includes(t("measures.item9Title"))).toBe(endorsed);
  if (endorsed) { await press(root, "Get support"); expect(crisis).toHaveBeenCalledTimes(1); }
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  await press(root, "PHQ-2"); expect(textOf(root)).not.toContain(t("measures.item9Title"));
});

it("restores a GAD-7 pending questionnaire once, keeps every answer, and reports a server failure honestly", async () => {
  await savePendingMeasure(key(), OWNER, { kind: "gad7", picks: [3, 2, 1, 0, 3, 2, 1], clientMeasureId: "pending-gad7", date: "2026-09-30" });
  const attempts: string[] = [];
  server([], init => { attempts.push(JSON.parse(String(init.body)).client_measure_id); return jsonResponse({ detail: "private" }, { status: 500 }); });
  const root = await ready(); await settle(15, 3);
  expect(attempts).toEqual(["pending-gad7"]);
  expect(textOf(root)).toContain(t("errors.serverError"));
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  expect((await loadPendingMeasure(key(), OWNER))!.picks).toEqual([3, 2, 1, 0, 3, 2, 1]);
});

it("an opted-in reminder uses the latest completed date and its dismissal survives a remount", async () => {
  await writeMeasureCadence(OWNER, { enabled: true, intervalWeeks: 2, snoozedUntil: null });
  server([await row("older", { measure: "phq2", score: 4 }, "2026-08-01T00:00:00Z"), await row("newer", { measure: "phq9", score: 4 }, "2026-09-01T00:00:00Z")]);
  const root = await ready(); expect(textOf(root)).toContain(t("measures.cadenceTitle"));
  await press(root, "Not now"); await settle(15, 3);
  expect(textOf(root)).not.toContain(t("measures.cadenceTitle"));
  expect((await readMeasureCadence(OWNER)).snoozedUntil).toBe("2026-10-08");
  await act(async () => { root.unmount(); }); const next = await ready();
  expect(textOf(next)).not.toContain(t("measures.cadenceTitle"));
});

it.each(["nonempty-terminal", "empty-terminal"])("the 21st %s page proves the public history walk bound without an infinite fixture", async terminal => {
  let pages = 0;
  stubFetch(url => {
    const u = new URL(url);
    if (!u.pathname.endsWith("/measures")) return jsonResponse({}, { status: 404 });
    pages++;
    if (pages > 1 && u.searchParams.get("expected_revision") !== "9") return jsonResponse({ detail: "snapshot changed" }, { status: 409 });
    const offset = Number(u.searchParams.get("offset") ?? 0);
    const data = pages === 21 && terminal === "empty-terminal" ? [] : [{ id: `r-${pages}`, client_measure_id: `m-${pages}`, blob: "AA==", measure_date: "2026-09-01" }];
    return jsonResponse(data, { headers: { "X-Measures-Revision": "9", ...(pages < 21 ? { "X-Next-Offset": String(offset + 1) } : {}) } });
  });
  const root = await ready(); await settle(10, 4);
  expect(pages).toBe(21);
  expect(textOf(root).includes(t("measures.walkLimit"))).toBe(terminal === "nonempty-terminal");
  expect(textOf(root)).not.toContain(t("common.loading"));
});

it("native cryptography retains no owned save plaintext or copied data key after a completed questionnaire", async () => {
  const native = globalThis.crypto, ownedPlaintexts: Uint8Array[] = [], submittedKeys: Uint8Array[] = [];
  const subtle = new Proxy(native.subtle, { get(target, property) {
    if (property === "encrypt") return async (...args: Parameters<SubtleCrypto["encrypt"]>) => {
      const data = args[2]; if (ArrayBuffer.isView(data)) ownedPlaintexts.push(data as Uint8Array);
      return target.encrypt(...args);
    };
    if (property === "importKey") return (...args: unknown[]) => {
      if (args[0] === "raw" && args[1] instanceof Uint8Array && (args[2] === "AES-GCM" || (args[2] as { name?: string })?.name === "AES-GCM")) submittedKeys.push(args[1]);
      return (target.importKey as (...args: unknown[]) => Promise<CryptoKey>).apply(target, args);
    };
    const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
  } });
  vi.stubGlobal("crypto", new Proxy(native, { get(target, property) { return property === "subtle" ? subtle : typeof Reflect.get(target, property, target) === "function" ? Reflect.get(target, property, target).bind(target) : Reflect.get(target, property, target); } }));
  server([]); const root = await ready(); await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2);
  await press(root, "Save measure"); await settle(15, 4);
  expect(textOf(root)).toContain(t("measures.savedNote"));
  expect(ownedPlaintexts.length).toBeGreaterThanOrEqual(2);
  expect(ownedPlaintexts.every(bytes => bytes.every(byte => byte === 0))).toBe(true);
  expect(submittedKeys.length).toBeGreaterThanOrEqual(2);
  expect(submittedKeys.every(bytes => bytes.every(byte => byte === 0))).toBe(true);
  expect(vault.get().dataKey).toEqual(key());
});

it("an authenticated history row is rendered while its native decrypted temporary buffer is erased", async () => {
  const encrypted = await row("native-custody", { measure: "phq2", score: 4 }, "2026-09-30");
  const native = globalThis.crypto, decrypted: ArrayBuffer[] = [];
  const subtle = new Proxy(native.subtle, { get(target, property) {
    if (property === "decrypt") return async (...args: Parameters<SubtleCrypto["decrypt"]>) => { const plain = await target.decrypt(...args); decrypted.push(plain); return plain; };
    const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
  } });
  vi.stubGlobal("crypto", new Proxy(native, { get(target, property) { return property === "subtle" ? subtle : typeof Reflect.get(target, property, target) === "function" ? Reflect.get(target, property, target).bind(target) : Reflect.get(target, property, target); } }));
  server([encrypted]); const root = await ready();
  expect(root.root.findAll(n => n.props.role === "img")).toHaveLength(1);
  expect(decrypted).toHaveLength(1);
  expect(new Uint8Array(decrypted[0]!).every(byte => byte === 0)).toBe(true);
  expect(vault.get().dataKey).toEqual(key());
});

it("quantitative chart ranges preserve nonzero lower and nonmaximal upper scores", async () => {
  server([await row("range-a", { measure: "phq9", score: 3 }, "2026-09-01"), await row("range-b", { measure: "phq9", score: 20 }, "2026-09-02")]);
  const root = await ready();
  expect(root.root.findAll(n => n.props.role === "img")[0]!.props["aria-label"]).toBe(t("measures.trendA11yWithValue", { count: 2, first: "2026-09-01", last: "2026-09-02", low: 11, high: 74, latest: 20, max: 27 }));
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it("partial answer progress remains quantitative while an in-flight save disables resubmission", async () => {
  let finish!: (response: Response) => void;
  server([], () => new Promise(resolve => { finish = resolve; }));
  const root = await ready(); await pick(root, 0, 1); await pick(root, 1, 2);
  expect(publicSurface(root.toJSON())).toMatchSnapshot("partial questionnaire");
  for (let i = 2; i < 9; i++) await pick(root, i, 0);
  await press(root, "Save measure"); await settle(10, 3);
  try {
    const saving = root.root.findAllByType("button").find(n => textOfNode(n) === t("entry.saving"));
    expect(saving).toBeDefined(); expect(saving!.props.disabled).toBe(true);
    expect(publicSurface(root.toJSON())).toMatchSnapshot("busy questionnaire");
  } finally { finish(jsonResponse({ id: "saved" }, { status: 201 })); await settle(15, 3); }
});

it("two completed questionnaires use independent server idempotency records", async () => {
  // These are genuine distinct random draws whose base64 starts with '+'.
  // Sanitizing their opaque ids must retain enough entropy to keep the two
  // accepted questionnaires independent, including this allowed RNG output.
  const native = globalThis.crypto;
  vi.stubGlobal("crypto", new Proxy(native, { get(target, property) {
    if (property === "getRandomValues") return <T extends ArrayBufferView>(array: T): T => {
      const result = target.getRandomValues(array); if (array instanceof Uint8Array && array.length > 1) { array[0] = 0xf8; array[1] = array[1]! & 15; } return result;
    };
    const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
  } }));
  const accepted = new Map<string, number>();
  server([], async init => {
    const body = JSON.parse(String(init.body));
    const plain = await decrypt(key(), fromBase64(body.blob), buildAad("measure", OWNER, body.client_measure_id));
    const payload = JSON.parse(new TextDecoder().decode(plain));
    if (accepted.has(body.client_measure_id)) return jsonResponse({ detail: "already recorded" }, { status: 409 });
    accepted.set(body.client_measure_id, payload.score); return jsonResponse({ id: `saved-${accepted.size}` }, { status: 201 });
  });
  const root = await ready(); await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2);
  await press(root, "Save measure"); await settle(15, 4);
  await pick(root, 1, 3); await press(root, "Save measure"); await settle(15, 4);
  expect([...accepted.values()]).toEqual([3, 4]);
  expect(textOf(root)).toContain(t("measures.savedNote"));
  expect(textOf(root)).not.toContain(t("measures.alreadyToday"));
});

it("a completed PHQ-9 with an unendorsed safety item does not invent a support status", async () => {
  server([]); const root = await ready(); for (let i = 0; i < 9; i++) await pick(root, i, 0);
  await press(root, "Save measure"); await settle(15, 4);
  expect(textOf(root)).toContain(t("measures.savedNote"));
  expect(textOf(root)).not.toContain(t("measures.item9Title"));
});

it.each(["locked", "unowned"])("a %s live questionnaire refuses saving and reports the declared lock status", async mode => {
  let posted = false; server([], () => { posted = true; return jsonResponse({ id: "saved" }, { status: 201 }); });
  const root = await ready(); await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2);
  if (mode === "locked") vault.lock(); else vault.unlock({ authKey: key(), dataKey: key() });
  await press(root, "Save measure"); await settle(15, 3);
  expect(posted).toBe(false); expect(textOf(root)).toContain(t("common.sessionLocked"));
});

it("an unowned unlocked vault cannot restore or send a saved questionnaire", async () => {
  vault.unlock({ authKey: key(), dataKey: key() }); let requested = false;
  stubFetch(() => { requested = true; return jsonResponse([], { headers: { "X-Measures-Revision": "1" } }); });
  const root = await ready();
  expect(requested).toBe(false); expect(textOf(root)).toContain(t("common.sessionLocked"));
});

it.each([false, true])("a native history transport failure reports honest offline or locked status (locked=%s)", async locked => {
  stubFetch(() => { if (locked) vault.lock(); throw new TypeError("connection interrupted"); });
  const root = await ready();
  expect(textOf(root)).toContain(t(locked ? "common.sessionLocked" : "measures.loadOffline"));
  expect(textOf(root)).not.toContain(t("common.loading"));
});

it("a lock during native row decryption retains only the completed rows, sorted chronologically, with the locked explanation", async () => {
  const rows = [await row("newer", { measure: "phq2", score: 4 }, "2026-09-30"), await row("older", { measure: "phq2", score: 2 }, "2026-09-01"), await row("unread", { measure: "phq2", score: 3 }, "2026-09-20")];
  const native = globalThis.crypto; let finish!: () => void, reached = false, decrypts = 0;
  const pause = new Promise<void>(resolve => { finish = resolve; });
  const subtle = new Proxy(native.subtle, { get(target, property) {
    if (property === "decrypt") return async (...args: Parameters<SubtleCrypto["decrypt"]>) => {
      const plain = await target.decrypt(...args); if (++decrypts === 2) { reached = true; await pause; } return plain;
    };
    const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
  } });
  vi.stubGlobal("crypto", new Proxy(native, { get(target, property) { return property === "subtle" ? subtle : typeof Reflect.get(target, property, target) === "function" ? Reflect.get(target, property, target).bind(target) : Reflect.get(target, property, target); } }));
  server(rows); const root = await ready();
  try { expect(reached).toBe(true); vault.lock(); }
  finally { finish(); await settle(15, 3); }
  expect(textOf(root)).toContain(t("common.sessionLocked"));
  const chart = root.root.findAll(n => n.props.role === "img")[0]; expect(chart).toBeDefined();
  expect(chart!.props["aria-label"]).toContain("2026-09-01 to 2026-09-30");
  expect(root.root.findAllByType("rect")).toHaveLength(2);
  expect(textOf(root)).not.toContain("2026-09-20");
});

it("a late decrypted initial history cannot overwrite the current history loaded after a successful save", async () => {
  const old = await row("old", { measure: "phq2", score: 1 }, "2026-09-01"), current = await row("current", { measure: "phq2", score: 5 }, "2026-09-30");
  const native = globalThis.crypto; let finish!: () => void, reached = false, decrypts = 0, reads = 0;
  const pause = new Promise<void>(resolve => { finish = resolve; });
  const subtle = new Proxy(native.subtle, { get(target, property) {
    if (property === "decrypt") return async (...args: Parameters<SubtleCrypto["decrypt"]>) => {
      const plain = await target.decrypt(...args); if (++decrypts === 1) { reached = true; await pause; } return plain;
    };
    const value = Reflect.get(target, property, target); return typeof value === "function" ? value.bind(target) : value;
  } });
  vi.stubGlobal("crypto", new Proxy(native, { get(target, property) { return property === "subtle" ? subtle : typeof Reflect.get(target, property, target) === "function" ? Reflect.get(target, property, target).bind(target) : Reflect.get(target, property, target); } }));
  stubFetch((_url, init) => init.method === "POST" ? jsonResponse({ id: "created" }, { status: 201 }) : jsonResponse([++reads === 1 ? old : current], { headers: { "X-Measures-Revision": String(reads) } }));
  const root = await ready();
  try {
    expect(reached).toBe(true); await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2);
    await press(root, "Save measure"); await settle(15, 4);
    expect(root.root.findAll(n => n.props.role === "img")[0]!.props["aria-label"]).toContain("2026-09-30");
  } finally { finish(); await settle(15, 3); }
  expect(root.root.findAll(n => n.props.role === "img")[0]!.props["aria-label"]).toContain("2026-09-30");
  expect(textOf(root)).not.toContain("2026-09-01");
});

it("a late initial history failure cannot clear the successfully refreshed current history", async () => {
  const current = await row("current", { measure: "phq2", score: 5 }, "2026-09-30");
  let finish!: (response: Response) => void, reads = 0;
  stubFetch((_url, init) => {
    if (init.method === "POST") return jsonResponse({ id: "created" }, { status: 201 });
    if (++reads === 1) return new Promise(resolve => { finish = resolve; });
    return jsonResponse([current], { headers: { "X-Measures-Revision": String(reads) } });
  });
  const root = await ready();
  try {
    await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2);
    await press(root, "Save measure"); await settle(15, 4);
    expect(root.root.findAll(n => n.props.role === "img")[0]!.props["aria-label"]).toContain("2026-09-30");
  } finally { finish(jsonResponse({ detail: "retired request failed" }, { status: 500 })); await settle(15, 3); }
  const chart = root.root.findAll(n => n.props.role === "img")[0]; expect(chart).toBeDefined();
  expect(chart!.props["aria-label"]).toContain("2026-09-30");
  expect(textOf(root)).not.toContain(t("errors.serverError"));
});

it.each(["load", "save"])("an unmapped native HTTP validation failure renders the authored %s fallback", async lane => {
  server([], () => jsonResponse({ detail: "private validation implementation" }, { status: 422 }));
  if (lane === "load") stubFetch(() => jsonResponse({ detail: "private validation implementation" }, { status: 422 }));
  const root = await ready();
  if (lane === "save") { await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2); await press(root, "Save measure"); await settle(15, 3); }
  expect(textOf(root)).toContain(t(lane === "load" ? "measures.loadFailed" : "measures.saveFailed"));
  expect(textOf(root)).not.toContain("private validation implementation");
});

it("human trends normalize ISO measure timestamps to their calendar dates", async () => {
  server([await row("timestamp-a", { measure: "phq2", score: 2 }, "2026-09-01T12:00:00Z"), await row("timestamp-b", { measure: "phq2", score: 4 }, "2026-09-30T12:00:00Z")]);
  const root = await ready();
  expect(root.root.findAll(n => n.props.role === "img")[0]!.props["aria-label"]).toContain("2026-09-01 to 2026-09-30");
  expect(publicSurface(root.toJSON())).not.toContain("T12:00:00Z");
});

it("a retired history continuation cannot consume the server read quota needed by the next current save", async () => {
  const current = await row("quota-current", { measure: "phq2", score: 4 }, "2026-09-30");
  let finish!: (response: Response) => void, reads = 0;
  stubFetch((url, init) => {
    if (init.method === "POST") return jsonResponse({ id: "created" }, { status: 201 });
    reads++;
    if (reads === 1) return new Promise(resolve => { finish = resolve; });
    // A server configured for three history reads per window. The first
    // pending walk, save refresh, and next save refresh fit that allowance.
    if (reads > 3) return jsonResponse({ detail: "read quota exceeded" }, { status: 429 });
    const offset = Number(new URL(url).searchParams.get("offset") ?? 0);
    return jsonResponse(offset === 0 ? [current] : [], { headers: { "X-Measures-Revision": offset === 0 ? "2" : "1" } });
  });
  const root = await ready();
  try {
    await press(root, "PHQ-2"); await pick(root, 0, 1); await pick(root, 1, 2);
    await press(root, "Save measure"); await settle(15, 4);
  } finally {
    finish(jsonResponse([{ id: "retired", client_measure_id: "old", blob: "AA==", measure_date: "2026-09-01" }], { headers: { "X-Measures-Revision": "1", "X-Next-Offset": "1" } }));
    await settle(15, 3);
  }
  await pick(root, 1, 3); await press(root, "Save measure"); await settle(15, 4);
  expect(textOf(root)).not.toContain(t("errors.rateLimited"));
  const chart = root.root.findAll(n => n.props.role === "img")[0]; expect(chart).toBeDefined();
  expect(chart!.props["aria-label"]).toContain("2026-09-30");
});

it("an admitted reminder dismissal after vault retirement cannot leave an ownerless native IndexedDB preference", async () => {
  setKvBackendForTests(null);
  await writeMeasureCadence(OWNER, { enabled: true, intervalWeeks: 2, snoozedUntil: null });
  server([]); const root = await ready();
  expect(textOf(root)).toContain(t("measures.cadenceTitle"));
  const storedBefore = new Set(await kv.keys());
  vault.lock(); await press(root, "Not now"); await settle(15, 4);
  expect(new Set(await kv.keys())).toEqual(storedBefore);
  expect((await readMeasureCadence(OWNER)).snoozedUntil).toBeNull();
});
