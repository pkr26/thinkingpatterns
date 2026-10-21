import { act, useState } from "react";
import { IDBFactory, IDBObjectStore } from "fake-indexeddb";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PatternsView, type PatternPayload } from "../src/views/Patterns";
import { api, sessionAbortSignal, setSessionExpiredHandler } from "../src/api/client";
import { encrypt, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { kv, StorageCommitError, newWriteGeneration, resetKvConnectionForTests, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { recordMood } from "../src/moodLog";
import * as moodService from "../src/moodLog";
import { writeMutedPids, readMutedPids } from "../src/patternMutes";
import { buildFeedbackBlob, recordFeedbackTap } from "../src/questionFeedback";
import { decrypt, fromBase64 } from "../src/crypto/core";
import { clearThresholdNotice, recordThresholdNotice } from "../src/thresholdNotice";
import * as thresholdService from "../src/thresholdNotice";
import { __setLocaleForTests, t } from "../src/strings";
import { notifyPaletteChanged, PALETTES } from "../src/tokens";
import { vault } from "../src/vault";
import { installSession, jsonResponse, memoryKvBackend, resetTestState, stubFetch } from "./helpers/api";
import { publicSurface } from "./helpers/publicSurface";
import { press, render, settle, textOf, textOfNode } from "./helpers/rtr";

let OWNER = "patterns-consumer", scenario = 0;
const key = () => new Uint8Array(new ArrayBuffer(32)).fill(19);
const pattern = (kind: string, detail: PatternPayload["detail"] = {}): PatternPayload => ({
  kind, label: `A repeated ${kind} observation`, occurrences: 1, confidence: .73,
  detail: { pattern_pid: `pid:${kind}`, ...detail },
});
async function response(patterns: unknown[], phase = "insight", stats = true): Promise<Response> {
  const payload = { v: 2, state_seq: 8, ...(stats ? { stats: { patterns } } : {}) };
  const blob = await encrypt(key(), new TextEncoder().encode(JSON.stringify(payload)), buildAad("insights", OWNER, "patterns"));
  return jsonResponse({ phase, active_days: 8, days_remaining: 22, streak: 2, state_seq: 8, blob: toBase64(blob) });
}
function server(insights: () => Response | Promise<Response>): void {
  stubFetch(url => new URL(url).pathname.endsWith("/insights") ? insights() : jsonResponse([], { headers: { "X-Entries-Revision": "1" } }));
}
async function ready(): Promise<ReturnType<typeof render> extends Promise<infer T> ? T : never> {
  const root = await render(<PatternsView onCrisis={() => {}} />);
  await settle(15, 3);
  return root;
}
beforeEach(() => {
  OWNER = `patterns-consumer-${++scenario}`;
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
  resetTestState(); __setLocaleForTests("en"); setKvBackendForTests(memoryKvBackend());
  installSession(OWNER); vault.unlock({ authKey: key(), dataKey: key() }, OWNER);
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); __setLocaleForTests("en"); setKvBackendForTests(null); });

it.each(["en", "es"] as const)("renders authored methods, lifecycle, disclosure and sensitive output in %s", async locale => {
  __setLocaleForTests(locale);
  const kinds = ["temporal", "mood_correlation", "link", "inertia", "energy_inertia", "pa_inertia", "na_inertia", "energy_mood_coupling", "sense_making", "activity_diversity", "instability", "mood_shift", "rumination", "topic", "recurring_phrase", "avoidance", "cadence", "future_kind"];
  const states = ["candidate", "emerging", "confirmed", "fading", "archived", "future_state", undefined];
  server(() => response(kinds.map((kind, i) => pattern(kind, {
    pattern_state: states[i % states.length], is_new: i % 2 === 0,
    ...(i % 3 === 0 ? { sample_entries: 0, sample_days: 0, first_seen: "2026-08-01", last_seen: "2026-09-30" } : i % 3 === 1 ? { sample_entries: 4, sample_days: 3 } : {}),
    ...(kind === "rumination" ? { sensitive: true } : {}),
  }))));
  const root = await ready();
  expect(root.root.findAllByType("details")).toHaveLength(kinds.length);
  expect(textOf(root)).toContain(t("insights.methodFallbackWeb"));
  expect(textOf(root)).toContain("future_state");
  expect(textOf(root)).not.toContain("A repeated rumination observation");
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it.each([0, 1, 3, 12])("renders %i encrypted local mood days with honest baseline geometry and accessible data", async count => {
  for (let i = 0; i < count; i++) await recordMood(key(), OWNER, `2026-09-${String(i + 1).padStart(2, "0")}`, [-1, 0, .8][i % 3]!);
  // Observe the real renderer's duplicate-sibling-key diagnostic. All
  // console output is forwarded unchanged; unrelated diagnostics stay visible.
  const originalConsoleError = console.error.bind(console), duplicateKeyErrors: unknown[][] = [];
  const observingErrors = vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
    originalConsoleError(...args);
    if (typeof args[0] === "string" && args[0].startsWith("Encountered two children with the same key,") &&
      args[0].includes("Keys should be unique so that components maintain their identity across updates.")) duplicateKeyErrors.push(args);
  });
  try {
  server(() => jsonResponse({ phase: "baseline", active_days: count === 0 ? 0 : count === 1 ? 1 : 8, days_remaining: count === 0 ? 0 : 22, streak: 1, blob: null }));
  const root = await ready();
  expect(root.root.findAllByType("rect")).toHaveLength(count > 1 ? count : 0);
  expect(root.root.findAllByType("tbody")).toHaveLength(count > 1 ? 1 : 0);
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  expect(duplicateKeyErrors, "The actual encrypted mood table must not emit React's duplicate sibling-key diagnostic").toEqual([]);
  } finally { observingErrors.mockRestore(); }
});

it("redraws visible mood bars when the browser changes its resolved palette", async () => {
  await recordMood(key(), OWNER, "2026-09-01", -1); await recordMood(key(), OWNER, "2026-09-02", 1);
  vi.stubGlobal("document", { documentElement: { dataset: { theme: "light" } } });
  server(() => jsonResponse({ phase: "baseline", active_days: 2, days_remaining: 28, streak: 1, blob: null }));
  const root = await ready();
  expect(root.root.findAllByType("rect").map(n => n.props.style.fill)).toEqual([PALETTES.light.moodMinus2, PALETTES.light.mood2]);
  document.documentElement.dataset.theme = "dark";
  await act(async () => { notifyPaletteChanged(); });
  expect(root.root.findAllByType("rect").map(n => n.props.style.fill)).toEqual([PALETTES.dark.moodMinus2, PALETTES.dark.mood2]);
});

it.each([1, 2])("shows %i muted patterns and restores one through its authored control", async count => {
  const rows = [pattern("topic"), pattern("link", { sensitive: true })];
  await writeMutedPids(key(), OWNER, new Set(rows.slice(0, count).map(p => p.detail.pattern_pid!)));
  server(() => response(rows));
  const root = await ready();
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  const unmute = root.root.findAllByType("button").find(n => String(n.children.join("")).includes("Unmute"));
  expect(unmute).toBeDefined();
  await act(async () => { unmute!.props.onClick(); }); await settle(15, 3);
  expect((await readMutedPids(key(), OWNER)).size).toBe(count - 1);
  expect(await buildFeedbackBlob(key(), OWNER)).not.toBeNull();
  expect(textOf(root)).toContain(t("insights.seenOne", { count: 1 }));
});

it("renders a verified minimal analysis without inventing a pattern card or repeating the threshold notice", async () => {
  await recordThresholdNotice(OWNER); server(() => response([], "insight", false));
  const root = await ready();
  expect(root.root.findAllByType("details")).toHaveLength(0);
  expect(textOf(root)).toContain(t("insights.noneYetWeb"));
  expect(textOf(root)).not.toContain(t("insights.thresholdNotice"));
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it.each(["offline", "server", "unknown", "tampered"])("renders the public %s failure without leaking transport content", async mode => {
  server(() => {
    if (mode === "offline") return Promise.reject(new TypeError("network down"));
    if (mode === "server") return jsonResponse({ detail: "private database failure" }, { status: 500 });
    if (mode === "tampered") return jsonResponse({ phase: "insight", active_days: 8, days_remaining: 22, streak: 1, blob: "AA==", state_seq: 8 });
    return jsonResponse({ phase: "future-phase", active_days: 8, days_remaining: 22, streak: 1, blob: null });
  });
  const root = await ready();
  expect(textOf(root)).not.toContain("private database failure");
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it("a visible legacy pattern without a persistent pid cannot create a mute or feedback record", async () => {
  const p = pattern("topic"); delete p.detail.pattern_pid;
  server(() => response([p])); const root = await ready();
  await press(root, "Mute"); await settle(15, 2);
  expect(textOf(root)).toContain(p.label);
  expect((await readMutedPids(key(), OWNER)).size).toBe(0);
  expect(await buildFeedbackBlob(key(), OWNER)).toBeNull();
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it("a locked live chart does not persist a new mute", async () => {
  server(() => response([pattern("topic")])); const root = await ready();
  vault.lock(); await press(root, "Mute"); await settle(15, 2);
  expect(textOf(root)).toContain(t("insights.seenOne", { count: 1 }));
  expect(await kv.getItem(`mindpattern.patternMutes.v1.${OWNER}`)).toBeNull();
});

it.each(["constructor", "toString", "__proto__", "hasOwnProperty"])("unknown authenticated kind and lifecycle %s use the declared fallback", async token => {
  server(() => response([pattern(token, { pattern_state: token })]));
  const root = await ready();
  expect(textOf(root)).toContain(t("insights.methodFallbackWeb"));
  expect(textOf(root)).toContain(`${t("insights.evidencePrefix")}: ${token}`);
  expect(textOf(root)).not.toContain("[native code]");
});

it("a retained authenticated generation cannot be replaced by an older verified analysis", async () => {
  await kv.setItem(`mindpattern.stateSeq.${OWNER}`, "9");
  server(() => response([pattern("topic")])); const root = await ready();
  expect(textOf(root)).toContain(t("insights.freshnessWeb"));
  expect(textOf(root)).not.toContain("A repeated topic observation");
});

it("a native shared-lock failure reports a safe public error instead of leaving a rejected load", async () => {
  vi.stubGlobal("navigator", { locks: { request: async () => { throw new Error("host lock unavailable"); } } });
  server(() => response([])); const failures: unknown[] = [], observe = (err: unknown) => { failures.push(err); };
  process.on("unhandledRejection", observe);
  try {
    const root = await ready();
    expect(textOf(root)).toContain("host lock unavailable");
    expect(failures).toEqual([]);
  } finally { process.removeListener("unhandledRejection", observe); }
});

it("a threshold-stamp storage fault reports the authored verified-analysis failure", async () => {
  const backend = memoryKvBackend();
  setKvBackendForTests({ ...backend, getItem: async slot => { if (slot.startsWith("mindpattern.thresholdNotice.")) throw new Error("device storage unavailable"); return backend.getItem(slot); } });
  server(() => response([pattern("topic")])); const root = await ready();
  expect(textOf(root)).toContain(t("insights.decryptFailedWeb"));
  // A failed committed-notice SET has a different catch from the GET above.
  // The original public helper Promise passes through unchanged; only the
  // declared backend's attempted storage commit is held and then refused.
  await act(async () => { root.unmount(); });
  resetTestState(); setKvBackendForTests(memoryKvBackend()); installSession(OWNER);
  vault.unlock({ authKey: key(), dataKey: key() }, OWNER);
  const marker = `mindpattern.thresholdNotice.v1.${OWNER}`, actualBackend = memoryKvBackend();
  const backendFault = new DOMException("Controlled threshold stamp quota refusal", "QuotaExceededError");
  let release!: () => void, reached!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { reached = resolve; });
  const setAttempts: Array<{ slot: string; value: string }> = [];
  setKvBackendForTests({ ...actualBackend, setItem: async (slot, value, permit) => {
    if (slot === marker) { setAttempts.push({ slot, value }); reached(); await held; throw backendFault; }
    return actualBackend.setItem(slot, value, permit);
  } });
  const actualNotice = thresholdService.recordThresholdNotice;
  const originals: Promise<void>[] = [];
  const noticeObserver = vi.spyOn(thresholdService, "recordThresholdNotice").mockImplementation((...args) => {
    const original = actualNotice(...args); originals.push(original); void original.catch(() => undefined); return original;
  });
  let writing: Awaited<ReturnType<typeof render>> | undefined;
  const drain = async (): Promise<void> => {
    let count = -1;
    while (count !== originals.length) {
      count = originals.length;
      for (const result of await Promise.allSettled([...originals])) {
        if (result.status === "rejected" && !(result.reason instanceof StorageCommitError && result.reason.cause === backendFault)) throw result.reason;
      }
    }
  };
  try {
    server(() => response([pattern("topic")])); writing = await render(<PatternsView onCrisis={() => {}} />);
    try { await vi.waitFor(() => { if (setAttempts.length !== 1) throw new Error("the actual threshold SET was not admitted"); }, { timeout: 10_000 }); }
    catch (cause) { throw new Error("SetupError: the original current notice did not reach its declared storage SET boundary", { cause }); }
    await entered;
    expect(textOf(writing)).toContain(t("insights.thresholdNotice"));
    expect(setAttempts).toEqual([{ slot: marker, value: "2026-10-05" }]);
    if (originals.length !== 1) throw new Error("SetupError: exactly one complete original public notice write must own the backend refusal");
    await act(async () => { release(); await drain(); });
    expect(textOf(writing), "A current committed threshold notice reports the real storage SET refusal through its authored analysis error").toContain(t("insights.decryptFailedWeb"));
    expect(await actualBackend.getItem(marker)).toBeNull();
  } finally {
    release();
    try { if (writing) await act(async () => { writing!.unmount(); }); await drain(); }
    finally { noticeObserver.mockRestore(); setKvBackendForTests(memoryKvBackend()); }
  }
});

it("an unowned unlocked vault cannot authorize an analysis chart", async () => {
  vault.unlock({ authKey: key(), dataKey: key() });
  server(() => response([])); const root = await ready();
  expect(textOf(root)).toContain(t("common.sessionLocked"));
});

it("a late vault lock during the genuine insights request reports session retirement", async () => {
  server(() => { vault.lock(); return jsonResponse({ phase: "baseline", active_days: 1, days_remaining: 29, streak: 1, blob: null }); });
  const root = await ready();
  expect(textOf(root)).toContain(t("errors.sessionEndedWeb"));
});

it("a session retired during native lock release leaves no rejected chart continuation", async () => {
  // Web Locks schedules release after the callback's waiting promise settles,
  // then settles the caller's separate released promise. A native HTTP task
  // may retire the session while that release task is still queued.
  let callbackSettled = false, release!: () => void;
  const releaseTask = new Promise<void>(resolve => { release = resolve; });
  vi.stubGlobal("navigator", { locks: { request: async (_name: string, callback: () => Promise<unknown>) => {
    const result = await callback(); callbackSettled = true;
    await releaseTask; return result;
  } } });
  stubFetch(url => new URL(url).pathname.endsWith("/insights")
    ? jsonResponse({ phase: "baseline", active_days: 1, days_remaining: 29, streak: 1, blob: null })
    : jsonResponse({ detail: "expired" }, { status: 401 }));
  setSessionExpiredHandler(() => { vault.lock(); });
  const failures: unknown[] = [], observe = (err: unknown) => { failures.push(err); };
  process.on("unhandledRejection", observe);
  try {
    const root = await render(<PatternsView onCrisis={() => {}} />);
    await vi.waitFor(() => { expect(callbackSettled).toBe(true); });
    await expect(api.getLlmConsent()).rejects.toMatchObject({ status: 401 });
    expect(vault.isUnlocked()).toBe(false);
    release(); await settle(15, 3);
    expect(failures).toEqual([]);
    expect(root.root.findAllByType("details")).toHaveLength(0);
  } finally {
    release(); process.removeListener("unhandledRejection", observe);
    setSessionExpiredHandler(null);
  }
});

it("a legacy mute without a pid cannot evict genuine feedback waiting for recomputation", async () => {
  for (let i = 0; i < 64; i++) await recordFeedbackTap(key(), OWNER, `known-${i}`, true);
  const p = pattern("topic"); delete p.detail.pattern_pid;
  server(() => response([p])); const root = await ready(); await press(root, "Mute"); await settle(15, 3);
  const sealed = await buildFeedbackBlob(key(), OWNER);
  const opened = await decrypt(key(), fromBase64(sealed!), buildAad("feedback", OWNER, "2026-10-05"));
  const wire = JSON.parse(new TextDecoder().decode(opened));
  expect(wire.feedback).toHaveLength(64);
  expect(wire.feedback[0]).toEqual({ pid: "known-0", resonated: true });
});

it("evidence only announces writing days when entry counts accompany them, and otherwise uses the missing-data marker", async () => {
  server(() => response([pattern("topic", { sample_days: 5 }), pattern("link", { sample_entries: 4 })]));
  const root = await ready();
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it("a pending encrypted mood read keeps the public baseline loading placeholder visible", async () => {
  const backend = memoryKvBackend(); setKvBackendForTests(backend);
  await recordMood(key(), OWNER, "2026-09-01", -1); await recordMood(key(), OWNER, "2026-09-02", 1);
  let finish!: () => void; const pending = new Promise<void>(resolve => { finish = resolve; }); let reading = false;
  setKvBackendForTests({ ...backend, getItem: async slot => { if (slot.startsWith("mindpattern.moodlog.")) { reading = true; await pending; } return backend.getItem(slot); } });
  server(() => jsonResponse({ phase: "baseline", active_days: 2, days_remaining: 28, streak: 1, blob: null }));
  const root = await ready();
  try { expect(reading).toBe(true); expect(publicSurface(root.toJSON())).toMatchSnapshot("mood read pending"); }
  finally { finish(); await settle(15, 3); }
  expect(root.root.findAllByType("rect")).toHaveLength(2);
});

it("a transport baseline label cannot spend the one-time insight threshold notice", async () => {
  server(() => response([], "baseline")); const first = await ready();
  expect(textOf(first)).not.toContain(t("insights.thresholdNotice"));
  await act(async () => { first.unmount(); });

  // Retire only this public view while delivery of its completed IndexedDB read result is held.
  // The same authenticated account/key remains live across navigation.
  const factory = new IDBFactory();
  let database: IDBDatabase | undefined;
  const open = factory.open.bind(factory);
  const opening = vi.spyOn(factory, "open").mockImplementation((...args) => {
    const request = open(...args);
    request.addEventListener("success", () => { database = request.result; });
    return request;
  });
  vi.stubGlobal("indexedDB", factory);
  setKvBackendForTests(null); resetKvConnectionForTests();
  const marker = `mindpattern.thresholdNotice.v1.${OWNER}`;
  await kv.setItem(writeGenerationKey(OWNER), await newWriteGeneration(OWNER, key()));
  await recordMood(key(), OWNER, "2026-09-01", -1);
  // A declared public route models App's keyed Patterns-to-Today unmount.
  // Only the view retires; its API owner and unlocked key stay live.
  function PatternsRoute() {
    const [showPatterns, setShowPatterns] = useState(true);
    return showPatterns
      ? <div key="patterns"><button onClick={() => setShowPatterns(false)}>Leave patterns</button><PatternsView onCrisis={() => {}} /></div>
      : <div key="today">Current home</div>;
  }
  const liveSignal = sessionAbortSignal(), liveDataKey = vault.get().dataKey;
  const moodSlot = `mindpattern.moodlog.${OWNER}`;
  let resourceRetired = false;
  const admittedMoodReads: Array<{ slot: string; afterRetirement: boolean }> = [];
  const actualGet = IDBObjectStore.prototype.get;
  const getting = vi.spyOn(IDBObjectStore.prototype, "get").mockImplementation(function (this: IDBObjectStore, ...args) {
    const originalRequest = actualGet.apply(this, args);
    if (args[0] === moodSlot) admittedMoodReads.push({ slot: moodSlot, afterRetirement: resourceRetired });
    return originalRequest;
  });
  const actualMoods = moodService.recentMoods, actualShown = thresholdService.thresholdNoticeShown;
  const moodOriginals: Promise<unknown>[] = [], shownOriginals: Promise<unknown>[] = [];
  const moodObserver = vi.spyOn(moodService, "recentMoods").mockImplementation((...args) => {
    const original = actualMoods(...args); moodOriginals.push(original); void original.catch(() => undefined); return original;
  });
  const shownObserver = vi.spyOn(thresholdService, "thresholdNoticeShown").mockImplementation((...args) => {
    const original = actualShown(...args); shownOriginals.push(original); void original.catch(() => undefined); return original;
  });
  let release!: () => void, reached!: () => void;
  const held = new Promise<void>(resolve => { release = resolve; });
  const entered = new Promise<void>(resolve => { reached = resolve; });
  const nativeGet = kv.getItem.bind(kv), nativeSet = kv.setItem.bind(kv);
  const originals: Promise<unknown>[] = [], returned: Promise<string | null>[] = [], writes: Promise<void>[] = [];
  let armed = true;
  const reading = vi.spyOn(kv, "getItem").mockImplementation((...args) => {
    const original = nativeGet(...args); originals.push(original);
    const result = original.then(async value => {
      if (args[0] === marker && armed) {
        armed = false;
        expect(value).toBeNull();
        reached();
        await held;
      }
      return value;
    });
    returned.push(result);
    return result;
  });
  const writing = vi.spyOn(kv, "setItem").mockImplementation((...args) => {
    const original = nativeSet(...args); originals.push(original); writes.push(original);
    return original;
  });
  let retiring: Awaited<ReturnType<typeof render>> | undefined;
  let next: Awaited<ReturnType<typeof render>> | undefined;
  let stamping: Awaited<ReturnType<typeof render>> | undefined;
  let stampRetirement: Promise<void> | undefined;
  let noticeAtPhysicalStamp = false, nativeRequestWasPending = false;
  let stampRetired = false, committedAfterRetirement = false;
  let allowStampInsights!: () => void;
  const stampInsights = new Promise<void>(resolve => { allowStampInsights = resolve; });
  let putting: { mockRestore(): void } | undefined;
  const drain = async (): Promise<void> => {
    let count = -1;
    while (count !== originals.length + returned.length + writes.length + moodOriginals.length + shownOriginals.length) {
      count = originals.length + returned.length + writes.length + moodOriginals.length + shownOriginals.length;
      const settled = await Promise.allSettled([...originals, ...returned, ...writes, ...moodOriginals, ...shownOriginals]);
      const failure = settled.find(result => result.status === "rejected");
      if (failure?.status === "rejected") throw failure.reason;
      for (let turn = 0; turn < 20; turn++) await Promise.resolve();
    }
  };
  let repeated: Awaited<ReturnType<typeof render>> | undefined;
  try {
    // The positive read forwards a real IndexedDB request and genuinely
    // decrypts the seeded account's mood before the retirement experiment.
    expect(await moodService.recentMoods(key(), OWNER, 30)).toEqual([{ date: "2026-09-01", value: -1 }]);
    expect(admittedMoodReads).toEqual([{ slot: moodSlot, afterRetirement: false }]);
    server(() => response([])); retiring = await render(<PatternsRoute />);
    await vi.waitFor(() => { expect(armed).toBe(false); }); await entered;
    if (shownOriginals.length !== 1) throw new Error("SetupError: the live original threshold helper must own the held GET result");
    await press(retiring, "Leave patterns");
    resourceRetired = true;
    expect(textOf(retiring)).toContain("Current home");
    expect({ sameSignal: sessionAbortSignal() === liveSignal, unAborted: liveSignal?.aborted === false,
      owner: vault.ownerUserId(), sameDataKey: vault.get().dataKey === liveDataKey }).toEqual({ sameSignal: true, unAborted: true, owner: OWNER, sameDataKey: true });
    // Await the unchanged complete threshold/mood helper Promises as well
    // as their actual KV producers. This observes storage admission rather
    // than a private recentMoods call count or a chosen microtask deadline.
    await act(async () => { release(); await drain(); });
    expect(admittedMoodReads.filter(read => read.afterRetirement),
      "A retired Patterns route must not admit a new account mood-log IndexedDB read after its held threshold result").toEqual([]);
    const unseenRetiredStamp = await kv.getItem(marker);
    await act(async () => { retiring!.unmount(); }); retiring = undefined;
    reading.mockRestore(); getting.mockRestore(); moodObserver.mockRestore(); shownObserver.mockRestore();
    await clearThresholdNotice(OWNER);

    // Observe and forward the genuine native put/request. Retire the public
    // view while that authored stamp request is physically still pending.
    const nativePut = IDBObjectStore.prototype.put;
    let stampEntered!: () => void, stampArmed = true;
    const admitted = new Promise<void>(resolve => { stampEntered = resolve; });
    putting = vi.spyOn(IDBObjectStore.prototype, "put").mockImplementation(function (this: IDBObjectStore, ...args) {
      const request = nativePut.apply(this, args);
      if (args[1] === marker && stampArmed) {
        stampArmed = false;
        nativeRequestWasPending = request.readyState === "pending";
        noticeAtPhysicalStamp = textOf(stamping!).includes(t("insights.thresholdNotice"));
        request.transaction!.addEventListener("complete", () => { committedAfterRetirement = stampRetired; });
        stampRetirement = Promise.resolve(act(() => { stamping!.unmount(); }));
        stampRetired = true;
        stampEntered();
      }
      return request;
    });
    server(() => stampInsights.then(() => response([]))); stamping = await render(<PatternsView onCrisis={() => {}} />);
    allowStampInsights();
    await vi.waitFor(() => { expect(stampArmed).toBe(false); }); await admitted; await stampRetirement;
    stamping = undefined; await drain(); putting.mockRestore(); putting = undefined;
    expect(await kv.getItem(marker)).not.toBeNull();
    await clearThresholdNotice(OWNER);
    server(() => response([])); next = await ready();
    expect(textOf(next)).toContain(t("insights.thresholdNotice"));
    expect(await kv.getItem(marker)).not.toBeNull();
    await act(async () => { next!.unmount(); }); next = undefined;
    repeated = await ready();
    expect(textOf(repeated)).not.toContain(t("insights.thresholdNotice"));
    expect({ unseenRetiredStamp, noticeAtPhysicalStamp, nativeRequestWasPending, committedAfterRetirement },
      "only a notice committed in the live chart may spend its one-time stamp").toEqual({
      unseenRetiredStamp: null, noticeAtPhysicalStamp: true, nativeRequestWasPending: true, committedAfterRetirement: true,
    });
  } finally {
    release(); allowStampInsights();
    try { await stampRetirement; await drain(); }
    finally {
      reading.mockRestore(); writing.mockRestore(); putting?.mockRestore();
      getting.mockRestore(); moodObserver.mockRestore(); shownObserver.mockRestore();
      for (const root of [retiring, stamping, next, repeated]) if (root) await act(async () => { root.unmount(); });
      opening.mockRestore(); database?.close(); resetKvConnectionForTests(); setKvBackendForTests(memoryKvBackend());
    }
  }
});

it("a legacy pid-less card cannot borrow the identity or unmute label of an unrelated persisted pattern", async () => {
  const p = pattern("topic", { pattern_pid: "Stryker was here!" });
  server(() => response([p])); const first = await ready(); await press(first, "Mute");
  await vi.waitFor(async () => expect(await readMutedPids(key(), OWNER)).toEqual(new Set(["Stryker was here!"])));
  await act(async () => first.unmount());
  const legacy = pattern("link"); delete legacy.detail.pattern_pid;
  server(() => response([legacy])); const next = await ready();
  const card = next.root.findAllByType("section").find(n => textOfNode(n).includes(legacy.label));
  expect(card).toBeDefined();
  expect(card!.findAllByType("button").map(textOfNode)).toContain("Mute");
  expect(card!.findAllByType("button").map(textOfNode)).not.toContain("Unmute");
});
