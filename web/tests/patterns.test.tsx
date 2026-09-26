/** Patterns + Question views and the feedback queue (P6): baseline ring +
 * local trend, pattern cards with evidence panels, the sensitive
 * non-quoting contract, mutes, the explicit-only recompute, and the
 * feedback blob's encrypted ride. Real crypto; fetch stubs at the edge. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { PatternsView } from "../src/views/Patterns";
import { QuestionView } from "../src/views/Question";
import { buildFeedbackBlob, clearFeedback, recordFeedbackTap, recordPatternMute } from "../src/questionFeedback";
import { decrypt, encrypt, fromBase64, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { genericQuestionForDate } from "../src/genericQuestions";
import { localDateISO } from "../src/dates";
import { getLocale } from "../src/strings";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { flush, press, render, settle, textOf } from "./helpers/rtr";

const ORIGIN = "http://localhost:5173";
const DATA_KEY = new Uint8Array(new ArrayBuffer(32)).fill(6);
const USER = "user-1";
const NONCE = fromBase64("AAAAAAAAAAAAAAAA");

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
  };
};

const insightsResponse = async (patterns: unknown[], phase = "active", stateSeq = 3): Promise<Response> => {
  const payload = JSON.stringify({ v: 2, stats: { patterns }, state_seq: stateSeq });
  const blob = await encrypt(DATA_KEY, new TextEncoder().encode(payload), buildAad("insights", USER, "patterns"));
  return jsonResponse({ phase, active_days: 40, streak: 3, days_remaining: 0, blob: toBase64(blob), state_seq: stateSeq });
};

const questionResponse = async (pid?: string): Promise<Response> => {
  const payload = JSON.stringify({ for_date: "2026-09-25", question: "What took up space today?", ...(pid ? { pattern_pid: pid } : {}) });
  const blob = await encrypt(DATA_KEY, new TextEncoder().encode(payload), buildAad("question", USER, "2026-09-25"));
  return jsonResponse({ for_date: "2026-09-25", blob: toBase64(blob) });
};

function stubEverything(responses: { insights?: () => Promise<Response> | Response; question?: () => Promise<Response> | Response; entries?: () => Response }): ReturnType<typeof stubFetch> {
  return stubFetch((url) => {
    if (url.endsWith("/insights") && !url.includes("recompute")) return responses.insights ? responses.insights() : jsonResponse({ phase: "baseline", active_days: 1, streak: 1, days_remaining: 29, blob: null });
    if (url.endsWith("/questions/today")) return responses.question ? responses.question() : jsonResponse({ detail: "none" }, { status: 404 });
    if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return responses.entries ? responses.entries() : jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
    return jsonResponse({ detail: "unmatched" }, { status: 404 });
  });
}

beforeEach(() => {
  resetTestState();
  setKvBackendForTests(memoryBackend());
  installSession(USER);
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(6);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("PatternsView", () => {
  it("baseline: honest progress + the device-local trend, never synced", async () => {
    stubEverything({});
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("Building your baseline");
    expect(textOf(root)).toContain("29 to go");
    expect(textOf(root)).toContain("never synced");
  });

  it("renders pattern cards with lifecycle labels and evidence panels", async () => {
    stubEverything({
      insights: () => insightsResponse([
        { kind: "temporal", label: "'work' concentrates on Sundays", occurrences: 9, confidence: 0.87, detail: { pattern_pid: "temporal:work", pattern_state: "confirmed", sample_days: 180, first_seen: "2026-08-02", last_seen: "2026-09-20" } },
        { kind: "link", label: "the day after 'sleep' comes up, entries read lower", occurrences: 6, confidence: 0.71, detail: { pattern_pid: "link:sleep", pattern_state: "emerging", is_new: true } },
      ]),
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("'work' concentrates on Sundays");
    expect(textOf(root)).toContain("established");
    expect(textOf(root)).toContain("seen 9 times");
    expect(textOf(root)).toContain("early evidence");
    expect(textOf(root)).toContain("new");
    // The evidence panel's content (the summary element itself is not in
    // textOf's joined node set; its expanded content is):
    expect(textOf(root)).toContain("Window: the last 180 days");
    expect(textOf(root)).toContain("your own writing schedule");
    expect(textOf(root)).toContain("No advice, no diagnosis");
  });

  it("a sensitive pattern NEVER quotes its text and offers support", async () => {
    stubEverything({
      insights: () => insightsResponse([
        { kind: "rumination", label: "I want to disappear forever", occurrences: 7, confidence: 0.9, detail: { pattern_pid: "rumination:x", pattern_state: "confirmed", sensitive: true } },
      ]),
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("A difficult thought has been returning");
    expect(textOf(root)).not.toContain("disappear");
    const onCrisis = vi.fn();
    const root2 = await render(<PatternsView onCrisis={onCrisis} />);
    await settle(40, 4);
    await press(root2, "Get support");
    expect(onCrisis).toHaveBeenCalledTimes(1);
  });

  it("a suppress-tier label WITHOUT the flag is still never quoted (belt-and-braces)", async () => {
    // The payload claims sensitivity: false, but the label matches the
    // crisis suppress tier — the exact regression mobile and the backend
    // both defend against (audit 2026-09-25). The web view must too.
    stubEverything({
      insights: () => insightsResponse([
        { kind: "rumination", label: "everyone would be better off", occurrences: 5, confidence: 0.8, detail: { pattern_pid: "rumination:unflagged", pattern_state: "confirmed", sensitive: false } },
      ]),
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("A difficult thought has been returning");
    expect(textOf(root)).not.toContain("better off");
  });

  it("muting hides a card, persists locally, and queues the server-side mute", async () => {
    stubEverything({
      insights: () => insightsResponse([
        { kind: "temporal", label: "'work' on Sundays", occurrences: 9, confidence: 0.87, detail: { pattern_pid: "temporal:work", pattern_state: "confirmed" } },
      ]),
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    await press(root, "Mute");
    await settle(40, 2);
    // The card body is gone; the label survives only on the unmute control.
    expect(textOf(root)).not.toContain("seen 9 times");
    expect(textOf(root)).toContain("1 pattern muted");
    // The queued feedback blob carries the mute:
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).not.toBeNull();
    const opened = await decrypt(DATA_KEY, fromBase64(blob!), buildAad("feedback", USER, new Date().toISOString().slice(0, 10)));
    const parsed = JSON.parse(new TextDecoder().decode(opened)) as { muted: string[]; unmuted: string[] };
    expect(parsed.muted).toEqual(["temporal:work"]);
  });

  it("muting a pattern leaves no readable pid in localStorage — the set persists as one encrypted kv blob (M-W4, audit 2026-09-26)", async () => {
    // Pattern ids are CONTENT-DERIVED ("topic:divorce"): the pre-fix flow
    // wrote them to plaintext localStorage. The mute set must live behind
    // the data-key-encrypted kv seam, and the server-side sync must keep
    // riding the feedback queue unchanged.
    const kvMap = new Map<string, string>();
    setKvBackendForTests({
      async getItem(k) {
        return kvMap.get(k) ?? null;
      },
      async setItem(k, v) {
        kvMap.set(k, v);
      },
      async removeItem(k) {
        kvMap.delete(k);
      },
      async keys() {
        return [...kvMap.keys()];
      },
    });
    stubEverything({
      insights: () => insightsResponse([
        { kind: "topic", label: "'divorce' keeps taking up space", occurrences: 9, confidence: 0.87, detail: { pattern_pid: "topic:divorce", pattern_state: "confirmed" } },
      ]),
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    await press(root, "Mute");
    await settle(40, 3);
    // localStorage carries NO readable pid token...
    const win = (globalThis as { window?: { localStorage?: Storage } }).window;
    const localScrape: string[] = [];
    for (let i = 0; i < (win?.localStorage?.length ?? 0); i += 1) {
      const k = win!.localStorage!.key(i)!;
      localScrape.push(`${k}=${win!.localStorage!.getItem(k)}`);
    }
    expect(localScrape.join("\n")).not.toContain("divorce");
    expect(localScrape.join("\n")).not.toContain("topic:");
    // ...and the kv blob holds the pid ONLY under the data key.
    const stored = kvMap.get("mindpattern.patternMutes.v1.user-1");
    expect(stored).toBeTruthy();
    expect(stored!).not.toContain("divorce");
    const opened = await decrypt(DATA_KEY, fromBase64(stored!), buildAad("pattern-mutes", USER));
    expect(JSON.parse(new TextDecoder().decode(opened))).toEqual(["topic:divorce"]);
    // The server-side mute sync is intact (questionFeedback queue):
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).not.toBeNull();
    const feedback = await decrypt(DATA_KEY, fromBase64(blob!), buildAad("feedback", USER, new Date().toISOString().slice(0, 10)));
    expect((JSON.parse(new TextDecoder().decode(feedback)) as { muted: string[] }).muted).toEqual(["topic:divorce"]);
  });

  it("a pre-fix plaintext mute list is adopted once and the plaintext copy removed (M-W4)", async () => {
    const win = (globalThis as { window?: { localStorage?: Storage } }).window;
    win?.localStorage?.setItem("mindpattern.mutedPids.v1.user-1", JSON.stringify(["topic:legacy"]));
    stubEverything({
      insights: () => insightsResponse([
        { kind: "topic", label: "'work' on Sundays", occurrences: 4, confidence: 0.8, detail: { pattern_pid: "topic:work", pattern_state: "confirmed" } },
        ]),
    });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    // The legacy plaintext is gone...
    expect(win?.localStorage?.getItem("mindpattern.mutedPids.v1.user-1")).toBeNull();
    // ...and its pid now lives encrypted, decryptable under the data key.
    const { readMutedPids } = await import("../src/patternMutes");
    const pids = await readMutedPids(DATA_KEY, USER);
    expect([...pids]).toEqual(["topic:legacy"]);
  });

  it("the one-time threshold notice appears exactly once", async () => {
    stubEverything({ insights: () => insightsResponse([]) });
    const root = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("Your patterns are live");
    const second = await render(<PatternsView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(second)).not.toContain("Your patterns are live");
  });
});

describe("QuestionView", () => {
  it("shows today's decrypted question and records a feedback tap privately", async () => {
    stubEverything({ question: () => questionResponse("temporal:work") });
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("What took up space today?");
    await press(root, "This resonated");
    await settle(40, 2);
    expect(textOf(root)).toContain("Noted");
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).not.toBeNull();
    const opened = await decrypt(DATA_KEY, fromBase64(blob!), buildAad("feedback", USER, new Date().toISOString().slice(0, 10)));
    const parsed = JSON.parse(new TextDecoder().decode(opened)) as { feedback: { pid: string; resonated: boolean }[] };
    expect(parsed.feedback).toEqual([{ pid: "temporal:work", resonated: true }]);
    await clearFeedback(USER);
    expect(await buildFeedbackBlob(DATA_KEY, USER)).toBeNull();
  });

  it("baseline 404 renders today's built-in question with the honest caption (M-W5, audit 2026-09-26)", async () => {
    // The generic-question pool used to be dead code on the web — the 404
    // branch now renders today's localized on-device question, like mobile.
    stubEverything({});
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain(genericQuestionForDate(localDateISO(), getLocale()));
    expect(textOf(root)).toContain("small built-in set");
  });

  it("the explicit recompute: single-use session, feedback attached, refresh note", async () => {
    await recordFeedbackTap(DATA_KEY, USER, "temporal:work", false);
    const calls: { url: string; init: RequestInit }[] = [];
    stubFetch((url, init) => {
      calls.push({ url, init });
      if (url.endsWith("/processing/sessions")) return jsonResponse({ session_token: "pst-1", expires_in: 300 });
      if (url.endsWith("/insights/recompute")) return jsonResponse({ phase: "active", days_remaining: 0 });
      if (url.endsWith("/insights")) return jsonResponse({ phase: "active", active_days: 40, streak: 2, days_remaining: 0, blob: null });
      if (url.startsWith(`${ORIGIN}/api/v1/entries?`)) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const onRefreshed = vi.fn();
    const root = await render(<QuestionView onRefreshed={onRefreshed} />);
    await settle(40, 4);
    await press(root, "Refresh patterns");
    await settle(40, 4);
    expect(onRefreshed).toHaveBeenCalledWith("Patterns refreshed.");
    const sessionCall = calls.find((call) => call.url.endsWith("/processing/sessions"));
    expect(sessionCall).toBeDefined();
    // The data key traveled ONLY inside the single-use session open —
    // pinned by the mock order: sessions BEFORE recompute, token in header.
    const recomputeCall = calls.find((call) => call.url.endsWith("/insights/recompute"));
    expect(recomputeCall).toBeDefined();
    expect((recomputeCall!.init.headers as Record<string, string>)["X-Processing-Token"]).toBe("pst-1");
    expect(JSON.parse(String(recomputeCall!.init.body))).toHaveProperty("feedback_blob");
    // The feedback queue was consumed:
    expect(await buildFeedbackBlob(DATA_KEY, USER)).toBeNull();
    expect(textOf(root)).toContain("ONLY action that sends your key");
  });
});

describe("questionFeedback queue semantics", () => {
  it("last mute write wins per pid; taps accumulate; encrypted at rest", async () => {
    await recordPatternMute(DATA_KEY, USER, "p1", true);
    await recordPatternMute(DATA_KEY, USER, "p2", true);
    await recordPatternMute(DATA_KEY, USER, "p1", false); // unmute p1
    await recordFeedbackTap(DATA_KEY, USER, "p3", true);
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    const opened = await decrypt(DATA_KEY, fromBase64(blob!), buildAad("feedback", USER, new Date().toISOString().slice(0, 10)));
    const parsed = JSON.parse(new TextDecoder().decode(opened)) as { feedback: unknown[]; muted: string[]; unmuted: string[] };
    expect(parsed.muted).toEqual(["p2"]);
    expect(parsed.unmuted).toEqual(["p1"]);
    expect(parsed.feedback.length).toBe(1);
  });
});
