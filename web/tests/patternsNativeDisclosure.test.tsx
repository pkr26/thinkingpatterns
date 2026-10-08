// @vitest-environment jsdom
import { webcrypto } from "node:crypto";
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PatternsView } from "../src/views/Patterns";
import { encrypt, toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { vault } from "../src/vault";
import { readMutedPids } from "../src/patternMutes";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
let root: Root | undefined;
let OWNER = "native-disclosure-owner", scenario = 0;
const key = () => new Uint8Array(32).fill(13);
beforeEach(() => { OWNER = `native-disclosure-owner-${++scenario}`; vi.stubGlobal("crypto", webcrypto); resetTestState(); installSession(OWNER); vault.unlock({ authKey: key(), dataKey: key() }, OWNER); });
afterEach(async () => { await act(async () => root?.unmount()); root = undefined; document.body.replaceChildren(); vi.unstubAllGlobals(); });
async function chart(legacy: boolean): Promise<HTMLDivElement> {
  const rows = [
    { kind: "topic", label: "First authored observation", occurrences: 1, confidence: .7, detail: { pattern_pid: "first" } },
    { kind: "link", label: "Second authored observation", occurrences: 2, confidence: .8, detail: legacy ? {} : { pattern_pid: "second" } },
    ...(legacy ? [{ kind: "inertia", label: "Third authored observation", occurrences: 3, confidence: .9, detail: {} }] : []),
  ];
  const blob = await encrypt(key(), new TextEncoder().encode(JSON.stringify({ v: 2, state_seq: 4, stats: { patterns: rows } })), buildAad("insights", OWNER, "patterns"));
  stubFetch(() => jsonResponse({ phase: "insight", active_days: 40, days_remaining: 0, streak: 1, state_seq: 4, blob: toBase64(blob) }));
  const container = document.createElement("div"); document.body.append(container); root = createRoot(container);
  await act(async () => root!.render(<PatternsView onCrisis={() => {}} />));
  await vi.waitFor(() => expect(container.querySelectorAll("details")).toHaveLength(rows.length));
  return container;
}
it("muting an earlier card preserves the native disclosure opened for another persistent pattern", async () => {
  const container = await chart(false);
  const details = container.querySelectorAll("details");
  await act(async () => details[1]!.querySelector("summary")!.click());
  expect(details[1]!.open).toBe(true);
  const mute = [...container.querySelectorAll("button")].find(n => n.textContent === "Mute")!;
  await act(async () => mute.click());
  expect(container.querySelectorAll("details")).toHaveLength(1);
  expect(container.querySelector("details")!.open).toBe(true);
  expect(container.querySelector("details")!.parentElement!.textContent).toContain("Second authored observation");
  await vi.waitFor(async () => expect(await readMutedPids(key(), OWNER)).toEqual(new Set(["first"])));
});
it("muting and restoring a persistent card leaves each separate legacy observation exactly once", async () => {
  const container = await chart(true);
  const titles = () => [...container.querySelectorAll("h2")].map(n => n.textContent).filter(text => text?.includes("authored observation"));
  expect(titles()).toEqual(["First authored observation", "Second authored observation", "Third authored observation"]);
  await act(async () => [...container.querySelectorAll("button")].find(n => n.textContent === "Mute")!.click());
  expect(titles()).toEqual(["Second authored observation", "Third authored observation"]);
  await vi.waitFor(async () => expect(await readMutedPids(key(), OWNER)).toEqual(new Set(["first"])));
  const restore = [...container.querySelectorAll("button")].find(n => n.textContent?.startsWith("Unmute"))!;
  await act(async () => restore.click());
  expect(titles()).toEqual(["First authored observation", "Second authored observation", "Third authored observation"]);
  await vi.waitFor(async () => expect(await readMutedPids(key(), OWNER)).toEqual(new Set()));
});
