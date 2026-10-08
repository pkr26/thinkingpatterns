// @vitest-environment jsdom
import { act, useLayoutEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it } from "vitest";
import { MeasuresView } from "../src/views/Measures";
import { PatternsView } from "../src/views/Patterns";
import { vault } from "../src/vault";
import { t } from "../src/strings";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
let root: Root | undefined;
afterEach(async () => { await act(async () => root?.unmount()); root = undefined; document.body.replaceChildren(); });

it.each(["Measures", "Patterns"])("%s first native DOM commit reports no fabricated transport error or answered questions", async kind => {
  resetTestState(); installSession("native-first-chart");
  vault.unlock({ authKey: new Uint8Array(32).fill(7), dataKey: new Uint8Array(32).fill(7) }, "native-first-chart");
  stubFetch(url => new URL(url).pathname.endsWith("/insights")
    ? jsonResponse({ phase: "baseline", active_days: 0, days_remaining: 30, streak: 0, blob: null })
    : jsonResponse([], { headers: { "X-Measures-Revision": "1" } }));
  const container = document.createElement("div"); document.body.append(container);
  const commits: { errors: string[]; progress: string[]; loading: string }[] = [];
  function Chart() {
    useLayoutEffect(() => { commits.push({
      errors: [...container.querySelectorAll('[role="alert"]')].map(n => n.textContent ?? ""),
      progress: [...container.querySelectorAll('[role="progressbar"]')].map(n => n.getAttribute("aria-label") ?? ""),
      loading: container.textContent ?? "",
    }); }, []);
    return kind === "Measures" ? <MeasuresView onCrisis={() => {}} /> : <PatternsView onCrisis={() => {}} />;
  }
  root = createRoot(container); await act(async () => root!.render(<Chart />));
  expect(commits).toHaveLength(1); expect(commits[0]!.errors).toEqual([]);
  if (kind === "Measures") {
    expect(commits[0]!.loading).toContain("0 of 9 answered");
    expect(commits[0]!.progress).toContain("0 of 9 answered");
    expect(commits[0]!.loading).not.toContain(t("measures.item9Title"));
  } else expect(commits[0]!.loading).toContain("Reading your baseline");
});
