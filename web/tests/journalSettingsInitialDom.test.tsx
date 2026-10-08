// @vitest-environment jsdom
import { act, useLayoutEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it } from "vitest";
import { EntryView } from "../src/views/Entry";
import { HistoryView } from "../src/views/History";
import { SettingsView } from "../src/views/Settings";
import { vault } from "../src/vault";
import { t } from "../src/strings";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
let root: Root | undefined;
afterEach(async () => { await act(async () => root?.unmount()); root = undefined; document.body.replaceChildren(); });
it.each(["Entry", "History", "Settings"] as const)("commits an honest first native %s DOM before passive fetch or draft effects", async kind => {
  resetTestState(); installSession("first-native-journal", "first-native-user"); vault.unlock({ authKey: new Uint8Array(32).fill(19), dataKey: new Uint8Array(32).fill(21) }, "first-native-journal");
  stubFetch(url => {
    const path = new URL(url).pathname;
    if (path.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, audio_available: false, sharing_available: false });
    if (path.endsWith("/llm-consent") || path.endsWith("/voice-consent")) return jsonResponse({ enabled: false, active_for_current_policy: false });
    if (path.endsWith("/key-envelope")) return jsonResponse({ key_scheme: "v1", salt: "", kdf_params: null, wrapped_data_key: null });
    return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
  });
  const container = document.createElement("div"); document.body.append(container); const first: { errors: string[]; fields: string[]; text: string; privacy: string }[] = [];
  function ObserveFirst() {
    useLayoutEffect(() => { first.push({ errors: [...container.querySelectorAll('[role="alert"]')].map(n => n.textContent ?? ""), fields: [...container.querySelectorAll("input,textarea")].map(n => (n as HTMLInputElement).value), text: container.textContent ?? "", privacy: [...container.querySelectorAll("section.card")].find(section => section.querySelector("h2")?.textContent === t("settings.privacyDataTitle"))?.textContent ?? "" }); }, []);
    return kind === "Entry" ? <EntryView onSaved={() => {}} /> : kind === "History" ? <HistoryView /> : <SettingsView onLockdown={() => {}} />;
  }
  root = createRoot(container); await act(async () => root!.render(<ObserveFirst />)); expect(first).toHaveLength(1); expect(first[0]!.errors).toEqual([]);
  if (kind === "History") expect(first[0]!.text).toContain(t("common.loading"));
  if (kind === "Entry") { expect(first[0]!.fields).toContain(""); expect(first[0]!.text).not.toContain(t("entry.draftRestoredNote")); }
  if (kind === "Settings") { expect(first[0]!.fields.every(value => value === "")).toBe(true); expect(first[0]!.privacy).toContain(t("common.loading")); }
});
