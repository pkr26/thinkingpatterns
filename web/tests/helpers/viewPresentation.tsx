import type { ReactElement } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { setKvBackendForTests } from "../../src/kvstore";
import { __setLocaleForTests } from "../../src/strings";
import { vault } from "../../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./api";
import { publicSurface } from "./publicSurface";
import { render, settle } from "./rtr";

/** Public rendered copy, layout and accessibility states. Callback behavior
 * remains in each view's interaction suites; no source objects are serialized. */
export function viewPresentation(name: string, make: () => ReactElement): void {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-05T12:00:00Z"));
    resetTestState(); __setLocaleForTests("en");
    const records = new Map<string, string>();
    setKvBackendForTests({ getItem: async key => records.get(key) ?? null, setItem: async (key, value) => { records.set(key, value); }, removeItem: async key => { records.delete(key); }, keys: async () => [...records.keys()] });
    installSession("presentation-owner");
    const key = () => new Uint8Array(new ArrayBuffer(32)).fill(8);
    vault.unlock({ authKey: key(), dataKey: key() }, "presentation-owner");
    stubFetch(url => {
      const path = new URL(url).pathname;
      if (path.endsWith("/meta")) return jsonResponse({ version: "1", api_version: "v1", unlock_days: 30, llm_available: false, sharing_available: true, sharing_disclosure_version: "v3" });
      if (path.endsWith("/llm-consent")) return jsonResponse({ enabled: false });
      if (path.endsWith("/entries")) return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
      if (path.endsWith("/measures")) return jsonResponse([], { headers: { "X-Measures-Revision": "1" } });
      if (path.endsWith("/consents") || path.endsWith("/account/access-log")) return jsonResponse([]);
      return jsonResponse({ detail: "not yet available", code: "not_found" }, { status: 404 });
    });
  });
  afterEach(() => { vi.useRealTimers(); setKvBackendForTests(null); __setLocaleForTests("en"); });
  it.each(["en", "es"] as const)(`${name} renders its settled public empty-account surface in %s`, async locale => {
    __setLocaleForTests(locale); const root = await render(make()); await settle(40, 3);
    expect(publicSurface(root.toJSON())).toMatchSnapshot();
  });
  it(`${name} renders a safe public surface after its vault is locked`, async () => {
    vault.lock(); const root = await render(make()); await settle(40, 3);
    expect(publicSurface(root.toJSON())).toMatchSnapshot();
  });
}
