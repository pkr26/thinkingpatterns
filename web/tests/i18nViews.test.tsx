/** Locale-flip CONSUMPTION test (M-W5, audit 2026-09-26): this is the test
 *  that would have caught the drift — the full en/es catalogs existed and
 *  passed key-parity while every view rendered hardcoded English. Flip the
 *  locale and assert Spanish copy (and Spanish chips/questions) actually
 *  reach the rendered tree. */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EntryView } from "../src/views/Entry";
import { MeasuresView } from "../src/views/Measures";
import { HistoryView } from "../src/views/History";
import { QuestionView } from "../src/views/Question";
import { genericQuestionForDate } from "../src/genericQuestions";
import { localDateISO } from "../src/dates";
import { __setLocaleForTests } from "../src/strings";
import { setKvBackendForTests, type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { render, settle, textOf } from "./helpers/rtr";

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
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(3);
  vault.unlock({ authKey: key(), dataKey: key() }, USER);
});
afterEach(() => {
  __setLocaleForTests("en");
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
});

describe("views consume the active locale (M-W5, audit 2026-09-26)", () => {
  it("Entry renders Spanish copy and Spanish prompt chips under es", async () => {
    __setLocaleForTests("es");
    stubFetch(() => jsonResponse({}, { status: 404 }));
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    expect(textOf(root)).toContain("La entrada de hoy");
    // textOf's node set skips <label>/<input> — assert the editor's
    // localized label/placeholder through their props instead.
    const area = root.root.findAllByType("textarea")[0]!;
    expect(String(area.props.placeholder)).toContain("Escriba con libertad");
    const label = area.parent as unknown as { children: React.ReactNode[] };
    expect(label.children.some((child) => typeof child === "string" && child.includes("¿Cómo estuvo hoy?"))).toBe(true);
    // The chips follow the locale (E-3 parity): today's Spanish starters
    // are exactly what renders.
    const { promptChipsFor } = await import("../src/promptChips");
    for (const chip of promptChipsFor(new Date(), 3, "es")) {
      expect(textOf(root)).toContain(chip);
    }
  });

  it("Measures renders the Spanish instrument and honest error copy under es", async () => {
    __setLocaleForTests("es");
    stubFetch((url) => {
      if (url.startsWith(`${ORIGIN}/api/v1/measures?`)) return jsonResponse([], { headers: { "X-Measures-Revision": "2" } });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<MeasuresView onCrisis={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain("Cuestionarios de bienestar");
    expect(textOf(root)).toContain("Poco interés o placer en hacer las cosas");
    expect(textOf(root)).toContain("Para nada"); // option0, localized
    expect(textOf(root)).not.toContain("Not at all");
  });

  it("History's locked-branch copy is Spanish under es", async () => {
    __setLocaleForTests("es");
    vault.lock();
    const root = await render(<HistoryView />);
    await settle(40, 3);
    expect(textOf(root)).toContain("Su sesión se bloqueó — inicie sesión de nuevo.");
  });

  it("Question's baseline 404 branch serves the Spanish generic question under es", async () => {
    __setLocaleForTests("es");
    stubFetch((url) => {
      if (url.endsWith("/questions/today")) return jsonResponse({ detail: "none" }, { status: 404 });
      return jsonResponse({}, { status: 404 });
    });
    const root = await render(<QuestionView onRefreshed={() => undefined} />);
    await settle(40, 4);
    expect(textOf(root)).toContain(genericQuestionForDate(localDateISO(), "es"));
    expect(textOf(root)).toContain("La pregunta de hoy");
  });
});
