import { readFileSync } from "node:fs";
import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { moodFill, moodInk, notifyPaletteChanged, subscribePalette } from "../src/tokens";
import { MOOD_OPTIONS } from "../src/mood";
import { MoodScale } from "../src/ui";
import { HistoryView } from "../src/views/History";
import { encryptEntry } from "../src/crypto/patient";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { render, settle, textOf } from "./helpers/rtr";

const css = readFileSync(new URL("../public/app.css", import.meta.url), "utf8");
function cssValue(theme: string, token: string): string {
  const start = css.indexOf(theme === "dark" ? '[data-theme="dark"] {' : ":root {");
  const block = css.slice(start, css.indexOf("}", start));
  const match = block.match(new RegExp(`--${token}:\\s*(#[0-9a-fA-F]{6})`));
  if (!match) throw new Error(`Missing visible CSS token ${theme}/${token}`);
  return match[1]!;
}
function contrast(a: string, b: string): number {
  const luminance = (hex: string) => {
    expect(hex).toMatch(/^#[0-9a-f]{6}$/i);
    const channels = [1, 3, 5].map((offset) => {
      const value = Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
      return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
    });
    return channels[0]! * 0.2126 + channels[1]! * 0.7152 + channels[2]! * 0.0722;
  };
  const left = luminance(a), right = luminance(b);
  return (Math.max(left, right) + 0.05) / (Math.min(left, right) + 0.05);
}
let dataKey: Uint8Array<ArrayBuffer>;
const owner = "token-consumer-owner";
let element: { dataset: { theme: string } };

beforeEach(() => {
  resetTestState();
  installSession(owner);
  dataKey = new Uint8Array(new ArrayBuffer(32)).fill(11);
  vault.unlock({ authKey: dataKey, dataKey }, owner);
  element = { dataset: { theme: "light" } };
  vi.stubGlobal("document", { documentElement: element });
});
afterEach(() => vi.unstubAllGlobals());

it("draws five readable check-in faces in both themes and redraws when the palette changes", async () => {
  const root = await render(<MoodScale options={MOOD_OPTIONS} value={0} onChange={() => {}} />);
  for (const theme of ["light", "dark", "light"]) {
    await act(async () => { element.dataset.theme = theme; notifyPaletteChanged(); });
    const buttons = root.root.findAllByType("button");
    expect(buttons).toHaveLength(5);
    expect(new Set(buttons.map(button => button.props.style["--face"])).size).toBe(5);
    expect(new Set(buttons.map(button => button.props.style["--face-soft"])).size).toBe(5);
    expect(new Set(buttons.map(button => button.props.style["--face-strong"])).size).toBe(5);
    for (const button of buttons) {
      const style = button.props.style;
      expect(style["--face"]).toMatch(/^#[0-9a-f]{6}$/i);
      expect(contrast(style["--face-strong"], style["--face-soft"])).toBeGreaterThanOrEqual(4.5);
      expect(contrast(style["--face-strong"], cssValue(theme, "surface"))).toBeGreaterThanOrEqual(4.5);
    }
  }
});

it("draws readable check-in faces before a document exists and releases its palette subscription on unmount", async () => {
  vi.stubGlobal("document", undefined);
  const root = await render(<MoodScale options={MOOD_OPTIONS} value={0} onChange={() => {}} />);
  for (const button of root.root.findAllByType("button")) {
    expect(contrast(button.props.style["--face-strong"], button.props.style["--face-soft"])).toBeGreaterThanOrEqual(4.5);
  }
  await act(async () => { root.unmount(); notifyPaletteChanged(); });
});

it("stops publishing theme changes to a disposed chart consumer", () => {
  const redraw = vi.fn();
  const dispose = subscribePalette(redraw);
  notifyPaletteChanged(); expect(redraw).toHaveBeenCalledOnce();
  dispose(); notifyPaletteChanged(); expect(redraw).toHaveBeenCalledOnce();
});

it("renders a readable neutral calendar marker when there is no mood reading, including before the DOM exists", async () => {
  for (const theme of ["light", "dark", undefined]) {
    vi.stubGlobal("document", theme ? { documentElement: { dataset: { theme } } } : undefined);
    const root = await render(<button style={{ backgroundColor: moodFill(null), color: moodInk(null) }}>17</button>);
    const style = root.root.findByType("button").props.style;
    expect(style.backgroundColor).toBe(cssValue(theme ?? "light", "mood-0"));
    expect(contrast(style.color, style.backgroundColor)).toBeGreaterThanOrEqual(4.5);
  }
});

it("draws calendar mood bins matching the surrounding CSS theme with readable day numbers", async () => {
  const now = new Date();
  const prefix = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}`;
  const cases = [[-0.301, "--2"], [-0.3, "--2"], [-0.051, "--1"], [-0.05, "--1"], [0.05, "-0"], [0.051, "-1"], [0.3, "-1"], [0.301, "-2"]] as const;
  const rows = await Promise.all(cases.map(async ([value], index) => {
    const date = `${prefix}-${String(index + 1).padStart(2, "0")}`;
    const entryId = `theme-day-${index}`;
    const { blobB64 } = await encryptEntry(dataKey, owner, entryId, "private writing", `${date}T12:00:00Z`, value, undefined, 1);
    return { id: entryId, client_entry_id: entryId, blob: blobB64, entry_date: date, received_at: `${date}T12:00:01Z`, content_version: 1 };
  }));
  stubFetch((url) => jsonResponse(url.includes("offset=0") ? rows : [], { headers: { "X-Entries-Revision": "7", ...(url.includes("offset=0") ? { "X-Next-Offset": "8" } : {}) } }));
  const root = await render(<HistoryView />);
  for (const theme of ["light", "dark", undefined]) {
    await act(async () => { vi.stubGlobal("document", theme ? { documentElement: { dataset: { theme } } } : undefined); notifyPaletteChanged(); });
    await settle(40, 3);
    {
      for (let index = 0; index < cases.length; index++) {
        const date = `${prefix}-${String(index + 1).padStart(2, "0")}`;
        const tile = root.root.findAllByType("button").find((button) => button.props["aria-label"]?.startsWith(`${date} — `));
        expect(tile, textOf(root)).toBeDefined();
        const { backgroundColor, color } = tile!.props.style;
        expect(backgroundColor).toBe(cssValue(theme ?? "light", `mood${cases[index]![1]}`));
        expect(contrast(color, backgroundColor)).toBeGreaterThanOrEqual(4.5);
      }
    }
  }
});
