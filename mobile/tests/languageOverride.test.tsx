/** The in-app language override (deep audit 2026-09-29, P2): a bilingual
 *  user with an English-locale device used to get a forced-English app —
 *  and the two module-load tr() tables froze the import-time locale even
 *  for setLocale callers. Pins the preference round-trip, the immediate
 *  application, and the per-render tables following the locale. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

vi.mock("../src/secureStore", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/secureStore")>();
  const map = new Map<string, string>();
  return {
    ...actual,
    secureStore: {
      getItem: async (k: string) => map.get(k) ?? null,
      setItem: async (k: string, v: string) => {
        map.set(k, v);
      },
      removeItem: async (k: string) => {
        map.delete(k);
      },
    },
  };
});

import {
  applyLanguageChoice,
  applyStoredLanguageChoice,
  readLanguageChoice,
  writeLanguageChoice,
} from "../src/languagePref";
import { getLocale, setLocale, t as tr } from "../src/strings";
import { bottomNavItems } from "../src/components/BottomNav";
import { render, textOf } from "./helpers/rtr";

describe("language preference storage", () => {
  it("defaults to device when nothing (or garbage) is stored", async () => {
    expect(await readLanguageChoice()).toBe("device");
  });

  it("round-trips a choice and applies it immediately", async () => {
    await writeLanguageChoice("es");
    expect(await readLanguageChoice()).toBe("es");
    expect(getLocale()).toBe("es");
    await writeLanguageChoice("device");
    expect(await readLanguageChoice()).toBe("device");
  });

  it("startup application honors the stored choice and never throws", async () => {
    await writeLanguageChoice("en");
    setLocale("es"); // simulate a device-detected es startup
    await applyStoredLanguageChoice();
    expect(getLocale()).toBe("en");
    // applyLanguageChoice("device") returns to detection.
    applyLanguageChoice("device");
  });
});

describe("the former module-load tables follow the locale", () => {
  beforeEach(() => {
    setLocale("en");
  });

  it("bottomNavItems() re-renders under the current locale", () => {
    const en = bottomNavItems().map((i) => i.label);
    expect(en).toContain(tr("nav.today"));
    setLocale("es");
    const es = bottomNavItems().map((i) => i.label);
    expect(es).not.toEqual(en);
    expect(es).toContain(tr("nav.today")); // tr() now reads Spanish too
  });

  it("BottomNav renders the Spanish labels after a switch", async () => {
    setLocale("es");
    const { BottomNav } = await import("../src/components/BottomNav");
    const root = await render(
      <BottomNav current="Entry" navigation={{ navigate: vi.fn() }} />,
    );
    expect(textOf(root)).toContain(tr("nav.today"));
  });
});
