/**
 * The i18n module (2026-09-19): the t() contract (total lookup, {var}
 * interpolation, es→en→key fallback), catalog completeness (es carries
 * every en key — a partial Spanish build must never ship), the locale
 * seam, and screen-level renders under es (Spanish copy appears, English
 * does not, crisis numbers/URLs never move).
 *
 * The suite pins "en" via tests/helpers/i18nSetup.ts; these tests flip
 * the seam explicitly and restore it in afterEach.
 */
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

// Same react-native layering as the crisis screen suite: controllable
// Linking/Platform over the base rnMock primitives.
const mocks = vi.hoisted(() => ({
  openURL: vi.fn(async (_url: string) => true),
  platform: { os: "ios" as "ios" | "android" },
}));
vi.mock("react-native", async (importOriginal) => {
  const actual = await importOriginal<typeof import("react-native")>();
  return {
    ...actual,
    Platform: {
      OS: mocks.platform.os,
      select: <T,>(opts: { ios?: T; android?: T; native?: T; default?: T }): T => {
        const perPlatform = mocks.platform.os === "ios" ? opts.ios : opts.android;
        return perPlatform ?? opts.native ?? (opts.default as T);
      },
    },
    Linking: { openURL: mocks.openURL },
  };
});

// EntryScreen harness (mirrors tests/screens/entryScreen.test.tsx): the
// screen is imported lazily INSIDE the es tests, after the locale flip —
// module-load-time catalog lookups (nav labels) must resolve in Spanish,
// exactly as they do in production where strings.ts initializes first.
vi.mock("../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

vi.mock("../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/MindPatternCrypto")>();
  return { ...actual, encryptEntry: vi.fn(() => ({ blobB64: "QkxPQg==" })) };
});

vi.mock("../src/moodLog", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/moodLog")>();
  return { ...actual, recordMood: vi.fn(async () => {}), recentMoods: vi.fn(async () => []), localStreak: vi.fn(async () => 0), localDateISO: vi.fn(() => "2026-09-19") };
});

vi.mock("../src/offlineQueue", () => ({
  QueueFullError: class extends Error {},
  QueueAbandonedError: class extends Error {},
  enqueue: vi.fn(async () => {}),
  flushQueue: vi.fn(async () => 0),
}));

let sessionState: Record<string, unknown>;
vi.mock("../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/store")>();
  return { ...actual, useSession: () => sessionState };
});

const {
  t,
  setLocale,
  getLocale,
  __setLocaleForTests,
  dateLocaleTag,
  enCatalog,
  esCatalog,
} = await import("../src/strings");

afterEach(() => {
  __setLocaleForTests("en");
  Alert.alert.mockClear();
});

describe("t() under the pinned English locale", () => {
  it("resolves a known key to its English copy", () => {
    expect(getLocale()).toBe("en");
    expect(t("crisis.call988")).toBe("Call or text 988");
  });

  it("interpolates {name} placeholders (strings and numbers) and leaves unknown ones literal", () => {
    expect(t("entry.daysToPatterns", { active: 3, total: 30 })).toBe("3/30 days to your patterns");
    expect(t("history.entryA11y", { date: "Monday" })).toBe("Entry from Monday");
    expect(t("insights.desc.temporal", { label: "work", count: 4, day: "Friday" }))
      .toBe("You've mentioned 'work' 4 times, most often on Fridays.");
    // A var the template never mentions is ignored; a placeholder with no
    // var stays visible for review instead of vanishing.
    expect(t("common.cancel", { unused: "x" })).toBe("Cancel");
    expect(t("crisis.actionA11y")).toBe("{label} — {detail}");
  });

  it("never throws: a key missing everywhere returns the raw key", () => {
    expect(t("no.such.key")).toBe("no.such.key");
  });
});

describe("the es→en→key fallback chain", () => {
  it("resolves Spanish copy under the es locale", () => {
    __setLocaleForTests("es");
    expect(t("crisis.call988")).toBe("Llame o envíe un mensaje de texto al 988");
  });

  it("falls back to ENGLISH when a key is missing in es (never the raw key)", () => {
    const key = "crisis.title";
    const spanish = esCatalog[key];
    delete esCatalog[key];
    try {
      __setLocaleForTests("es");
      expect(t(key)).toBe(enCatalog[key]);
    } finally {
      esCatalog[key] = spanish!;
    }
    expect(t(key)).not.toBe(enCatalog[key]); // restored: Spanish again
  });
});

describe("catalog completeness (a partial Spanish build must never ship)", () => {
  it("the es catalog carries every en key with non-empty copy", () => {
    const missing = Object.keys(enCatalog).filter(
      (key) => typeof esCatalog[key] !== "string" || esCatalog[key]!.length === 0,
    );
    expect(missing).toEqual([]);
  });

  it("the es catalog adds no keys the en catalog lacks (en is the source of truth)", () => {
    const extra = Object.keys(esCatalog).filter((key) => !(key in enCatalog));
    expect(extra).toEqual([]);
  });

  it("crisis phone numbers and URLs are never translated", () => {
    for (const [key, needle] of [
      ["crisis.call988", "988"],
      ["crisis.call988.detail", "988"],
      ["crisis.call988.fallback", "988"],
      ["crisis.text741741", "741741"],
      ["crisis.chat", "988lifeline.org"],
      ["crisis.findhelpline", "findahelpline.com"],
      ["crisis.emergency", "911"],
      ["crisis.findhelpline.fallback", "findahelpline.com"],
    ] as const) {
      expect(esCatalog[key]).toContain(needle);
    }
  });
});

describe("the locale seam", () => {
  it("setLocale/getLocale round-trip and dateLocaleTag follows the locale", () => {
    expect(dateLocaleTag()).toBe("en-US");
    setLocale("es");
    expect(getLocale()).toBe("es");
    expect(dateLocaleTag()).toBe("es-ES");
    setLocale("en");
    expect(getLocale()).toBe("en");
    expect(dateLocaleTag()).toBe("en-US");
  });
});

describe("screens render under es", () => {
  it("CrisisScreen speaks Spanish and keeps every number/URL", async () => {
    __setLocaleForTests("es");
    const { CrisisScreen } = await import("../src/screens/CrisisScreen");
    const { render, textOf } = await import("./helpers/rtr");
    const root = await render(<CrisisScreen region="US" />);
    const text = textOf(root);
    expect(text).toContain("Si está pensando en hacerse daño"); // es headline
    expect(text).not.toContain("If you are thinking about harming yourself"); // en headline gone
    // Safety-critical: numbers and URLs survive translation untouched.
    expect(text).toContain("988");
    expect(text).toContain("741741");
    expect(text).toContain("911");
    expect(text).toContain("findahelpline.com");
  });

  it("EntryScreen speaks Spanish (editor placeholder, save button, nav) and no English leaks", async () => {
    __setLocaleForTests("es");
    const { EntryScreen } = await import("../src/screens/EntryScreen");
    const { vault } = await import("../src/vault");
    const { render, textOf, inputByPlaceholder } = await import("./helpers/rtr");
    vault.lock();
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.alloc(32, 2) });
    sessionState = { activeDays: 0, unlockDays: 30, touchActivity: vi.fn() };
    const root = await render(<EntryScreen navigation={{ navigate: vi.fn() }} />);
    const text = textOf(root);
    expect(text).toContain("0/30 días para sus patrones"); // es progress line
    expect(text).toContain("Guardar entrada"); // es save button
    expect(text).toContain("Agregar detalles (opcional)"); // es disclosure
    expect(text).toContain("Ayuda"); // es nav "Get help" (module loaded under es)
    expect(text).not.toContain("days to your patterns"); // en progress gone
    expect(text).not.toContain("Save entry"); // en button gone
    expect(inputByPlaceholder(root, "¿Qué hay hoy?")).toBeTruthy(); // es placeholder
  });
});

describe("2026-09-20 audit copy pins (L-72 / M-36 / M-25 / L-65)", () => {
  it("L-72: the 'certain day' fallback pluralizes cleanly in {day}s templates", () => {
    // "certain" + "s" used to render "certains" on evidence rows.
    expect(t("insights.desc.certainDay")).toBe("certain day");
    expect(t("insights.desc.sleepTemporal", { day: t("insights.desc.certainDay") })).toContain(
      "fall most often on certain days.",
    );
    expect(t("insights.desc.tagTemporal", { label: "x", day: t("insights.desc.certainDay") })).not.toContain(
      "certains",
    );
  });

  it("L-72: the energy carryover sentence is grammatical (has, not have)", () => {
    expect(t("insights.ev.carryoverEnergy")).toContain("your energy has been carrying over");
  });

  it("M-36: the Spanish insights copy holds the usted register and no stutter", () => {
    __setLocaleForTests("es");
    try {
      // 355-356: these two keys used "tu/tus" in a 100%-usted catalog.
      expect(t("insights.languageTitle")).toBe("Sobre el idioma de su diario");
      expect(t("insights.languageBody")).toContain("sus entradas y registros");
      expect(t("insights.languageBody")).not.toMatch(/\btu\b|\btus\b/);
      // 370: the "diario diario" stutter is gone.
      expect(t("insights.method.link")).not.toContain("diario diario");
      expect(t("insights.method.link")).toContain("estudios de registro diario");
      // 403 / 464: natural comparatives, no anglicized "read higher by X".
      expect(t("insights.ev.moodDiffValue")).toBe(
        "las entradas suenan {direction} que su propia norma, por una diferencia de {amount}",
      );
      expect(t("insights.desc.moodShift")).toContain("han sonado {direction} que su línea base habitual");
    } finally {
      __setLocaleForTests("en");
    }
  });

  it("M-25: the v2 sharing disclosure names every readable class in BOTH locales", () => {
    for (const key of ["share.grantBody", "share.disclosure"] as const) {
      const en = t(key);
      expect(en).toContain("measures (PHQ-9 questionnaires)");
      expect(en.toLowerCase()).toContain("summary");
      __setLocaleForTests("es");
      try {
        const es = t(key);
        expect(es).toContain("cuestionarios de bienestar (PHQ-9)");
        expect(es).toContain("resumen");
      } finally {
        __setLocaleForTests("en");
      }
    }
    // The stale-state and 409 copy exists and stays calm.
    expect(t("share.termsUpdatedTitle")).toBe("Sharing terms updated");
    expect(t("share.grantOutdatedBody")).toContain("nothing was shared");
    expect(t("share.listFailedNote")).toContain("Couldn’t load who you are sharing with");
  });

  it("L-65: the partial-registration copy exists in both locales", () => {
    expect(t("login.registerPartialTitle")).toBe("Account created");
    expect(t("login.registerPartialBody")).toContain("Switch to sign-in");
    __setLocaleForTests("es");
    try {
      expect(t("login.registerPartialTitle")).toBe("Cuenta creada");
      expect(t("login.registerPartialBody")).toContain("iniciar sesión");
    } finally {
      __setLocaleForTests("en");
    }
  });

  it("M-16: every measures key resolves in both locales", () => {
    const keys = [
      "measures.intro", "measures.offlineNote", "measures.historyTitle", "measures.stemsHeader",
      "measures.recordButton", "measures.crisisTitle", "measures.crisisBody",
      ...Array.from({ length: 9 }, (_, i) => `measures.phq9.item${i + 1}`),
      ...[0, 1, 2, 3].map((v) => `measures.phq9.option${v}`),
    ];
    for (const key of keys) {
      expect(t(key)).not.toBe(key);
      expect(t(key).length).toBeGreaterThan(2);
    }
  });
});
