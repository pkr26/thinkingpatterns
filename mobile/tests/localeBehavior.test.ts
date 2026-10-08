import { afterEach, expect, it } from "vitest";
import shippedCopy from "./fixtures/mobile-visible-copy.json";
import { setLocale, t } from "../src/strings";

afterEach(() => setLocale("en"));

it("the public translator delivers every shipped English and Spanish message", () => {
  // Reviewable user-visible copy, separate from source bytes. Exercise the
  // public lookup and interpolation consumers; never inspect catalog internals.
  const values = { name: "Morgan", label: "Support", detail: "Call now", active: 3, total: 30, date: "Monday", count: 4, day: "Friday" };
  for (const locale of ["en", "es"] as const) {
    setLocale(locale);
    for (const [key, expected] of Object.entries(shippedCopy[locale])) {
      expect(t(key), `${locale}:${key}`).toBe(expected);
      const interpolated = expected.replace(/\{([a-zA-Z][a-zA-Z0-9_]*)\}/g, (match, name: string) => name in values ? String(values[name as keyof typeof values]) : match);
      expect(t(key, values), `${locale}:${key} with values`).toBe(interpolated);
    }
  }
});
