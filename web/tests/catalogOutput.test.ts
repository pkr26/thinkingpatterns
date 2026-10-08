import { readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

type Row = {
  phase: "preauth" | "full";
  locale: "en" | "es";
  key: string;
  plain: string;
  vars: Record<string, string>;
  interpolated: string;
};
const { rows } = JSON.parse(readFileSync(join(import.meta.dirname, "fixtures/catalog-output.json"), "utf8")) as { rows: Row[] };

afterEach(async () => {
  const strings = await import("../src/strings");
  strings.__setLocaleForTests("en");
});

describe("user-visible bilingual catalog output", () => {
  for (const phase of ["preauth", "full"] as const) {
    for (const locale of ["en", "es"] as const) {
      it(`${phase} ${locale} messages preserve copy and interpolate caller values`, async () => {
        vi.resetModules();
        const strings = await import("../src/strings");
        strings.__setLocaleForTests(locale);
        if (phase === "full") await strings.loadFullCatalogs(locale);
        const expected = rows.filter((row) => row.phase === phase && row.locale === locale);
        expect(expected.length).toBeGreaterThan(0);
        for (const row of expected) {
          expect(strings.t(row.key), row.key).toBe(row.plain);
          expect(strings.t(row.key, row.vars), `${row.key} interpolation`).toBe(row.interpolated);
        }
      });
    }
  }
});
