import { describe, expect, it } from "vitest";
import { en } from "../src/locales/en";
import { es } from "../src/locales/es";

/**
 * Deep-audit 2026-09-28 (docs HIGH): the web catalogs used to carry dead
 * crisis strings that contradicted the rendered surfaces — most dangerously
 * "Crisis Text Line: text HOME to 741741 (US, CA, UK, IE)", factually wrong
 * (741741 is the US short code only; CA uses 686868, UK 85258, IE 50808) —
 * so a future refactor that started rendering one of them would direct
 * non-US users to a dead number. The invariant pinned here: no catalog
 * string may attach a multi-country claim to the US-only short codes, and
 * the non-US pointer stays findahelpline.com.
 */

type Catalog = Record<string, string>;

describe("crisis hotline copy stays single-sourced", () => {
  const catalogs: [string, Catalog][] = [
    ["en", en as Catalog],
    ["es", es as Catalog],
  ];

  it("never scopes 988 or 741741 beyond the US", () => {
    for (const [name, cat] of catalogs) {
      for (const [key, value] of Object.entries(cat)) {
        expect(
          /\b(?:US|EE\. UU\.),?\s*(?:CA|Canadá|UK|Reino Unido|IE|Irlanda)/.test(value),
          `${name}:${key} scopes a US-only short code to multiple countries`,
        ).toBe(false);
      }
    }
  });

  it("keeps findahelpline.com as the non-US pointer", () => {
    for (const [name, cat] of catalogs) {
      const outsideUS = Object.entries(cat).filter(([k]) => k === "crisis.webOutsideUS");
      expect(outsideUS.length, name).toBe(1);
      expect(outsideUS[0]![1], name).toContain("findahelpline.com");
    }
  });
});
