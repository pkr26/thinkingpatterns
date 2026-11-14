import { expect, it } from "vitest";
import { t } from "../src/strings";

it("preserves unresolved placeholders when optional interpolation values are absent", () => {
  const missing = "Untranslated {name} has {count} items and {missing}";
  expect(t(missing)).toBe(missing);
});

it("interpolates supplied values including zero while preserving an unknown placeholder", () => {
  expect(t("Untranslated {name} has {count} items and {missing}", { name: "Ada", count: 0 }))
    .toBe("Untranslated Ada has 0 items and {missing}");
});
