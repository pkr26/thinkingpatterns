import { runTestControl } from "./helpers/testControl";
import { beforeEach, expect, it } from "vitest";
import { resetInsightsFreshness, verifyInsightsGeneration } from "../src/views/PatientView";

beforeEach(() => runTestControl(resetInsightsFreshness));

it.each([NaN, Infinity, -Infinity, -1, -0.5, 0.5, Number.MAX_SAFE_INTEGER + 1])("rejects an echoed invalid generation %s", generation => {
  expect(() => verifyInsightsGeneration("patient", generation, generation)).toThrow("freshness check");
  expect(() => verifyInsightsGeneration("patient", 0, 0)).not.toThrow();
});

it.each([undefined, null, "0", "1", {}, [], true])("rejects a nonnumeric encrypted generation %j", generation => {
  expect(() => verifyInsightsGeneration("patient", generation, 0)).toThrow("freshness check");
  expect(() => verifyInsightsGeneration("patient", 0, 0)).not.toThrow();
});

it("accepts zero and the largest safe generation, but remembers the high water independently for each patient", () => {
  verifyInsightsGeneration("first", 0, 0);
  verifyInsightsGeneration("first", Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER);
  expect(() => verifyInsightsGeneration("first", Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER - 1)).toThrow("freshness check");
  expect(() => verifyInsightsGeneration("second", 0, 0)).not.toThrow();
  expect(() => verifyInsightsGeneration("first", Number.MAX_SAFE_INTEGER, Number.MAX_SAFE_INTEGER)).not.toThrow();
});

it("rejects a disagreement without advancing the patient's acknowledged high water", () => {
  verifyInsightsGeneration("patient", 3, 3);
  expect(() => verifyInsightsGeneration("patient", 7, 8)).toThrow("freshness check");
  expect(() => verifyInsightsGeneration("patient", 4, 4)).not.toThrow();
});
