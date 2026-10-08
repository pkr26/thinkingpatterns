import { expect, it } from "vitest";
import { runTestControl } from "./helpers/testControl";

const context = globalThis as typeof globalThis & { __stryker__?: { activeMutant?: string } };
it("evaluates arguments under the active campaign and restores it after the synchronous control", () => {
  const original = context.__stryker__, campaign = { activeMutant: "known-active-operator" }; context.__stryker__ = campaign;
  try {
    const argument = () => campaign.activeMutant;
    expect(runTestControl(value => ({ argument: value, duringControl: campaign.activeMutant }), argument())).toEqual({ argument: "known-active-operator", duringControl: undefined });
    expect(campaign.activeMutant).toBe("known-active-operator");
  } finally { context.__stryker__ = original; }
});
it("restores the active campaign even when a state control fails", () => {
  const original = context.__stryker__, campaign = { activeMutant: "known-active-operator" }; context.__stryker__ = campaign;
  try {
    const error = new Error("Test control failed"); expect(() => runTestControl(() => { throw error; })).toThrow(error);
    expect(campaign.activeMutant).toBe("known-active-operator");
  } finally { context.__stryker__ = original; }
});
