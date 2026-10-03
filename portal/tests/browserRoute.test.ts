import { afterEach, describe, expect, it, vi } from "vitest";
import { readPatientRoute, writePatientRoute } from "../src/browserRoute";
afterEach(() => vi.unstubAllGlobals());
describe("chart browser routes", () => {
  it("routes only bounded identifiers and keeps text out of the URL", () => {
    const location = { hash: "#/patient/user-1" };
    const pushState = vi.fn((_state, _title, hash) => { location.hash = hash; });
    vi.stubGlobal("window", { location, history: { pushState } });
    expect(readPatientRoute()).toBe("user-1");
    writePatientRoute("user-2");
    expect(pushState).toHaveBeenCalledWith(null, "", "#/patient/user-2");
    writePatientRoute("user-2");
    expect(pushState).toHaveBeenCalledTimes(1);
    writePatientRoute("../../other");
    expect(pushState).toHaveBeenCalledTimes(1);
    writePatientRoute(null);
    expect(readPatientRoute()).toBeNull();
    location.hash = `#/patient/${"x".repeat(129)}`;
    expect(readPatientRoute()).toBeNull();
  });
  it("handles hosts without browser APIs", () => {
    vi.stubGlobal("window", undefined);
    expect(readPatientRoute()).toBeNull();
    expect(() => writePatientRoute(null)).not.toThrow();
  });
});
