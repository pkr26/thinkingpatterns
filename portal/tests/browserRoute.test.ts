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
    expect(location.hash).toBe("#/patients");
    location.hash = `#/patient/${"x".repeat(129)}`;
    expect(readPatientRoute()).toBeNull();
  });
  it("handles hosts without browser APIs", () => {
    vi.stubGlobal("window", undefined);
    expect(readPatientRoute()).toBeNull();
    expect(() => writePatientRoute(null)).not.toThrow();
  });
});

it.each(["a", "Z", "0", "_", "-", "Aa0_-", "x".repeat(128)])("reads and writes the full supported patient identifier %s", id => {
  const location = { hash: `#/patient/${id}` };
  const pushState = vi.fn((_state, _title, hash: string) => { location.hash = hash; });
  vi.stubGlobal("window", { location, history: { pushState } });
  expect(readPatientRoute()).toBe(id);
  location.hash = "#/patients";
  writePatientRoute(id);
  expect(pushState).toHaveBeenCalledWith(null, "", `#/patient/${id}`);
  expect(readPatientRoute()).toBe(id);
});

it.each(["", "x".repeat(129), "patient name", "patient/other", "é", "a.b", "a@b", "a\\b", "a?token=b", "a\n", "a:"])("refuses an unsupported identifier without changing browser history: %s", id => {
  const location = { hash: `#/patient/${id}` };
  const pushState = vi.fn();
  vi.stubGlobal("window", { location, history: { pushState } });
  expect(readPatientRoute()).toBeNull();
  location.hash = "#/patients";
  writePatientRoute(id);
  expect(pushState).not.toHaveBeenCalled();
});

it.each(["/patient/a", "#patient/a", "#/patient/a/", "#/patient/a/other", "#/other/a", "#/patients", "prefix#/patient/a"])("ignores a hash outside the exact chart route: %s", hash => {
  vi.stubGlobal("window", { location: { hash } });
  expect(readPatientRoute()).toBeNull();
});

it("degrades if reading the location or writing browser history throws", () => {
  vi.stubGlobal("window", { get location() { throw new Error("location unavailable"); } });
  expect(readPatientRoute()).toBeNull();
  expect(() => writePatientRoute("patient-1")).not.toThrow();
  vi.stubGlobal("window", { location: { hash: "#/patients" }, history: { pushState: () => { throw new Error("history unavailable"); } } });
  expect(() => writePatientRoute("patient-1")).not.toThrow();
});
