import { afterEach, expect, it, vi } from "vitest";
import { currentOrigin, downloadTextFile, isOnline, localStore, onWindowEvent, pageHidden, requestAccountDownload } from "../src/platform";

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });
it("hands an export ticket to the native download manager through a temporary same-window form", () => {
  const children: Record<string, unknown>[] = []; const forms: Record<string, unknown>[] = [];
  const remove = vi.fn(), submit = vi.fn();
  vi.stubGlobal("document", { createElement: (type: string) => type === "form" ? { appendChild: (input: Record<string, unknown>) => children.push(input), submit, remove } : {}, body: { appendChild: (form: Record<string, unknown>) => forms.push(form) } });
  const ticket = "aB_1-".repeat(8) + "xyz"; expect(ticket).toHaveLength(43);
  expect(requestAccountDownload(ticket)).toBe(true);
  expect(forms).toEqual([{ method: "POST", action: "/api/v1/account/export-download", target: "_self", enctype: "application/x-www-form-urlencoded", acceptCharset: "UTF-8", hidden: true, appendChild: expect.any(Function), submit, remove }]);
  expect(children).toEqual([{ type: "hidden", name: "ticket", value: ticket }]); expect(submit).toHaveBeenCalledOnce(); expect(remove).toHaveBeenCalledOnce();
});
it.each(["", "a".repeat(42), "a".repeat(44), "a".repeat(42) + "+", "a".repeat(42) + "=", " " + "a".repeat(43), "a".repeat(43) + " "])("refuses malformed download tickets before handing any capability to the DOM: %s", ticket => {
  const createElement = vi.fn(); vi.stubGlobal("document", { createElement }); expect(requestAccountDownload(ticket)).toBe(false); expect(createElement).not.toHaveBeenCalled();
});
it.each(["create", "append", "submit"])("reports native export failure and removes any allocated form after %s failure", failure => {
  const remove = vi.fn();
  vi.stubGlobal("document", { createElement: (type: string) => { if (failure === "create") throw new Error("denied"); return type === "form" ? { appendChild: () => { if (failure === "append") throw new Error("denied"); }, submit: () => { throw new Error("denied"); }, remove } : {}; }, body: { appendChild: () => {} } });
  expect(requestAccountDownload("a".repeat(43))).toBe(false); expect(remove).toHaveBeenCalledTimes(failure === "create" ? 0 : 1);
});
it("supplies the actual downloadable Blob contents and MIME, and preserves its capability for the stated one-minute window", async () => {
  vi.useFakeTimers(); let blob: Blob | null = null;
  const anchor = { href: "", download: "", rel: "", click: vi.fn() }, revoke = vi.fn();
  vi.stubGlobal("window", { document: { createElement: () => anchor } });
  vi.stubGlobal("URL", { createObjectURL: (value: Blob) => { blob = value; return "blob:download-contract"; }, revokeObjectURL: revoke });
  expect(downloadTextFile("encrypted.json", "{\"encrypted\":true}", "application/json")).toBe(true);
  expect(blob).toBeInstanceOf(Blob); expect((blob as unknown as Blob).type).toBe("application/json"); expect(await (blob as unknown as Blob).text()).toBe('{"encrypted":true}');
  expect(anchor).toMatchObject({ href: "blob:download-contract", download: "encrypted.json", rel: "noopener" }); expect(anchor.click).toHaveBeenCalledOnce();
  vi.advanceTimersByTime(59999); expect(revoke).not.toHaveBeenCalled(); vi.advanceTimersByTime(1); expect(revoke).toHaveBeenCalledWith("blob:download-contract");
});
it("requires both Blob URL operations and tolerates unavailable or throwing browser capability accessors", () => {
  vi.stubGlobal("window", { document: {} });
  const create = vi.fn(); vi.stubGlobal("URL", { createObjectURL: create }); expect(downloadTextFile("a", "x", "text/plain")).toBe(false); expect(create).not.toHaveBeenCalled();
  vi.stubGlobal("window", { get location() { throw new Error("denied"); }, get localStorage() { throw new Error("denied"); } });
  expect(currentOrigin()).toBe(""); expect(localStore.get("x")).toBeNull(); expect(() => localStore.remove("x")).not.toThrow(); expect(() => localStore.removePrefix("x")).not.toThrow();
  vi.stubGlobal("navigator", { get onLine() { throw new Error("denied"); } }); expect(isOnline()).toBe(true);
  vi.stubGlobal("document", { get visibilityState() { throw new Error("denied"); } }); expect(pageHidden({ visibilityState: "hidden" })).toBe(true); expect(pageHidden({ visibilityState: "visible" })).toBe(false);
});
it("prefers real document visibility, treats unknown visibility/connectivity as usable, and returns a harmless unsubscribe after failed registration", () => {
  for (const state of ["visible", "hidden", "unknown"]) { vi.stubGlobal("document", { visibilityState: state }); expect(pageHidden({ visibilityState: "hidden" })).toBe(state === "hidden"); }
  vi.stubGlobal("document", { visibilityState: 1 }); expect(pageHidden({ visibilityState: "hidden" })).toBe(true); expect(pageHidden()).toBe(false);
  vi.stubGlobal("navigator", undefined); expect(isOnline()).toBe(true);
  vi.stubGlobal("window", { addEventListener: () => { throw new Error("blocked"); } }); expect(onWindowEvent("online", vi.fn())()).toBeUndefined();
  vi.stubGlobal("window", {}); expect(onWindowEvent("online", vi.fn())()).toBeUndefined(); localStore.remove("x"); localStore.removePrefix("x");
});
