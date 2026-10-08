import { afterEach, expect, it, vi } from "vitest";
import { confirmLocalErasure } from "../src/localErasure";
import { setKvBackendForTests } from "../src/kvstore";
afterEach(() => { setKvBackendForTests(null); vi.restoreAllMocks(); window.localStorage.clear(); window.sessionStorage.clear(); });
it.each(["empty", "foreign-only"] as const)("finishes erasure while actual browser storage is %s", async domain => {
  const owner="erasure-browser-iteration", id=`mindpattern.erase.${owner}`;
  const physical = new Map([[id, JSON.stringify({v:1, owner, remoteConfirmed:false, keys:[]})]]);
  setKvBackendForTests({ async getItem(k) { return physical.get(k)??null; }, async setItem(k,v) { physical.set(k,v); }, async removeItem(k) { physical.delete(k); }, async keys() { return [...physical.keys()]; }, async compareAndSet(k,expected,value) { if ((physical.get(k)??null)!==expected) return false; physical.set(k,value); return true; } });
  window.localStorage.clear(); window.sessionStorage.clear();
  if (domain==="foreign-only") window.localStorage.setItem("foreign-application-preference", "retained");
  await confirmLocalErasure(owner); expect(physical.has(id)).toBe(false);
  if (domain==="foreign-only") expect(window.localStorage.getItem("foreign-application-preference")).toBe("retained");
});
