// @vitest-environment jsdom
import { webcrypto } from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { setKvBackendForTests } from "../src/kvstore";
import { adoptLegacyPlaintextMutes, readMutedPids, writeMutedPids } from "../src/patternMutes";

const owner = "native-legacy-read-retry-owner";
const legacySlot = `mindpattern.mutedPids.v1.${owner}`;
const key = new Uint8Array(new ArrayBuffer(32)).fill(17);
let records: Map<string, string>;

beforeEach(() => {
  vi.stubGlobal("crypto", webcrypto);
  records = new Map();
  window.localStorage.clear();
  setKvBackendForTests({
    getItem: async slot => records.get(slot) ?? null,
    setItem: async (slot, value) => { records.set(slot, value); },
    removeItem: async slot => { records.delete(slot); },
    keys: async () => [...records.keys()],
  });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  setKvBackendForTests(null);
  window.localStorage.clear();
});

it("retains an unreadable plaintext mute list for a later native storage read retry", async () => {
  await writeMutedPids(key, owner, ["already-muted"]);
  const legacyRaw = JSON.stringify(["not-yet-adopted"]);
  window.localStorage.setItem(legacySlot, legacyRaw);

  // The browser storage read alone fails. Its ordinary remove operation stays
  // available, so deleting the unread list would lose the only plaintext copy.
  const nativeGet = Storage.prototype.getItem;
  const readFault = vi.spyOn(Storage.prototype, "getItem").mockImplementation(function (this: Storage, name: string) {
    if (name === legacySlot) throw new DOMException("transient native storage read failure", "SecurityError");
    return nativeGet.call(this, name);
  });
  try {
    expect(await adoptLegacyPlaintextMutes(key, owner)).toEqual(new Set(["already-muted"]));
  } finally {
    readFault.mockRestore();
  }

  expect(window.localStorage.getItem(legacySlot)).toBe(legacyRaw);
  expect(await readMutedPids(key, owner)).toEqual(new Set(["already-muted"]));
  expect(await adoptLegacyPlaintextMutes(key, owner)).toEqual(new Set(["already-muted", "not-yet-adopted"]));
  expect(window.localStorage.getItem(legacySlot)).toBeNull();
});
