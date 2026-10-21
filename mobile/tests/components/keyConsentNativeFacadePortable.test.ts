/** witness: real installed AsyncStorage.native facade and public
 * production consent APIs. Only the lowest native tuple transport is synthetic.
 * This is a Node/native-interface proof, not an Android/iOS hardware test. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
// These file-scoped factories preserve the normal project's alias table.
// The production bare import resolves to the actual installed native facade;
// only the facade's canonical RCT transport module is replaced.
vi.mock("@react-native-async-storage/async-storage/src/RCTAsyncStorage", async () => ({
  default: (await import("../helpers/keyConsentNativeBridge")).default,
}));
vi.mock("@react-native-async-storage/async-storage", async () => {
  // Runtime source import with the package's published interface as the type
  // boundary: importing vendor TS as a type would re-check its pre-existing
  // unchecked-index diagnostics under this project's stricter compiler flags.
  const nativeFacadeModule: string = "@react-native-async-storage/async-storage/src/AsyncStorage.native";
  return { default: (await import(nativeFacadeModule)).default as AsyncStorageStatic };
});
import storage, { type AsyncStorageStatic } from "@react-native-async-storage/async-storage";
import { api } from "../../src/api/client";
import { hasKeyShipConsent, recordKeyShipConsent, clearKeyShipConsent } from "../../src/components/keyConsent";
import { resetNativeTransport } from "../helpers/keyConsentNativeBridge";

const USER = "cccccccccccccccccccccccccccccccc";
const CONTROL = "@fathom/native-facade-control";
async function finite<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try { return await Promise.race([promise, new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`SetupError: native consent producer deadline ${label}`)), 5_000);
  })]); }
  finally { if (timer) clearTimeout(timer); }
}
beforeEach(async () => { await finite(api.clearSession(), "prior credential retirement"); resetNativeTransport(); });
afterEach(async () => { await finite(api.clearSession(), "credential cleanup"); resetNativeTransport(); });

it("the shipping native storage facade delivers empty and nonempty values through its actual Promise and callback", async () => {
  await finite(storage.setItem(CONTROL, ""), "empty control write");
  const emptyCallbacks: Array<[unknown, string | null]> = [];
  const emptyPromise = storage.getItem(CONTROL, (error, value) => { emptyCallbacks.push([error, value ?? null]); });
  expect(await finite(emptyPromise, "empty control delivery")).toBeNull();
  expect(emptyCallbacks).toEqual([[undefined, null]]);
  await finite(storage.setItem(CONTROL, "1"), "nonempty control write");
  const valueCallbacks: Array<[unknown, string | null]> = [];
  const valuePromise = storage.getItem(CONTROL, (error, value) => { valueCallbacks.push([error, value ?? null]); });
  expect(await finite(valuePromise, "nonempty control delivery")).toBe("1");
  expect(valueCallbacks).toEqual([[undefined, "1"]]);
  await finite(storage.removeItem(CONTROL), "control deletion");
  expect(await finite(storage.getItem(CONTROL), "missing control delivery")).toBeNull();
});

it("a publicly admitted native consent acknowledgement remains acknowledged until the account clears it", async () => {
  await finite(api.setSession("synthetic-native-consent-bearer", USER, "native-consent-owner"), "actual owner credential publication");
  expect(await finite(api.getUserId(), "published owner read")).toBe(USER);
  expect(await finite(hasKeyShipConsent(USER), "initial absent acknowledgement")).toBe(false);
  await finite(recordKeyShipConsent(USER), "actual admitted consent write");
  expect(await finite(hasKeyShipConsent(USER), "later native acknowledgement read")).toBe(true);
  await finite(clearKeyShipConsent(USER), "actual consent deletion");
  expect(await finite(hasKeyShipConsent(USER), "later cleared acknowledgement read")).toBe(false);
});
