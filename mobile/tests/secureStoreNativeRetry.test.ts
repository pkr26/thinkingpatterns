import { afterEach, beforeEach, expect, it } from "vitest";
import * as Keychain from "react-native-keychain";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";

const custody = Keychain as unknown as {
  __reset(): void;
  __failWrites(value: boolean): void;
};
beforeEach(() => {
  storage.__reset();
  custody.__reset();
  runTestControl(setSecureStoreBackend, null);
});
afterEach(() => {
  custody.__failWrites(false);
  runTestControl(setSecureStoreBackend, null);
});

it("retries default native custody after a rejected first write without resetting the exported store", async () => {
  custody.__failWrites(true);
  try {
    const first = await secureStore.setItem("native-custody-retry", "first value")
      .then(() => "fulfilled", () => "rejected");
    expect(first).toBe("rejected");
    expect(await storage.getItem("native-custody-retry")).toBeNull();
  } finally {
    custody.__failWrites(false);
  }
  await secureStore.setItem("native-custody-retry", "recovered value");
  expect(await secureStore.getItem("native-custody-retry")).toBe("recovered value");
  const persisted = await storage.getItem("native-custody-retry");
  expect(persisted).toMatch(/^\{"v":1,"c":"/);
  expect(persisted).not.toContain("recovered value");
});
