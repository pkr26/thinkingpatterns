import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { createCipheriv } from "node:crypto";
import * as Keychain from "react-native-keychain";
import storage from "./helpers/storageMock";
import { Platform, Vibration } from "./helpers/rnMock";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { applyStoredLanguageChoice, readLanguageChoice, writeLanguageChoice } from "../src/languagePref";
import { getLocale, setLocale } from "../src/strings";
import { hapticsEnabled, lightHaptic, loadHapticsSetting, setHapticsEnabled } from "../src/haptics";
import { loadOnboardingPanel } from "../src/onboarding";
import { unlockFailureCount } from "../src/unlockBackoff";
import { verifyUnlockProof } from "../src/unlockProof";
import { filterEntries } from "../src/historyFind";
const owner = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); (Keychain as unknown as { __reset(): void }).__reset(); runTestControl(setSecureStoreBackend, null); Platform.OS = "ios"; });
afterEach(() => { vi.restoreAllMocks(); Platform.OS = "ios"; });

it.each(["en", "es", "device", "", "de", "garbage"])("reads the interoperable encrypted language preference %s", async value => {
  await secureStore.setItem("@mindpattern/language_pref", value);
  expect(await readLanguageChoice()).toBe(value === "en" || value === "es" || value === "device" ? value : "device");
});
it("the device preference follows native Spanish detection immediately and after an unreadable store", async () => {
  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(() => ({ resolvedOptions: () => ({ locale: "es-MX" }) }) as Intl.DateTimeFormat);
  setLocale("en"); await writeLanguageChoice("device"); expect(getLocale()).toBe("es");
  setLocale("en"); vi.spyOn(secureStore, "getItem").mockRejectedValue(new Error("Encrypted preference is temporarily unavailable"));
  expect(await readLanguageChoice()).toBe("device"); await applyStoredLanguageChoice(); expect(getLocale()).toBe("es");
});
it("an unavailable native haptic preference restores the optional Android pulse after a previous disable", async () => {
  await setHapticsEnabled(false); vi.spyOn(storage, "getItem").mockRejectedValue(new Error("Native preferences unavailable"));
  expect(await loadHapticsSetting()).toBe(true); expect(hapticsEnabled()).toBe(true); Platform.OS = "android"; Vibration.vibrate.mockClear(); lightHaptic(); expect(Vibration.vibrate).toHaveBeenCalledWith(10);
});
it("resumes a legacy onboarding position after migrating it into the account's native preference", async () => {
  await storage.setItem("@mindpattern/onboarding_panel", "2"); expect(await loadOnboardingPanel(5, owner)).toBe(2);
  expect(await storage.getItem("@mindpattern/onboarding_panel")).toBeNull(); expect(await loadOnboardingPanel(5, owner)).toBe(2);
});
it("an unreadable native onboarding position shows the first panel", async () => {
  vi.spyOn(storage, "getItem").mockRejectedValue(new Error("Native resume preference unavailable")); expect(await loadOnboardingPanel(5, owner)).toBe(0);
});
it.each(["-1", "0", "nonnumeric", "Infinity", "NaN"])("restored encrypted unlock failures %s cannot manufacture a negative or invalid count", async raw => {
  await secureStore.setItem("mindpattern.unlockFail.alice", raw); expect(await unlockFailureCount("alice")).toBe(0);
});
it("verifies the existing authenticated unlock-proof format through its actual encrypted native record", async () => {
  const key = Buffer.alloc(32, 49), nonce = Buffer.alloc(12, 50), cipher = createCipheriv("aes-256-gcm", key, nonce);
  cipher.setAAD(Buffer.from(JSON.stringify(["unlockproof", owner])));
  const blob = Buffer.concat([nonce, cipher.update("mindpattern-unlock-proof/v1"), cipher.final(), cipher.getAuthTag()]);
  await storage.setItem(`@mindpattern/unlockproof_${owner}`, blob.toString("base64")); expect(await verifyUnlockProof(key, owner)).toBe("ok");
});
it("native history search folds accents and case without expanding distinct sharp-S spellings", () => {
  const entries = [{ clientEntryId: "a", entryDate: "2026-10-05", text: "Straße" }, { clientEntryId: "b", entryDate: "2026-10-06", text: "STRASSE" }];
  expect(filterEntries(entries, "straße").map(entry => entry.clientEntryId)).toEqual(["a"]); expect(filterEntries(entries, "strasse").map(entry => entry.clientEntryId)).toEqual(["b"]);
});
