import React from "react";
import TestRenderer, { act } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
afterEach(() => { vi.restoreAllMocks(); vi.resetModules(); });

it.each([
  ["es-MX", "es", "es-ES", "Guardar entrada"],
  ["es-ES", "es", "es-ES", "Guardar entrada"],
  ["en-US", "en", "en-US", "Save entry"],
  ["fr-ES", "en", "en-US", "Save entry"],
])("detects device %s at actual translator initialization", async (device, locale, dateTag, copy) => {
  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(() => ({ resolvedOptions: () => ({ locale: device }) }) as Intl.DateTimeFormat);
  vi.resetModules(); const strings = await import("../src/strings");
  expect(strings.getLocale()).toBe(locale); expect(strings.dateLocaleTag()).toBe(dateTag); expect(strings.t("entry.save")).toBe(copy);
});

it("uses English when the native internationalization service cannot detect a device locale", async () => {
  vi.spyOn(Intl, "DateTimeFormat").mockImplementation(() => { throw new Error("Intl service unavailable"); });
  vi.resetModules(); const strings = await import("../src/strings");
  expect(strings.getLocale()).toBe("en"); expect(strings.dateLocaleTag()).toBe("en-US");
});

it("restores the current device preference through the public reset action", async () => {
  let device = "en-US"; vi.spyOn(Intl, "DateTimeFormat").mockImplementation(() => ({ resolvedOptions: () => ({ locale: device }) }) as Intl.DateTimeFormat);
  vi.resetModules(); const strings = await import("../src/strings"); strings.setLocale("es");
  strings.resetToDeviceLocale(); expect(strings.getLocale()).toBe("en");
  device = "es-MX"; strings.resetToDeviceLocale(); expect(strings.getLocale()).toBe("es"); expect(strings.dateLocaleTag()).toBe("es-ES");
});

it("refreshes a mounted native reader when the user changes language", async () => {
  vi.resetModules(); const strings = await import("../src/strings"); strings.setLocale("en");
  function VisibleCopy() { strings.useLocale(); return <>{strings.t("common.cancel")}</>; }
  let root!: TestRenderer.ReactTestRenderer;
  await act(async () => { root = TestRenderer.create(<VisibleCopy />); }); expect(root.toJSON()).toBe("Cancel");
  await act(async () => { strings.setLocale("es"); }); expect(root.toJSON()).toBe("Cancelar");
  await act(async () => { strings.setLocale("en"); }); expect(root.toJSON()).toBe("Cancel");
  await act(async () => { root.unmount(); });
});
