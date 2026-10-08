import { expect, it, vi } from "vitest";

// This is the framework side of React's external-store subscription API.
// Retired consumers must not receive a later language dispatch.
const framework = vi.hoisted(() => ({ subscribe: undefined as undefined | ((listener: () => void) => () => void), snapshot: undefined as undefined | (() => string) }));
vi.mock("react", async importOriginal => {
  const actual = await importOriginal<typeof import("react")>();
  return { ...actual, useSyncExternalStore: (subscribe: (listener: () => void) => () => void, snapshot: () => string) => {
    framework.subscribe = subscribe; framework.snapshot = snapshot; return snapshot();
  } };
});
it("releases the exact framework listener when its reader is disposed", async () => {
  vi.resetModules(); const { setLocale, useLocale } = await import("../src/strings");
  setLocale("en"); expect(useLocale()).toBe("en");
  const observed: string[] = [], unsubscribe = framework.subscribe!(() => { observed.push(framework.snapshot!()); });
  setLocale("es"); expect(observed).toEqual(["es"]);
  unsubscribe(); setLocale("en"); expect(observed).toEqual(["es"]);
});

it("keeps another reader subscribed when one reader is disposed", async () => {
  vi.resetModules(); const { setLocale, useLocale } = await import("../src/strings");
  setLocale("en"); useLocale(); let retired = false;
  const first = framework.subscribe!(() => { if (retired) throw new Error("React dispatched to a disposed reader"); });
  const observed: string[] = [], second = framework.subscribe!(() => { observed.push(framework.snapshot!()); });
  first(); retired = true; setLocale("es"); expect(observed).toEqual(["es"]); second(); setLocale("en");
});
