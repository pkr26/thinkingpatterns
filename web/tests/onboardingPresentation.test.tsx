import { afterEach, expect, it, vi } from "vitest";
import { __setLocaleForTests } from "../src/strings";
import { setKvBackendForTests } from "../src/kvstore";
import { localStore } from "../src/platform";
import { clearOnboardingSeen, hasSeenOnboarding, markOnboardingSeen, Onboarding } from "../src/views/Onboarding";
import { publicSurface } from "./helpers/publicSurface";
import { press, render } from "./helpers/rtr";

afterEach(() => { __setLocaleForTests("en"); setKvBackendForTests(null); });

it.each(["en", "es"] as const)("shows all three onboarding panels with usable completion controls in %s", async locale => {
  __setLocaleForTests(locale);
  const done = vi.fn(); const root = await render(<Onboarding onDone={done} />);
  for (let index = 0; index < 3; index++) {
    expect(publicSurface(root.toJSON())).toMatchSnapshot();
    const buttons = root.root.findAllByType("button");
    expect(buttons).toHaveLength(1);
    await press(root, buttons[0]!.props["aria-label"] ?? (locale === "es" ? index === 2 ? "Empezar a escribir" : "Siguiente" : index === 2 ? "Start journaling" : "Next"));
    expect(done).toHaveBeenCalledTimes(index === 2 ? 1 : 0);
  }
});

it("migrates a legacy completion stamp only after the current-account write succeeds", async () => {
  const records = new Map<string, string>(); const removed: string[] = [];
  setKvBackendForTests({ getItem: async k => records.get(k) ?? null, setItem: async (k, v) => { records.set(k, v); }, removeItem: async k => { records.delete(k); removed.push(k); }, keys: async () => [...records.keys()] });
  const key = "mindpattern.onboarding.v1.presentation-legacy";
  localStore.set(key, "done");
  expect(await hasSeenOnboarding("presentation-legacy")).toBe(true);
  expect(localStore.get(key)).toBeNull();
  expect(await hasSeenOnboarding("presentation-legacy")).toBe(true);
  await clearOnboardingSeen("presentation-legacy");
  expect(removed).toEqual([key]);
  expect(await hasSeenOnboarding("presentation-legacy")).toBe(false);
  await markOnboardingSeen("presentation-legacy");
  expect(await hasSeenOnboarding("presentation-legacy")).toBe(true);
  records.set(key, "false");
  expect(await hasSeenOnboarding("presentation-legacy")).toBe(false);
});

it("rejects failed generation-fenced migration and retains the recoverable legacy stamp", async () => {
  const key = "mindpattern.onboarding.v1.presentation-deleted";
  localStore.set(key, "done");
  setKvBackendForTests({ getItem: async () => null, setItem: async () => { throw new Error("generation changed"); }, removeItem: async () => {}, keys: async () => [] });
  await expect(hasSeenOnboarding("presentation-deleted")).rejects.toThrow("Writing was not saved");
  expect(localStore.get(key)).toBe("done"); localStore.remove(key);
});
