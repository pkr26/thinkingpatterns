import { afterEach, expect, it, vi } from "vitest";
import { CrisisCard } from "../src/crisis";
import { __setLocaleForTests } from "../src/strings";
import { vault } from "../src/vault";
import { publicSurface } from "./helpers/publicSurface";
import { press, render } from "./helpers/rtr";
afterEach(() => { __setLocaleForTests("en"); vault.lock(); });
it.each(["en", "es"] as const)("renders accessible public resource actions and support copy in %s without a session", async locale => {
  __setLocaleForTests(locale); vault.lock(); const root = await render(<CrisisCard onClose={() => {}} />);
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});
it("keeps resource actions before the unlocked plan link and submits both dialog actions", async () => {
  const key = () => new Uint8Array(new ArrayBuffer(32)); vault.unlock({ authKey: key(), dataKey: key() }, "crisis-owner");
  const close = vi.fn(), plan = vi.fn(); const root = await render(<CrisisCard onClose={close} onMakeSafetyPlan={plan} />);
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  const buttons = root.root.findAllByType("button");
  for (const button of buttons) await press(root, String(button.children.find(child => typeof child === "string")));
  expect(close).toHaveBeenCalledOnce(); expect(plan).toHaveBeenCalledOnce();
});
