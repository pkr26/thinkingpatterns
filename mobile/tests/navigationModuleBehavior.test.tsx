import React from "react";
import { expect, it, vi } from "vitest";
import { render, textOf, screenNames, screenOptions } from "./helpers/rtr";

vi.mock("../src/store", async original => ({ ...await original<typeof import("../src/store")>(), useSession: () => ({ authStatus: "loading", unlocked: false }) }));

it("cold module initialization provides a branded boot screen and reachable offline crisis route", async () => {
  // Import in the case: a broken module initializer must fail a real
  // consumer assertion, rather than disappear as a collection error.
  const { AppNavigator } = await import("../src/navigation");
  const root = await render(<AppNavigator />);
  expect(screenNames(root)).toEqual(["Booting", "Crisis"]);
  expect(screenOptions(root, "Booting")).toEqual({ headerShown: false });
  expect(screenOptions(root, "Crisis")).toEqual({ title: "Get help" });
  expect(textOf(root)).toContain("Fathom");
  expect(textOf(root)).toContain("Your patterns, from your words. Encrypted on this device.");
});
