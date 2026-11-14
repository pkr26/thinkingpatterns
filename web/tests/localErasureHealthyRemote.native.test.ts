/** Unexecuted direct public remote-confirmation regression for original57/58/59. */
import { afterEach, beforeEach, expect, it } from "vitest";
import { kv } from "../src/kvstore";
import { confirmRemoteLocalErasure, pendingLocalErasures } from "../src/localErasure";
import { resetTestState } from "./helpers/api";

beforeEach(() => { resetTestState(); });
afterEach(() => { resetTestState(); });

it("completes healthy remote-confirmed local cleanup when no checkpoint existed and preserves the other account", async () => {
  const owner = "healthy-remote-owner";
  const own = "mindpattern.safetyPlan.healthy-remote-owner";
  const other = "mindpattern.safetyPlan.healthy-remote-other";
  await kv.setItem(own, "opaque account ciphertext");
  await kv.setItem(other, "other account ciphertext");
  // First assertion is actual positive public completion, with no authored backend fault.
  await expect(confirmRemoteLocalErasure(owner)).resolves.toBeUndefined();
  expect(await kv.getItem(own)).toBeNull();
  expect(await kv.getItem(other)).toBe("other account ciphertext");
  expect(await kv.getItem("mindpattern.erase.healthy-remote-owner")).toBeNull();
  expect(await pendingLocalErasures()).toEqual([]);
});
