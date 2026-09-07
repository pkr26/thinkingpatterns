/**
 * brainSync: account-deletion hygiene for the per-account recompute stamp.
 *
 * The daily auto-refresh itself was deleted after the red-team audit — the
 * data key only ever travels via the Question screen's explicit button.
 * What remains is the stamp wipe the Settings delete flow relies on.
 */
import { beforeEach, describe, expect, it } from "vitest";
import storage from "./helpers/storageMock";
import { clearRecomputeStamp } from "../src/brainSync";

beforeEach(() => {
  storage.__reset();
});

describe("clearRecomputeStamp", () => {
  it("removes only the given account's stamp", async () => {
    await storage.setItem("@mindpattern/last_recompute_user-1", "2026-09-01");
    await storage.setItem("@mindpattern/last_recompute_user-2", "2026-09-01");

    await clearRecomputeStamp("user-1");

    expect(await storage.getItem("@mindpattern/last_recompute_user-1")).toBeNull();
    // Another account's stamp (legacy data) is untouched.
    expect(await storage.getItem("@mindpattern/last_recompute_user-2")).toBe("2026-09-01");
  });

  it("is a no-op when no stamp exists", async () => {
    await expect(clearRecomputeStamp("ghost")).resolves.toBeUndefined();
  });
});
