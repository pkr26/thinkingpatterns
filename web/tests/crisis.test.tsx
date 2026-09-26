/** The crisis card is static, offline, and complete: 988, 741741, 911
 *  guidance and findahelpline.com must all be present — this content is
 *  a safety contract, not copy (WEB_PLAN P1 placeholder, expanded P8). */
import { describe, expect, it, vi } from "vitest";
import { CrisisCard } from "../src/crisis";
import { press, render, textOf } from "./helpers/rtr";

describe("CrisisCard", () => {
  it("lists the core crisis resources", async () => {
    const root = await render(<CrisisCard onClose={() => undefined} />);
    const text = textOf(root);
    expect(text).toContain("911");
    expect(text).toContain("988");
    expect(text).toContain("741741");
    expect(text).toContain("findahelpline.com");
  });

  it("closes via its button", async () => {
    const onClose = vi.fn();
    const root = await render(<CrisisCard onClose={onClose} />);
    await press(root, "Close");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
