/** The crisis card is static, offline, and complete: 988, 741741, 911
 *  guidance and findahelpline.com must all be present — this content is
 *  a safety contract, not copy (WEB_PLAN P1 placeholder, expanded P8).
 *
 * Clinical review 2026-09-27: the 988 LIFELINE CHAT joins the action
 * list (a person who cannot or will not use a phone reaches the same
 * lifeline, in writing), and the "Make a safety plan" link renders only
 * while the vault is unlocked — always BELOW the static resources, which
 * stay complete and first in every state. */
import { describe, expect, it, vi } from "vitest";
import { CrisisCard } from "../src/crisis";
import { vault } from "../src/vault";
import { press, render, textOf } from "./helpers/rtr";

const key = () => new Uint8Array(new ArrayBuffer(32)).fill(4);

describe("CrisisCard", () => {
  it("lists the core crisis resources", async () => {
    const root = await render(<CrisisCard onClose={() => undefined} />);
    const text = textOf(root);
    expect(text).toContain("911");
    expect(text).toContain("988");
    expect(text).toContain("741741");
    expect(text).toContain("findahelpline.com");
  });

  it("offers the 988 lifeline CHAT with the never-translated URL, opened externally", async () => {
    const root = await render(<CrisisCard onClose={() => undefined} />);
    const chat = root.root.findAllByType("a").find((n) => n.props.href === "https://988lifeline.org/chat");
    expect(chat).toBeTruthy();
    // External link discipline: a new tab that owes this page nothing.
    expect(chat!.props.target).toBe("_blank");
    expect(chat!.props.rel).toBe("noreferrer");
    expect(textOf(root)).toContain("Chat online at 988lifeline.org");
  });

  it("closes via its button", async () => {
    const onClose = vi.fn();
    const root = await render(<CrisisCard onClose={onClose} />);
    await press(root, "Close");
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe("CrisisCard safety-plan link (clinical review 2026-09-27)", () => {
  it("shows nothing while the vault is locked — the static resources stay complete and first", async () => {
    vault.lock();
    const onMakeSafetyPlan = vi.fn();
    const root = await render(<CrisisCard onClose={() => undefined} onMakeSafetyPlan={onMakeSafetyPlan} />);
    expect(textOf(root)).not.toContain("Make a safety plan");
    // The plan is a supplement, never a gate: every line is still here.
    expect(textOf(root)).toContain("988");
    expect(textOf(root)).toContain("741741");
    expect(textOf(root)).toContain("findahelpline.com");
  });

  it("while unlocked, the link renders BELOW the resources and opens the plan", async () => {
    vault.unlock({ authKey: key(), dataKey: key() }, "user-1");
    const onMakeSafetyPlan = vi.fn();
    const root = await render(<CrisisCard onClose={() => undefined} onMakeSafetyPlan={onMakeSafetyPlan} />);
    const text = textOf(root);
    expect(text).toContain("Make a safety plan");
    // Static resources first, plan link after them.
    expect(text.indexOf("findahelpline.com")).toBeLessThan(text.indexOf("Make a safety plan"));
    await press(root, "Make a safety plan");
    expect(onMakeSafetyPlan).toHaveBeenCalledTimes(1);
    vault.lock();
  });
});
