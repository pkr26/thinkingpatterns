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
import { crisisDialogShownOn, recordCrisisDialogShown } from "../src/crisisDialog";
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

/** independent audit 2026-09-27 (P2): the prompt throttle used to persist
 *  a PLAINTEXT DATE of a crisis-flagged interaction in localStorage
 *  (mindpattern.crisisDialog.v1.<userId>). The record is session-scoped in
 *  memory now, and the legacy key is swept on first use. */
describe("crisis prompt throttle (audit 2026-09-27: no plaintext date on disk)", () => {
  it("stamps once per (account, day) IN MEMORY ONLY — no localStorage write, and the legacy plaintext stamp is swept", async () => {
    const storage = (globalThis as { window?: { localStorage?: Storage } }).window!.localStorage!;
    // A pre-fix leftover: a plaintext crisis-interaction date on disk.
    storage.setItem("mindpattern.crisisDialog.v1.user-legacy", "2026-09-26");
    const setSpy = vi.spyOn(storage, "setItem");
    expect(await crisisDialogShownOn("user-crisis-a", "2026-09-27")).toBe(false);
    await recordCrisisDialogShown("user-crisis-a", "2026-09-27");
    // Once-per-day, per-account, in-memory semantics unchanged:
    expect(await crisisDialogShownOn("user-crisis-a", "2026-09-27")).toBe(true);
    expect(await crisisDialogShownOn("user-crisis-a", "2026-09-26")).toBe(false); // day-scoped
    expect(await crisisDialogShownOn("user-crisis-b", "2026-09-27")).toBe(false); // account-scoped
    // The throttle wrote NOTHING to localStorage — no date of a
    // crisis-flagged interaction ever touches disk...
    expect(setSpy).not.toHaveBeenCalled();
    // ...and the pre-fix plaintext stamp was removed, not resurrected.
    expect(storage.getItem("mindpattern.crisisDialog.v1.user-legacy")).toBeNull();
    const keys = Array.from({ length: storage.length }, (_, i) => storage.key(i));
    expect(keys.filter((k) => k?.startsWith("mindpattern.crisisDialog"))).toEqual([]);
    setSpy.mockRestore();
  });
});
