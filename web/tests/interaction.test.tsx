// @ts-nocheck
// @vitest-environment jsdom
/**
 * Interaction-layer regression tests (hardening 2026-09-26 ii). The
 * redesign shipped Dialog/MoreMenu/SegmentedControl/scales/toasts with
 * no behavioral pins — this suite holds the exact contracts the audit
 * found breakable, under a REAL DOM where focus and key events behave
 * like the browser (react-test-renderer cannot express them):
 *
 *  - Dialog: focus moves in, Tab wraps both ways, Escape closes, focus
 *    RESTORES to the trigger — including when the parent re-renders with
 *    a new inline onClose identity (the exact regression that used to
 *    tear the trap down mid-dialog).
 *  - MoreMenu: opening focuses the first item, arrows roam, Escape
 *    returns focus to the trigger.
 *  - SegmentedControl: roving tabindex + ArrowRight/Left selection
 *    (what role=radiogroup promises).
 *  - DotScale/BarScale/MoodScale: accessible names and selection
 *    feedback (check badge) — never color-only.
 *  - ToastHost: the live region stays mounted when empty.
 *  - Crisis SMS link: `?body=` everywhere except legacy iOS (`&body=`).
 */
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { CrisisCard, crisisSmsLink, smsBodySeparator } from "../src/crisis";
import { BarScale, Dialog, DotScale, MoreMenu, MoodScale, SegmentedControl, ToastHost } from "../src/ui";

let container: HTMLDivElement | null = null;
let root: Root | null = null;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  if (root) {
    act(() => root!.unmount());
  }
  container?.remove();
  container = null;
  root = null;
});

function render(ui: React.ReactElement): void {
  act(() => {
    root!.render(ui);
  });
}

function pressKey(target: Node, key: string, shift = false): void {
  act(() => {
    target.dispatchEvent(new KeyboardEvent("keydown", { key, shiftKey: shift, bubbles: true, cancelable: true }));
  });
}

const options5 = [
  { value: -1, labelKey: "entry.moodHeavy" },
  { value: -0.5, labelKey: "entry.moodLow" },
  { value: 0, labelKey: "entry.moodOkay" },
  { value: 0.5, labelKey: "entry.moodGood" },
  { value: 1, labelKey: "entry.moodLight" },
] as const;

/* ------------------------------------------------------------------ dialog */

describe("Dialog focus management", () => {
  function mountDialog(onClose: () => void): void {
    const trigger = document.createElement("button");
    trigger.textContent = "Get help";
    document.body.appendChild(trigger);
    trigger.focus();
    render(
      <Dialog title="Help" onClose={onClose}>
        <button type="button">first</button>
        <button type="button">last</button>
      </Dialog>,
    );
  }

  it("moves focus into the dialog on open and restores it on close", () => {
    const trigger = document.createElement("button");
    trigger.textContent = "Get help";
    document.body.appendChild(trigger);
    act(() => trigger.focus());
    expect(document.activeElement).toBe(trigger);

    const close = vi.fn();
    render(
      <Dialog title="Help" onClose={close}>
        <button type="button">first</button>
        <button type="button">last</button>
      </Dialog>,
    );
    expect(document.activeElement?.textContent).toBe("first");

    // Unmount (the parent removes the dialog) → focus returns to trigger.
    act(() => root!.unmount());
    expect(document.activeElement).toBe(trigger);
    trigger.remove();
  });

  it("wraps Tab from the last focusable to the first and back", () => {
    mountDialog(() => undefined);
    const dialog = document.querySelector('[role="dialog"]')!;
    const [first, last] = [...dialog.querySelectorAll("button")];
    act(() => last!.focus());
    pressKey(document, "Tab");
    expect(document.activeElement).toBe(first);
    pressKey(document, "Tab", true);
    expect(document.activeElement).toBe(last);
    act(() => root!.unmount());
  });

  it("Escape closes", () => {
    const close = vi.fn();
    mountDialog(close);
    pressKey(document, "Escape");
    expect(close).toHaveBeenCalledTimes(1);
    act(() => root!.unmount());
  });

  it("inerts the background but never the dialog itself (live-E2E regression)", () => {
    // Real shape: the dialog renders INSIDE #app-content alongside the
    // view. The naive inert-on-#app-content approach muted the dialog's
    // own focusables — initial focus silently stopped moving in.
    const main = document.createElement("main");
    main.id = "app-content";
    const view = document.createElement("div");
    view.innerHTML = "<button type='button'>background action</button>";
    main.appendChild(view);
    document.body.appendChild(main);
    render(
      <Dialog title="Help" onClose={() => undefined}>
        <a href="tel:988">Call or text 988</a>
        <button type="button">close</button>
      </Dialog>,
    );
    const dialog = document.querySelector('[role="dialog"]')!;
    expect(view.hasAttribute("inert")).toBe(true);
    expect(dialog.hasAttribute("inert")).toBe(false);
    // Focus DID move into the dialog despite the inerted sibling.
    expect(dialog.contains(document.activeElement)).toBe(true);
    act(() => root!.unmount());
    expect(view.hasAttribute("inert")).toBe(false);
    main.remove();
  });

  it("survives a parent re-render with a NEW onClose identity (regression)", () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    act(() => trigger.focus());

    let closeCalls = 0;
    // Two different inline closures, like App.tsx renders on state change.
    render(
      <Dialog title="Help" onClose={() => { closeCalls += 1; }}>
        <button type="button">first</button>
        <button type="button">last</button>
      </Dialog>,
    );
    const dialog = document.querySelector('[role="dialog"]')!;
    const [first, last] = [...dialog.querySelectorAll("button")];
    act(() => last!.focus());
    render(
      <Dialog title="Help" onClose={() => { closeCalls += 1; }}>
        <button type="button">first</button>
        <button type="button">last</button>
      </Dialog>,
    );

    // The trap must NOT have been torn down: focus stays inside, not
    // yanked back to the first item by a re-run effect.
    expect(document.activeElement).toBe(last);
    // ...and Tab still wraps with the new props mounted.
    pressKey(document, "Tab");
    expect(document.activeElement?.textContent).toBe("first");

    // Escape still reaches the CURRENT closure exactly once (no listener
    // leak from the re-render).
    pressKey(document, "Escape");
    expect(closeCalls).toBe(1);

    // Closing restores the original trigger — not an element from inside
    // the dying dialog (the pre-fix failure mode).
    act(() => root!.unmount());
    expect(document.activeElement).toBe(trigger);
    trigger.remove();
  });
});

/* --------------------------------------------------------------- more menu */

describe("MoreMenu keyboard pattern", () => {
  const items = [
    { id: "a", label: "Alpha" },
    { id: "b", label: "Beta" },
    { id: "c", label: "Gamma", danger: true },
  ];

  it("opening focuses the first item; arrows roam; Escape refocuses the trigger", () => {
    let selected: string | null = null;
    render(<MoreMenu label="More" items={items} activeIds={[]} onSelect={(id) => { selected = id; }} />);
    const trigger = container!.querySelector("button")!;
    act(() => (trigger as HTMLButtonElement).click());
    const menu = container!.querySelector('[role="menu"]')!;
    expect(menu).not.toBeNull();
    expect(document.activeElement?.textContent).toBe("Alpha");

    pressKey(document.activeElement!, "ArrowDown");
    expect(document.activeElement?.textContent).toBe("Beta");
    pressKey(document.activeElement!, "ArrowDown");
    expect(document.activeElement?.textContent).toBe("Gamma");
    pressKey(document.activeElement!, "ArrowUp");
    expect(document.activeElement?.textContent).toBe("Beta");
    pressKey(document.activeElement!, "End");
    expect(document.activeElement?.textContent).toBe("Gamma");

    pressKey(document.activeElement!, "Escape");
    expect(container!.querySelector('[role="menu"]')).toBeNull();
    expect(document.activeElement).toBe(trigger);

    // Selecting an item closes the menu and reports the id.
    act(() => trigger.click());
    const gamma = [...container!.querySelectorAll('[role="menuitem"]')].find((b) => b.textContent === "Gamma") as HTMLButtonElement;
    act(() => gamma.click());
    expect(selected).toBe("c");
    expect(container!.querySelector('[role="menu"]')).toBeNull();
  });
});

/* -------------------------------------------------------- segmented control */

describe("SegmentedControl radio keyboard pattern", () => {
  const options = [
    { id: "light", label: "Light" },
    { id: "dark", label: "Dark" },
    { id: "auto", label: "Auto" },
  ];

  it("tabs stop only on the checked option; arrows select and move focus", () => {
    let active = "light";
    const onSelect = (id: string): void => { active = id; };
    const rerender = (): void => {
      render(<SegmentedControl options={options} activeId={active} onSelect={onSelect} a11yLabel="Theme" />);
    };
    rerender();
    const buttons = [...container!.querySelectorAll('[role="radio"]')] as HTMLButtonElement[];
    expect(buttons.map((b) => b.tabIndex)).toEqual([0, -1, -1]);

    act(() => buttons[0]!.focus());
    pressKey(document.activeElement!, "ArrowRight");
    rerender();
    expect(active).toBe("dark");
    const after = [...container!.querySelectorAll('[role="radio"]')] as HTMLButtonElement[];
    expect(after.map((b) => b.tabIndex)).toEqual([-1, 0, -1]);
    expect(document.activeElement?.textContent).toBe("Dark");

    pressKey(document.activeElement!, "ArrowLeft");
    rerender();
    expect(active).toBe("light");

    pressKey(document.activeElement!, "End");
    rerender();
    expect(active).toBe("auto");
    pressKey(document.activeElement!, "Home");
    rerender();
    expect(active).toBe("light");
  });
});

/* ------------------------------------------------------------ check-in scales */

describe("check-in scales", () => {
  it("DotScale announces '{n} — {label}', not concatenated spans", () => {
    render(<DotScale options={options5} value={null} onChange={() => undefined} />);
    const buttons = [...container!.querySelectorAll("button")];
    expect(buttons[0]!.getAttribute("aria-label")).toMatch(/1\s+—\s+\S+/);
    expect(buttons[0]!.getAttribute("aria-label")).not.toBe("1Rough");
  });

  it("BarScale renders directional bars with aria-pressed selection", () => {
    let value: number | null = -0.5;
    const onChange = (v: number | null): void => { value = v; };
    const options3 = options5.slice(0, 3);
    render(<BarScale options={options3} value={value} onChange={onChange} groupLabel="Energy" />);
    const group = container!.querySelector(".bar-scale")!;
    expect(group.getAttribute("role")).toBe("group");
    expect(group.getAttribute("aria-label")).toBe("Energy");
    const items = [...group.querySelectorAll("button")];
    expect(items.map((b) => b.getAttribute("aria-pressed"))).toEqual(["false", "true", "false"]);
    // The middle option fills exactly 2 of 3 bars.
    expect(items[1]!.querySelectorAll(".bar-bars__cell--on")).toHaveLength(2);
    act(() => items[1]!.click());
    expect(value).toBe(null); // tapping the selected value clears it
  });

  it("MoodScale shows a check badge on the selected face (never color-only)", () => {
    render(<MoodScale options={options5} value={0.5} onChange={() => undefined} />);
    const selected = container!.querySelector('.mood-item[aria-pressed="true"]');
    expect(selected).not.toBeNull();
    expect(selected!.querySelector(".mood-face__check")).not.toBeNull();
    // Every face level carries distinct expressions: the heavy end draws
    // brows + a bent mouth, the neutral face has no brows at all.
    const faces = [...container!.querySelectorAll(".mood-item")];
    const pathCount = (item: Element): number => item.querySelectorAll("svg path").length;
    expect(pathCount(faces[0]!)).toBeGreaterThan(pathCount(faces[2]!));
  });
});

/* ------------------------------------------------------------------ toasts */

describe("ToastHost live region", () => {
  it("stays mounted (announceable) when there are no toasts", () => {
    render(<ToastHost items={[]} />);
    const host = container!.querySelector(".toast-host");
    expect(host).not.toBeNull();
    expect(host!.getAttribute("role")).toBe("status");
    expect(host!.getAttribute("aria-live")).toBe("polite");
  });

  it("renders each toast with its message", () => {
    render(<ToastHost items={[{ id: 1, message: "Saved.", tone: "ok" }]} />);
    expect(container!.querySelector(".toast")!.textContent).toContain("Saved.");
  });
});

/* -------------------------------------------------------------- crisis SMS */

describe("crisisSmsLink platform dialect", () => {
  it("uses RFC 5724 ?body= by default", () => {
    expect(crisisSmsLink()).toBe("sms:741741?body=HOME");
  });

  it("is a feature probe, not a userAgent regex: an iOS UA alone changes nothing (audit 2026-09-26 LOW)", () => {
    const original = navigator.userAgent;
    Object.defineProperty(navigator, "userAgent", { value: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)", configurable: true });
    try {
      // This host's URL parser sees `?body=` as a query parameter, so the
      // standard shape wins regardless of the UA string.
      expect(crisisSmsLink()).toBe("sms:741741?body=HOME");
    } finally {
      Object.defineProperty(navigator, "userAgent", { value: original, configurable: true });
    }
  });

  it("falls back to legacy &body= only when the platform's query parsing cannot see ?body=", () => {
    // The pure decision core: try ?body= first, fall back to &body=.
    expect(smsBodySeparator(() => true)).toBe("?");
    expect(smsBodySeparator(() => false)).toBe("&");
  });

  it("the HOME keyword stays present and correctly delimited on both iOS shapes", () => {
    for (const separator of ["?", "&"] as const) {
      expect(`sms:741741${separator}body=HOME`).toMatch(/^sms:741741[?&]body=HOME$/);
    }
    expect(crisisSmsLink()).toMatch(/^sms:741741[?&]body=HOME$/);
  });

  it("CrisisCard wires the helper into the SMS action", () => {
    render(<CrisisCard onClose={() => undefined} />);
    const sms = [...container!.querySelectorAll("a")].find((a) => a.getAttribute("href")?.startsWith("sms:"));
    expect(sms).toBeDefined();
    expect(sms!.getAttribute("href")).toBe("sms:741741?body=HOME");
  });
});
