/** Tiny renderer helpers for web view tests (react-test-renderer),
 *  mirroring the portal's helper.
 *
 *  Redesign 2026-09-26: components may wrap their labels in styled spans
 *  and carry decorative SVGs, so label/text matching walks the subtree
 *  recursively instead of reading direct string children only. The
 *  behavioral contracts stay: press() refuses disabled buttons (their
 *  handler is absent by design), and field lookups still require the
 *  control to be wrapped by its <label>. */
import { act } from "react";
import { afterEach } from "vitest";
import RTR from "react-test-renderer";
import type { ReactTestInstance } from "react-test-renderer";

type ReactTestRenderer = ReturnType<typeof RTR.create>;

const mountedRoots = new Set<ReactTestRenderer>();
afterEach(async () => {
  await act(async () => { for (const root of mountedRoots) root.unmount(); });
  mountedRoots.clear();
});

type NodeWithChildren = { children: unknown[] };

export async function render(ui: React.ReactElement): Promise<ReactTestRenderer> {
  let root!: ReactTestRenderer;
  await act(async () => {
    root = RTR.create(ui);
  });
  mountedRoots.add(root);
  return root;
}

/** Pump REAL time for genuinely-async work (WebCrypto derivations land
 *  on the libuv threadpool, which microtask flush() cannot advance). Use
 *  only in tests running on real timers. */
export async function settle(ms = 60, rounds = 4): Promise<void> {
  for (let i = 0; i < rounds; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, ms));
    });
  }
}

export async function flush(times = 3): Promise<void> {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await Promise.resolve();
    });
  }
}

/** All text inside a rendered node, depth-first (spans/svg-safe). */
export const textOfNode = (node: unknown): string => {
  const children = (node as NodeWithChildren | null)?.children;
  if (!Array.isArray(children)) return "";
  return children
    .map((child) => (typeof child === "string" ? child : textOfNode(child)))
    .join("");
};

const textNodes = (root: ReactTestRenderer): ReactTestInstance[] =>
  root.root
    .findAllByType("span")
    .concat(root.root.findAllByType("p"))
    .concat(root.root.findAllByType("h1"))
    .concat(root.root.findAllByType("h2"))
    .concat(root.root.findAllByType("h3"))
    .concat(root.root.findAllByType("strong"))
    .concat(root.root.findAllByType("button"))
    .concat(root.root.findAllByType("div"));

const joined = (n: ReactTestInstance): string => textOfNode(n);

export function textOf(root: ReactTestRenderer): string {
  return textNodes(root).map(joined).join(" | ");
}

export async function press(root: ReactTestRenderer, label: string): Promise<void> {
  const button = root.root.findAllByType("button").find((n) => joined(n) === label);
  if (!button) throw new Error(`no button labeled ${JSON.stringify(label)}`);
  // A disabled Button withholds onClick entirely (by design, see ui.tsx);
  // pressing one from a test is a test bug, not an app behavior to drive.
  if (typeof button.props.onClick !== "function") {
    throw new Error(`button ${JSON.stringify(label)} is disabled — there is no click path to press`);
  }
  await act(async () => {
    button.props.onClick();
  });
}

/** Whether the labeled button is in its disabled state (the F3 gate
 *  lives here, so tests assert state instead of forcing a click). */
export function isDisabled(root: ReactTestRenderer, label: string): boolean {
  const button = root.root.findAllByType("button").find((n) => joined(n) === label);
  if (!button) throw new Error(`no button labeled ${JSON.stringify(label)}`);
  return button.props.disabled === true;
}

export function buttonByLabel(root: ReactTestRenderer, label: string): boolean {
  return root.root.findAllByType("button").some((n) => joined(n) === label);
}

/** Press an icon-only button matched by its aria-label (redesign
 *  2026-09-26: calendar pagers and other icon controls carry no text). */
export async function pressAria(root: ReactTestRenderer, ariaLabel: string): Promise<void> {
  const button = root.root.findAllByType("button").find((n) => n.props["aria-label"] === ariaLabel);
  if (!button) throw new Error(`no button with aria-label ${JSON.stringify(ariaLabel)}`);
  if (typeof button.props.onClick !== "function") {
    throw new Error(`button ${JSON.stringify(ariaLabel)} is disabled — there is no click path to press`);
  }
  await act(async () => {
    button.props.onClick();
  });
}

/** Flip a role=switch control. With `matching`, picks the switch whose
 *  aria-label contains it (Settings now renders more than one switch —
 *  the LLM consent and the check-in cadence). */
export async function pressSwitch(root: ReactTestRenderer, matching?: string): Promise<void> {
  const toggle = root.root.findAllByType("button").find((n) =>
    n.props.role === "switch"
    && (matching === undefined || String(n.props["aria-label"] ?? "").includes(matching)));
  if (!toggle) throw new Error(`no role=switch control rendered${matching ? ` matching ${JSON.stringify(matching)}` : ""}`);
  await act(async () => {
    toggle.props.onClick();
  });
}

/** Type into a <label>-wrapped input, matched by the label's text (the
 *  Field component renders exactly that shape). */
export async function typeInto(root: ReactTestRenderer, labelText: string, value: string): Promise<void> {
  const field = root.root.findAllByType("input").find((n) => {
    const label = n.parent;
    return label !== null && label.type === "label" && textOfNode(label).includes(labelText);
  });
  if (!field) throw new Error(`no input whose label contains ${JSON.stringify(labelText)}`);
  await act(async () => {
    field.props.onChange({ target: { value } });
  });
}

/** Type into a <label>-wrapped textarea, matched by the label's text (the
 *  TextArea component renders exactly that shape). */
export async function typeArea(root: ReactTestRenderer, labelText: string, value: string): Promise<void> {
  const field = root.root.findAllByType("textarea").find((n) => {
    const label = n.parent;
    return label !== null && label.type === "label" && textOfNode(label).includes(labelText);
  });
  if (!field) throw new Error(`no textarea whose label contains ${JSON.stringify(labelText)}`);
  await act(async () => {
    field.props.onChange({ target: { value } });
  });
}

/** Set a <label>-wrapped checkbox, matched by the label's text (the
 *  Checkbox component renders exactly that shape — a real input inside
 *  its label, so keyboard/SR semantics stay real in the app too). */
export async function setCheckbox(root: ReactTestRenderer, labelText: string, checked: boolean): Promise<void> {
  const box = root.root.findAllByType("input").find((n) => {
    const label = n.parent;
    return n.props.type === "checkbox" && label !== null && label.type === "label" && textOfNode(label).includes(labelText);
  });
  if (!box) throw new Error(`no checkbox whose label contains ${JSON.stringify(labelText)}`);
  await act(async () => {
    box.props.onChange({ target: { checked } });
  });
}
