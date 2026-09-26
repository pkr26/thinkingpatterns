/** Tiny renderer helpers for web view tests (react-test-renderer),
 *  mirroring the portal's helper. */
import { act } from "react";
import RTR from "react-test-renderer";
import type { ReactTestInstance } from "react-test-renderer";

type ReactTestRenderer = ReturnType<typeof RTR.create>;

type NodeWithChildren = { children: React.ReactNode[] };

export async function render(ui: React.ReactElement): Promise<ReactTestRenderer> {
  let root!: ReactTestRenderer;
  await act(async () => {
    root = RTR.create(ui);
  });
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

const joined = (n: ReactTestInstance): string =>
  (n as unknown as NodeWithChildren).children.join("");

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
 * lives here, so tests assert state instead of forcing a click). */
export function isDisabled(root: ReactTestRenderer, label: string): boolean {
  const button = root.root.findAllByType("button").find((n) => joined(n) === label);
  if (!button) throw new Error(`no button labeled ${JSON.stringify(label)}`);
  return button.props.disabled === true;
}

export function buttonByLabel(root: ReactTestRenderer, label: string): boolean {
  return root.root.findAllByType("button").some((n) => joined(n) === label);
}

/** Type into a <label>-wrapped input, matched by the label's text (the
 *  Field component renders exactly that shape). */
export async function typeInto(root: ReactTestRenderer, labelText: string, value: string): Promise<void> {
  const field = root.root.findAllByType("input").find((n) => {
    const label = n.parent;
    return (
      label !== null &&
      (label as unknown as NodeWithChildren).children.some(
        (c) => typeof c === "string" && c.includes(labelText),
      )
    );
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
    return (
      label !== null &&
      (label as unknown as NodeWithChildren).children.some(
        (c) => typeof c === "string" && c.includes(labelText),
      )
    );
  });
  if (!field) throw new Error(`no textarea whose label contains ${JSON.stringify(labelText)}`);
  await act(async () => {
    field.props.onChange({ target: { value } });
  });
}
