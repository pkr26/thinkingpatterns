/** Tiny renderer helpers for portal view tests (react-test-renderer).
 *
 *  Redesign 2026-09-26: components may wrap their labels in styled spans,
 *  so label/text matching walks the subtree recursively instead of reading
 *  direct string children only. */
import { act } from "react";
import RTR from "react-test-renderer";
import type { ReactTestInstance } from "react-test-renderer";

type ReactTestRenderer = ReturnType<typeof RTR.create>;

type NodeWithChildren = { children: unknown[] };

export async function render(ui: React.ReactElement): Promise<ReactTestRenderer> {
  let root!: ReactTestRenderer;
  await act(async () => {
    root = RTR.create(ui);
  });
  return root;
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

const allStrings = (node: unknown): string[] => {
  const children = (node as NodeWithChildren | null)?.children;
  if (!Array.isArray(children)) return [];
  return children.flatMap((child) => (typeof child === "string" ? [child] : allStrings(child)));
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

/** Every text string in the tree, ONCE, in document order — occurrence
 *  COUNTS stay exact (textOf re-reports nested text at every level). */
export function stringsOf(root: ReactTestRenderer): string[] {
  return allStrings(root.root);
}

export async function press(root: ReactTestRenderer, label: string): Promise<void> {
  const button = root.root.findAllByType("button").find((n) => joined(n) === label);
  if (!button) throw new Error(`no button labeled ${JSON.stringify(label)}`);
  await act(async () => {
    button.props.onClick();
  });
}

export function buttonByLabel(root: ReactTestRenderer, label: string): boolean {
  return root.root.findAllByType("button").some((n) => joined(n) === label);
}

/** Type into a <label>-wrapped input, matched by the label's text (the
 * Field component renders exactly that shape). */
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

export async function typeTextarea(root: ReactTestRenderer, placeholder: string, value: string): Promise<void> {
  const field = root.root.findAllByType("textarea").find((n) => n.props.placeholder === placeholder);
  if (!field) throw new Error(`no textarea matching ${JSON.stringify(placeholder)}`);
  await act(async () => {
    field.props.onChange({ target: { value } });
  });
}
