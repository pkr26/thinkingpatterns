/**
 * react-test-renderer utilities: render with act(), flatten rendered text,
 * locate touchables by their label, fire handler props, and drive Alert
 * dialog button callbacks.
 */
import ReactTestRenderer, { act, ReactTestInstance } from "react-test-renderer";
import React from "react";
import { Text, TouchableOpacity, Alert, TextInput, Switch } from "./rnMock";

export { act };

export type Root = ReactTestRenderer;

export async function render(ui: React.ReactElement): Promise<ReactTestRenderer> {
  let renderer!: ReactTestRenderer;
  await act(async () => {
    renderer = ReactTestRenderer.create(ui);
  });
  return renderer;
}

export async function flush(times = 3): Promise<void> {
  for (let i = 0; i < times; i++) {
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
}

function flattenChildren(c: unknown): string {
  if (c === null || c === undefined || typeof c === "boolean") return "";
  if (typeof c === "string" || typeof c === "number") return String(c);
  if (Array.isArray(c)) return c.map(flattenChildren).join("");
  if (React.isValidElement(c)) return flattenChildren((c.props as { children?: unknown }).children);
  return "";
}

/** All rendered text, in document order, one entry per Text node. */
export function allText(root: ReactTestRenderer): string[] {
  return root.root.findAllByType(Text).map((n) => flattenChildren(n.props.children));
}

export function textOf(root: ReactTestRenderer): string {
  return allText(root).join(" ");
}

export function hasText(root: ReactTestRenderer, fragment: string): boolean {
  return textOf(root).includes(fragment);
}

/** The TouchableOpacity that contains a Text node matching `label`. */
export function touchableByLabel(root: ReactTestRenderer, label: string): ReactTestInstance {
  const textNode = root.root.findAllByType(Text).find((n) => flattenChildren(n.props.children).includes(label));
  if (!textNode) throw new Error(`no Text node containing ${JSON.stringify(label)}:\n${allText(root).join(" | ")}`);
  let node: ReactTestInstance | null = textNode;
  while (node && node.type !== TouchableOpacity) node = node.parent;
  if (!node) throw new Error(`no TouchableOpacity wrapping ${JSON.stringify(label)}`);
  return node;
}

export async function pressLabel(root: ReactTestRenderer, label: string): Promise<void> {
  const button = touchableByLabel(root, label);
  await act(async () => {
    await (button.props as { onPress?: () => unknown }).onPress?.();
  });
}

/** Fire onPress WITHOUT awaiting its promise — for tests that keep the
 *  handler busy (pending network) and assert the interim state. */
export async function firePress(root: ReactTestRenderer, label: string): Promise<void> {
  const button = touchableByLabel(root, label);
  await act(async () => {
    void (button.props as { onPress?: () => unknown }).onPress?.();
  });
}

export function inputByPlaceholder(root: ReactTestRenderer, placeholder: string): ReactTestInstance {
  const node = root.root.findAllByType(TextInput).find((n) => n.props.placeholder === placeholder);
  if (!node) throw new Error(`no TextInput with placeholder ${JSON.stringify(placeholder)}`);
  return node;
}

export async function typeInto(root: ReactTestRenderer, placeholder: string, value: string): Promise<void> {
  const input = inputByPlaceholder(root, placeholder);
  await act(async () => {
    (input.props as { onChangeText?: (t: string) => void }).onChangeText?.(value);
  });
}

export async function submitInput(root: ReactTestRenderer, placeholder: string): Promise<void> {
  const input = inputByPlaceholder(root, placeholder);
  await act(async () => {
    (input.props as { onSubmitEditing?: () => unknown }).onSubmitEditing?.();
  });
}

export function switchByValue(root: ReactTestRenderer, value: boolean): ReactTestInstance {
  const node = root.root.findAllByType(Switch).find((n) => n.props.value === value);
  if (!node) throw new Error(`no Switch with value=${value}`);
  return node;
}

export async function toggleSwitch(root: ReactTestRenderer, value: boolean, next: boolean): Promise<void> {
  const sw = switchByValue(root, value);
  await act(async () => {
    (sw.props as { onValueChange?: (v: boolean) => unknown }).onValueChange?.(next);
  });
}

export function lastAlert(): [string, string?, Array<{ text: string; onPress?: () => unknown }>?] {
  const calls = Alert.alert.mock.calls as [string, string?, Array<{ text: string; onPress?: () => unknown }>?][];
  const call = calls[calls.length - 1];
  if (!call) throw new Error("Alert.alert was never called");
  return call;
}

export async function pressAlertButton(label: string): Promise<void> {
  const call = lastAlert();
  const button = call[2]?.find((b) => b.text === label);
  if (!button) {
    throw new Error(`no alert button ${JSON.stringify(label)}; buttons: ${JSON.stringify(call[2])}`);
  }
  await act(async () => {
    await button.onPress?.();
  });
}

/** Screen names currently mounted as Stack.Screen children. */
export function screenNames(root: ReactTestRenderer): string[] {
  return root.root
    .findAll((n) => typeof n.props === "object" && n.props !== null && "name" in (n.props as Record<string, unknown>))
    .map((n) => (n.props as { name?: unknown }).name as string)
    .filter((n): n is string => typeof n === "string");
}

/** The options prop of a mounted Stack.Screen, by screen name. */
export function screenOptions(root: ReactTestRenderer, name: string): Record<string, unknown> {
  const node = root.root
    .findAll((n) => (n.props as { name?: unknown } | undefined)?.name === name)
    .find(() => true);
  if (!node) throw new Error(`no Stack.Screen named ${JSON.stringify(name)}`);
  return (node.props as { options?: Record<string, unknown> }).options ?? {};
}

/** Every style object rendered anywhere in the tree (StyleSheet.create is
 *  the identity in the mock, so style props ARE the literal objects). */
export function allStyles(root: ReactTestRenderer): Record<string, unknown>[] {
  const found: Record<string, unknown>[] = [];
  const visit = (style: unknown): void => {
    if (!style) return;
    if (Array.isArray(style)) {
      style.forEach(visit);
      return;
    }
    if (typeof style === "object") found.push(style as Record<string, unknown>);
  };
  for (const node of root.root.findAll(() => true)) visit((node.props as { style?: unknown }).style);
  return found;
}

/** Asserts that the exact style object appears in the rendered tree. */
export function expectStyle(root: ReactTestRenderer, expected: Record<string, unknown>): void {
  const styles = allStyles(root);
  if (!styles.some((s) => JSON.stringify(s) === JSON.stringify(expected))) {
    throw new Error(`style not rendered: ${JSON.stringify(expected)}\nrendered styles:\n${styles.map((s) => JSON.stringify(s)).join("\n")}`);
  }
}
