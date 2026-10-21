/** public UI regression: actual App mounts the shipped LoginView.
 * No successful credentials, session adoption, key mocks or private state setters. */
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { applyLanguagePref } from "../src/strings";
import { resetTestState, stubFetch } from "./helpers/api";
import { buttonByLabel, isDisabled, press, render, textOfNode, typeInto } from "./helpers/rtr";

let mounted: ReactTestRenderer | undefined;
function input(root: ReactTestRenderer, label: string) {
  const found = root.root.findAllByType("input").find(node => node.parent?.type === "label" && textOfNode(node.parent).includes(label));
  if (!found) throw new Error("SetupError: shipped labeled input absent: " + label);
  return found;
}
async function mountActualLogin(): Promise<ReactTestRenderer> {
  mounted = await render(<App />);
  const deadline = Date.now() + 5000;
  while (!buttonByLabel(mounted, "Sign in")) {
    if (Date.now() > deadline) throw new Error("SetupError: actual App boot did not publish Login");
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 10)); });
  }
  return mounted;
}
beforeEach(() => {
  vi.useRealTimers(); resetTestState(); applyLanguagePref("en");
  stubFetch(() => { throw new Error("SetupError: no credential request belongs to empty-field presentation"); });
});
afterEach(async () => {
  try { if (mounted) await act(async () => { mounted!.unmount(); }); }
  finally { mounted = undefined; resetTestState(); vi.unstubAllGlobals(); }
});

it("actual App sign-in starts with an empty username and keeps explicit user edits controlled", async () => {
  const root = await mountActualLogin();
  expect(input(root, "Username").props.value).toBe("");
  expect(input(root, "Password").props.value).toBe("");
  expect(input(root, "Username").props.autoComplete).toBe("username");
  expect(isDisabled(root, "Sign in")).toBe(false);
  await typeInto(root, "Username", "synthetic_explicit_user");
  expect(input(root, "Username").props.value).toBe("synthetic_explicit_user");
  await typeInto(root, "Username", "");
  expect(input(root, "Username").props.value).toBe("");
});

it("actual App registration opens with an empty username and an unchecked age attestation", async () => {
  const root = await mountActualLogin();
  await press(root, "Create an account");
  expect(input(root, "Username").props.value).toBe("");
  expect(input(root, "Password").props.value).toBe("");
  expect(input(root, "Confirm password").props.value).toBe("");
  const age = root.root.findAllByType("input").find(node => node.props.type === "checkbox");
  if (!age) throw new Error("SetupError: actual registration age control absent");
  expect(age.props.checked).toBe(false);
  expect(isDisabled(root, "Create journal")).toBe(true);
});
