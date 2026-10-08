import { expect, it, vi } from "vitest";
import { act } from "react";
import { publicSurface } from "./helpers/publicSurface";
import { Button, Card, Disclosure, ErrorBanner, Field, InfoBanner, Note, PasswordStrengthMeter } from "../src/ui";
import { press, render, textOf } from "./helpers/rtr";

it("preserves the public layout, labels and accessibility states of portal controls", async () => {
  const root = await render(<main>
    <Button label="Continue" />
    <Button label="Remove" danger small disabled />
    <Button label="Back" variant="ghost" />
    <Button label="Save" type="submit" />
    <Card title="Ordinary card"><p>Body</p></Card>
    <Card title="Danger card" deep tone="danger" className="account-warning"><p>Important content</p></Card>
    <Card><p>Card without heading</p></Card>
    <Field label="Name" value="Example" onChange={() => {}} />
    <Field label="Email" value="person@example.test" type="email" placeholder="Email address" autoComplete="email" onChange={() => {}} />
    <Disclosure summary="Read the policy"><p>Policy details</p></Disclosure>
    <Note>Plain note</Note><Note tone="muted">Muted note</Note><Note tone="ok" role="status">Saved</Note>
    <Note tone="danger" role="alert">Failed</Note><Note tone="warn">Warning</Note>
    <ErrorBanner message="Try again" /><InfoBanner message="Loading" /><InfoBanner message="Account notice" flush />
    <PasswordStrengthMeter strength={0} /><PasswordStrengthMeter strength={1} />
    <PasswordStrengthMeter strength={2} /><PasswordStrengthMeter strength={3} /><PasswordStrengthMeter strength={4} />
  </main>);
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it("reveals and remasks password fields while preserving field input and labels", async () => {
  const change = vi.fn();
  const root = await render(<Field label="Current password" value="secret phrase" type="password" reveal onChange={change} />);
  expect(root.root.findByType("input").props.type).toBe("password");
  expect(textOf(root)).toContain("Show password");
  await press(root, "Show password");
  expect(root.root.findByType("input").props.type).toBe("text");
  expect(textOf(root)).toContain("Hide password");
  await act(async () => { root.root.findByType("input").props.onChange({ target: { value: "replacement" } }); });
  expect(change).toHaveBeenCalledExactlyOnceWith("replacement");
  await press(root, "Hide password");
  expect(root.root.findByType("input").props.type).toBe("password");
  await act(async () => { root.update(<Field label="Email" value="doctor@example.test" type="email" reveal onChange={change} />); });
  expect(root.root.findByType("input").props.type).toBe("email");
  expect(root.root.findAllByType("button")).toHaveLength(0);
});

it("omits empty notices and rejects an ambiguous submit action", async () => {
  const empty = await render(<><ErrorBanner message="" /><InfoBanner message="" /></>);
  expect(empty.toJSON()).toBeNull();
  await expect(render(<Button label="Save" type="submit" onPress={() => {}} />)).rejects.toThrow("a submit button must not carry its own onPress (double-fire)");
});
