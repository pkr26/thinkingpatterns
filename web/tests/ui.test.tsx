/** UI kit: primitives render, respond, and carry the patient theme. */
import { describe, expect, it, vi } from "vitest";
import { AppFrame, Button, Card, ErrorBanner, Field, Note, theme } from "../src/ui";
import { flush, press, render, textOf, typeInto } from "./helpers/rtr";

describe("Button", () => {
  it("renders its label and fires onPress", async () => {
    const onPress = vi.fn();
    const root = await render(<Button label="Save" onPress={onPress} />);
    expect(textOf(root)).toContain("Save");
    await press(root, "Save");
    expect(onPress).toHaveBeenCalledTimes(1);
  });

  it("ignores presses when disabled", async () => {
    const onPress = vi.fn();
    const root = await render(<Button label="Save" onPress={onPress} disabled />);
    const button = root.root.findByType("button");
    expect(button.props.disabled).toBe(true);
    // Defense in depth: the handler is not merely ignored when disabled —
    // it is absent, so no synthetic click path can reach onPress.
    expect(button.props.onClick).toBeUndefined();
    expect(onPress).not.toHaveBeenCalled();
  });

  it("renders a danger variant with the danger color", async () => {
    const root = await render(<Button label="Delete" onPress={() => undefined} danger />);
    expect(root.root.findByType("button").props.style.backgroundColor).toBe(theme.danger);
  });
});

describe("Card", () => {
  it("renders an h2 title and children", async () => {
    const root = await render(
      <Card title="Today">
        <Note>hello</Note>
      </Card>,
    );
    expect(root.root.findAllByType("h2").length).toBe(1);
    expect(textOf(root)).toContain("Today");
    expect(textOf(root)).toContain("hello");
  });

  it("renders without a title", async () => {
    const root = await render(<Card>plain</Card>);
    expect(root.root.findAllByType("h2").length).toBe(0);
  });
});

describe("Field", () => {
  it("wraps a labeled input and reports changes", async () => {
    const onChange = vi.fn();
    const root = await render(<Field label="Username" value="a" onChange={onChange} />);
    await typeInto(root, "Username", "ab");
    expect(onChange).toHaveBeenCalledWith("ab");
    const input = root.root.findByType("input");
    expect(input.props.type).toBe("text");
  });

  it("passes type, placeholder and autoComplete through", async () => {
    const root = await render(
      <Field label="Password" value="" onChange={() => undefined} type="password" placeholder="•••" autoComplete="current-password" />,
    );
    const input = root.root.findByType("input");
    expect(input.props.type).toBe("password");
    expect(input.props.placeholder).toBe("•••");
    expect(input.props.autoComplete).toBe("current-password");
  });
});

describe("Note", () => {
  it("renders multiline text with pre-wrap and tones", async () => {
    const root = await render(
      <>
        <Note role="status">{"line one\nline two"}</Note>
        <Note tone="ok">good</Note>
        <Note tone="danger">bad</Note>
        <Note tone="warn">careful</Note>
      </>,
    );
    const notes = root.root.findAllByType("p");
    expect(notes[0]!.props.style.whiteSpace).toBe("pre-wrap");
    expect(notes[0]!.props.role).toBe("status");
    expect(notes[1]!.props.style.color).toBe(theme.ok);
    expect(notes[2]!.props.style.color).toBe(theme.danger);
    expect(notes[3]!.props.style.color).toBe(theme.warn);
  });
});

describe("ErrorBanner", () => {
  it("renders nothing without a message", async () => {
    const root = await render(<ErrorBanner message="" />);
    await flush();
    expect(root.toJSON()).toBeNull();
  });

  it("announces the message with role=alert", async () => {
    const root = await render(<ErrorBanner message="Something failed" />);
    expect(root.root.findByType("div").props.role).toBe("alert");
    expect(textOf(root)).toContain("Something failed");
  });
});

describe("AppFrame", () => {
  it("renders the sticky header, the crisis entry point, and children", async () => {
    const onCrisis = vi.fn();
    const root = await render(
      <AppFrame title="MindPattern" onCrisis={onCrisis}>
        <Note>content</Note>
      </AppFrame>,
    );
    expect(root.root.findByType("header").props.className).toBe("app-header");
    expect(root.root.findByType("main").props.className).toBe("app-main");
    expect(root.root.findAllByType("h1").length).toBe(1);
    await press(root, "Get help");
    expect(onCrisis).toHaveBeenCalledTimes(1);
    expect(textOf(root)).toContain("content");
  });
});
