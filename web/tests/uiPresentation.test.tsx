import { act } from "react";
import { expect, it, vi } from "vitest";
import { AppFrame, Avatar, BarScale, BottomNav, Button, Card, Checkbox, Chip, Dialog, DotScale, Field, Icon, Logo, MoodScale, MoreMenu, NavTabs, Note, PillNote, ProgressDots, ProgressTrack, SegmentedControl, Skeleton, TextArea, ToastHost, Toggle, type IconName } from "../src/ui";
import { ENERGY_OPTIONS, MOOD_OPTIONS, SLEEP_OPTIONS } from "../src/mood";
import { publicSurface } from "./helpers/publicSurface";
import { press, render } from "./helpers/rtr";

const noop = () => {};
const icons: IconName[] = ["home", "book", "sparkles", "help", "clipboard", "share", "sliders", "shield", "flame", "sun", "moon", "chevron-left", "chevron-right", "chevron-down", "check", "x", "heart", "alert", "info", "copy", "more", "logout", "edit", "trash", "search", "refresh", "phone", "mic", "play"];
const nav = [{ id: "today", label: "Today", icon: "home" as const }, { id: "history", label: "History", icon: "book" as const }];

it("preserves the rendered patient controls, decorative drawings and accessible states", async () => {
  const root = await render(<main>
    {icons.map(name => <Icon key={name} name={name} />)}<Icon name="home" size={27} /><Logo /><Logo size={42} />
    <Button label="Save" onPress={noop} /><Button label="Remove" onPress={noop} danger small block icon="trash" />
    <Button label="Back" onPress={noop} variant="ghost" icon="chevron-left" /><Button label="Wait" onPress={noop} variant="quiet" disabled />
    <Chip label="Walking" onPress={noop} selected icon="sun" /><Chip label="Rest" onPress={noop} disabled /><Chip label="Insert prompt" onPress={noop} toggle={false} />
    <Card title="Ordinary"><p>Body</p></Card><Card deep title="Private" tone="sensitive"><p>Private writing</p></Card><Card tone="danger"><p>Remove account</p></Card>
    <Field label="Name" value="Alice" onChange={noop} /><Field label="Password" value="secret" type="password" autoComplete="current-password" placeholder="Password" onChange={noop} />
    <TextArea label="Journal" value="Two\nlines" onChange={noop} /><TextArea label="Plan" value="Plan text" onChange={noop} rows={4} maxLength={200} disabled placeholder="Start here" />
    <Note>Ordinary</Note>{(["muted", "ok", "danger", "warn", "lead"] as const).map(tone => <Note key={tone} tone={tone} role="status">{tone}</Note>)}
    <PillNote>Plain</PillNote><PillNote tone="ok" icon="check" role="status">Saved</PillNote><PillNote tone="warn" icon="alert">Queued</PillNote><PillNote tone="muted">Muted</PillNote>
    <Toggle checked label="Consent on" onChange={noop} /><Toggle checked={false} label="Consent off" onChange={noop} /><Toggle checked disabled label="Unavailable" onChange={noop} />
    <Checkbox checked onChange={noop}>Agreed</Checkbox><Checkbox checked={false} onChange={noop}>Unselected</Checkbox>
    <SegmentedControl options={[{ id: "en", label: "English" }, { id: "es", label: "Español" }]} activeId="es" onSelect={noop} a11yLabel="Language" />
    <NavTabs items={nav} activeId="history" onSelect={noop} /><BottomNav items={nav} activeId="today" onSelect={noop} more={<span>More</span>} />
    <MoreMenu label="More" items={[{ id: "plan", label: "Plan", icon: "heart" }, { id: "remove", label: "Delete", danger: true }, { id: "plain", label: "Plain" }]} activeIds={["plan"]} onSelect={noop} up />
    <MoreMenu label="Other actions" items={[]} activeIds={[]} onSelect={noop} />
    <ToastHost items={[]} /><ToastHost items={[{ id: 1, message: "Saved", tone: "ok" }, { id: 2, message: "Offline", tone: "warn" }, { id: 3, message: "Updated", tone: "info" }]} />
    <Skeleton /><Skeleton lines={1} title /><Skeleton lines={0} />
    <ProgressDots total={4} current={2} label="Step 3 of 4" />
    {[-1, 0, 0.245, 1, 2].map(progress => <ProgressTrack key={progress} progress={progress} label="Completion" />)}
    <Avatar name=" Alice   Baker Carter " /><Avatar name="alice" /><Avatar name=" " />
  </main>);
  expect(publicSurface(root.toJSON())).toMatchSnapshot("closed controls");
  await press(root, "More");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("open overflow navigation");
});

it("preserves each check-in expression, selected cue and qualitative energy bar", async () => {
  for (const value of [null, ...MOOD_OPTIONS.map(option => option.value)]) {
    const root = await render(<MoodScale options={MOOD_OPTIONS} value={value} onChange={noop} />);
    expect(publicSurface(root.toJSON())).toMatchSnapshot(`mood ${value}`);
  }
  const single = await render(<MoodScale options={[MOOD_OPTIONS[2]!]} value={0} onChange={noop} groupLabel="Single choice" />);
  expect(publicSurface(single.toJSON())).toMatchSnapshot("single neutral expression");
  for (const count of [6, 11]) {
    const options = Array.from({ length: count }, (_, n) => ({ value: n, labelKey: `entry.expression.${n}` }));
    const root = await render(<MoodScale options={options} value={null} onChange={noop} groupLabel="Qualitative choices" />);
    expect(publicSurface(root.toJSON())).toMatchSnapshot(`expression thresholds for ${count} choices`);
  }
  for (const value of [null, 1, 3, 5]) {
    const root = await render(<DotScale options={SLEEP_OPTIONS} value={value} onChange={noop} />);
    expect(publicSurface(root.toJSON())).toMatchSnapshot(`sleep ${value}`);
  }
  for (const value of [null, -1, 0, 1]) {
    const root = await render(<BarScale options={ENERGY_OPTIONS} value={value} onChange={noop} groupLabel="Energy" />);
    expect(publicSurface(root.toJSON())).toMatchSnapshot(`energy ${value}`);
  }
});

it("preserves the public responsive application header, skip link and content landmark", async () => {
  const help = vi.fn(); const root = await render(<AppFrame title="Fathom" onCrisis={help}><p>Writing view</p></AppFrame>);
  expect(publicSurface(root.toJSON())).toMatchSnapshot(); await press(root, "Get help"); expect(help).toHaveBeenCalledOnce();
});

it("submits selected navigation ids and clears an already enabled switch", async () => {
  const select = vi.fn(), change = vi.fn();
  const root = await render(<><NavTabs items={nav} activeId="today" onSelect={select} /><BottomNav items={nav} activeId="history" onSelect={select} more={null} /><SegmentedControl options={[{ id: "en", label: "English" }, { id: "es", label: "Spanish" }]} activeId="en" onSelect={select} a11yLabel="Language" /><Toggle checked label="Enabled" onChange={change} /></>);
  const history = root.root.findAllByType("button").filter(button => button.children.some(child => child === "History"));
  for (const button of history) await act(async () => { button.props.onClick(); });
  await press(root, "Spanish");
  expect(select.mock.calls).toEqual([["history"], ["history"], ["es"]]);
  const toggle = root.root.findByProps({ role: "switch" }); await act(async () => { toggle.props.onClick(); }); expect(change).toHaveBeenCalledExactlyOnceWith(false);
});

it("forwards editable and toggle input values and closes a dialog only for its backdrop", async () => {
  const text = vi.fn(), checked = vi.fn(), close = vi.fn();
  const root = await render(<><TextArea label="Writing" value="" onChange={text} /><Checkbox checked={false} onChange={checked}>Agree</Checkbox><Toggle label="Consent" checked={false} onChange={checked} /><Dialog title="Help" onClose={close}><button>Inside</button></Dialog></>);
  await act(async () => { root.root.findByType("textarea").props.onChange({ target: { value: "New writing" } }); root.root.findByType("input").props.onChange({ target: { checked: true } }); });
  expect(text).toHaveBeenCalledWith("New writing"); expect(checked).toHaveBeenCalledWith(true);
  await press(root, ""); expect(checked).toHaveBeenCalledTimes(2);
  const backdrop = root.root.findAllByType("div").find(node => node.props.className === "dialog-backdrop")!;
  const panel = {}, background = {};
  await act(async () => { backdrop.props.onMouseDown({ target: panel, currentTarget: background }); });
  expect(close).not.toHaveBeenCalled();
  await act(async () => { backdrop.props.onMouseDown({ target: background, currentTarget: background }); });
  expect(close).toHaveBeenCalledOnce();
});
