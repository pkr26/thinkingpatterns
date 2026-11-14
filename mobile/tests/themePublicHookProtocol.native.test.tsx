/** Exported ThemeProvider/hook protocol under the frozen Node/React renderer.
 * The fixture is an exported-hook consumer, not a shipped Settings regression. */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Text, View, useColorScheme } from "react-native";
import { ThemeProvider, themeStorageKey, useSetThemeMode, useTheme } from "../src/theme";
import storage from "./helpers/storageMock";

let root: ReturnType<typeof ReactTestRenderer.create> | undefined;
const releaseReceipts: Array<() => void> = [];
const ownedReceipts: Promise<unknown>[] = [];
function gate() {
  let release!: () => void;
  const waiting = new Promise<void>(resolve => { release = resolve; });
  releaseReceipts.push(release);
  return { waiting, release };
}
function Palette() {
  const theme = useTheme();
  return <View accessibilityLabel="Current theme palette" style={{ backgroundColor: theme.colors.bg }} />;
}
function HookConsumer() {
  const setter = useSetThemeMode();
  const [deliveries, setDeliveries] = React.useState(0);
  // This is the public React effect contract of an exported hook value.
  // It counts effect deliveries, never renders or private context/fiber state.
  React.useEffect(() => { setDeliveries(value => value + 1); }, [setter]);
  return <><Text accessibilityLabel="Theme synchronization effects">{deliveries}</Text><Palette /></>;
}
function deliveries() {
  const text = root!.root.findAllByType(Text).find(node => node.props.accessibilityLabel === "Theme synchronization effects")!;
  return React.Children.toArray(text.props.children).join("");
}
function palette() {
  return root!.root.findAllByType(View).find(node => node.props.accessibilityLabel === "Current theme palette")!.props.style.backgroundColor;
}
beforeEach(() => {
  vi.restoreAllMocks(); storage.__reset();
  vi.mocked(useColorScheme).mockReturnValue("light");
});
afterEach(async () => {
  for (const release of releaseReceipts.splice(0)) release();
  await act(async () => { await Promise.allSettled(ownedReceipts.splice(0)); });
  if (root) { await act(async () => root!.unmount()); root = undefined; }
  vi.restoreAllMocks(); vi.mocked(useColorScheme).mockReturnValue("dark");
});

it.each(["system", "", null])("a completed native preference %j does not republish an unchanged exported theme setter", async stored => {
  const slot = themeStorageKey();
  if (stored !== null) await storage.setItem(slot, stored);
  const read = storage.getItem.bind(storage), receipt = gate();
  let admitted = false;
  vi.spyOn(storage, "getItem").mockImplementation(key => {
    const original = read(key);
    if (key !== slot) return original;
    admitted = true;
    const delivered = original.then(async value => { await receipt.waiting; return value; });
    ownedReceipts.push(delivered);
    return delivered;
  });
  await act(async () => { root = ReactTestRenderer.create(<ThemeProvider><HookConsumer /></ThemeProvider>); });
  expect(admitted).toBe(true);
  expect(deliveries()).toBe("1");
  expect(palette()).toBe("#f8f5ef");
  try {
    await act(async () => { receipt.release(); await Promise.all(ownedReceipts); });
    expect(deliveries(), "Completing a non-overriding preference does not deliver a second synchronization effect through the exported setter hook").toBe("1");
    expect(palette()).toBe("#f8f5ef");
    expect(await read(slot)).toBe(stored);
  } finally { receipt.release(); await Promise.allSettled(ownedReceipts); }
});

it("native StrictMode cleanup retires the first actual preference receipt before its reconnect receipt commits", async () => {
  const slot = themeStorageKey();
  await storage.setItem(slot, "dark");
  const read = storage.getItem.bind(storage), receipts: Array<{ gate: ReturnType<typeof gate>; original: Promise<string | null>; delivered: Promise<string | null> }> = [];
  vi.spyOn(storage, "getItem").mockImplementation(key => {
    const original = read(key);
    if (key !== slot) return original;
    const held = gate();
    // Publish through the real public storage provider after its first read
    // has captured dark and before StrictMode reconnect admits the next read.
    // Both read results are the actual original provider values, unchanged.
    if (receipts.length === 0) ownedReceipts.push(storage.setItem(slot, "light"));
    const delivered = original.then(async value => { await held.waiting; return value; });
    receipts.push({ gate: held, original, delivered }); ownedReceipts.push(delivered);
    return delivered;
  });
  await act(async () => { root = ReactTestRenderer.create(<React.StrictMode><ThemeProvider><Palette /></ThemeProvider></React.StrictMode>); });
  expect(receipts, "The installed renderer supplies its actual StrictMode setup/cleanup/reconnect sequence").toHaveLength(2);
  expect(await receipts[0]!.original).toBe("dark");
  expect(await receipts[1]!.original).toBe("light");
  try {
    await act(async () => { receipts[1]!.gate.release(); await receipts[1]!.delivered; });
    expect(palette()).toBe("#f8f5ef");
    await act(async () => { receipts[0]!.gate.release(); await receipts[0]!.delivered; });
    expect(palette(), "A receipt retired by actual StrictMode cleanup cannot replace the current reconnect palette").toBe("#f8f5ef");
  } finally {
    for (const row of receipts) row.gate.release();
    await Promise.allSettled(ownedReceipts);
  }
});
