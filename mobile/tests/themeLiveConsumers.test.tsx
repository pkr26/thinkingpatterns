/** Missing finite public consumers only: mounted language subscription and
 * independent dark navigation/calendar colors. Existing scale witnesses
 * remain the first broader replay; no palette or locale internals are read. */
import TestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { Text, TouchableOpacity, View, useColorScheme } from "react-native";
import { ThemeProvider } from "../src/theme";
import { BottomNav } from "../src/components/BottomNav";
import { MoodCalendar } from "../src/components/MoodCalendar";
import { PrivacyScreen } from "../src/screens/PrivacyScreen";
import { readLanguageChoice, writeLanguageChoice } from "../src/languagePref";
import { setLocale } from "../src/strings";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";

let root: TestRenderer.ReactTestRenderer | undefined;
const flattenText = (value: unknown): string => Array.isArray(value) ? value.map(flattenText).join("") : typeof value === "string" || typeof value === "number" ? String(value) : "";
const copy = () => root!.root.findAllByType(Text).map(node => flattenText(node.props.children)).join(" ");
const flatStyle = (value: unknown): Record<string, unknown> => Array.isArray(value)
  ? Object.assign({}, ...value.map(flatStyle)) : value && typeof value === "object" ? value as Record<string, unknown> : {};

beforeEach(() => {
  vi.useRealTimers(); vi.restoreAllMocks(); storage.__reset(); keychain.__reset(); setLocale("en");
  vi.mocked(useColorScheme).mockReturnValue("dark");
});
afterEach(async () => {
  try { if (root) await act(async () => { root!.unmount(); }); }
  finally { root = undefined; setLocale("en"); vi.restoreAllMocks(); }
});

it("an acknowledged encrypted language choice updates already mounted public navigation and privacy copy", async () => {
  await act(async () => { root = TestRenderer.create(<ThemeProvider><BottomNav current="Entry" navigation={{ navigate: () => {} }}/><PrivacyScreen navigation={{ navigate: () => {} }}/></ThemeProvider>); });
  expect(copy()).toContain("Today");
  expect(copy()).toContain("Privacy, in plain language");
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Today")?.props.accessibilityState).toEqual({ selected: true });
  await act(async () => {
    try { await writeLanguageChoice("es"); }
    catch (error) { throw new Error("SetupError: actual encrypted Spanish preference producer failed", { cause: error }); }
  });
  expect(await readLanguageChoice()).toBe("es");
  expect(copy()).toContain("Hoy");
  expect(copy()).toContain("Privacidad, en lenguaje claro");
  expect(root!.root.findAllByType(TouchableOpacity).find(node => node.props.accessibilityLabel === "Hoy")?.props.accessibilityState).toEqual({ selected: true });
  expect(root!.root.findAllByType(View).some(node => node.props.accessibilityRole === "tablist" && node.props.accessibilityLabel === "Navegación principal")).toBe(true);
  await act(async () => {
    try { await writeLanguageChoice("en"); }
    catch (error) { throw new Error("SetupError: actual encrypted English preference producer failed", { cause: error }); }
  });
  expect(await readLanguageChoice()).toBe("en");
  expect(copy()).toContain("Today");
  expect(copy()).toContain("Privacy, in plain language");
  expect(copy()).not.toContain("Privacidad, en lenguaje claro");
});

it("the saved dark palette publishes an independent visible navigation border and negative journal mood dot", async () => {
  // A legitimate journaled date in the current native month avoids any
  // fixture clock override. Its independent mood is in the admitted range.
  const now = new Date();
  const day = `${now.getFullYear()}-${String(now.getMonth()+1).padStart(2,"0")}-${String(now.getDate()).padStart(2,"0")}`;
  await storage.setItem("@mindpattern/theme.mode", "dark");
  await act(async () => { root = TestRenderer.create(<ThemeProvider><BottomNav current="History" navigation={{ navigate: () => {} }}/><MoodCalendar dayMoods={{ [day]: -0.6 }} journaledDays={new Set([day])} selectedDay={null} onSelectDay={() => {}}/></ThemeProvider>); });
  expect(root!.root.findAllByType(View).filter(node => node.props.accessibilityRole === "tablist").map(node => flatStyle(node.props.style).borderTopColor)).toEqual(["#3a352c"]);
  expect(root!.root.findAllByType(View).filter(node => {
    const style = flatStyle(node.props.style); return style.width === 4 && style.height === 4;
  }).map(node => flatStyle(node.props.style).backgroundColor)).toEqual(["#d98a80"]);
  expect(root!.root.findAllByType(TouchableOpacity).some(node => typeof node.props.accessibilityLabel === "string" && node.props.accessibilityLabel.endsWith(", journaled") && node.props.accessibilityState === undefined)).toBe(true);
});
