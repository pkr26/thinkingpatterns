import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { expect, it } from "vitest";
import { Text } from "react-native";
import { MoodCalendar } from "../src/components/MoodCalendar";
import { ThemeProvider } from "../src/theme";
import { installedNativeLogBox } from "./helpers/nativeLogBox";

it("the installed Native development diagnostic tray remains free of invalid calendar children", async () => {
  const device = installedNativeLogBox();
  let calendar: ReactTestRenderer.ReactTestRenderer | undefined;
  let tray: ReactTestRenderer.ReactTestRenderer | undefined;
  device.start();
  try {
    await act(async () => { tray = ReactTestRenderer.create(<device.Tray />); calendar = ReactTestRenderer.create(<ThemeProvider><MoodCalendar dayMoods={{}} journaledDays={new Set()} selectedDay={null} onSelectDay={() => {}} /></ThemeProvider>); });
    await act(async () => { await new Promise<void>(resolve => setImmediate(resolve)); await new Promise<void>(resolve => setTimeout(resolve, 40)); });
    const flatten = (value: any): string => Array.isArray(value) ? value.map(flatten).join("") : typeof value === "string" ? value : "";
    const nativeMessage = tray!.root.findAllByType(Text).map(node => flatten(node.props.children)).join(" ");
    expect(nativeMessage).not.toContain("Encountered two children with the same key");
  } finally {
    await act(async () => { calendar?.unmount(); tray?.unmount(); });
    device.dispose();
  }
});

it("the installed Native tray renders a public device warning receipt", async () => {
  const device = installedNativeLogBox(); let tray: ReactTestRenderer.ReactTestRenderer | undefined;
  device.start();
  try {
    await act(async () => { tray = ReactTestRenderer.create(<device.Tray />); });
    await act(async () => console.warn("Native calendar diagnostic device is connected"));
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 60)); });
    const flatten = (value: any): string => Array.isArray(value) ? value.map(flatten).join("") : typeof value === "string" ? value : "";
    expect(tray!.root.findAllByType(Text).map(node => flatten(node.props.children)).join(" ")).toContain("Native calendar diagnostic device is connected");
  } finally { await act(async () => tray?.unmount()); device.dispose(); }
});
