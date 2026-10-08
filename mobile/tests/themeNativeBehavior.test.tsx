/** The Native consumer observes palette, readable body type and its real
 * persisted override. The startup reader uses actual storage bytes. */
import React from "react";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import ReactTestRenderer, { act } from "react-test-renderer";
import { Text, View, TouchableOpacity, useColorScheme } from "react-native";
import { GhostButton } from "../src/components/buttons";
import { MoodCalendar } from "../src/components/MoodCalendar";
import { BottomNav } from "../src/components/BottomNav";
import { ThemeProvider, useTheme, useSetThemeMode, type ThemeMode } from "../src/theme";
import storage from "./helpers/storageMock";
let root: ReturnType<typeof ReactTestRenderer.create> | undefined, choose: (mode: ThemeMode) => void;
function Consumer() { const theme = useTheme(); choose = useSetThemeMode(); return <Text accessibilityLabel="Native theme preview" style={{ color: theme.colors.body, backgroundColor: theme.colors.bg, ...theme.type.body }}>A readable journal paragraph</Text>; }
async function mount(children: React.ReactNode = <Consumer/>) { await act(async () => { root = ReactTestRenderer.create(<ThemeProvider>{children}</ThemeProvider>); }); await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); }
function style() { return root!.root.findByType(Text).props.style; }
beforeEach(() => { vi.restoreAllMocks(); storage.__reset(); vi.mocked(useColorScheme).mockReturnValue("light"); });
afterEach(async () => { if (root) { await act(async () => root!.unmount()); root = undefined; } vi.restoreAllMocks(); vi.mocked(useColorScheme).mockReturnValue("dark"); });
it.each(["dark", "light", "system", "invalid", "", null])("Native saved override %j selects its advertised palette", async stored => {
 if (stored !== null) await storage.setItem("@mindpattern/theme.mode", stored); await mount();
 expect(style()).toEqual({ color: stored === "dark" ? "#cfc7ba" : "#4d463d", backgroundColor: stored === "dark" ? "#211e1a" : "#f8f5ef", fontSize: 15, lineHeight: 21 });
});
it.each(["dark", "light", "system"] as const)("Native selecting %s persists the override and publishes the current palette", async mode => {
 await mount(); await act(async () => choose(mode));
 expect(await storage.getItem("@mindpattern/theme.mode")).toBe(mode); expect(style().backgroundColor).toBe(mode === "dark" ? "#211e1a" : "#f8f5ef");
});
it("a failed Native preference write still preserves the explicit palette for this session", async () => {
 await mount(); vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native preference writes unavailable")); await act(async () => choose("dark")); expect(style().backgroundColor).toBe("#211e1a");
});
it("a late Native startup read cannot undo a newer palette whose persistence failed", async () => {
 await storage.setItem("@mindpattern/theme.mode", "dark"); const read = storage.getItem.bind(storage); let release!: () => void;
 const held = new Promise<void>(resolve => { release = resolve; }); vi.spyOn(storage, "getItem").mockImplementation(async key => { const value = await read(key); if (key === "@mindpattern/theme.mode") await held; return value; });
 await mount(); vi.spyOn(storage, "setItem").mockRejectedValueOnce(new Error("Native preference writes unavailable")); await act(async () => choose("light")); release(); await act(async () => { await held; await new Promise(resolve => setTimeout(resolve, 0)); }); expect(style().backgroundColor).toBe("#f8f5ef");
});
it("actual Native quiet actions retain a usable hit area around their visible labels", async () => {
 await mount(<GhostButton label="Sign out instead" onPress={()=>{}}/>);
 expect(root!.root.findByType(TouchableOpacity).props.hitSlop).toEqual({top:12,bottom:12,left:12,right:12});
});
it("a stored Native light override remains light on an otherwise dark device",async()=>{
 vi.mocked(useColorScheme).mockReturnValue("dark");await storage.setItem("@mindpattern/theme.mode","light");await mount();expect(style().backgroundColor).toBe("#f8f5ef");expect(style().color).toBe("#4d463d");
});
it("the actual Native light navigation retains its visible border",async()=>{
 await mount(<BottomNav current="Entry" navigation={{navigate:()=>{}}}/>);const flat=(value:any):any=>Array.isArray(value)?Object.assign({},...value.map(flat)):value??{};expect(root!.root.findAllByType(View).some(node=>flat(node.props.style).borderTopColor==="#e7e0d4")).toBe(true);
});
it("the actual Native light calendar shows a heavier mood dot without changing the selected-day label", async () => {
 vi.useFakeTimers({toFake:["Date"]});vi.setSystemTime(new Date(2026,9,7,12));
 try { await mount(<MoodCalendar dayMoods={{"2026-10-06":-0.6}} journaledDays={new Set(["2026-10-06"])} selectedDay={null} onSelectDay={()=>{}}/>);
 const flat=(value:any):any=>Array.isArray(value)?Object.assign({},...value.map(flat)):value??{};
 expect(root!.root.findAllByType(View).some(node=>flat(node.props.style).backgroundColor==="#a0483f"&&flat(node.props.style).width===4&&flat(node.props.style).height===4)).toBe(true);
 } finally {vi.useRealTimers();}
});
