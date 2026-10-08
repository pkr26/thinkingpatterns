import { afterEach, beforeEach, expect, it, vi } from "vitest";
import React from "react";
import ReactTestRenderer from "react-test-renderer";
import { Platform } from "react-native";
import { AudioModule, recorderControls, fakeRecorderStatus, __resetAudioMock } from "./helpers/expoAudioMock";
import * as files from "./helpers/expoFsMock";
import { discardTakeFile, useVoiceRecorder } from "../src/audio/recorder";
import { render, act, flush } from "./helpers/rtr";
let latest: ReturnType<typeof useVoiceRecorder>;
const copy = { permissionDenied: "Microphone access was denied", failed: "This recording could not finish" };
function Consumer({ strings = copy }: { strings?: typeof copy }) { latest = useVoiceRecorder(strings); return null; }
const uri = `${files.cacheDirectory}public-recorder-contract.m4a`;
beforeEach(() => { vi.restoreAllMocks(); __resetAudioMock(); files.__resetFiles(); vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(new Date("2026-10-06T04:00:00Z")); });
afterEach(() => { vi.restoreAllMocks(); vi.useRealTimers(); Object.assign(Platform, { OS: "ios" }); });
async function start() { files.__seedFile(uri, "cmVjb3JkZWQgc3BlZWNo"); fakeRecorderStatus.url = uri; await act(async () => { await latest.start(); }); }
it.each([[-90, 0], [-60, 0], [-30, 0.5], [0, 1], [12, 1]])("reports a bounded visible level for native metering %s", async (metering, expected) => {
  fakeRecorderStatus.metering = metering; const root = await render(<Consumer />); expect(latest.level).toBe(0);
  await start(); expect(latest.level).toBe(expected); await act(async () => { await latest.stop(); }); expect(latest.level).toBe(0);
  await act(async () => root.unmount()); await flush();
});
it.each([undefined, "unavailable"])("reports silence when native metering is %s", async metering => {
  Object.assign(fakeRecorderStatus, { metering }); const root = await render(<Consumer />); await start(); expect(latest.level).toBe(0); await act(async () => root.unmount()); await flush();
});
it.each([[undefined, 3], [null, 3], ["unavailable", 3], [NaN, 3], [Infinity, 3], [-5, 3], [0, 3], [1, 1], [499, 1], [1500, 2], [2500, 3], [312000, 300]])("publishes honest bounded duration for native milliseconds %s", async (reported, expected) => {
  Object.assign(fakeRecorderStatus, { durationMillis: reported }); const root = await render(<Consumer />); await start(); vi.setSystemTime(new Date("2026-10-06T04:00:02.500Z"));
  await act(async () => { await latest.stop(); }); expect(latest.take).toEqual({ uri, base64: "cmVjb3JkZWQgc3BlZWNo", mime: "audio/m4a", durationSeconds: expected });
  await act(async () => root.unmount()); await flush();
});
it.each(["ios", "android"])("supplies the linked %s provider with a mono AAC speech recording contract", async platform => {
  Object.assign(Platform, { OS: platform }); const root = await render(<Consumer />); const native = AudioModule.AudioRecorder.mock.calls[0]![0] as Record<string, unknown>;
  expect(native).toMatchObject({ extension: ".m4a", sampleRate: 16000, numberOfChannels: 1, bitRate: 24000, isMeteringEnabled: true });
  expect(native).toMatchObject(platform === "ios" ? { audioQuality: 96 } : { outputFormat: "mpeg4", audioEncoder: "aac" });
  await start(); expect(AudioModule.setAudioModeAsync).toHaveBeenCalledWith({ allowsRecording: true, playsInSilentMode: true, shouldPlayInBackground: false });
  expect(recorderControls.prepareToRecordAsync).toHaveBeenCalledWith(expect.objectContaining({ extension: ".m4a", sampleRate: 16000, numberOfChannels: 1, bitRate: 24000, isMeteringEnabled: true }));
  await act(async () => root.unmount()); await flush();
});
it("uses the native status URI when the recorder's URI accessor has not published it", async () => {
  const root = await render(<Consumer />), native = AudioModule.AudioRecorder.mock.results[0]!.value;
  Object.defineProperty(native, "uri", { get: () => null }); await start(); await act(async () => { await latest.stop(); }); expect(latest.take?.uri).toBe(uri);
  await act(async () => root.unmount()); await flush(); expect(files.__hasFile(uri)).toBe(false);
});
it("reports a stopped native recorder with no URI as failed and allows the next recording", async () => {
  const root = await render(<Consumer />); await act(async () => { await latest.start(); await latest.stop(); });
  expect(latest.state).toBe("stopped"); expect(latest.error).toBe(copy.failed); expect(latest.take).toBeNull();
  await start(); await act(async () => { await latest.stop(); }); expect(latest.take?.uri).toBe(uri); expect(latest.error).toBeNull();
  await act(async () => root.unmount()); await flush();
});
it.each([undefined, null])("treats missing native permission %s as a denial before preparing", async permission => {
  AudioModule.requestRecordingPermissionsAsync.mockResolvedValueOnce(permission as never); const root = await render(<Consumer />);
  await act(async () => { await latest.start(); }); expect(latest.error).toBe(copy.permissionDenied); expect(latest.state).toBe("idle"); expect(recorderControls.record).not.toHaveBeenCalled();
  await act(async () => root.unmount()); await flush();
});
it("deletes an unreadable take, reports failure, and retries deletion after a transient native filesystem refusal", async () => {
  const root = await render(<Consumer />); await start(); files.readAsStringAsync.mockRejectedValueOnce(new Error("Native recording cannot be read")); files.deleteAsync.mockRejectedValueOnce(new Error("Native cache was temporarily busy"));
  await act(async () => { await latest.stop(); }); expect(latest.state).toBe("stopped"); expect(latest.error).toBe(copy.failed); expect(latest.take).toBeNull(); expect(files.__hasFile(uri)).toBe(true);
  await act(async () => { latest.reset(); }); await flush(); expect(files.__hasFile(uri)).toBe(false); expect(latest.error).toBeNull(); expect(latest.elapsedSeconds).toBe(0); expect(latest.state).toBe("idle");
  await act(async () => root.unmount()); await flush();
});
it("uses current localized copy after a native prepare rejection resumes", async () => {
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  recorderControls.prepareToRecordAsync.mockImplementationOnce(async () => { await gate; throw new Error("Native prepare refused"); });
  const root = await render(<Consumer />); let pending!: Promise<void>; await act(async () => { pending = latest.start(); }); await flush();
  const updated = { permissionDenied: "Acceso denegado", failed: "No se pudo terminar la grabación" }; await act(async () => root.update(<Consumer strings={updated} />));
  await act(async () => { release(); await pending; }); expect(latest.error).toBe(updated.failed); expect(latest.state).toBe("idle");
  await act(async () => root.unmount()); await flush();
});
it("auto-stops at exactly five minutes and releases every native timer on reset", async () => {
  vi.useFakeTimers(); const root = await render(<Consumer />); await start();
  await act(async () => { await vi.advanceTimersByTimeAsync(500); }); expect(latest.elapsedSeconds).toBe(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(500); }); expect(latest.elapsedSeconds).toBe(1);
  await act(async () => { await vi.advanceTimersByTimeAsync(298500); }); expect(latest.state).toBe("recording");
  await act(async () => { await vi.advanceTimersByTimeAsync(500); }); expect(latest.state).toBe("stopped"); expect(latest.take?.durationSeconds).toBe(300); expect(vi.getTimerCount()).toBe(0);
  await act(async () => { latest.reset(); }); expect(vi.getTimerCount()).toBe(0); await act(async () => root.unmount()); await act(async () => { await Promise.resolve(); });
});
it("a second native recording begins with zero elapsed time after a completed take", async () => {
  vi.useFakeTimers(); const root = await render(<Consumer />); await start();
  await act(async () => { await vi.advanceTimersByTimeAsync(1500); });
  await act(async () => { await latest.stop(); }); expect(latest.elapsedSeconds).toBe(1);
  await act(async () => { await latest.start(); }); expect(latest.state).toBe("recording"); expect(latest.elapsedSeconds).toBe(0);
  await act(async () => root.unmount()); await act(async () => { await Promise.resolve(); });
});
it("discards absent or already removed takes without leaking a native filesystem failure", async () => {
  await expect(discardTakeFile(null)).resolves.toBeUndefined(); const take = { uri, base64: "", mime: "audio/m4a", durationSeconds: 1 }; files.__seedFile(uri);
  await discardTakeFile(take); expect(files.__hasFile(uri)).toBe(false); await expect(discardTakeFile(take)).resolves.toBeUndefined();
});

it("an idle stop does not manufacture a stopped take or an error", async () => {
  const root = await render(<Consumer />); await act(async () => { await latest.stop(); });
  expect(latest.state).toBe("idle"); expect(latest.error).toBeNull(); expect(latest.take).toBeNull(); await act(async () => root.unmount()); await flush();
});
it("an already recording start preserves the native file and original elapsed duration", async () => {
  const root = await render(<Consumer />); await start(); vi.setSystemTime(new Date("2026-10-06T04:00:03Z"));
  await act(async () => { await latest.start(); }); expect(files.__hasFile(uri)).toBe(true); expect(latest.state).toBe("recording");
  await act(async () => { await latest.stop(); }); expect(latest.take?.durationSeconds).toBe(3); expect(latest.error).toBeNull();
  await act(async () => root.unmount()); await flush();
});
it.each(["starting", "stopping"])("a duplicate start settles before the held native %s operation completes", async phase => {
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  if (phase === "starting") AudioModule.requestRecordingPermissionsAsync.mockImplementationOnce(async () => { reached(); await gate; return { granted: true }; });
  const root = await render(<Consumer />); files.__seedFile(uri); fakeRecorderStatus.url = uri; let first!: Promise<void>;
  if (phase === "starting") await act(async () => { first = latest.start(); });
  else { await start(); recorderControls.stop.mockImplementationOnce(async () => { reached(); await gate; }); await act(async () => { first = latest.stop(); }); }
  await Promise.race([entered, first]); let duplicate!: Promise<void>; await act(async () => { duplicate = latest.start(); });
  try { expect(await Promise.race([duplicate.then(() => "settled"), new Promise(resolve => setTimeout(() => resolve("blocked"), 100))])).toBe("settled"); }
  finally { await act(async () => { release(); await Promise.all([first, duplicate]); }); await act(async () => root.unmount()); await flush(); }
});
it("a stop queued during native preparation yields the single finished take", async () => {
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  recorderControls.prepareToRecordAsync.mockImplementationOnce(async () => { reached(); await gate; fakeRecorderStatus.url = uri; files.__seedFile(uri, "bGF0ZSBuYXRpdmUgc3BlZWNo"); });
  const root = await render(<Consumer />); let starting!: Promise<void>, stopping!: Promise<void>;
  await act(async () => { starting = latest.start(); }); await Promise.race([entered, starting]); await act(async () => { stopping = latest.stop(); });
  await act(async () => { release(); await Promise.all([starting, stopping]); }); expect(latest.state).toBe("stopped"); expect(latest.take?.base64).toBe("bGF0ZSBuYXRpdmUgc3BlZWNo"); expect(latest.error).toBeNull();
  await act(async () => root.unmount()); await flush();
});
it.each(["prepare", "read"])("a rejected obsolete native %s cannot replace the reset state with an error", async phase => {
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  const root = await render(<Consumer />); let pending!: Promise<void>;
  if (phase === "prepare") {
    recorderControls.prepareToRecordAsync.mockImplementationOnce(async () => { reached(); await gate; throw new Error("Obsolete Native prepare failed"); });
    await act(async () => { pending = latest.start(); });
  } else {
    await start(); files.readAsStringAsync.mockImplementationOnce(async () => { reached(); await gate; throw new Error("Obsolete Native file became unreadable"); });
    await act(async () => { pending = latest.stop(); });
  }
  await Promise.race([entered, pending]); await act(async () => { latest.reset(); }); await act(async () => { release(); await pending; }); await flush();
  expect(latest.state).toBe("idle"); expect(latest.error).toBeNull(); expect(latest.take).toBeNull(); expect(files.__hasFile(uri)).toBe(false);
  await act(async () => root.unmount()); await flush();
});

it("a stop admitted during native preparation releases the timer created by the completing start", async () => {
  vi.useFakeTimers();
  let release!: () => void; const gate = new Promise<void>(resolve => { release = resolve; });
  recorderControls.prepareToRecordAsync.mockImplementationOnce(async () => { await gate; fakeRecorderStatus.url = uri; files.__seedFile(uri); });
  const root = await render(<Consumer />); let starting!: Promise<void>, stopping!: Promise<void>;
  await act(async () => { starting = latest.start(); });
  await act(async () => { stopping = latest.stop(); });
  await act(async () => { release(); await Promise.all([starting, stopping]); });
  expect(latest.state).toBe("stopped"); expect(latest.take?.uri).toBe(uri); expect(vi.getTimerCount()).toBe(0);
  await act(async () => root.unmount()); await act(async () => { await Promise.resolve(); });
});

it.each(["reset", "unmount"])("%s releases the native timer before a held disposal can complete", async cancel => {
  vi.useFakeTimers(); const root = await render(<Consumer />); await start();
  await act(async () => { await vi.advanceTimersByTimeAsync(1500); }); expect(latest.elapsedSeconds).toBe(1);
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  recorderControls.stop.mockImplementationOnce(async () => { reached(); await gate; });
  await act(async () => { if (cancel === "reset") latest.reset(); else root.unmount(); });
  await act(async () => { for (let turn = 0; turn < 20; turn++) await Promise.resolve(); });
  try {
    expect(files.__hasFile(uri)).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
    if (cancel === "reset") { expect(latest.elapsedSeconds).toBe(0); expect(latest.state).toBe("idle"); }
  } finally {
    await act(async () => { release(); await Promise.resolve(); });
    if (cancel === "reset") await act(async () => root.unmount());
    await act(async () => { await Promise.resolve(); });
  }
});

it("StrictMode replay admits only the current effect's native microphone recording", async () => {
  function AutomaticConsumer() {
    latest = useVoiceRecorder(copy);
    React.useEffect(() => { void latest.start(); }, []);
    return null;
  }
  recorderControls.prepareToRecordAsync.mockImplementation(async () => { fakeRecorderStatus.url = uri; files.__seedFile(uri); });
  let root!: ReactTestRenderer.ReactTestRenderer;
  await act(async () => { root = ReactTestRenderer.create(<React.StrictMode><AutomaticConsumer /></React.StrictMode>, { unstable_strictMode: true } as never); });
  await act(async () => { for (let turn = 0; turn < 20; turn++) await Promise.resolve(); });
  expect(latest.state).toBe("recording"); expect(files.__hasFile(uri)).toBe(true);
  expect(AudioModule.requestRecordingPermissionsAsync).toHaveBeenCalledTimes(1); expect(recorderControls.record).toHaveBeenCalledTimes(1);
  await act(async () => root.unmount()); await flush(); expect(files.__hasFile(uri)).toBe(false);
});

it("a new pending native recording clears the preceding published take immediately", async () => {
  const root = await render(<Consumer />); await start(); await act(async () => { await latest.stop(); }); expect(latest.take?.uri).toBe(uri);
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  AudioModule.requestRecordingPermissionsAsync.mockImplementationOnce(async () => { reached(); await gate; return { granted: true }; });
  let pending!: Promise<void>; await act(async () => { pending = latest.start(); }); await Promise.race([entered, pending]);
  try { expect(latest.take).toBeNull(); }
  finally { await act(async () => { release(); await pending; }); await act(async () => root.unmount()); await flush(); }
});

it.each([true, false])("a reset during the native permission response %s cannot change audio mode or display the obsolete denial", async granted => {
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  AudioModule.requestRecordingPermissionsAsync.mockImplementationOnce(async () => { reached(); await gate; return { granted }; });
  const root = await render(<Consumer />); let pending!: Promise<void>; await act(async () => { pending = latest.start(); }); await Promise.race([entered, pending]);
  await act(async () => { latest.reset(); }); await act(async () => { release(); await pending; }); await flush();
  expect(latest.error).toBeNull(); expect(latest.state).toBe("idle"); expect(AudioModule.setAudioModeAsync).not.toHaveBeenCalled();
  await act(async () => root.unmount()); await flush();
});

it("a reset while deleting the preceding take prevents a later native microphone permission request", async () => {
  const root = await render(<Consumer />); await start(); await act(async () => { await latest.stop(); });
  let release!: () => void, reached!: () => void; const gate = new Promise<void>(resolve => { release = resolve; }), entered = new Promise<void>(resolve => { reached = resolve; });
  const deleteNative = files.deleteAsync.getMockImplementation()!;
  files.deleteAsync.mockImplementationOnce(async (...args) => { reached(); await gate; await deleteNative(...args); });
  let pending!: Promise<void>; await act(async () => { pending = latest.start(); }); await Promise.race([entered, pending]);
  await act(async () => { latest.reset(); }); await act(async () => { release(); await pending; }); await flush();
  expect(AudioModule.requestRecordingPermissionsAsync).toHaveBeenCalledTimes(1); expect(latest.error).toBeNull(); expect(latest.state).toBe("idle"); expect(files.__hasFile(uri)).toBe(false);
  await act(async () => root.unmount()); await flush();
});
