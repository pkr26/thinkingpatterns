/** MOB-01: control actual async boundaries, assert filesystem custody and native release. */
import { beforeEach, describe, expect, it } from "vitest";
import React from "react";
import { AudioModule, recorderControls, fakeRecorderStatus, __resetAudioMock } from "./helpers/expoAudioMock";
import * as fs from "./helpers/expoFsMock";
import { useVoiceRecorder } from "../src/audio/recorder";
import { render, act, flush } from "./helpers/rtr";

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}
let latest: ReturnType<typeof useVoiceRecorder>;
function Harness() {
  latest = useVoiceRecorder({ permissionDenied: "denied", failed: "failed" });
  return null;
}
beforeEach(() => { __resetAudioMock(); fs.__resetFiles(); });

for (const boundary of ["permission", "audio mode", "prepare"] as const) {
  for (const cancel of ["reset", "unmount"] as const) {
    it(`${cancel} while ${boundary} is pending prevents a late recording and scrubs a late URI`, async () => {
      const wait = deferred<void>();
      const uri = `${fs.cacheDirectory}late-${boundary}.m4a`;
      if (boundary === "permission") AudioModule.requestRecordingPermissionsAsync.mockImplementationOnce(async () => { await wait.promise; return { granted: true }; });
      if (boundary === "audio mode") AudioModule.setAudioModeAsync.mockImplementationOnce(async () => { await wait.promise; });
      if (boundary === "prepare") recorderControls.prepareToRecordAsync.mockImplementationOnce(async () => {
        await wait.promise;
        fakeRecorderStatus.url = uri;
        fs.__seedFile(uri);
      });
      const root = await render(<Harness />);
      let starting!: Promise<void>;
      await act(async () => { starting = latest.start(); });
      await flush();
      await act(async () => { if (cancel === "unmount") root.unmount(); else latest.reset(); });
      expect(recorderControls.release).not.toHaveBeenCalled();
      await act(async () => { wait.resolve(); await starting; });
      await flush();
      expect(recorderControls.record).not.toHaveBeenCalled();
      expect(fs.__hasFile(uri)).toBe(false);
      if (boundary !== "prepare") expect(recorderControls.prepareToRecordAsync).not.toHaveBeenCalled();
      if (cancel === "unmount") expect(recorderControls.release).toHaveBeenCalledTimes(1);
      else {
        expect(latest.state).toBe("idle");
        expect(latest.take).toBeNull();
        expect(recorderControls.release).not.toHaveBeenCalled();
        await act(async () => { root.unmount(); });
      }
    });
  }
}

describe("native and file disposal custody", () => {
  it("StrictMode effect replay keeps one usable native recorder and releases it only on real unmount", async () => {
    const root = await render(<React.StrictMode><Harness /></React.StrictMode>);
    await flush();
    expect(AudioModule.AudioRecorder).toHaveBeenCalledTimes(1);
    expect(recorderControls.release).not.toHaveBeenCalled();
    const uri = `${fs.cacheDirectory}strict-mode.m4a`;
    fakeRecorderStatus.url = uri; fs.__seedFile(uri);
    await act(async () => { await latest.start(); await latest.stop(); });
    expect(latest.take?.uri).toBe(uri);
    expect(fs.__hasFile(uri)).toBe(true);
    await act(async () => { root.unmount(); });
    await flush();
    expect(fs.__hasFile(uri)).toBe(false);
    expect(recorderControls.release).toHaveBeenCalledTimes(1);
  });

  it("unmount during active recording waits for native stop before deleting and releasing", async () => {
    const wait = deferred<void>();
    const uri = `${fs.cacheDirectory}active.m4a`;
    const root = await render(<Harness />);
    fakeRecorderStatus.url = uri; fs.__seedFile(uri);
    await act(async () => { await latest.start(); });
    recorderControls.stop.mockImplementationOnce(async () => { await wait.promise; });
    await act(async () => { root.unmount(); });
    await flush();
    expect(fs.__hasFile(uri)).toBe(true);
    expect(recorderControls.release).not.toHaveBeenCalled();
    await act(async () => { wait.resolve(); });
    await flush();
    expect(fs.__hasFile(uri)).toBe(false);
    expect(recorderControls.release).toHaveBeenCalledTimes(1);
    expect(fs.deleteAsync.mock.invocationCallOrder[0]).toBeLessThan(recorderControls.release.mock.invocationCallOrder[0]);
    expect(fs.readAsStringAsync).not.toHaveBeenCalled();
  });

  for (const boundary of ["stop", "read"] as const) {
    it(`unmount while ${boundary} completes cannot publish a take and deletes the recording`, async () => {
      const wait = deferred<void>();
      const uri = `${fs.cacheDirectory}pending-${boundary}.m4a`;
      const root = await render(<Harness />);
      fakeRecorderStatus.url = uri; fs.__seedFile(uri);
      await act(async () => { await latest.start(); });
      if (boundary === "stop") recorderControls.stop.mockImplementationOnce(async () => { await wait.promise; });
      else fs.readAsStringAsync.mockImplementationOnce(async () => { await wait.promise; return "QUJD"; });
      let stopping!: Promise<void>;
      await act(async () => { stopping = latest.stop(); });
      await flush();
      await act(async () => { root.unmount(); });
      expect(recorderControls.release).not.toHaveBeenCalled();
      await act(async () => { wait.resolve(); await stopping; });
      await flush();
      expect(latest.take).toBeNull();
      expect(fs.__hasFile(uri)).toBe(false);
      expect(recorderControls.release).toHaveBeenCalledTimes(1);
      if (boundary === "stop") expect(fs.readAsStringAsync).not.toHaveBeenCalled();
    });
  }

  it("reset fences a pending read and drains disposal before the next take, which remains usable", async () => {
    const wait = deferred<void>();
    const oldUri = `${fs.cacheDirectory}old.m4a`;
    const newUri = `${fs.cacheDirectory}new.m4a`;
    const root = await render(<Harness />);
    fakeRecorderStatus.url = oldUri; fs.__seedFile(oldUri);
    await act(async () => { await latest.start(); });
    fs.readAsStringAsync.mockImplementationOnce(async () => { await wait.promise; return "T0xE"; });
    let stopping!: Promise<void>; let starting!: Promise<void>;
    await act(async () => { stopping = latest.stop(); });
    await flush();
    recorderControls.prepareToRecordAsync.mockImplementationOnce(async () => { fakeRecorderStatus.url = newUri; fs.__seedFile(newUri, "TkVX"); });
    await act(async () => { latest.reset(); starting = latest.start(); });
    expect(recorderControls.prepareToRecordAsync).toHaveBeenCalledTimes(1);
    await act(async () => { wait.resolve(); await stopping; await starting; });
    expect(latest.state).toBe("recording");
    expect(latest.take).toBeNull();
    expect(fs.__hasFile(oldUri)).toBe(false);
    expect(fs.__hasFile(newUri)).toBe(true);
    await act(async () => { await latest.stop(); });
    expect(latest.take).toMatchObject({ uri: newUri, base64: "TkVX" });
    expect(fs.__hasFile(newUri)).toBe(true);
    await act(async () => { root.unmount(); });
    await flush();
    expect(fs.__hasFile(newUri)).toBe(false);
  });

  it("duplicate starts and stops share one native operation while the current take succeeds", async () => {
    const wait = deferred<void>();
    AudioModule.requestRecordingPermissionsAsync.mockImplementationOnce(async () => { await wait.promise; return { granted: true }; });
    const uri = `${fs.cacheDirectory}single.m4a`;
    const root = await render(<Harness />);
    fakeRecorderStatus.url = uri; fs.__seedFile(uri);
    let first!: Promise<void>; let duplicate!: Promise<void>;
    await act(async () => { first = latest.start(); duplicate = latest.start(); });
    await flush();
    expect(AudioModule.requestRecordingPermissionsAsync).toHaveBeenCalledTimes(1);
    await act(async () => { wait.resolve(); await Promise.all([first, duplicate]); });
    const stopWait = deferred<void>();
    recorderControls.stop.mockImplementationOnce(async () => { await stopWait.promise; });
    await act(async () => { first = latest.stop(); duplicate = latest.stop(); });
    expect(first).toBe(duplicate);
    await act(async () => { stopWait.resolve(); await Promise.all([first, duplicate]); });
    expect(recorderControls.record).toHaveBeenCalledTimes(1);
    expect(recorderControls.stop).toHaveBeenCalledTimes(1);
    expect(fs.readAsStringAsync).toHaveBeenCalledTimes(1);
    expect(latest.take?.uri).toBe(uri);
    await act(async () => { root.unmount(); });
  });
});
