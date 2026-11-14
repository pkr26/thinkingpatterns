import { act, StrictMode, Suspense, startTransition, useLayoutEffect, useState } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useRecorder, type UseRecorder, pickRecorderMime, normalizeMime } from "../src/audio/recorder";
import { render as renderWithCleanup } from "./helpers/rtr";
let roots: Awaited<ReturnType<typeof renderWithCleanup>>[];
async function render(element: React.ReactElement) { const root = await renderWithCleanup(element); roots.push(root); return root; }

let current: UseRecorder, tracks: { stop: ReturnType<typeof vi.fn> }[], calls: number;
let failConstruct = false, failStart = false, reportedMime: string | null = null, connected = false;
let recorder: FakeRecorder, pending: (() => Promise<MediaStream>) | null;
let deferStops: boolean, stoppedEvents: (() => void)[];
let deferTrackEnd = false, trackEndEvents: (() => void)[] = [];
let frames: Map<number, () => void>, frameId: number, sample = 128;
const close = vi.fn(async () => {});
const win = window as unknown as Record<string, unknown>;
class FakeRecorder {
  static isTypeSupported(type: string): boolean { return type === "audio/ogg;codecs=opus"; }
  state = "inactive"; mimeType: string;
  ondataavailable: ((event: { data: Blob }) => void) | null = null;
  onstop: (() => void) | null = null; onerror: (() => void) | null = null;
  constructor(stream: MediaStream, options?: { mimeType?: string }) {
    if (failConstruct) throw new Error("constructor failed"); this.mimeType = reportedMime ?? options?.mimeType ?? "audio/webm"; recorder = this;
    // Ending every recorded track also stops MediaRecorder. Keep that
    // browser behavior so deleting a redundant recorder.stop() cannot
    // earn artificial kill credit from an incomplete media fixture.
    const tracked = stream.getTracks(), ended = new Set<MediaStreamTrack>();
    for (const track of tracked) {
      if (vi.isMockFunction(track.stop)) {
        const stop = vi.mocked(track.stop), original = stop.getMockImplementation();
        stop.mockImplementation(() => { original?.(); ended.add(track); if (ended.size === tracked.length) { if (deferTrackEnd) trackEndEvents.push(() => this.streamEnded()); else this.streamEnded(); } });
      }
    }
  }
  start(): void { if (failStart) throw new Error("start failed"); this.state = "recording"; }
  private queueStop(): void { const dispatch = () => this.onstop?.(); if (deferStops) stoppedEvents.push(dispatch); else void Promise.resolve().then(dispatch); }
  stop(): void { if (this.state === "inactive") throw new Error("recorder is inactive"); this.state = "inactive"; this.queueStop(); }
  streamEnded(): void { if (this.state !== "inactive") { this.state = "inactive"; this.queueStop(); } }
}
class Meter {
  close = close;
  createMediaStreamSource(): { connect: () => void } { return { connect: () => { connected = true; } }; }
  createAnalyser(): { fftSize: number; readonly frequencyBinCount: number; getByteTimeDomainData: (buffer: Uint8Array) => void } {
    return { fftSize: 0, get frequencyBinCount() { return this.fftSize / 2; }, getByteTimeDomainData: buffer => { buffer.fill(128); if (buffer.length && connected) buffer[0] = sample; } };
  }
}
function Probe({ denied = "Permission denied" }: { denied?: string }): null { current = useRecorder({ unsupported: "Recording unavailable", permissionDenied: denied, failed: "Recording failed" }); return null; }
beforeEach(() => {
  roots = []; tracks = []; calls = 0; failConstruct = false; failStart = false; reportedMime = null; connected = false; pending = null; frameId = 0; frames = new Map(); sample = 128; deferStops = false; stoppedEvents = []; deferTrackEnd = false; trackEndEvents = []; close.mockClear();
  vi.stubGlobal("MediaRecorder", FakeRecorder);
  vi.stubGlobal("navigator", { mediaDevices: { getUserMedia: async (constraints: MediaStreamConstraints) => { calls++; if (constraints.audio !== true) throw new Error("An audio capture request is required"); if (pending) return pending(); const track = { stop: vi.fn() }; tracks.push(track); return { getTracks: () => [track] } as unknown as MediaStream; } } });
  win.setInterval = (callback: () => void, ms: number) => setInterval(callback, ms); win.clearInterval = (id: ReturnType<typeof setInterval>) => clearInterval(id);
  win.requestAnimationFrame = (callback: () => void) => { frames.set(++frameId, callback); return frameId; }; win.cancelAnimationFrame = (id: number) => { frames.delete(Number(id)); }; win.AudioContext = Meter;
});
afterEach(async () => { await act(async () => { for (const root of roots) root.unmount(); }); for (const name of ["setInterval", "clearInterval", "requestAnimationFrame", "cancelAnimationFrame", "AudioContext"]) delete win[name]; vi.useRealTimers(); vi.unstubAllGlobals(); });
async function frame(): Promise<void> { const [id, callback] = [...frames][0]!; frames.delete(id); await act(async () => callback()); }

it("uses the first actually supported recorder format even if an earlier capability probe throws", () => {
  const supported = vi.spyOn(FakeRecorder, "isTypeSupported").mockImplementationOnce(() => { throw new Error("probe failed"); });
  expect(pickRecorderMime()).toBe("audio/ogg;codecs=opus"); expect(supported).toHaveBeenCalledWith("audio/ogg;codecs=opus"); supported.mockRestore();
});
it("supports a browser offering only plain WebM and normalizes padded MIME parameters for the upload", () => {
  const spy = vi.spyOn(FakeRecorder, "isTypeSupported").mockImplementation(type => type === "audio/webm");
  expect(pickRecorderMime()).toBe("audio/webm"); expect(normalizeMime("  AUDIO/WEBM ; codecs=opus ")).toBe("audio/webm"); spy.mockRestore();
});
it("exposes unsupported state before any start attempt and after resetting when the browser has no recorder", async () => {
  vi.stubGlobal("MediaRecorder", undefined); const root = await render(<Probe />);
  expect(current.state).toBe("unsupported"); await act(async () => current.reset()); expect(current.state).toBe("unsupported");
  await act(async () => root.unmount());
});
it("reports unsupported recording when formats, the recorder, or microphone acquisition are unavailable", async () => {
  for (const missing of ["formats", "recorder", "microphone"]) {
    const spy = missing === "formats" ? vi.spyOn(FakeRecorder, "isTypeSupported").mockReturnValue(false) : null;
    if (missing === "recorder") vi.stubGlobal("MediaRecorder", undefined);
    if (missing === "microphone") vi.stubGlobal("navigator", {});
    const root = await render(<Probe />); await act(async () => current.start());
    expect(current.state).toBe("unsupported"); expect(current.error).toBe("Recording unavailable"); expect(calls).toBe(0);
    await act(async () => root.unmount()); spy?.mockRestore(); vi.stubGlobal("MediaRecorder", FakeRecorder);
  }
});
it.each(["construct", "start"])("releases every acquired track after %s failure and permits a fresh attempt", async failure => {
  const root = await render(<Probe />); failConstruct = failure === "construct"; failStart = failure === "start";
  await act(async () => current.start()); expect(current.error).toBe("Recording failed"); expect(tracks[0]!.stop).toHaveBeenCalledOnce(); expect(current.recording).toBeNull();
  failConstruct = false; failStart = false; await act(async () => current.start()); expect(current.state).toBe("recording"); expect(current.error).toBeNull(); expect(calls).toBe(2);
  await act(async () => root.unmount()); expect(tracks[1]!.stop).toHaveBeenCalledOnce();
});
it("never acknowledges a discarded acquisition or retains its late microphone stream", async () => {
  const requests: ((stream: MediaStream) => void)[] = []; pending = () => new Promise(r => { requests.push(r); });
  const root = await render(<Probe />); let acquisition!: Promise<void>;
  await act(async () => { acquisition = current.start(); }); let second!: Promise<void>; await act(async () => { second = current.start(); });
  const stop = vi.fn();
  try { expect(calls).toBe(1); }
  finally { await act(async () => { current.reset(); for (const resolve of requests) resolve({ getTracks: () => [{ stop }] } as unknown as MediaStream); await Promise.allSettled([acquisition, second]); }); }
  expect(stop).toHaveBeenCalledOnce(); expect(current.state).toBe("idle"); expect(current.recording).toBeNull(); expect(frames.size).toBe(0);
  pending = null; await act(async () => current.start()); expect(current.state).toBe("recording"); expect(calls).toBe(2);
  await act(async () => root.unmount());
});
it("cannot confuse an older reset acquisition with its replacement, even while both permission requests are outstanding", async () => {
  const requests: ((stream: MediaStream) => void)[] = []; pending = () => new Promise(r => { requests.push(r); });
  const root = await render(<Probe />); let old!: Promise<void>, replacement!: Promise<void>;
  await act(async () => { old = current.start(); }); await act(async () => current.reset()); await act(async () => { replacement = current.start(); });
  const oldStop = vi.fn(), newStop = vi.fn();
  try {
    expect(requests).toHaveLength(2);
    await act(async () => { requests[0]!({ getTracks: () => [{ stop: oldStop }] } as unknown as MediaStream); await old; });
    expect(oldStop).toHaveBeenCalledOnce(); expect(current.state).toBe("idle");
  } finally {
    await act(async () => { for (const resolve of requests) resolve({ getTracks: () => [{ stop: newStop }] } as unknown as MediaStream); await Promise.allSettled([old, replacement]); });
  }
  expect(current.state).toBe("recording"); await act(async () => current.reset()); expect(newStop).toHaveBeenCalledOnce(); await act(async () => root.unmount());
});
it("discards a microphone acquired after unmount and ignores a rejection from an obsolete request", async () => {
  let resolve!: (stream: MediaStream) => void; pending = () => new Promise(r => { resolve = r; });
  const root = await render(<Probe />); let acquisition!: Promise<void>; await act(async () => { acquisition = current.start(); }); await act(async () => root.unmount());
  const stop = vi.fn(); await act(async () => { resolve({ getTracks: () => [{ stop }] } as unknown as MediaStream); await acquisition; }); expect(stop).toHaveBeenCalledOnce();
  const before = calls; let retired!: Promise<void>; await act(async () => { retired = current.start(); });
  try { expect(calls).toBe(before); }
  finally { await act(async () => { resolve({ getTracks: () => [{ stop: vi.fn() }] } as unknown as MediaStream); await retired; current.reset(); }); }
  let reject!: (error: Error) => void; pending = () => new Promise((_resolve, r) => { reject = r; });
  const other = await render(<Probe />); await act(async () => { acquisition = current.start(); }); await act(async () => current.reset()); await act(async () => { reject(new Error("denied")); await acquisition; });
  expect(current.error).toBeNull(); expect(current.state).toBe("idle"); await act(async () => other.unmount());
});
it("shows permission denial without retaining a live recorder or preventing the next attempt", async () => {
  pending = async () => { throw new Error("permission denied"); }; const root = await render(<Probe />); await act(async () => current.start());
  expect(current.error).toBe("Permission denied"); expect(current.state).toBe("idle"); pending = null; await act(async () => current.start()); expect(current.state).toBe("recording"); expect(current.error).toBeNull();
  await act(async () => root.unmount());
});
it("can acquire the microphone after the application's StrictMode effect cleanup and remount", async () => {
  const root = await render(<StrictMode><Probe /></StrictMode>);
  await act(async () => current.start());
  expect(current.state).toBe("recording"); expect(calls).toBe(1);
  await act(async () => current.stop()); expect(current.recording).not.toBeNull();
  await act(async () => root.unmount());
});
it("clears an error on reset and uses the latest translated permission message after a render", async () => {
  pending = async () => { throw new Error("permission denied"); }; const root = await render(<Probe />);
  await act(async () => current.start()); expect(current.error).toBe("Permission denied");
  await act(async () => current.reset()); expect(current.error).toBeNull();
  await act(async () => root.update(<Probe denied="Permiso denegado" />)); await act(async () => current.start()); expect(current.error).toBe("Permiso denegado");
  await act(async () => root.unmount());
});
it("ignores a late browser error from a discarded recorder after a fresh take has started", async () => {
  const root = await render(<Probe />); await act(async () => current.start()); const discarded = recorder;
  await act(async () => current.reset()); await act(async () => current.start());
  await act(async () => discarded.onerror?.());
  expect(current.state).toBe("recording"); expect(current.error).toBeNull(); expect(tracks[1]!.stop).not.toHaveBeenCalled();
  await act(async () => current.stop()); await act(async () => root.unmount());
});
it("releases the level meter and elapsed clock when the browser ends the recorded stream itself", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] }); vi.setSystemTime(0);
  const root = await render(<Probe />); await act(async () => current.start()); sample = 160; await frame(); expect(current.level).toBeGreaterThan(0);
  await act(async () => recorder.streamEnded()); expect(current.state).toBe("stopped"); expect(current.level).toBe(0); expect(close).toHaveBeenCalledOnce(); expect(frames.size).toBe(0);
  await act(async () => vi.advanceTimersByTime(2500)); expect(current.elapsedSeconds).toBe(0); await act(async () => root.unmount());
});
it("does not let a queued stop event from the previous take finish its replacement", async () => {
  deferStops = true; const root = await render(<Probe />); await act(async () => current.start());
  await act(async () => current.stop()); await act(async () => current.start());
  await act(async () => { stoppedEvents.shift()!(); });
  expect(current.state).toBe("recording"); expect(current.recording).toBeNull(); expect(tracks[1]!.stop).not.toHaveBeenCalled();
  await act(async () => current.reset()); await act(async () => { for (const dispatch of stoppedEvents) dispatch(); }); await act(async () => root.unmount());
});
it("does not cancel an unrelated frame with valid browser id zero while resetting an idle recorder", async () => {
  let observed = false; frames.set(0, () => { observed = true; }); const root = await render(<Probe />);
  await act(async () => current.reset()); expect(frames.has(0)).toBe(true); frames.get(0)!(); expect(observed).toBe(true);
  await act(async () => root.unmount());
});
it("keeps real recorded chunks, uses the selected MIME when the recorder omits it and rounds a short take to at least one second", async () => {
  vi.useFakeTimers({ toFake: ["Date"] }); vi.setSystemTime(10000); reportedMime = "";
  const root = await render(<Probe />); await act(async () => current.start());
  await act(async () => { recorder.ondataavailable?.({ data: new Blob() }); recorder.ondataavailable?.({ data: new Blob(["first"]) }); recorder.ondataavailable?.({ data: new Blob(["second"]) }); current.stop(); });
  expect(current.state).toBe("stopped"); expect(current.recording).toMatchObject({ mime: "audio/ogg;codecs=opus", normalizedMime: "audio/ogg", extension: ".ogg", durationSeconds: 1 }); expect(await current.recording!.blob.text()).toBe("firstsecond");
  await act(async () => current.stop()); expect(tracks[0]!.stop).toHaveBeenCalledOnce(); await act(async () => current.reset()); expect(current.recording).toBeNull(); expect(current.elapsedSeconds).toBe(0); expect(current.level).toBe(0);
  await act(async () => root.unmount());
});
it("uses the browser's requested recording format and records elapsed wall-clock duration across successive takes", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] }); vi.setSystemTime(0);
  const root = await render(<Probe />); await act(async () => current.start());
  await act(async () => vi.advanceTimersByTime(3800)); await act(async () => { recorder.ondataavailable?.({ data: new Blob(["voice"]) }); current.stop(); });
  expect(current.recording).toMatchObject({ mime: "audio/ogg;codecs=opus", normalizedMime: "audio/ogg", extension: ".ogg", durationSeconds: 4 });
  expect(await current.recording!.blob.text()).toBe("voice"); expect(current.elapsedSeconds).toBe(3);
  await act(async () => current.start()); expect(current.elapsedSeconds).toBe(0);
  await act(async () => current.reset()); await act(async () => root.unmount());
});
it("shows a symmetric bounded live sound level and disposes the audio context, frame loop and elapsed clock", async () => {
  vi.useFakeTimers({ toFake: ["Date", "setInterval", "clearInterval"] }); vi.setSystemTime(0);
  const root = await render(<Probe />); await act(async () => current.start()); await frame(); expect(current.level).toBe(0);
  sample = 160; await frame(); const positive = current.level; expect(positive).toBeGreaterThan(0); expect(positive).toBeLessThan(1);
  sample = 96; await frame(); expect(current.level).toBe(positive);
  sample = 0; await frame(); expect(current.level).toBe(1);
  await act(async () => vi.advanceTimersByTime(1500)); expect(current.elapsedSeconds).toBe(1);
  const stale = [...frames.values()][0]!; await act(async () => current.reset()); expect(close).toHaveBeenCalledOnce(); expect(frames.size).toBe(0); expect(current.level).toBe(0);
  await act(async () => stale()); expect(frames.size).toBe(0); expect(current.level).toBe(0); await act(async () => vi.advanceTimersByTime(3000)); expect(current.elapsedSeconds).toBe(0);
  await act(async () => root.unmount());
});
it("continues recording when the optional level meter fails", async () => {
  win.AudioContext = class { close = close; createMediaStreamSource(): never { throw new Error("meter unavailable"); } };
  const root = await render(<Probe />); await act(async () => current.start()); expect(current.state).toBe("recording"); expect(current.error).toBeNull(); expect(current.level).toBe(0);
  await act(async () => current.stop()); expect(current.state).toBe("stopped"); expect(tracks[0]!.stop).toHaveBeenCalledOnce(); expect(close).toHaveBeenCalledOnce(); await act(async () => root.unmount());
});

// The browser queues recorder inactivation after all tracks end. Explicit
// stop(), by contrast, changes recorder.state synchronously.
it("inactivates an active recorder immediately when resetting before the queued track-end task", async () => {
  deferTrackEnd = true; const root = await render(<Probe />);
  try {
    await act(async () => current.start()); const active = recorder; expect(active.state).toBe("recording");
    await act(async () => { current.reset(); expect(active.state).toBe("inactive"); });
  } finally { await act(async () => { for (const dispatch of trackEndEvents.splice(0)) dispatch(); root.unmount(); }); }
});
it("inactivates an active recorder immediately when unmounting before the queued track-end task", async () => {
  deferTrackEnd = true; const root = await render(<Probe />);
  try {
    await act(async () => current.start()); const active = recorder; expect(active.state).toBe("recording");
    await act(async () => root.unmount()); expect(active.state).toBe("inactive");
  } finally { await act(async () => { for (const dispatch of trackEndEvents.splice(0)) dispatch(); root.unmount(); }); }
});

it("does not add a discarded take's queued data to a replacement recording", async () => {
  deferStops = true; const root = await render(<Probe />);
  try {
    await act(async () => current.start()); const old = recorder;
    await act(async () => current.stop());
    await act(async () => current.reset());
    await act(async () => current.start()); const fresh = recorder;
    await act(async () => {
      old.ondataavailable?.({ data: new Blob(["discarded"]) });
      fresh.ondataavailable?.({ data: new Blob(["fresh"]) });
      current.stop();
      for (const dispatch of stoppedEvents.splice(0)) dispatch();
    });
    expect(current.recording).not.toBeNull();
    expect(await current.recording!.blob.text()).toBe("fresh");
  } finally {
    await act(async () => { current.reset(); for (const dispatch of stoppedEvents.splice(0)) dispatch(); root.unmount(); });
  }
});

it("does not throw when stopping again after a replacement recorder fails to construct", async () => {
  deferStops = true; const root = await render(<Probe />);
  try {
    await act(async () => current.start()); expect(current.state).toBe("recording");
    await act(async () => current.stop());
    failConstruct = true; await act(async () => current.start());
    expect(current.error).toBe("Recording failed");
    await act(async () => { expect(() => current.stop()).not.toThrow(); });
  } finally {
    await act(async () => { current.reset(); for (const dispatch of stoppedEvents.splice(0)) dispatch(); root.unmount(); });
  }
});


it("allows the caller's layout effect to start before the recorder passive effect", async () => {
  let started: Promise<void> | undefined;
  function LayoutStart(): null {
    current = useRecorder({ unsupported: "Recording unavailable", permissionDenied: "Permission denied", failed: "Recording failed" });
    useLayoutEffect(() => { started = current.start(); }, []);
    return null;
  }
  const root = await render(<LayoutStart />);
  try {
    expect(calls, "layout start reaches microphone acquisition").toBe(1);
    await act(async () => { await started; });
    expect(current.state).toBe("recording");
  } finally { await act(async () => { await started; root.unmount(); }); }
});


it("retained idle stop cannot stop a later active recording", async () => {
  await render(<Probe />);
  const stopWhileIdle = current.stop;
  await act(async () => current.start());
  expect(current.state).toBe("recording");
  expect(recorder.state).toBe("recording");
  try {
    await act(async () => stopWhileIdle());
    expect(recorder.state).toBe("recording");
  } finally {
    await act(async () => current.reset());
  }
});


it("repeated urgent stop does not bypass an earlier suspended finalize", async () => {
  let pause!: (value: boolean) => void;
  let release!: () => void;
  let released = false;
  let gateThrows = 0;
  const pendingGate = new Promise<void>(resolve => { release = resolve; });
  function Gate({ suspended }: { suspended: boolean }): null {
    if (suspended && !released) { gateThrows++; throw pendingGate; }
    return null;
  }
  function CommittedProbe(): null {
    const recorderValue = useRecorder({ unsupported: "Recording unavailable", permissionDenied: "Permission denied", failed: "Recording failed" });
    useLayoutEffect(() => { current = recorderValue; });
    return null;
  }
  function Caller(): React.ReactElement {
    const [suspended, setSuspended] = useState(false);
    pause = setSuspended;
    return <><CommittedProbe /><Suspense fallback={null}><Gate suspended={suspended} /></Suspense></>;
  }
  deferStops = true; sample = 224;
  await render(<Caller />);
  await act(async () => current.start());
  expect(current.state).toBe("recording");
  await frame();
  expect(current.level).toBeGreaterThan(0);
  try {
    await act(async () => { startTransition(() => { current.stop(); pause(true); }); });
    expect(gateThrows).toBeGreaterThan(0);
    expect(recorder.state).toBe("inactive");
    expect(stoppedEvents).toHaveLength(1);
    expect(current.level).toBeGreaterThan(0);
    await act(async () => current.stop());
    expect(current.level).toBeGreaterThan(0);
  } finally {
    released = true; release();
    await act(async () => { pause(false); current.reset(); });
  }
});
