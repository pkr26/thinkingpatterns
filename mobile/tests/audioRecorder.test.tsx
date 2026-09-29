/**
 * useVoiceRecorder lifecycle (VOICE_PLAN remediation, 2026-09-29): the
 * hook driven end to end against the expo-audio/expo-file-system mocks —
 * the prepareToRecordAsync gate (C3), the pinned codec options (C4), the
 * honest clamped duration (M2), take-file hygiene through reset and
 * unmount (M1), and the permission/failed branches.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

const {
  AudioModule,
  recorderControls,
  fakeRecorderStatus,
  __resetAudioMock,
} = await import("./helpers/expoAudioMock");
const fs = await import("./helpers/expoFsMock");
const { useVoiceRecorder, MAX_RECORDING_SECONDS } = await import("../src/audio/recorder");
const { render, act, flush } = await import("./helpers/rtr");

const STRINGS = { permissionDenied: "mic denied", failed: "record failed" };

/** The hook's return value, captured at the last render. */
let latest: ReturnType<typeof useVoiceRecorder> | null = null;
function Harness(): React.JSX.Element {
  latest = useVoiceRecorder(STRINGS);
  return null;
}

/** Produce a finished take: seed the fs + recorder status, start, stop. */
async function recordTake(root: Awaited<ReturnType<typeof render>>, uri: string, durationMillis: number): Promise<void> {
  fs.__seedFile(uri, "QUJDREVG");
  fakeRecorderStatus.url = uri;
  fakeRecorderStatus.durationMillis = durationMillis;
  await act(async () => {
    await latest!.start();
  });
  await act(async () => {
    await latest!.stop();
  });
  await flush();
}

beforeEach(() => {
  __resetAudioMock();
  fs.__resetFiles();
  latest = null;
});

afterEach(() => {
  vi.useRealTimers();
});

describe("recorder lifecycle", () => {
  it("records with the pinned codec contract (mono 16 kHz ~24 kbps AAC in .m4a)", async () => {
    await render(<Harness />);
    const options = vi.mocked(await import("./helpers/expoAudioMock")).useAudioRecorder.mock.calls[0][0];
    // Android: STRING enums — numeric constants crash the EnumTypeConverter.
    expect(options.android.outputFormat).toBe("mpeg4");
    expect(options.android.audioEncoder).toBe("aac");
    // iOS: no outputFormat — the .m4a default container is AAC (LPCM
    // cannot live in .m4a); 96 is AudioQuality.HIGH (0x60).
    expect(options.ios).not.toHaveProperty("outputFormat");
    expect(options.ios.audioQuality).toBe(96);
    expect(options.sampleRate).toBe(16000);
    expect(options.numberOfChannels).toBe(1);
    expect(options.bitRate).toBe(24000);
    expect(options.extension).toBe(".m4a");
  });

  it("a denied microphone permission surfaces the message and never prepares", async () => {
    AudioModule.requestRecordingPermissionsAsync.mockResolvedValueOnce({ granted: false } as never);
    await render(<Harness />);
    await act(async () => {
      await latest!.start();
    });
    expect(latest!.error).toBe("mic denied");
    expect(latest!.state).toBe("idle");
    expect(recorderControls.prepareToRecordAsync).not.toHaveBeenCalled();
    expect(recorderControls.record).not.toHaveBeenCalled();
  });

  it("a failed prepare surfaces the failed message and never records (C3)", async () => {
    recorderControls.prepareToRecordAsync.mockRejectedValueOnce(new Error("not prepared"));
    await render(<Harness />);
    await act(async () => {
      await latest!.start();
    });
    expect(latest!.error).toBe("record failed");
    expect(latest!.state).toBe("idle");
    expect(recorderControls.record).not.toHaveBeenCalled();
  });

  it("start prepares before recording; stop yields a take read through the fs", async () => {
    const uri = "/tmp/mindpattern-test-cache/take-1.m4a";
    const root = await render(<Harness />);
    fs.__seedFile(uri, "QUJDREVG");
    fakeRecorderStatus.url = uri;
    fakeRecorderStatus.durationMillis = 4200;
    await act(async () => {
      await latest!.start();
    });
    // The native contract: prepareToRecordAsync BEFORE record() — iOS
    // startRecording guards on .prepared, Android record() no-ops without it.
    expect(recorderControls.prepareToRecordAsync).toHaveBeenCalledTimes(1);
    expect(recorderControls.record).toHaveBeenCalledTimes(1);
    expect(latest!.state).toBe("recording");
    await act(async () => {
      await latest!.stop();
    });
    await flush();
    expect(latest!.state).toBe("stopped");
    expect(latest!.take).toEqual({
      uri,
      base64: "QUJDREVG",
      mime: "audio/m4a",
      // The recorder's honest durationMillis (4200 ms), not the wall clock.
      durationSeconds: 4,
    });
    expect(fs.readAsStringAsync).toHaveBeenCalledWith(uri, { encoding: "base64" });
  });

  it("the 300 s auto-stop fires from the interval and clamps the duration (M2)", async () => {
    vi.useFakeTimers();
    const uri = "/tmp/mindpattern-test-cache/take-clamp.m4a";
    fs.__seedFile(uri, "QUJDREVG");
    fakeRecorderStatus.url = uri;
    const root = await render(<Harness />);
    await act(async () => {
      await latest!.start();
    });
    // A backgrounded wall clock overruns while the recorder reports 312 s.
    fakeRecorderStatus.durationMillis = 312_345;
    await act(async () => {
      root.update(<Harness />);
    });
    const startedAt = Date.now();
    vi.setSystemTime(startedAt + (MAX_RECORDING_SECONDS + 1) * 1000);
    // Fire one interval tick (no real-timer flush(): setTimeout is faked).
    await act(async () => {
      await vi.advanceTimersByTimeAsync(600);
    });
    expect(latest!.state).toBe("stopped");
    // Never the wall clock's 301 s — the server rejects > 310 s.
    expect(latest!.take?.durationSeconds).toBe(MAX_RECORDING_SECONDS);
  });

  it("reset discards the take's cache file (privacy)", async () => {
    const uri = "/tmp/mindpattern-test-cache/take-reset.m4a";
    const root = await render(<Harness />);
    await recordTake(root, uri, 1500);
    expect(latest!.take).not.toBeNull();
    await act(async () => {
      latest!.reset();
    });
    await flush();
    expect(fs.deleteAsync).toHaveBeenCalledWith(uri, { idempotent: true });
    expect(fs.__hasFile(uri)).toBe(false);
    expect(latest!.take).toBeNull();
    expect(latest!.state).toBe("idle");
  });

  it("unmount discards an unconsumed take (M1: no plaintext left behind)", async () => {
    const uri = "/tmp/mindpattern-test-cache/take-unmount.m4a";
    const root = await render(<Harness />);
    await recordTake(root, uri, 1500);
    expect(fs.__hasFile(uri)).toBe(true);
    await act(async () => {
      root.unmount();
    });
    await flush();
    expect(fs.deleteAsync).toHaveBeenCalledWith(uri, { idempotent: true });
    expect(fs.__hasFile(uri)).toBe(false);
  });
});
