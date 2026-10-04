/** useRecorder harness tests (voice-audit remediation 2026-09-29, H1/M-1/
 *  L-6): the unmount teardown actually runs at UNMOUNT, the discard paths
 *  detach the recorder's events before the stream tracks die (a discarded
 *  take can never resurrect through the async stop event), double-start
 *  is guarded, the 5-minute cap finalizes, and onerror finalizes with the
 *  mic released. Plus the H3 pins: voice calls ride a deadline strictly
 *  longer than the global 15 s one. */
// @ts-nocheck

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import RTR from "react-test-renderer";
import { useRecorder, type UseRecorder } from "../src/audio/recorder";
import { api, ApiError, REQUEST_TIMEOUT_MS, VOICE_REQUEST_TIMEOUT_MS } from "../src/api/client";
import { installSession, resetTestState, stubFetch } from "./helpers/api";

// --- the MediaRecorder / getUserMedia mock harness ----------------------------
//
// Mirrors the MediaRecorder spec's ASYNC stop semantics: recorder.stop()
// — and a stream whose tracks all end while a recorder is live — queue
// the dataavailable/stop events as microtasks. A handler detached before
// that flush therefore never fires, which is exactly the resurrection
// vector the teardown order must close.

class MockMediaTrack {
  stopped = false;
  constructor(private readonly onStopped: () => void) {}
  stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    this.onStopped();
  }
}

class MockMediaStream {
  readonly tracks: MockMediaTrack[];
  private readonly recorders = new Set<MockMediaRecorder>();
  constructor() {
    const stream = this;
    this.tracks = [
      new MockMediaTrack(() => {
        // Spec: when every track of the recorded stream has ended, the
        // recorder stops the same way recorder.stop() stops it.
        if (stream.tracks.every((track) => track.stopped)) {
          for (const recorder of stream.recorders) recorder.streamEnded();
        }
      }),
    ];
  }
  getTracks(): MockMediaTrack[] {
    return [...this.tracks];
  }
  attach(recorder: MockMediaRecorder): void {
    this.recorders.add(recorder);
  }
}

class MockMediaRecorder {
  static readonly instances: MockMediaRecorder[] = [];
  static isTypeSupported(mime: string): boolean {
    return mime.startsWith("audio/webm");
  }
  state: "inactive" | "recording" = "inactive";
  onstop: (() => void) | null = null;
  ondataavailable: ((event: { data: Blob }) => void) | null = null;
  onerror: (() => void) | null = null;
  stoppedByTrackEnd = false;
  /** Test knob: make stop() itself throw (the L-6 finalize guard). */
  forceStopError = false;
  private readonly stream: MockMediaStream;
  constructor(stream: MockMediaStream, _options?: { mimeType?: string }) {
    this.stream = stream;
    stream.attach(this);
    MockMediaRecorder.instances.push(this);
  }
  get mimeType(): string {
    return "audio/webm;codecs=opus";
  }
  start(): void {
    this.state = "recording";
  }
  stop(): void {
    if (this.forceStopError) throw new Error("stop() exploded");
    if (this.state === "inactive") throw new Error("stop() called on an inactive recorder");
    this.state = "inactive";
    this.queueStopEvents();
  }
  /** The spec's "tracks ended" stop — indistinguishable from stop(). */
  streamEnded(): void {
    if (this.state !== "recording") return;
    this.state = "inactive";
    this.stoppedByTrackEnd = true;
    this.queueStopEvents();
  }
  fireError(): void {
    this.onerror?.();
  }
  private queueStopEvents(): void {
    void Promise.resolve().then(() => {
      this.ondataavailable?.({ data: new Blob(["take-bytes"]) });
      this.onstop?.();
    });
  }
}

interface Harness {
  streams: MockMediaStream[];
  getUserMediaCalls: number;
  windowPatches: string[];
}

/** Install the recorder globals for the node environment: MediaRecorder,
 *  navigator.mediaDevices.getUserMedia, and the window timers the hook
 *  schedules through (the setup shim's window carries none of them). The
 *  timer delegates resolve the global at CALL time, so fake-timer swaps
 *  stay observable. */
function installHarness(options?: { userMediaError?: Error }): Harness {
  const harness: Harness = { streams: [], getUserMediaCalls: 0, windowPatches: [] };
  MockMediaRecorder.instances.length = 0;
  vi.stubGlobal("MediaRecorder", MockMediaRecorder);
  vi.stubGlobal("navigator", {
    onLine: true,
    mediaDevices: {
      getUserMedia: async (): Promise<MediaStream> => {
        harness.getUserMediaCalls += 1;
        if (options?.userMediaError) throw options.userMediaError;
        const stream = new MockMediaStream();
        harness.streams.push(stream);
        return stream as unknown as MediaStream;
      },
    },
  });
  const win = (globalThis as unknown as { window: Record<string, unknown> }).window;
  const define = (name: string, value: unknown): void => {
    win[name] = value;
    harness.windowPatches.push(name);
  };
  define("setInterval", (handler: () => void, ms?: number) => setInterval(handler, ms));
  define("clearInterval", (id: ReturnType<typeof setInterval>) => clearInterval(id));
  define("requestAnimationFrame", (callback: (time: number) => void) =>
    setTimeout(() => callback(0), 16) as unknown as number);
  define("cancelAnimationFrame", (id: number) => clearTimeout(id));
  return harness;
}

/** A null-rendering probe exposing the hook's latest return value. */
function Probe(props: { captured: { current: UseRecorder | null } }): null {
  props.captured.current = useRecorder({ unsupported: "unsupported", permissionDenied: "denied", failed: "failed" });
  return null;
}

async function renderProbe(): Promise<{ root: ReturnType<typeof RTR.create>; captured: { current: UseRecorder | null } }> {
  const captured: { current: UseRecorder | null } = { current: null };
  let root!: ReturnType<typeof RTR.create>;
  await act(async () => {
    root = RTR.create(<Probe captured={captured} />);
  });
  return { root, captured };
}

let harness: Harness;

beforeEach(() => {
  harness = installHarness();
});
afterEach(() => {
  for (const name of harness.windowPatches) delete (globalThis as unknown as { window: Record<string, unknown> }).window[name];
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("useRecorder (voice-audit 2026-09-29)", () => {
  it("H1: unmount stops the stream tracks and detaches the recorder handlers", async () => {
    const { root, captured } = await renderProbe();
    await act(async () => {
      await captured.current!.start();
    });
    const stream = harness.streams[0]!;
    const recorder = MockMediaRecorder.instances[0]!;
    expect(captured.current!.state).toBe("recording");
    expect(recorder.onstop).toBeTypeOf("function");

    await act(async () => {
      root.unmount();
    });
    // Tracks dead, events detached, recorder stopped — and no take
    // resurrects through the queued stop event.
    expect(stream.tracks.every((track) => track.stopped)).toBe(true);
    expect(recorder.state).toBe("inactive");
    expect(recorder.onstop).toBeNull();
    expect(recorder.ondataavailable).toBeNull();
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(captured.current!.recording).toBeNull();
  });

  it("H1: reset() during recording discards the take — no async resurrection", async () => {
    const { captured } = await renderProbe();
    await act(async () => {
      await captured.current!.start();
    });
    const recorder = MockMediaRecorder.instances[0]!;
    await act(async () => {
      captured.current!.reset();
    });
    expect(captured.current!.state).toBe("idle");
    expect(captured.current!.recording).toBeNull();
    // The discard detached the events BEFORE any stop could queue them.
    expect(recorder.onstop).toBeNull();
    expect(recorder.ondataavailable).toBeNull();
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
    expect(captured.current!.recording).toBeNull();
  });

  it("M-1: a second start while one is live is a no-op (one stream, one recorder)", async () => {
    const { captured } = await renderProbe();
    await act(async () => {
      await captured.current!.start();
    });
    await act(async () => {
      await captured.current!.start();
    });
    expect(harness.getUserMediaCalls).toBe(1);
    expect(MockMediaRecorder.instances).toHaveLength(1);
    expect(captured.current!.state).toBe("recording");
  });

  it("the hard 5-minute cap auto-stops and finalizes the take", async () => {
    vi.useFakeTimers();
    const { captured } = await renderProbe();
    await act(async () => {
      await captured.current!.start();
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300_500);
    });
    expect(captured.current!.state).toBe("stopped");
    const take = captured.current!.recording;
    expect(take).not.toBeNull();
    expect(take!.blob.type).toBe("audio/webm");
    expect(take!.normalizedMime).toBe("audio/webm");
    expect(take!.extension).toBe(".webm");
    expect(take!.durationSeconds).toBeGreaterThanOrEqual(300);
    // The cap stops the recorder AND the mic underneath it.
    expect(MockMediaRecorder.instances[0]!.state).toBe("inactive");
    expect(harness.streams[0]!.tracks.every((track) => track.stopped)).toBe(true);
  });

  it("L-6: recorder.onerror surfaces the error and finalizes (mic released)", async () => {
    const { captured } = await renderProbe();
    await act(async () => {
      await captured.current!.start();
    });
    await act(async () => {
      MockMediaRecorder.instances[0]!.fireError();
    });
    expect(captured.current!.error).toBe("failed");
    expect(captured.current!.state).not.toBe("recording");
    expect(MockMediaRecorder.instances[0]!.state).toBe("inactive");
    expect(harness.streams[0]!.tracks.every((track) => track.stopped)).toBe(true);
  });

  it("L-6: a stop() that throws still tears the stream down (finalize guard)", async () => {
    const { captured } = await renderProbe();
    await act(async () => {
      await captured.current!.start();
    });
    const recorder = MockMediaRecorder.instances[0]!;
    recorder.forceStopError = true;
    await act(async () => {
      captured.current!.stop();
    });
    // The guarded finalize means the mic dies even when stop() explodes.
    expect(harness.streams[0]!.tracks.every((track) => track.stopped)).toBe(true);
  });
});

describe("voice request deadlines (H3, audit 2026-09-29)", () => {
  it("VOICE_REQUEST_TIMEOUT_MS is strictly longer than the global 15s cap", () => {
    expect(REQUEST_TIMEOUT_MS).toBe(15_000);
    expect(VOICE_REQUEST_TIMEOUT_MS).toBeGreaterThan(REQUEST_TIMEOUT_MS);
    // The server budgets 120 s for one upstream transcription; the client
    // deadline must cover it with margin.
    expect(VOICE_REQUEST_TIMEOUT_MS).toBeGreaterThanOrEqual(150_000);
  });

  it("transcribeAudio survives the 15s global cap and dies at its own deadline", async () => {
    vi.useFakeTimers();
    resetTestState();
    installSession();
    // A hung backend: the fetch never answers on its own — only the abort
    // (the deadline firing) ends it, which is exactly what the timer owns.
    stubFetch((_url: string, init: RequestInit) =>
      new Promise<Response>((_resolve, reject) => {
        init.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      }),
    );
    let caught: unknown = null;
    const pending = api.transcribeAudio("AAAA", "audio/webm", 60).catch((err: unknown) => {
      caught = err;
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS + 5_000);
    });
    expect(caught).toBeNull(); // the old 15 s cap would have killed this take
    await act(async () => {
      await vi.advanceTimersByTimeAsync(VOICE_REQUEST_TIMEOUT_MS);
    });
    await pending;
    expect(caught).toBeInstanceOf(ApiError);
    expect((caught as ApiError).status).toBe(0);
    expect((caught as ApiError).message).toContain("180");
  });
});
