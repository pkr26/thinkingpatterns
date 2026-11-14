import { beforeEach, expect, it, vi } from "vitest";
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { __resetAudioMock } from "./helpers/expoAudioMock";
import * as files from "./helpers/expoFsMock";
import { useVoiceRecorder } from "../src/audio/recorder";

let latest: ReturnType<typeof useVoiceRecorder> | undefined;
function RecorderConsumer() {
  latest = useVoiceRecorder({ permissionDenied: "Microphone denied", failed: "Recording failed" });
  return null;
}
beforeEach(() => { vi.restoreAllMocks(); __resetAudioMock(); files.__resetFiles(); latest = undefined; });

it("a recording without a native URI reports failure without reading an invalid file", async () => {
  let root: ReactTestRenderer.ReactTestRenderer | undefined;
  const operations: Promise<unknown>[] = [];
  const own = <T,>(operation: Promise<T>): Promise<T> => { operations.push(operation); return operation; };
  try {
    await act(async () => { root = ReactTestRenderer.create(<RecorderConsumer />); });
    expect(latest).toBeDefined();
    if (!latest) return;
    await act(async () => { await own(latest!.start()); });
    expect(latest.state).toBe("recording");
    await act(async () => { await own(latest!.stop()); });
    expect(latest.state).toBe("stopped");
    expect(latest.error).toBe("Recording failed");
    expect(latest.take).toBeNull();
    // No URI is available from the SDK. Do not send an invalid argument across
    // the Expo filesystem boundary merely to manufacture the error above.
    expect(files.readAsStringAsync, "No file can be read without a native URI").not.toHaveBeenCalled();
  } finally {
    await Promise.allSettled(operations);
    if (root) await act(async () => { root!.unmount(); });
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); });
    await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); });
  }
}, 12000);
