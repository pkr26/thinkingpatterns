import { beforeEach, expect, it, vi } from "vitest";
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { __resetAudioMock, fakeRecorderStatus } from "./helpers/expoAudioMock";
import * as files from "./helpers/expoFsMock";
import { discardTakeFile, useVoiceRecorder } from "../src/audio/recorder";

let latest: ReturnType<typeof useVoiceRecorder> | undefined;
function PublicRecorderConsumer() {
  latest = useVoiceRecorder({ permissionDenied: "Microphone denied", failed: "Recording failed" });
  return null;
}
beforeEach(() => {
  vi.restoreAllMocks();
  __resetAudioMock();
  files.__resetFiles();
  latest = undefined;
});

it("the exported recorder admits a recording and returns its readable speech take", async () => {
  const uri = `${files.cacheDirectory}public-hook-contract.m4a`;
  const speech = "cHVibGljIHJlY29yZGVyIHNwZWVjaA==";
  let root: ReactTestRenderer.ReactTestRenderer | undefined;
  const publicOperations: Promise<unknown>[] = [];
  const own = <T,>(operation: Promise<T>): Promise<T> => {
    publicOperations.push(operation);
    return operation;
  };
  try {
    await files.writeAsStringAsync(uri, speech);
    fakeRecorderStatus.url = uri;
    fakeRecorderStatus.durationMillis = 2000;
    await act(async () => { root = ReactTestRenderer.create(<PublicRecorderConsumer />); });
    expect(latest, "The exported hook supplies its documented recorder interface").toBeDefined();
    expect(latest?.state).toBe("idle");
    expect(latest?.take).toBeNull();
    if (!latest) return; // The assertion above already failed for a missing public interface.
    await act(async () => { await own(latest!.start()); });
    expect(latest.state, "An admitted public start reaches recording").toBe("recording");
    expect(latest.error).toBeNull();
    await act(async () => { await own(latest!.stop()); });
    expect(latest.state).toBe("stopped");
    expect(latest.error).toBeNull();
    expect(latest.take).toEqual({ uri, base64: speech, mime: "audio/m4a", durationSeconds: 2 });
    expect(await files.readAsStringAsync(uri)).toBe(speech);
  } finally {
    await Promise.allSettled(publicOperations);
    try {
      if (root) await act(async () => { root!.unmount(); });
      // The hook owns asynchronous disposal; keep this task isolated until
      // its public/native promise jobs have had an ordinary event-loop turn.
      await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); });
      await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); });
    } finally {
      await discardTakeFile({ uri, base64: speech, mime: "audio/m4a", durationSeconds: 2 });
    }
  }
}, 12000);
