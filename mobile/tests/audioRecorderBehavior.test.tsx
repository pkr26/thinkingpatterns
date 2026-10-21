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
  // BEGIN resource metadata receiver observation
  const ownedUri = `${files.cacheDirectory}status-uri-owned-metadata-cleanup.m4a`;
  const nativeAdd = Set.prototype.add, receivers: Set<unknown>[] = [];
  const observer = vi.spyOn(Set.prototype, "add").mockImplementation(function (this: Set<unknown>, value: unknown) {
    const result = nativeAdd.call(this, value);
    if (value === ownedUri && !receivers.includes(this)) receivers.push(this);
    return result;
  });
  let retired = false;
  let mountedRoot: ReactTestRenderer.ReactTestRenderer | undefined;
  // END resource metadata receiver observation
  // BEGIN resource metadata effect ownership
  try {
  // END resource metadata effect ownership
  const root = await render(<Consumer />), native = AudioModule.AudioRecorder.mock.results[0]!.value;
  // BEGIN resource metadata mounted root ownership
  mountedRoot = root;
  // END resource metadata mounted root ownership
  Object.defineProperty(native, "uri", { get: () => null }); await start(); await act(async () => { await latest.stop(); }); expect(latest.take?.uri).toBe(uri);
  // BEGIN resource metadata distinct public native take
  files.__seedFile(ownedUri, "cmVzb3VyY2Ugb3duZXI="); fakeRecorderStatus.url = ownedUri;
  await act(async () => { await latest.start(); await latest.stop(); });
  expect(latest.take?.uri).toBe(ownedUri);
  // END resource metadata distinct public native take
  await act(async () => root.unmount()); await flush(); expect(files.__hasFile(uri)).toBe(false);
  // BEGIN resource metadata settled ownership assertion
  retired = true;
  expect(files.__hasFile(ownedUri)).toBe(false);
  expect(receivers).toHaveLength(1);
  expect(receivers[0]!.has(ownedUri), "deleted native take metadata must release its URI").toBe(false);
  } finally {
    try { if (!retired && mountedRoot) { await act(async () => mountedRoot!.unmount()); await flush(); } }
    finally { observer.mockRestore(); }
  }
  // END resource metadata settled ownership assertion
});
it("reports a stopped native recorder with no URI as failed and allows the next recording", async () => {
  const root = await render(<Consumer />); await act(async () => { await latest.start(); await latest.stop(); });
  expect(latest.state).toBe("stopped"); expect(latest.error).toBe(copy.failed); expect(latest.take).toBeNull();
  await start(); await act(async () => { await latest.stop(); }); expect(latest.take?.uri).toBe(uri); expect(latest.error).toBeNull();
  await act(async () => root.unmount()); await flush();

  // BEGIN public exported-hook layout admission
  const layoutUri = `${files.cacheDirectory}layout-start-public-recorder.m4a`;
  const previousPermission = AudioModule.requestRecordingPermissionsAsync.getMockImplementation();
  let releaseLayoutPermission!: () => void;
  const layoutPermission = new Promise<void>(resolve => { releaseLayoutPermission = resolve; });
  let layoutRecorder: ReturnType<typeof useVoiceRecorder> | undefined;
  let layoutStarting: Promise<void> | undefined;
  let layoutRoot: ReactTestRenderer.ReactTestRenderer | undefined;
  function LayoutStartConsumer() {
    const current = useVoiceRecorder(copy);
    layoutRecorder = current;
    React.useLayoutEffect(() => {
      const pending = current.start();
      layoutStarting = pending;
      void pending.catch(() => {});
    }, [current.start]);
    return null;
  }
  AudioModule.requestRecordingPermissionsAsync.mockImplementation(async () => {
    await layoutPermission;
    return { granted: true };
  });
  try {
    files.__seedFile(layoutUri, "bGF5b3V0LXN0YXJ0"); fakeRecorderStatus.url = layoutUri;
    await act(async () => { layoutRoot = ReactTestRenderer.create(<LayoutStartConsumer />); });
    await act(async () => { releaseLayoutPermission(); if (layoutStarting) await layoutStarting; });
    expect(layoutRecorder?.state, "A recorder started from a public layout effect reaches recording").toBe("recording");
  } finally {
    releaseLayoutPermission();
    try { if (layoutStarting) await layoutStarting; }
    finally {
      try { await act(async () => { layoutRecorder?.reset(); }); }
      finally {
        try { await act(async () => { layoutRoot?.unmount(); }); }
        finally {
          try { await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); }); }
          finally {
            if (previousPermission) AudioModule.requestRecordingPermissionsAsync.mockImplementation(previousPermission);
            else AudioModule.requestRecordingPermissionsAsync.mockReset();
          }
        }
      }
    }
  }
  // END public exported-hook layout admission
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
  // BEGIN public confirmed-absent take cleanup retirement
  const normalPrepare = recorderControls.prepareToRecordAsync.getMockImplementation()!;
  const normalDelete = files.deleteAsync.getMockImplementation()!;
  const normalRelease = recorderControls.release.getMockImplementation()!;
  const freshUris = ["a", "b", "c", "d"].map(name => `${files.cacheDirectory}retired-take-${name}.m4a`);
  const recordedBytes = "cmVjb3JkZWQgc3BlZWNo";
  let auditWindow = false, obsoleteARequested = false, retiredAUri: string | null = null;
  let root: ReactTestRenderer.ReactTestRenderer | undefined, mounted = false;
  let didRelease!: () => void;
  const nativeReleased = new Promise<void>(resolve => { didRelease = resolve; });
  const publicPorts: Promise<void>[] = [];
  const ownPublicPort = (pending: Promise<void>): Promise<void> => {
    publicPorts.push(pending.then(() => undefined, () => undefined));
    return pending;
  };
  recorderControls.prepareToRecordAsync.mockImplementation(async options => {
    await normalPrepare(options);
    const freshUri = freshUris.shift();
    if (!freshUri) throw new Error("No fresh public take fixture remains");
    fakeRecorderStatus.url = freshUri;
    files.__seedFile(freshUri, recordedBytes);
  });
  files.deleteAsync.mockImplementation((path, options) => {
    if (auditWindow && path === retiredAUri) obsoleteARequested = true;
    return normalDelete(path, options);
  });
  recorderControls.release.mockImplementation(() => {
    try { return normalRelease(); }
    finally { didRelease(); }
  });
  try {
    await act(async () => { root = ReactTestRenderer.create(<Consumer />); });
    mounted = true;
    await act(async () => { await ownPublicPort(latest.start()); });
    expect(latest.state).toBe("recording");
    await act(async () => { await ownPublicPort(latest.stop()); });
    const completedA = latest.take;
    expect(completedA?.base64).toBe(recordedBytes);
    if (!completedA) throw new Error("The first public recording did not finish");
    retiredAUri = completedA.uri;
    expect(files.__hasFile(retiredAUri)).toBe(true);
    await ownPublicPort(discardTakeFile(completedA));
    expect(files.__hasFile(retiredAUri)).toBe(false);
    await act(async () => { latest.reset(); });

    await act(async () => { await ownPublicPort(latest.start()); });
    expect(latest.state).toBe("recording");
    await act(async () => { await ownPublicPort(latest.stop()); });
    const completedB = latest.take;
    expect(completedB?.base64).toBe(recordedBytes);
    if (!completedB) throw new Error("The second public recording did not finish");
    expect(completedB.uri).not.toBe(retiredAUri);
    expect(files.__hasFile(completedB.uri)).toBe(true);
    await ownPublicPort(discardTakeFile(completedB));
    expect(files.__hasFile(completedB.uri)).toBe(false);
    await act(async () => { latest.reset(); });

    await act(async () => { await ownPublicPort(latest.start()); });
    expect(latest.state).toBe("recording");
    expect(latest.take).toBeNull();
    auditWindow = true;
    await act(async () => { await ownPublicPort(latest.stop()); });
    const completedC = latest.take;
    expect(completedC?.base64).toBe(recordedBytes);
    if (!completedC) throw new Error("The third public recording did not finish");
    expect(completedC.uri).not.toBe(retiredAUri);
    expect(completedC.uri).not.toBe(completedB.uri);
    expect(files.__hasFile(completedC.uri)).toBe(true);
    await ownPublicPort(discardTakeFile(completedC));
    expect(files.__hasFile(completedC.uri)).toBe(false);
    await act(async () => { latest.reset(); });
    await act(async () => { await ownPublicPort(latest.start()); });
    expect(latest.state).toBe("recording");
    expect(latest.take).toBeNull();
    auditWindow = false;
    await act(async () => { await ownPublicPort(latest.stop()); });
    const completedD = latest.take;
    expect(completedD?.base64).toBe(recordedBytes);
    if (!completedD) throw new Error("The fourth public recording did not finish");
    expect(completedD.uri).not.toBe(retiredAUri);
    expect(completedD.uri).not.toBe(completedC.uri);
    expect(files.__hasFile(completedD.uri)).toBe(true);
    expect(files.__hasFile(retiredAUri)).toBe(false);
    expect(obsoleteARequested, "confirmed-absent earlier take must retire its cleanup obligation").toBe(false);
  } finally {
    auditWindow = false;
    try {
      await Promise.allSettled(publicPorts);
      if (root) await act(async () => { root!.unmount(); });
      if (mounted) await nativeReleased;
    } finally {
      try { await new Promise<void>(resolve => setTimeout(resolve, 0)); }
      finally {
        recorderControls.prepareToRecordAsync.mockImplementation(normalPrepare);
        files.deleteAsync.mockImplementation(normalDelete);
        recorderControls.release.mockImplementation(normalRelease);
      }
    }
  }
  // END public confirmed-absent take cleanup retirement
});

it("an idle stop does not manufacture a stopped take or an error", async () => {
  const root = await render(<Consumer />); await act(async () => { await latest.stop(); });
  expect(latest.state).toBe("idle"); expect(latest.error).toBeNull(); expect(latest.take).toBeNull(); await act(async () => root.unmount()); await flush();
  // BEGIN public cancelled-stop settlement postfix
  {
    let cancelledRoot: ReactTestRenderer.ReactTestRenderer | undefined;
    let cancelledOperation: Promise<void> | undefined, observedOperation: Promise<void> | undefined;
    let heldNativeOperation: Promise<void> | undefined;
    let releaseCancellation!: () => void, reachedCancellation!: () => void;
    const cancellationGate = new Promise<void>(resolve => { releaseCancellation = resolve; });
    const cancellationEntered = new Promise<void>(resolve => { reachedCancellation = resolve; });
    const delegatedNativeOperation = recorderControls.stop.getMockImplementation()!;
    let cancelledSettled = false;
    let cancelledFailure: unknown = null;
    try {
      await act(async () => { cancelledRoot = ReactTestRenderer.create(<Consumer />); });
      files.__seedFile(uri, "cmVjb3JkZWQgc3BlZWNo"); fakeRecorderStatus.url = uri;
      await act(async () => { await latest.start(); });
      recorderControls.stop.mockImplementationOnce((...args) => {
        heldNativeOperation = (async () => {
          reachedCancellation();
          await cancellationGate;
          await delegatedNativeOperation(...args);
        })();
        return heldNativeOperation;
      });
      await act(async () => {
        cancelledOperation = latest.stop();
        observedOperation = cancelledOperation.then(
          () => { cancelledSettled = true; },
          error => { cancelledFailure = error; cancelledSettled = true; },
        );
        latest.reset();
        await cancellationEntered;
      });
      expect(cancelledSettled, "A cancelled stop settles independently of held reset cleanup").toBe(true);
      expect(cancelledFailure, "Reset cancellation fulfills the exported stop Promise").toBeNull();
    } finally {
      releaseCancellation();
      try {
        await act(async () => {
          if (cancelledOperation) await cancelledOperation;
          if (observedOperation) await observedOperation;
          if (heldNativeOperation) await heldNativeOperation;
        });
      } finally {
        try { if (cancelledRoot) await act(async () => cancelledRoot!.unmount()); }
        finally {
          try { await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); }); }
          finally { recorderControls.stop.mockImplementation(delegatedNativeOperation); }
        }
      }
    }
  }
  // END public cancelled-stop settlement postfix

});
it("an already recording start preserves the native file and original elapsed duration", async () => {
  const root = await render(<Consumer />); await start(); vi.setSystemTime(new Date("2026-10-06T04:00:03Z"));
  await act(async () => { await latest.start(); }); expect(files.__hasFile(uri)).toBe(true); expect(latest.state).toBe("recording");
  await act(async () => { await latest.stop(); }); expect(latest.take?.durationSeconds).toBe(3); expect(latest.error).toBeNull();
  await act(async () => root.unmount()); await flush();
  // BEGIN public idle-native-reset prepared-file postfix
  {
    // A successful installed iOS media reset prepares a file while this
    // shared recorder is registered and idle. This models that result;
    // a constructor URL alone is not treated as an existing file.
    const idlePreparedUri = `${files.cacheDirectory}idle-native-reset-prepared-file.m4a`;
    const nextPreparedUri = `${files.cacheDirectory}next-explicitly-prepared-file.m4a`;
    let idleResetRoot: ReactTestRenderer.ReactTestRenderer | undefined;
    let committedIdleMount = false, observedIdleDisposal = false;
    let pendingIdleStart: Promise<void> | undefined;
    const observedNativePorts: Promise<void>[] = [];
    let acknowledgeIdleRelease!: () => void;
    const idleReleaseDone = new Promise<void>(resolve => { acknowledgeIdleRelease = resolve; });
    const delegatedPrepare = recorderControls.prepareToRecordAsync.getMockImplementation()!;
    const delegatedStop = recorderControls.stop.getMockImplementation()!;
    const delegatedRelease = recorderControls.release.getMockImplementation()!;
    try {
      await act(async () => { idleResetRoot = ReactTestRenderer.create(<Consumer />); });
      committedIdleMount = true;
      await files.writeAsStringAsync(idlePreparedUri, "c3VjY2Vzc2Z1bC1pZGxlLXByZXBhcmF0aW9u");
      Object.assign(fakeRecorderStatus, { url: idlePreparedUri, canRecord: true, isRecording: false, mediaServicesDidReset: true });
      recorderControls.prepareToRecordAsync.mockImplementationOnce((...args) => {
        const pending = (async () => {
          await delegatedPrepare(...args);
          await files.writeAsStringAsync(nextPreparedUri, "c3VjY2Vzc2Z1bC1uZXh0LXByZXBhcmF0aW9u");
          Object.assign(fakeRecorderStatus, { url: nextPreparedUri, canRecord: true, isRecording: false, mediaServicesDidReset: false });
        })();
        observedNativePorts.push(pending); void pending.catch(() => {});
        return pending;
      });
      await act(async () => {
        pendingIdleStart = latest.start();
        void pendingIdleStart.catch(() => {});
        await pendingIdleStart;
      });
      recorderControls.stop.mockImplementationOnce((...args) => {
        const pending = (async () => { observedIdleDisposal = true; await delegatedStop(...args); })();
        observedNativePorts.push(pending); void pending.catch(() => {});
        return pending;
      });
      recorderControls.release.mockImplementationOnce(() => {
        try { delegatedRelease(); } finally { acknowledgeIdleRelease(); }
      });
      await act(async () => { idleResetRoot!.unmount(); idleResetRoot = undefined; });
      await idleReleaseDone;
      let idlePreparedFileStillPresent: boolean;
      try { await files.readAsStringAsync(idlePreparedUri); idlePreparedFileStillPresent = true; }
      catch (error) {
        if (!(error instanceof Error) || error.message !== "file not found") throw error;
        idlePreparedFileStillPresent = false;
      }
      expect(idlePreparedFileStillPresent, "Disposal removes an idle native-reset file before explicit preparation replaces its URI").toBe(false);
    } finally {
      try {
        if (pendingIdleStart) await Promise.allSettled([pendingIdleStart]);
      } finally {
        try {
          if (idleResetRoot) await act(async () => { idleResetRoot!.unmount(); idleResetRoot = undefined; });
          await act(async () => {
            await Promise.allSettled(observedNativePorts);
            if (committedIdleMount && observedIdleDisposal) await idleReleaseDone;
          });
        } finally {
          try { await new Promise<void>(resolve => setTimeout(resolve, 0)); }
          finally {
            recorderControls.prepareToRecordAsync.mockImplementation(delegatedPrepare);
            recorderControls.stop.mockImplementation(delegatedStop);
            recorderControls.release.mockImplementation(delegatedRelease);
          }
        }
      }
    }
  }
  // END public idle-native-reset prepared-file postfix

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
  // BEGIN resource metadata native disposal admission
  await entered;
  // END resource metadata native disposal admission
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
  // BEGIN public cancelled-start settlement postfix
  {
    let cancelledRoot: ReactTestRenderer.ReactTestRenderer | undefined;
    let cancelledOperation: Promise<void> | undefined, observedOperation: Promise<void> | undefined;
    let heldNativeOperation: Promise<void> | undefined;
    let releaseCancellation!: () => void, reachedCancellation!: () => void;
    const cancellationGate = new Promise<void>(resolve => { releaseCancellation = resolve; });
    const cancellationEntered = new Promise<void>(resolve => { reachedCancellation = resolve; });
    const delegatedNativeOperation = files.deleteAsync.getMockImplementation()!;
    let cancelledSettled = false;
    let cancelledFailure: unknown = null;
    try {
      await act(async () => { cancelledRoot = ReactTestRenderer.create(<Consumer />); });
      files.__seedFile(uri, "cmVjb3JkZWQgc3BlZWNo"); fakeRecorderStatus.url = uri;
      await act(async () => { await latest.start(); });
    await act(async () => { await latest.stop(); });
    expect(latest.take?.uri).toBe(uri);
      files.deleteAsync.mockImplementationOnce((...args) => {
        heldNativeOperation = (async () => {
          reachedCancellation();
          await cancellationGate;
          await delegatedNativeOperation(...args);
        })();
        return heldNativeOperation;
      });
      await act(async () => {
        cancelledOperation = latest.start();
        observedOperation = cancelledOperation.then(
          () => { cancelledSettled = true; },
          error => { cancelledFailure = error; cancelledSettled = true; },
        );
        latest.reset();
        await cancellationEntered;
      });
      expect(cancelledSettled, "A cancelled start settles independently of held reset file deletion").toBe(true);
      expect(cancelledFailure, "Reset cancellation fulfills the exported start Promise").toBeNull();
    } finally {
      releaseCancellation();
      try {
        await act(async () => {
          if (cancelledOperation) await cancelledOperation;
          if (observedOperation) await observedOperation;
          if (heldNativeOperation) await heldNativeOperation;
        });
      } finally {
        try { if (cancelledRoot) await act(async () => cancelledRoot!.unmount()); }
        finally {
          try { await act(async () => { await new Promise<void>(resolve => setTimeout(resolve, 0)); }); }
          finally { files.deleteAsync.mockImplementation(delegatedNativeOperation); }
        }
      }
    }
  }
  // END public cancelled-start settlement postfix

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


  // Model the installed iOS media-services-reset producer while disposal's
  // ordinary native stop is pending. The oracle reads the file service;
  // it does not inspect URI ownership bookkeeping or callback counts.
  const beforeResetUri = `${files.cacheDirectory}before-native-media-reset.m4a`;
  const afterResetUri = `${files.cacheDirectory}after-native-media-reset.m4a`;
  let resetRoot: ReactTestRenderer.ReactTestRenderer | undefined;
  let mountedForReset = false, observedDisposal = false;
  let releaseNativeStop!: () => void, enteredNativeStop!: () => void, nativeReleased!: () => void;
  const nativeStopGate = new Promise<void>(resolve => { releaseNativeStop = resolve; });
  const nativeStopEntered = new Promise<void>(resolve => { enteredNativeStop = resolve; });
  const nativeReleaseDone = new Promise<void>(resolve => { nativeReleased = resolve; });
  const nativePorts: Promise<void>[] = [];
  const originalStop = recorderControls.stop.getMockImplementation()!;
  const originalRelease = recorderControls.release.getMockImplementation()!;
  try {
    await files.writeAsStringAsync(beforeResetUri, "b2xkLW5hdGl2ZS10YWtl");
    fakeRecorderStatus.url = beforeResetUri;
    await act(async () => { resetRoot = ReactTestRenderer.create(<Consumer />); });
    mountedForReset = true;
    await act(async () => { await latest.start(); });
    recorderControls.stop.mockImplementationOnce(() => {
      const pending = (async () => { observedDisposal = true; enteredNativeStop(); await nativeStopGate; await originalStop(); })();
      nativePorts.push(pending); void pending.catch(() => {});
      return pending;
    });
    recorderControls.release.mockImplementationOnce(() => { originalRelease(); nativeReleased(); });
    await act(async () => { resetRoot!.unmount(); resetRoot = undefined; });
    await nativeStopEntered;
    // Actual native reset calls prepare(currentOptions), which allocates a
    // distinct URI/file outside the JavaScript lane. This typed service
    // model publishes that result before the held stop Promise returns.
    await files.writeAsStringAsync(afterResetUri, "bmV3LW5hdGl2ZS1wcmVwYXJlZC1maWxl");
    Object.assign(fakeRecorderStatus, { url: afterResetUri, canRecord: true, isRecording: false, mediaServicesDidReset: true });
    await act(async () => { releaseNativeStop(); await Promise.all(nativePorts); await nativeReleaseDone; });
    let preparedFileStillPresent: boolean;
    try { await files.readAsStringAsync(afterResetUri); preparedFileStillPresent = true; }
    catch (error) {
      if (!(error instanceof Error) || error.message !== "file not found") throw error;
      preparedFileStillPresent = false;
    }
    expect(preparedFileStillPresent, "Disposal removes a file prepared by native media reset before stop completion").toBe(false);
  } finally {
    releaseNativeStop();
    try {
      if (resetRoot) await act(async () => { resetRoot!.unmount(); resetRoot = undefined; });
      await act(async () => { await Promise.allSettled(nativePorts); if (mountedForReset && observedDisposal) await nativeReleaseDone; });
    } finally {
      try { await new Promise<void>(resolve => setTimeout(resolve, 0)); }
      finally {
        recorderControls.stop.mockImplementation(originalStop);
        recorderControls.release.mockImplementation(originalRelease);
      }
    }
  }
});
