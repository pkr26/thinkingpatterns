/** Node-test mock of expo-audio (VOICE_PLAN 2026-09-29): mirrors the REAL
 *  API names the production code touches — AudioModule.requestRecording-
 *  PermissionsAsync, useAudioRecorder's prepareToRecordAsync/record/stop,
 *  useAudioRecorderState, createAudioPlayer. The recorder is a stable fake
 *  whose getStatus() reads a module-level status object tests shape per
 *  case (url, durationMillis, metering) — the same seam the real hook
 *  polls. */
import { vi } from "vitest";

export type FakeRecorderStatus = {
  canRecord: boolean;
  isRecording: boolean;
  durationMillis: number;
  mediaServicesDidReset: boolean;
  url: string | null;
  metering?: number;
};

/** Shared, mutable recorder status — tests set fields BEFORE driving
 *  start/stop so stop() reads the honest duration/uri through the hook. */
export const fakeRecorderStatus: FakeRecorderStatus = {
  canRecord: false,
  isRecording: false,
  durationMillis: 0,
  mediaServicesDidReset: false,
  url: null,
};

/** Shared recorder-method mocks: one recorder lives at a time in tests, so
 *  every instance the hook returns uses these EXACT vi.fn's — tests can
 *  mockRejectedValueOnce (e.g. prepareToRecordAsync failure) on them. */
export const recorderControls = {
  prepareToRecordAsync: vi.fn(async (_options?: unknown): Promise<void> => {
    fakeRecorderStatus.canRecord = true;
  }),
  record: vi.fn((): void => {
    fakeRecorderStatus.isRecording = true;
  }),
  stop: vi.fn(async (): Promise<void> => {
    fakeRecorderStatus.isRecording = false;
  }),
  release: vi.fn((): void => {}),
};

export type FakeRecorder = typeof recorderControls & {
  uri: string | null;
  getStatus: () => FakeRecorderStatus;
};

export const useAudioRecorder = vi.fn((): FakeRecorder => ({
  ...recorderControls,
  get uri(): string | null {
    return fakeRecorderStatus.url;
  },
  getStatus: (): FakeRecorderStatus => ({ ...fakeRecorderStatus }),
}));

/** The real hook polls recorder.getStatus() on an interval; the mock reads
 *  it on every render instead — same contract (current RecorderState),
 *  deterministic under node without timer control. */
export const useAudioRecorderState = vi.fn((recorder: FakeRecorder): FakeRecorderStatus =>
  recorder.getStatus(),
);

export const AudioModule = {
  AudioRecorder: vi.fn(function AudioRecorder(_options: unknown): FakeRecorder {
    return {
      ...recorderControls,
      get uri(): string | null { return fakeRecorderStatus.url; },
      getStatus: (): FakeRecorderStatus => ({ ...fakeRecorderStatus }),
    };
  }),
  requestRecordingPermissionsAsync: vi.fn(async () => ({ granted: true })),
  setAudioModeAsync: vi.fn(async () => undefined),
};

/** Shared player-method mocks (createAudioPlayer consumers: HistoryScreen
 *  playback). Tests flip play to throw for the failure path. */
export const playerControls = {
  play: vi.fn((): void => {}),
  release: vi.fn((): void => {}),
};

export const createAudioPlayer = vi.fn(() => ({ ...playerControls }));

/** Reset the module state between tests in a file (mock history + status). */
export function __resetAudioMock(): void {
  fakeRecorderStatus.canRecord = false;
  fakeRecorderStatus.isRecording = false;
  fakeRecorderStatus.durationMillis = 0;
  fakeRecorderStatus.mediaServicesDidReset = false;
  fakeRecorderStatus.url = null;
  delete fakeRecorderStatus.metering;
  for (const mock of [
    ...Object.values(recorderControls),
    ...Object.values(playerControls),
    useAudioRecorder,
    useAudioRecorderState,
    AudioModule.requestRecordingPermissionsAsync,
    AudioModule.AudioRecorder,
    AudioModule.setAudioModeAsync,
    createAudioPlayer,
  ]) mock.mockClear();
  recorderControls.prepareToRecordAsync.mockImplementation(async () => {
    fakeRecorderStatus.canRecord = true;
  });
  recorderControls.record.mockImplementation(() => {
    fakeRecorderStatus.isRecording = true;
  });
  recorderControls.stop.mockImplementation(async () => {
    fakeRecorderStatus.isRecording = false;
  });
  recorderControls.release.mockImplementation(() => {});
  playerControls.play.mockImplementation(() => {});
  playerControls.release.mockImplementation(() => {});
  AudioModule.requestRecordingPermissionsAsync.mockImplementation(async () => ({ granted: true }));
  AudioModule.setAudioModeAsync.mockImplementation(async () => undefined);
}
