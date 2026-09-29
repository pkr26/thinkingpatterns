/** Node-test mock of expo-audio (VOICE_PLAN 2026-09-29): the recorder hook
 *  is inert outside a device — tests drive the pure helpers only. */
import { vi } from "vitest";

export const AudioModule = {
  requestRecorderPermissionsAsync: vi.fn(async () => ({ granted: true })),
  setAudioModeAsync: vi.fn(async () => undefined),
};

export const useAudioRecorder = vi.fn(() => ({
  record: vi.fn(),
  stop: vi.fn(async () => undefined),
  uri: null,
  metering: null,
}));

export const createAudioPlayer = vi.fn(() => ({ play: vi.fn(), release: vi.fn() }));
