/**
 * The microphone recorder (VOICE_PLAN P4, 2026-09-29) over expo-audio.
 *
 * Records m4a/AAC, 16 kHz mono ~24 kbps — the compressed speech profile
 * the plan pins (shared/audio_vectors.json) — with a hard 5-minute
 * auto-stop (server bound 310 s) and live metering for the level dot.
 * The take is read to base64 through expo-file-system for the
 * transcription upload; nothing is written anywhere else, and the cache
 * file is deleted once the entry is saved or the take discarded.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import { AudioModule, useAudioRecorder } from "expo-audio";
import * as FileSystem from "expo-file-system/legacy";

export const MAX_RECORDING_SECONDS = 300;

/** Compressed speech: ~900 KB for a full 5-minute take (the plan's
 * default_codecs contract). */
const RECORDING_OPTIONS = {
  android: {
    extension: ".m4a",
    outputFormat: 2, // MPEG_4
    audioEncoder: 3, // AAC
    sampleRate: 16000,
    numberOfChannels: 1,
    bitRate: 24000,
  },
  ios: {
    extension: ".m4a",
    outputFormat: "lpcm" as unknown as number, // set below via record(); expo normalizes
    audioQuality: 96, // Medium
    sampleRate: 16000,
    numberOfChannels: 1,
    bitRate: 24000,
    linearPCMBitDepth: 16,
    linearPCMIsBigEndian: false,
    linearPCMIsFloat: false,
  },
  web: { mimeType: "audio/mp4", bitsPerSecond: 24000 },
  isMeteringEnabled: true,
} as const;

export interface VoiceTake {
  uri: string;
  base64: string;
  mime: string;
  durationSeconds: number;
}

export type VoiceRecorderState = "idle" | "recording" | "stopped" | "unsupported";

export interface UseVoiceRecorder {
  state: VoiceRecorderState;
  elapsedSeconds: number;
  /** 0..1 display level from recorder metering (0 while idle). */
  level: number;
  error: string | null;
  take: VoiceTake | null;
  start: () => Promise<void>;
  stop: () => Promise<void>;
  reset: () => void;
}

/** Delete the cache file of a take that will not be kept. */
export async function discardTakeFile(take: VoiceTake | null): Promise<void> {
  if (!take) return;
  try {
    await FileSystem.deleteAsync(take.uri, { idempotent: true });
  } catch {
    // best-effort: the OS reclaims the cache dir regardless
  }
}

export function useVoiceRecorder(strings: {
  unsupported: string;
  permissionDenied: string;
  failed: string;
}): UseVoiceRecorder {
  const recorder = useAudioRecorder(RECORDING_OPTIONS as never);
  const [state, setState] = useState<VoiceRecorderState>("idle");
  const [elapsedSeconds, setElapsed] = useState(0);
  const [level, setLevel] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [take, setTake] = useState<VoiceTake | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startedAtRef = useRef(0);
  const activeTakeRef = useRef<VoiceTake | null>(null);

  const clearTimer = useCallback((): void => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  useEffect(() => {
    // Mirror expo-audio's metering into a 0..1 display level (dBFS −60..0).
    const metering = (recorder as { metering?: number | null }).metering;
    if (typeof metering === "number" && state === "recording") {
      setLevel(Math.min(1, Math.max(0, (metering + 60) / 60)));
    } else if (state !== "recording") {
      setLevel(0);
    }
  }, [recorder, state]);

  const stop = useCallback(async (): Promise<void> => {
    clearTimer();
    const durationSeconds = Math.max(1, Math.round((Date.now() - startedAtRef.current) / 1000));
    try {
      await recorder.stop();
    } catch {
      // stop on an already-stopped recorder is not fatal
    }
    const uri = (recorder as { uri?: string | null }).uri ?? activeTakeRef.current?.uri ?? null;
    setState("stopped");
    if (!uri) {
      setError(strings.failed);
      return;
    }
    try {
      const base64 = await FileSystem.readAsStringAsync(uri, {
        encoding: FileSystem.EncodingType.Base64,
      });
      setTake({ uri, base64, mime: "audio/m4a", durationSeconds });
    } catch {
      setError(strings.failed);
    }
  }, [clearTimer, recorder, strings.failed]);

  const start = useCallback(async (): Promise<void> => {
    setError(null);
    setTake(null);
    try {
      const permission = await AudioModule.requestRecordingPermissionsAsync();
      if (!permission?.granted) {
        setError(strings.permissionDenied);
        return;
      }
      await AudioModule.setAudioModeAsync({
        allowsRecording: true,
        playsInSilentMode: true,
        shouldPlayInBackground: false,
      });
      startedAtRef.current = Date.now();
      setElapsed(0);
      recorder.record();
      setState("recording");
      clearTimer();
      timerRef.current = setInterval(() => {
        const seconds = Math.floor((Date.now() - startedAtRef.current) / 1000);
        setElapsed(seconds);
        if (seconds >= MAX_RECORDING_SECONDS) void stop();
      }, 500);
    } catch {
      setError(strings.failed);
      setState("idle");
    }
  }, [clearTimer, recorder, stop, strings]);

  const reset = useCallback((): void => {
    clearTimer();
    void discardTakeFile(take);
    setTake(null);
    setElapsed(0);
    setError(null);
    setState("idle");
  }, [clearTimer, take]);

  useEffect(() => {
    // Unmount cleans the timer; the TAKE file's life is the caller's
    // (EntryScreen discards it on save/discard).
    return () => clearTimer();
  }, [clearTimer]);

  return { state, elapsedSeconds, level, error, take, start, stop, reset };
}
