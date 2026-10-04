/**
 * The microphone recorder (VOICE_PLAN P4, 2026-09-29) over expo-audio.
 *
 * Records m4a/AAC, 16 kHz mono ~24 kbps — the compressed speech profile
 * the plan pins (shared/audio_vectors.json) — with a hard 5-minute
 * auto-stop (server bound 310 s) and live metering for the level dot.
 * The take is read to base64 through expo-file-system for the
 * transcription upload; nothing is written anywhere else, and the cache
 * file is deleted once the entry is saved or the take discarded, and again on
 * unmount. A process kill can bypass those callbacks; cold-start, account-
 * erasure, and origin-retirement recovery scrub Expo Audio's cache roots.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import {
  AudioModule,
  useAudioRecorder,
  useAudioRecorderState,
  type RecordingOptions,
} from "expo-audio";
import * as FileSystem from "expo-file-system/legacy";

export const MAX_RECORDING_SECONDS = 300;

/** Compressed speech: ~900 KB for a full 5-minute take (the plan's
 * default_codecs contract). Option shapes are expo-audio 57's
 * (src/Audio.types.ts): Android takes STRING enum values for
 * outputFormat/audioEncoder (numeric constants crash the native
 * EnumTypeConverter), iOS omits outputFormat — the default container for
 * ".m4a" is MPEG4AAC, and LPCM cannot live in an .m4a anyway. 96 is
 * AudioQuality.HIGH (0x60). */
const RECORDING_OPTIONS: RecordingOptions = {
  extension: ".m4a",
  sampleRate: 16000,
  numberOfChannels: 1,
  bitRate: 24000,
  android: {
    extension: ".m4a",
    outputFormat: "mpeg4",
    audioEncoder: "aac",
  },
  ios: {
    extension: ".m4a",
    audioQuality: 96, // AudioQuality.HIGH (0x60)
  },
  web: { mimeType: "audio/mp4", bitsPerSecond: 24000 },
  isMeteringEnabled: true,
};

export interface VoiceTake {
  uri: string;
  base64: string;
  mime: string;
  durationSeconds: number;
}

export type VoiceRecorderState = "idle" | "recording" | "stopped";

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
  permissionDenied: string;
  failed: string;
}): UseVoiceRecorder {
  const recorder = useAudioRecorder(RECORDING_OPTIONS);
  // The real status hook: polls the recorder (duration, metering, url).
  // recorder.metering/duration do NOT exist on the recorder object itself.
  const recorderStatus = useAudioRecorderState(recorder);
  const [state, setState] = useState<VoiceRecorderState>("idle");
  const [elapsedSeconds, setElapsed] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [take, setTake] = useState<VoiceTake | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startedAtRef = useRef(0);
  // Latest-value refs: the auto-stop timer and a late stop() must see the
  // CURRENT recorder status and take, not the first render's snapshot.
  const statusRef = useRef(recorderStatus);
  statusRef.current = recorderStatus;
  const takeRef = useRef<VoiceTake | null>(null);

  const clearTimer = useCallback((): void => {
    if (timerRef.current !== null) {
      clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  /** Metering is dBFS (−60..0 for speech); map to a 0..1 display level. */
  const level =
    state === "recording" && typeof recorderStatus.metering === "number"
      ? Math.min(1, Math.max(0, (recorderStatus.metering + 60) / 60))
      : 0;

  const stop = useCallback(async (): Promise<void> => {
    clearTimer();
    try {
      await recorder.stop();
    } catch {
      // stop on an already-stopped recorder is not fatal
    }
    const status = statusRef.current;
    const uri = status.url ?? (recorder as { uri?: string | null }).uri ?? null;
    setState("stopped");
    // Honest duration first (the recorder's own durationMillis — a
    // backgrounded wall clock keeps ticking and would 422 the take),
    // wall clock only when the recorder never reported one, and the
    // server's 310 s bound is never reachable: clamp to the cap.
    const reportedMs = status.durationMillis;
    const honestMs =
      typeof reportedMs === "number" && Number.isFinite(reportedMs) && reportedMs > 0
        ? reportedMs
        : Date.now() - startedAtRef.current;
    const durationSeconds = Math.min(
      MAX_RECORDING_SECONDS,
      Math.max(1, Math.round(honestMs / 1000)),
    );
    if (!uri) {
      setError(strings.failed);
      return;
    }
    try {
      const base64 = await FileSystem.readAsStringAsync(uri, {
        encoding: FileSystem.EncodingType.Base64,
      });
      const finished: VoiceTake = { uri, base64, mime: "audio/m4a", durationSeconds };
      takeRef.current = finished;
      setTake(finished);
    } catch {
      // An unreadable take is unusable — its cache file must not survive
      // either (unmount would not know the uri: no take was recorded).
      try {
        await FileSystem.deleteAsync(uri, { idempotent: true });
      } catch {
        // best-effort: the OS reclaims the cache dir regardless
      }
      setError(strings.failed);
    }
  }, [clearTimer, recorder, strings.failed]);

  const start = useCallback(async (): Promise<void> => {
    setError(null);
    setTake(null);
    takeRef.current = null;
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
      // iOS startRecording guards on .prepared and Android record()
      // no-ops while unprepared — the native take only exists after this.
      await recorder.prepareToRecordAsync();
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
    void discardTakeFile(takeRef.current);
    takeRef.current = null;
    setTake(null);
    setElapsed(0);
    setError(null);
    setState("idle");
  }, [clearTimer]);

  useEffect(() => {
    // Unmount discards the TAKE file itself (audit M1): the transcript
    // review can outlive the screen (background lock, navigation) and a
    // plaintext recording must not sit in the cache dir meanwhile. A take
    // already consumed by reset()/save is null — nothing to delete.
    return () => {
      clearTimer();
      void discardTakeFile(takeRef.current);
    };
  }, [clearTimer]);

  return { state, elapsedSeconds, level, error, take, start, stop, reset };
}
