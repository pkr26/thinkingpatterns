/**
 * Microphone recording through expo-audio.
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
import { Platform } from "react-native";
import {
  AudioModule,
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
  // Own the native object's release: Expo's convenience hook releases on
  // unmount before an outstanding prepare/stop can reveal its file URI.
  // Supply the platform-specific options expected by the native constructor.
  const recorderRef = useRef<InstanceType<typeof AudioModule.AudioRecorder> | null>(null);
  if (recorderRef.current === null) {
    recorderRef.current = new AudioModule.AudioRecorder({
      ...RECORDING_OPTIONS,
      ...(Platform.OS === "ios" ? RECORDING_OPTIONS.ios : RECORDING_OPTIONS.android),
    });
  }
  const recorder = recorderRef.current;
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
  // CURRENT recorder status, not the first render's snapshot.
  const statusRef = useRef(recorderStatus);
  statusRef.current = recorderStatus;
  const mounted = useRef(true);
  const generation = useRef(0);
  const phase = useRef<"idle" | "starting" | "recording" | "stopping" | "finished">("idle");
  const ownedUris = useRef(new Set<string>());
  const lane = useRef<Promise<unknown>>(Promise.resolve());
  const stopping = useRef<Promise<void> | null>(null);
  const stringsRef = useRef(strings); stringsRef.current = strings;

  // Native prepare/stop/read and disposal share one lane. A new take cannot
  // start until cancellation has drained the previous native operation.
  const enqueue = useCallback((run: () => Promise<void>): Promise<void> => {
    const pending = lane.current.then(run, run);
    lane.current = pending.catch(() => {});
    return pending;
  }, []);
  const rememberUri = useCallback((): string | null => {
    let uri: string | null = null;
    try { uri = recorder.uri || recorder.getStatus().url || null; } catch { /* already released */ }
    if (uri) ownedUris.current.add(uri);
    return uri;
  }, [recorder]);
  const scrub = useCallback(async (): Promise<void> => {
    for (const uri of [...ownedUris.current]) {
      try { await FileSystem.deleteAsync(uri, { idempotent: true }); ownedUris.current.delete(uri); }
      catch { /* Retain ownership for the next cleanup; cold start also scrubs. */ }
    }
  }, []);
  const stopNative = useCallback(async (): Promise<void> => {
    rememberUri();
    try { await recorder.stop(); } catch { /* already stopped or not prepared */ }
    rememberUri();
  }, [recorder, rememberUri]);

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

  const stop = useCallback((): Promise<void> => {
    if (phase.current === "stopping") return stopping.current ?? Promise.resolve();
    if (!mounted.current || (phase.current !== "recording" && phase.current !== "starting")) return Promise.resolve();
    const admitted = generation.current;
    phase.current = "stopping";
    clearTimer();
    const owns = () => mounted.current && admitted === generation.current;
    const pending = enqueue(async () => {
      if (!owns()) return;
      clearTimer();
      await stopNative();
      if (!owns()) { await scrub(); return; }
      const status = statusRef.current;
      const uri = rememberUri();
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
        phase.current = "finished";
        setError(stringsRef.current.failed);
        return;
      }
      try {
        const base64 = await FileSystem.readAsStringAsync(uri, {
          encoding: FileSystem.EncodingType.Base64,
        });
        if (!owns()) { await scrub(); return; }
        const finished: VoiceTake = { uri, base64, mime: "audio/m4a", durationSeconds };
        phase.current = "finished";
        setTake(finished);
      } catch {
        // An unreadable take is unusable — its cache file must not survive
        // either (unmount would not know the uri: no take was recorded).
        await scrub();
        if (owns()) { phase.current = "finished"; setError(stringsRef.current.failed); }
      }
    });
    stopping.current = pending;
    return pending;
  }, [clearTimer, enqueue, rememberUri, scrub, stopNative]);

  const start = useCallback(async (): Promise<void> => {
    if (!mounted.current || phase.current === "starting" || phase.current === "recording" || phase.current === "stopping") return;
    const admitted = ++generation.current;
    const owns = () => mounted.current && admitted === generation.current;
    phase.current = "starting";
    setError(null);
    setTake(null);
    await enqueue(async () => {
      if (!owns()) return;
      // Starting over also owns deletion of the preceding finished take.
      await scrub();
      if (!owns()) return;
      try {
        const permission = await AudioModule.requestRecordingPermissionsAsync();
        if (!owns()) return;
        if (!permission?.granted) {
          phase.current = "idle";
          setError(stringsRef.current.permissionDenied);
          return;
        }
        await AudioModule.setAudioModeAsync({
          allowsRecording: true,
          playsInSilentMode: true,
          shouldPlayInBackground: false,
        });
        if (!owns()) return;
        // iOS startRecording guards on .prepared and Android record()
        // no-ops while unprepared — the native take only exists after this.
        // iOS reuses the previous AVAudioRecorder URL when options are
        // omitted. Each take needs a fresh file identity: EntryScreen
        // deduplicates transcription and attachment ownership by URI.
        rememberUri();
        await recorder.prepareToRecordAsync(RECORDING_OPTIONS);
        rememberUri();
        if (!owns()) { await stopNative(); await scrub(); return; }
        startedAtRef.current = Date.now();
        setElapsed(0);
        recorder.record();
        rememberUri();
        phase.current = "recording";
        setState("recording");
        clearTimer();
        timerRef.current = setInterval(() => {
          const seconds = Math.floor((Date.now() - startedAtRef.current) / 1000);
          setElapsed(seconds);
          if (seconds >= MAX_RECORDING_SECONDS) void stop();
        }, 500);
      } catch {
        rememberUri(); await stopNative(); await scrub();
        if (owns()) { phase.current = "idle"; setError(stringsRef.current.failed); setState("idle"); }
      }
    });
  }, [clearTimer, enqueue, recorder, rememberUri, scrub, stop, stopNative]);

  const reset = useCallback((): void => {
    generation.current++;
    phase.current = "idle";
    clearTimer();
    rememberUri();
    void enqueue(async () => { await stopNative(); await scrub(); });
    if (mounted.current) {
      setTake(null);
      setElapsed(0);
      setError(null);
      setState("idle");
    }
  }, [clearTimer, enqueue, rememberUri, scrub, stopNative]);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      generation.current++;
      phase.current = "idle";
      clearTimer();
      // Capture now and after queued work settles, while the native object
      // is still alive. Do not release it before a late prepare exposes URI.
      rememberUri();
      void enqueue(async () => {
        await stopNative(); await scrub();
        if (!mounted.current) recorder.release();
      });
    };
  }, [clearTimer, enqueue, recorder, rememberUri, scrub, stopNative]);

  return { state, elapsedSeconds, level, error, take, start, stop, reset };
}
