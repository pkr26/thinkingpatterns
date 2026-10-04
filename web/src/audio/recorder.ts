/**
 * The microphone recorder (VOICE_PLAN P3, 2026-09-29).
 *
 * MediaRecorder with the browser-format fallback chain pinned in
 * shared/audio_vectors.json: Chrome/Firefox speak webm/opus, Safari only
 * reliably produces mp4/AAC — the FIRST mime isTypeSupported accepts wins,
 * and the file extension is always derived from the ACTUAL winning mime
 * (naming an mp4 ".webm" is the classic Safari recorder bug). Hard
 * 5-minute auto-stop (the plan's recording cap; the server bound is 310 s).
 *
 * The hook owns the MediaStream's lifecycle: stop() and unmount both tear
 * down every track and the recorder; the resulting Blob never touches
 * storage — it lives in memory until the entry is saved (kept ⇒ encrypted
 * and uploaded) or discarded.
 */
// @ts-nocheck

import { useCallback, useEffect, useRef, useState } from "react";

/** Client-side recording cap; the server accepts up to 310 s for clock
 * skew (shared/audio_vectors.json recording_limits). */
export const MAX_RECORDING_SECONDS = 300;

/** The fallback chain, most-preferred first. */
export const RECORDER_MIME_CANDIDATES: readonly string[] = [
  "audio/webm;codecs=opus",
  "audio/webm",
  "audio/ogg;codecs=opus",
  "audio/mp4",
];

/** Strip codec parameters for the wire ("audio/webm;codecs=opus" →
 * "audio/webm") — the server's allowlist matches bare mimes. */
export function normalizeMime(raw: string): string {
  return raw.split(";", 1)[0]!.trim().toLowerCase();
}

/** The extension implied by a normalized mime (server-side table mirrored;
 * pinned by contract tests). */
export function extensionForMime(normalized: string): string {
  switch (normalized) {
    case "audio/webm":
      return ".webm";
    case "audio/ogg":
      return ".ogg";
    case "audio/mpeg":
      return ".mp3";
    case "audio/wav":
      return ".wav";
    default:
      return ".m4a"; // audio/mp4 | audio/m4a | audio/x-m4a
  }
}

export function pickRecorderMime(): string | null {
  if (typeof MediaRecorder === "undefined") return null;
  for (const candidate of RECORDER_MIME_CANDIDATES) {
    try {
      if (MediaRecorder.isTypeSupported(candidate)) return candidate;
    } catch {
      // isTypeSupported itself throwing (exotic embedders): keep walking.
    }
  }
  return null;
}

export type RecorderState = "idle" | "recording" | "stopped" | "unsupported";

export interface Recording {
  blob: Blob;
  /** The FULL mime MediaRecorder reported (may carry codec parameters). */
  mime: string;
  /** The normalized mime for the wire. */
  normalizedMime: string;
  extension: string;
  durationSeconds: number;
}

export interface UseRecorder {
  state: RecorderState;
  elapsedSeconds: number;
  level: number; // 0..1 live input level (0 when idle/unavailable)
  recording: Recording | null;
  error: string | null;
  start: () => Promise<void>;
  stop: () => void;
  reset: () => void;
}

export function useRecorder(i18n: {
  unsupported: string;
  permissionDenied: string;
  failed: string;
}): UseRecorder {
  const [state, setState] = useState<RecorderState>(
    typeof MediaRecorder !== "undefined" ? "idle" : "unsupported",
  );
  const [elapsedSeconds, setElapsed] = useState(0);
  const [level, setLevel] = useState(0);
  const [recording, setRecording] = useState<Recording | null>(null);
  const [error, setError] = useState<string | null>(null);

  const recorderRef = useRef<MediaRecorder | null>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const chunksRef = useRef<BlobPart[]>([]);
  const timerRef = useRef<number | null>(null);
  const analyserRef = useRef<AnalyserNode | null>(null);
  const audioCtxRef = useRef<AudioContext | null>(null);
  const rafRef = useRef<number | null>(null);
  const startedAtRef = useRef<number>(0);
  /** Guard against stop() racing the auto-stop timer. */
  const finishingRef = useRef(false);

  /** Shared resource teardown. `assemble` (the finalize path) leaves the
   *  recorder's onstop/ondataavailable attached — recorder.stop() has
   *  already queued the events that assemble the kept blob, and detaching
   *  them here would lose the take the user asked to KEEP. Every other
   *  caller (reset, unmount) detaches FIRST: stopping the tracks makes the
   *  browser fire the recorder's async stop event, and a discarded take
   *  must stay discarded — reset()/unmount may not resurrect it through a
   *  handler that outlived the decision (audit 2026-09-29 H1). */
  const teardown = useCallback((assemble = false): void => {
    if (timerRef.current !== null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
    if (rafRef.current !== null) {
      window.cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    }
    analyserRef.current = null;
    if (audioCtxRef.current) {
      void audioCtxRef.current.close().catch(() => undefined);
      audioCtxRef.current = null;
    }
    if (!assemble && recorderRef.current) {
      recorderRef.current.onstop = null;
      recorderRef.current.ondataavailable = null;
    }
    if (streamRef.current) {
      for (const track of streamRef.current.getTracks()) track.stop();
      streamRef.current = null;
    }
    recorderRef.current = null;
    setLevel(0);
  }, []);

  const finalize = useCallback((): void => {
    if (finishingRef.current) return;
    finishingRef.current = true;
    const recorder = recorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      try {
        recorder.stop(); // fires onstop → assembles the blob
      } catch {
        // L-6 (audit 2026-09-29): a stop that itself throws must not
        // strand the mic — teardown always runs below.
      }
    }
    teardown(true);
  }, [teardown]);

  // Unmount is a hard teardown: no dangling mic indicator, no rAF loop.
  // The body lives in the CLEANUP (audit 2026-09-29 H1): the effect used
  // to run it at MOUNT with a no-op cleanup, so leaving the view kept the
  // stream and the timers alive.
  useEffect(() => () => {
    const recorder = recorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      recorder.onstop = null;
      recorder.ondataavailable = null;
      try {
        recorder.stop();
      } catch {
        // already inactive racing the unmount
      }
    }
    teardown();
  }, [teardown]);

  const acquisition = useRef(0);
  const pendingAcquisition = useRef(false);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; acquisition.current += 1; pendingAcquisition.current = false; }; }, []);
  const start = useCallback(async (): Promise<void> => {
    // Re-entrancy guard (M-1, audit 2026-09-29): a second press while a
    // recorder or stream is already live would build a SECOND recorder
    // over a second mic hold and orphan the first — bail instead.
    if (!alive.current || pendingAcquisition.current || recorderRef.current !== null || streamRef.current !== null) return;
    setError(null);
    const mime = pickRecorderMime();
    if (typeof MediaRecorder === "undefined" || !navigator.mediaDevices?.getUserMedia || mime === null) {
      setState("unsupported");
      setError(i18n.unsupported);
      return;
    }
    const operation = ++acquisition.current;
    pendingAcquisition.current = true;
    let stream: MediaStream;
    try {
      stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    } catch {
      if (operation === acquisition.current) { pendingAcquisition.current = false; if (alive.current) setError(i18n.permissionDenied); }
      return;
    }
    if (!alive.current || operation !== acquisition.current) { for (const track of stream.getTracks()) track.stop(); return; }
    pendingAcquisition.current = false;
    streamRef.current = stream;
    chunksRef.current = [];
    finishingRef.current = false;
    startedAtRef.current = Date.now();
    let recorder: MediaRecorder;
    try {
      recorder = new MediaRecorder(stream, { mimeType: mime });
    } catch {
      for (const track of stream.getTracks()) track.stop();
      streamRef.current = null;
      setError(i18n.failed);
      return;
    }
    recorderRef.current = recorder;
    recorder.ondataavailable = (event: BlobEvent): void => {
      if (event.data && event.data.size > 0) chunksRef.current.push(event.data);
    };
    // L-6 (audit 2026-09-29): a failed recorder surfaces honestly and
    // finalizes immediately — finalize's guarded stop() means teardown
    // always runs, so the mic never stays live behind a dead take.
    recorder.onerror = (): void => {
      setError(i18n.failed);
      finalize();
    };
    recorder.onstop = (): void => {
      const fullMime = recorder.mimeType || mime;
      const normalized = normalizeMime(fullMime);
      const durationSeconds = Math.max(1, Math.round((Date.now() - startedAtRef.current) / 1000));
      setRecording({
        blob: new Blob(chunksRef.current, { type: normalized }),
        mime: fullMime,
        normalizedMime: normalized,
        extension: extensionForMime(normalized),
        durationSeconds,
      });
      setState("stopped");
    };
    try { recorder.start(1000); } catch { recorder.onstop = null; teardown(); setError(i18n.failed); return; }
    setState("recording");
    setElapsed(0);
    timerRef.current = window.setInterval(() => {
      const seconds = Math.floor((Date.now() - startedAtRef.current) / 1000);
      setElapsed(seconds);
      if (seconds >= MAX_RECORDING_SECONDS) finalize();
    }, 500);
    // Live level meter (display-only): AnalyserNode over the same stream.
    try {
      const Ctx = window.AudioContext;
      if (Ctx) {
        const ctx = new Ctx();
        audioCtxRef.current = ctx;
        const source = ctx.createMediaStreamSource(stream);
        const analyser = ctx.createAnalyser();
        analyser.fftSize = 512;
        source.connect(analyser);
        analyserRef.current = analyser;
        const buffer = new Uint8Array(analyser.frequencyBinCount);
        const tick = (): void => {
          const node = analyserRef.current;
          if (!node) return;
          node.getByteTimeDomainData(buffer);
          let peak = 0;
          for (const sample of buffer) peak = Math.max(peak, Math.abs(sample - 128));
          setLevel(Math.min(1, peak / 96));
          rafRef.current = window.requestAnimationFrame(tick);
        };
        rafRef.current = window.requestAnimationFrame(tick);
      }
    } catch {
      // The meter is cosmetic; recording continues without it.
    }
  }, [finalize, i18n, teardown]);

  const stop = useCallback((): void => {
    if (state !== "recording") return;
    finalize();
  }, [finalize, state]);

  const reset = useCallback((): void => {
    acquisition.current += 1;
    pendingAcquisition.current = false;
    // Discard the live recorder BEFORE the track teardown: detach the
    // event handlers first so neither recorder.stop() nor the track stop's
    // async stop event can resurrect the take this reset just discarded.
    const recorder = recorderRef.current;
    if (recorder && recorder.state !== "inactive") {
      recorder.onstop = null;
      recorder.ondataavailable = null;
      try {
        recorder.stop();
      } catch {
        // already inactive racing the reset
      }
    }
    teardown();
    setRecording(null);
    setElapsed(0);
    setError(null);
    setState(typeof MediaRecorder !== "undefined" ? "idle" : "unsupported");
  }, [teardown]);

  return { state, elapsedSeconds, level, recording, error, start, stop, reset };
}
