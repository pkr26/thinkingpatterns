/** EntryView voice-UI render states (2026-09-29 P2 coverage gate): the
 *  mic card, the recording card (timer + level dot + stop), and the
 *  review card (playback, keep-audio toggle, re-record, discard) shipped
 *  with the voice wave and had no test driving their actual UI states —
 *  Entry.tsx sat at 56% functions. Minimal getUserMedia/MediaRecorder
 *  globals drive the real useVoiceRecorder hook through its states. */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

import { EntryView } from "../src/views/Entry";
import { encryptEntry } from "../src/crypto/patient";
import { vault } from "../src/vault";
import { installSession, jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { press, pressSwitch, render, settle, textOf } from "./helpers/rtr";

const USER = "user-1";
const DATA_KEY = new Uint8Array(32).fill(9);

// --- the smallest recorder globals the hook needs ---------------------------
class TinyRecorder {
  static instances: TinyRecorder[] = [];
  static isTypeSupported(mime: string): boolean {
    return mime === "audio/webm";
  }
  mimeType = "audio/webm";
  ondataavailable: ((e: { data: Blob }) => void) | null = null;
  onstop: (() => void) | null = null;
  #stopped = false;
  constructor(public stream: MediaStream) {
    TinyRecorder.instances.push(this);
  }
  start(): void {
    /* chunks arrive on stop in this mock */
  }
  stop(): void {
    if (this.#stopped) return;
    this.#stopped = true;
    this.ondataavailable?.({ data: new Blob([new Uint8Array(64).fill(1)], { type: "audio/webm" }) });
    this.onstop?.();
  }
  getTracks(): Array<{ stop: () => void }> {
    return [{ stop: () => undefined }];
  }
}

function stubRecorderGlobals(): void {
  const stream = { getTracks: () => [{ stop: () => undefined }] } as unknown as MediaStream;
  Object.defineProperty(globalThis, "MediaRecorder", { value: TinyRecorder, configurable: true });
  // Patch ONLY the object-URL members: replacing the URL constructor
  // wholesale breaks the api client's origin parsing.
  const RealURL = globalThis.URL as typeof URL & {
    createObjectURL?: (b: Blob) => string;
    revokeObjectURL?: (u: string) => void;
  };
  RealURL.createObjectURL = () => "blob:mock-take";
  RealURL.revokeObjectURL = () => undefined;
  Object.defineProperty(navigator, "mediaDevices", {
    value: { getUserMedia: async () => stream },
    configurable: true,
  });
  // The hook's elapsed timer and level meter ride window timers + rAF,
  // which the node test window does not provide.
  const win = (globalThis as unknown as {
    window: Window & typeof globalThis & Record<string, unknown>;
  }).window;
  if (win && typeof win.setInterval !== "function") {
    win.setInterval = (fn: () => void, _ms?: number) => {
      void fn();
      return 0 as unknown as number;
    };
    win.clearInterval = () => undefined;
    win.requestAnimationFrame = () => 0;
    win.cancelAnimationFrame = () => undefined;
  }
}

beforeEach(() => {
  resetTestState();
  installSession(USER);
  vault.unlock({ authKey: DATA_KEY, dataKey: DATA_KEY }, USER);
  TinyRecorder.instances.length = 0;
  stubRecorderGlobals();
  // The mic flow's preflight: audio stack available + voice consent on.
  stubFetch((url) => {
    if (url.endsWith("/meta")) return jsonResponse({ audio_available: true });
    if (url.endsWith("/account/voice-consent")) return jsonResponse({ enabled: true });
    if (url.endsWith("/audio/transcriptions")) {
      return jsonResponse({
        original_text: "spoken journal words",
        language: "en",
        language_raw: "english",
        english_text: null,
        provider_name: "p",
        policy_version: "1",
      });
    }
    if (url.endsWith("/entries") && url.includes("offset=0")) {
      return jsonResponse([], { headers: { "X-Entries-Revision": "1" } });
    }
    return jsonResponse({}, { status: 201 });
  });
});

describe("EntryView voice UI states", () => {
  it("record → stop → transcribe renders the review card with its controls", async () => {
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    // Idle: the mic button is offered.
    await press(root, "Record instead");
    await settle(40, 3);
    // Recording state: the timer card with its Stop button.
    expect(textOf(root)).toContain("Recording…");
    await press(root, "Stop recording");
    await settle(40, 4);
    // Transcription landed: the review card shows the transcript controls.
    expect(textOf(root)).toContain("Record again");
    expect(textOf(root)).toContain("Use text only");
    // The transcript was inserted into the editor (a textarea's VALUE,
    // not a text child — read the input node directly).
    const editor = root.root.findAllByType("textarea")[0]!;
    expect(String((editor.props as { value?: string }).value)).toContain("spoken journal words");
  });

  it("the review card's toggle and discard work", async () => {
    const root = await render(<EntryView onSaved={() => undefined} />);
    await settle(40, 3);
    await press(root, "Record instead");
    await settle(40, 3);
    await press(root, "Stop recording");
    await settle(40, 4);
    expect(textOf(root)).toContain("Record again");
    // The keep-audio toggle's OFF label is visible (opt-in retention)...
    expect(textOf(root)).toContain("recording will be deleted");
    // ...and flipping it opts IN (the label flips to the retention copy).
    await pressSwitch(root);
    await settle(40, 1);
    expect(textOf(root)).toContain("Keep the recording");
    // Discard removes the review card entirely.
    await press(root, "Use text only");
    await settle(40, 2);
    expect(textOf(root)).not.toContain("Record again");
    // And the mic button returns.
    expect(textOf(root)).toContain("Record instead");
  });

  it("a voice take saves like any entry (upload + editor reset)", async () => {
    const saved: string[] = [];
    const root = await render(<EntryView onSaved={() => saved.push("saved")} />);
    await settle(40, 3);
    await press(root, "Record instead");
    await settle(40, 3);
    await press(root, "Stop recording");
    await settle(40, 4);
    const editor = root.root.findAllByType("textarea")[0]!;
    expect(String((editor.props as { value?: string }).value)).toContain("spoken journal words");
    await press(root, "Save entry");
    await settle(40, 5);
    expect(saved).toEqual(["saved"]);
    const after = root.root.findAllByType("textarea")[0]!;
    expect(String((after.props as { value?: string }).value)).toBe("");
  });
});
