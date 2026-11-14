import React from "react";
import { Text } from "react-native";
import ReactTestRenderer, { act } from "react-test-renderer";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { ErrorBoundary } from "../src/ErrorBoundary";
import { ThemeProvider } from "../src/theme";
import { useVoiceRecorder } from "../src/audio/recorder";
import { __resetAudioMock } from "./helpers/expoAudioMock";

function RecorderSurface(): React.JSX.Element {
  const recorder = useVoiceRecorder({ permissionDenied: "Microphone denied", failed: "Recording failed" });
  return <Text>{`Recorder ready: ${recorder.state}`}</Text>;
}

beforeEach(() => {
  __resetAudioMock();
  vi.spyOn(console, "warn").mockImplementation(() => {});
  vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => { vi.restoreAllMocks(); });

it("renders an available recorder inside the application error boundary", async () => {
  let root: ReactTestRenderer.ReactTestRenderer | undefined;
  try {
    await act(async () => {
      root = ReactTestRenderer.create(<ThemeProvider><ErrorBoundary><RecorderSurface /></ErrorBoundary></ThemeProvider>);
    });
    const visible = root!.root.findAllByType(Text).map(node => String(node.props.children)).join(" ");
    expect(visible, "A recording screen must remain available instead of showing the crash fallback").toContain("Recorder ready: idle");
  } finally {
    if (root) await act(async () => { root!.unmount(); });
  }
}, 12000);
