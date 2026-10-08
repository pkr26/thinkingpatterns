/** Static asset contracts, separate from the behavioral mutation oracle. */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { expect, it } from "vitest";
import { MAX_RECORDING_SECONDS, RECORDER_MIME_CANDIDATES } from "../src/audio/recorder";

it("preserves the documented recorder candidates and recording limit", () => {
  const shared = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), "../../shared/audio_vectors.json"), "utf8"));
  expect(RECORDER_MIME_CANDIDATES[0]).toBe("audio/webm;codecs=opus");
  expect(RECORDER_MIME_CANDIDATES).toContain("audio/mp4");
  expect(MAX_RECORDING_SECONDS).toBe(300);
  expect(MAX_RECORDING_SECONDS).toBe(shared.recording_limits.max_duration_seconds_client);
});
