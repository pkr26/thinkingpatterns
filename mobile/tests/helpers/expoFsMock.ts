/** Node-test mock of expo-file-system (VOICE_PLAN 2026-09-29). */
import { vi } from "vitest";

const files = new Map<string, string>();

export const EncodingType = { Base64: "base64", UTF8: "utf8" } as const;

export const cacheDirectory = "/tmp/mindpattern-test-cache/";

export default {
  readAsStringAsync: vi.fn(async (uri: string) => {
    if (!files.has(uri)) throw new Error("file not found");
    return files.get(uri)!;
  }),
  writeAsStringAsync: vi.fn(async (uri: string, content: string) => {
    files.set(uri, content);
  }),
  deleteAsync: vi.fn(async (uri: string) => {
    files.delete(uri);
  }),
};
