/** Node-test mock of expo-file-system/legacy (VOICE_PLAN 2026-09-29).
 *  The production import shape is `import * as FileSystem from
 *  "expo-file-system/legacy"` — the legacy entry re-exports the module
 *  surface, so readAsStringAsync/writeAsStringAsync/deleteAsync and
 *  EncodingType must live on the NAMESPACE, not only the default export. */
import { vi } from "vitest";

const files = new Map<string, string>();

export const EncodingType = { Base64: "base64", UTF8: "utf8" } as const;

export const cacheDirectory = "/tmp/mindpattern-test-cache/";

export const readAsStringAsync = vi.fn(async (uri: string) => {
  if (!files.has(uri)) throw new Error("file not found");
  return files.get(uri)!;
});

export const writeAsStringAsync = vi.fn(async (uri: string, content: string) => {
  files.set(uri, content);
});

export const deleteAsync = vi.fn(async (uri: string) => {
  files.delete(uri);
});

/** Test seams: seed a take/scratch file, observe what still exists, and
 *  reset the in-memory volume between tests in a file. */
export const __seedFile = (uri: string, content = "QUJDREVG"): void => {
  files.set(uri, content);
};
export const __hasFile = (uri: string): boolean => files.has(uri);
export const __resetFiles = (): void => {
  files.clear();
  readAsStringAsync.mockClear();
  writeAsStringAsync.mockClear();
  deleteAsync.mockClear();
};

export default {
  EncodingType,
  cacheDirectory,
  readAsStringAsync,
  writeAsStringAsync,
  deleteAsync,
};
