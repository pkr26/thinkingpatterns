import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, clearSession, setSession } from "../src/api";

const NativeResponse = Response;
beforeEach(() => {
  vi.useFakeTimers();
  clearSession();
  setSession("deadline-token", "https://clinic.example.com");
});
afterEach(() => {
  clearSession();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it("keeps a deadline when a native empty-body Response has a pending JSON parser", async () => {
  class PendingEmptyResponse extends NativeResponse {
    override json(): Promise<any> {
      return new Promise(() => {});
    }
  }
  vi.stubGlobal("fetch", vi.fn(async () => new PendingEmptyResponse(null, { status: 200 })));
  const outcome: { settled: boolean; error?: unknown } = { settled: false };
  void api.me().then(
    () => { outcome.settled = true; },
    (error) => { outcome.settled = true; outcome.error = error; },
  );
  for (let i = 0; i < 50; i++) await Promise.resolve();
  expect(outcome.settled).toBe(false);
  await vi.advanceTimersByTimeAsync(15_000);
  for (let i = 0; i < 50; i++) await Promise.resolve();
  expect(outcome).toMatchObject({
    settled: true,
    error: { status: 0, message: "request timed out while reading response" },
  });
  expect(vi.getTimerCount()).toBe(0);
});
