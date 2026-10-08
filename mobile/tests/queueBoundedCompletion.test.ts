import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import { api, ApiError, OriginPinnedError } from "../src/api/client";
import { abortInFlightFlush, enqueue, flushQueue, queueLength, rejectedEntries } from "../src/offlineQueue";
const owner = "11111111111111111111111111111111";
beforeEach(() => { storage.__reset(); abortInFlightFlush(); vi.spyOn(api, "getUserId").mockResolvedValue(owner); });
afterEach(() => { abortInFlightFlush(); vi.restoreAllMocks(); vi.useRealTimers(); });
it.each(["success", "reject", "oversized", "temporary", "expired"])("settles a finite %s native upload without posting the retained payload repeatedly", async kind => {
  await enqueue({ userId: owner, clientEntryId: "finite-native-request", entryDate: "2026-10-05", blobB64: "retained encrypted journal" });
  let requests = 0;
  vi.spyOn(api, "createQueuedEntry").mockImplementation(async () => {
    if (++requests > 1) throw new OriginPinnedError("https://queued.example", "https://replacement.example");
    if (kind !== "success") throw new ApiError(kind === "reject" ? 400 : kind === "oversized" ? 413 : kind === "expired" ? 401 : 503, kind);
    return {} as never;
  });
  const result = await flushQueue(owner).catch((error: unknown) => error);
  if (kind === "expired") expect(result).toMatchObject({ name: "SessionExpiredError" }); else expect(result).toBe(kind === "success" ? 1 : 0);
  expect(requests).toBe(1); expect(await queueLength(owner)).toBe(kind === "success" || kind === "reject" || kind === "oversized" ? 0 : 1);
  expect((await rejectedEntries(owner)).length).toBe(kind === "reject" || kind === "oversized" ? 1 : 0);
});
