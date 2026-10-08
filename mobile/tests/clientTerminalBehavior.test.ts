import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../src/api/client";
import storage from "./helpers/storageMock";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";

beforeEach(async () => { storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);await api.setSession("token", "a".repeat(32), "alice"); });
afterEach(async () => { await api.clearSession();vi.unstubAllGlobals(); });

it("stops a complete measures walk before sending any continuation", async () => {
  const rows = [{ id: "terminal", blob: "sealed" }];let calls = 0;
  const fetch = vi.fn(async () => ++calls === 1 ? new Response(JSON.stringify(rows)) : new Response('{"detail":"unexpected continuation"}', { status: 400 }));
  vi.stubGlobal("fetch", fetch);
  expect(await api.listMeasures()).toEqual(rows);expect(fetch).toHaveBeenCalledOnce();
});
