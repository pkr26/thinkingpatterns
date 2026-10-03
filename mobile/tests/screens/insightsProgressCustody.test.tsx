import { afterEach, beforeEach, expect, it, vi } from "vitest";
import React from "react";
import { Text } from "react-native";
vi.mock("../../src/api/client", async importOriginal => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ...actual, ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});
import { api } from "../../src/api/client";
import { resetApi } from "../helpers/apiMock";
import { SessionProvider, useSession } from "../../src/store";
import { InsightsScreen } from "../../src/screens/InsightsScreen";
import { vault } from "../../src/vault";
import { render, act, flush } from "../helpers/rtr";
import storage from "../helpers/storageMock";
let session: ReturnType<typeof useSession>;
let root: Awaited<ReturnType<typeof render>>;
function Probe() { session = useSession(); return <Text>{String(session.activeDays)}</Text>; }
const tree = (insights = true) => <SessionProvider><Probe />{insights && <InsightsScreen />}</SessionProvider>;
beforeEach(() => {
  storage.__reset(); resetApi(api as never); vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32), dataKey: Buffer.alloc(32, 7) }, "user-1");
});
afterEach(async () => { if (root) await act(async () => root.unmount()); vi.restoreAllMocks(); });
it("an unmounted old-account Patterns response cannot overwrite progress or cancel the new owner's pending refresh", async () => {
  let oldResponse!: (value: unknown) => void, newResponse!: (value: unknown) => void;
  vi.mocked(api.insights).mockImplementationOnce(() => new Promise(resolve => { oldResponse = resolve; }));
  root = await render(tree()); await flush();
  expect(api.insights).toHaveBeenCalledOnce();
  await act(async () => root.update(tree(false)));
  vi.mocked(api.getUserId).mockResolvedValue("user-2");
  vi.mocked(api.insights).mockImplementationOnce(() => new Promise(resolve => { newResponse = resolve; }));
  let fresh!: Promise<void>; await act(async () => { fresh = session.refreshActiveDays(); });
  expect(session.activeDaysKnown).toBe(false); expect(session.activeDaysLoading).toBe(true);
  await act(async () => oldResponse({ phase: "baseline", active_days: 99, days_remaining: 0 })); await flush();
  expect(session.activeDaysKnown).toBe(false); expect(session.activeDaysLoading).toBe(true);
  await act(async () => { newResponse({ phase: "baseline", active_days: 11, days_remaining: 19 }); await fresh; });
  expect(session.activeDays).toBe(11); expect(session.activeDaysKnown).toBe(true);
});
it("provider adoption rejects old owner/request proofs and cannot turn an unknown response into known progress", async () => {
  root = await render(tree(false)); await flush();
  let oldRead!: Awaited<ReturnType<typeof session.beginProgressRead>>;
  await act(async () => { oldRead = await session.beginProgressRead(); });
  vi.mocked(api.getUserId).mockResolvedValue("user-2"); vi.mocked(api.insights).mockResolvedValue({ active_days: 12 } as never);
  await act(async () => { await session.refreshActiveDays(); session.applyActiveDays(99, oldRead!); session.finishProgressRead(oldRead!); });
  expect(session.activeDays).toBe(12); expect(session.activeDaysKnown).toBe(true);
  await act(async () => { await session.signOut(); session.applyActiveDays(99, oldRead!); });
  expect(session.activeDaysKnown).toBe(false);
});
