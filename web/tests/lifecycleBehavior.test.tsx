import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { clearSession, setSession } from "../src/api/client";
import { usePatientOperation, type PatientOperation } from "../src/patientOperation";
import { useBfcacheGuard, useHiddenTabLock, useIdleLock } from "../src/sessionLock";
import { vault } from "../src/vault";
import { resetTestState } from "./helpers/api";
import { render } from "./helpers/rtr";

beforeEach(() => { resetTestState(); vi.useFakeTimers(); });
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); });
const event = (type: string, detail: Record<string, unknown> = {}) => window.dispatchEvent({ type, ...detail } as Event);
function Locks({ active, callback }: { active: boolean, callback: (reason: string) => void }) {
  useIdleLock(active, callback); useBfcacheGuard(active, callback); useHiddenTabLock(active, callback); return <p>Session</p>;
}
it("removes all lifecycle listeners when disabled, and installs the latest callback when reactivated", async () => {
  const old = vi.fn(), current = vi.fn();
  const root = await render(<Locks active callback={old} />);
  await act(async () => { root.update(<Locks active={false} callback={old} />); });
  event("pageshow", { persisted: true }); event("visibilitychange", { visibilityState: "hidden" }); event("click");
  await act(async () => { await vi.advanceTimersByTimeAsync(300000); }); expect(old).not.toHaveBeenCalled();
  await act(async () => { root.update(<Locks active callback={current} />); });
  event("pageshow", { persisted: true }); event("visibilitychange", { visibilityState: "hidden" });
  expect(current.mock.calls).toEqual([["bfcache"], ["hidden"]]);
  await act(async () => { root.unmount(); });
  event("click"); event("pageshow", { persisted: true }); event("visibilitychange", { visibilityState: "hidden" });
  await act(async () => { await vi.advanceTimersByTimeAsync(300000); });
  expect(current).toHaveBeenCalledTimes(2); expect(old).not.toHaveBeenCalled();
});
it("ignores pageshow events whose persisted flag is absent or malformed", async () => {
  const callback = vi.fn(); await render(<Locks active callback={callback} />);
  for (const persisted of [undefined, null, false, "true", 1]) event("pageshow", { persisted });
  expect(callback).not.toHaveBeenCalled(); event("pageshow", { persisted: true }); expect(callback).toHaveBeenCalledWith("bfcache");
});

let begin: (() => PatientOperation | null) | undefined;
function Consumer() { begin = usePatientOperation(); return <p>Asynchronous view</p>; }
function unlock(owner = "lifecycle-owner", byte = 7) {
  const key = () => new Uint8Array(new ArrayBuffer(32)).fill(byte);
  vault.unlock({ authKey: key(), dataKey: key() }, owner);
}
it("allows an active view's operation and rejects results after the view unmounts", async () => {
  setSession("bearer", "lifecycle-owner", "alice"); unlock(); const root = await render(<Consumer />);
  const operation = begin!()!; expect(operation).not.toBeNull(); expect(operation.current()).toBe(true); expect(operation.viewCurrent()).toBe(true);
  await act(async () => { root.unmount(); });
  expect(operation.current()).toBe(false); expect(operation.viewCurrent()).toBe(false); expect(begin!()).toBeNull();
});
it("rejects a previous login's asynchronous result even when the successor has the same account", async () => {
  setSession("old bearer", "lifecycle-owner", "alice"); unlock(); await render(<Consumer />);
  const old = begin!()!;
  setSession("new bearer", "lifecycle-owner", "alice"); unlock("lifecycle-owner", 9);
  expect(old.current()).toBe(false); expect(old.viewCurrent()).toBe(false); expect(begin!()!.current()).toBe(true);
  clearSession(); expect(begin!()).toBeNull();
});
it("does not permit content commits after a vault lock, key replacement or owner change", async () => {
  setSession("bearer", "lifecycle-owner", "alice"); unlock(); await render(<Consumer />);
  const old = begin!()!; unlock("lifecycle-owner", 9); expect(old.current()).toBe(false);
  const current = begin!()!; vault.lock(); expect(current.current()).toBe(false); expect(begin!()).toBeNull();
  unlock("different-owner"); expect(current.current()).toBe(false); expect(begin!()).toBeNull();
});
