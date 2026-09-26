/** Session-lock machinery: idle auto-lock resets on activity and dies on
 *  deactivate/unmount; the bfcache guard locks only on a persisted
 *  pageshow. Driven through the platform seam's window shim. */
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useBfcacheGuard, useIdleLock, IDLE_LOCK_MS } from "../src/sessionLock";
import { render } from "./helpers/rtr";

// The setup shim's window object (used to dispatch synthetic events).
const shimWindow = (globalThis as { window?: unknown }).window;

function Probe(props: { active: boolean; onLock: (reason: string) => void }): React.ReactElement {
  useIdleLock(props.active, props.onLock);
  useBfcacheGuard(props.active, props.onLock);
  return <div>probe</div>;
}

const dispatch = (event: { type: string; persisted?: boolean }): void => {
  (shimWindow as { dispatchEvent: (e: { type: string; persisted?: boolean }) => boolean }).dispatchEvent(event);
};

describe("useIdleLock", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("locks after 10 idle minutes", async () => {
    const onLock = vi.fn();
    const root = await render(<Probe active={true} onLock={onLock} />);
    expect(onLock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1);
    expect(onLock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(onLock).toHaveBeenCalledWith("idle");
  });

  it("resets the timer on real interaction", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    dispatch({ type: "keydown" });
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    expect(onLock).not.toHaveBeenCalled();
    dispatch({ type: "mousemove" });
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    expect(onLock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1000);
    expect(onLock).toHaveBeenCalledWith("idle");
  });

  it("never locks while inactive (no session to protect)", async () => {
    const onLock = vi.fn();
    await render(<Probe active={false} onLock={onLock} />);
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS * 5);
    expect(onLock).not.toHaveBeenCalled();
  });

  it("stops the timer on unmount", async () => {
    const onLock = vi.fn();
    const root = await render(<Probe active={true} onLock={onLock} />);
    await act(async () => {
      root.unmount();
    });
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS * 2);
    expect(onLock).not.toHaveBeenCalled();
  });
});

describe("useBfcacheGuard", () => {
  it("locks on a persisted pageshow (back/forward cache restore)", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    dispatch({ type: "pageshow", persisted: true });
    expect(onLock).toHaveBeenCalledWith("bfcache");
  });

  it("ignores a normal (non-persisted) pageshow", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    dispatch({ type: "pageshow", persisted: false });
    expect(onLock).not.toHaveBeenCalled();
  });

  it("is inert while inactive", async () => {
    const onLock = vi.fn();
    await render(<Probe active={false} onLock={onLock} />);
    dispatch({ type: "pageshow", persisted: true });
    expect(onLock).not.toHaveBeenCalled();
  });
});
