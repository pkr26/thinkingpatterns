/** Session-lock machinery: idle auto-lock resets on real interaction (and
 *  ignores a mouse jiggler), the bfcache guard locks only on a persisted
 *  pageshow, and the hidden-tab guard locks the moment the tab goes to
 *  the background (mobile background-lock parity, W-1). Driven through
 *  the platform seam's window shim. */
import { act } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useBfcacheGuard, useHiddenTabLock, useIdleLock, IDLE_LOCK_MS } from "../src/sessionLock";
import { render } from "./helpers/rtr";

// The setup shim's window object (used to dispatch synthetic events).
const shimWindow = (globalThis as { window?: unknown }).window;

function Probe(props: { active: boolean; onLock: (reason: string) => void }): React.ReactElement {
  useIdleLock(props.active, props.onLock);
  useBfcacheGuard(props.active, props.onLock);
  useHiddenTabLock(props.active, props.onLock);
  return <div>probe</div>;
}

const dispatch = (event: { type: string; persisted?: boolean; visibilityState?: string }): void => {
  (shimWindow as { dispatchEvent: (e: { type: string; persisted?: boolean; visibilityState?: string }) => boolean }).dispatchEvent(event);
};

describe("useIdleLock", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("locks after 5 idle minutes (mobile parity)", async () => {
    const onLock = vi.fn();
    const root = await render(<Probe active={true} onLock={onLock} />);
    expect(onLock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1);
    expect(onLock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1);
    expect(onLock).toHaveBeenCalledWith("idle");
  });

  it("resets the timer on real interaction (click, keydown)", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    dispatch({ type: "keydown" });
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    expect(onLock).not.toHaveBeenCalled();
    dispatch({ type: "click" });
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    expect(onLock).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(1000);
    expect(onLock).toHaveBeenCalledWith("idle");
  });

  it("a mouse jiggler does NOT defeat the lock — mousemove is not activity (W-1)", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    await vi.advanceTimersByTimeAsync(IDLE_LOCK_MS - 1000);
    for (let i = 0; i < 60; i += 1) {
      dispatch({ type: "mousemove" });
      await vi.advanceTimersByTimeAsync(1000);
    }
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

describe("useHiddenTabLock (W-1: mobile background-lock parity)", () => {
  it("locks the moment the tab goes hidden", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    dispatch({ type: "visibilitychange", visibilityState: "hidden" });
    expect(onLock).toHaveBeenCalledWith("hidden");
    expect(onLock).toHaveBeenCalledTimes(1);
  });

  it("does not lock when the tab becomes (or stays) visible", async () => {
    const onLock = vi.fn();
    await render(<Probe active={true} onLock={onLock} />);
    dispatch({ type: "visibilitychange", visibilityState: "visible" });
    dispatch({ type: "visibilitychange" });
    expect(onLock).not.toHaveBeenCalled();
  });

  it("is inert while inactive (no session to protect)", async () => {
    const onLock = vi.fn();
    await render(<Probe active={false} onLock={onLock} />);
    dispatch({ type: "visibilitychange", visibilityState: "hidden" });
    expect(onLock).not.toHaveBeenCalled();
  });

  it("the document is the truth when one exists: a visible document overrides the event-borne state", async () => {
    // In a real browser visibilityState lives on document, not the event.
    // Pin the precedence so a stray event property cannot lock (or unlock)
    // a visible tab.
    const globals = globalThis as { document?: unknown };
    const previous = globals.document;
    Object.defineProperty(globalThis, "document", {
      configurable: true,
      value: { visibilityState: "visible" },
    });
    try {
      const onLock = vi.fn();
      await render(<Probe active={true} onLock={onLock} />);
      dispatch({ type: "visibilitychange", visibilityState: "hidden" });
      expect(onLock).not.toHaveBeenCalled();
    } finally {
      if (previous === undefined) {
        delete globals.document;
      } else {
        Object.defineProperty(globalThis, "document", { configurable: true, value: previous });
      }
    }
  });
});
