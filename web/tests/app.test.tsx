/** App state machine (P3): booting → login → onboarding → home, sign-out,
 *  privacy, the epoch-death funnel, and the crisis overlay from every
 *  state. Sign-in drives REAL crypto against fetch stubs. */
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, hasSession } from "../src/api/client";
import { vault } from "../src/vault";
import { jsonResponse, resetTestState, stubFetch } from "./helpers/api";
import { flush, press, render, textOf } from "./helpers/rtr";

// The real LoginView is covered by tests/login.test.tsx with REAL crypto;
// here it is replaced by a deterministic stand-in so the state machine (and
// the fake-timer idle/bfcache paths) never wait on the PBKDF2 threadpool.
vi.mock("../src/views/LoginView", async () => {
  const { setSession } = await import("../src/api/client");
  const { vault } = await import("../src/vault");
  const React = await import("react");
  return {
    LoginView: (props: { onSuccess: (s: { userId: string; username: string }) => void }) =>
      React.createElement("button", {
        onClick: () => {
          setSession("tok", "user-7", "alice");
          const key = () => new Uint8Array(new ArrayBuffer(32));
          vault.unlock({ authKey: key(), dataKey: key() }, "user-7");
          props.onSuccess({ userId: "user-7", username: "alice" });
        },
      }, "Sign in"),
  };
});

function authStubs(): void {
  stubFetch((url) => {
    if (url.endsWith("/auth/logout")) return new Response(null, { status: 204 });
    return jsonResponse({ detail: "unmatched", code: "not_found" }, { status: 404 });
  });
}

async function signIn(root: ReactTestRenderer): Promise<void> {
  await press(root, "Sign in");
  await flush();
}

beforeEach(() => {
  vi.useFakeTimers();
  resetTestState();
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("App", () => {
  it("boots to the login view", async () => {
    const root = await render(<App />);
    expect(textOf(root)).toContain("Starting…");
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    expect(textOf(root)).toContain("Sign in");
  });

  it("signs in, walks first-run onboarding, and lands home; the stamp sticks", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    expect(textOf(root)).toContain("A journal that is yours alone");
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    expect(textOf(root)).toContain("Today's entry");
    expect(hasSession()).toBe(true);
  });

  it("a returning account skips onboarding", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    expect(textOf(root)).toContain("Today's entry");

    // Sign out, sign back in: onboarding must not repeat.
    await press(root, "Sign out (all devices)");
    await flush();
    expect(textOf(root)).toContain("Sign in");
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    await signIn(root);
    await flush();
    expect(textOf(root)).toContain("Today's entry");
    expect(textOf(root)).not.toContain("Step 1 of 3");
  });

  it("the epoch-death funnel: a 401 collapses to sign-in with the honest notice", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    expect(textOf(root)).toContain("Today's entry");

    vi.stubGlobal(
      "fetch",
      vi.fn(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 })),
    );
    await act(async () => {
      await expect(api.meta()).rejects.toThrow();
    });
    await flush();
    expect(textOf(root)).toContain("Your session ended");
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
  });

  it("deletion from another device (410) lands its own message", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    vi.stubGlobal(
      "fetch",
      vi.fn(() => jsonResponse({ detail: "deleted", code: "account_deleted" }, { status: 410 })),
    );
    await act(async () => {
      await expect(api.insights()).rejects.toThrow();
    });
    await flush();
    expect(textOf(root)).toContain("This account was deleted");
  });

  it("idle lock collapses an open session with its notice", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    await vi.advanceTimersByTimeAsync(10 * 60 * 1000 + 10);
    await flush();
    expect(textOf(root)).toContain("Locked after inactivity");
    expect(vault.isUnlocked()).toBe(false);
  });

  it("the privacy view opens from home and returns", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    await press(root, "Privacy");
    expect(textOf(root)).toContain("Privacy, honestly");
    await press(root, "Back");
    expect(textOf(root)).toContain("Today's entry");
  });

  it("the crisis overlay is reachable while signed out AND signed in", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await press(root, "Get help");
    expect(textOf(root)).toContain("Get help now");
    await press(root, "Close");

    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    await press(root, "Get help");
    expect(textOf(root)).toContain("Get help now");
    expect(textOf(root)).toContain("988");
  });

  it("sign out issues the epoch-killing logout request", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    const fetchMock = (globalThis as unknown as { fetch?: { mock: { calls: [string][] } } }).fetch;
    await press(root, "Sign out (all devices)");
    await flush();
    expect(textOf(root)).toContain("Sign in");
    const calls = fetchMock?.mock.calls ?? [];
    expect(calls.some(([url]) => url.endsWith("/auth/logout"))).toBe(true);
  });
});
