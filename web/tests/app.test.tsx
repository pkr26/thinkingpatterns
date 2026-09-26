/** App state machine (P3): booting → login → onboarding → home, sign-out,
 *  privacy, the epoch-death funnel, and the crisis overlay from every
 *  state. Sign-in drives REAL crypto against fetch stubs. */
import { act } from "react";
import type { ReactTestRenderer } from "react-test-renderer";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, hasSession } from "../src/api/client";
import { enqueue } from "../src/offlineQueue";
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

    // Sign out (W-6): every mindpattern.* localStorage flag goes with the
    // session — a shared browser keeps no trace an account used it.
    await press(root, "Sign out (all devices)");
    await flush();
    expect(textOf(root)).toContain("Sign in");
    expect(hasSession()).toBe(false);
    expect(vault.isUnlocked()).toBe(false);
    const storage = (globalThis as { window?: { localStorage?: Storage } }).window?.localStorage;
    const leftover = storage ? Array.from({ length: storage.length }, (_, i) => storage.key(i)!).filter((key) => key.startsWith("mindpattern.")) : [];
    expect(leftover).toEqual([]);
    // The wiped onboarding flag means onboarding honestly repeats after an
    // explicit sign-out (the flag no longer exists to suppress it):
    await signIn(root);
    await flush();
    expect(textOf(root)).toContain("Step 1 of 3");
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    expect(textOf(root)).toContain("Today's entry");

    // A session-expiry funnel is NOT a sign-out: the flags survive, so
    // signing back in after a 401 does not repeat onboarding.
    vi.stubGlobal(
      "fetch",
      vi.fn(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 })),
    );
    await act(async () => {
      await expect(api.meta()).rejects.toThrow();
    });
    await flush();
    expect(textOf(root)).toContain("Your session ended");
    vi.stubGlobal("fetch", vi.fn((url: string) => {
      if (String(url).endsWith("/auth/logout")) return new Response(null, { status: 204 });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    }));
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

  it("the hidden-tab guard locks the session the moment the tab is backgrounded (W-1)", async () => {
    // Mobile parity: backgrounding locks the vault immediately. The web
    // equivalent — visibilitychange to hidden — must funnel to sign-in with
    // the keys gone, not leave decrypted text rendered in a hidden tab.
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    expect(vault.isUnlocked()).toBe(true);
    const shimWindow = (globalThis as { window?: { dispatchEvent: (event: unknown) => boolean } }).window;
    await act(async () => {
      shimWindow!.dispatchEvent({ type: "visibilitychange", visibilityState: "hidden" });
    });
    await flush();
    expect(textOf(root)).toContain("this tab went to the background");
    expect(vault.isUnlocked()).toBe(false);
    expect(hasSession()).toBe(false);
    // Coming back visible must NOT silently resurrect the session:
    await act(async () => {
      shimWindow!.dispatchEvent({ type: "visibilitychange", visibilityState: "visible" });
    });
    await flush();
    expect(vault.isUnlocked()).toBe(false);
    expect(textOf(root)).toContain("Sign in");
  });

  // Audit 2026-09-25: sessionActive had drifted to miss the later-phase
  // views — the idle lock (and bfcache guard) was disarmed exactly where
  // decrypted data and exports live. Every in-app view must lock.
  for (const navLabel of ["Measures", "Share", "Settings"]) {
    it(`the idle lock stays armed on the ${navLabel} view`, async () => {
      authStubs();
      const root = await render(<App />);
      await vi.advanceTimersByTimeAsync(50);
      await flush();
      await signIn(root);
      await press(root, "Next");
      await press(root, "Next");
      await press(root, "Start journaling");
      await flush();
      expect(textOf(root)).toContain(navLabel); // the nav row is present
      await press(root, navLabel);
      await flush();
      expect(vault.isUnlocked()).toBe(true);
      await vi.advanceTimersByTimeAsync(10 * 60 * 1000 + 10);
      await flush();
      expect(textOf(root)).toContain("Locked after inactivity");
      expect(vault.isUnlocked()).toBe(false);
      expect(hasSession()).toBe(false);
    });
  }

  it("a parked entry flushes on the periodic retry without any online transition", async () => {
    // The `online` event only fires on offline→online transitions: an
    // entry parked while the browser still believed it was online (server
    // 5xx) must be picked up by the session's periodic flush instead.
    const mock = stubFetch((url) => {
      if (url.includes("/entries") && !url.includes("?")) return jsonResponse({ id: "row" }, { status: 201 });
      if (url.endsWith("/auth/logout")) return new Response(null, { status: 204 });
      return jsonResponse({ detail: "unmatched" }, { status: 404 });
    });
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    // Park an entry for the account the mock login is about to unlock,
    // not due for another 15 s: the sign-in flush must find nothing to
    // send, so the PERIODIC flush is the only thing that can drain it.
    await enqueue({
      userId: "user-7",
      clientEntryId: "e-parked-1",
      blobB64: "AAECAwQFBgcICQoL",
      entryDate: "2026-09-25",
      notBefore: Date.now() + 15_000,
    });
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    expect(mock.mock.calls.some(([url]) => String(url).includes("/entries") && !String(url).includes("?"))).toBe(false);
    await vi.advanceTimersByTimeAsync(30_000 + 100);
    // The flush is a promise chain (kv reads → withLock → fetch → text());
    // give it several timer-async rounds to settle like the browser would.
    for (let round = 0; round < 6; round += 1) await vi.advanceTimersByTimeAsync(50);
    await flush();
    const posts = mock.mock.calls.filter(([url]) => String(url).includes("/entries") && !String(url).includes("?"));
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String((posts[0] as [string, RequestInit])[1]!.body))).toMatchObject({ client_entry_id: "e-parked-1" });
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
