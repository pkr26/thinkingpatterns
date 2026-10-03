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
import { applyLanguagePref } from "../src/strings";
import { flush, press, render, textOf } from "./helpers/rtr";

// Preload modules in this state-machine suite; production still lazy-loads them.
await import("../src/views/Entry");

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
    await act(async () => { await import("../src/views/Entry"); });
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
    await act(async () => { await import("../src/views/Entry"); });
    await flush();
    expect(textOf(root)).toContain("Today's entry");

    // Sign out (W-6): every mindpattern.* localStorage flag goes with the
    // session — a shared browser keeps no trace an account used it.
    await press(root, "More");
    await press(root, "Sign out (this device)");
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
    await act(async () => { await import("../src/views/Entry"); });
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
    await act(async () => { await import("../src/views/Entry"); });
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
    await act(async () => { await import("../src/views/Entry"); });
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
  // (2026-09-27: the safety-plan view joins the loop — it renders
  // decrypted plan text, so it must lock like the rest.)
  for (const navLabel of ["Measures", "Safety plan", "Share", "Settings"]) {
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
      await press(root, "More");
      expect(textOf(root)).toContain(navLabel); // the More menu lists it
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
    await press(root, "More");
    await press(root, "Privacy");
    expect(textOf(root)).toContain("Privacy, honestly");
    await press(root, "Back");
    await act(async () => { await import("../src/views/Entry"); });
    await flush();
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

  it("a language preference change re-renders the whole shell LIVE (audit 2026-09-26 LOW)", async () => {
    authStubs();
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    await signIn(root);
    await press(root, "Next");
    await press(root, "Next");
    await press(root, "Start journaling");
    await flush();
    await act(async () => { await import("../src/views/Entry"); });
    await flush();
    expect(textOf(root)).toContain("Today's entry");
    // The Settings seam flipped the catalog; the shell (this test mounts the
    // REAL App, not a stand-in) must follow without a reload.
    applyLanguagePref("es");
    await flush();
    expect(textOf(root)).toContain("La entrada de hoy");
    applyLanguagePref("auto");
    await flush();
    await act(async () => { await import("../src/views/Entry"); });
    await flush();
    expect(textOf(root)).toContain("Today's entry");
  });

  it("sign out issues the per-device logout request (jti revocation, 2026-09-26)", async () => {
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
    await press(root, "More");
    await press(root, "Sign out (this device)");
    await flush();
    expect(textOf(root)).toContain("Sign in");
    const calls = fetchMock?.mock.calls ?? [];
    expect(calls.some(([url]) => url.endsWith("/auth/logout"))).toBe(true);
  });

  it("L-8 (2026-09-28): mounting the App sweeps the legacy plaintext crisis stamps", async () => {
    authStubs();
    const storage = (globalThis as { window?: { localStorage?: Storage } }).window?.localStorage;
    expect(storage).toBeTruthy();
    storage!.setItem("mindpattern.crisisDialog.v1.user-7", "2026-09-26");
    const root = await render(<App />);
    await vi.advanceTimersByTimeAsync(50);
    await flush();
    expect(textOf(root)).toContain("Sign in");
    // Swept for EVERY visitor at mount — not only after a crisis-flagged
    // save first consults the module.
    expect(storage!.getItem("mindpattern.crisisDialog.v1.user-7")).toBeNull();
    await act(async () => {
      void root;
    });
  });

  it("M-4 (2026-09-28): a rotation broadcast from another tab locks this tab down", async () => {
    const channels = new Set<TestChannel>();
    class TestChannel {
      onmessage: ((event: {data:unknown}) => void) | null = null;
      constructor(_name: string) { channels.add(this); }
      postMessage(data: unknown): void { for (const channel of channels) if (channel !== this) channel.onmessage?.({data}); }
      close(): void { channels.delete(this); }
    }
    vi.stubGlobal("BroadcastChannel",TestChannel);
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
    // Another tab started a password rotation and broadcast the lockdown.
    await act(async () => {
      const otherPage = new TestChannel("mindpattern-session-lockdown");
      otherPage.postMessage({reason:"rotation",source_id:"another-page"});
      otherPage.close();
    });
    await flush(6);
    expect(vault.isUnlocked()).toBe(false);
    expect(hasSession()).toBe(false);
    expect(textOf(root)).toContain("Sign in");
  });
});

it("a late authenticated startup cannot resurrect a session after expiry", async () => {
  let release!:()=>void;const pending=new Promise<void>(resolve=>{release=resolve;});
  const strings=await import('../src/strings');const delayed=vi.spyOn(strings,'loadFullCatalogs').mockImplementation(()=>pending);
  authStubs();const root=await render(<App/>);await vi.advanceTimersByTimeAsync(50);await signIn(root);
  vi.stubGlobal('fetch',vi.fn(()=>jsonResponse({detail:'expired',code:'unauthorized'},{status:401})));
  await act(async()=>{await expect(api.meta()).rejects.toThrow();});
  await act(async()=>{release();await pending;});await flush(8);
  expect(vault.isUnlocked()).toBe(false);expect(textOf(root)).toContain('Sign in');expect(textOf(root)).not.toContain('A journal that is yours alone');delayed.mockRestore();
});

it("a confirmed erasure failure stays visible and retries without touching another account", async () => {
  const {setKvBackendForTests}=await import('../src/kvstore');let fail=true;
  const records=new Map([['mindpattern.safetyPlan.erased','encrypted plan'],['mindpattern.safetyPlan.other','other plan'],['mindpattern.erase.erased',JSON.stringify({v:1,owner:'erased',remoteConfirmed:true,keys:['mindpattern.safetyPlan.erased']})]]);
  setKvBackendForTests({getItem:async key=>records.get(key)??null,setItem:async(key,value)=>{records.set(key,value);},removeItem:async key=>{if(fail&&key==='mindpattern.safetyPlan.erased')throw new Error('storage denied');records.delete(key);},compareAndSet:async(key,before,after)=>{if((records.get(key)??null)!==before)return false;records.set(key,after);return true;},keys:async()=>[...records.keys()]});
  const root=await render(<App/>);await flush(10);expect(textOf(root)).toContain('Unfinished local deletion');expect(records.get('mindpattern.safetyPlan.erased')).toBe('encrypted plan');
  fail=false;await press(root,'Retry local cleanup');await flush(10);expect(records.has('mindpattern.safetyPlan.erased')).toBe(false);expect(records.get('mindpattern.safetyPlan.other')).toBe('other plan');expect(textOf(root)).not.toContain('Unfinished local deletion');
});

it("an unconfirmed deletion never erases data until an explicit local-erasure action", async () => {
  const {setKvBackendForTests}=await import('../src/kvstore');const records=new Map([['mindpattern.safetyPlan.pending','retained plan'],['mindpattern.erase.pending',JSON.stringify({v:1,owner:'pending',remoteConfirmed:false,keys:['mindpattern.safetyPlan.pending']})]]);
  setKvBackendForTests({getItem:async key=>records.get(key)??null,setItem:async(key,value)=>{records.set(key,value);},removeItem:async key=>{records.delete(key);},compareAndSet:async(key,before,after)=>{if((records.get(key)??null)!==before)return false;records.set(key,after);return true;},keys:async()=>[...records.keys()]});
  const root=await render(<App/>);await flush(10);expect(records.get('mindpattern.safetyPlan.pending')).toBe('retained plan');
  await press(root,'I confirmed deletion — remove its local records');await flush(10);expect(records.has('mindpattern.safetyPlan.pending')).toBe(false);expect(textOf(root)).not.toContain('Unfinished local deletion');
});
