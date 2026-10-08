import { act } from "react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, hasSession } from "../src/api/client";
import { vault } from "../src/vault";
import { preserveActiveDraft } from "../src/entryDraft";
import { preserveSafetyPlan } from "../src/safetyPlan";
import { abortInFlightFlush, flushQueueOnReconnect } from "../src/offlineQueue";
import { reconcile } from "../src/sync";
import { applyLanguagePref, t } from "../src/strings";
import { hasLocalRotation, resumeLocalRotation } from "../src/localRotation";
import { confirmLocalErasure, confirmRemoteLocalErasure, pendingLocalErasures, resumeConfirmedErasures } from "../src/localErasure";
import { hasSeenOnboarding, markOnboardingSeen } from "../src/views/Onboarding";
import { kv, newWriteGeneration, setKvBackendForTests, writeGenerationKey } from "../src/kvstore";
import { resetTestState, jsonResponse, stubFetch } from "./helpers/api";
import { flush, press, render, textOf, textOfNode } from "./helpers/rtr";
import { publicSurface } from "./helpers/publicSurface";
import { adoptLegacyPlaintextMutes } from "../src/patternMutes";

const state = vi.hoisted(() => ({
  hooks: {} as Record<string, ((reason: string) => void) | null>,
  seen: true,
  failures: [] as unknown[],
  erasures: [] as { owner: string; remoteConfirmed: boolean }[],
  pending: [] as { owner: string; remoteConfirmed: boolean }[],
  keyByte: 5,
  loginOwner: "shell-owner",
  loginName: "alice",
}));
vi.mock("../src/views/LoginView", async () => {
  const React = await import("react");
  const { setSession } = await import("../src/api/client");
  const { vault } = await import("../src/vault");
  return { LoginView: ({ onSuccess }: any) => React.createElement("button", { onClick: () => {
    const owner=state.loginOwner,name=state.loginName;
    setSession("shell-token", owner, name);
    vault.unlock({ authKey: new Uint8Array(32).fill(4), dataKey: new Uint8Array(32).fill(state.keyByte) }, owner);
    return onSuccess({ userId: owner, username: name });
  } }, "Sign in") };
});
vi.mock("../src/views/Onboarding", async () => {
  const React = await import("react");
  return {
    hasSeenOnboarding: vi.fn(async () => state.seen),
    markOnboardingSeen: vi.fn(async () => { state.seen = true; }),
    clearOnboardingSeen: vi.fn(async () => { state.seen = false; }),
    Onboarding: ({ onDone }: any) => React.createElement("button", { onClick: onDone }, "Finish introduction"),
  };
});
vi.mock("../src/views/Entry", async () => {
  const React = await import("react");
  return { EntryView: ({ onSaved, onCrisis }: any) => React.createElement("section", {},
    React.createElement("p", {}, "Today screen"),
    React.createElement("button", { onClick: () => onSaved("sent", "2026-10-05") }, "Commit online"),
    React.createElement("button", { onClick: () => onSaved("queued", "2026-10-05") }, "Park offline"),
    React.createElement("button", { onClick: onCrisis }, "Entry help")) };
});
vi.mock("../src/views/History", () => ({ HistoryView: () => <p>History screen</p> }));
vi.mock("../src/views/Patterns", () => ({ PatternsView: ({ onCrisis }: any) => <><p>Patterns screen</p><button onClick={onCrisis}>Patterns help</button></> }));
vi.mock("../src/views/Question", () => ({ QuestionView: ({ onRefreshed }: any) => <><p>Question screen</p><button onClick={() => onRefreshed("Question refreshed")}>Refresh question</button></> }));
vi.mock("../src/views/Measures", () => ({ MeasuresView: ({ onCrisis }: any) => <><p>Measures screen</p><button onClick={onCrisis}>Measures help</button></> }));
vi.mock("../src/views/SafetyPlan", () => ({ SafetyPlanView: ({ onCrisis }: any) => <><p>Safety plan screen</p><button onClick={onCrisis}>Plan help</button></> }));
vi.mock("../src/views/Share", () => ({ ShareView: () => <p>Share screen</p> }));
vi.mock("../src/views/Settings", () => ({ SettingsView: ({ onLockdown, onOpenSafetyPlan }: any) => <><p>Settings screen</p><button onClick={onOpenSafetyPlan}>Open stored plan</button><button onClick={() => onLockdown("Password changed")}>Finish password change</button></> }));
vi.mock("../src/views/Privacy", () => ({ Privacy: ({ onBack }: any) => <><p>Privacy screen</p><button onClick={onBack}>Back to journal</button></> }));
vi.mock("../src/offlineQueue", () => ({ abortInFlightFlush: vi.fn(), flushQueueOnReconnect: vi.fn(async () => {}) }));
vi.mock("../src/entryDraft", () => ({ preserveActiveDraft: vi.fn(async () => {}) }));
vi.mock("../src/safetyPlan", () => ({ preserveSafetyPlan: vi.fn(async () => {}) }));
vi.mock("../src/patternMutes", () => ({ adoptLegacyPlaintextMutes: vi.fn(async () => {}) }));
vi.mock("../src/sessionLock", () => ({
  useIdleLock: (enabled: boolean, callback: any) => { state.hooks.idle = enabled ? callback : null; },
  useBfcacheGuard: (enabled: boolean, callback: any) => { state.hooks.bfcache = enabled ? callback : null; },
  useHiddenTabLock: (enabled: boolean, callback: any) => { state.hooks.hidden = enabled ? callback : null; },
}));
vi.mock("../src/sync", () => ({ reconcile: vi.fn(async () => ({ kind: "freshness" })) }));
vi.mock("../src/localRotation", () => ({ hasLocalRotation: vi.fn(async () => false), resumeLocalRotation: vi.fn(async () => {}) }));
vi.mock("../src/localErasure", () => ({
  resumeConfirmedErasures: vi.fn(async () => { if (state.failures.length) throw state.failures.shift(); return state.erasures; }),
  pendingLocalErasures: vi.fn(async () => state.pending),
  confirmLocalErasure: vi.fn(async (owner: string) => { state.erasures = state.erasures.filter((row) => row.owner !== owner); }),
  confirmRemoteLocalErasure: vi.fn(async () => {}),
}));

beforeEach(() => {
  vi.useFakeTimers();
  resetTestState();
  vi.clearAllMocks();
  state.seen = true; state.failures = []; state.erasures = []; state.pending = []; state.hooks = {};
  state.keyByte=5;
  state.loginOwner="shell-owner";state.loginName="alice";
  vi.mocked(hasLocalRotation).mockReset().mockResolvedValue(false);
  vi.mocked(resumeLocalRotation).mockReset().mockResolvedValue(undefined);
  vi.mocked(hasSeenOnboarding).mockReset().mockImplementation(async()=>state.seen);
  vi.mocked(markOnboardingSeen).mockReset().mockImplementation(async()=>{state.seen=true;});
  vi.mocked(reconcile).mockResolvedValue({ kind: "freshness" });
  (window.location as any).hash = "#/today";
  (window as any).history = { pushState: (_state: unknown, _title: string, hash: string) => { (window.location as any).hash = hash; } };
  stubFetch(() => jsonResponse({}));
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); applyLanguagePref("en"); });

async function signedIn() {
  const root = await render(<App />);
  await act(async () => { await vi.advanceTimersByTimeAsync(50); });
  await press(root, "Sign in");
  await flush(15);
  return root;
}
async function more(root: Awaited<ReturnType<typeof signedIn>>, destination: string) {
  await press(root, "More"); await press(root, destination); await flush(10);
}

it("routes all primary and overflow destinations, preserves both editors, and exposes both navigation surfaces", async () => {
  const root = await signedIn();
  expect(textOf(root)).toContain("Today screen");
  expect(textOf(root)).toContain("Signed in as alice");
  expect(root.root.findAllByType("nav")).toHaveLength(2);
  for (const [label, screen, kind] of [["History", "History", "history"], ["Patterns", "Patterns", "patterns"], ["Question", "Question", "question"], ["Today", "Today", "today"]]) {
    await press(root, label!); await flush(10);
    expect(textOf(root)).toContain(`${screen} screen`);
    expect(window.location.hash).toBe(`#/${kind}`);
  }
  for (const [label, screen, kind] of [["Measures", "Measures", "measures"], ["Safety plan", "Safety plan", "safetyplan"], ["Share", "Share", "share"], ["Settings", "Settings", "settings"], ["Privacy", "Privacy", "privacy"]]) {
    await more(root, label!);
    expect(textOf(root)).toContain(`${screen} screen`);
    expect(window.location.hash).toBe(`#/${kind}`);
    if (kind === "privacy") await press(root, "Back to journal");
  }
  expect(preserveActiveDraft).toHaveBeenCalled();
  expect(preserveSafetyPlan).toHaveBeenCalled();
});

it("renders the complete signed-in navigation and distinct online/offline confirmations", async () => {
  const root = await signedIn();
  await press(root, "Commit online");await press(root, "Park offline");await press(root, "More");
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
  await press(root, "Settings");await press(root, "More");
  expect(publicSurface(root.toJSON())).toMatchSnapshot();
});

it("adopts legacy mute preferences at sign-in and wipes its temporary migration key", async () => {
  vi.mocked(hasLocalRotation).mockResolvedValueOnce(true);
  stubFetch(() => jsonResponse({ salt: "confirmed-salt" }));
  await signedIn();
  expect(adoptLegacyPlaintextMutes).toHaveBeenCalledExactlyOnceWith(vault.get().dataKey, "shell-owner");
  const handedKey = vi.mocked(resumeLocalRotation).mock.calls[0]![1];
  expect([...handedKey]).toEqual(Array(32).fill(0));
  expect([...vault.get().dataKey]).toEqual(Array(32).fill(5));
});

it("drains parked writing on a connectivity event only while a session owns the interface", async () => {
  const root = await signedIn();vi.mocked(flushQueueOnReconnect).mockClear();
  await act(async () => { window.dispatchEvent({ type: "online" } as Event); });await flush(10);
  expect(flushQueueOnReconnect).toHaveBeenCalledOnce();
  await act(async () => { state.hooks.idle!("idle"); });vi.mocked(flushQueueOnReconnect).mockClear();
  await act(async () => { window.dispatchEvent({ type: "online" } as Event); });await flush(10);
  expect(flushQueueOnReconnect).not.toHaveBeenCalled();expect(textOf(root)).toContain("Sign in");
});

it.each([new Error("Remote cleanup is pending"), "untyped remote cleanup failure"])("retains pending account cleanup after an authoritative deletion cannot finish", async fault => {
  const root = await signedIn();state.pending = [{ owner: "shell-owner", remoteConfirmed: true }];
  vi.mocked(confirmRemoteLocalErasure).mockRejectedValueOnce(fault);vi.mocked(abortInFlightFlush).mockClear();
  stubFetch(() => jsonResponse({ detail: "deleted", code: "account_deleted" }, { status: 410 }));
  await act(async () => { await api.meta().catch(() => {}); });await flush(15);
  expect(textOf(root)).toContain(fault instanceof Error ? fault.message : t("app.erasureIncomplete"));
  expect(textOf(root)).toContain(t("app.erasureExplanation"));expect(pendingLocalErasures).toHaveBeenCalled();
  expect(abortInFlightFlush).toHaveBeenCalledOnce();expect(textOf(root)).toContain("Sign in");
});

it.each([new Error("Flag cleanup is pending"), "untyped flag cleanup failure"])("keeps device sign-out cleanup failures visible", async fault => {
  const root = await signedIn();const remove = vi.spyOn(kv, "removeItem").mockRejectedValueOnce(fault);
  try {
    await more(root, "Sign out (this device)");await flush(15);
    expect(textOf(root)).toContain(fault instanceof Error ? fault.message : t("app.erasureIncomplete"));
    expect(textOf(root)).toContain("Sign in");
  } finally { remove.mockRestore(); }
});

it("renders closed help and an empty notice region at startup, keeping the brief boot status visible", async () => {
  const root = await render(<App />);
  expect(textOf(root)).toContain("Starting…");
  expect(root.root.findAllByProps({ role: "dialog" })).toHaveLength(0);
  expect(root.root.findAllByProps({ className: "toast" })).toHaveLength(0);
  await act(async () => { await vi.advanceTimersByTimeAsync(39); });
  expect(textOf(root)).toContain("Starting…");
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  expect(textOf(root)).toContain("Sign in");
  expect(root.root.findAllByProps({ role: "alert" })).toHaveLength(0);
});

it("releases its pending boot deadline when the page unmounts", async () => {
  const root = await render(<App />);expect(vi.getTimerCount()).toBe(1);
  await act(async () => { root.unmount(); });expect(vi.getTimerCount()).toBe(0);
});

it("retires an unfinished sign-in adoption when its page unmounts", async () => {
  let release!: (pending: boolean) => void;
  vi.mocked(hasLocalRotation).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const root = await signedIn();vi.mocked(flushQueueOnReconnect).mockClear();vi.mocked(adoptLegacyPlaintextMutes).mockClear();
  await act(async () => { root.unmount(); });
  await act(async () => { release(false); });await flush(15);
  expect(flushQueueOnReconnect).not.toHaveBeenCalled();expect(adoptLegacyPlaintextMutes).not.toHaveBeenCalled();
});

it("keeps a locked and unmounted adoption from publishing an old key into a replacement page",async()=>{
  let release!:(pending:boolean)=>void;
  vi.mocked(hasLocalRotation).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
  const old=await signedIn();stubFetch(()=>jsonResponse({detail:"expired"},{status:401}));
  await act(async()=>{await api.meta().catch(()=>{});});await act(async()=>{old.unmount();});
  state.keyByte=9;const handedKeys:number[]=[];const adopt=kv.adoptVerifiedWriteGeneration;
  const observer=vi.spyOn(kv,"adoptVerifiedWriteGeneration").mockImplementation(async(owner,key,current)=>{
    handedKeys.push(key[0]!);return adopt(owner,key,current);
  });
  try {
    stubFetch(()=>jsonResponse({}));const successor=await signedIn();
    await act(async()=>{release(false);});await flush(25);
    expect(handedKeys).toEqual([9]);expect(textOf(successor)).toContain("Today screen");
  } finally {release(false);observer.mockRestore();await flush(10);}
});

it("keeps a failed old adoption from replacing an already locked interface", async () => {
  let fail!: (error: Error) => void;
  vi.mocked(hasLocalRotation).mockImplementationOnce(() => new Promise((_resolve, reject) => { fail = reject; }));
  const root = await signedIn();stubFetch(() => jsonResponse({ detail: "expired" }, { status: 401 }));
  await act(async () => { await api.meta().catch(() => {}); });
  await act(async () => { fail(new Error("An obsolete migration failure")); });await flush(15);
  expect(textOf(root)).toContain("Sign in");expect(textOf(root)).not.toContain("Settings screen");expect(textOf(root)).not.toContain("An obsolete migration failure");
});

it("keeps a completed old onboarding lookup from replacing an already locked interface", async () => {
  let release!: (seen: boolean) => void;
  vi.mocked(hasSeenOnboarding).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const root = await signedIn();stubFetch(() => jsonResponse({ detail: "expired" }, { status: 401 }));
  await act(async () => { await api.meta().catch(() => {}); });
  await act(async () => { release(true); });await flush(15);
  expect(textOf(root)).toContain("Sign in");expect(textOf(root)).not.toContain("Today screen");
});

it("waits for an existing origin-wide account transition before adopting the new session", async () => {
  const queues = new Map<string, Promise<unknown>>();
  const request = <T,>(name: string, callback: () => Promise<T>): Promise<T> => {
    const next = (queues.get(name) ?? Promise.resolve()).catch(() => {}).then(callback);queues.set(name, next);
    const clear = () => { if (queues.get(name) === next) queues.delete(name); };void next.then(clear, clear);return next;
  };
  const before = navigator;vi.stubGlobal("navigator", { ...before, locks: { request } });
  let release!: () => void;const previous = request("account-transition", () => new Promise<void>(resolve => { release = resolve; }));await flush(3);
  try {
    const root = await signedIn();expect(textOf(root)).toContain("Sign in");expect(textOf(root)).not.toContain("Today screen");
    await act(async () => { release();await previous; });await flush(15);
    expect(textOf(root)).toContain("Today screen");
  } finally { release();await previous;await flush(15); }
});

it("does not adopt a queued older login's account metadata after another account has unlocked",async()=>{
  const queues=new Map<string,Promise<unknown>>();
  const request=<T,>(name:string,callback:()=>Promise<T>):Promise<T>=>{
    const next=(queues.get(name)??Promise.resolve()).catch(()=>{}).then(callback);queues.set(name,next);return next;
  };
  vi.stubGlobal("navigator",{...navigator,locks:{request}});
  const records=new Map<string,string>();
  setKvBackendForTests({getItem:async key=>records.get(key)??null,setItem:async(key,value)=>{records.set(key,value);},removeItem:async key=>{records.delete(key);},keys:async()=>[...records.keys()],compareAndSet:async(key,expected,value)=>{
    if((records.get(key)??null)!==expected)return false;records.set(key,value);return true;
  }});
  const original=await newWriteGeneration("shell-owner",new Uint8Array(32).fill(5));
  records.set(writeGenerationKey("shell-owner"),original);
  let release!:()=>void;const held=request("account-transition",()=>new Promise<void>(resolve=>{release=resolve;}));await flush(3);
  try {
    const root=await signedIn();state.loginOwner="replacement-owner";state.loginName="bob";state.keyByte=9;
    await press(root,"Sign in");
    await act(async()=>{release();await held;});await flush(25);
    expect(records.get(writeGenerationKey("shell-owner"))).toBe(original);
    expect(textOf(root)).toContain("Signed in as bob");
  } finally {release();await held;await flush(10);}
});

it("completes a queued verified login quietly after the session expires before its origin lock is granted",async()=>{
  const queues=new Map<string,Promise<unknown>>(),failures:unknown[]=[];
  const request=<T,>(name:string,callback:()=>Promise<T>):Promise<T>=>{
    const next=(queues.get(name)??Promise.resolve()).catch(()=>{}).then(callback);queues.set(name,next);
    void next.catch(error=>{failures.push(error);});return next;
  };
  vi.stubGlobal("navigator",{...navigator,locks:{request}});
  let release!:()=>void;const held=request("account-transition",()=>new Promise<void>(resolve=>{release=resolve;}));await flush(3);
  try {
    const root=await signedIn();stubFetch(()=>jsonResponse({detail:"expired"},{status:401}));
    await act(async()=>{await api.meta().catch(()=>{});});
    expect(vault.isUnlocked()).toBe(false);
    await act(async()=>{release();await held;});await flush(25);
    expect(failures).toEqual([]);expect(textOf(root)).toContain("Sign in");
    expect(textOf(root)).not.toContain("Today screen");
  } finally {release();await held;await flush(10);}
});

it("removes its expiry callback before an unrelated session can fail", async () => {
  const root = await signedIn();await act(async () => { root.unmount(); });
  vi.mocked(abortInFlightFlush).mockClear();vi.mocked(preserveActiveDraft).mockClear();
  stubFetch(() => jsonResponse({ detail: "expired", code: "unauthorized" }, { status: 401 }));
  await expect(api.meta()).rejects.toMatchObject({ status: 401 });
  expect(abortInFlightFlush).not.toHaveBeenCalled();expect(preserveActiveDraft).not.toHaveBeenCalled();
  expect(vault.isUnlocked()).toBe(true);
});

it("removes both browser-history listeners after locking the page", async () => {
  const root = await signedIn();await act(async () => { state.hooks.idle!("idle"); });
  for (const type of ["popstate", "hashchange"]) {
    await act(async () => { window.location.hash = "#/history";window.dispatchEvent({ type } as Event); });await flush(10);
    expect(textOf(root)).toContain("Sign in");expect(textOf(root)).not.toContain("History screen");
  }
});

it("stops visibility reconciliation as soon as its owner locks", async () => {
  const root = await signedIn();await act(async () => { state.hooks.idle!("idle"); });vi.mocked(reconcile).mockClear();
  vi.stubGlobal("document", { visibilityState: "visible" });
  await act(async () => { window.dispatchEvent({ type: "visibilitychange" } as Event); });await flush(10);
  expect(reconcile).not.toHaveBeenCalled();expect(textOf(root)).toContain("Sign in");
});

it("announces credential rotation detected during reconciliation", async () => {
  const root = await signedIn();vi.mocked(reconcile).mockResolvedValueOnce({ kind: "credentialRotated" });
  await act(async () => { window.dispatchEvent({ type: "online" } as Event); });await flush(10);
  expect(textOf(root)).toContain(t("app.noticeRotatedElsewhere"));expect(textOf(root)).toContain("Sign in");
});

it("shows the generic erasure caption for an initial untyped cleanup failure", async () => {
  state.failures = ["native failure without an Error object"];
  const root = await render(<App />);await flush(10);
  expect(textOf(root)).toContain(t("app.erasureIncomplete"));
});

it("keeps startup free of fabricated cleanup notices while native storage is still opening", async () => {
  let release!: (rows: Awaited<ReturnType<typeof resumeConfirmedErasures>>) => void;
  vi.mocked(resumeConfirmedErasures).mockImplementationOnce(() => new Promise(resolve => { release = resolve; }));
  const root = await render(<App />);
  try {
    expect(textOf(root)).not.toContain(t("app.erasureTitle"));expect(root.root.findAllByProps({role:"alert"})).toHaveLength(0);
  } finally { await act(async () => { release([]); });await flush(10); }
});

it("clears the old account caption before a replacement adoption fails", async () => {
  const root = await signedIn();await act(async () => { state.hooks.idle!("idle"); });
  vi.mocked(hasLocalRotation).mockRejectedValueOnce(new Error("A new adoption needs recovery"));
  await press(root,"Sign in");await flush(15);
  expect(textOf(root)).toContain("Settings screen");expect(textOf(root)).not.toContain("Signed in as");
});

it("assigns the usual success appearance to a refreshed question notice", async () => {
  const root = await signedIn();await press(root,"Question");await flush(10);await press(root,"Refresh question");
  const toast=root.root.findAllByProps({className:"toast"})[0]!;
  expect(toast.findAllByType("path").map(node=>node.props.d)).toEqual(["M5 12.5l4.5 4.5L19 7.5"]);
});

it("retains an existing sync notice when a later reconciliation is offline", async () => {
  const root = await signedIn();vi.mocked(reconcile).mockResolvedValueOnce({kind:"error",message:"Still awaiting a refresh"});
  await act(async () => { window.dispatchEvent({type:"online"} as Event); });await flush(10);
  vi.mocked(reconcile).mockResolvedValueOnce({kind:"offline"});
  await act(async () => { window.dispatchEvent({type:"online"} as Event); });await flush(10);
  expect(textOf(root)).toContain("Still awaiting a refresh");
});

it("keeps an old onboarding save from skipping a replacement session's introduction", async () => {
  state.seen=false;const root=await signedIn();let release!:()=>void;
  vi.mocked(markOnboardingSeen).mockImplementationOnce(()=>new Promise<void>(resolve=>{release=resolve;}));
  await press(root,"Finish introduction");await act(async()=>{state.hooks.idle!("idle");});
  await press(root,"Sign in");await flush(15);expect(textOf(root)).toContain("Finish introduction");
  await act(async()=>{release();});await flush(10);
  expect(textOf(root)).toContain("Finish introduction");expect(textOf(root)).not.toContain("Today screen");
});

it("keeps an old onboarding save from skipping a newly acquired session after remote deletion", async () => {
  state.seen=false;const root=await signedIn();let release!:()=>void;
  vi.mocked(markOnboardingSeen).mockImplementationOnce(()=>new Promise<void>(resolve=>{release=resolve;}));
  await press(root,"Finish introduction");
  stubFetch(()=>jsonResponse({detail:"deleted",code:"account_deleted"},{status:410}));
  await act(async()=>{await api.meta().catch(()=>{});});await flush(10);
  expect(textOf(root)).toContain("Sign in");
  stubFetch(()=>jsonResponse({}));await press(root,"Sign in");await flush(15);
  expect(textOf(root)).toContain("Finish introduction");
  await act(async()=>{release();});await flush(10);
  expect(textOf(root)).toContain("Finish introduction");expect(textOf(root)).not.toContain("Today screen");
});

it("does not fetch a successor's key envelope for a retired migration lookup",async()=>{
  let release!:(pending:boolean)=>void;
  vi.mocked(hasLocalRotation).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
  const root=await signedIn();
  stubFetch(()=>jsonResponse({detail:"expired"},{status:401}));
  await act(async()=>{await api.meta().catch(()=>{});});await flush(10);
  const fetch=stubFetch(()=>jsonResponse({salt:"successor-salt"}));
  await press(root,"Sign in");
  try {
    await act(async()=>{release(true);});await flush(20);
    expect(fetch).not.toHaveBeenCalled();expect(textOf(root)).toContain("Today screen");
  } finally {release(false);await flush(10);}
});

it.each(Array.from({length:24},(_,index)=>index+6))("dispatches local migration only with a live vault at native response boundary %s",async depth=>{
  vi.mocked(hasLocalRotation).mockResolvedValueOnce(true);
  const liveAtDispatch:boolean[]=[];
  vi.mocked(resumeLocalRotation).mockImplementationOnce(async()=>{
    liveAtDispatch.push(vault.isUnlocked()&&vault.ownerUserId()==="shell-owner");
  });
  const retire=(remaining:number):void=>{queueMicrotask(()=>{
    if(remaining>1)retire(remaining-1);
    else state.hooks.idle?.("idle");
  });};
  stubFetch(()=>new Response(new ReadableStream<Uint8Array>({start(controller){
    controller.enqueue(new TextEncoder().encode('{"salt":"confirmed-salt"}'));controller.close();retire(depth);
  }})));
  await signedIn();await flush(40);
  expect(liveAtDispatch).not.toContain(false);
});

it("keeps ownerless metadata intact when the volatile vault has already locked before signout",async()=>{
  const root=await signedIn();await kv.setItem("mindpattern.rekeyHint.null","retained legacy hint");
  vault.lock();await more(root,"Sign out (this device)");await flush(15);
  expect(await kv.getItem("mindpattern.rekeyHint.null")).toBe("retained legacy hint");
  expect(textOf(root)).toContain("Sign in");
});

it("keeps an old onboarding save from adopting a different unlocked account", async () => {
  state.seen=false;const root=await signedIn();let release!:()=>void;
  vi.mocked(markOnboardingSeen).mockImplementationOnce(()=>new Promise<void>(resolve=>{release=resolve;}));
  await press(root,"Finish introduction");
  const {setSession}=await import("../src/api/client");setSession("successor","different-owner","bob");vault.unlock({authKey:new Uint8Array(32).fill(7),dataKey:new Uint8Array(32).fill(8)},"different-owner");
  await act(async()=>{release();});await flush(10);
  expect(textOf(root)).toContain("Finish introduction");expect(textOf(root)).not.toContain("Today screen");
});

it("refuses to mark onboarding metadata while its unlocked vault has no verified owner", async () => {
  state.seen=false;const root=await signedIn();
  vault.unlock({authKey:new Uint8Array(32).fill(7),dataKey:new Uint8Array(32).fill(8)});
  vi.mocked(markOnboardingSeen).mockClear();await press(root,"Finish introduction");await flush(10);
  expect(markOnboardingSeen).not.toHaveBeenCalled();expect(textOf(root)).toContain("Finish introduction");
});

it("accepts another page's rotation packet only while its own session is active", async () => {
  const channels=new Set<Channel>();
  class Channel {
    onmessage:((event:{data:unknown})=>void)|null=null;
    constructor(readonly name:string){channels.add(this);}
    postMessage(data:unknown){for(const channel of channels)if(channel!==this&&channel.name===this.name)channel.onmessage?.({data});}
    close(){channels.delete(this);}
  }
  vi.stubGlobal("BroadcastChannel",Channel);const root=await render(<App />);
  await act(async()=>{await vi.advanceTimersByTimeAsync(50);});const other=new Channel("mindpattern-session-lockdown");
  const rotation={reason:"rotation",source_id:"another-page"};
  await act(async()=>{other.postMessage(rotation);});expect(textOf(root)).not.toContain(t("app.noticeRotatedElsewhere"));
  await press(root,"Sign in");await flush(15);
  await act(async()=>{other.postMessage(rotation);});await flush(10);
  expect(textOf(root)).toContain(t("app.noticeRotatedElsewhere"));expect(textOf(root)).toContain("Sign in");other.close();
});

it("expires each saved notice independently while retaining newer writing confirmations", async () => {
  const root = await signedIn();
  await press(root, "Commit online");
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  await press(root, "Park offline");
  await act(async () => { await vi.advanceTimersByTimeAsync(3199); });
  let notices = root.root.findAllByProps({ className: "toast" });
  expect(notices.map(textOfNode)).toEqual([t("app.saved"), t("app.savedOffline")]);
  await act(async () => { await vi.advanceTimersByTimeAsync(1); });
  notices = root.root.findAllByProps({ className: "toast" });
  expect(notices.map(textOfNode)).toEqual([t("app.savedOffline")]);
  await act(async () => { await vi.advanceTimersByTimeAsync(1000); });
  expect(root.root.findAllByProps({ className: "toast" })).toHaveLength(0);
});

it("keeps help reachable from each editor and returns to the same screen or opens the stored safety plan", async () => {
  const root = await signedIn();
  for (const [destination, button, screen] of [["Today", "Entry help", "Today"], ["Patterns", "Patterns help", "Patterns"], ["Measures", "Measures help", "Measures"], ["Safety plan", "Plan help", "Safety plan"]]) {
    if (destination === "Today" || destination === "Patterns") { await press(root, destination!); await flush(10); }
    else await more(root, destination!);
    await press(root, button!);
    expect(root.root.findAllByProps({ role: "dialog" })).toHaveLength(1);
    expect(textOf(root)).toContain(`${screen} screen`);
    await press(root, "Close");
    expect(root.root.findAllByProps({ role: "dialog" })).toHaveLength(0);
  }
  await press(root, "Get help"); await press(root, t("crisis.makePlan")); await flush(10);
  expect(root.root.findAllByProps({ role: "dialog" })).toHaveLength(0);
  expect(textOf(root)).toContain("Safety plan screen");
  await more(root, "Settings"); await press(root, "Open stored plan"); await flush(10);
  expect(textOf(root)).toContain("Safety plan screen");
  await more(root, "Question"); await press(root, "Refresh question");
  expect(textOf(root)).toContain("Question refreshed");
  await more(root, "Settings"); await press(root, "Finish password change"); await flush(10);
  expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false);
  expect(textOf(root)).toContain("Password changed");
});

it("bounds periodic queue retries to online live sessions and removes connectivity subscriptions after locking", async () => {
  const root = await signedIn(); vi.mocked(flushQueueOnReconnect).mockClear(); vi.mocked(reconcile).mockClear();
  const navigatorBefore = navigator;
  vi.stubGlobal("navigator", { ...navigatorBefore, locks: navigatorBefore.locks, onLine: false });
  await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
  expect(flushQueueOnReconnect).not.toHaveBeenCalled();
  vi.stubGlobal("navigator", { ...navigatorBefore, locks: navigatorBefore.locks, onLine: true });
  await act(async () => { await vi.advanceTimersByTimeAsync(30000); });
  expect(flushQueueOnReconnect).toHaveBeenCalledOnce();
  vi.stubGlobal("document", { visibilityState: "hidden" });
  await act(async () => { window.dispatchEvent({ type: "visibilitychange" } as Event); });
  expect(reconcile).not.toHaveBeenCalled();
  await act(async () => { state.hooks.idle!("idle"); });
  expect(abortInFlightFlush).toHaveBeenCalled();
  vi.mocked(flushQueueOnReconnect).mockClear();
  await act(async () => { window.dispatchEvent({ type: "online" } as Event); await vi.advanceTimersByTimeAsync(60000); });
  expect(flushQueueOnReconnect).not.toHaveBeenCalled(); expect(reconcile).not.toHaveBeenCalled();
  expect(textOf(root)).toContain("Sign in");
});

it("clears this browser's local flags and rekey hint during explicit device sign-out", async () => {
  const root = await signedIn();
  window.localStorage.setItem("mindpattern.private-flag", "old account");
  window.localStorage.setItem("unrelated-setting", "retain");
  await kv.setItem("mindpattern.rekeyHint.shell-owner", "old hint");
  await more(root, "Sign out (this device)"); await flush(20);
  expect(window.localStorage.getItem("mindpattern.private-flag")).toBeNull();
  expect(window.localStorage.getItem("unrelated-setting")).toBe("retain");
  expect(await kv.getItem("mindpattern.rekeyHint.shell-owner")).toBeNull();
  expect(textOf(root)).toContain("Sign in");
});

it.each([401, 410])("locks for authoritative HTTP %i and only seals live writing while its account still exists", async status => {
  const root = await signedIn(); vi.mocked(preserveActiveDraft).mockClear(); vi.mocked(preserveSafetyPlan).mockClear();
  stubFetch(() => jsonResponse({ detail: "expired", code: status === 410 ? "account_deleted" : "invalid_token" }, { status }));
  await act(async () => { await api.keyEnvelope().catch(() => {}); }); await flush(15);
  expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false); expect(textOf(root)).toContain("Sign in");
  const alert = root.root.findAllByProps({ role: "alert" }); expect(alert).toHaveLength(1);
  expect(textOfNode(alert[0])).toContain(t(status === 410 ? "app.noticeDeleted" : "app.noticeExpired"));
  if (status === 410) { expect(confirmRemoteLocalErasure).toHaveBeenCalledWith("shell-owner"); expect(preserveActiveDraft).not.toHaveBeenCalled(); expect(preserveSafetyPlan).not.toHaveBeenCalled(); }
  else { expect(preserveActiveDraft).toHaveBeenCalled(); expect(preserveSafetyPlan).toHaveBeenCalled(); }
});

it.each([new Error("Keep the encrypted originals"), "untyped recovery failure"])("opens Settings honestly when sign-in migration recovery fails", async failure => {
  vi.mocked(hasLocalRotation).mockRejectedValueOnce(failure);
  const root = await signedIn();
  expect(textOf(root)).toContain("Settings screen");
  expect(textOf(root)).toContain(failure instanceof Error ? failure.message : "Local key migration needs recovery. Your encrypted originals are retained.");
  expect(root.root.findAllByProps({role:"alert"})).toHaveLength(1);
  expect(textOf(root)).not.toContain("Signed in as");
});

it("resumes a pending migration before entering the journal and repeats onboarding after unreadable metadata", async () => {
  vi.mocked(hasLocalRotation).mockResolvedValueOnce(true);
  stubFetch(() => jsonResponse({ salt: "confirmed-salt" }));
  vi.mocked(hasSeenOnboarding).mockRejectedValueOnce(new Error("unreadable onboarding marker"));
  const root = await signedIn();
  expect(resumeLocalRotation).toHaveBeenCalledWith("shell-owner", expect.any(Uint8Array), "confirmed-salt");
  expect(textOf(root)).toContain("Finish introduction");
});

it.each([new Error("Cleanup permission denied"), "untyped cleanup failure"])("announces confirmation failures while retaining the account cleanup control", async failure => {
  state.erasures = [{ owner: "old-owner", remoteConfirmed: false }];
  vi.mocked(confirmLocalErasure).mockRejectedValueOnce(failure);
  const root = await render(<App />); await flush(10);
  const confirm = root.root.findAllByType("button").find(node => textOfNode(node).includes("I confirmed deletion"))!;
  await act(async () => { confirm.props.onClick(); }); await flush(10);
  expect(textOf(root)).toContain(failure instanceof Error ? failure.message : t("app.erasureIncomplete"));
  expect(textOf(root)).toContain("old-owner");
  expect(root.root.findAllByProps({ role: "alert" })).toHaveLength(1);
});

it("routes browser history events and removes their handlers after sign-out", async () => {
  const root = await signedIn();
  for (const event of ["popstate", "hashchange"]) {
    await act(async () => { window.location.hash = "#/history"; window.dispatchEvent({ type: event } as Event); });
    await flush(10); expect(textOf(root)).toContain("History screen");
    expect(root.root.findAllByType("nav")).toHaveLength(2);
    await press(root, "Today"); await flush(10);
  }
  await more(root, "Sign out (this device)");
  expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false);
  await act(async () => { window.location.hash = "#/share"; window.dispatchEvent({ type: "hashchange" } as Event); });
  expect(textOf(root)).toContain("Sign in"); expect(textOf(root)).not.toContain("Share screen");
});

it("applies first-run introduction and localized navigation live", async () => {
  state.seen = false;
  const root = await signedIn();
  expect(textOf(root)).toContain("Finish introduction");
  await press(root, "Finish introduction"); await flush(10);
  expect(textOf(root)).toContain("Today screen");
  await act(async () => { applyLanguagePref("es"); });
  expect(textOf(root)).toContain("Hoy");
  await act(async () => { applyLanguagePref("en"); });
  expect(textOf(root)).toContain("Today");
});

it("keeps a retired onboarding completion from reopening the signed-in interface", async () => {
  state.seen = false;
  const root = await signedIn();
  let finish!: () => void;
  vi.mocked(markOnboardingSeen).mockImplementationOnce(() => new Promise<void>(resolve => { finish = resolve; }));
  await press(root, "Finish introduction");
  expect(markOnboardingSeen).toHaveBeenCalledWith("shell-owner");
  await act(async () => { state.hooks.idle!("idle"); });
  expect(textOf(root)).toContain("Sign in");
  await act(async () => { finish(); });
  await flush(10);
  expect(hasSession()).toBe(false);
  expect(vault.isUnlocked()).toBe(false);
  expect(textOf(root)).toContain("Sign in");
  expect(textOf(root)).not.toContain("Today screen");
});

it("shows online/offline save notices, retains only the newest three, and expires each toast", async () => {
  const root = await signedIn(); vi.mocked(flushQueueOnReconnect).mockClear();
  await press(root, "Commit online");
  expect(flushQueueOnReconnect).toHaveBeenCalledOnce();
  expect(textOf(root)).toContain("Saved.");
  await press(root, "Park offline");
  expect(flushQueueOnReconnect).toHaveBeenCalledOnce();
  expect(textOf(root)).toContain("Saved offline");
  await press(root, "Commit online"); await press(root, "Park offline");
  const notices = root.root.findAllByType("div").filter((node) => node.props.className === "toast");
  expect(notices).toHaveLength(3);
  expect(notices.map(textOfNode).filter((text) => text.includes("Saved offline"))).toHaveLength(2);
  await act(async () => { await vi.advanceTimersByTimeAsync(4300); });
  expect(root.root.findAllByType("div").filter((node) => node.props.className === "toast")).toHaveLength(0);
});

it.each([["idle", "inactivity"], ["hidden", "background"], ["bfcache", "restored"]])("locks the active interface on a %s lifecycle event", async (reason, notice) => {
  const root = await signedIn();
  expect(state.hooks[reason!]).toBeTypeOf("function");
  await act(async () => { state.hooks[reason!]!(reason!); });
  expect(hasSession()).toBe(false); expect(vault.isUnlocked()).toBe(false);
  expect(textOf(root)).toContain("Sign in"); expect(textOf(root).toLowerCase()).toContain(notice!.toLowerCase());
});

it("reconciles on connectivity and visible-tab events, showing freshness/error outcomes or locking rotated credentials", async () => {
  const root = await signedIn();
  await act(async () => { window.dispatchEvent({ type: "online" } as Event); });
  await flush(10); expect(textOf(root)).toContain("freshness check");
  vi.mocked(reconcile).mockResolvedValue({ kind: "error", message: "Sync could not refresh" });
  vi.stubGlobal("document", { visibilityState: "visible" });
  await act(async () => { window.dispatchEvent({ type: "visibilitychange" } as Event); });
  await flush(10); expect(textOf(root)).toContain("Sync could not refresh");
  vi.mocked(reconcile).mockResolvedValue({ kind: "credentialRotated" });
  await act(async () => { window.dispatchEvent({ type: "online" } as Event); });
  await flush(10); expect(vault.isUnlocked()).toBe(false); expect(textOf(root)).toContain("Sign in");
});

it("keeps cleanup failures visible and retries unconfirmed account erasure through its confirmation control", async () => {
  state.failures = ["non-error storage failure"];
  state.pending = [{ owner: "old-owner", remoteConfirmed: false }, { owner: "confirmed-owner", remoteConfirmed: true }];
  state.erasures = [{ owner: "old-owner", remoteConfirmed: false }];
  const root = await render(<App />); await flush(10);
  expect(textOf(root)).toContain("old-owner");
  const confirms = root.root.findAllByType("button").filter((node) => textOfNode(node).includes("I confirmed deletion"));
  expect(confirms).toHaveLength(1);
  await act(async () => { confirms[0]!.props.onClick(); }); await flush(10);
  expect(textOf(root)).not.toContain("old-owner");
});
