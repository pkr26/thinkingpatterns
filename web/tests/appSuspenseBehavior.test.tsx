import {act} from "react";
import {afterEach,expect,it,vi} from "vitest";
import {App} from "../src/App";
import {flush,press,render,textOf} from "./helpers/rtr";
import {resetTestState,jsonResponse,stubFetch} from "./helpers/api";

const chunk=vi.hoisted(()=>{
  let release!:()=>void;
  const promise=new Promise<void>(resolve=>{release=resolve;});
  return {promise,release};
});
vi.mock("../src/views/Entry",async()=>{
  await chunk.promise;
  return {EntryView:()=> <p>Loaded journal</p>};
});
vi.mock("../src/views/LoginView",async()=>{
  const {setSession}=await import("../src/api/client");
  const {vault}=await import("../src/vault");
  return {LoginView:({onSuccess}:any)=><button onClick={()=>{
    setSession("chunk-token","chunk-owner","alice");
    vault.unlock({authKey:new Uint8Array(32).fill(4),dataKey:new Uint8Array(32).fill(5)},"chunk-owner");
    void onSuccess({userId:"chunk-owner",username:"alice"});
  }}>Sign in</button>};
});
vi.mock("../src/views/Onboarding",()=>({hasSeenOnboarding:async()=>true,markOnboardingSeen:async()=>{},clearOnboardingSeen:async()=>{},Onboarding:()=>null}));
vi.mock("../src/localRotation",()=>({hasLocalRotation:async()=>false,resumeLocalRotation:async()=>{}}));
vi.mock("../src/localErasure",()=>({resumeConfirmedErasures:async()=>[],pendingLocalErasures:async()=>[],confirmRemoteLocalErasure:async()=>{},confirmLocalErasure:async()=>{}}));
vi.mock("../src/offlineQueue",()=>({abortInFlightFlush:()=>{},flushQueueOnReconnect:async()=>{}}));
vi.mock("../src/patternMutes",()=>({adoptLegacyPlaintextMutes:async()=>{}}));
afterEach(()=>{chunk.release();vi.useRealTimers();vi.restoreAllMocks();vi.unstubAllGlobals();});

it("announces a held native page chunk before rendering its journal",async()=>{
  resetTestState();vi.useFakeTimers();stubFetch(()=>jsonResponse({}));window.location.hash="#/today";
  const root=await render(<App/>);
  try {
    await act(async()=>{await vi.advanceTimersByTimeAsync(40);});await press(root,"Sign in");await flush(15);
    expect(root.root.findAllByProps({role:"status"}).some(node=>node.children.join("").includes("Loading…"))).toBe(true);
    expect(textOf(root)).not.toContain("Loaded journal");
    await act(async()=>{chunk.release();});await flush(15);
    expect(textOf(root)).toContain("Loaded journal");
  } finally {chunk.release();await flush(5);}
});
