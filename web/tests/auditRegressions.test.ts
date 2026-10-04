import { afterEach, describe, it, expect, vi } from "vitest";
import React, { act } from "react";
import RTR from "react-test-renderer";
import { useRecorder, type UseRecorder } from "../src/audio/recorder";
import { enqueue, queueLength } from "../src/offlineQueue";
import { setKvBackendForTests } from "../src/kvstore";
import { api, setSession, clearSession, setSessionExpiredHandler, REQUEST_TIMEOUT_MS } from "../src/api/client";
import { withLock } from "../src/platform";
afterEach(() => { vi.useRealTimers(); vi.unstubAllGlobals(); vi.restoreAllMocks(); setKvBackendForTests(null); clearSession(); setSessionExpiredHandler(null); });
function deferred<T>() { let resolve!: (value:T)=>void; const promise=new Promise<T>(r=>resolve=r); return {promise,resolve}; }
describe("October audit regression: durable custody and operation lifetime",()=>{
 it("late microphone permission after unmount stops the late stream before recording", async()=>{
  vi.useFakeTimers(); const permission=deferred<MediaStream>(); const stopped=vi.fn(); const stream={getTracks:()=>[{stop:stopped}]} as unknown as MediaStream;
  let starts=0;
  class Recorder { static isTypeSupported(){return true;} state="inactive"; mimeType="audio/webm"; onstop=null; ondataavailable=null; onerror=null; constructor(_s:unknown){} start(){starts++;this.state="recording";} stop(){this.state="inactive";} }
  vi.stubGlobal("MediaRecorder", Recorder); vi.stubGlobal("navigator",{mediaDevices:{getUserMedia:()=>permission.promise}});
  Object.assign(window,{setInterval,clearInterval,requestAnimationFrame:()=>0,cancelAnimationFrame:()=>{}});
  let latest!:UseRecorder; function Probe(){latest=useRecorder({unsupported:"unsupported",permissionDenied:"denied",failed:"failed"});return null;}
  let root!:ReturnType<typeof RTR.create>; await act(async()=>{root=RTR.create(React.createElement(Probe));});
  let pending!:Promise<void>; await act(async()=>{pending=latest.start();}); await act(async()=>{root.unmount();});
  await act(async()=>{permission.resolve(stream);await pending;});
  expect(starts).toBe(0); expect(stopped).toHaveBeenCalledTimes(1);vi.clearAllTimers();
 });
 it("two starts while permission is pending produce only one permission acquisition",async()=>{
  vi.useFakeTimers(); const a=deferred<MediaStream>(),b=deferred<MediaStream>(); const stops=[vi.fn(),vi.fn()]; let calls=0;let starts=0;
  class Recorder { static isTypeSupported(){return true;} state="inactive"; mimeType="audio/webm"; onstop=null;ondataavailable=null;onerror=null;constructor(_s:unknown){}start(){starts++;this.state="recording";}stop(){this.state="inactive";} }
  vi.stubGlobal("MediaRecorder",Recorder);vi.stubGlobal("navigator",{mediaDevices:{getUserMedia:()=>calls++===0?a.promise:b.promise}});Object.assign(window,{setInterval,clearInterval,requestAnimationFrame:()=>0,cancelAnimationFrame:()=>{}});
  let latest!:UseRecorder;function Probe(){latest=useRecorder({unsupported:"u",permissionDenied:"d",failed:"f"});return null;}let root!:ReturnType<typeof RTR.create>;await act(async()=>{root=RTR.create(React.createElement(Probe));});
  let first!:Promise<void>,second!:Promise<void>;await act(async()=>{first=latest.start();second=latest.start();});await act(async()=>{a.resolve({getTracks:()=>[{stop:stops[0]}]} as unknown as MediaStream);b.resolve({getTracks:()=>[{stop:stops[1]}]} as unknown as MediaStream);await Promise.all([first,second]);});await act(async()=>{root.unmount();});
  expect(starts).toBe(1);expect(calls).toBe(1);expect(stops[0]).toHaveBeenCalled();vi.clearAllTimers();
 });
 it("enqueue refuses success when storage rejects every write",async()=>{
  vi.stubGlobal("navigator",{locks:{request:(_n:string,fn:()=>Promise<unknown>)=>fn()}});setKvBackendForTests({getItem:async()=>null,setItem:async()=>{throw new Error("QuotaExceededError");},removeItem:async()=>{}});
  await expect(enqueue({userId:"audit-storage",clientEntryId:"audit-entry",blobB64:"ciphertext",entryDate:"2026-10-03"})).rejects.toThrow("not saved");expect(await queueLength("audit-storage")).toBe(0);
 });
 it("real 401 export Response fires the expiry handler",async()=>{
  setSession("audit-token","audit-user","audit-name");const expired=vi.fn();setSessionExpiredHandler(expired);vi.stubGlobal("fetch",vi.fn(async()=>new Response(JSON.stringify({detail:"expired",code:"unauthorized"}),{status:401})));
  await expect(api.exportAccountRaw()).rejects.toMatchObject({status:401});expect(expired).toHaveBeenCalledTimes(1);
 });
 it("request timeout and session abort remain armed while consuming a response body",async()=>{
  vi.useFakeTimers();setSession("audit-token","audit-user","audit-name");const body=deferred<string>();let signal!:AbortSignal;vi.stubGlobal("fetch",vi.fn(async(_url,init)=>{signal=init.signal;return {status:200,ok:true,url:"",headers:new Headers(),text:()=>body.promise};}));
  const pending=api.insights();const assertion=expect(pending).rejects.toThrow("timed out");await Promise.resolve();await Promise.resolve();await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS+10);expect(signal.aborted).toBe(true);await assertion;clearSession();body.resolve("{}");

 });
 it("storage refuses an unsupported shared lock without executing either mutation",async()=>{
  vi.stubGlobal("navigator",{});const ran=vi.fn(async()=>{});
  const results=await Promise.allSettled([withLock("audit-long-lock",ran),withLock("audit-long-lock",ran)]);
  expect(results.every(result=>result.status==="rejected")).toBe(true);expect(ran).not.toHaveBeenCalled();
 });
});

describe("native bounded streams",()=>{
 it("accepts 204 acknowledgments when a proxy exposes an empty response stream",async()=>{
  setSession("audit-token","audit-user","audit-name");const cancelled=vi.fn();const response=new Response(new ReadableStream({cancel:cancelled}));Object.defineProperty(response,"status",{value:204});vi.stubGlobal("fetch",vi.fn(async()=>response));
  await expect(api.deleteEntry("entry-id")).resolves.toBeNull();expect(cancelled).toHaveBeenCalledTimes(1);
 });
 it("raw export body readers are interrupted by logout even if fetch ignores its signal",async()=>{
  setSession("audit-token","audit-user","audit-name");
  const source=new ReadableStream<Uint8Array>({pull:()=>new Promise(()=>{})});
  vi.stubGlobal("fetch",vi.fn(async()=>new Response(source)));
  const response=await api.exportAccountRaw();const pending=response.body!.getReader().read();const rejected=expect(pending).rejects.toThrow("session ended");clearSession();await rejected;
 });
 it("caps streamed JSON bytes before untrusted parsing",async()=>{
  setSession("audit-token","audit-user","audit-name");vi.stubGlobal("fetch",vi.fn(async()=>new Response(new Uint8Array(17*1024*1024))));await expect(api.insights()).rejects.toThrow("safe size limit");
 });
});
