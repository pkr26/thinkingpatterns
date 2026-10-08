import { getEventListeners } from "node:events";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, clearSession, setSession } from "../src/api";

let sessionSignal:AbortSignal;
beforeEach(()=>{
  clearSession();vi.useFakeTimers();const NativeController=AbortController,created:AbortSignal[]=[];
  vi.stubGlobal("AbortController",class extends NativeController{constructor(){super();created.push(this.signal);}});
  setSession("native-resource-owner","https://clinic.example.com");sessionSignal=created[0]!;
});
afterEach(()=>{clearSession();vi.unstubAllGlobals();vi.useRealTimers();});
it.each(["complete","empty","no-content","server-fault","reader-fault"])("releases the live session's native abort subscription after a %s response",async kind=>{
  vi.stubGlobal("fetch",vi.fn(async()=>{
    if(kind==="no-content")return new Response(null,{status:204});
    if(kind==="reader-fault")return new Response(new ReadableStream({start(target){target.error(new Error("native body failed"));}}));
    return new Response(kind==="empty"?null:kind==="server-fault"?'{"detail":"unavailable"}':'{"completed":true}',{status:kind==="server-fault"?500:200});
  }));
  await api.me().catch(()=>{});
  expect(getEventListeners(sessionSignal,"abort")).toHaveLength(0);expect(vi.getTimerCount()).toBe(0);
});
it("releases the native session subscription after refusing a body beyond the clinician response budget",async()=>{
  vi.stubGlobal("fetch",vi.fn(async()=>new Response(new ReadableStream<Uint8Array>({start(target){target.enqueue(new Uint8Array(16*1024*1024+1));target.close();}}))));
  await expect(api.me()).rejects.toMatchObject({status:0,message:"Server response exceeded this client's safe size limit."});
  expect(getEventListeners(sessionSignal,"abort")).toHaveLength(0);expect(vi.getTimerCount()).toBe(0);
});
it("removes the completed request subscription before a later logout can abort its native transport",async()=>{
  let transport!:AbortSignal;vi.stubGlobal("fetch",vi.fn(async(_url,init)=>{transport=init.signal;return new Response('{"completed":true}');}));
  expect(await api.me()).toEqual({completed:true});clearSession();expect(transport.aborted).toBe(false);
});
