import {afterEach,beforeEach,expect,it,vi} from "vitest";
import {getEventListeners} from "node:events";
import {api,auth,clearSession,detailToMessage,listEntriesWalk,normalizeApiBaseUrl,setSession,setSessionExpiredHandler} from "../src/api/client";
import {installSession,jsonResponse,resetTestState,stubFetch} from "./helpers/api";

beforeEach(()=>{resetTestState();installSession();});
afterEach(()=>{clearSession();setSessionExpiredHandler(null);vi.useRealTimers();vi.restoreAllMocks();vi.unstubAllGlobals();});
const settle=async()=>{for(let n=0;n<60;n++)await Promise.resolve();};
function observe<T>(promise:Promise<T>){const result:{settled:boolean;value?:T;error?:unknown}={settled:false};void promise.then(value=>{result.value=value;result.settled=true;},error=>{result.error=error;result.settled=true;});return result;}

it.each(["public","logout"])("preserves a native %s body read failure",async flow=>{
  const fault=new Error("connection lost during response");let source!:ReadableStreamDefaultController<Uint8Array>;
  stubFetch(()=>new Response(new ReadableStream({start(controller){source=controller;}})));
  const result=observe(flow==="public"?auth.meta():api.logout());
  try{await settle();source.error(fault);await settle();expect(result).toMatchObject({settled:true});expect(result.error).toBe(fault);}
  finally{try{source.close();}catch{/* already failed */}await settle();}
});
it("reports a logout body deadline instead of claiming revocation succeeded",async()=>{
  vi.useFakeTimers();let release!:(value:unknown)=>void;
  stubFetch(()=>({status:200,ok:true,url:"",headers:new Headers(),json:()=>new Promise(resolve=>{release=resolve;})}) as unknown as Response);
  const result=observe(api.logout());
  try{await settle();await vi.advanceTimersByTimeAsync(15000);await settle();expect(result).toMatchObject({settled:true,error:{name:"ApiError",status:0,message:"request timed out while reading response"}});expect(vi.getTimerCount()).toBe(0);}
  finally{release({});await settle();}
});
it.each([false,7,"unexpected"])("uses an object fallback for authenticated primitive JSON %s",async body=>{stubFetch(()=>jsonResponse(body));expect(await api.meta()).toEqual({});});
it("rejects an empty session token with actionable copy",()=>{expect(()=>setSession(" \t","next","next")).toThrow("invalid empty session token");});
it.each([()=>api.logout(),()=>api.exportAccountRaw()])("refuses a protected operation after signout",async invoke=>{clearSession();const fetch=stubFetch(()=>jsonResponse({}));await expect(invoke()).rejects.toMatchObject({name:"ApiError",status:0,message:"not signed in"});expect(fetch).not.toHaveBeenCalled();});

it("keeps only nonempty access-log cursors",async()=>{
  for(const cursor of ["  ","","cursor"]){const fetch=stubFetch((url,init)=>{expect(init.method).toBe("GET");expect(new URL(url).pathname).toBe("/api/v1/account/access-log");expect(new URL(url).searchParams.size).toBe(0);return jsonResponse([],{headers:{"X-Next-Cursor":cursor}});});expect(await api.accessLogPage()).toEqual({rows:[],nextCursor:cursor.trim()?cursor:null});expect(fetch).toHaveBeenCalledOnce();}
});
it.each(["0a".repeat(16)+"a","a"+"0a".repeat(16)])("refuses a consent id with an extra boundary character",id=>{const fetch=stubFetch(()=>new Response(null,{status:204}));expect(()=>api.rewrapConsent(id,"pub","key","proof")).toThrow("invalid consent id — refusing the request");expect(()=>api.revokeConsent(id,"proof")).toThrow("invalid consent id — refusing the request");expect(fetch).not.toHaveBeenCalled();});

it.each(["measures","consents"])("rejects malformed %s revisions before transport",async resource=>{
  const fetch=stubFetch(()=>jsonResponse([]));const invoke=resource==="measures"?api.listMeasuresPage:api.listConsentsPage;
  for(const expectedRevision of ["","-1","01","1e0","9223372036854775808","9".repeat(20)])await expect(invoke({expectedRevision})).rejects.toMatchObject({status:0,message:`invalid ${resource==="measures"?"measure":"consent"} page request`});expect(fetch).not.toHaveBeenCalled();
});
it("omits the initial measure offset and revision, then sends a pinned continuation",async()=>{
  let calls=0;stubFetch((url,init)=>{expect(init.method).toBe("GET");const p=new URL(url).searchParams;expect(p.get("limit")).toBe("100");expect(p.get("page_bytes")).toBe("2097152");if(++calls===1){expect(p.has("offset")).toBe(false);expect(p.has("expected_revision")).toBe(false);}else{expect(p.get("offset")).toBe("1");expect(p.get("expected_revision")).toBe("7");}return jsonResponse([],{headers:{"X-Measures-Revision":"7"}});});
  expect(await api.listMeasuresPage()).toEqual({measures:[],nextOffset:null,revision:"7"});expect(await api.listMeasuresPage({offset:1,expectedRevision:"7"})).toEqual({measures:[],nextOffset:null,revision:"7"});
});
it.each(["entries","measures","consents"])("rejects a %s continuation after an empty page",async resource=>{
  stubFetch(()=>jsonResponse([],{headers:{"X-Next-Offset":"0"}}));const invoke=resource==="entries"?()=>api.listEntriesPage():resource==="measures"?()=>api.listMeasuresPage():()=>api.listConsentsPage();await expect(invoke()).rejects.toMatchObject({status:0,message:`server returned an invalid ${resource} continuation`});
});
it("rejects a changed consent revision with the collection conflict contract",async()=>{stubFetch(()=>jsonResponse([],{headers:{"X-Consents-Revision":"8"}}));await expect(api.listConsentsPage({expectedRevision:"7"})).rejects.toMatchObject({status:409,code:"collection_changed",message:"consents changed while paging; retry the request"});});
it("fences the entire entry walk to the caller's current generation",async()=>{
  let current=true;const fetch=stubFetch(()=>{current=false;return jsonResponse([]);});await expect(listEntriesWalk(undefined,()=>current)).rejects.toMatchObject({status:0,message:"session ended"});expect(fetch).toHaveBeenCalledOnce();
});

it.each(["abort","cancel","done","failure"])("cleans a raw export body on %s",async outcome=>{
  vi.useFakeTimers();let source!:ReadableStreamDefaultController<Uint8Array>;const cancelled=vi.fn();const fault=new Error("export disconnected");
  stubFetch(()=>new Response(new ReadableStream({start(controller){source=controller;},cancel:cancelled})));
  const response=await api.exportAccountRaw();const reader=response.body!.getReader();const pending=observe(reader.read());
  try{
    await settle();
    if(outcome==="abort")clearSession();else if(outcome==="cancel")await reader.cancel("download abandoned");else if(outcome==="done")source.close();else source.error(fault);
    await settle();expect(pending.settled).toBe(true);expect(vi.getTimerCount()).toBe(0);
    if(outcome==="abort")expect(pending.error).toMatchObject({name:"ApiError",status:0,message:"session ended or response timed out"});else if(outcome==="failure")expect(pending.error).toBe(fault);else expect(pending.value).toEqual({done:true,value:undefined});
    if(outcome==="abort"||outcome==="cancel")expect(cancelled).toHaveBeenCalledOnce();
  }finally{try{source.close();}catch{/* settled */}clearSession();await settle();}
});
it("aborts an alternate raw export before its consumer begins",async()=>{
  vi.useFakeTimers();let release!:(value:string)=>void;
  stubFetch(()=>({status:200,ok:true,url:"",headers:new Headers(),text:()=>new Promise(resolve=>{release=resolve;})}) as unknown as Response);
  const response=await api.exportAccountRaw();clearSession();expect(vi.getTimerCount()).toBe(0);const result=observe(response.text());
  try{await settle();expect(result).toMatchObject({settled:true,error:{status:0,message:"session ended"}});expect(vi.getTimerCount()).toBe(0);}
  finally{release?.("{}");await settle();}
});
it("releases an empty native raw export's deadline before returning it",async()=>{
  vi.useFakeTimers();let signal!:AbortSignal;stubFetch((_url,init)=>{signal=init.signal!;return new Response(null);});
  const response=await api.exportAccountRaw();expect(response.body).toBeNull();expect(vi.getTimerCount()).toBe(0);await vi.advanceTimersByTimeAsync(120000);expect(signal.aborted).toBe(false);
});
it("cancels an alternate no-content body and returns the authenticated null contract",async()=>{
  vi.useFakeTimers();const cancelled=vi.fn();const body=new ReadableStream({cancel:cancelled});
  stubFetch(()=>({status:204,ok:true,url:"",headers:new Headers(),body,text:async()=>{throw new Error("No-content body must not be consumed");}}) as unknown as Response);
  expect(await api.meta()).toBeNull();await settle();expect(cancelled).toHaveBeenCalledOnce();expect(vi.getTimerCount()).toBe(0);
});
it("returns null for an ordinary authenticated native no-content response",async()=>{stubFetch(()=>new Response(null,{status:204}));expect(await api.meta()).toBeNull();});
it.each(["unauthorized","account_deleted","gone"])("reports a raw export %s with its own account identity",async code=>{
  const handler=vi.fn();setSessionExpiredHandler(handler);const status=code==="unauthorized"?401:410;
  stubFetch(()=>jsonResponse({detail:"unavailable",code},{status}));await expect(api.exportAccountRaw()).rejects.toMatchObject({status,code,message:status===401?"session ended":"unavailable"});
  expect(handler).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({status,code}),{userId:"user-1",origin:"http://localhost:5173",accountDeleted:status===410});
});
it.each([401,410])("can reject a native empty export (%s) without a notification callback",async status=>{
  setSessionExpiredHandler(null);stubFetch(()=>new Response(null,{status}));await expect(api.exportAccountRaw()).rejects.toMatchObject({status,message:status===401?"session ended":"request failed (410)"});
});
it("classifies legacy gone as deletion only on the explicit account route",async()=>{
  const handler=vi.fn();setSessionExpiredHandler(handler);stubFetch(()=>jsonResponse({detail:"deleted",code:"gone"},{status:410}));
  await expect(api.deleteAccount("proof")).rejects.toMatchObject({status:410,code:"gone"});expect(handler).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({status:410,code:"gone"}),{userId:"user-1",origin:"http://localhost:5173",accountDeleted:true});
});
it("keeps exactly two hundred readable error characters without adding an ellipsis",()=>{const text="a".repeat(200);expect(detailToMessage(text,400)).toBe(text);expect(detailToMessage("ftp://opaque keep",400)).toBe("keep");});
it("uses the explicit GET method and omits an absent entry date filter",async()=>{
  stubFetch((url,init)=>{expect(init.method).toBe("GET");expect(new URL(url).searchParams.has("since")).toBe(false);return jsonResponse([]);});expect(await api.listEntriesPage()).toEqual({entries:[],nextOffset:null,revision:undefined});
});
it("uses the explicit consent page GET method and full snapshot terminal contract",async()=>{
  const rows=Array.from({length:200},(_,n)=>({id:String(n)}));stubFetch((_url,init)=>{expect(init.method).toBe("GET");return jsonResponse(rows,{headers:{"X-Consents-Revision":"7"}});});expect(await api.listConsentsPage()).toEqual({consents:rows,nextOffset:null,revision:"7"});
});
it.each(["account_deleted","gone"])("can reject a deleted raw export (%s) without a callback",async code=>{setSessionExpiredHandler(null);stubFetch(()=>jsonResponse({detail:"deleted",code},{status:410}));await expect(api.exportAccountRaw()).rejects.toMatchObject({status:410,message:"deleted",code});});
it("keeps a successful error-code payload separate from account death",async()=>{
  const handler=vi.fn();setSessionExpiredHandler(handler);stubFetch(()=>jsonResponse({code:"account_deleted"}));expect(await api.meta()).toEqual({code:"account_deleted"});expect(handler).not.toHaveBeenCalled();
  stubFetch(()=>jsonResponse({code:"gone"}));expect(await api.deleteAccount("proof")).toEqual({code:"gone"});expect(handler).not.toHaveBeenCalled();
});
it("passes the complete nondeleted identity when an ordinary bearer expires",async()=>{const handler=vi.fn();setSessionExpiredHandler(handler);stubFetch(()=>jsonResponse({detail:"expired",code:"unauthorized"},{status:401}));await expect(api.meta()).rejects.toMatchObject({status:401});expect(handler).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({status:401,code:"unauthorized"}),{userId:"user-1",origin:"http://localhost:5173",accountDeleted:false});});
it("keeps an unrelated account lifecycle 410 separate from confirmed deletion",async()=>{const handler=vi.fn();setSessionExpiredHandler(handler);stubFetch(()=>jsonResponse({detail:"absent",code:"not_found"},{status:410}));await expect(api.deleteAccount("proof")).rejects.toMatchObject({status:410,code:"not_found"});expect(handler).not.toHaveBeenCalled();});
it("releases a completed alternate response's deadline and old-session cancellation link",async()=>{
  vi.useFakeTimers();let signal!:AbortSignal;stubFetch((_url,init)=>{signal=init.signal!;return {status:200,ok:true,url:"",headers:new Headers(),text:async()=>'{"complete":true}'} as unknown as Response;});expect(await api.meta()).toEqual({complete:true});expect(vi.getTimerCount()).toBe(0);clearSession();expect(signal.aborted).toBe(false);
});
it("releases a proactive token expiry timer when the account signs out",async()=>{vi.useFakeTimers();const handler=vi.fn();setSessionExpiredHandler(handler);setSession("timed","owner","alice",3600);expect(vi.getTimerCount()).toBe(1);clearSession();expect(vi.getTimerCount()).toBe(0);await vi.advanceTimersByTimeAsync(3600000);expect(handler).not.toHaveBeenCalled();});
it.each([1,2,3])("refuses content when an alternate body retires its owner at microtask boundary %s",async depth=>{
  const queue=(remaining:number):void=>{queueMicrotask(()=>{if(remaining===1)clearSession();else queue(remaining-1);});};
  stubFetch(()=>({status:200,ok:true,url:"",headers:new Headers(),text:()=>Promise.resolve().then(()=>{queue(depth);return '{"secret":"old account"}';})}) as unknown as Response);
  await expect(api.meta()).rejects.toMatchObject({name:"ApiError",status:0,message:depth===2?"session ended or response timed out":"session ended"});
});

it.each(["public","logout"])("keeps a %s header deadline distinct from a connection failure",async flow=>{
  vi.useFakeTimers();
  stubFetch((_url,init)=>new Promise((_resolve,reject)=>{init.signal!.addEventListener("abort",()=>reject(new DOMException("aborted","AbortError")),{once:true});}));
  const result=observe(flow==="public"?auth.meta():api.logout());
  await settle();await vi.advanceTimersByTimeAsync(15000);await settle();
  expect(result).toMatchObject({settled:true,error:{status:0,message:"request timed out after 15s"}});
  expect(vi.getTimerCount()).toBe(0);
});
it.each(["public","logout"])("keeps a %s response origin refusal distinct from a connection failure",async flow=>{
  stubFetch(()=>{const response=jsonResponse({});Object.defineProperty(response,"url",{value:"https://foreign.example/api/v1/meta"});return response;});
  await expect(flow==="public"?auth.meta():api.logout()).rejects.toMatchObject({status:0,message:"server redirected the request to a different origin"});
});
it("normalizes non-ASCII outside whitespace before parsing the configured server",()=>{
  // URL itself strips ASCII whitespace only; user-pasted NBSP is trimmed by the client.
  expect(normalizeApiBaseUrl("\u00a0http://localhost:5173\u00a0")).toBe("http://localhost:5173");
});
it("preserves the empty URL sentinel and native scheme-relative parsing",()=>{
  expect(normalizeApiBaseUrl("")).toBe("");
  expect(normalizeApiBaseUrl("   ")).toBe("");
  expect(normalizeApiBaseUrl("https:api.example/base")).toBe("https://api.example/base");
});
it("removes a complete URL while retaining text after its boundary",()=>{
  expect(detailToMessage("https://opaque.example/path keep",400)).toBe("keep");
  expect(detailToMessage("http:// words",400)).toBe("http:// words");
  expect(detailToMessage("http://opaque.example/path keep",400)).toBe("keep");
});
it("keeps raw export transport free of ambient browser credentials",async()=>{
  const fetch=stubFetch((_url,init)=>{expect(init.credentials).toBe("omit");expect(init.redirect).toBe("error");expect(init.cache).toBe("no-store");expect(init.referrerPolicy).toBe("no-referrer");return new Response(null);});
  expect((await api.exportAccountRaw()).body).toBeNull();expect(fetch).toHaveBeenCalledOnce();
});
it("allows a native export consumer to wrap its standard body method",async()=>{
  stubFetch(()=>new Response("encrypted export"));const response=await api.exportAccountRaw();
  const nativeRead=response.text.bind(response);const consumed=vi.fn();
  Object.defineProperty(response,"text",{configurable:true,value:async()=>{consumed();return nativeRead();}});
  expect(await response.text()).toBe("encrypted export");expect(consumed).toHaveBeenCalledOnce();
});
it("releases a pending fetch deadline as soon as its session retires",async()=>{
  vi.useFakeTimers();let release!:(response:Response)=>void;
  stubFetch(()=>new Promise<Response>(resolve=>{release=resolve;}));const result=observe(api.meta());
  try {
    await settle();expect(vi.getTimerCount()).toBe(1);clearSession();expect(vi.getTimerCount()).toBe(0);
    release(new Response('{}'));await settle();expect(result).toMatchObject({settled:true,error:{status:0,message:"session ended"}});
  } finally { release(new Response('{}'));await settle(); }
});
it("does not notify proactive expiry again after HTTP rejection already tripped its one-shot latch",async()=>{
  vi.useFakeTimers();const handler=vi.fn();setSessionExpiredHandler(handler);setSession("timed","owner","alice",15);
  stubFetch(()=>jsonResponse({detail:"expired",code:"unauthorized"},{status:401}));
  await expect(api.meta()).rejects.toMatchObject({status:401});expect(handler).toHaveBeenCalledOnce();
  await vi.advanceTimersByTimeAsync(15000);expect(handler).toHaveBeenCalledOnce();
});
it("releases a body-method abort subscription after native consumption completes",async()=>{
  let signal!:AbortSignal;stubFetch((_url,init)=>{signal=init.signal!;return new Response("encrypted export");});
  const response=await api.exportAccountRaw();const before=getEventListeners(signal,"abort").length;
  expect(await response.text()).toBe("encrypted export");await settle();
  expect(getEventListeners(signal,"abort").length).toBe(before);
});
it("releases a hung alternate body's native abort subscription at its deadline",async()=>{
  vi.useFakeTimers();let signal!:AbortSignal,release!:(text:string)=>void;
  stubFetch((_url,init)=>{signal=init.signal!;return {status:200,ok:true,url:"",headers:new Headers(),text:()=>new Promise<string>(resolve=>{release=resolve;})} as unknown as Response;});
  const result=observe(api.meta());
  try {
    await settle();expect(getEventListeners(signal,"abort").length).toBeGreaterThan(0);
    await vi.advanceTimersByTimeAsync(15000);await settle();
    expect(result).toMatchObject({settled:true,error:{status:0,message:"request timed out while reading response"}});
    expect(getEventListeners(signal,"abort")).toHaveLength(0);
  } finally { release('{}');await settle(); }
});
it("releases an interrupted native raw stream's abort subscription",async()=>{
  vi.useFakeTimers();let signal!:AbortSignal,source!:ReadableStreamDefaultController<Uint8Array>;
  stubFetch((_url,init)=>{signal=init.signal!;return new Response(new ReadableStream({start(controller){source=controller;}}));});
  const response=await api.exportAccountRaw();const reader=response.body!.getReader();const result=observe(reader.read());
  try {
    await settle();expect(getEventListeners(signal,"abort").length).toBeGreaterThan(0);
    await vi.advanceTimersByTimeAsync(120000);await settle();
    expect(result).toMatchObject({settled:true,error:{status:0,message:"session ended or response timed out"}});
    expect(getEventListeners(signal,"abort")).toHaveLength(0);
  } finally { try{source.close();}catch{/* cancelled */}reader.releaseLock();await settle(); }
});
it("accepts a successful JSON logout acknowledgement",async()=>{
  stubFetch(()=>jsonResponse({revoked:true}));expect(await api.logout()).toBeNull();
});
it.each(["measures","consents"])("accepts the short %s revision 99 without a lexical maximum-prefix comparison",async collection=>{
  const header=collection==="measures"?"X-Measures-Revision":"X-Consents-Revision";
  stubFetch(()=>jsonResponse([],{headers:{[header]:"99"}}));
  const result=collection==="measures"?await api.listMeasuresPage({expectedRevision:"99"}):await api.listConsentsPage({expectedRevision:"99"});
  expect(result.revision).toBe("99");expect(result.nextOffset).toBeNull();
});
