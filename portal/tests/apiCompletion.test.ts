import {afterEach,beforeEach,expect,it,vi} from "vitest";
import {api,auth,normalizeApiBaseUrl,clearSession,setSession} from "../src/api";
beforeEach(()=>{clearSession();setSession("bounded-consumer","https://clinic.example.com");vi.useFakeTimers();});
afterEach(()=>{clearSession();vi.unstubAllGlobals();vi.useRealTimers();});
it("delivers complete native JSON bodies before displaying a successful server result",async()=>{
 const body=new ReadableStream<Uint8Array>({start(controller){controller.enqueue(new TextEncoder().encode('{"complete":'));controller.enqueue(new TextEncoder().encode('true}'));controller.close();}});
 vi.stubGlobal("fetch",vi.fn(async()=>new Response(body,{headers:{"Content-Type":"application/json"}})));
 const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};void api.me().then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});
 for(let step=0;step<200;step++)await Promise.resolve();
 expect(outcome.settled).toBe(true);expect(outcome.error).toBeUndefined();expect(outcome.value).toEqual({complete:true});expect(vi.getTimerCount()).toBe(0);
});
it("delivers a native server-body fault promptly instead of leaving its consumer pending",async()=>{
 const fault=new Error("server body broke");
 const body=new ReadableStream<Uint8Array>({start(controller){controller.error(fault);}});
 vi.stubGlobal("fetch",vi.fn(async()=>new Response(body)));
 const outcome:{settled:boolean,error?:unknown}={settled:false};void api.me().then(()=>{outcome.settled=true;},error=>{outcome.settled=true;outcome.error=error;});
 for(let step=0;step<200;step++)await Promise.resolve();expect(outcome.settled).toBe(true);expect(outcome.error).toBe(fault);expect(vi.getTimerCount()).toBe(0);
});

it("rejects a single native chunk beyond the response budget before a consumer can accept it",async()=>{
 const limit=16*1024*1024;const cancelled:unknown[]=[];
 const body=new ReadableStream<Uint8Array>({start(controller){const chunk=new Uint8Array(limit+1).fill(32);chunk[0]=123;chunk[1]=125;controller.enqueue(chunk);controller.close();},cancel(reason){cancelled.push(reason);}});
 vi.stubGlobal("fetch",vi.fn(async()=>new Response(body)));
 const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};void api.me().then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});
 for(let step=0;step<300;step++)await Promise.resolve();expect(outcome.settled).toBe(true);expect(outcome.value).toBeUndefined();expect(outcome.error).toMatchObject({name:"ApiError",status:0,message:"Server response exceeded this client's safe size limit."});expect(vi.getTimerCount()).toBe(0);
});

it("normalizes copied HTTPS paths after WHATWG URL parsing",()=>{
 expect(normalizeApiBaseUrl(String.raw`https:\\clinic.example.com/path/child///`)).toBe("https://clinic.example.com/path/child");
 expect(normalizeApiBaseUrl("https://clinic.example.com/path///")).toBe("https://clinic.example.com/path");
});

it.each(["signin", "retired bearer"])("reports a body deadline to an unauthenticated %s consumer",async mode=>{
 clearSession();const body=new ReadableStream<Uint8Array>({start(controller){controller.enqueue(new TextEncoder().encode('{"partial":'));}});
 vi.stubGlobal("fetch",vi.fn(async()=>new Response(body)));const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};const promise=mode==="signin"?auth.saltFor("https://clinic.example.com","clinician"):auth.logoutBearer("https://clinic.example.com","retired-token");
 void promise.then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});for(let step=0;step<80;step++)await Promise.resolve();expect(outcome.settled).toBe(false);vi.advanceTimersByTime(15_000);for(let step=0;step<200;step++)await Promise.resolve();expect(outcome.settled).toBe(true);expect(outcome.value).toBeUndefined();expect(outcome.error).toMatchObject({name:"ApiError",status:0});expect(vi.getTimerCount()).toBe(0);
});

it("settles an already expired late fetch before attempting its held alternate body",async()=>{
 let finishFetch!:(response:Response)=>void,finishBody!:(value:unknown)=>void;const body=new Promise(resolve=>{finishBody=resolve;});vi.stubGlobal("fetch",vi.fn(()=>new Promise<Response>(resolve=>{finishFetch=resolve;})));
 const outcome:{settled:boolean,error?:unknown}={settled:false};void api.me().then(()=>{outcome.settled=true;},error=>{outcome.settled=true;outcome.error=error;});vi.advanceTimersByTime(15_000);
 try{finishFetch({status:200,ok:true,url:"https://clinic.example.com/api/v1/me",headers:new Headers(),json:()=>body} as unknown as Response);for(let step=0;step<100;step++)await Promise.resolve();expect(outcome.settled).toBe(true);expect(outcome.error).toMatchObject({name:"ApiError",status:0,message:"request timed out while reading response"});expect(vi.getTimerCount()).toBe(0);}finally{finishBody({late:true});for(let step=0;step<20;step++)await Promise.resolve();}
});

it.each(["salt","logout"])("preserves the typed origin rejection before parsing an unauthenticated %s response",async mode=>{
 vi.stubGlobal("fetch",vi.fn(async()=>({status:200,ok:true,url:"https://another-origin.example/api/v1/auth",headers:new Headers(),json:async()=>({salt:"sealed"})} as unknown as Response)));
 const request=mode==="salt"?auth.saltFor("https://clinic.example.com","clinician"):api.logout();await expect(request).rejects.toMatchObject({name:"ApiError",status:0,message:"server redirected the request to a different origin"});
});

it("reports the native fetch deadline to an unauthenticated sign-in consumer",async()=>{
 clearSession();let release!:(response:Response)=>void;vi.stubGlobal("fetch",vi.fn((_url,init:RequestInit)=>new Promise<Response>((resolve,reject)=>{release=resolve;init.signal!.addEventListener("abort",()=>reject(new DOMException("The operation was aborted","AbortError")),{once:true});})));
 const outcome:{settled:boolean,error?:unknown}={settled:false};void auth.saltFor("https://clinic.example.com","clinician").then(()=>{outcome.settled=true;},error=>{outcome.settled=true;outcome.error=error;});
 try{vi.advanceTimersByTime(15_000);for(let step=0;step<100;step++)await Promise.resolve();expect(outcome.settled).toBe(true);expect(outcome.error).toMatchObject({name:"ApiError",status:0,message:"request timed out after 15s"});expect(vi.getTimerCount()).toBe(0);}finally{release(new Response('{}'));for(let step=0;step<20;step++)await Promise.resolve();}
});
