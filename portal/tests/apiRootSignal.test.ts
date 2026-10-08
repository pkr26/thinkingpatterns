// @vitest-environment jsdom
import {afterEach,expect,it,vi} from "vitest";
import {auth,clearSession} from "../src/api";
afterEach(()=>{clearSession();vi.unstubAllGlobals();vi.useRealTimers();});
it("settles an unauthenticated native browser body deadline without an uncaught signal-listener exception",async()=>{
 clearSession();vi.useFakeTimers();vi.stubGlobal("AbortController",window.AbortController);
 const errors:unknown[]=[];const observe=(event:ErrorEvent)=>{errors.push(event.error);event.preventDefault();};window.addEventListener("error",observe);
 const body=new ReadableStream<Uint8Array>({start(controller){controller.enqueue(new TextEncoder().encode('{"partial":'));}});
 vi.stubGlobal("fetch",vi.fn(async()=>new Response(body)));
 const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};void auth.saltFor("https://clinic.example.com","clinician").then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});
 try{for(let i=0;i<100;i++)await Promise.resolve();expect(outcome.settled).toBe(false);vi.advanceTimersByTime(15_000);for(let i=0;i<160;i++)await Promise.resolve();expect(errors).toEqual([]);expect(outcome.settled).toBe(true);expect(outcome.value).toBeUndefined();expect(outcome.error).toMatchObject({name:"ApiError",status:0,message:"request timed out while reading response"});}finally{window.removeEventListener("error",observe);}
});
