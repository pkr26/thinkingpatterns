import { afterEach,beforeEach,expect,it,vi } from "vitest";
import { api,auth,clearSession,setSession } from "../src/api";
const NativeResponse=Response;
beforeEach(()=>{vi.restoreAllMocks();clearSession();setSession("native-edge-bearer","https://clinic.example.com");vi.useFakeTimers();});
afterEach(()=>{clearSession();vi.restoreAllMocks();vi.unstubAllGlobals();vi.useRealTimers();});
it("refuses an atomic native acknowledgement that arrives after its session ended",async()=>{
 let finish!:(response:Response)=>void;vi.stubGlobal("fetch",vi.fn(()=>new Promise<Response>(resolve=>{finish=resolve;})));
 const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};void api.changePasswordAtomic({operation_id:"native-operation",expected_custody_version:1,custody_version:2,verifier:"old",new_salt:"salt",new_verifier:"new",wrap_pub_key:"public",wrap_key_blob:"private",notes_keyring_blob:"notes"}).then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});
 clearSession();finish(new NativeResponse(null,{status:204}));for(let i=0;i<120;i++)await Promise.resolve();expect(outcome.settled).toBe(true);expect(outcome.value).toBeUndefined();expect(outcome.error).toMatchObject({status:0,message:"session ended"});
});
it("refuses native JSON that finished just before the originating session retired",async()=>{
 const json=NativeResponse.prototype.json;vi.spyOn(NativeResponse.prototype,"json").mockImplementation(async function(this:Response){const data=await json.call(this);clearSession();return data;});
 vi.stubGlobal("fetch",vi.fn(async()=>new NativeResponse('{"private":"old-session"}')));
 await expect(api.me()).rejects.toMatchObject({status:0,message:"session ended"});
});
it("retains the deadline fence after a foreign native response JSON promise has fulfilled",async()=>{
 // A forwarded fetch may return the host's native Response while a different
 // realm owns the active Response constructor. Its body and parser stay native.
 vi.stubGlobal("Response",class ResponseFromOtherRealm extends NativeResponse {});
 const json=NativeResponse.prototype.json;vi.spyOn(NativeResponse.prototype,"json").mockImplementation(async function(this:Response){const data=await json.call(this);queueMicrotask(()=>queueMicrotask(()=>vi.advanceTimersByTime(15_000)));return data;});
 vi.stubGlobal("fetch",vi.fn(async()=>new NativeResponse('{"late":"native-result"}')));
 await expect(api.me()).rejects.toMatchObject({status:0,message:"session ended or response timed out"});expect(vi.getTimerCount()).toBe(0);
});
it.each(["legacy","snapshot"])("reports an invalid %s patient continuation with its public resource context",async mode=>{
 vi.stubGlobal("fetch",vi.fn(async()=>new NativeResponse("[]",{headers:{"X-Next-Offset":"invalid",...(mode==="snapshot"?{"X-Patients-Revision":"17"}:{})}})));
 await expect(api.patientsPage()).rejects.toMatchObject({status:0,message:"server returned an invalid patients continuation"});
});
it("normalizes enrollment input before the native Headers parser accepts it",async()=>{
 let enrollment:string|null=null;vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{enrollment=new Request(url,init).headers.get("X-Therapist-Enrollment-Token");return new NativeResponse('{"token":"registered","user_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}');}));
 await auth.registerTherapist("https://clinic.example.com",{username:"clinician",salt:"salt",verifier:"proof",display_name:"Clinician",wrap_pub_key:"public",wrap_key_blob:"private",age_attestation:"minimum_age_confirmed_v1"},"\u00a0enrollment-secret\u00a0");expect(enrollment).toBe("enrollment-secret");
});
it("walks a complete legacy patient page without silently switching to snapshot revision requests",async()=>{
 const rows=Array.from({length:200},(_,i)=>({user_id:String(i),username:"patient",status:"active"}));const urls:string[]=[];
 vi.stubGlobal("fetch",vi.fn(async(url:string)=>{urls.push(url);return new NativeResponse(JSON.stringify(urls.length===1?rows:[{user_id:"last",username:"last",status:"active"}]));}));
 expect(await api.patients()).toHaveLength(201);expect(urls).toHaveLength(2);expect(new URL(urls[1]!).searchParams.get("offset")).toBe("200");expect(new URL(urls[1]!).searchParams.has("expected_revision")).toBe(false);
});
it("refuses persistent patient continuations at the explicit page cap with the correct public explanation",async()=>{
 const rows=Array.from({length:200},(_,i)=>({user_id:String(i),username:"patient",status:"active"}));let calls=0;
 vi.stubGlobal("fetch",vi.fn(async()=>{calls++;return new NativeResponse(JSON.stringify(rows));}));
 await expect(api.patients()).rejects.toMatchObject({status:0,message:"server keeps returning patient continuations — aborting the request"});expect(calls).toBe(6);
});
it("stops a changed patient snapshot after one restart before a later native outage",async()=>{
 let calls=0;vi.stubGlobal("fetch",vi.fn(async()=>{calls++;return calls<=2?new NativeResponse('{"detail":"changed","code":"collection_changed"}',{status:409}):new NativeResponse('{"detail":"outage"}',{status:503});}));
 await expect(api.patients()).rejects.toMatchObject({status:409,code:"collection_changed"});expect(calls).toBe(2);
});
