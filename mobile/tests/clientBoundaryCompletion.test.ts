import {afterEach,beforeEach,expect,it,vi} from "vitest";
import {api,canonicalOrigin,setUnauthorizedHandler} from "../src/api/client";
import {__resetLocalKeyLifecycleForTests,advanceLocalWriteScope,captureLocalWritePermit,installLocalDataKey} from "../src/localWriteGuard";
import storage from "./helpers/storageMock";
import {secureStore} from "../src/secureStore";
import {vault} from "../src/vault";
import {runTestControl} from "./helpers/testControl";
const USER="a".repeat(32),ORIGIN="http://localhost:8000";
function answer(value:unknown,status=200,headers:Record<string,string>={}){const response=new Response(JSON.stringify(value),{status,headers});Object.defineProperty(response,"url",{value:ORIGIN+"/api/v1/meta"});return response;}
function serve(handler:(url:string,init:RequestInit)=>Response|Promise<Response>){const fetch=vi.fn(handler);vi.stubGlobal("fetch",fetch);return fetch;}
beforeEach(async()=>{storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);setUnauthorizedHandler(null);await api.setSession("token",USER,"alice");});
afterEach(async()=>{vi.restoreAllMocks();await api.clearSession();setUnauthorizedHandler(null);vi.unstubAllGlobals();});
it("treats an account-deletion code on HTTP 401 as expiry rather than confirmed deletion",async()=>{
  const handler=vi.fn();setUnauthorizedHandler(handler);serve(()=>answer({detail:"expired",code:"account_deleted"},401));
  await expect(api.meta()).rejects.toMatchObject({status:401,code:"account_deleted"});
  expect(handler).toHaveBeenCalledExactlyOnceWith({status:401,code:"account_deleted",accountDeleted:false,userId:USER,username:"alice",origin:"http://127.0.0.1:8000"});
});
it.each(["malformed","empty-continuation"])("keeps the consent page rejection copy for a %s revision/cursor",async kind=>{
  serve(()=>answer([],200,kind==="malformed"?{"X-Consents-Revision":"x7"}:{"X-Consents-Revision":"7","X-Next-Offset":"1"}));
  await expect(api.listConsentsPage()).rejects.toMatchObject({status:0,message:"invalid consent page response — refusing the response"});
});
const params={name:"pbkdf2-sha256",iterations:600000} as const;
const sensitive:[string,()=>Promise<unknown>][]=[
  ["registration",()=>api.register("alice","salt","proof","minimum_age_confirmed_v1")],
  ["recovery enrollment",()=>api.setupRecoveryKit("password","recovery","wrapped","v2")],
  ["recovery removal",()=>api.removeRecoveryKit("password")],
  ["recovery login",()=>api.recoverLogin("alice","recovery","v2")],
  ["recovery password",()=>api.resetPasswordWithRecovery("recovery",{new_salt:"salt",new_verifier:"proof",wrapped_data_key:"wrapped"},"processing")],
  ["processing session",()=>api.openProcessingSession("data-key")],
  ["export",()=>api.exportAccount()],
  ["delete account",()=>api.deleteAccount("proof")],
  ["voice consent",()=>api.setVoiceConsent(true,"proof")],
  ["voice sharing",()=>api.setShareVoice("consent",true,"proof")],
  ["LLM consent",()=>api.setLlmConsent(true,"proof")],
  ["rekey",()=>api.rekeyStoredData("old","new","proof",{operation_id:"operation",new_salt:"salt",new_verifier:"next",consent_wraps:[]})],
  ["credential rotation",()=>api.rotateCredential("old","salt","next")],
  ["password rotation",()=>api.changePassword("old","salt","next","wrapped","processing",params)],
  ["envelope upgrade",()=>api.upgradeKeyEnvelope(params,"wrapped","processing","proof")],
  ["consent rewrap",()=>api.rewrapConsent("b".repeat(32),"pub","wrapped","proof")],
  ["consent grant",()=>api.grantConsent("123456","pub","wrapped","proof")],
  ["consent revocation",()=>api.revokeConsent("b".repeat(32),"proof")],
];
it.each(sensitive)("refuses unverifiable final origin for %s",async(_name,invoke)=>{serve(()=>new Response('{}'));await expect(invoke()).rejects.toMatchObject({name:"ApiError",status:0,message:"could not verify this request was not redirected — check your server URL"});});
it("rejects a restored cleartext remote base before any credential reaches transport",async()=>{await storage.setItem("@mindpattern/base_url","http://remote.example");const fetch=serve(()=>answer({}));await expect(api.meta()).rejects.toMatchObject({name:"ApiError",status:0,message:"refusing to send data to an invalid or cleartext remote server URL"});expect(fetch).not.toHaveBeenCalled();});
it("explains the HTTPS requirement when opening a processing session with a restored cleartext remote origin",async()=>{
  await storage.setItem("@mindpattern/base_url","http://remote.example");const fetch=serve(()=>answer({}));
  await expect(api.openProcessingSession("data-key")).rejects.toMatchObject({status:0,message:"the encryption key can only be sent over HTTPS (or localhost) — update the server URL"});
  expect(fetch).not.toHaveBeenCalled();
});
it("retires a processing key while its initial Native origin read is held",async()=>{
 const read=storage.getItem;let first=true,release:()=>void=()=>{},ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const value=await read(slot);if(slot==="@mindpattern/base_url"&&first){first=false;ready();await new Promise<void>(resolve=>{release=resolve;});}return value;});const receipts:unknown[]=[];serve((_url,init)=>{receipts.push(JSON.parse(String(init.body)));return answer({session_token:"new-processing"});});const pending=api.openProcessingSession("old-owned-data-key").catch(error=>error);await Promise.race([started,pending]);await api.setSession("replacement","b".repeat(32),"bob");try{release();expect(await pending).toMatchObject({code:"stale_operation"});expect(receipts).toEqual([]);expect(await api.getUserId()).toBe("b".repeat(32));}finally{release();await pending;}
});
it("rejects a retired processing producer before an unavailable Native origin provider",async()=>{
 const permit=captureLocalWritePermit(USER);await api.setSession("replacement","b".repeat(32),"bob");const read=storage.getItem;vi.spyOn(storage,"getItem").mockImplementation(async slot=>{if(slot==="@mindpattern/base_url")throw new Error("Native origin provider unavailable");return read(slot);});const receipts:unknown[]=[];serve((_url,init)=>{receipts.push(JSON.parse(String(init.body)));return answer({});});await expect(api.openProcessingSession("old-owned-data-key",permit)).rejects.toThrow("The local account/session changed");expect(receipts).toEqual([]);
});
it("prioritizes a retired processing key over a corrupt old Native origin completion",async()=>{
 const key=Buffer.alloc(32,7);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32,2),dataKey:key},USER);installLocalDataKey(USER,key);const permit=captureLocalWritePermit(USER,key);const read=storage.getItem;let first=true,release:()=>void=()=>{},ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async slot=>{if(slot==="@mindpattern/base_url"&&first){first=false;ready();await new Promise<void>(resolve=>{release=resolve;});return "http://corrupt-old-origin.example";}return read(slot);});const receipts:unknown[]=[];serve((_url,init)=>{receipts.push(init.body);return answer({});});const pending=api.openProcessingSession("old-owned-data-key",permit).catch(error=>error);await Promise.race([started,pending]);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32,3),dataKey:Buffer.alloc(32,8)},USER);installLocalDataKey(USER,vault.get().dataKey);try{release();expect((await pending).message).toContain("retired account or key generation");expect(receipts).toEqual([]);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,8));}finally{release();await pending;vault.lock();}
});
it("prioritizes retired ownership over a corrupt native base completion",async()=>{
  const read=storage.getItem;vi.spyOn(storage,"getItem").mockImplementation(async slot=>{
    if(slot==="@mindpattern/base_url"){advanceLocalWriteScope();return "::::invalid-installed-origin";}
    return read(slot);
  });
  const fetch=serve(()=>answer({}));
  await expect(api.meta()).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed; no request was sent."});
  expect(fetch).not.toHaveBeenCalled();
});
it("rejects a retired producer before attempting an unavailable native origin read",async()=>{
  const permit=captureLocalWritePermit(USER);await api.setSession("replacement","b".repeat(32),"bob");
  const read=storage.getItem;vi.spyOn(storage,"getItem").mockImplementation(async slot=>{
    if(slot==="@mindpattern/base_url")throw new Error("native origin storage unavailable");
    return read(slot);
  });
  const fetch=serve(()=>answer({}));
  await expect(api.createEntry("entry_1","sealed","2026-10-05",1,permit)).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed; no request was sent."});
  expect(fetch).not.toHaveBeenCalled();
});
it.each(["", " \t "])("refuses queued ciphertext when a restored credential token is blank (%s)",async token=>{
  const permit=captureLocalWritePermit(USER);await secureStore.setItem("@mindpattern/token",token);
  const fetch=serve(()=>answer({accepted:true}));
  await expect(api.createQueuedEntry("entry_1","sealed","2026-10-05",ORIGIN,permit)).rejects.toMatchObject({status:0,code:"stale_operation",message:"No authenticated session owns the queued ciphertext; no request was sent."});
  expect(fetch).not.toHaveBeenCalled();
});
it("prioritizes dispatched ownership retirement over a malformed native response URL",async()=>{
  const fetch=serve(()=>{
    const response=new Response("{}");Object.defineProperty(response,"url",{value:"not an absolute native URL"});
    advanceLocalWriteScope();return response;
  });
  await expect(api.meta()).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed. This request may already have committed; confirm its outcome before retrying."});
  expect(fetch).toHaveBeenCalledOnce();
});
it("retires a no-content response when ownership changes during asynchronous origin verification",async()=>{
  const fetch=serve(()=>{
    const response=new Response(null,{status:204});
    Object.defineProperty(response,"url",{get:()=>{queueMicrotask(()=>advanceLocalWriteScope());return ORIGIN+"/api/v1/meta";}});
    return response;
  });
  await expect(api.meta()).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed. This request may already have committed; confirm its outcome before retrying."});
  expect(fetch).toHaveBeenCalledOnce();
});
it("prioritizes a retired username-read completion over a restored account mismatch",async()=>{
  const permit=captureLocalWritePermit(USER);await secureStore.setItem("@mindpattern/user_id","b".repeat(32));
  const read=storage.getItem;vi.spyOn(storage,"getItem").mockImplementation(async slot=>{
    const value=await read(slot);if(slot==="@mindpattern/username")advanceLocalWriteScope();return value;
  });
  const fetch=serve(()=>answer({}));
  await expect(api.createQueuedEntry("entry_1","sealed","2026-10-05",ORIGIN,permit)).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed; no request was sent."});
  expect(fetch).not.toHaveBeenCalled();
});
it.each(["@mindpattern/user_id","@mindpattern/username"])("keeps verifier login independent of unavailable old credential metadata %s",async failedSlot=>{
  const read=storage.getItem;vi.spyOn(storage,"getItem").mockImplementation(async slot=>{
    if(slot===failedSlot)throw new Error("native credential database unavailable");
    return read(slot);
  });
  const fetch=serve(()=>answer({token:"new-verifier-token"}));
  expect(await api.login("alice","password-proof")).toEqual({token:"new-verifier-token"});
  expect(fetch).toHaveBeenCalledOnce();expect(fetch.mock.calls[0]![1].headers).not.toHaveProperty("Authorization");
});
it.each(["entries","measures","consents"])("refuses a numeric %s snapshot pin before native transport",async resource=>{
  const fetch=serve(()=>answer([]));const options={expectedRevision:99 as unknown as string};
  await expect(resource==="entries"?api.listEntriesPage(options):resource==="measures"?api.listMeasuresPage(options):api.listConsentsPage(options)).rejects.toMatchObject({status:0});
  expect(fetch).not.toHaveBeenCalled();
});
it("canonicalizes every actual loopback spelling without changing remote origins",()=>{for(const host of ["localhost","127.0.0.1","[::1]"])expect(canonicalOrigin(`http://${host}:8000`)).toBe("http://127.0.0.1:8000");expect(canonicalOrigin("https://remote.example:8443")).toBe("https://remote.example:8443");});
it.each(["entries","measures","consents"])("rejects an array-like JSON object as a %s page",async collection=>{serve(()=>answer({length:1}));const invoke=collection==="entries"?()=>api.listEntriesPage():collection==="measures"?()=>api.listMeasuresPage():()=>api.listConsentsPage();await expect(invoke()).rejects.toMatchObject({name:"ApiError",status:0,message:`invalid ${collection==="entries"?"entry":collection==="measures"?"measure":"consent"} page response — refusing the response`});});
it.each(["entry","measure"])("rejects a %s page larger than its requested limit",async collection=>{serve(()=>answer([{},{}]));await expect(collection==="entry"?api.listEntriesPage({limit:1}):api.listMeasuresPage({limit:1})).rejects.toMatchObject({status:0,message:`invalid ${collection} page response — refusing the response`});});
it.each(["entry","measure"])("rejects an unsafe offset-plus-row count for %s",async collection=>{serve(()=>answer([{}]));await expect(collection==="entry"?api.listEntriesPage({offset:Number.MAX_SAFE_INTEGER}):api.listMeasuresPage({offset:Number.MAX_SAFE_INTEGER})).rejects.toMatchObject({status:0,message:`invalid ${collection} page response — refusing the response`});});
it("accepts the final valid consent offset and rejects a malformed pin",async()=>{const fetch=serve(()=>answer([]));expect(await api.listConsentsPage({offset:1000})).toEqual({consents:[],nextOffset:null,revision:null});await expect(api.listConsentsPage({expectedRevision:"x7"})).rejects.toMatchObject({status:0,message:"invalid consent page request — refusing the request"});expect(fetch).toHaveBeenCalledOnce();});
it.each(["a"+"b".repeat(32),"b".repeat(32)+"a"])("rejects extra characters on a consent identifier",async id=>{const fetch=serve(()=>answer({}));expect(()=>api.rewrapConsent(id,"pub","wrapped","proof")).toThrow("invalid consent id — refusing the request");await expect(api.revokeConsent(id,"proof")).rejects.toMatchObject({status:0,message:"invalid consent id — refusing the request"});expect(fetch).not.toHaveBeenCalled();});
it("rejects an invalid entry update identifier before transport",async()=>{const fetch=serve(()=>answer({}));await expect(api.updateEntry("../entry","sealed","2026-10-05")).rejects.toMatchObject({status:0,message:"invalid entry id — refusing the request"});expect(fetch).not.toHaveBeenCalled();});
it("retains every unusual measure row while deduplicating only string identifiers",async()=>{serve(()=>answer([null,{id:7},{id:7},{id:"one"},{id:"one"}]));expect(await api.listMeasures()).toEqual([null,{id:7},{id:7},{id:"one"}]);});
it.each(["entry","measure","update","audio"])("refuses a retired writer permit for %s",async operation=>{
  const permit=captureLocalWritePermit(USER);await api.setSession("next","b".repeat(32),"bob");const fetch=serve(()=>answer({}));
  const invoke=operation==="entry"?()=>api.createEntry("entry_1","sealed","2026-10-05",1,permit):operation==="measure"?()=>api.createMeasure("measure_1","sealed","2026-10-05",permit):operation==="update"?()=>api.updateEntry("entry_1","sealed","2026-10-05",1,permit):()=>api.uploadAudioAttachment("entry_1","audio","audio/mp4",2,ORIGIN,permit);
  await expect(invoke()).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed; no request was sent."});expect(fetch).not.toHaveBeenCalled();
});
it("keeps queued entry creation on its fixed initial content generation",async()=>{const fetch=serve(()=>answer({id:"new"}));expect(await api.createQueuedEntry("entry_1","sealed","2026-10-05",ORIGIN)).toEqual({id:"new"});const [url,init]=fetch.mock.calls[0]!;expect(url).toBe(ORIGIN+"/api/v1/entries");expect(init.method).toBe("POST");expect(JSON.parse(String(init.body))).toEqual({client_entry_id:"entry_1",blob:"sealed",entry_date:"2026-10-05",content_version:1});});
it.each(["ordinary","export"])("reports legacy gone only for the %s account-death contract",async operation=>{const expired=vi.fn();setUnauthorizedHandler(expired);serve(()=>answer({detail:"unavailable",code:"gone"},410));await expect(operation==="ordinary"?api.meta():api.exportAccount()).rejects.toMatchObject({status:410,code:"gone"});if(operation==="ordinary")expect(expired).not.toHaveBeenCalled();else expect(expired).toHaveBeenCalledExactlyOnceWith(expect.objectContaining({accountDeleted:true,userId:USER}));});
it("can report bearer rejection without an unauthorized callback",async()=>{setUnauthorizedHandler(null);serve(()=>answer({detail:"expired",code:"unauthorized"},401));await expect(api.meta()).rejects.toMatchObject({status:401,message:"expired",code:"unauthorized"});});
it.each(["entries","measures","consents"])("accepts a valid short %s revision above the maximum's lexical prefix",async resource=>{
  const header=resource==="entries"?"X-Entries-Revision":resource==="measures"?"X-Measures-Revision":"X-Consents-Revision";serve(()=>answer([],200,{[header]:"99"}));
  const result=resource==="entries"?await api.listEntriesPage({expectedRevision:"99"}):resource==="measures"?await api.listMeasuresPage({expectedRevision:"99"}):await api.listConsentsPage({expectedRevision:"99"});expect(result.revision).toBe("99");
});
it.each(["terminal","overflow"])("checks the %s probe at the full entry walk bound",async outcome=>{
  let calls=0;const fetch=serve(url=>{
    if(++calls>101)return answer({detail:"unexpected extra request"},500);
    const offset=Number(new URL(url).searchParams.get("offset"));
    if(calls===101)return answer(outcome==="terminal"?[]:[{id:"overflow",client_entry_id:"overflow"}]);
    return answer([{id:String(offset),client_entry_id:String(offset)}],200,{"X-Next-Offset":String(offset+1)});
  });
  if(outcome==="terminal")expect(await api.listEntries()).toEqual(Array.from({length:100},(_,n)=>({id:String(n),client_entry_id:String(n)})));
  else await expect(api.listEntries()).rejects.toMatchObject({status:0,message:"server keeps returning entry continuations — aborting sync, contact support or check the server"});expect(fetch).toHaveBeenCalledTimes(101);
});
it("bounds a consent server that keeps advancing valid cursors",async()=>{
  let calls=0;const fetch=serve(url=>{if(++calls>6)return answer({detail:"unexpected extra request"},500);const offset=Number(new URL(url).searchParams.get("offset"));return answer([{id:String(offset)}],200,{"X-Next-Offset":String(offset+1),"X-Consents-Revision":"7"});});
  await expect(api.listConsents()).rejects.toMatchObject({status:0,message:"server keeps returning consent continuations — aborting the request"});expect(fetch).toHaveBeenCalledTimes(6);
});
it.each(["measures","consents"])("surfaces %s failures that are not a retryable snapshot conflict",async resource=>{
  for(const [status,code] of [[403,"collection_changed"],[409,"version_conflict"]] as const){let calls=0;const fetch=serve(()=>++calls===1?answer({detail:"refused",code},status):answer({detail:"unexpected extra request"},500));
    if(resource==="measures"&&status===409)continue;
    await expect(resource==="measures"?api.listMeasures():api.listConsents()).rejects.toMatchObject({status,code,message:"refused"});expect(fetch).toHaveBeenCalledOnce();
  }
});
it("finishes an empty measure history at the first terminal response",async()=>{let calls=0;const fetch=serve(()=>++calls===1?answer([]):answer({detail:"unexpected extra request"},500));expect(await api.listMeasures()).toEqual([]);expect(fetch).toHaveBeenCalledOnce();});
it("ends a snapshot-aware full consent page without inventing another legacy page",async()=>{const rows=Array.from({length:200},(_,n)=>({id:String(n)}));const fetch=serve(()=>answer(rows,200,{"X-Consents-Revision":"7"}));expect(await api.listConsentsPage()).toEqual({consents:rows,nextOffset:null,revision:"7"});expect(fetch).toHaveBeenCalledOnce();});
it("reports unrelated account-route gone codes without declaring deletion",async()=>{const expired=vi.fn();setUnauthorizedHandler(expired);serve(()=>answer({detail:"missing",code:"not_found"},410));await expect(api.deleteAccount("proof")).rejects.toMatchObject({status:410,code:"not_found"});expect(expired).not.toHaveBeenCalled();});
it("uses the explicit nondeleted identity for an ordinary bearer rejection",async()=>{const expired=vi.fn();setUnauthorizedHandler(expired);serve(()=>answer({detail:"expired",code:"unauthorized"},401));await expect(api.meta()).rejects.toMatchObject({status:401});expect(expired).toHaveBeenCalledExactlyOnceWith({status:401,code:"unauthorized",accountDeleted:false,userId:USER,username:"alice",origin:"http://127.0.0.1:8000"});});
