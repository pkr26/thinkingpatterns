import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api,detailToMessage } from "../src/api/client";
import { __resetLocalKeyLifecycleForTests, captureLocalWritePermit } from "../src/localWriteGuard";
import { secureStore } from "../src/secureStore";
import storage from "./helpers/storageMock";
import { runTestControl } from "./helpers/testControl";

const USER="a".repeat(32), ORIGIN="http://localhost:8000";
const entry=(id:string)=>({id,client_entry_id:id,blob:"sealed",entry_date:"2026-10-05",received_at:"2026-10-05T12:00:00Z"});
function answer(body:unknown,status=200,headers:Record<string,string>={}) {
  const response=new Response(JSON.stringify(body),{status,headers});
  Object.defineProperty(response,"url",{value:ORIGIN+"/api/v1/meta"});return response;
}
function serve(handler:(url:string,init:RequestInit)=>Response|Promise<Response>) {
  const fetch=vi.fn(handler);vi.stubGlobal("fetch",fetch);return fetch;
}
beforeEach(async()=>{storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);await api.setSession("token",USER,"alice");});
afterEach(async()=>{vi.restoreAllMocks();await api.clearSession();vi.unstubAllGlobals();});

it.each([{limit:0},{limit:1.5},{limit:501},{pageBytes:0},{pageBytes:1.5},{pageBytes:2097153},{expectedRevision:"x7"}])("refuses malformed measure options %j before transport",async options=>{
  const fetch=serve(()=>answer([]));await expect(api.listMeasuresPage(options)).rejects.toThrow("invalid measure page request");expect(fetch).not.toHaveBeenCalled();
});
it("accepts the smallest measure page and the documented byte/page ceilings",async()=>{
  const fetch=serve(()=>answer([]));
  for(const options of [{limit:1,pageBytes:1},{limit:500,pageBytes:2097152}]) {
    expect(await api.listMeasuresPage(options)).toMatchObject({measures:[],nextOffset:null,revision:null});
    const params=new URL(fetch.mock.calls.at(-1)![0]).searchParams;
    expect(params.get("limit")).toBe(String(options.limit));expect(params.get("page_bytes")).toBe(String(options.pageBytes));
  }
});

const collections=[
  ["entries","X-Entries-Revision",()=>api.listEntries("2026-10-01")],
  ["measures","X-Measures-Revision",()=>api.listMeasures()],
  ["consents","X-Consents-Revision",()=>api.listConsents()],
] as const;
it.each(collections)("deduplicates real %s pages while pinning the same snapshot",async(resource,header,invoke)=>{
  const first=entry("first"),second=entry("second");let calls=0;
  const fetch=serve(url=>{
    const params=new URL(url).searchParams;++calls;
    if(calls===1){expect(params.has("expected_revision")).toBe(false);return answer([first],200,{[header]:"7","X-Next-Offset":"1"});}
    expect(params.get("offset")).toBe("1");expect(params.get("expected_revision")).toBe("7");
    if(resource==="entries")expect(params.get("since")).toBe("2026-10-01");
    return answer([first,second],200,{[header]:"7"});
  });
  expect(await invoke()).toEqual([first,second]);expect(fetch).toHaveBeenCalledTimes(2);
});
for(const start of ["legacy","snapshot"] as const)it.each(collections)(`restarts real %s pages when ${start} protocol changes`,async(_resource,header,invoke)=>{
  let calls=0;const fetch=serve(url=>{
    ++calls;
    if(calls===1)return answer([entry("old")],200,{"X-Next-Offset":"1",...(start==="snapshot"?{[header]:"7"}:{})});
    if(calls===2)return answer([entry("mixed")],200,start==="legacy"?{[header]:"7"}:{});
    expect(new URL(url).searchParams.get("offset")).toBe("0");expect(new URL(url).searchParams.has("expected_revision")).toBe(false);
    return answer([entry("fresh")],200,{[header]:"8"});
  });
  expect(await invoke()).toEqual([entry("fresh")]);expect(fetch).toHaveBeenCalledTimes(3);
});
it.each(collections)("bounds %s snapshot retries through the real request client",async(_resource,_header,invoke)=>{
  let calls=0;const fetch=serve(()=>++calls<=2?answer({detail:"changed",code:"collection_changed"},409):answer({detail:"unexpected extra request"},500));
  await expect(invoke()).rejects.toMatchObject({status:409,message:"changed",code:"collection_changed"});expect(fetch).toHaveBeenCalledTimes(2);
});
it.each(collections)("walks stable headerless %s pages without inventing a snapshot pin",async(_resource,_header,invoke)=>{
  let calls=0;const first=entry("first"),second=entry("second");const fetch=serve(url=>{
    expect(new URL(url).searchParams.has("expected_revision")).toBe(false);
    return ++calls===1?answer([first],200,{"X-Next-Offset":"1"}):answer([second]);
  });
  expect(await invoke()).toEqual([first,second]);expect(fetch).toHaveBeenCalledTimes(2);
});
it.each(collections)("reports the final repeated %s protocol conflict with its public retry copy",async(resource,header,invoke)=>{
  let calls=0;const fetch=serve(()=>++calls%2===1?answer([entry("legacy")],200,{"X-Next-Offset":"1"}):answer([entry("snapshot")],200,{[header]:"7"}));
  await expect(invoke()).rejects.toMatchObject({status:409,message:`${resource} changed while paging; retry the request`,code:"collection_changed"});
  expect(fetch).toHaveBeenCalledTimes(4);
});
it("stops a complete measures walk at its first terminal page",async()=>{
  const rows=[{id:"terminal",blob:"sealed"}];let calls=0;
  const fetch=serve(()=>++calls===1?answer(rows):answer({detail:"unexpected continuation"},400));
  expect(await api.listMeasures()).toEqual(rows);expect(fetch).toHaveBeenCalledOnce();
});

it("keeps a bounded date window ordered, filtered and deduplicated",async()=>{
  let calls=0;const fetch=serve(url=>{
    const params=new URL(url).searchParams;expect(params.get("since")).toBe("2026-10-01 + ?");expect(params.get("until")).toBe("2026-11-01 + ?");
    expect(params.get("limit")).toBe("500");expect(params.get("page_bytes")).toBe("2097152");
    if(++calls===1)return answer([entry("one")],200,{"X-Entries-Revision":"7","X-Next-Offset":"1"});
    expect(params.get("expected_revision")).toBe("7");expect(params.get("offset")).toBe("1");
    return answer([entry("one"),entry("two")],200,{"X-Entries-Revision":"7"});
  });
  expect(await api.listEntriesWindow("2026-10-01 + ?","2026-11-01 + ?",2)).toEqual([entry("one"),entry("two")]);expect(fetch).toHaveBeenCalledTimes(2);
});
it("refuses to retain a date-window row beyond the caller's bound",async()=>{
  serve(()=>answer([entry("one"),entry("two")],200,{"X-Entries-Revision":"7"}));
  await expect(api.listEntriesWindow("2026-10-01","2026-11-01",1)).rejects.toThrow("entry window exceeded the on-device bound — narrowing the month view");
});
it("retries a moved date-window snapshot from offset zero",async()=>{
  let calls=0;const fetch=serve(url=>{
    ++calls;if(calls===1)return answer([entry("old")],200,{"X-Entries-Revision":"7","X-Next-Offset":"1"});
    if(calls===2)return answer({detail:"changed",code:"collection_changed"},409);
    expect(new URL(url).searchParams.get("offset")).toBe("0");return answer([entry("fresh")],200,{"X-Entries-Revision":"8"});
  });
  expect(await api.listEntriesWindow("2026-10-01","2026-11-01")).toEqual([entry("fresh")]);expect(fetch).toHaveBeenCalledTimes(3);
});
it("surfaces a second date-window conflict and a non-conflict request failure",async()=>{
  for(const status of [409,403]) {
    let calls=0;const fetch=serve(()=>++calls<=(status===409?2:1)?answer({detail:"changed",code:"collection_changed"},status):answer({detail:"unexpected extra request"},500));
    await expect(api.listEntriesWindow("2026-10-01","2026-11-01")).rejects.toMatchObject({status,message:"changed"});expect(fetch).toHaveBeenCalledTimes(status===409?2:1);
  }
});
it("bounds a server that continually advances date-window cursors",async()=>{
  let calls=0;const fetch=serve(url=>{
    if(++calls>100)return answer({detail:"unexpected extra request"},500);
    const offset=Number(new URL(url).searchParams.get("offset"));return answer([entry(String(offset))],200,{"X-Entries-Revision":"7","X-Next-Offset":String(offset+1)});
  });
  await expect(api.listEntriesWindow("2026-10-01","2026-11-01",1500)).rejects.toThrow("server keeps returning entry continuations — aborting window fetch");expect(fetch).toHaveBeenCalledTimes(100);
});

it("refuses queued ciphertext when the persisted bearer tuple was changed to another account",async()=>{
  const permit=captureLocalWritePermit(USER);await secureStore.setItem("@mindpattern/user_id","b".repeat(32));
  const fetch=serve(()=>answer({}));
  await expect(api.createQueuedEntry("entry_1","sealed","2026-10-05",ORIGIN,permit)).rejects.toMatchObject({status:0,code:"stale_operation",message:"The queued ciphertext belongs to another account; no request was sent."});expect(fetch).not.toHaveBeenCalled();
});
it("uses the queued origin and owner while reading a previously committed entry",async()=>{
  const permit=captureLocalWritePermit(USER);const fetch=serve(()=>answer(entry("entry_1")));
  expect(await api.getEntry("entry_1",ORIGIN,permit)).toEqual(entry("entry_1"));expect(fetch).toHaveBeenCalledOnce();
});

it.each([
  ["base","@mindpattern/token"],
  ["@mindpattern/token","@mindpattern/user_id"],
  ["@mindpattern/user_id","@mindpattern/username"],
] as const)("prevents legacy credential resurrection after the native %s boundary retires",async(boundary,nextSlot)=>{
  // The old bare-ciphertext envelope is a supported installed-client input.
  // A native read may return its already-captured bytes after logout removed
  // the durable slot. The request must stop before initiating that read.
  const legacy=JSON.parse((await storage.getItem(nextSlot))!).c as string;
  const read=storage.getItem;let retirement:Promise<void>|undefined;let replayed=false;
  vi.spyOn(storage,"getItem").mockImplementation(async slot=>{
    if(retirement&&slot===nextSlot&&!replayed){replayed=true;await retirement;return legacy;}
    const value=await read(slot);
    if(!retirement&&slot===(boundary==="base"?"@mindpattern/base_url":boundary))retirement=api.clearSession();
    return value;
  });
  const fetch=serve(()=>answer({}));
  await expect(api.meta()).rejects.toMatchObject({status:0,code:"stale_operation",message:"The account or key generation changed; no request was sent."});
  await retirement;expect(fetch).not.toHaveBeenCalled();vi.restoreAllMocks();
  expect(await api.isLoggedIn()).toBe(false);expect(await api.getUserId()).toBeNull();expect(await api.getUsername()).toBeNull();
});

it("sanitizes error text without exposing domain tails or joining separate words",()=>{
  const cases:[unknown,string][]=[
    ["look sub.api.evil.example:9999/path/tail end","look end"],
    ["look evil.example:9999/path/tail end","look end"],
    ["look evil.example:9999 end","look end"],
    ["keep 12345 words","keep words"],["keep 1 2 3 4 words","keep words"],
    ["keep 123a words","keep 123a words"],["keep a123 words","keep a123 words"],
    ["keep1-234word","keep word"],
  ];for(const [input,expected]of cases)expect(detailToMessage(input,422)).toBe(expected);
});
it("keeps origin-pinned refusal on its complete public error surface",async()=>{
  const fetch=serve(()=>answer({}));
  await expect(api.createQueuedEntry("entry_1","sealed","2026-10-05","https://other.example")).rejects.toMatchObject({name:"OriginPinnedError",message:"refusing to send data pinned to https://other.example while http://localhost:8000 is selected"});expect(fetch).not.toHaveBeenCalled();
});
it.each(["entries","measures","consents"] as const)("accepts headerless native-compatible %s page responses",async resource=>{
  const rows=[entry("one")];serve(async()=>({status:200,ok:true,url:ORIGIN+"/api/v1/"+resource,json:async()=>rows}) as Response);
  const result=resource==="entries"?await api.listEntriesPage():resource==="measures"?await api.listMeasuresPage():await api.listConsentsPage();
  expect(result).toMatchObject({[resource]:rows,nextOffset:null,revision:null});
});
