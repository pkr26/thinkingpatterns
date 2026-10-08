import {afterEach,beforeEach,expect,it,vi} from "vitest";
import {api,clearSession,listEntriesWalk,setSessionExpiredHandler} from "../src/api/client";
import {installSession,jsonResponse,resetTestState,stubFetch} from "./helpers/api";
const entry=(id:string)=>({id,client_entry_id:id,blob:"sealed",entry_date:"2026-10-05",received_at:"2026-10-05T12:00:00Z"});
const consent=(id:string)=>({id,therapist_id:"therapist",display_name:"Therapist",username:"therapist",status:"active",granted_at:"2026-10-05",revoked_at:null});
beforeEach(()=>{resetTestState();installSession();});
afterEach(()=>{clearSession();setSessionExpiredHandler(null);vi.restoreAllMocks();vi.unstubAllGlobals();});
const collections=[
  ["entries","X-Entries-Revision",()=>listEntriesWalk("2026-10-01"),entry],
  ["consents","X-Consents-Revision",()=>api.listConsents(),consent],
] as const;
it.each(collections)("deduplicates real %s pages while keeping one snapshot",async(resource,header,invoke,row)=>{
  let calls=0;const fetch=stubFetch(url=>{
    const params=new URL(url).searchParams;
    if(++calls===1){expect(params.has("expected_revision")).toBe(false);return jsonResponse([row("first")],{headers:{[header]:"7","X-Next-Offset":"1"}});}
    expect(params.get("offset")).toBe("1");expect(params.get("expected_revision")).toBe("7");
    if(resource==="entries")expect(params.get("since")).toBe("2026-10-01");
    return jsonResponse([row("first"),row("second")],{headers:{[header]:"7"}});
  });
  expect(await invoke()).toEqual([row("first"),row("second")]);expect(fetch).toHaveBeenCalledTimes(2);
});
for(const start of ["legacy","snapshot"] as const)it.each(collections)(`refuses mixed real %s pages when ${start} protocol changes`,async(resource,header,invoke,row)=>{
  let calls=0;const fetch=stubFetch(url=>{
    ++calls;if(calls===1)return jsonResponse([row("old")],{headers:{"X-Next-Offset":"1",...(start==="snapshot"?{[header]:"7"}:{})}});
    if(calls===2)return jsonResponse([row("mixed")],{headers:start==="legacy"?{[header]:"7"}:{}});
    expect(new URL(url).searchParams.get("offset")).toBe("0");expect(new URL(url).searchParams.has("expected_revision")).toBe(false);
    return jsonResponse([row("fresh")],{headers:{[header]:"8"}});
  });
  if(resource==="entries"&&start==="snapshot") {
    await expect(invoke()).rejects.toMatchObject({status:0,message:"server dropped the entries snapshot revision"});expect(fetch).toHaveBeenCalledTimes(2);
  } else {expect(await invoke()).toEqual([row("fresh")]);expect(fetch).toHaveBeenCalledTimes(3);}
});
it.each(collections)("bounds %s snapshot retries through the real request client",async(_resource,_header,invoke)=>{
  let calls=0;const fetch=stubFetch(()=>++calls<=3?jsonResponse({detail:"changed",code:"collection_changed"},{status:409}):jsonResponse({detail:"unexpected extra request"},{status:500}));
  await expect(invoke()).rejects.toMatchObject({status:409,message:"changed",code:"collection_changed"});expect(fetch).toHaveBeenCalledTimes(3);
});
it.each(collections)("walks stable headerless %s pages without introducing a revision pin",async(_resource,_header,invoke,row)=>{
  let calls=0;const fetch=stubFetch(url=>{
    expect(new URL(url).searchParams.has("expected_revision")).toBe(false);
    return ++calls===1?jsonResponse([row("first")],{headers:{"X-Next-Offset":"1"}}):jsonResponse([row("second")]);
  });
  expect(await invoke()).toEqual([row("first"),row("second")]);expect(fetch).toHaveBeenCalledTimes(2);
});
it("reports a persistently mixed entry protocol after exactly three complete attempts",async()=>{
  let calls=0;const fetch=stubFetch(()=>++calls%2===1?jsonResponse([entry("legacy")],{headers:{"X-Next-Offset":"1"}}):jsonResponse([entry("snapshot")],{headers:{"X-Entries-Revision":"7"}}));
  await expect(listEntriesWalk()).rejects.toMatchObject({status:409,message:"the entries snapshot changed mid-walk — restarting",code:"collection_changed"});
  expect(fetch).toHaveBeenCalledTimes(6);
});
it("refuses an entry walk without a signed-in owner before transport",async()=>{
  clearSession();const fetch=stubFetch(()=>jsonResponse([]));
  await expect(listEntriesWalk()).rejects.toThrow("session ended");expect(fetch).not.toHaveBeenCalled();
});
it.each(["terminal","overflow"] as const)("checks the %s terminal probe at the entry-walk page bound",async outcome=>{
  let calls=0;const fetch=stubFetch(url=>{
    if(++calls>201)return jsonResponse({detail:"unexpected extra request"},{status:500});
    const offset=Number(new URL(url).searchParams.get("offset"));
    if(calls===201)return jsonResponse(outcome==="terminal"?[]:[entry("overflow")]);
    return jsonResponse([entry(String(offset))],{headers:{"X-Next-Offset":String(offset+1)}});
  });
  if(outcome==="terminal")expect(await listEntriesWalk()).toEqual(Array.from({length:200},(_,index)=>entry(String(index))));
  else await expect(listEntriesWalk()).rejects.toThrow("server keeps returning entry continuations — aborting sync");
  expect(fetch).toHaveBeenCalledTimes(201);
});
it("bounds a consent server that continually advances valid cursors",async()=>{
  let calls=0;const fetch=stubFetch(url=>{
    if(++calls>6)return jsonResponse({detail:"unexpected extra request"},{status:500});
    const offset=Number(new URL(url).searchParams.get("offset"));return jsonResponse([consent(String(offset))],{headers:{"X-Next-Offset":String(offset+1),"X-Consents-Revision":"7"}});
  });
  await expect(api.listConsents()).rejects.toThrow("server keeps returning consent continuations — aborting the request");expect(fetch).toHaveBeenCalledTimes(6);
});
it.each(["unauthorized","account_deleted"])("can report %s without a registered expiry callback",async code=>{
  setSessionExpiredHandler(null);const status=code==="unauthorized"?401:410;
  stubFetch(()=>jsonResponse({detail:"unavailable",code},{status}));
  await expect(api.meta()).rejects.toMatchObject({status,code,message:"unavailable"});
  await expect(api.exportAccountRaw()).rejects.toMatchObject({status,code});
});
it.each(["account_deleted","gone"])("keeps unrelated resource 410 (%s) separate from account expiry",async code=>{
  const expired=vi.fn();setSessionExpiredHandler(expired);
  stubFetch(()=>jsonResponse({detail:"unavailable",code},{status:410}));
  await expect(api.meta()).rejects.toMatchObject({status:410,code});
  expect(expired).toHaveBeenCalledTimes(code==="account_deleted"?1:0);
});
