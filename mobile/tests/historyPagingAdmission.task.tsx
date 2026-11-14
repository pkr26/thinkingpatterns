/** Explicit Node22 concurrent React renderer task profile. Platform and
 * fetch/Response transports are declared hosts; API/AES/vault/storage execute
 * real code. Each input resolves the current tree, never an old responder.
 * This is not a physical-device scheduling claim.
 */
import React from "react";
import ReactTestRenderer, { act } from "react-test-renderer";
import { beforeEach, afterEach, expect, it, vi } from "vitest";
import { Text, TouchableOpacity, FlatList, Alert } from "react-native";
import { appendFileSync } from "node:fs";
import { HistoryScreen } from "../src/screens/HistoryScreen";
import { SessionProvider } from "../src/store";
import { ThemeProvider } from "../src/theme";
import { api } from "../src/api/client";
import { vault } from "../src/vault";
import { encryptEntry } from "../src/crypto/journalCrypto";
import { resetEntryVersionMirrors } from "../src/entryVersions";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { setSecureStoreBackend } from "../src/secureStore";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";

const USER="c".repeat(32),KEY=Buffer.alloc(32,7),DAY="2026-10-05";
type Root=ReturnType<typeof ReactTestRenderer.create>;
let root:Root|undefined,applicationErrors:unknown[]=[],phases:unknown[]=[];
const gates:Array<()=>void>=[];
const rejectApplication=(e:unknown)=>applicationErrors.push(e);
const turn=()=>new Promise<void>(resolve=>setImmediate(resolve));
async function flush(){await act(async()=>{for(let i=0;i<80;i++)await Promise.resolve();});}
function pause(){let release!:()=>void;const wait=new Promise<void>(resolve=>release=resolve);gates.push(release);return{wait,release};}
function row(id:string,text:string,version=1){return{id:`server-${id}`,client_entry_id:id,entry_date:DAY,received_at:`${DAY}T12:00:00Z`,content_version:version,blob:encryptEntry({dataKey:KEY},USER,id,text,DAY,null,undefined,version).blobB64};}
function answer(url:string,body:unknown,headers:Record<string,string>={},status=200){const r=new Response(JSON.stringify(body),{status,headers:{"Content-Type":"application/json",...headers}});Object.defineProperty(r,"url",{value:url});return r;}
function paging(){return root!.root.findAllByType(TouchableOpacity).filter(n=>n.props.accessibilityLabel==="Load older encrypted journal entries");}
function text(){return root!.root.findAllByType(Text).map(n=>n.props.children).flat(Infinity).filter(x=>typeof x==="string"||typeof x==="number").join(" ");}
async function pressPaging(){const current=paging();expect(current).toHaveLength(1);expect(current[0]!.props.disabled).not.toBe(true);await act(async()=>current[0]!.props.onPress());await flush();}
async function mount(){await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SessionProvider><HistoryScreen navigation={{navigate(){}}}/></SessionProvider></ThemeProvider>);});await flush();}
async function currentInputTaskAfter(trigger:()=>void,providerState:()=>Record<string,unknown>){
 (globalThis as {IS_REACT_ACT_ENVIRONMENT?:boolean}).IS_REACT_ACT_ENVIRONMENT=false;
 try{
  await new Promise<void>((resolve,reject)=>setImmediate(()=>{
   // The independent input Task is armed before trigger schedules render work.
   setImmediate(()=>{
    try{
     const current=paging();phases.push({phase:"input-task",controlCount:current.length,disabled:current.map(n=>Boolean(n.props.disabled)),...providerState()});
     if(current.length!==1||current[0]!.props.disabled)throw new Error("SetupError: current enabled paging control was not admitted before commit");
     current[0]!.props.onPress();setImmediate(resolve);
    }catch(error){reject(error);}
   });
   try{trigger();}catch(error){reject(error);}
  }));
  await turn();
 }finally{(globalThis as {IS_REACT_ACT_ENVIRONMENT?:boolean}).IS_REACT_ACT_ENVIRONMENT=true;await flush();}
}
beforeEach(async()=>{
 applicationErrors=[];phases=[];(globalThis as {IS_REACT_ACT_ENVIRONMENT?:boolean}).IS_REACT_ACT_ENVIRONMENT=true;
 process.on("unhandledRejection",rejectApplication);vi.useRealTimers();vi.restoreAllMocks();storage.__reset();
 runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);runTestControl(resetEntryVersionMirrors);
 vault.lock();await api.setSession("current-paging-task-bearer",USER,"current-paging-task");
 vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32,3),dataKey:Buffer.from(KEY)},USER);vi.mocked(Alert.alert).mockClear();
});
afterEach(async()=>{
 for(const release of gates.splice(0))release();await flush();await turn();await flush();
 if(root){await act(async()=>root!.unmount());root=undefined;}vault.lock();await api.clearSession();await turn();
 process.off("unhandledRejection",rejectApplication);vi.restoreAllMocks();vi.unstubAllGlobals();
 if(process.env.HISTORY_PAGING_TASK_WITNESS)appendFileSync(process.env.HISTORY_PAGING_TASK_WITNESS,JSON.stringify({test:expect.getState().currentTestName,node:process.version,phases,declaredPlatformAndFetchResponseHosts:true,physicalDeviceSchedulingClaim:false,applicationErrors:applicationErrors.map(String)})+"\n");
 expect(applicationErrors,"owned application error surface").toEqual([]);
});

it("a current mounted paging input decrypts and appends its requested page",async()=>{
 const first=row("task-first","Native current first writing"),older=row("task-older","Native current older writing");
 vi.stubGlobal("fetch",async(url:string)=>new URL(url).pathname.endsWith("/entries")?new URL(url).searchParams.get("offset")==="1"?answer(url,[older],{"X-Entries-Revision":"1"}):answer(url,[first],{"X-Entries-Revision":"1","X-Next-Offset":"1"}):answer(url,{}));
 await mount();await pressPaging();expect(text()).toContain("Native current older writing");expect(paging()).toHaveLength(0);
});

it("a live paging input task refuses a current replacement refresh before its hide commit",async()=>{
 const held=pause(),first=row("task-refresh-first","Native current refresh writing"),older=row("task-refresh-older","Native prohibited concurrent older writing");let initialReads=0,refreshWaiting=false;
 vi.stubGlobal("fetch",async(url:string)=>{
  if(!new URL(url).pathname.endsWith("/entries"))return answer(url,{});
  if(new URL(url).searchParams.get("offset")==="1")return answer(url,[older],{"X-Entries-Revision":"1"});
  if(++initialReads===2){refreshWaiting=true;await held.wait;}
  return answer(url,[first],{"X-Entries-Revision":"1","X-Next-Offset":"1"});
 });
 try{
  await mount();await currentInputTaskAfter(()=>{root!.root.findByType(FlatList).props.refreshControl.props.onRefresh();},()=>({refreshWaiting}));
  expect(refreshWaiting).toBe(true);expect(text()).not.toContain("Native prohibited concurrent older writing");
  held.release();await flush();expect(text()).toContain("Native current refresh writing");
 }finally{held.release();await flush();await turn();await flush();}
});

it.each(["continuation","terminal"]as const)("a live paging input task cannot reopen the %s fifth short page before its cap commit",async completion=>{
 const records=Array.from({length:completion==="terminal"?47:60},(_,i)=>row(`task-cap-${i}`,`Native task capped writing ${i}`));let pages=0;
 vi.stubGlobal("fetch",async(url:string)=>{
  if(!new URL(url).pathname.endsWith("/entries"))return answer(url,{});
  const offset=Number(new URL(url).searchParams.get("offset")??0);pages++;
  if(pages>5)return answer(url,{detail:"Native sixth request temporarily unavailable"},{},503);
  return answer(url,records.slice(offset,offset+10),{"X-Entries-Revision":"1",...(offset<40||completion==="continuation"?{"X-Next-Offset":String(offset+10)}:{})});
 });
 await mount();for(let i=0;i<3;i++)await pressPaging();
 await currentInputTaskAfter(()=>{const current=paging();if(current.length!==1||current[0]!.props.disabled)throw new Error("SetupError: fifth-page trigger lacks a live control");current[0]!.props.onPress();},()=>({completedNativePageResponses:pages,completion}));
 expect(text()).toContain(`Native task capped writing ${completion==="terminal"?46:49}`);expect(text()).not.toContain("Native task capped writing 50");
 expect(paging()).toHaveLength(0);expect(vi.mocked(Alert.alert).mock.calls).toEqual([]);
});

it("a live paging input task after a finite refresh outage preserves downloaded generation two",async()=>{
 const first=row("task-offline-first","Native first pre-outage writing"),older=row("task-offline-new","Native downloaded generation two",2),replay=row("task-offline-new","Native rejected generation one",1);let fail=false,outageDelivered=false,cold=false;
 vi.stubGlobal("fetch",async(url:string)=>{
  if(!new URL(url).pathname.endsWith("/entries"))return answer(url,{});
  if(fail){fail=false;outageDelivered=true;throw new TypeError("Native radio offline");}
  const continuation=new URL(url).searchParams.get("offset")==="1";
  return answer(url,cold?[replay]:continuation?[older]:[first],{"X-Entries-Revision":"1",...(!cold&&!continuation?{"X-Next-Offset":"1"}:{})});
 });
 await mount();fail=true;
 await currentInputTaskAfter(()=>{root!.root.findByType(FlatList).props.refreshControl.props.onRefresh();},()=>({outageDelivered}));
 expect(outageDelivered).toBe(true);expect(text()).toContain("Native downloaded generation two");
 await act(async()=>{root!.unmount();root=undefined;});runTestControl(resetEntryVersionMirrors);cold=true;await mount();
 expect(text()).not.toContain("Native rejected generation one");expect(text()).toContain("Sign out");
});
