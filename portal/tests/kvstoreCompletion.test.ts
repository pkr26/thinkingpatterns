import { runTestControl } from "./helpers/testControl";
import {afterEach,beforeEach,expect,it,vi} from "vitest";
import {kv,resetKvConnectionForTests,setKvBackendForTests,StorageReadError} from "../src/kvstore";
beforeEach(()=>{runTestControl(setKvBackendForTests, null);runTestControl(resetKvConnectionForTests);});
afterEach(()=>{vi.unstubAllGlobals();runTestControl(resetKvConnectionForTests);});
it.each(["read","keys","write","delete"] as const)("acknowledges a completed host %s event before displaying a durable result",async operation=>{
  const request={result:operation==="keys"?["saved"]:"ciphertext",onsuccess:null,onerror:null} as unknown as IDBRequest;
  const transaction={oncomplete:null,onerror:null,onabort:null,objectStore:()=>({get:()=>request,getAllKeys:()=>request,put:()=>request,delete:()=>request})} as unknown as IDBTransaction;
  const db={onclose:null,transaction:()=>transaction};
  const open={result:db,onsuccess:null} as unknown as IDBOpenDBRequest;
  vi.stubGlobal("indexedDB",{open:()=>open});
  const outcome:{settled:boolean,value?:unknown,error?:unknown}={settled:false};
  const promise=operation==="read"?kv.getItem("saved"):operation==="keys"?kv.keys():operation==="write"?kv.setItem("saved","ciphertext"):kv.removeItem("saved");
  void promise.then(value=>{outcome.settled=true;outcome.value=value;},error=>{outcome.settled=true;outcome.error=error;});
  open.onsuccess?.call(open,new Event("success"));
  for(let step=0;step<20;step++)await Promise.resolve();
  request.onsuccess?.call(request,new Event("success"));transaction.oncomplete?.call(transaction,new Event("complete"));
  for(let step=0;step<20;step++)await Promise.resolve();
  expect(outcome.settled).toBe(true);expect(outcome.error).toBeUndefined();
  expect(outcome.value).toEqual(operation==="read"?"ciphertext":operation==="keys"?["saved"]:undefined);
});
it.each(["absent","denied"])("settles unavailable %s storage before exposing record absence",async mode=>{
 vi.stubGlobal("indexedDB",mode==="absent"?undefined:{open(){throw new Error("host denied opening");}});
 let outcome:unknown;let settled=false;void kv.getItem("saved").then(()=>{settled=true;},error=>{settled=true;outcome=error;});
 for(let step=0;step<20;step++)await Promise.resolve();expect(settled).toBe(true);expect(outcome).toBeInstanceOf(StorageReadError);
});
