import { afterEach,beforeEach,describe,expect,it,vi } from "vitest";
import { IDBFactory } from "fake-indexeddb";
import { kv,resetKvConnectionForTests,setKvBackendForTests,writeGenerationKey } from "../src/kvstore";
import { stageLocalRotation,resumeLocalRotation,hasLocalRotation } from "../src/localRotation";
import { stageLocalErasure,confirmLocalErasure } from "../src/localErasure";
import { encrypt,decrypt,toBase64,fromBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import * as cryptoCore from "../src/crypto/core";
import { saveSafetyPlan,loadSafetyPlan,EMPTY_SAFETY_PLAN } from "../src/safetyPlan";
import { enqueue,flushQueue,requeueRejected } from "../src/offlineQueue";
import { api,ApiError } from "../src/api/client";
const owner="idb-rotation",draft=`mindpattern.draft.active.${owner}`,oldKey=new Uint8Array(32).fill(2),newKey=new Uint8Array(32).fill(3);
const credential={operation_id:"11111111-1111-4111-8111-111111111111",new_salt:toBase64(new Uint8Array(16).fill(4)),new_verifier:toBase64(newKey)};
beforeEach(()=>{setKvBackendForTests(null);resetKvConnectionForTests();vi.stubGlobal("indexedDB",new IDBFactory());vi.stubGlobal("navigator",{locks:{request:async(_name:string,run:()=>Promise<unknown>)=>run()}});});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();resetKvConnectionForTests();});
async function ciphertext(text:string){return toBase64(await encrypt(oldKey,new TextEncoder().encode(text),buildAad("draft",owner)));}
async function unfencedLegacyWrite(value:string){
 const request=indexedDB.open("mindpattern",1);const db=await new Promise<IDBDatabase>((resolve,reject)=>{request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);});
 try{await new Promise<void>((resolve,reject)=>{const tx=db.transaction("kv","readwrite");tx.objectStore("kv").put(value,draft);tx.oncomplete=()=>resolve();tx.onabort=()=>reject(tx.error);tx.onerror=()=>reject(tx.error);});}finally{db.close();}
}
describe("transactional migration custody",()=>{
 it("rejects a pre-rotation encrypted callback after checkpoint cleanup, retaining the readable current plan",async()=>{
  const originalPlan={...EMPTY_SAFETY_PLAN,coping:"Acknowledged plan before rotation"};
  await saveSafetyPlan(oldKey,owner,originalPlan);
  const actualEncrypt=cryptoCore.encrypt;let release:(()=>void)|undefined;
  vi.spyOn(cryptoCore,"encrypt").mockImplementation(async(...args)=>{
    const blob=await actualEncrypt(...args);
    if(new TextDecoder().decode(args[1]).includes("Suspended old-key writing"))await new Promise<void>(resolve=>{release=resolve;});
    return blob;
  });
  const late=saveSafetyPlan(oldKey,owner,{...originalPlan,coping:"Suspended old-key writing"});
  const rejected=expect(late).rejects.toThrow("not saved");
  for(let i=0;i<50&&!release;i++)await new Promise(resolve=>setTimeout(resolve,0));
  expect(release).toBeTypeOf("function");
  await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
  expect(await hasLocalRotation(owner)).toBe(false);
  release!();await rejected;
  expect(await loadSafetyPlan(newKey,owner)).toEqual(originalPlan);
  await expect(saveSafetyPlan(oldKey,owner,{...originalPlan,coping:"An old-key callback started after cleanup"})).rejects.toThrow("old account key");
  await expect(kv.setItem(`mindpattern.safetyPlan.${owner}`,await ciphertext("unpermitted"))).rejects.toThrow("not saved");
  await saveSafetyPlan(newKey,owner,{...originalPlan,coping:"Fresh current-key writing"});
  expect((await loadSafetyPlan(newKey,owner))?.coping).toBe("Fresh current-key writing");
 });
 it("rejects delayed old-key queue insertion and accepts a fresh key-bound producer after restart",async()=>{
  const permit=await kv.captureWritePermit(owner,oldKey),id="delayed-queue";
  const blob=toBase64(await encrypt(oldKey,new TextEncoder().encode("old queued writing"),buildAad("entry",owner,id,"1")));
  await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
  await expect(enqueue({userId:owner,clientEntryId:id,blobB64:blob,entryDate:"2026-10-03"},permit)).rejects.toThrow("not saved");
  await expect(enqueue({userId:owner,clientEntryId:id,blobB64:blob,entryDate:"2026-10-03"})).rejects.toThrow("generation permit");
  resetKvConnectionForTests();
  const current=await kv.captureWritePermit(owner,newKey),newId="current-queue";
  const currentBlob=toBase64(await encrypt(newKey,new TextEncoder().encode("fresh queued writing"),buildAad("entry",owner,newId,"1")));
  await enqueue({userId:owner,clientEntryId:newId,blobB64:currentBlob,entryDate:"2026-10-03"},current);
  const key=(await kv.keys()).find(key=>key.startsWith("mindpattern/queue.v1.items."))!;
  expect(await kv.getItem(key)).toContain(currentBlob);
  expect(await kv.getItem(writeGenerationKey(owner))).not.toContain(toBase64(newKey));
 });
 it("prevents an old flush's rejection from reinserting old blobs after rotation",async()=>{
  const id="late-rejected-entry",entry={userId:owner,clientEntryId:id,blobB64:toBase64(await encrypt(oldKey,new TextEncoder().encode("rejectable words"),buildAad("entry",owner,id,"1"))),entryDate:"2026-10-03"};
  await enqueue(entry,await kv.captureWritePermit(owner,oldKey));
  let reject:((error:Error)=>void)|undefined;
  vi.spyOn(api,"createEntry").mockImplementation(()=>new Promise((_resolve,rejectRequest)=>{reject=rejectRequest;}));
  const flush=flushQueue(owner),rejected=expect(flush).rejects.toThrow("not saved");
  for(let i=0;i<50&&!reject;i++)await new Promise(resolve=>setTimeout(resolve,0));expect(reject).toBeTypeOf("function");
  await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
  reject!(new ApiError(422,"rejected"));await rejected;
  const queue=(await kv.keys()).find(key=>key.startsWith("mindpattern/queue.v1.items."))!;
  const raw=JSON.parse((await kv.getItem(queue))!) as {items:Array<{blobB64:string}>};
  expect(new TextDecoder().decode(await decrypt(newKey,fromBase64(raw.items[0]!.blobB64),buildAad("entry",owner,id,"1")))).toBe("rejectable words");
  expect((await kv.keys()).some(key=>key.startsWith("mindpattern/queue.v1.rejected."))).toBe(false);
 });
 it("prevents a suspended rejected-store drain from committing with a superseded generation",async()=>{
  const id="requeue-after-rotation",scope=btoa(`${window.location.origin}\0${owner}`).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,""),slot=`mindpattern/queue.v1.rejected.${scope}`;
  const item={userId:owner,clientEntryId:id,blobB64:toBase64(await encrypt(oldKey,new TextEncoder().encode("retained rejected words"),buildAad("entry",owner,id,"1"))),entryDate:"2026-10-03"};
  await kv.setItem(slot,JSON.stringify({v:1,items:[item]}));
  let release:(()=>void)|undefined;
  vi.stubGlobal("navigator",{locks:{request:async(name:string,run:()=>Promise<unknown>)=>{
    if(name.includes("queue-flush"))await new Promise<void>(resolve=>{release=resolve;});
    return run();
  }}});
  const drain=requeueRejected(owner),rejected=expect(drain).rejects.toThrow("not saved");
  for(let i=0;i<50&&!release;i++)await new Promise(resolve=>setTimeout(resolve,0));expect(release).toBeTypeOf("function");
  await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
  const current=await kv.getItem(slot);release!();await rejected;expect(await kv.getItem(slot)).toBe(current);
 });
 it("retains a durable minimal deletion fence so late writes cannot resurrect erased ciphertext",async()=>{
  const permit=await kv.captureWritePermit(owner,oldKey),original=await ciphertext("private deleted writing");await kv.setItem(draft,original,permit);
  await stageLocalErasure(owner);await confirmLocalErasure(owner);resetKvConnectionForTests();
  await expect(kv.setItem(draft,original,permit)).rejects.toThrow("not saved");
  await expect(kv.captureWritePermit(owner,oldKey)).rejects.toThrow("old account key");
  expect(await kv.getItem(draft)).toBeNull();
  expect(JSON.parse((await kv.getItem(writeGenerationKey(owner)))!)).toMatchObject({v:1,deleted:true});
  expect((await kv.getItem(writeGenerationKey(owner)))!).not.toContain("keyTag");
  await expect(kv.adoptVerifiedWriteGeneration(owner,newKey)).rejects.toThrow("erased");
 });
 it("adopts a separately verified new key without altering unreadable local ciphertext, and fences prior callbacks",async()=>{
  const plan={...EMPTY_SAFETY_PLAN,coping:"Original ciphertext is recovery evidence"};await saveSafetyPlan(oldKey,owner,plan);
  await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
  const priorPermit=await kv.captureWritePermit(owner,newKey),slot=`mindpattern.safetyPlan.${owner}`,raw=await kv.getItem(slot),nextKey=new Uint8Array(32).fill(6);
  await expect(kv.captureWritePermit(owner,nextKey)).rejects.toThrow("old account key");
  await kv.adoptVerifiedWriteGeneration(owner,nextKey,()=>false);expect(await kv.getItem(writeGenerationKey(owner))).toBe(priorPermit.generation);
  await kv.adoptVerifiedWriteGeneration(owner,nextKey);await kv.adoptVerifiedWriteGeneration(owner,nextKey);
  expect((await kv.captureWritePermit(owner,nextKey)).keyBound).toBe(true);expect(await kv.getItem(slot)).toBe(raw);
  await expect(kv.setItem(slot,raw!,priorPermit)).rejects.toThrow("not saved");
  await expect(loadSafetyPlan(nextKey,owner)).rejects.toThrow("authenticated");expect(await loadSafetyPlan(newKey,owner)).toEqual(plan);
  await kv.setItem("guarded","before");await expect(kv.compareAndSetForMigration("guarded","before","after",undefined,()=>false)).rejects.toThrow("not saved atomically");expect(await kv.getItem("guarded")).toBe("before");
 });
 it("durably upgrades legacy checkpoints before generation advancement and keeps completed resumes idempotent",async()=>{
  await kv.setItem(draft,await ciphertext("legacy checkpoint words"));await stageLocalRotation(owner,oldKey,newKey,credential);
  const slot=`mindpattern.localRotation.${owner}`,raw=(await kv.getItem(slot))!,plain=await decrypt(newKey,fromBase64(raw),buildAad("local-rotation",owner));
  const legacy=JSON.parse(new TextDecoder().decode(plain));plain.fill(0);delete legacy.generationBefore;delete legacy.generationAfter;
  await kv.setItem(slot,toBase64(await encrypt(newKey,new TextEncoder().encode(JSON.stringify(legacy)),buildAad("local-rotation",owner))));
  await resumeLocalRotation(owner,newKey,credential.new_salt);await resumeLocalRotation(owner,newKey,credential.new_salt);
  expect(new TextDecoder().decode(await decrypt(newKey,fromBase64((await kv.getItem(draft))!),buildAad("draft",owner)))).toBe("legacy checkpoint words");
  await expect(kv.captureWritePermit(owner,oldKey)).rejects.toThrow("old account key");
 });
 it("preserves a legacy competing writer injected after the preliminary read and before migration comparison",async()=>{
  const original=await ciphertext("original"),competing=await ciphertext("newer writing");await kv.setItem(draft,original);await stageLocalRotation(owner,oldKey,newKey,credential);
  const actual=kv.getItem.bind(kv);let inserted=false;
  const read=vi.spyOn(kv,"getItem").mockImplementation(async key=>{const value=await actual(key);if(key===draft&&!inserted){inserted=true;await unfencedLegacyWrite(competing);}return value;});
  await expect(resumeLocalRotation(owner,newKey,credential.new_salt)).rejects.toThrow("changed during migration");read.mockRestore();
  expect(await kv.getItem(draft)).toBe(competing);expect(await hasLocalRotation(owner)).toBe(true);
  expect(new TextDecoder().decode(await decrypt(oldKey,fromBase64(competing),buildAad("draft",owner)))).toBe("newer writing");
 });
 it("fences normal writes and deletes while a checkpoint exists, but permits confirmed account erasure and other owners",async()=>{
  const original=await ciphertext("private original");await kv.setItem(draft,original);await stageLocalRotation(owner,oldKey,newKey,credential);
  await expect(kv.setItem(draft,await ciphertext("late autosave"))).rejects.toThrow("not saved");await expect(kv.removeItem(draft)).rejects.toThrow("did not finish");expect(await kv.getItem(draft)).toBe(original);
  const other="mindpattern.draft.active.other-owner";await kv.setItem(other,"other ciphertext");
  await stageLocalErasure(owner);await confirmLocalErasure(owner);expect(await kv.getItem(draft)).toBeNull();expect(await hasLocalRotation(owner)).toBe(false);expect(await kv.getItem(other)).toBe("other ciphertext");
 });
 it("commits matching snapshots atomically and fails closed when an injected store lacks CAS",async()=>{
  await kv.setItem("plain","before");expect(await kv.compareAndSetForMigration("plain","wrong","after")).toBe(false);expect(await kv.getItem("plain")).toBe("before");expect(await kv.compareAndSetForMigration("plain","before","after")).toBe(true);expect(await kv.getItem("plain")).toBe("after");
  setKvBackendForTests({getItem:async()=>"before",setItem:vi.fn(),removeItem:async()=>{}});await expect(kv.compareAndSetForMigration("plain","before","after")).rejects.toThrow("not saved atomically");
 });
});
