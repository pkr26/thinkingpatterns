import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { kv, setKvBackendForTests } from "../src/kvstore";
import { encrypt, decrypt, toBase64, fromBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { stageLocalRotation, resumeLocalRotation, hasLocalRotation, rotationSalt, rotationDataKey } from "../src/localRotation";
const oldKey = new Uint8Array(32).fill(2), newKey = new Uint8Array(32).fill(3);
const owner = "rotation-user";
const credential = { operation_id: "11111111-1111-4111-8111-111111111111",new_salt:toBase64(new Uint8Array(16).fill(4)),new_verifier:toBase64(newKey),consent_wraps:[] };
let records: Map<string,string>; let fail = "";
beforeEach(() => {
 records = new Map(); fail = "";
 setKvBackendForTests({ getItem:async key => records.get(key) ?? null,setItem:async(key,value) => { if(key === fail) throw new Error("quota"); records.set(key,value); },compareAndSet:async(key,expected,value)=>{if(key===fail)throw new Error("quota");if((records.get(key)??null)!==expected)return false;records.set(key,value);return true;},removeItem:async key => { records.delete(key); },keys:async()=>[...records.keys()] });
 vi.stubGlobal("navigator",{locks:{request:async(_name:string,run:()=>Promise<unknown>)=>run()}});
});
afterEach(()=>{setKvBackendForTests(null);vi.unstubAllGlobals();});
async function seed(key:string,domain:string,text:string) { await kv.setItem(key,toBase64(await encrypt(oldKey,new TextEncoder().encode(text),buildAad(domain,owner)))); }
describe("durable local key migration",()=>{
 it("stages before mutation, fences unconfirmed remote state, and resumes a partial destination failure without losing originals",async()=>{
  const draft=`mindpattern.draft.active.${owner}`,plan=`mindpattern.safetyPlan.${owner}`;
  await seed(draft,"draft","saved journal draft");await seed(plan,"safety-plan","saved safety plan"); const original=new Map(records);
  const staged=await stageLocalRotation(owner,oldKey,newKey,credential);expect(staged).toEqual(credential);expect(records.get(draft)).toBe(original.get(draft));expect(records.get(plan)).toBe(original.get(plan));
  const journal=records.get(`mindpattern.localRotation.${owner}`)!;expect(journal).not.toContain("saved journal");expect(journal).not.toContain(toBase64(oldKey));
  await expect(resumeLocalRotation(owner,newKey,"old-salt")).rejects.toThrow("not been confirmed");expect(records.get(draft)).toBe(original.get(draft));
  fail=plan;await expect(resumeLocalRotation(owner,newKey,credential.new_salt)).rejects.toThrow("not saved");expect(await hasLocalRotation(owner)).toBe(true);expect(records.get(plan)).toBe(original.get(plan));
  const resumedCredential=await stageLocalRotation(owner,oldKey,newKey,{...credential,operation_id:crypto.randomUUID()});expect(resumedCredential).toEqual(credential);
  fail="";await resumeLocalRotation(owner,newKey,credential.new_salt);expect(await hasLocalRotation(owner)).toBe(false);
  expect(new TextDecoder().decode(await decrypt(newKey,fromBase64(records.get(draft)!),buildAad("draft",owner)))).toBe("saved journal draft");
  expect(new TextDecoder().decode(await decrypt(newKey,fromBase64(records.get(plan)!),buildAad("safety-plan",owner)))).toBe("saved safety plan");
 });
 it("never overwrites concurrent local writing or hides an unreadable original",async()=>{
  const draft=`mindpattern.draft.active.${owner}`;await seed(draft,"draft","original");await stageLocalRotation(owner,oldKey,newKey,credential);
  records.set(draft,"concurrent ciphertext");await expect(resumeLocalRotation(owner,newKey,credential.new_salt)).rejects.toThrow("changed during migration");expect(records.get(draft)).toBe("concurrent ciphertext");expect(await hasLocalRotation(owner)).toBe(true);
  records.clear();records.set(draft,"malformed cipher");await expect(stageLocalRotation(owner,oldKey,newKey,credential)).rejects.toThrow();expect(records.get(draft)).toBe("malformed cipher");expect(await hasLocalRotation(owner)).toBe(false);
 });
 it("retains every valid legacy and v2 queue blob across rekey",async()=>{
  const key="mindpattern/queue.v1.rejected.test",items=[];
  for(const version of [null,"1"]) {const id=version ? "v2" : "legacy";const aad=version?buildAad("entry",owner,id,version):buildAad("entry",owner,id);items.push({userId:owner,clientEntryId:id,blobB64:toBase64(await encrypt(oldKey,new TextEncoder().encode(id),aad)),entryDate:"2026-10-01",attempts:3});}
  records.set(key,JSON.stringify({v:1,items}));await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
  const next=JSON.parse(records.get(key)!).items;expect(next).toHaveLength(2);expect(next[0].attempts).toBe(3);
  for(const item of next){const aad=item.clientEntryId==="legacy"?buildAad("entry",owner,item.clientEntryId):buildAad("entry",owner,item.clientEntryId,"1");expect(new TextDecoder().decode(await decrypt(newKey,fromBase64(item.blobB64),aad))).toBe(item.clientEntryId);}
 });
 it("keeps salt and random v2 candidate stable through exact retries",async()=>{
  const salt=await rotationSalt(owner,null);expect(await rotationSalt(owner,null)).toEqual(salt);
  const key=await rotationDataKey(owner,newKey);expect(await rotationDataKey(owner,newKey)).toEqual(key);expect(key).not.toEqual(newKey);
  await expect(rotationDataKey(owner,oldKey)).rejects.toThrow();
  records.set(`mindpattern.rotationSalt.${owner}`,toBase64(new Uint8Array(2)));await expect(rotationSalt(owner,null)).rejects.toThrow("invalid");
 });
});
