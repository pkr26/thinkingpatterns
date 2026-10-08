/** Exported migration + public storage/lock contracts, real browser crypto;
 * no rendered Login/Settings or actual IndexedDB-engine scheduling claim. */
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import { kv,setKvBackendForTests } from "../src/kvstore";
import { stageLocalRotation,resumeLocalRotation } from "../src/localRotation";
import { knownEntryVersion,observeEntryVersions,resetEntryVersionMirrors } from "../src/entryVersions";
import { decrypt,encrypt,fromBase64,toBase64 } from "../src/crypto/core";
import { buildAad } from "../src/crypto/aad";
import { withLock } from "../src/platform";
const owner="rotation-public-custody",oldKey=new Uint8Array(new ArrayBuffer(32)).fill(41),newKey=new Uint8Array(new ArrayBuffer(32)).fill(43);
const credential={operation_id:"11111111-1111-4111-8111-111111111111",new_salt:toBase64(new Uint8Array(new ArrayBuffer(16)).fill(47)),new_verifier:toBase64(newKey)};
let physical:Map<string,string>,checkpointCommitReceipt:Promise<void>|undefined,destinationCommitReceipt:Promise<void>|undefined,failedDestination:string|undefined;
beforeEach(()=>{
 physical=new Map();checkpointCommitReceipt=undefined;destinationCommitReceipt=undefined;failedDestination=undefined;resetEntryVersionMirrors();
 setKvBackendForTests({async getItem(k){return physical.get(k)??null;},async setItem(k,v){physical.set(k,v);},async removeItem(k){physical.delete(k);},async keys(){return [...physical.keys()];},async compareAndSet(k,expected,v){if(k===`mindpattern.localRotation.${owner}`)await checkpointCommitReceipt;else if(k===`mindpattern.safetyPlan.${owner}`)await destinationCommitReceipt;if(k===failedDestination)throw new Error("physical destination commit refused");if((physical.get(k)??null)!==expected)return false;physical.set(k,v);return true;}});
});
afterEach(()=>{setKvBackendForTests(null);resetEntryVersionMirrors();vi.unstubAllGlobals();vi.restoreAllMocks();});
function exclusiveBrowserLocks(){const tails=new Map<string,Promise<unknown>>();vi.stubGlobal("navigator",{locks:{request<T>(name:string,callback:()=>Promise<T>):Promise<T>{const run=(tails.get(name)??Promise.resolve()).then(callback,callback);tails.set(name,run.catch(()=>{}));return run;}}});}
it.each(["stage","resume"] as const)("%s waits for the shared browser migration lock",async operation=>{
 exclusiveBrowserLocks();if(operation==="resume")await stageLocalRotation(owner,oldKey,newKey,credential);
 let entered!:()=>void,release!:()=>void;const admitted=new Promise<void>(r=>{entered=r;}),receipt=new Promise<void>(r=>{release=r;});
 const held=withLock("local-rotation",async()=>{entered();await receipt;});await admitted;const before=[...physical];
 const work=operation==="stage"?stageLocalRotation(owner,oldKey,newKey,credential):resumeLocalRotation(owner,newKey,credential.new_salt);let timer:ReturnType<typeof setTimeout>|undefined;
 try{expect(await Promise.race([work.then(()=>"settled",()=>"settled"),new Promise<string>(r=>{timer=setTimeout(()=>r("held behind migration lock"),100);})])).toBe("held behind migration lock");expect([...physical]).toEqual(before);}
 finally{if(timer!==undefined)clearTimeout(timer);release();await held;await work;}
});
it("a modern checkpoint finishes without acquiring an unrelated unfinished checkpoint rewrite receipt",async()=>{
 await stageLocalRotation(owner,oldKey,newKey,credential);
 let release!:()=>void;checkpointCommitReceipt=new Promise<void>(r=>{release=r;});
 const work=resumeLocalRotation(owner,newKey,credential.new_salt);let timer:ReturnType<typeof setTimeout>|undefined;
 try{expect(await Promise.race([work.then(()=>"settled"),new Promise<string>(r=>{timer=setTimeout(()=>r("unfinished native checkpoint rewrite"),100);})])).toBe("settled");expect(physical.has(`mindpattern.localRotation.${owner}`)).toBe(false);}
 finally{if(timer!==undefined)clearTimeout(timer);release();await work;}
});
it("migration clears the prior-key process high-water mark when its durable ciphertext was removed before staging",async()=>{
 const id="retired-key-entry",versions=`mindpattern.entryVersions.${owner}`;
 await observeEntryVersions(owner,oldKey,[{clientEntryId:id,contentVersion:7}]);
 await kv.removeItem(versions);expect(await knownEntryVersion(owner,oldKey,id)).toBe(7);
 await stageLocalRotation(owner,oldKey,newKey,credential);await resumeLocalRotation(owner,newKey,credential.new_salt);
 expect(await knownEntryVersion(owner,newKey,id)).toBeNull();
});
it("resumes an already durable destination without labeling its new-key ciphertext a conflict",async()=>{
 const slot=`mindpattern.safetyPlan.${owner}`,text="acknowledged migrated plan";
 physical.set(slot,toBase64(await encrypt(oldKey,new TextEncoder().encode(text),buildAad("safety-plan",owner))));
 await stageLocalRotation(owner,oldKey,newKey,credential);
 const bytes=await decrypt(newKey,fromBase64(physical.get(`mindpattern.localRotation.${owner}`)!),buildAad("local-rotation",owner));
 const journal=JSON.parse(new TextDecoder().decode(bytes)) as {records:Array<{key:string;after:string}>};bytes.fill(0);
 // A previous process completed this physical destination write before
 // the checkpoint's terminal removal. Resume must accept both receipts.
 for(const record of journal.records)physical.set(record.key,record.after);
 await resumeLocalRotation(owner,newKey,credential.new_salt);
 const plan=await decrypt(newKey,fromBase64(physical.get(slot)!),buildAad("safety-plan",owner));expect(new TextDecoder().decode(plan)).toBe(text);plan.fill(0);
 expect(physical.has(`mindpattern.localRotation.${owner}`)).toBe(false);
});
it("an upgraded legacy checkpoint remains authenticated for recovery after a refused destination commit",async()=>{
 const slot=`mindpattern.safetyPlan.${owner}`,journalKey=`mindpattern.localRotation.${owner}`;
 physical.set(slot,toBase64(await encrypt(oldKey,new TextEncoder().encode("retained plan"),buildAad("safety-plan",owner))));
 await stageLocalRotation(owner,oldKey,newKey,credential);
 const bytes=await decrypt(newKey,fromBase64(physical.get(journalKey)!),buildAad("local-rotation",owner));
 const legacy=JSON.parse(new TextDecoder().decode(bytes));bytes.fill(0);delete legacy.generationBefore;delete legacy.generationAfter;
 physical.set(journalKey,toBase64(await encrypt(newKey,new TextEncoder().encode(JSON.stringify(legacy)),buildAad("local-rotation",owner))));
 failedDestination=slot;await expect(resumeLocalRotation(owner,newKey,credential.new_salt)).rejects.toThrow("not saved atomically");failedDestination=undefined;
 // The public retry opens the actual retained ciphertext with its normal
 // authenticated domain, then completes the same migration.
 expect(await stageLocalRotation(owner,oldKey,newKey,credential)).toEqual(credential);
 await resumeLocalRotation(owner,newKey,credential.new_salt);expect(physical.has(journalKey)).toBe(false);
});
it("reports conflicting current ciphertext before acquiring an unfinished destination comparison",async()=>{
 const slot=`mindpattern.safetyPlan.${owner}`;
 physical.set(slot,toBase64(await encrypt(oldKey,new TextEncoder().encode("old plan"),buildAad("safety-plan",owner))));
 await stageLocalRotation(owner,oldKey,newKey,credential);
 const competing=toBase64(await encrypt(oldKey,new TextEncoder().encode("independent newer writing"),buildAad("safety-plan",owner)));physical.set(slot,competing);
 let release!:()=>void;destinationCommitReceipt=new Promise<void>(r=>{release=r;});
 const work=resumeLocalRotation(owner,newKey,credential.new_salt),settled=work.then(()=>"unexpected success",error=>error instanceof Error?error.message:"unexpected error");let timer:ReturnType<typeof setTimeout>|undefined;
 try{expect(await Promise.race([settled,new Promise<string>(r=>{timer=setTimeout(()=>r("unfinished Native destination comparison"),100);})])).toContain("changed during migration");expect(physical.get(slot)).toBe(competing);}
 finally{if(timer!==undefined)clearTimeout(timer);release();await settled;}
});
