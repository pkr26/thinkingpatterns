import crypto from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import * as files from "./helpers/expoFsMock";
import { runTestControl } from "./helpers/testControl";
import { secureStore, setSecureStoreBackend } from "../src/secureStore";
import { api, DEFAULT_BASE_URL } from "../src/api/client";
import { accountStorageKey } from "../src/accountStorage";
import { advanceLocalWriteScope, __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { clearLocalRekey, localRekeyRequest, markLocalRekeyPhase, pendingLocalRekey, pendingLocalRekeyOldSalt, prepareLocalRekey, resumeLocalRekey, storeLocalRekeyRequest, storeLocalRekeyTokens, type AtomicRekeyBody } from "../src/localRekey";
import { emptySafetyPlan, loadSafetyPlan, saveSafetyPlan } from "../src/safetyPlan";
import { enqueueAudio, flushAudioQueue } from "../src/audioQueue";
import { encryptAudio } from "../src/crypto/journalCrypto";
import * as envelopeCrypto from "../src/crypto/envelope";
import { enqueue, flushQueue } from "../src/offlineQueue";

const USER="c".repeat(32),OLD=Buffer.alloc(32,5),NEXT=Buffer.alloc(32,9),SALT=Buffer.alloc(16,3).toString("base64");
const origin=new URL(DEFAULT_BASE_URL).origin,slot=accountStorageKey.localRekey(origin,USER);
beforeEach(async()=>{vi.restoreAllMocks();storage.__reset();files.__resetFiles();runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);await api.setSession("rekey-token",USER,"alice");});
afterEach(async()=>{vi.restoreAllMocks();await api.clearSession();vi.unstubAllGlobals();});
async function prepared(){await saveSafetyPlan(OLD,USER,{...emptySafetyPlan(),warningSigns:"My retained warning signs"});await prepareLocalRekey(USER,OLD,NEXT,{oldSaltB64:SALT});}
async function installed(){const index=JSON.parse((await secureStore.getItem(slot))!);const chunks:string[]=[];for(let i=0;i<index.parts;i++)chunks.push((await secureStore.getItem(`${slot}.chunk.${index.revision}.${i}`))!);return {index,value:JSON.parse(chunks.join(""))};}
async function replaceJournal(change:(value:any)=>unknown){const {index,value}=await installed(),text=JSON.stringify(change(value));await secureStore.setItem(`${slot}.chunk.${index.revision}.0`,text);await secureStore.setItem(slot,JSON.stringify({...index,parts:1}));}
async function requestBody():Promise<AtomicRekeyBody>{return {operation_id:(await localRekeyRequest(USER,NEXT)).operationId,new_salt:"new-salt",new_verifier:"new-verifier",consent_wraps:[]};}
it("reports an absent checkpoint honestly and installs a fresh verified key without needing replacements",async()=>{
  expect(await pendingLocalRekey(USER)).toBe(false);expect(await pendingLocalRekeyOldSalt(USER)).toBeNull();
  await expect(localRekeyRequest(USER,NEXT)).rejects.toThrow("Missing key-rotation checkpoint");
  await expect(storeLocalRekeyTokens(USER,NEXT,{old:"old",next:"new"})).rejects.toThrow("Missing key-rotation checkpoint");
  await expect(storeLocalRekeyRequest(USER,NEXT,{operation_id:"missing",new_salt:"salt",new_verifier:"proof",consent_wraps:[]})).rejects.toThrow("Missing key-rotation checkpoint");
  await expect(markLocalRekeyPhase(USER,"credential")).rejects.toThrow("Missing key-rotation checkpoint");
  await expect(resumeLocalRekey(USER,NEXT)).resolves.toBeUndefined();
  await saveSafetyPlan(NEXT,USER,emptySafetyPlan());expect(await loadSafetyPlan(NEXT,USER)).toEqual(emptySafetyPlan());
});
it("retains the retry salt, stable random operation and authenticated request exactly across native checkpoint rewrites",async()=>{
  await prepared();expect(await pendingLocalRekeyOldSalt(USER)).toBe(SALT);
  const first=await localRekeyRequest(USER,NEXT);expect(first.operationId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  const body=await requestBody();await storeLocalRekeyTokens(USER,NEXT,{old:"old-processing",next:"next-processing"});await storeLocalRekeyRequest(USER,NEXT,body);await storeLocalRekeyRequest(USER,NEXT,body);
  expect(await localRekeyRequest(USER,NEXT)).toEqual({operationId:first.operationId,tokens:{old:"old-processing",next:"next-processing"},body});
  await markLocalRekeyPhase(USER,"server");expect(await localRekeyRequest(USER,NEXT)).toEqual({operationId:first.operationId,tokens:{old:"old-processing",next:"next-processing"},body});
  await expect(resumeLocalRekey(USER,NEXT)).rejects.toThrow("confirmed online");await markLocalRekeyPhase(USER,"credential");await resumeLocalRekey(USER,NEXT);
  expect(await loadSafetyPlan(NEXT,USER)).toEqual({...emptySafetyPlan(),warningSigns:"My retained warning signs"});expect(await pendingLocalRekey(USER)).toBe(false);
});
it.each(["operation","request"])("refuses an inconsistent %s retry while preserving the original request",async kind=>{
  await prepared();const body=await requestBody();await storeLocalRekeyRequest(USER,NEXT,body);
  const different={...body,...(kind==="operation"?{operation_id:"d".repeat(36)}:{new_verifier:"changed"})};
  await expect(storeLocalRekeyRequest(USER,NEXT,different)).rejects.toThrow(kind==="operation"?"operation mismatch":"request changed");expect((await localRekeyRequest(USER,NEXT)).body).toEqual(body);
});
it.each([{old:"",next:"new"},{old:"old",next:""},{old:"",next:""}])("refuses empty possession tokens %j",async tokens=>{
  await prepared();await expect(storeLocalRekeyTokens(USER,NEXT,tokens)).rejects.toThrow("Invalid processing session");expect((await localRekeyRequest(USER,NEXT)).tokens).toBeUndefined();
});
it.each([null,7,"salt",Buffer.alloc(15).toString("base64"),Buffer.alloc(17).toString("base64")])("does not reuse an installed malformed old salt %j",async oldSaltB64=>{
  await prepared();await replaceJournal(value=>({...value,oldSaltB64}));expect(await pendingLocalRekeyOldSalt(USER)).toBeNull();expect(await pendingLocalRekey(USER)).toBe(true);
});
it.each(["version","changes","phase","operation"])("refuses a corrupt installed journal %s without replacing any authored ciphertext",async field=>{
  await prepared();await replaceJournal(value=>({...value,...(field==="version"?{v:2}:field==="changes"?{changes:{}}:field==="phase"?{phase:"unknown"}:{operationId:"00000000-0000-0000-0000-000000000000"})}));
  await expect(resumeLocalRekey(USER,NEXT,{credentialConfirmed:true})).rejects.toThrow("Invalid local key-rotation journal");expect(await loadSafetyPlan(OLD,USER)).toEqual({...emptySafetyPlan(),warningSigns:"My retained warning signs"});expect(await pendingLocalRekey(USER)).toBe(true);
});
it.each(["owner","origin"])("refuses a checkpoint belonging to another %s",async field=>{
  await prepared();await replaceJournal(value=>({...value,...(field==="owner"?{userId:"d".repeat(32)}:{origin:"https://another.example"})}));
  await expect(resumeLocalRekey(USER,NEXT,{credentialConfirmed:true})).rejects.toThrow("different account or server");expect(await pendingLocalRekey(USER)).toBe(true);
});
it.each(["empty-revision","fraction","zero","too-many","missing-chunk"])("preserves a damaged native checkpoint index (%s)",async mode=>{
  await prepared();const {index}=await installed();
  if(mode==="missing-chunk")await secureStore.removeItem(`${slot}.chunk.${index.revision}.0`);
  else await secureStore.setItem(slot,JSON.stringify({...index,...(mode==="empty-revision"?{revision:""}:{parts:mode==="fraction"?1.5:mode==="zero"?0:501})}));
  await expect(localRekeyRequest(USER,NEXT)).rejects.toThrow(mode==="missing-chunk"?"Incomplete rekey checkpoint":"Invalid rekey checkpoint index");expect(await pendingLocalRekey(USER)).toBe(true);
});
it("requires the authenticated checkpoint proof to carry its expected purpose",async()=>{
  await prepared();const nonce=Buffer.alloc(12,6),cipher=crypto.createCipheriv("aes-256-gcm",NEXT,nonce);cipher.setAAD(Buffer.from(JSON.stringify(["local-rekey",USER,origin])));
  const proof=Buffer.concat([nonce,cipher.update(Buffer.from("authenticated but wrong purpose")),cipher.final(),cipher.getAuthTag()]).toString("base64");
  await replaceJournal(value=>({...value,proof}));await expect(localRekeyRequest(USER,NEXT)).rejects.toThrow("Key-rotation proof mismatch");expect(await pendingLocalRekey(USER)).toBe(true);
});
it("opens a checkpoint written by an independent earlier client using the durable proof purpose",async()=>{
  await prepared();const nonce=Buffer.alloc(12,6),cipher=crypto.createCipheriv("aes-256-gcm",NEXT,nonce);cipher.setAAD(Buffer.from(JSON.stringify(["local-rekey",USER,origin])));
  const proof=Buffer.concat([nonce,cipher.update(Buffer.from("mindpattern-local-rekey/v1")),cipher.final(),cipher.getAuthTag()]).toString("base64");
  await replaceJournal(value=>({...value,proof}));expect((await localRekeyRequest(USER,NEXT)).operationId).toMatch(/^[0-9a-f-]{36}$/);
});
it.each(["prefix","suffix"])("refuses extra %s characters around a stored rotation UUID",async side=>{
  await prepared();await replaceJournal(value=>({...value,operationId:side==="prefix"?"x"+value.operationId:value.operationId+"x"}));
  await expect(localRekeyRequest(USER,NEXT)).rejects.toThrow("Invalid local key-rotation journal");
});
it("reads a complete native checkpoint at the maximum supported chunk count",async()=>{
  await prepared();const {index}=await installed();for(let i=1;i<500;i++)await secureStore.setItem(`${slot}.chunk.${index.revision}.${i}`,"");
  await secureStore.setItem(slot,JSON.stringify({...index,parts:500}));expect((await localRekeyRequest(USER,NEXT)).operationId).toMatch(/^[0-9a-f-]{36}$/);
});
it("retires superseded native checkpoint chunks on every successful rewrite",async()=>{
  await prepared();await storeLocalRekeyTokens(USER,NEXT,{old:"old",next:"next"});await storeLocalRekeyRequest(USER,NEXT,await requestBody());
  expect((await storage.getAllKeys()).filter(key=>key.startsWith(slot+".chunk."))).toHaveLength(1);
});
async function recorded(){await enqueueAudio({userId:USER,clientEntryId:"recorded",...encryptAudio({dataKey:OLD},USER,"recorded",Buffer.from("retained recording")),mime:"audio/m4a",durationSeconds:5});}
it("erases staged recordings if the native checkpoint cannot durably take ownership",async()=>{
  await recorded();const original=files.writeAsStringAsync.mock.calls.map(([uri])=>uri);const save=secureStore.setItem;
  vi.spyOn(secureStore,"setItem").mockImplementation(async(key,value)=>{if(key===slot)throw new Error("native checkpoint write failed");return save(key,value);});
  await expect(prepareLocalRekey(USER,OLD,NEXT)).rejects.toThrow("native checkpoint write failed");
  for(const [uri] of files.writeAsStringAsync.mock.calls)expect(files.__hasFile(uri)).toBe(original.includes(uri));
});
it("explicit checkpoint clearing removes both old and staged ciphertext recordings",async()=>{
  await recorded();await prepareLocalRekey(USER,OLD,NEXT);const written=files.writeAsStringAsync.mock.calls.map(([uri])=>uri);expect(written).toHaveLength(2);
  await clearLocalRekey(USER);for(const uri of written)expect(files.__hasFile(uri)).toBe(false);
});
it("resuming a committed recording deletes the retired original and retains its current replacement",async()=>{
  await recorded();await prepareLocalRekey(USER,OLD,NEXT);const [original,replacement]=files.writeAsStringAsync.mock.calls.map(([uri])=>uri);
  await resumeLocalRekey(USER,NEXT,{credentialConfirmed:true});expect(files.__hasFile(original!)).toBe(false);expect(files.__hasFile(replacement!)).toBe(true);
});
it("retains independent edits instead of overwriting them with a prepared replacement",async()=>{
  await prepared();const record=accountStorageKey.safetyPlan(USER);await storage.setItem(record,"independently changed ciphertext");
  await expect(resumeLocalRekey(USER,NEXT,{credentialConfirmed:true})).rejects.toThrow("local record changed during rotation");expect(await storage.getItem(record)).toBe("independently changed ciphertext");expect(await pendingLocalRekey(USER)).toBe(true);
});
it("reuses the already-applied replacement after a native cleanup interruption",async()=>{
  await prepared();const remove=storage.multiRemove;vi.spyOn(storage,"multiRemove").mockRejectedValueOnce(new Error("native cleanup failed"));
  await expect(resumeLocalRekey(USER,NEXT,{credentialConfirmed:true})).rejects.toThrow("native cleanup failed");vi.restoreAllMocks();
  expect(await loadSafetyPlan(NEXT,USER)).toEqual({...emptySafetyPlan(),warningSigns:"My retained warning signs"});expect(await pendingLocalRekey(USER)).toBe(true);
  await resumeLocalRekey(USER,NEXT,{credentialConfirmed:true});expect(await pendingLocalRekey(USER)).toBe(false);expect(storage.multiRemove).toBe(remove);
});
it("retires a queued checkpoint rewrite after its native read completes in a new scope",async()=>{
  await prepared();const read=secureStore.getItem;let release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
  vi.spyOn(secureStore,"getItem").mockImplementationOnce(async key=>{const value=await read(key);ready();await new Promise<void>(resolve=>{release=resolve;});return value;});
  const pending=storeLocalRekeyTokens(USER,NEXT,{old:"old",next:"next"});await started;advanceLocalWriteScope();release();
  await expect(pending).rejects.toThrow();vi.restoreAllMocks();expect((await localRekeyRequest(USER,NEXT)).tokens).toBeUndefined();
});
it("explicitly removes every checkpoint chunk while preserving the authored original",async()=>{
  await prepared();await clearLocalRekey(USER);expect(await pendingLocalRekey(USER)).toBe(false);expect((await storage.getAllKeys()).some(key=>key.startsWith(slot+".chunk."))).toBe(false);
  expect(await loadSafetyPlan(OLD,USER)).toEqual({...emptySafetyPlan(),warningSigns:"My retained warning signs"});
});
it("keeps queued checkpoint writers serialized when a predecessor settles while its successor is still reading",async()=>{
  await prepared();const body=await requestBody(),read=secureStore.getItem;let reads=0,release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
  vi.spyOn(secureStore,"getItem").mockImplementation(async key=>{const value=await read(key);if(key===slot&&++reads===2){ready();await new Promise<void>(resolve=>{release=resolve;});}return value;});
  const first=storeLocalRekeyTokens(USER,NEXT,{old:"first",next:"first-next"});
  const second=storeLocalRekeyTokens(USER,NEXT,{old:"second",next:"second-next"});
  await Promise.race([started,second]);const third=storeLocalRekeyRequest(USER,NEXT,body);
  for(let i=0;i<80;i++)await Promise.resolve();release();await Promise.all([first,second,third]);vi.restoreAllMocks();
  expect(await localRekeyRequest(USER,NEXT)).toEqual({operationId:body.operation_id,tokens:{old:"second",next:"second-next"},body});
});
it("lets a replacement owner's checkpoint complete while an old native read remains held",async()=>{
  await prepared();const read=secureStore.getItem;let release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
  vi.spyOn(secureStore,"getItem").mockImplementationOnce(async key=>{const value=await read(key);ready();await new Promise<void>(resolve=>{release=resolve;});return value;});
  const old=storeLocalRekeyTokens(USER,NEXT,{old:"retired",next:"retired-next"});void old.catch(()=>{});await Promise.race([started,old]);
  const other="d".repeat(32);await api.setSession("replacement",other,"bob");await prepareLocalRekey(other,OLD,NEXT);
  let completed=false;const current=storeLocalRekeyTokens(other,NEXT,{old:"current",next:"current-next"});void current.then(()=>{completed=true;});
  try{for(let i=0;i<200;i++)await Promise.resolve();expect(completed).toBe(true);}finally{release();await old.catch(()=>{});await current;vi.restoreAllMocks();}
  expect((await localRekeyRequest(other,NEXT)).tokens).toEqual({old:"current",next:"current-next"});
});
it("refuses another owner's transition before consulting an unavailable native origin",async()=>{
  vi.spyOn(storage,"getItem").mockRejectedValue(new Error("native origin unavailable"));
  await expect(prepareLocalRekey("d".repeat(32),OLD,NEXT)).rejects.toThrow("local account/server changed during key transition");
});
it.each(["request","tokens","resume"])("requires the checkpoint key before an authenticated %s operation",async operation=>{
  await prepared();const wrong=Buffer.alloc(32,11),body=await requestBody();
  await expect(operation==="request"?storeLocalRekeyRequest(USER,wrong,body):operation==="tokens"?storeLocalRekeyTokens(USER,wrong,{old:"old",next:"next"}):resumeLocalRekey(USER,wrong,{credentialConfirmed:true})).rejects.toThrow("blob failed authentication");
  expect(await pendingLocalRekey(USER)).toBe(true);
});
it("erases the authenticated proof plaintext retained by the native decryption consumer",async()=>{
  await prepared();const decrypt=envelopeCrypto.decrypt,held:Buffer[]=[];
  vi.spyOn(envelopeCrypto,"decrypt").mockImplementation((...args)=>{const plain=decrypt(...args);if(args[2]?.toString().includes('"local-rekey"'))held.push(plain);return plain;});
  await localRekeyRequest(USER,NEXT);expect(held).toHaveLength(1);expect(held[0]).toEqual(Buffer.alloc(held[0]!.length));
});
it("erases every authored plaintext after preparing its encrypted replacement",async()=>{
  const decrypt=envelopeCrypto.decrypt,held:Buffer[]=[];
  vi.spyOn(envelopeCrypto,"decrypt").mockImplementation((...args)=>{const plain=decrypt(...args);held.push(plain);return plain;});
  await prepared();expect(held.length).toBeGreaterThan(0);for(const plain of held)expect(plain).toEqual(Buffer.alloc(plain.length));
});
it("rejects a retired origin completion before reading an unavailable authored store",async()=>{
  const get=storage.getItem;let originReads=0;
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{
    if(key==="@mindpattern/base_url"&&++originReads===2){const value=await get(key);advanceLocalWriteScope();return value;}
    if(key===accountStorageKey.safetyPlan(USER))throw new Error("native authored storage unavailable");return get(key);
  });
  await expect(prepareLocalRekey(USER,OLD,NEXT)).rejects.toThrow("local account/server changed during key transition");
});
it("pauses retained queue transport while a restarted committed checkpoint is applying its new ciphertext",async()=>{
  const blob=envelopeCrypto.encrypt(OLD,Buffer.from("retained queued text"),Buffer.from(JSON.stringify(["entry",USER,"queued"]))).toString("base64");
  await enqueue({userId:USER,clientEntryId:"queued",entryDate:"2026-10-05",blobB64:blob});await prepareLocalRekey(USER,OLD,NEXT);
  runTestControl(__resetLocalKeyLifecycleForTests);await api.setSession("committed-new-bearer",USER,"alice");
  const read=storage.getItem;let release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});let held=false;
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(!held&&key.startsWith("@mindpattern/queue.v2.items.")){held=true;ready();await new Promise<void>(resolve=>{release=resolve;});}return value;});
  const applying=resumeLocalRekey(USER,NEXT,{credentialConfirmed:true});void applying.catch(()=>{});await Promise.race([started,applying]);
  const transport=vi.fn(async()=>new Response("{}"));vi.stubGlobal("fetch",transport);
  try{await expect(flushQueue(USER)).rejects.toThrow("paused");expect(transport).not.toHaveBeenCalled();}finally{release();await applying;}
});
it("refuses a retired authored read before attempting to decrypt its corrupt native ciphertext",async()=>{
  const target=accountStorageKey.safetyPlan(USER);await storage.setItem(target,"corrupt retained native ciphertext");const read=storage.getItem;let retired=false;
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(key===target&&!retired){retired=true;advanceLocalWriteScope();}return value;});
  await expect(prepareLocalRekey(USER,OLD,NEXT)).rejects.toThrow("local account/server changed during key transition");
  expect(await storage.getItem(target)).toBe("corrupt retained native ciphertext");expect(await pendingLocalRekey(USER)).toBe(false);
});
it("reports retirement before classifying an independently changed native record as a recovery conflict",async()=>{
  await prepared();const target=accountStorageKey.safetyPlan(USER);await storage.setItem(target,"independently changed ciphertext");const read=storage.getItem;let retired=false;
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(key===target&&!retired){retired=true;advanceLocalWriteScope();}return value;});
  await expect(resumeLocalRekey(USER,NEXT,{credentialConfirmed:true})).rejects.toThrow("local account/server changed during key transition");
  expect(await storage.getItem(target)).toBe("independently changed ciphertext");expect(await pendingLocalRekey(USER)).toBe(true);
});
it("refuses retired recovery before reading an unavailable authored store after an admitted native write drains",async()=>{
  await prepared();runTestControl(__resetLocalKeyLifecycleForTests);await api.setSession("cold-restored-token",USER,"alice");
  const target=accountStorageKey.safetyPlan(USER),write=storage.setItem,read=storage.getItem;let release!:()=>void,ready!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;}),started=new Promise<void>(resolve=>{ready=resolve;});let blocked=false,retired=false;
  vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{if(key===target&&!blocked){blocked=true;ready();await gate;}return write(key,value);});
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{if(retired&&key===target)throw new Error("Native authored store is unavailable");return read(key);});
  const saving=saveSafetyPlan(OLD,USER,emptySafetyPlan());await Promise.race([started,saving]);const recovery=resumeLocalRekey(USER,NEXT,{credentialConfirmed:true});void recovery.catch(()=>{});
  for(let i=0;i<150;i++)await Promise.resolve();advanceLocalWriteScope();retired=true;release();
  await saving;await expect(recovery).rejects.toThrow("local account/server changed during key transition");
});
it("refuses an old queued checkpoint writer before it can wait on obsolete native storage",async()=>{
  await prepared();const write=storage.setItem,read=storage.getItem;let ready!:()=>void,releaseFirst!:()=>void,releaseRead!:()=>void;const reached=new Promise<void>(resolve=>{ready=resolve;}),firstGate=new Promise<void>(resolve=>{releaseFirst=resolve;}),readGate=new Promise<void>(resolve=>{releaseRead=resolve;});let held=false,retired=false;
  vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{if(key===slot&&!held){held=true;ready();await firstGate;await write(key,value);retired=true;advanceLocalWriteScope();return;}return write(key,value);});
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{if(retired&&key===slot)await readGate;return read(key);});
  const first=markLocalRekeyPhase(USER,"server");await Promise.race([reached,first]);const second=storeLocalRekeyTokens(USER,NEXT,{old:"old-proof",next:"next-proof"});
  const result=second.then(()=>({complete:true}),error=>({error:(error as Error).message}));releaseFirst();await first;
  try{expect(await Promise.race([result,new Promise(resolve=>setTimeout(()=>resolve({blocked:true}),100))])).toEqual({error:"The local account/server changed during key transition"});}
  finally{releaseRead();await result;}
});
it("refuses to install a key after a native checkpoint deletion completes in a retired scope",async()=>{
  await prepared();const remove=storage.multiRemove;let retired=false;
  vi.spyOn(storage,"multiRemove").mockImplementation(async keys=>{await remove(keys);if(keys.includes(slot)&&!retired){retired=true;advanceLocalWriteScope();}});
  await expect(resumeLocalRekey(USER,NEXT,{credentialConfirmed:true})).rejects.toThrow("local account/server changed during key transition");
  expect(await pendingLocalRekey(USER)).toBe(false);
});
it("settles an interrupted real queued request without classifying the frozen generation as a retry",async()=>{
  const id="held-before-key-rotation",blob=envelopeCrypto.encrypt(OLD,Buffer.from("retained queued text"),Buffer.from(JSON.stringify(["entry",USER,id]))).toString("base64");
  await enqueue({userId:USER,clientEntryId:id,entryDate:"2026-10-05",blobB64:blob});
  let ready!:()=>void,release!:()=>void;const reached=new Promise<void>(resolve=>{ready=resolve;}),gate=new Promise<void>(resolve=>{release=resolve;});
  vi.stubGlobal("fetch",vi.fn(async()=>{ready();await gate;return new Response("{}",{status:200,headers:{"Content-Type":"application/json"}});}));
  const flush=flushQueue(USER);void flush.catch(()=>{});await Promise.race([reached,flush]);
  try{await prepareLocalRekey(USER,OLD,NEXT);release();await expect(flush).resolves.toBe(0);expect(await pendingLocalRekey(USER)).toBe(true);}
  finally{release();await flush.catch(()=>{});}
});
it("settles an interrupted recording before rereading unavailable native descriptors",async()=>{
  await recorded();const descriptor=(await storage.getAllKeys()).find(key=>key.startsWith("@mindpattern/audioqueue.v1:"))!;
  expect(descriptor).toBeTypeOf("string");const read=storage.getItem;let ready!:()=>void,releaseFetch!:()=>void,releaseRead!:()=>void;const reached=new Promise<void>(resolve=>{ready=resolve;}),fetchGate=new Promise<void>(resolve=>{releaseFetch=resolve;}),readGate=new Promise<void>(resolve=>{releaseRead=resolve;});let obsolete=false;
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{if(obsolete&&key===descriptor)await readGate;return read(key);});
  vi.stubGlobal("fetch",vi.fn(async()=>{ready();await fetchGate;return new Response("{}",{status:200,headers:{"Content-Type":"application/json"}});}));
  const flush=flushAudioQueue(),result=flush.then(value=>({value}),error=>({error:(error as Error).message}));await Promise.race([reached,result]);
  try{await prepareLocalRekey(USER,OLD,NEXT);obsolete=true;releaseFetch();expect(await Promise.race([result,new Promise(resolve=>setTimeout(()=>resolve({blocked:true}),100))])).toEqual({value:0});}
  finally{releaseFetch();releaseRead();await result;}
  expect(await pendingLocalRekey(USER)).toBe(true);
});
