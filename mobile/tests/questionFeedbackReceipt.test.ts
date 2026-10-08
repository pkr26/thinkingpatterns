/** Real Native encrypted storage and AES receipt acknowledgment, independent of screen mocks. */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api } from "../src/api/client";
import { vault } from "../src/vault";
import { accountStorageKey } from "../src/accountStorage";
import * as feedback from "../src/questionFeedback";
import * as envelope from "../src/crypto/envelope";
import { engine } from "../src/crypto/engine";
import { captureLocalWritePermit, installLocalDataKey, markAccountDeleted, __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";
import storage from "./helpers/storageMock";
const USER = "a".repeat(32), KEY = Buffer.alloc(32, 21);
type Receipt = { events: ReadonlyArray<feedback.FeedbackEvent & { event_id?: string }> };
const prepare = feedback.buildFeedbackBlob as (dataKey: Buffer, userId: string, prepared?: (receipt: Receipt) => void) => Promise<string | null>;
const consume = feedback.clearFeedback as (userId: string, permit: ReturnType<typeof captureLocalWritePermit>, acknowledged: {dataKey: Buffer; receipt: Receipt}) => Promise<void>;
const decode = (blob: string) => JSON.parse(envelope.decrypt(KEY, Buffer.from(blob, "base64"), envelope.buildAad("feedback", USER, new Date().toISOString().slice(0,10))).toString());
const queued = async () => { const raw = await storage.getItem(accountStorageKey.feedback(USER)); return raw ? JSON.parse(envelope.decrypt(KEY,Buffer.from(raw,"base64"),envelope.buildAad("feedback-local",USER)).toString()) : []; };
beforeEach(async()=>{vi.restoreAllMocks();storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();await api.setSession("Native receipt bearer",USER,"alice");vault.unlock({masterKey:Buffer.alloc(32,3),authKey:Buffer.alloc(32,4),dataKey:Buffer.from(KEY)},USER);installLocalDataKey(USER,vault.get().dataKey);});
afterEach(async()=>{vi.restoreAllMocks();vault.lock();await api.clearSession();});
it("an initially retired Native feedback builder does not wait on an unavailable encrypted read",async()=>{
 let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(storage,"getItem").mockImplementation(()=>gate.then(()=>null));let finished=false;const result=feedback.buildFeedbackBlob(KEY,USER,undefined,()=>false).catch(error=>{finished=true;return error;});try{await Promise.race([result,new Promise(resolve=>setTimeout(resolve,120))]);expect(finished).toBe(true);}finally{release();await result;}
});
it.each(["receipt","legacy"] as const)("an initially retired Native %s clear refuses before waiting behind an accepted unavailable append",async mode=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed(),get=storage.getItem.bind(storage);let entered=false,release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const raw=await get(name);if(name===accountStorageKey.feedback(USER)){entered=true;await gate;}return raw;});const first=feedback.recordFeedbackTap(KEY,USER,"accepted",false);await vi.waitFor(()=>expect(entered).toBe(true));let finished=false;const result=feedback.clearFeedback(USER,captureLocalWritePermit(USER,KEY),mode==="receipt"?{dataKey:KEY,receipt}:undefined,()=>false).catch(error=>{finished=true;return error;});try{await Promise.race([result,new Promise(resolve=>setTimeout(resolve,120))]);expect(finished).toBe(true);}finally{release();await Promise.all([first,result]);}
});
it("a Native builder retired between its receipt decoder and await continuation refuses its returned encrypted blob",async()=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const get=storage.getItem.bind(storage);let current=true,first=true;vi.spyOn(storage,"getItem").mockImplementation(async name=>{const raw=await get(name);if(first&&name===accountStorageKey.feedback(USER)){first=false;queueMicrotask(()=>queueMicrotask(()=>{current=false;}));}return raw;});await expect(feedback.buildFeedbackBlob(KEY,USER,undefined,()=>current)).rejects.toBeInstanceOf(Error);
});
it.each(["append","receipt rewrite"] as const)("a Native %s retired after receipt decode leaves primitive contexts available for the current append",async mode=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed();await feedback.recordFeedbackTap(KEY,USER,"later",false);const get=storage.getItem.bind(storage);let current=true,first=true;const contexts:Array<WeakRef<object>>=[],borrow=<T extends object>(make:()=>T):T=>{if(contexts.filter(ref=>ref.deref()!==undefined).length>=3)throw new Error("Native crypto contexts are full until host collection");const value=make();contexts.push(new WeakRef(value));return value;};
 vi.spyOn(storage,"getItem").mockImplementation(async name=>{const raw=await get(name);if(first&&name===accountStorageKey.feedback(USER)){first=false;queueMicrotask(()=>queueMicrotask(()=>{current=false;const cipher=engine.createCipheriv.bind(engine),decipher=engine.createDecipheriv.bind(engine),hash=engine.createHash.bind(engine);vi.spyOn(engine,"createCipheriv").mockImplementation((...args)=>borrow(()=>cipher(...args)));vi.spyOn(engine,"createDecipheriv").mockImplementation((...args)=>borrow(()=>decipher(...args)));vi.spyOn(engine,"createHash").mockImplementation((...args)=>borrow(()=>hash(...args)));}));}return raw;});
 await expect(mode==="append"?feedback.recordFeedbackTap(KEY,USER,"retired",true,()=>current):feedback.clearFeedback(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt},()=>current)).rejects.toBeInstanceOf(Error);await feedback.recordFeedbackTap(KEY,USER,"current",true);vi.restoreAllMocks();expect((await queued()).map((event:feedback.FeedbackTap)=>event.pid)).toEqual(["earlier","later","current"]);
});
it.each(["build","receipt clear","legacy clear"] as const)("a retired Native view refuses %s without changing its durable feedback",async mode=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed(),before=await queued(),permit=captureLocalWritePermit(USER,KEY);
 const result=mode==="build"?feedback.buildFeedbackBlob(KEY,USER,undefined,()=>false):feedback.clearFeedback(USER,permit,mode==="receipt clear"?{dataKey:KEY,receipt}:undefined,()=>false);await expect(result).rejects.toBeInstanceOf(Error);expect(await queued()).toEqual(before);
});
it.each(["build","receipt clear"] as const)("a Native %s read delivered after view retirement rejects and preserves every feedback event",async mode=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed(),slot=accountStorageKey.feedback(USER),get=storage.getItem.bind(storage),before=await get(slot);let entered=false,current=true,release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const raw=await get(name);if(name===slot){entered=true;await gate;}return raw;});const result=(mode==="build"?feedback.buildFeedbackBlob(KEY,USER,undefined,()=>current):feedback.clearFeedback(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt},()=>current)).catch(error=>error);await vi.waitFor(()=>expect(entered).toBe(true));current=false;release();expect(await result).toBeInstanceOf(Error);expect(await get(slot)).toBe(before);
});
it.each(["receipt clear","legacy clear"] as const)("a queued Native %s retires before dispatching an unavailable old-view read or erasure",async mode=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed(),slot=accountStorageKey.feedback(USER),get=storage.getItem.bind(storage);let entered=false,first=true,current=true,allowFresh=false,releaseFirst!:()=>void,releaseLate!:()=>void;const firstGate=new Promise<void>(resolve=>{releaseFirst=resolve;}),lateGate=new Promise<void>(resolve=>{releaseLate=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const raw=await get(name);if(name===slot){if(first){first=false;entered=true;await firstGate;}else if(!current&&!allowFresh)await lateGate;}return raw;});const remove=storage.removeItem.bind(storage);vi.spyOn(storage,"removeItem").mockImplementation(async name=>{if(name===slot&&!current&&!allowFresh)await lateGate;return remove(name);});const firstAppend=feedback.recordFeedbackTap(KEY,USER,"accepted",false);await vi.waitFor(()=>expect(entered).toBe(true));const stale=feedback.clearFeedback(USER,captureLocalWritePermit(USER,KEY),mode==="receipt clear"?{dataKey:KEY,receipt}:undefined,()=>current).catch(error=>error);current=false;releaseFirst();let finished=false,fresh:Promise<void>=Promise.resolve();const settled=stale.then(()=>{finished=true;});try{await Promise.race([settled,new Promise(resolve=>setTimeout(resolve,120))]);expect(finished).toBe(true);allowFresh=true;fresh=feedback.recordFeedbackTap(KEY,USER,"current",true);await fresh;}finally{releaseFirst();releaseLate();await Promise.all([firstAppend,stale,fresh]);}expect((await queued()).map((event:feedback.FeedbackTap)=>event.pid)).toEqual(["earlier","accepted","current"]);
});
it("acknowledging an earlier Native feedback blob preserves a later tap for the next recompute",async()=>{
 await feedback.recordPatternMute(KEY,USER,"topic:earlier",true);let receipt:Receipt={events:[{pid:"topic:earlier",mute:true}]};const blob=await prepare(KEY,USER,value=>{receipt=value;});expect(decode(blob!)).toEqual({feedback:[],muted:["topic:earlier"],unmuted:[]});
 await feedback.recordFeedbackTap(KEY,USER,"topic:later",false);await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});const next=await feedback.buildFeedbackBlob(KEY,USER);expect(next).toBeTruthy();expect(decode(next!)).toEqual({feedback:[{pid:"topic:later",resonated:false}],muted:[],unmuted:[]});
});
async function sealed() { let receipt:Receipt|undefined;const blob=await prepare(KEY,USER,value=>{receipt=value;});expect(blob).toBeTruthy();expect(receipt).toBeDefined();return {blob:blob!,receipt:receipt!}; }
it("Native event ids are fresh internal metadata and never enter the server feedback payload",async()=>{
 await feedback.recordFeedbackTap(KEY,USER,"same",true);await feedback.recordFeedbackTap(KEY,USER,"same",true);await feedback.recordPatternMute(KEY,USER,"same",false);const {blob,receipt}=await sealed();expect(receipt.events).toHaveLength(3);expect(new Set(receipt.events.map(event=>event.event_id)).size).toBe(3);receipt.events.forEach(event=>expect(event.event_id).toMatch(/^[A-Za-z0-9+/]{22}==$/));expect(decode(blob)).toEqual({feedback:[{pid:"same",resonated:true},{pid:"same",resonated:true}],muted:[],unmuted:["same"]});
});
it("identical Native late taps survive consumption of only the earlier event id",async()=>{
 await feedback.recordFeedbackTap(KEY,USER,"same",true);const {receipt}=await sealed();await feedback.recordFeedbackTap(KEY,USER,"same",true);await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});expect((await queued()).map((event:feedback.FeedbackTap)=>({pid:event.pid,resonated:event.resonated}))).toEqual([{pid:"same",resonated:true}]);
});
it("an evicted Native acknowledged id cannot consume a new identical event from the bounded queue",async()=>{
 await feedback.recordFeedbackTap(KEY,USER,"same",true);const {receipt}=await sealed();for(let index=0;index<101;index++)await feedback.recordFeedbackTap(KEY,USER,"same",true);const before=await queued();expect(before).toHaveLength(100);expect(before.some((event:{event_id:string})=>event.event_id===receipt.events[0]!.event_id)).toBe(false);await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});expect(await queued()).toEqual(before);
});
it("consuming a complete Native snapshot removes the queue and a later empty build has no receipt",async()=>{
 await feedback.recordFeedbackTap(KEY,USER,"a",true);await feedback.recordPatternMute(KEY,USER,"b",false);const {receipt}=await sealed();await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});const prepared=vi.fn();expect(await prepare(KEY,USER,prepared)).toBeNull();expect(prepared).not.toHaveBeenCalled();expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();
});
it("counted Native legacy matching consumes exact duplicate tap and mute occurrences while new ids remain",async()=>{
 const legacy=[{pid:"a",resonated:true},{pid:"a",resonated:true},{pid:"b",mute:true},{pid:"b",mute:false}];await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(JSON.stringify(legacy)),envelope.buildAad("feedback-local",USER)).toString("base64"));const {receipt}=await sealed();await feedback.recordFeedbackTap(KEY,USER,"a",true);await feedback.recordPatternMute(KEY,USER,"b",true);await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});expect(decode((await feedback.buildFeedbackBlob(KEY,USER))!)).toEqual({feedback:[{pid:"a",resonated:true}],muted:["b"],unmuted:[]});
});
it("a partial Native legacy receipt respects pid, event kind, value and counted occurrence",async()=>{
 const legacy=[{pid:"a",resonated:true},{pid:"a",resonated:true},{pid:"a",resonated:false},{pid:"b",resonated:true},{pid:"a",mute:true},{pid:"a",mute:false}];await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(JSON.stringify(legacy)),envelope.buildAad("feedback-local",USER)).toString("base64"));await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt:{events:[{pid:"a",resonated:true},{pid:"a",mute:true}]}});expect(await queued()).toEqual([legacy[1],legacy[2],legacy[3],legacy[5]]);
});
it("a modern Native receipt never consumes an id-less legacy event of the same content",async()=>{
 const legacy={pid:"a",resonated:true};await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(JSON.stringify([legacy])),envelope.buildAad("feedback-local",USER)).toString("base64"));await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt:{events:[{...legacy,event_id:"modern-receipt-only"}]}});expect(await queued()).toEqual([legacy]);
});
it("an empty Native receipt preserves a later valid append even after corrupt stored metadata",async()=>{
 await storage.setItem(accountStorageKey.feedback(USER),"Native corrupt wire");expect(await feedback.buildFeedbackBlob(KEY,USER)).toBeNull();await feedback.recordFeedbackTap(KEY,USER,"late",false);const before=await queued();await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt:{events:[]}});expect(await queued()).toEqual(before);
});
it("Native authenticated JSON validation skips invalid event rows and projects only feedback wire fields",async()=>{
 const raw='[null,1,"x",{}, {"pid":7,"resonated":true},{"pid":"bad","resonated":7},{"pid":"ok","resonated":false,"mute":true,"private":"never ship"}]';await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(raw),envelope.buildAad("feedback-local",USER)).toString("base64"));expect(decode((await feedback.buildFeedbackBlob(KEY,USER))!)).toEqual({feedback:[{pid:"ok",resonated:false}],muted:[],unmuted:[]});
});
it.each(["append-first","consume-first"])("the Native %s lane preserves the late append across a held physical read",async order=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed(),read=storage.getItem.bind(storage);let entered=false,first=true,release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.feedback(USER)&&first){first=false;entered=true;await gate;}return value;});
 const ack=()=>consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt}),tap=()=>feedback.recordFeedbackTap(KEY,USER,"later",false);const a=order==="append-first"?tap():ack();await vi.waitFor(()=>expect(entered).toBe(true));const b=order==="append-first"?ack():tap();try{await Promise.resolve();release();await Promise.all([a,b]);}finally{release();}expect(decode((await feedback.buildFeedbackBlob(KEY,USER))!)).toEqual({feedback:[{pid:"later",resonated:false}],muted:[],unmuted:[]});
});
it.each(["delete","rewrite"])("Native %s acknowledgment refuses a retired scope and preserves its account wire",async mode=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed();if(mode==="rewrite")await feedback.recordFeedbackTap(KEY,USER,"later",false);const read=storage.getItem.bind(storage),before=await read(accountStorageKey.feedback(USER));let entered=false,release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.feedback(USER)){entered=true;await gate;}return value;});const pending=consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});const observed=pending.catch(error=>error);await vi.waitFor(()=>expect(entered).toBe(true));await api.setSession("replacement Native receipt bearer","b".repeat(32),"bob");release();expect(await observed).toBeInstanceOf(Error);expect(await read(accountStorageKey.feedback(USER))).toBe(before);
});
it.each(["wire-cipher-refusal","callback-refusal","successful-clear","rewrite-refusal"])("Native %s retires all actual owned feedback key and plaintext buffers",async outcome=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);let receipt:Receipt;const before=await sealed();receipt=before.receipt;if(outcome==="rewrite-refusal")await feedback.recordFeedbackTap(KEY,USER,"later",false);const keys:Buffer[]=[],plains:Buffer[]=[],original=envelope.encrypt;vi.spyOn(envelope,"encrypt").mockImplementation((...args)=>{keys.push(args[0]);plains.push(args[1]);if(outcome==="wire-cipher-refusal")throw new Error("Native cipher refused");return original(...args);});
 if(outcome==="successful-clear") {await feedback.recordFeedbackTap(KEY,USER,"later",false);keys.length=0;plains.length=0;await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt});}
 else if(outcome==="rewrite-refusal"){vi.spyOn(storage,"setItem").mockRejectedValueOnce(new Error("Native full storage"));await expect(consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt})).rejects.toThrow("Native full storage");}
 else await expect(prepare(KEY,USER,outcome==="callback-refusal"?()=>{throw new Error("Native callback refused");}:undefined)).rejects.toThrow();
 expect(keys.length).toBeGreaterThan(0);expect(keys.every(key=>key.every(value=>value===0))).toBe(true);expect(plains.every(plain=>plain.every(value=>value===0))).toBe(true);expect(KEY).toEqual(Buffer.alloc(32,21));
});
it.each(['{}','null','"string"','false','7'])("Native authenticated non-array JSON %s stays absent and its physical plaintext is cleared",async raw=>{
 await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(raw),envelope.buildAad("feedback-local",USER)).toString("base64"));const physical:Buffer[]=[],original=envelope.decrypt;vi.spyOn(envelope,"decrypt").mockImplementation((...args)=>{const plain=original(...args);if(args[2]?.toString().startsWith('["feedback-local",'))physical.push(plain);return plain;});const prepared=vi.fn();expect(await prepare(KEY,USER,prepared)).toBeNull();expect(prepared).not.toHaveBeenCalled();expect(physical).toHaveLength(1);expect(physical[0]!.every(value=>value===0)).toBe(true);
});
it.each([{events:[{pid:"b",resonated:true}]},{events:[{pid:"a",resonated:false}]},{events:[{pid:"a",mute:false}]}])("Native partial receipt %j never steals an earlier different pid or value",async ({events})=>{
 const legacy=[{pid:"a",resonated:true},{pid:"a",resonated:false},{pid:"b",resonated:true},{pid:"a",mute:true},{pid:"a",mute:false}];await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(JSON.stringify(legacy)),envelope.buildAad("feedback-local",USER)).toString("base64"));await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt:{events}});expect(await queued()).toEqual(legacy.filter(event=>JSON.stringify(event)!==JSON.stringify(events[0])));
});
it("a Native legacy tap with surplus mute metadata cannot acknowledge a different mute event",async()=>{
 const mute={pid:"a",mute:true},tap={pid:"a",resonated:true,mute:true};await storage.setItem(accountStorageKey.feedback(USER),envelope.encrypt(KEY,Buffer.from(JSON.stringify([mute,tap])),envelope.buildAad("feedback-local",USER)).toString("base64"));await consume(USER,captureLocalWritePermit(USER,KEY),{dataKey:KEY,receipt:{events:[tap]}});expect(await queued()).toEqual([mute]);
});
it("a Native append retires its physical encryption key and payload after both successful and refused commits",async()=>{
 const keys:Buffer[]=[],plains:Buffer[]=[],original=envelope.encrypt;vi.spyOn(envelope,"encrypt").mockImplementation((...args)=>{keys.push(args[0]);plains.push(args[1]);return original(...args);});await feedback.recordFeedbackTap(KEY,USER,"successful",true);vi.spyOn(storage,"setItem").mockRejectedValueOnce(new Error("Native write refused"));await expect(feedback.recordPatternMute(KEY,USER,"refused",true)).rejects.toThrow("Native write refused");expect(keys).toHaveLength(2);expect(keys.every(key=>key.every(value=>value===0))).toBe(true);expect(plains.every(plain=>plain.every(value=>value===0))).toBe(true);expect(KEY).toEqual(Buffer.alloc(32,21));
});
it.each(["append","consume"])("a queued retired Native %s cannot block the next owner's feedback behind an unavailable old-account read",async operation=>{
 await feedback.recordFeedbackTap(KEY,USER,"earlier",true);const {receipt}=await sealed(),permit=captureLocalWritePermit(USER,KEY),read=storage.getItem.bind(storage);let firstEntered=false,reads=0,releaseFirst!:()=>void,releaseLate!:()=>void;const firstGate=new Promise<void>(resolve=>{releaseFirst=resolve;}),lateGate=new Promise<void>(resolve=>{releaseLate=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await read(name);if(name===accountStorageKey.feedback(USER)){reads++;if(reads===1){firstEntered=true;await firstGate;}else await lateGate;}return value;});
 const first=feedback.recordFeedbackTap(KEY,USER,"staged",false).catch(error=>error);await vi.waitFor(()=>expect(firstEntered).toBe(true));const second=(operation==="append"?feedback.recordPatternMute(KEY,USER,"queued",true):consume(USER,permit,{dataKey:KEY,receipt})).catch(error=>error);const other="b".repeat(32),next=Buffer.alloc(32,22);await api.setSession("new Native feedback bearer",other,"bob");installLocalDataKey(other,next);let finished=false;const current=feedback.recordFeedbackTap(next,other,"current owner",true).then(()=>{finished=true;});releaseFirst();try{await Promise.race([current,new Promise(resolve=>setTimeout(resolve,120))]);expect(finished).toBe(true);}finally{releaseLate();await Promise.all([first,second,current]);}const raw=(await read(accountStorageKey.feedback(other)))!;const parsed=JSON.parse(envelope.decrypt(next,Buffer.from(raw,"base64"),envelope.buildAad("feedback-local",other)).toString());expect(parsed[0]).toMatchObject({pid:"current owner",resonated:true});
});
it("authorized Native erasure removes feedback after its account lifecycle is tombstoned",async()=>{
 await feedback.recordFeedbackTap(KEY,USER,"old health feedback",true);markAccountDeleted(USER);await feedback.eraseFeedback(USER);expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();
});

it.each(["tap", "mute"] as const)("a Native %s caller admits feedback only while its explicit view receipt is current", async (kind) => {
  const append = (pid: string, current: () => boolean) => kind === "tap"
    ? feedback.recordFeedbackTap(KEY, USER, pid, true, current)
    : feedback.recordPatternMute(KEY, USER, pid, true, current);
  await append("current view", () => true);
  const before = await queued();
  expect(before).toHaveLength(1);
  await expect(append("retired view", () => false)).rejects.toBeInstanceOf(Error);
  expect(await queued()).toEqual(before);
});

it("a retired Native view cannot decrypt or rewrite its feedback after a held encrypted read returns", async () => {
  await feedback.recordFeedbackTap(KEY, USER, "earlier", true);
  const slot = accountStorageKey.feedback(USER), read = storage.getItem.bind(storage), before = await read(slot);
  let entered = false, first = true, current = true, release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const raw = await read(name);
    if (name === slot && first) { first = false; entered = true; await gate; }
    return raw;
  });
  const physical: Buffer[] = [], originalDecrypt = envelope.decrypt;
  vi.spyOn(envelope, "decrypt").mockImplementation((...args) => {
    const plain = originalDecrypt(...args); physical.push(plain); return plain;
  });
  const result = feedback.recordPatternMute(KEY, USER, "retired", true, () => current).catch((error) => error);
  await vi.waitFor(() => expect(entered).toBe(true));
  current = false;
  release();
  expect(await result).toBeInstanceOf(Error);
  expect(await read(slot)).toBe(before);
  // The receipt was retired before ciphertext delivery, so no health
  // plaintext needs to be allocated by the retired continuation.
  expect(physical).toEqual([]);
});

it("a queued retired Native feedback view releases the lane before dispatching another unavailable read", async () => {
  const slot = accountStorageKey.feedback(USER), read = storage.getItem.bind(storage);
  let entered = false, first = true, current = true, releaseFirst!: () => void, releaseUnavailable!: () => void;
  const firstGate = new Promise<void>((resolve) => { releaseFirst = resolve; });
  const unavailableGate = new Promise<void>((resolve) => { releaseUnavailable = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const raw = await read(name);
    if (name === slot) {
      if (first) { first = false; entered = true; await firstGate; }
      else if (!current) await unavailableGate;
    }
    return raw;
  });
  const firstAppend = feedback.recordFeedbackTap(KEY, USER, "already accepted", true);
  await vi.waitFor(() => expect(entered).toBe(true));
  const retired = feedback.recordPatternMute(KEY, USER, "queued retired", true, () => current).catch((error) => error);
  current = false;
  releaseFirst();
  await firstAppend;
  await Promise.resolve();
  // The new view uses another authenticated owner, whose Native storage
  // is available even while the retired old-account provider is held.
  const other = "b".repeat(32), next = Buffer.alloc(32, 22);
  await api.setSession("current Native view bearer", other, "bob");
  installLocalDataKey(other, next);
  let completed = false;
  const currentAppend = feedback.recordFeedbackTap(next, other, "current replacement", true, () => true).then(() => { completed = true; });
  try {
    await Promise.race([currentAppend, new Promise((resolve) => setTimeout(resolve, 120))]);
    expect(completed).toBe(true);
  } finally {
    releaseUnavailable();
    await Promise.allSettled([firstAppend, retired, currentAppend]);
  }
  const wire = (await read(accountStorageKey.feedback(other)))!;
  expect(JSON.parse(envelope.decrypt(next, Buffer.from(wire, "base64"), envelope.buildAad("feedback-local", other)).toString()))
    .toEqual([expect.objectContaining({pid: "current replacement", resonated: true})]);
});

it("an already retired Native feedback caller resolves its rejection without waiting behind another view's unavailable read", async () => {
  const slot = accountStorageKey.feedback(USER), read = storage.getItem.bind(storage);
  let entered = false, release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const wire = await read(name);
    if (name === slot) { entered = true; await gate; }
    return wire;
  });
  const active = feedback.recordFeedbackTap(KEY, USER, "active view", true);
  await vi.waitFor(() => expect(entered).toBe(true));
  let rejected = false;
  const retired = feedback.recordPatternMute(KEY, USER, "retired view", true, () => false).catch((error) => {
    expect(error).toBeInstanceOf(Error);
    rejected = true;
  });
  try {
    await Promise.race([retired, new Promise((resolve) => setTimeout(resolve, 120))]);
    expect(rejected).toBe(true);
  } finally {
    release();
    await Promise.all([active, retired]);
  }
  expect((await queued()).map((event: feedback.FeedbackEvent) => event.pid)).toEqual(["active view"]);
});

it("a Native feedback continuation retired between read completion and caller resumption cannot publish a new queue row", async () => {
  await feedback.recordFeedbackTap(KEY, USER, "accepted earlier", true);
  const slot = accountStorageKey.feedback(USER), read = storage.getItem.bind(storage), before = await read(slot);
  let entered = false, first = true, current = true, release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const wire = await read(name);
    if (name === slot && first) { first = false; entered = true; await gate; }
    return wire;
  });
  const result = feedback.recordPatternMute(KEY, USER, "retired on delivery", true, () => current).catch((error) => error);
  await vi.waitFor(() => expect(entered).toBe(true));
  release();
  // Native read delivery resumes the storage wrapper, then readPending.
  // The already queued view event arrives before its caller's separate
  // Promise continuation; no callback mutates the ownership predicate.
  queueMicrotask(() => queueMicrotask(() => { current = false; }));
  expect(await result).toBeInstanceOf(Error);
  expect(await read(slot)).toBe(before);
});
