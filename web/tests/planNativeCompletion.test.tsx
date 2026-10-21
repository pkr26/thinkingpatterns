import { act } from "react";
import { createRequire } from "node:module";
import { webcrypto } from "node:crypto";
import { t } from "../src/strings";
import * as planStorage from "../src/safetyPlan";
import { afterEach,beforeEach,describe,expect,it,vi } from "vitest";
import { SafetyPlanView } from "../src/views/SafetyPlan";
import { EMPTY_SAFETY_PLAN,loadSafetyPlan,preserveSafetyPlan,saveSafetyPlan,type SafetyPlan } from "../src/safetyPlan";
import { setKvBackendForTests,type KvBackend } from "../src/kvstore";
import { vault } from "../src/vault";
import { resetTestState,installSession,memoryKvBackend } from "./helpers/api";
import { isDisabled,press,render,settle,textOf,textOfNode,typeArea } from "./helpers/rtr";
const USER="a".repeat(32),KEY=new Uint8Array(32).fill(4),SLOT=`mindpattern.safetyPlan.${USER}`;
const PLAN:SafetyPlan={warningSigns:"old warning",coping:"old coping",peoplePlaces:"old people",helpers:"old helpers",professionals:"old professional",saferEnvironment:"old environment"};
let map:Map<string,string>,backend:KvBackend;
beforeEach(()=>{resetTestState();installSession(USER);vault.unlock({authKey:new Uint8Array(KEY),dataKey:new Uint8Array(KEY)},USER);map=new Map();backend={async getItem(k){return map.get(k)??null;},async setItem(k,v){map.set(k,v);},async removeItem(k){map.delete(k);},async keys(){return [...map.keys()];}};setKvBackendForTests(backend);});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();});
async function ready(){const root=await render(<SafetyPlanView onCrisis={()=>undefined}/>);await settle(25,4);return root;}
const warning=(root:Awaited<ReturnType<typeof render>>)=>root.root.findAllByType("textarea")[0]!.props.value;
// Exercise the real DOM window between a retry's queued hydration and its commit.
// Only delivery of captured ciphertext reads is controlled; crypto and the full
// storage helper Promises are original, and every producer is drained on failure.
async function acknowledgedSaveRetiresPendingRestore(): Promise<void> {
  const deferred = () => {
    let resolve!: () => void;
    const promise = new Promise<void>(yes => { resolve = yes; });
    return { promise, resolve };
  };
  function requireSetup(value: unknown, message: string): asserts value {
    if (!value) throw new Error("SetupError: " + message);
  }
  const until = async (message: string, condition: () => boolean) => {
    const deadline = performance.now() + 8000;
    while (!condition()) {
      if (performance.now() > deadline) throw new Error("SetupError: timed out waiting for " + message);
      await act(async () => { await new Promise<void>(yes => setTimeout(yes, 5)); });
    }
  };
  const pending: { label: string; promise: Promise<unknown>; settled: boolean; failed: boolean; reason: unknown }[] = [];
  const own = <T,>(label: string, promise: Promise<T>): Promise<T> => {
    const item = { label, promise, settled: false, failed: false, reason: undefined as unknown };
    pending.push(item);
    void promise.then(() => { item.settled = true; }, reason => {
      item.settled = true; item.failed = true; item.reason = reason;
    });
    return promise;
  };
  const drain = async () => {
    for (;;) {
      const count = pending.length;
      await act(async () => { await Promise.allSettled(pending.map(item => item.promise)); });
      if (count === pending.length && pending.every(item => item.settled)) break;
    }
    const fault = pending.find(item => item.failed);
    if (fault) throw new Error("Owned safety-plan restore/save/crypto/backend producer failed: " + fault.label, { cause: fault.reason });
  };

  await act(async () => { resetTestState(); });
  const owner = "safety-plan-acknowledged-save-owner", key = new Uint8Array(32).fill(37);
  const slot = `mindpattern.safetyPlan.${owner}`;
  const oldPlan = { ...EMPTY_SAFETY_PLAN, warningSigns: "older durable warning", coping: "older durable coping" };
  const early = "early edit before hydration", acknowledged = "newer acknowledged warning";
  const inheritedLocks = (globalThis.navigator as Navigator | undefined)?.locks;
  const { JSDOM } = createRequire(import.meta.url)("jsdom");
  const dom = new JSDOM('<!doctype html><html><body><div id="plan"></div></body></html>', { url: "http://localhost:5173" });
  Object.defineProperty(dom.window.navigator, "locks", { configurable: true, value: inheritedLocks });
  const container = dom.window.document.getElementById("plan") as HTMLDivElement;
  const button = (label: string) => [...container.querySelectorAll<HTMLButtonElement>("button")].find(node => node.textContent === label);
  const field = () => [...container.querySelectorAll<HTMLTextAreaElement>("textarea")].find(node => node.parentElement?.textContent?.includes(t("plan.warningSigns")));
  const edit = async (value: string) => {
    const current = field(); requireSetup(current && !current.disabled, "current enabled warning-sign field");
    const setter = Object.getOwnPropertyDescriptor(dom.window.HTMLTextAreaElement.prototype, "value")?.set;
    requireSetup(setter, "native textarea value setter");
    await act(async () => { setter.call(current, value); current.dispatchEvent(new dom.window.Event("input", { bubbles: true })); });
  };
  let root: ReturnType<(typeof import("react-dom/client"))["createRoot"]> | undefined;
  let deadline: ReturnType<typeof setTimeout> | undefined;
  const initialRead = deferred(), replacementRead = deferred(), retryWindow = deferred();
  let cleanupStarted = false, rawReads = 0, helperLoads = 0, replacementPending = false;
  let retryClicked = false, retryFailed = false, retryFault: unknown;
  const originalLoad = planStorage.loadSafetyPlan, originalSave = planStorage.saveSafetyPlan;
  try {
    const nativeSubtle = webcrypto.subtle;
    const subtle = new Proxy(nativeSubtle, { get(target, property) {
      const value = Reflect.get(target, property, target);
      if (typeof value !== "function") return value;
      return (...args: unknown[]) => {
        const result = value.apply(target, args);
        return result && typeof result.then === "function" ? own("native " + String(property), result) : result;
      };
    } });
    vi.stubGlobal("crypto", new Proxy(webcrypto, { get(target, property) {
      if (property === "subtle") return subtle;
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    } }));
    for (const [name, value] of Object.entries({ window: dom.window, document: dom.window.document, navigator: dom.window.navigator, Node: dom.window.Node, HTMLElement: dom.window.HTMLElement, HTMLTextAreaElement: dom.window.HTMLTextAreaElement, Event: dom.window.Event, MouseEvent: dom.window.MouseEvent, MutationObserver: dom.window.MutationObserver })) vi.stubGlobal(name, value);
    const actualBackend = memoryKvBackend(); setKvBackendForTests(actualBackend);
    installSession(owner); vault.unlock({ authKey: key.slice(), dataKey: key.slice() }, owner);
    await own("original seed save", originalSave(key, owner, oldPlan));
    setKvBackendForTests({ ...actualBackend, getItem: name => own("captured ciphertext read " + name, (async () => {
      const captured = await actualBackend.getItem(name);
      if (name === slot) {
        const number = ++rawReads;
        if (number === 1) await initialRead.promise;
        if (number === 3) { replacementPending = true; await replacementRead.promise; replacementPending = false; }
      }
      return captured;
    })()) });
    vi.spyOn(planStorage, "loadSafetyPlan").mockImplementation((...args) => {
      const number = ++helperLoads, promise = own("original full load " + number, originalLoad(...args));
      if (number === 2) own("completed retry observer", promise.then(() => {
        // Product's awaiting continuation queues hydration before this native
        // microtask clicks the still-current, enabled Retry control.
        queueMicrotask(() => {
          try {
            if (cleanupStarted) return;
            const retry = button(t("plan.retryRestore"));
            if (retry && !retry.disabled) { retryClicked = true; retry.click(); }
          } catch (error) { retryFailed = true; retryFault = error; }
          finally { retryWindow.resolve(); }
        });
      }));
      return promise;
    });
    vi.spyOn(planStorage, "saveSafetyPlan").mockImplementation((...args) => own("original component save", originalSave(...args)));
    const { createRoot } = await import("react-dom/client"); root = createRoot(container);
    await act(async () => root!.render(<SafetyPlanView onCrisis={() => { throw new Error("Unexpected crisis navigation"); }} />));
    await until("initial read and enabled Retry", () => rawReads === 1 && !!button(t("plan.retryRestore")) && !button(t("plan.retryRestore"))!.disabled);
    await edit(early);
    const retry = button(t("plan.retryRestore")); requireSetup(retry && !retry.disabled, "enabled Retry before hydration");
    // Keep the actual DOM event outside act: flushing it would remove the window.
    retry.click();
    await Promise.race([retryWindow.promise, new Promise<void>(yes => { deadline = setTimeout(yes, 2000); })]);
    if (deadline) clearTimeout(deadline); deadline = undefined;
    if (retryFailed) throw new Error("Queued public Retry click failed", { cause: retryFault });
    requireSetup(retryClicked, "enabled Retry was not observed before hydration; no forced schedule");
    await until("pending replacement read and committed hydration", () => rawReads === 3 && replacementPending && !button(t("plan.retryRestore")));
    requireSetup(field()?.value === early, "the real early edit survives hydration's dirty-field merge");
    await edit(acknowledged);
    const save = button(t("plan.save")); requireSetup(save && !save.disabled, "hydrated enabled Save");
    await act(async () => save.click());
    await until("acknowledged save", () => container.textContent!.includes(t("plan.savedNote")) && !!button(t("plan.save")) && !button(t("plan.save"))!.disabled);
    const atAck = await own("durable read at acknowledgement", originalLoad(key, owner));
    requireSetup(atAck?.warningSigns === acknowledged, "original crypto/storage committed the new writing");
    requireSetup(replacementPending, "older replacement read remains pending at acknowledgement");
    await act(async () => { replacementRead.resolve(); });
    await until("replacement load completion", () => pending.some(item => item.label === "original full load 3" && item.settled));
    await act(async () => { initialRead.resolve(); }); await drain();
    const durable = await own("durable read after replacement completion", originalLoad(key, owner));
    expect({ visible: field()?.value, durable: durable?.warningSigns }, "An acknowledged safety-plan save remains visible when an earlier public Retry returns its older ciphertext").toEqual({ visible: acknowledged, durable: acknowledged });
  } finally {
    cleanupStarted = true;
    if (deadline) clearTimeout(deadline);
    retryWindow.resolve(); initialRead.resolve(); replacementRead.resolve();
    try { await drain(); }
    finally {
      try { if (root) await act(async () => root!.unmount()); }
      finally {
        try { await drain(); }
        finally { vi.restoreAllMocks(); resetTestState(); dom.window.close(); vi.unstubAllGlobals(); }
      }
    }
  }
}

describe("native local plan completion",()=>{
 it("the initialized editor preserves a dirty plan through the actual navigation seal",async()=>{const root=await ready();await typeArea(root,"My warning signs","new unsaved writing");await preserveSafetyPlan();expect(await loadSafetyPlan(KEY,USER)).toEqual({...EMPTY_SAFETY_PLAN,warningSigns:"new unsaved writing"});expect(map.get(SLOT)).not.toContain("new unsaved writing");});
 it("a clean restored editor leaves a subsequently authored durable receipt untouched",async()=>{await saveSafetyPlan(KEY,USER,PLAN);await ready();await saveSafetyPlan(KEY,USER,{...PLAN,coping:"new other screen"});const raw=map.get(SLOT);await preserveSafetyPlan();expect(map.get(SLOT)).toBe(raw);expect((await loadSafetyPlan(KEY,USER))?.coping).toBe("new other screen");});
 it("a save clears dirty custody so a later navigation cannot resurrect its old receipt",async()=>{const root=await ready();await typeArea(root,"My warning signs","saved writing");await press(root,"Save my plan");await settle(25,4);expect(textOf(root)).toContain("Saved — encrypted on this device");expect(textOf(root)).not.toContain("Stryker");await saveSafetyPlan(KEY,USER,PLAN);const raw=map.get(SLOT);await preserveSafetyPlan();expect(map.get(SLOT)).toBe(raw);});
 it("a subsequent edit clears the visible saved note and becomes the preserved plan",async()=>{const root=await ready();await typeArea(root,"My warning signs","saved writing");await press(root,"Save my plan");await settle(25,4);expect(textOf(root)).toContain("Saved — encrypted");await typeArea(root,"What helps me cope","a newer cope");expect(textOf(root)).not.toContain("Saved — encrypted");await preserveSafetyPlan();expect((await loadSafetyPlan(KEY,USER))?.coping).toBe("a newer cope");});
 it("actual native commit failure retains written fields and removes a prior saved note",async()=>{const root=await ready();await typeArea(root,"My warning signs","first writing");await press(root,"Save my plan");await settle(25,4);await typeArea(root,"My warning signs","new failed writing");backend.setItem=async()=>{throw new Error("native disk quota");};await press(root,"Save my plan");await settle(25,4);expect(warning(root)).toBe("new failed writing");expect(textOf(root)).toContain("Writing was not saved on this device");expect(textOf(root)).not.toContain("Saved — encrypted");expect(isDisabled(root,"Save my plan")).toBe(false);backend.setItem=async(k,v)=>{map.set(k,v);};expect((await loadSafetyPlan(KEY,USER))?.warningSigns).toBe("first writing");});
 it("a held native commit advertises busy while keeping newer edits dirty",async()=>{
  const root=await ready();await typeArea(root,"My warning signs","accepted writing");
  let release!:()=>void;const gate=new Promise<void>(resolve=>release=resolve);let reached=false;
  const pending:{promise:Promise<void>;settled:boolean;failed:boolean;reason:unknown}[]=[];
  const own=(promise:Promise<void>):Promise<void>=>{
   const result={promise,settled:false,failed:false,reason:undefined as unknown};pending.push(result);
   void promise.then(()=>{result.settled=true;},reason=>{result.settled=true;result.failed=true;result.reason=reason;});
   return promise;
  };
  const drain=async():Promise<void>=>{
   for(;;){
    const count=pending.length;
    await act(async()=>{await Promise.allSettled(pending.map(result=>result.promise));});
    if(count===pending.length&&pending.every(result=>result.settled))break;
   }
   const fault=pending.find(result=>result.failed);
   if(fault)throw new Error("Owned safety-plan save or backend completion failed",{cause:fault.reason});
  };
  const originalSave=planStorage.saveSafetyPlan,originalSet=backend.setItem;
  const saveObserver=vi.spyOn(planStorage,"saveSafetyPlan").mockImplementation((...args)=>own(originalSave(...args)));
  try{
   backend.setItem=(k,v)=>own((async()=>{reached=true;await gate;map.set(k,v);})());
   await press(root,"Save my plan");await settle(25,4);expect(reached).toBe(true);
   const saveButton=root.root.findAllByType("button")[0];
   expect({label:saveButton?textOfNode(saveButton):null,disabled:saveButton?.props.disabled===true},"A pending plan commit keeps the visible Save control labeled Saving and disabled").toEqual({label:"Saving…",disabled:true});
   await typeArea(root,"My warning signs","newer typed writing");await act(async()=>release());await settle(25,4);
   expect(warning(root)).toBe("newer typed writing");expect(textOf(root)).not.toContain("Saved — encrypted");expect(isDisabled(root,"Save my plan")).toBe(false);
   backend.setItem=async(k,v)=>{map.set(k,v);};await preserveSafetyPlan();expect((await loadSafetyPlan(KEY,USER))?.warningSigns).toBe("newer typed writing");
  }finally{
   release();
   try{await drain();}
   finally{
    try{await act(async()=>root.unmount());}
    finally{
     try{await drain();}
     finally{backend.setItem=originalSet;saveObserver.mockRestore();}
    }
   }
  }
 });
 it("a held initial restore preserves early typed fields and protects untouched stored fields",async()=>{await saveSafetyPlan(KEY,USER,PLAN);let release!:()=>void;const gate=new Promise<void>(r=>release=r);const get=backend.getItem.bind(backend);let first=true;const before=map.get(SLOT);backend.getItem=async k=>{const value=await get(k);if(k===SLOT&&first){first=false;await gate;}return value;};const root=await render(<SafetyPlanView onCrisis={()=>undefined}/>);await typeArea(root,"My warning signs","early typed warning");await preserveSafetyPlan();expect(map.get(SLOT)).toBe(before);await act(async()=>release());await settle(25,4);expect(warning(root)).toBe("early typed warning");expect(root.root.findAllByType("textarea")[1]!.props.value).toBe(PLAN.coping);await preserveSafetyPlan();expect(await loadSafetyPlan(KEY,USER)).toEqual({...PLAN,warningSigns:"early typed warning"});});
 it("the public retry retires an earlier native restore success",async()=>{await saveSafetyPlan(KEY,USER,PLAN);let release!:()=>void;const gate=new Promise<void>(r=>release=r);let first=true;const get=backend.getItem.bind(backend);backend.getItem=async k=>{const value=await get(k);if(k===SLOT&&first){first=false;await gate;}return value;};const root=await render(<SafetyPlanView onCrisis={()=>undefined}/>);await saveSafetyPlan(KEY,USER,{...PLAN,coping:"latest durable coping"});await press(root,"Retry restoring saved plan");await settle(25,4);expect(warning(root)).toBe(PLAN.warningSigns);await typeArea(root,"My warning signs","newer retry edit");await act(async()=>release());await settle(25,4);expect(warning(root)).toBe("newer retry edit");expect(root.root.findAllByType("textarea")[1]!.props.value).toBe("latest durable coping");expect(textOf(root)).not.toContain("could not");});
 it("the public retry retires an earlier native restore failure",async()=>{let release!:()=>void;const gate=new Promise<void>(r=>release=r);let first=true;const get=backend.getItem.bind(backend);backend.getItem=async k=>{if(k===SLOT&&first){first=false;await gate;throw new Error("old native read failure");}return get(k);};const root=await render(<SafetyPlanView onCrisis={()=>undefined}/>);await press(root,"Retry restoring saved plan");await settle(25,4);await act(async()=>release());await settle(25,4);expect(textOf(root)).not.toContain("Local encrypted records could not be read");await typeArea(root,"My warning signs","new writing");await press(root,"Save my plan");await settle(25,4);expect(textOf(root)).toContain("Saved — encrypted");});
 it("an unhydrated unreadable plan refuses save and stays recoverable",async()=>{map.set(SLOT,"unreadable-recoverable");const root=await ready();expect(textOf(root)).toContain("could not be authenticated");await typeArea(root,"My warning signs","early unsaved");await preserveSafetyPlan();expect(map.get(SLOT)).toBe("unreadable-recoverable");await press(root,"Save my plan");expect(textOf(root)).toContain("Restore the existing encrypted plan");expect(map.get(SLOT)).toBe("unreadable-recoverable");});
 it("the clean flag resets dirty field tracking before a later native restore retry",async()=>{await saveSafetyPlan(KEY,USER,PLAN);let fail=true;const get=backend.getItem.bind(backend);backend.getItem=async k=>{if(k===SLOT&&fail){fail=false;throw new Error("native restore failed");}return get(k);};const root=await ready();await typeArea(root,"My warning signs","early edit");await press(root,"Retry restoring saved plan");await settle(25,4);await press(root,"Save my plan");await settle(25,4);expect((await loadSafetyPlan(KEY,USER))?.warningSigns).toBe("early edit");
   await act(async()=>root.unmount());
   await acknowledgedSaveRetiresPendingRestore();
 });
 it("a public save after actual vault lock reports the locked session",async()=>{const root=await ready();await typeArea(root,"My warning signs","unsaved");vault.lock();await press(root,"Save my plan");expect(textOf(root)).toContain("Your session locked — sign in again.");expect(map.has(SLOT)).toBe(false);
   await act(async()=>root.unmount());
   vault.unlock({authKey:KEY.slice(),dataKey:KEY.slice()},USER);
   const retained=await ready();await typeArea(retained,"My warning signs","unverified retained writing");
   await act(async()=>{vault.unlock({authKey:KEY.slice(),dataKey:KEY.slice()});});
   await press(retained,"Save my plan");await settle(25,4);
   expect(textOf(retained)).toContain("Your session locked — sign in again.");
   expect(map.has(SLOT)).toBe(false);
   await act(async()=>retained.unmount());
   const unowned=await ready();await typeArea(unowned,"My warning signs","not yet restored writing");
   await press(unowned,"Save my plan");await settle(25,4);
   expect(textOf(unowned)).toContain("Restore the existing encrypted plan");
   expect(textOf(unowned)).toContain("Retry restoring saved plan");
   expect(map.has(SLOT)).toBe(false);});
 it("a second native save failure clears the old success receipt without another edit",async()=>{const root=await ready();await typeArea(root,"My warning signs","same writing");await press(root,"Save my plan");await settle(25,4);expect(textOf(root)).toContain("Saved — encrypted");backend.setItem=async()=>{throw new Error("native write unavailable");};await press(root,"Save my plan");await settle(25,4);expect(textOf(root)).toContain("Writing was not saved on this device");expect(textOf(root)).not.toContain("Saved — encrypted");});

 it("an empty-message native crypto failure still reports the local save fallback",async()=>{const root=await ready();await typeArea(root,"My warning signs","retained writing");vi.spyOn(crypto.subtle,"encrypt").mockRejectedValueOnce(new DOMException("","OperationError"));await press(root,"Save my plan");await settle(25,4);expect(textOf(root)).toContain("Could not save your plan — it is still on screen.");expect(warning(root)).toBe("retained writing");});

});
