/** Native linked-module capability and physically stored Health samples. */
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {Platform} from "react-native";
import {vault} from "../src/vault";
import {readFileSync} from "node:fs";
import ts from "typescript";
import * as reminderPreferences from "../src/reminderPreferences";
import * as accountStorage from "../src/accountStorage";
let healthApi:typeof import("../src/healthkit");
const healthKitCapability=()=>healthApi.healthKitCapability();
const ensureStateOfMindWriteAccess=()=>healthApi.ensureStateOfMindWriteAccess();
const writeStateOfMind:typeof healthApi.writeStateOfMind=(...args)=>healthApi.writeStateOfMind(...args);
const mirrorMoodCheckIn:typeof healthApi.mirrorMoodCheckIn=(...args)=>healthApi.mirrorMoodCheckIn(...args);
const setMoodMirrorPref:typeof healthApi.setMoodMirrorPref=(...args)=>healthApi.setMoodMirrorPref(...args);
const clearMoodMirrorPref:typeof healthApi.clearMoodMirrorPref=(...args)=>healthApi.clearMoodMirrorPref(...args);
const getMoodMirrorPref:typeof healthApi.getMoodMirrorPref=(...args)=>healthApi.getMoodMirrorPref(...args);
function linkedNativeModule(){
 // Metro invokes the shipped module with a lexical require. The Node ESM
 // transform cannot link its native pod; compile the exact on-disk target
 // source to CommonJS, retaining every mutation/instrumentation expression.
 const source=readFileSync(new URL("../src/healthkit.ts",import.meta.url),"utf8");
 const code=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,esModuleInterop:true}}).outputText;
 const module={exports:{}};const nativeRequire=(name:string)=>{if(name==="react-native-health"){if(nativeFault)throw new Error("Native pod unavailable");nativeResolve?.();return native;}if(name==="react-native")return {Platform};if(name==="@react-native-async-storage/async-storage")return storage;if(name==="./reminderPreferences")return reminderPreferences;if(name==="./accountStorage")return accountStorage;throw new Error("Unexpected Native dependency "+name);};
 new Function("require","module","exports",code)(nativeRequire,module,module.exports);healthApi=module.exports as typeof healthApi;
}
import storage from "./helpers/storageMock";
import {accountStorageKey} from "../src/accountStorage";
import {changeLocalSessionOwner,__resetLocalKeyLifecycleForTests} from "../src/localWriteGuard";
import {runTestControl} from "./helpers/testControl";
let samples:Array<{kind:string,valence:number,date:string}>,sheetVisible:boolean;
let native:Record<string,unknown>;
let nativeResolve:(()=>void)|undefined, nativeFault=false;
const device=(status:unknown)=>({requestAuthorization:async()=>{sheetVisible=true;return true;},getAuthorizationStatus:async()=>status,saveStateOfMind:async(value:{kind:string,valence:number,date:string})=>{samples.push({...value});return true;}});
const originalOS=Platform.OS,originalVersion=Platform.Version;
beforeEach(()=>{vi.restoreAllMocks();storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);changeLocalSessionOwner("native-health-owner");samples=[];sheetVisible=false;nativeResolve=undefined;nativeFault=false;native=device({stateOfMind:2});Platform.OS="ios";Platform.Version=18;linkedNativeModule();});
afterEach(()=>{Platform.OS=originalOS;Platform.Version=originalVersion;vi.unstubAllGlobals();vi.restoreAllMocks();});
it.each([18,"18",19,"18.2"])("a linked native device version=%j advertises State of Mind writing",version=>{Platform.Version=version;expect(healthKitCapability()).toEqual({available:true});});
it.each([17,"17.9"])("a native device version=%j without State of Mind explains that capability",version=>{Platform.Version=version;expect(healthKitCapability()).toEqual({available:false,reason:"settings.reasonHealthIOS18"});});
it("a linked native Android adapter need not pass an iOS version gate",()=>{Platform.OS="android";Platform.Version=7;expect(healthKitCapability()).toEqual({available:true});});
it.each([{}, {requestAuthorization:async()=>true}, {saveStateOfMind:async()=>true}])("an incomplete Native adapter has a meaningful unavailable result: %j",value=>{native=value;expect(healthKitCapability()).toEqual({available:false,reason:"settings.reasonHealthOldModule"});});
it("a linked default-export Native module advertises the same device capability",()=>{native={default:device({stateOfMind:2})};expect(healthKitCapability()).toEqual({available:true});});
it.each([null,undefined,false,17,"unknown",{stateOfMind:2}])("a Native authorization result %j preserves the documented write outcome",async status=>{native=device(status);expect(await writeStateOfMind(.37,"2026-10-07")).toBe(true);expect(samples).toEqual([{kind:"pleasant",valence:.37,date:"2026-10-07"}]);});
it("a native adapter without a status callback can acknowledge the actual saved sample",async()=>{native=device({stateOfMind:2});delete native.getAuthorizationStatus;expect(await ensureStateOfMindWriteAccess()).toBe(true);expect(await writeStateOfMind(-.42,"2026-10-06")).toBe(true);expect(samples).toEqual([{kind:"unpleasant",valence:-.42,date:"2026-10-06"}]);});
it("an unowned check-in never opens the Native authorization sheet",async()=>{expect(await writeStateOfMind(.5,"2026-10-07",()=>false)).toBe(false);expect(sheetVisible).toBe(false);expect(samples).toEqual([]);});
it("a retired check-in leaves no native sample after an actual authorization sheet completes",async()=>{let release!:()=>void,entered=false,owns=true;const wait=new Promise<void>(resolve=>{release=resolve;});native={...device({stateOfMind:2}),requestAuthorization:async()=>{entered=true;sheetVisible=true;await wait;return true;}};const result=writeStateOfMind(.5,"2026-10-07",()=>owns);await vi.waitFor(()=>expect(entered).toBe(true));owns=false;release();expect(await result).toBe(false);expect(samples).toEqual([]);});
it("a physically disabled Health preference prevents a pending check-in after Native permission acknowledgement",async()=>{const user="native-health-owner";await setMoodMirrorPref(user,true);let release!:()=>void,entered=false;const wait=new Promise<void>(resolve=>{release=resolve;});native={...device({stateOfMind:2}),requestAuthorization:async()=>{entered=true;sheetVisible=true;await wait;return true;}};const result=mirrorMoodCheckIn(user,.5,"2026-10-07");await vi.waitFor(()=>expect(entered).toBe(true));await setMoodMirrorPref(user,false);release();expect(await result).toBe(false);expect(samples).toEqual([]);expect(await getMoodMirrorPref(user)).toBe(false);expect(JSON.parse((await storage.getItem(accountStorageKey.healthMirror(user)))!).enabled).toBe(false);});
it("an absent Native pod returns false from both exported action helpers",async()=>{native=null as never;expect(await ensureStateOfMindWriteAccess()).toBe(false);expect(await writeStateOfMind(.5,"2026-10-07")).toBe(false);expect(samples).toEqual([]);});
it("a native preference storage refusal returns false from the public mirror helper",async()=>{vi.spyOn(storage,"getItem").mockRejectedValue(new Error("Native preference provider unavailable"));expect(await mirrorMoodCheckIn("native-health-owner",.5,"2026-10-07")).toBe(false);expect(sheetVisible).toBe(false);expect(samples).toEqual([]);});
it("a linked Native action can acknowledge before a later provider refusal",async()=>{let delivered=false;nativeResolve=()=>{if(delivered)return;delivered=true;queueMicrotask(()=>queueMicrotask(()=>{native.requestAuthorization=async()=>false;}));};expect(await ensureStateOfMindWriteAccess()).toBe(true);expect(sheetVisible).toBe(true);});
it("a native persisted opt-in refusal is a completed false receipt from the public mirror helper",async()=>{await storage.setItem(accountStorageKey.healthMirror("native-health-owner"),"true");expect(await mirrorMoodCheckIn("native-health-owner",.5,"2026-10-07")).toBe(false);expect(samples).toEqual([]);});
it.each([1,2,3].flatMap(turn=>["disable","clear"].map(kind=>({turn,kind}))))("a delivered Native $kind preference event at turn=$turn prevents an obsolete authorization sheet",async({turn,kind})=>{
 const user="native-health-owner";await setMoodMirrorPref(user,true);const get=storage.getItem.bind(storage);let first=true,pending:Promise<void>|undefined;
 vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const raw=await get(slot);if(first&&slot===accountStorageKey.healthMirror(user)){first=false;let remaining=turn;const event=()=>{if(--remaining>0){queueMicrotask(event);return;}pending=kind==="disable"?setMoodMirrorPref(user,false):clearMoodMirrorPref(user);};queueMicrotask(event);}return raw;});
 expect(await mirrorMoodCheckIn(user,.5,"2026-10-07")).toBe(false);await pending;expect(sheetVisible).toBe(false);expect(samples).toEqual([]);expect(await getMoodMirrorPref(user)).toBe(false);
});
it("a Native pod that cannot resolve returns false from both public action helpers",async()=>{nativeFault=true;expect(await ensureStateOfMindWriteAccess()).toBe(false);expect(await writeStateOfMind(.5,"2026-10-07")).toBe(false);expect(samples).toEqual([]);});
it("a mislinked callable Native default export cannot advertise a State of Mind adapter",async()=>{const callable=Object.assign(()=>{},device({stateOfMind:2}));native={default:callable};expect(healthKitCapability()).toEqual({available:false,reason:"settings.reasonHealthOldModule"});expect(await ensureStateOfMindWriteAccess()).toBe(false);expect(await writeStateOfMind(.5,"2026-10-07")).toBe(false);expect(sheetVisible).toBe(false);});
it("an ownership provider failure returns a false public mirror receipt without Native disclosure",async()=>{expect(await mirrorMoodCheckIn("native-health-owner",.5,"2026-10-07",()=>{throw new Error("Ownership provider unavailable");})).toBe(false);expect(sheetVisible).toBe(false);expect(samples).toEqual([]);});
it("an unowned public mirror admission cannot adopt a later Native vault receipt",async()=>{
 const user="native-health-owner";await setMoodMirrorPref(user,true);vault.lock();const result=mirrorMoodCheckIn(user,.5,"2026-10-07",()=>vault.ownerUserId()===user);queueMicrotask(()=>vault.unlock({masterKey:Buffer.alloc(32,31),authKey:Buffer.alloc(32,32),dataKey:Buffer.alloc(32,33)},user));expect(await result).toBe(false);expect(sheetVisible).toBe(false);expect(samples).toEqual([]);vault.lock();
});
it("the exported Native writer honors an actual physically disabled opt-in provider",async()=>{const user="native-health-owner";await setMoodMirrorPref(user,false);expect(await writeStateOfMind(.5,"2026-10-07",()=>true,()=>getMoodMirrorPref(user))).toBe(false);expect(samples).toEqual([]);});
it("a mislinked callable Native module cannot smuggle a valid default adapter past the public capability boundary",async()=>{native=Object.assign(()=>{},{default:device({stateOfMind:2})}) as never;expect(healthKitCapability()).toEqual({available:false,reason:"settings.reasonHealthOldModule"});expect(await ensureStateOfMindWriteAccess()).toBe(false);expect(sheetVisible).toBe(false);});
