import {readFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {createRequire} from "node:module";
const nativeRequire=createRequire(import.meta.url),babel=nativeRequire("@babel/core"),nativeRoot=dirname(nativeRequire.resolve("react-native/package.json"));

/** Installed JSTimers owns callback allocation and cancellation. The test
 * device implements Native Timing's create/delete/frame transport and public
 * hasActiveTimersInRange contract exactly as JavaTimerManager's nonrepeating
 * duration predicate. This is a screen + SDK/device-module boundary, not a
 * running Android JVM or a Root navigation test. No capacity limit is imposed. */
export function installedNativeTiming(){
 type NativeTimer={id:number,duration:number,targetTime:number,repeat:boolean};
 const timers=new Map<number,NativeTimer>();let now=Date.now();
 const transport={
  createTimer:(id:number,duration:number,schedulingTime:number,repeat:boolean)=>{timers.set(id,{id,duration,targetTime:schedulingTime+duration,repeat});},
  deleteTimer:(id:number)=>{timers.delete(id);},
  setSendIdleEvents:()=>{},
 };
 const filename=resolve(nativeRoot,"Libraries/Core/Timers/JSTimers.js");
 const code=babel.transformSync(readFileSync(filename,"utf8"),{filename,babelrc:false,configFile:false,plugins:[nativeRequire.resolve("babel-plugin-syntax-hermes-parser"),nativeRequire.resolve("@babel/plugin-transform-flow-strip-types"),nativeRequire.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;
 if(!code)throw Error("Installed Native timer module could not be loaded");
 const module={exports:{} as any};
 new Function("require","module","exports","__DEV__",code)((name:string)=>{
  if(name==="./NativeTiming")return{__esModule:true,default:transport};
  if(name.endsWith("/toError"))return{default:(value:unknown)=>value instanceof Error?value:new Error(String(value))};
  if(name.endsWith("/BatchedBridge"))return{default:{setReactNativeMicrotasksCallback:()=>{}}};
  if(name.endsWith("/Systrace"))return{trace:()=>{}};
  if(name==="invariant")return nativeRequire(name);
  throw Error("Unmapped installed Native timer dependency "+name);
 },module,module.exports,false);
 const js=module.exports.default;
 return{
  setTimeout:((handler:(...args:any[])=>void,delay=0,...args:any[])=>js.setTimeout(handler,delay,...args)) as typeof setTimeout,
  clearTimeout:((handle:ReturnType<typeof setTimeout>)=>js.clearTimeout(handle)) as typeof clearTimeout,
  // TimingModule.kt72 → JavaTimerManager.kt265/380. This answers a Native
  // public idle query, rather than inspecting JS callbacks or call counts.
  hasActiveTimersInRange:(rangeMs:number)=>[...timers.values()].some(timer=>!timer.repeat&&timer.duration<rangeMs),
  advance:(milliseconds:number)=>{now+=milliseconds;const due=[...timers.values()].filter(timer=>timer.targetTime<now);for(const timer of due){if(timer.repeat)timer.targetTime=now+timer.duration;else timers.delete(timer.id);}if(due.length)js.callTimers(due.map(timer=>timer.id));},
 };
}
