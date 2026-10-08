import{readFileSync}from"node:fs";
import{dirname,resolve}from"node:path";
import{createRequire}from"node:module";
const requireNative=createRequire(import.meta.url),babel=requireNative("@babel/core"),nativeRoot=dirname(requireNative.resolve("react-native/package.json"));
function load(relative:string,dependency:(name:string)=>unknown){const filename=resolve(nativeRoot,relative),code=babel.transformSync(readFileSync(filename,"utf8"),{filename,babelrc:false,configFile:false,plugins:[requireNative.resolve("babel-plugin-syntax-hermes-parser"),requireNative.resolve("@babel/plugin-transform-flow-strip-types"),requireNative.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;if(!code)throw Error("Installed AppState module could not be loaded");const module={exports:{} as any};new Function("require","module","exports","__DEV__",code)(dependency,module,module.exports,false);return module.exports.default;}
/** Executes actual AppState → NativeEventEmitter → RCTDeviceEventEmitter →
 * EventEmitter. Native state/observer transport is supplied. The oracle is
 * the exported SDK listenerCount result, including its permanent constructor
 * listener; no capacity, private registry access or function-call count. */
export function installedNativeAppState(){
 const prior=Object.getOwnPropertyDescriptor(globalThis,"__rctDeviceEventEmitter"),platform={__esModule:true,default:{OS:"ios"}},invariant=requireNative("invariant");
 const EventEmitter=load("Libraries/vendor/emitter/EventEmitter.js",name=>{throw Error("Unknown installed EventEmitter dependency "+name);});
 const emitter=load("Libraries/EventEmitter/RCTDeviceEventEmitter.js",name=>{if(name.endsWith("/EventEmitter"))return{__esModule:true,default:EventEmitter};if(name.endsWith("/Systrace"))return{trace:(_label:unknown,operation:()=>void)=>operation()};throw Error("Unknown installed device emitter dependency "+name);});
 const NativeEmitter=load("Libraries/EventEmitter/NativeEventEmitter.js",name=>{if(name.endsWith("/Platform"))return platform;if(name.endsWith("/RCTDeviceEventEmitter"))return{__esModule:true,default:emitter};if(name==="invariant")return invariant;throw Error("Unknown installed Native emitter dependency "+name);});
 const nativeState={getConstants:()=>({initialAppState:"active"}),getCurrentAppState:(callback:(value:unknown)=>void)=>callback({app_state:"active"}),addListener:()=>{},removeListeners:()=>{}};
 const appState=load("Libraries/AppState/AppState.js",name=>{if(name.endsWith("/NativeEventEmitter"))return{__esModule:true,default:NativeEmitter};if(name.endsWith("/Platform"))return platform;if(name.endsWith("/NativeAppState"))return{__esModule:true,default:nativeState};if(name.endsWith("/logError"))return{__esModule:true,default:(error:unknown)=>{throw error;}};throw Error("Unknown installed AppState dependency "+name);});
 return{appState,listenerCount:(event:string)=>emitter.listenerCount(event),emit:(state:string)=>emitter.emit("appStateDidChange",{app_state:state}),dispose:()=>{emitter.removeAllListeners();if(prior)Object.defineProperty(globalThis,"__rctDeviceEventEmitter",prior);else delete(globalThis as any).__rctDeviceEventEmitter;}};
}
