import {readFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {createRequire} from "node:module";

const requireNative=createRequire(import.meta.url);
const babel=requireNative("@babel/core") as {transformSync(source:string,options:Record<string,unknown>):{code?:string}|null};
const nativeRoot=dirname(requireNative.resolve("@react-native/virtualized-lists/package.json"));
const modules=new Map<string,{exports:Record<string,any>}>();

// Execute the installed RN layout/window implementation. Only its Flow
// annotations and module syntax are transformed; no native algorithm is copied.
function loadNative(name:string):Record<string,any>{
  const existing=modules.get(name);if(existing)return existing.exports;
  const module={exports:{}};modules.set(name,module);
  const filename=resolve(nativeRoot,"Lists",`${name}.js`);
  const code=babel.transformSync(readFileSync(filename,"utf8"),{filename,babelrc:false,configFile:false,plugins:[requireNative.resolve("@babel/plugin-transform-flow-strip-types"),requireNative.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;
  if(!code)throw new Error("Native layout source could not be loaded");
  const dependency=(id:string)=>{
    if(id==="./VirtualizeUtils")return loadNative("VirtualizeUtils");
    // This public offset query does not consult platform window-size flags.
    if(id==="react-native/src/private/featureflags/ReactNativeFeatureFlags")return new Proxy({__esModule:true}, {get(_target,name){if(name==="__esModule")return true;throw new Error("Unexpected native feature flag query");}});
    return requireNative(id);
  };
  new Function("require","module","exports",code)(dependency,module,module.exports);
  return module.exports;
}

export function nativeWritingAtScrollOffset<T>(data:T[],keyExtractor:(item:T,index:number)=>string,lengths:number[],offset:number):T|undefined{
  const Metrics=loadNative("ListMetricsAggregator").default;
  const metrics=new Metrics();let y=0;
  const props={data,keyExtractor,getItem:(rows:T[],index:number)=>rows[index],getItemCount:(rows:T[])=>rows.length};
  lengths.forEach((height,index)=>{metrics.notifyCellLayout({cellIndex:index,cellKey:keyExtractor(data[index],index),orientation:{horizontal:false,rtl:false},layout:{x:0,y,width:320,height}});y+=height;});
  metrics.notifyListContentLayout({orientation:{horizontal:false,rtl:false},layout:{width:320,height:y}});
  const index=loadNative("VirtualizeUtils").elementsThatOverlapOffsets([offset],props,metrics)[0];
  return index===undefined?undefined:data[index];
}
