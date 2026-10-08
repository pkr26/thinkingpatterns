import React from "react";
import {readFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {createRequire} from "node:module";
import {installedPressability} from "./nativePressability";
const nativeRequire=createRequire(import.meta.url);
const babel=nativeRequire("@babel/core");
const filename=resolve(dirname(nativeRequire.resolve("react-native/package.json")),"Libraries/Components/Touchable/TouchableOpacity.js");
const code=babel.transformSync(readFileSync(filename,"utf8"),{filename,babelrc:false,configFile:false,plugins:[nativeRequire.resolve("babel-plugin-syntax-hermes-parser"),nativeRequire.resolve("@babel/plugin-transform-flow-strip-types"),nativeRequire.resolve("@babel/plugin-transform-react-jsx"),nativeRequire.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;
if(!code)throw Error("Installed Native TouchableOpacity could not be loaded");
const flatten=(style:any):any=>Array.isArray(style)?Object.assign({},...style.map(flatten)):style;
class OpacityValue{value:number;constructor(value:number){this.value=value;}resetAnimation(){} }
const module={exports:{} as any};
const dependency=(name:string)=>{
 if(name==="react")return React;
 if(name.endsWith("/Animated"))return{Value:OpacityValue,View:"NativeTouchableView",timing:()=>({start:()=>{}})};
 if(name.endsWith("/Easing"))return{quad:(v:number)=>v,inOut:(f:unknown)=>f};
 if(name.endsWith("/Pressability"))return installedPressability();
 if(name.endsWith("/PressabilityDebugView")||name.endsWith("/PressabilityDebug"))return{PressabilityDebugView:()=>null};
 if(name.endsWith("/flattenStyle"))return flatten;
 if(name.endsWith("/Platform"))return{OS:"ios",isTV:false};
 throw Error("Unmapped installed TouchableOpacity dependency "+name);
};
// Execute the installed component and its actual update/unmount methods.
// Only native opacity animation and host drawing are replaced.
new Function("require","module","exports","__DEV__",code)(dependency,module,module.exports,false);
export const NativeTouchableOpacity=module.exports.default as React.ComponentType<any>;
export function grantedTouchable(props:any){
 const event={currentTarget:1,target:1,persist:()=>{},dispatchConfig:{registrationName:"onResponderGrant"},nativeEvent:{pageX:10,pageY:10,locationX:10,locationY:10,timestamp:Date.now(),touches:[{pageX:10,pageY:10}]}};
 if(!props.onStartShouldSetResponder(event))throw Error("Native gesture refused");
 props.onResponderGrant(event);
 return()=>props.onResponderRelease(event);
}
