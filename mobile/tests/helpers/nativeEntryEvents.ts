import React from "react";
import {readFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {createRequire} from "node:module";
const requireNative=createRequire(import.meta.url),babel=requireNative("@babel/core");
const navigationFile=resolve(dirname(requireNative.resolve("@react-navigation/core/package.json")),"lib/module/useEventEmitter.js");
const navigationCode=babel.transformSync(readFileSync(navigationFile,"utf8"),{filename:navigationFile,babelrc:false,configFile:false,plugins:[requireNative.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;
if(!navigationCode)throw Error("Installed navigation emitter could not be loaded");
const navigationModule={exports:{} as any};new Function("require","module","exports",navigationCode)((name:string)=>{if(name==="react")return React;throw Error("Unknown installed navigation emitter dependency "+name);},navigationModule,navigationModule.exports);
export const useNativeNavigationEvents=navigationModule.exports.useEventEmitter as ()=>{create:(target:string)=>{addListener:(type:string,callback:()=>void)=>()=>void};emit:(event:{type:string;target:string})=>void};
const inputFile=resolve(dirname(requireNative.resolve("react-native/package.json")),"Libraries/Components/TextInput/TextInput.js"),inputSource=readFileSync(inputFile,"utf8"),start=inputSource.indexOf("  const _onChange ="),end=inputSource.indexOf("  const _onSelectionChange =",start);
if(start<0||end<0)throw Error("Installed Native input delivery handler could not be located");
const inputCode=babel.transformSync(inputSource.slice(start,end),{filename:inputFile,babelrc:false,configFile:false,plugins:[requireNative.resolve("babel-plugin-syntax-hermes-parser"),requireNative.resolve("@babel/plugin-transform-flow-strip-types")]})?.code;
if(!inputCode)throw Error("Installed Native input handler could not be loaded");
/** Executes the installed TextInput change-event forwarding handler. Host
 * text/event counters are Native transport seams; the public callbacks and
 * their exact SDK ordering execute unchanged against currently committed props. */
export function nativeInputChange(props:{onChangeText?:(text:string)=>void;onChange?:(event:unknown)=>void},text:string){
 let lastText="",eventCount=0;const handler=new Function("props","inputRef","setLastNativeText","setMostRecentEventCount",inputCode+"\nreturn _onChange;")(props,{current:{}},(value:string)=>{lastText=value;},(value:number)=>{eventCount=value;});
 handler({nativeEvent:{text,eventCount:1}});return{lastText,eventCount};
}
