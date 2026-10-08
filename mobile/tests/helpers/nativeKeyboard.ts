import {readFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {createRequire} from "node:module";
const nativeRequire=createRequire(import.meta.url),babel=nativeRequire("@babel/core"),nativeRoot=dirname(nativeRequire.resolve("react-native/package.json"));
function load(relative:string,dependency:(name:string)=>unknown){
 const filename=resolve(nativeRoot,relative),code=babel.transformSync(readFileSync(filename,"utf8"),{filename,babelrc:false,configFile:false,plugins:[nativeRequire.resolve("babel-plugin-syntax-hermes-parser"),nativeRequire.resolve("@babel/plugin-transform-flow-strip-types"),nativeRequire.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;
 if(!code)throw Error("Installed Native keyboard module could not be loaded");const module={exports:{} as any};new Function("require","module","exports","__DEV__",code)(dependency,module,module.exports,false);return module.exports.default;
}
/** Execute the installed Keyboard → dismissKeyboard → TextInputState chain.
 * The native input focus commands deliver real keyboard-observer semantics;
 * React host drawing and the platform event transport are the only seams. */
export function installedNativeKeyboard(){
 const listeners=new Map<string,Set<(value:unknown)=>void>>(),emit=(event:string,value:unknown)=>{for(const listener of listeners.get(event)??[])listener(value);};
 class NativeEmitter{addListener(event:string,listener:(value:unknown)=>void){const group=listeners.get(event)??new Set();group.add(listener);listeners.set(event,group);return{remove:()=>group.delete(listener)};}removeAllListeners(event:string){listeners.delete(event);}}
 const platform={__esModule:true,default:{OS:"ios"}},commands={focus:()=>emit("keyboardDidShow",{duration:0,easing:"keyboard",endCoordinates:{screenX:0,screenY:500,width:320,height:250}}),blur:()=>emit("keyboardDidHide",{})};
 const input=load("Libraries/Components/TextInput/TextInputState.js",name=>{
  if(name.endsWith("TextInputNativeComponent"))return{Commands:commands};if(name.endsWith("/RendererProxy"))return{findNodeHandle:(host:any)=>host?._nativeTag??null};if(name.endsWith("/Platform"))return platform;throw Error("Unmapped installed Native input dependency "+name);
 });
 const dismiss=load("Libraries/Utilities/dismissKeyboard.js",name=>{if(name.endsWith("/TextInputState"))return{default:input};throw Error("Unmapped installed Native dismiss dependency "+name);});
 const keyboard=load("Libraries/Components/Keyboard/Keyboard.js",name=>{
  if(name.endsWith("/NativeEventEmitter"))return NativeEmitter;if(name.endsWith("/LayoutAnimation"))return{Types:{},configureNext:()=>{}};if(name.endsWith("/dismissKeyboard"))return dismiss;if(name.endsWith("/Platform"))return platform;if(name.endsWith("/NativeKeyboardObserver"))return{};throw Error("Unmapped installed Native keyboard dependency "+name);
 });
 const host={_nativeTag:123,currentProps:{editable:true}};input.registerInput(host);return{keyboard,focus:()=>input.focusTextInput(host),focusedInput:()=>input.currentlyFocusedInput()};
}
