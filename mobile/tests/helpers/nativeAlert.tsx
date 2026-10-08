import React from "react";
import {Text,View,TouchableOpacity} from "react-native";
import {readFileSync} from "node:fs";
import {dirname,resolve} from "node:path";
import {createRequire} from "node:module";
const nativeRequire=createRequire(import.meta.url),babel=nativeRequire("@babel/core"),nativeRoot=dirname(nativeRequire.resolve("react-native/package.json"));
/** Installed Alert.alert → prompt → RCTAlertManager → NativeAlertManager.
 * The device's system window persists independently of its caller's view.
 * Only that Native window transport/drawing is supplied here. */
export function installedNativeAlert(platform:"ios"|"android"="ios"){
 type WindowArgs={title:string,message?:string,buttons:Array<Record<string,string>>};
 const state={current:null as null|(WindowArgs&{callback:(button:string)=>void})};
 function load(relative:string,dependency:(name:string)=>unknown){const filename=resolve(nativeRoot,relative),code=babel.transformSync(readFileSync(filename,"utf8"),{filename,babelrc:false,configFile:false,plugins:[nativeRequire.resolve("babel-plugin-syntax-hermes-parser"),nativeRequire.resolve("@babel/plugin-transform-flow-strip-types"),nativeRequire.resolve("@babel/plugin-transform-modules-commonjs")]})?.code;if(!code)throw Error("Installed Native alert module could not load");const module={exports:{} as any};new Function("require","module","exports","__DEV__",code)(dependency,module,module.exports,false);return module.exports;}
 const manager=load("Libraries/Alert/RCTAlertManager.ios.js",name=>{if(name==="./NativeAlertManager")return{__esModule:true,default:{alertWithArgs:(args:WindowArgs,callback:(button:string)=>void)=>{state.current={...args,callback};}}};throw Error("Unmapped Native alert manager dependency "+name);});
 const dialog={getConstants:()=>({buttonClicked:"buttonClicked",dismissed:"dismissed",buttonPositive:-1,buttonNegative:-2,buttonNeutral:-3}),showAlert:(config:Record<string,unknown>,_error:unknown,action:(kind:string,button:number)=>void)=>{const buttons=[[-3,config.buttonNeutral],[-2,config.buttonNegative],[-1,config.buttonPositive]].filter(([,label])=>typeof label==="string").map(([key,label])=>({[String(key)]:String(label)}));state.current={title:String(config.title),message:String(config.message),buttons,callback:button=>action("buttonClicked",Number(button))};}};
 const Alert=load("Libraries/Alert/Alert.js",name=>{if(name.endsWith("/Platform"))return{__esModule:true,default:{OS:platform}};if(name==="./RCTAlertManager")return manager;if(name.endsWith("NativeDialogManagerAndroid"))return{__esModule:true,default:dialog};throw Error("Unmapped Native alert dependency "+name);}).default;
 function Window(){const current=state.current;return current?<View accessibilityRole="alert"><Text>{current.title}</Text><Text>{current.message}</Text>{current.buttons.map((button,index)=>{const label=Object.values(button).join("");return <TouchableOpacity key={index} accessibilityLabel={label} onPress={()=>{state.current=null;current.callback(Object.keys(button)[0]!);}}><Text>{label}</Text></TouchableOpacity>;})}</View>:null;}
 return{alert:Alert.alert.bind(Alert),Window};
}
