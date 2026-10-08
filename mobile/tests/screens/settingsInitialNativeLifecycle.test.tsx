/** Root + Native scene-lifecycle module boundary. The device supplies the
 * already committed host's Help gesture and AppState event before passive
 * effects. This does not claim execution of Android/Fabric commit scheduling. */
import React from "react";
import ReactTestRenderer,{act} from "react-test-renderer";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {TouchableOpacity} from "react-native";
import {AppNavigator} from "../../src/navigation";
import {SessionProvider} from "../../src/store";
import {SettingsScreen} from "../../src/screens/SettingsScreen";
import {CrisisScreen} from "../../src/screens/CrisisScreen";
import {ThemeProvider} from "../../src/theme";
import {api} from "../../src/api/client";
import {secureStore,setSecureStoreBackend} from "../../src/secureStore";
import {vault} from "../../src/vault";
import {recordOnboardingSeen} from "../../src/onboarding";
import {installLocalDataKey,__resetLocalKeyLifecycleForTests} from "../../src/localWriteGuard";
import {runTestControl} from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
import {nativeGrantedPress} from "../helpers/nativePressability";
import {emitAppState} from "../helpers/rnMock";
import {publicSurface} from "../helpers/publicSurface";
import {assertPublicSurface} from "../helpers/publicSurfaceOracle";
const device=vi.hoisted(()=>({beforePassive:undefined as undefined|(()=>void)}));
vi.mock("@react-navigation/native-stack",async()=>{
 const React=await import("react"),routes=(children:any):any[]=>React.Children.toArray(children).flatMap((node:any)=>React.isValidElement(node)&&node.type===React.Fragment?routes((node.props as any).children):[node]);let navigate:(screen:string)=>void=()=>{};
 const navigation={navigate:(screen:string)=>navigate(screen),popToTop:()=>{},addListener:()=>()=>{}};
 const Scene=({component:Component,name}:any)=>{React.useLayoutEffect(()=>{if(name==="Settings")device.beforePassive?.();},[Component,name]);return Component?React.createElement(Component,{navigation}):null;};
 return{createNativeStackNavigator:()=>({Navigator:({children}:any)=>{const[route,setRoute]=React.useState("Settings");navigate=setRoute;const choices=routes(children);return choices.find(node=>node.props?.name===route)??choices[0]??null;},Screen:Scene})};
});
const USER="a".repeat(32),DATA=Buffer.alloc(32,13);let root:ReturnType<typeof ReactTestRenderer.create>|undefined;
beforeEach(async()=>{vi.useRealTimers();vi.restoreAllMocks();storage.__reset();keychain.__reset();device.beforePassive=undefined;runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();await api.setSession("Native initial settings bearer",USER,"alice");await recordOnboardingSeen(USER);vault.unlock({masterKey:Buffer.alloc(32,11),authKey:Buffer.alloc(32,12),dataKey:Buffer.from(DATA)},USER);installLocalDataKey(USER,vault.get().dataKey);vi.stubGlobal("fetch",async(url:string)=>{const path=new URL(url).pathname;const body=path.endsWith("/meta")?{unlock_days:30}:path.endsWith("/insights")?{active_days:2}:path.endsWith("/auth/key-envelope")?{key_scheme:"v1",salt:Buffer.alloc(16,7).toString("base64"),kdf_params:null,wrapped_data_key:null}:{enabled:false,active_for_current_policy:true};const response=new Response(JSON.stringify(body),{status:200});Object.defineProperty(response,"url",{value:url});return response;});});
afterEach(async()=>{if(root){assertPublicSurface(publicSurface(root),1);await act(async()=>root!.unmount());root=undefined;}vi.restoreAllMocks();vi.unstubAllGlobals();vault.lock();await api.clearSession();});
it("the first committed Native Settings frame retired before passive effects leaves the credential worker available",async()=>{
 const read=storage.getItem.bind(storage),write=storage.setItem.bind(storage),remove=storage.removeItem.bind(storage);let worker:Promise<unknown>=Promise.resolve(),retired=false,started=false,ready=false,replacement:Promise<void>|undefined;
 const nativeJob=<T,>(operation:()=>Promise<T>):Promise<T>=>{const pending=worker.then(operation,operation);worker=pending.catch(()=>{});return pending;};
 // Every UID read has the same finite physical SQLite IO latency. Neither
 // the number of reads nor component/private state changes that fault.
 // The next real credential operation starts after the first physical UID
 // body frees the FIFO worker; its JS receipt can be delivered separately.
 vi.spyOn(storage,"getItem").mockImplementation(slot=>nativeJob(async()=>{
   if(retired&&slot==="@mindpattern/user_id")await new Promise<void>(resolve=>{setTimeout(resolve,800);});
   const answer=await read(slot);
   if(retired&&!started&&slot==="@mindpattern/user_id"){started=true;replacement=api.setSession("replacement Native initial-settings bearer",USER,"alice");void replacement.then(()=>{ready=true;});}
   return answer;
 }));
 vi.spyOn(storage,"setItem").mockImplementation((slot,value)=>nativeJob(()=>write(slot,value)));
 vi.spyOn(storage,"removeItem").mockImplementation(slot=>nativeJob(()=>remove(slot)));
 device.beforePassive=()=>{device.beforePassive=undefined;const help=root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Need help now? Crisis resources")!,tap=nativeGrantedPress(help.props);try{tap.release();}finally{tap.dispose();}retired=true;emitAppState("inactive");};
 try{await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SessionProvider><AppNavigator/></SessionProvider></ThemeProvider>);});await vi.waitFor(()=>expect(started).toBe(true),{timeout:1500});expect(root!.root.findAllByType(SettingsScreen)).toHaveLength(0);expect(root!.root.findAllByType(CrisisScreen)).toHaveLength(1);await vi.waitFor(()=>expect(ready).toBe(true),{timeout:1100,interval:5});expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement Native initial-settings bearer");}
 finally{await replacement;await worker;}
});
