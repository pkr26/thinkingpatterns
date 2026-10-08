/** Accessible activation can fire onPress/onValueChange without the parent
 * ScrollView's touch-start event. Exercise the shipped parent idle deadline,
 * native credential/storage/crypto providers and real Settings screen. */
import React from "react";
import crypto from "node:crypto";
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import ReactTestRenderer,{act} from "react-test-renderer";
import { Text,TextInput,TouchableOpacity,Switch } from "react-native";
import { api } from "../../src/api/client";
import { SessionProvider,useSession } from "../../src/store";
import { ThemeProvider } from "../../src/theme";
import { SettingsScreen } from "../../src/screens/SettingsScreen";
import { vault } from "../../src/vault";
import { setSecureStoreBackend } from "../../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../../src/localWriteGuard";
import { runTestControl } from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as files from "../helpers/expoFsMock";
import * as keychain from "../helpers/keychainMock";
import { setReminderEnabled } from "../../src/reminders";
import { setMeasureReminderEnabled } from "../../src/measureReminders";
import { enableBiometricUnlock } from "../../src/biometricUnlock";
// Node cannot load linked native pods synchronously. Pin only the device's
// capability facts; preserve the shipped preference/actions and parent store.
vi.mock("../../src/nativeFeatures",async original=>({...await original<typeof import("../../src/nativeFeatures")>(),reminderCapability:()=>({available:true})}));
vi.mock("../../src/healthkit",async original=>({...await original<typeof import("../../src/healthkit")>(),healthKitCapability:()=>({available:true})}));
vi.mock("@notifee/react-native",()=>({default:{requestPermission:async()=>({authorizationStatus:1}),createChannel:async()=>"channel",createTriggerNotification:async()=>"notification",cancelNotification:async()=>{},cancelAllNotifications:async()=>{},getTriggerNotifications:async()=>[],getDisplayedNotifications:async()=>[]},TriggerType:{TIMESTAMP:0},RepeatFrequency:{DAILY:1}}));
vi.mock("react-native-health",()=>({default:{requestAuthorization:async()=>true,getAuthorizationStatus:async()=>({stateOfMind:2}),saveStateOfMind:async()=>true}}));
const USER="a".repeat(32),SALT=Buffer.alloc(16,3),PASSWORD="the known account password",master=crypto.pbkdf2Sync(PASSWORD,SALT,600000,32,"sha256"),auth=Buffer.from(crypto.hkdfSync("sha256",master,Buffer.alloc(0),Buffer.from("mindpattern/auth/v1"),32)),data=Buffer.from(crypto.hkdfSync("sha256",master,Buffer.alloc(0),Buffer.from("mindpattern/data/v1"),32));
let root:ReturnType<typeof ReactTestRenderer.create>|undefined,session:ReturnType<typeof useSession>,recovery:boolean;
function Probe(){session=useSession();return <Text accessibilityLabel="session observation">{JSON.stringify({auth:session.authStatus,unlocked:session.unlocked,loading:session.activeDaysLoading})}</Text>;}
function state(){return JSON.parse(root!.root.findAllByType(Text).find(n=>n.props.accessibilityLabel==="session observation")!.props.children);}
async function press(label:string){const button=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel===label);expect(button,`available action ${label}`).toBeDefined();expect(button!.props.disabled).not.toBe(true);await act(async()=>{await button!.props.onPress();});}
async function toggle(label:string,on:boolean){const control=root!.root.findAllByType(Switch).find(n=>n.props.accessibilityLabel===label);expect(control,`available switch ${label}`).toBeDefined();expect(control!.props.disabled).not.toBe(true);await act(async()=>{await control!.props.onValueChange(on);});}
beforeEach(async()=>{
 vi.useRealTimers();vi.restoreAllMocks();storage.__reset();files.__resetFiles();keychain.__reset();keychain.__setBiometryType("FaceID");runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();recovery=false;
 const notifications=new Map<string,unknown>();
 vi.stubGlobal("require",(name:string)=>{if(name==="@notifee/react-native")return {default:{requestPermission:async()=>({authorizationStatus:1}),createChannel:async()=>"channel",getTriggerNotifications:async()=>[],getDisplayedNotifications:async()=>[],createTriggerNotification:async(n:{id:string},trigger:unknown)=>{notifications.set(n.id,trigger);return n.id;},cancelNotification:async(id:string)=>{notifications.delete(id);},cancelAllNotifications:async()=>{notifications.clear();}},TriggerType:{TIMESTAMP:0},RepeatFrequency:{DAILY:1}};if(name==="react-native-health")return {requestAuthorization:async()=>true,getAuthorizationStatus:async()=>({stateOfMind:2}),saveStateOfMind:async()=>true};throw new Error("unavailable native module "+name);});
 await api.setSession("native-bearer",USER,"alice");await api.cacheSalt("alice",SALT.toString("base64"));vault.unlock({masterKey:Buffer.from(master),authKey:Buffer.from(auth),dataKey:Buffer.from(data)},USER);await setReminderEnabled(USER,true);await setMeasureReminderEnabled(USER,true);await enableBiometricUnlock(USER,vault.get().dataKey);
 vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{const path=new URL(url).pathname;let value:unknown={};if(path.endsWith("/meta"))value={unlock_days:30,llm_available:false,sharing_available:false,audio_available:false};else if(path.endsWith("/insights"))value={active_days:5};else if(path.endsWith("/auth/key-envelope"))value={key_scheme:"v1",salt:SALT.toString("base64"),kdf_params:null,wrapped_data_key:null};else if(path.endsWith("/account/recovery")){if(init.method==="PUT")recovery=true;if(init.method==="DELETE")recovery=false;value={enabled:recovery,set_at:recovery?"2026-10-06T00:00:00Z":null,scheme:"v2"};}else if(path.endsWith("/consent/llm")||path.endsWith("/consent/voice"))value={enabled:false,active_for_current_policy:false};else if(path.endsWith("/auth/logout"))value={};else throw new Error("unexpected native route "+path);const response=new Response(JSON.stringify(value));Object.defineProperty(response,"url",{value:url});return response;});
});
afterEach(async()=>{if(root){await act(async()=>root!.unmount());root=undefined;}vi.useRealTimers();vi.restoreAllMocks();vault.lock();await api.clearSession();vi.unstubAllGlobals();});
const scenarios=["daily enabled","daily time","check-in enabled","check-in cadence","Health","biometric","language","theme","haptics","password card","recovery create","recovery remove"] as const;
it.each(scenarios)("keeps the real native vault open while Settings %s is activated accessibly",async action=>{
 recovery=action==="recovery remove";await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SessionProvider><Probe/><SettingsScreen navigation={{navigate:()=>{},popToTop:()=>{}}}/></SessionProvider></ThemeProvider>);});
 await vi.waitFor(()=>expect(state()).toEqual({auth:"loggedIn",unlocked:true,loading:false}));await vi.waitFor(()=>expect(root!.root.findAllByType(TouchableOpacity).some(n=>n.props.accessibilityLabel==="Reminder time: Morning 9:00")).toBe(true));
 if(action==="recovery create"||action==="recovery remove"){await press(action==="recovery create"?"Create recovery kit":"Remove kit");await act(async()=>{const field=root!.root.findAllByType(TextInput).find(n=>n.props.accessibilityLabel==="Password confirmation")!;expect(field).toBeDefined();field.props.onChangeText(PASSWORD);});}
 vi.useFakeTimers();await act(async()=>vi.advanceTimersByTimeAsync(120000));expect(state().unlocked).toBe(true);
 if(action==="daily enabled")await toggle("Daily reminder",false);else if(action==="daily time")await press("Reminder time: Morning 9:00");else if(action==="check-in enabled")await toggle("Check-in reminders",false);else if(action==="check-in cadence")await press("Check-in interval: 2 weeks");else if(action==="Health")await toggle("Mirror mood check-ins to the Health app",true);else if(action==="biometric")await toggle("Biometric unlock",false);else if(action==="language")await press("App language: English");else if(action==="theme")await press("Theme: Light");else if(action==="haptics")await toggle("Haptics",false);else if(action==="password card")await press("Change password");else await press("Confirm with password");
 await act(async()=>vi.advanceTimersByTimeAsync(180000));expect(state().unlocked).toBe(true);await act(async()=>vi.advanceTimersByTimeAsync(120000));expect(state().unlocked).toBe(false);expect(vault.isUnlocked()).toBe(false);
});
