/** Public onboarding controls, encrypted credentials, supported stored panel
 * positions and Native reminder delivery. Native modules are transport seams. */
import React from "react";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {Switch,TouchableOpacity} from "react-native";
import {api} from "../../src/api/client";
import {vault} from "../../src/vault";
import {OnboardingScreen} from "../../src/screens/OnboardingScreen";
import {ThemeProvider} from "../../src/theme";
import {accountStorageKey} from "../../src/accountStorage";
import {installLocalDataKey,__resetLocalKeyLifecycleForTests} from "../../src/localWriteGuard";
import {runTestControl} from "../helpers/testControl";
import storage from "../helpers/storageMock";
import {render,flush,pressLabel,textOf,act} from "../helpers/rtr";
import {nativeGrantedPress} from "../helpers/nativePressability";
const USER="a".repeat(32),nav={navigate:vi.fn(),replace:vi.fn()};
const {notifications}=vi.hoisted(()=>({notifications:new Map<string,unknown>()}));
vi.mock("@notifee/react-native",()=>({default:{requestPermission:async()=>({authorizationStatus:1}),createChannel:async()=>"native channel",getTriggerNotifications:async()=>[],getDisplayedNotifications:async()=>[],createTriggerNotification:async(record:{id:string},trigger:unknown)=>{notifications.set(record.id,trigger);return record.id;},cancelNotification:async(id:string)=>{notifications.delete(id);},cancelAllNotifications:async()=>{notifications.clear();}},TriggerType:{TIMESTAMP:0},RepeatFrequency:{DAILY:1}}));
vi.mock("../../src/store",async original=>({...await original<typeof import("../../src/store")>(),useSession:()=>({touchActivity:()=>{}})}));
beforeEach(async()=>{vi.restoreAllMocks();notifications.clear();storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();await api.setSession("Native onboarding bearer",USER,"alice");vault.unlock({masterKey:Buffer.alloc(32,1),authKey:Buffer.alloc(32,2),dataKey:Buffer.alloc(32,3)},USER);installLocalDataKey(USER,vault.get().dataKey);nav.navigate.mockClear();nav.replace.mockClear();});
afterEach(async()=>{vi.restoreAllMocks();vi.unstubAllGlobals();vault.lock();await api.clearSession();});
it("an actual Native Continue release before the initial empty panel receipt preserves the chosen second panel",async()=>{
 const get=storage.getItem.bind(storage);let release!:()=>void,entered=false;const held=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const answer=await get(slot);if(slot===accountStorageKey.onboardingPanel(USER)){entered=true;await held;}return answer;});
 const root=await render(<ThemeProvider><OnboardingScreen navigation={nav}/></ThemeProvider>);await vi.waitFor(()=>expect(entered).toBe(true));const host=root.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Continue to panel 2 of 3")!,tap=nativeGrantedPress(host.props);
 try{await act(async()=>{tap.release();});expect(textOf(root)).toContain("2 of 3");release();await flush();expect(textOf(root)).toContain("2 of 3");expect(textOf(root)).toContain("Your words stay yours");}finally{release();tap.dispose();await act(async()=>root.unmount());}
});
it("a Native credential and stored panel receipt continue through all current public onboarding controls",async()=>{
 const root=await render(<ThemeProvider><OnboardingScreen navigation={nav}/></ThemeProvider>);await flush();expect(textOf(root)).toContain("1 of 3");const reminder=root.root.findAllByType(Switch).find(node=>node.props.accessibilityLabel==="Daily reminder")!;await act(async()=>reminder.props.onValueChange(true));await flush();expect(JSON.parse((await storage.getItem(accountStorageKey.reminders(USER)))!).enabled).toBe(true);
 await pressLabel(root,"Continue");await flush();await pressLabel(root,"Read the privacy policy");expect(nav.navigate).toHaveBeenCalledWith("Privacy");await pressLabel(root,"Continue");await flush();await pressLabel(root,"Need help now? Crisis resources");expect(nav.navigate).toHaveBeenCalledWith("Crisis");await pressLabel(root,"I understand — start writing");await flush();expect(await storage.getItem(accountStorageKey.onboardingSeen(USER))).toBe("1");expect(nav.replace).toHaveBeenCalledWith("Entry");await act(async()=>root.unmount());
});
it("an unmounted Native onboarding preference receipt leaves its physical storage worker available to the replacement login",async()=>{
 const root=await render(<ThemeProvider><OnboardingScreen navigation={nav}/></ThemeProvider>);await flush();const read=storage.getItem.bind(storage),write=storage.setItem.bind(storage),remove=storage.removeItem.bind(storage),slot=accountStorageKey.reminders(USER);let retired=false,ready=false,replacement:Promise<void>|undefined,release!:()=>void,timer:ReturnType<typeof setTimeout>|undefined;const held=new Promise<void>(resolve=>{release=resolve;});let worker:Promise<unknown>=Promise.resolve();const nativeJob=<T,>(operation:()=>Promise<T>):Promise<T>=>{const pending=worker.then(operation,operation);worker=pending.catch(()=>{});return pending;};
 vi.spyOn(storage,"getItem").mockImplementation(name=>nativeJob(async()=>{if(retired&&name===slot){timer??=setTimeout(release,800);await held;}return read(name);}));
 vi.spyOn(storage,"setItem").mockImplementation(async(name,value)=>{await nativeJob(()=>write(name,value));if(!retired&&name===slot){retired=true;act(()=>root.unmount());setImmediate(()=>{replacement=api.setSession("replacement Native onboarding bearer",USER,"alice");void replacement.then(()=>{ready=true;});});}});
 vi.spyOn(storage,"removeItem").mockImplementation(name=>nativeJob(()=>remove(name)));
 try{const reminder=root.root.findAllByType(Switch).find(node=>node.props.accessibilityLabel==="Daily reminder")!;await act(async()=>{reminder.props.onValueChange(true);});await vi.waitFor(()=>expect(retired).toBe(true));await vi.waitFor(()=>expect(ready).toBe(true),{timeout:250,interval:5});expect(await api.getUserId()).toBe(USER);expect(await read("@mindpattern/token")).not.toBeNull();}
 finally{release();if(timer)clearTimeout(timer);await replacement;await worker;}
});
it("a live Native onboarding reminder opt-in is reflected in the device's scheduled notification",async()=>{
 const root=await render(<ThemeProvider><OnboardingScreen navigation={nav}/></ThemeProvider>);await flush();const reminder=root.root.findAllByType(Switch).find(node=>node.props.accessibilityLabel==="Daily reminder")!;await act(async()=>{reminder.props.onValueChange(true);});await vi.waitFor(()=>expect(notifications.has("mindpattern-daily-reminder")).toBe(true));await act(async()=>root.unmount());
});
it("a retired Native onboarding opt-in cannot persist after the current opt-out's physical write refuses",async()=>{
 const root=await render(<ThemeProvider><OnboardingScreen navigation={nav}/></ThemeProvider>);await flush();const get=storage.getItem.bind(storage),set=storage.setItem.bind(storage),slot=accountStorageKey.reminders(USER);let entered=false,first=true,release!:()=>void;const held=new Promise<void>(resolve=>{release=resolve;});
 vi.spyOn(storage,"getItem").mockImplementation(async name=>{const answer=await get(name);if(first&&name==="@mindpattern/user_id"){first=false;entered=true;await held;}return answer;});vi.spyOn(storage,"setItem").mockImplementation(async(name,value)=>{if(name===slot&&JSON.parse(value).enabled===false)throw new Error("Native opt-out write refused");return set(name,value);});
 const control=()=>root.root.findAllByType(Switch).find(node=>node.props.accessibilityLabel==="Daily reminder")!;
 try{await act(async()=>{control().props.onValueChange(true);});await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{control().props.onValueChange(false);});release();await flush();await flush();expect(control().props.value).toBe(false);const raw=await get(slot);expect(raw===null||JSON.parse(raw).enabled===false).toBe(true);expect(notifications.has("mindpattern-daily-reminder")).toBe(false);}finally{release();await act(async()=>root.unmount());}
});
