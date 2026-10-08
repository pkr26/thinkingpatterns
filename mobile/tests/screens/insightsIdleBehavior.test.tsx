/** Accessible pattern activation keeps the actual parent's finite idle deadline alive. */
import React from "react";
import ReactTestRenderer,{act} from "react-test-renderer";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {Text,TouchableOpacity,ScrollView} from "react-native";
import {api} from "../../src/api/client";
import {SessionProvider,useSession} from "../../src/store";
import {InsightsScreen} from "../../src/screens/InsightsScreen";
import {ThemeProvider} from "../../src/theme";
import {vault} from "../../src/vault";
import {encrypt,buildAad,decrypt} from "../../src/crypto/envelope";
import {INSIGHTS_PAYLOAD_VERSION} from "../../src/crypto/journalCrypto";
import {secureStore,setSecureStoreBackend} from "../../src/secureStore";
import {__resetLocalKeyLifecycleForTests,installLocalDataKey} from "../../src/localWriteGuard";
import {accountStorageKey} from "../../src/accountStorage";
import {runTestControl} from "../helpers/testControl";
import storage from "../helpers/storageMock";
import * as keychain from "../helpers/keychainMock";
const USER="a".repeat(32),KEY=Buffer.alloc(32,84);
let root:ReturnType<typeof ReactTestRenderer.create>|undefined,session:ReturnType<typeof useSession>;
function Probe(){session=useSession();return <Text accessibilityLabel="Native Patterns session state">{JSON.stringify({auth:session.authStatus,unlocked:session.unlocked,loading:session.activeDaysLoading})}</Text>;}
function state(){return JSON.parse(root!.root.findAllByType(Text).find(n=>n.props.accessibilityLabel==="Native Patterns session state")!.props.children);}
beforeEach(async()=>{
 vi.useRealTimers();vi.restoreAllMocks();storage.__reset();keychain.__reset();runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();await api.setSession("Native Patterns idle bearer",USER,"alice");vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32,83),dataKey:Buffer.from(KEY)},USER);installLocalDataKey(USER,vault.get().dataKey);
 const blob=encrypt(KEY,Buffer.from(JSON.stringify({v:INSIGHTS_PAYLOAD_VERSION,stats:{patterns:[{kind:"topic",label:"The actual native idle observation",occurrences:4,confidence:.5,detail:{pattern_pid:"topic:native-idle"}}]}})),buildAad("insights",USER,"patterns")).toString("base64");
 vi.stubGlobal("fetch",async(url:string)=>{const path=new URL(url).pathname;let value:unknown={};if(path.endsWith("/meta"))value={unlock_days:30};else if(path.endsWith("/insights"))value={phase:"insight",active_days:40,days_remaining:0,blob};else throw new Error("Unexpected Native idle route "+path);const response=new Response(JSON.stringify(value));Object.defineProperty(response,"url",{value:url});return response;});
});
afterEach(async()=>{vi.useRealTimers();if(root){await act(async()=>root!.unmount());root=undefined;}vi.restoreAllMocks();vault.lock();await api.clearSession();vi.unstubAllGlobals();});
it.each(["accessible mute","screen touch"])("the actual Native vault remains unlocked after %s interaction",async action=>{
 await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SessionProvider><Probe/><InsightsScreen/></SessionProvider></ThemeProvider>);});await vi.waitFor(()=>expect(state()).toEqual({auth:"loggedIn",unlocked:true,loading:false}));await vi.waitFor(()=>expect(root!.root.findAllByType(TouchableOpacity).some(n=>n.props.accessibilityLabel==="Mute this pattern — The actual native idle observation")).toBe(true));vi.useFakeTimers();await act(async()=>vi.advanceTimersByTimeAsync(120000));if(action==="accessible mute"){const button=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Mute this pattern — The actual native idle observation")!;await act(async()=>button.props.onPress());const receipt=(await storage.getItem(accountStorageKey.feedback(USER)))!;expect(JSON.parse(decrypt(KEY,Buffer.from(receipt,"base64"),buildAad("feedback-local",USER)).toString("utf8"))).toMatchObject([{pid:"topic:native-idle",mute:true}]);}else await act(async()=>root!.root.findByType(ScrollView).props.onTouchStart());await act(async()=>vi.advanceTimersByTimeAsync(180000));expect(state().unlocked).toBe(true);await act(async()=>vi.advanceTimersByTimeAsync(120000));expect(state().unlocked).toBe(false);expect(vault.isUnlocked()).toBe(false);
});
it("a failed Native pattern refresh completes the actual shared progress token instead of leaving other screens loading",async()=>{
 await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SessionProvider><Probe/><InsightsScreen/></SessionProvider></ThemeProvider>);});await vi.waitFor(()=>expect(state()).toEqual({auth:"loggedIn",unlocked:true,loading:false}));await vi.waitFor(()=>expect(root!.root.findAllByType(TouchableOpacity).some(n=>n.props.accessibilityLabel==="Mute this pattern — The actual native idle observation")).toBe(true));const nativeFetch=globalThis.fetch;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{if(new URL(String(args[0])).pathname.endsWith("/insights")){const response=new Response(JSON.stringify({code:"service_unavailable",detail:"The actual Native pattern provider refused the refresh"}),{status:500});Object.defineProperty(response,"url",{value:String(args[0])});return response;}return nativeFetch(...args);});await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});expect(root!.root.findAllByType(Text).some(n=>n.props.accessibilityRole==="alert")).toBe(true);expect(state()).toEqual({auth:"loggedIn",unlocked:true,loading:false});
});
it("a Native refresh without an authenticated owner resolves with the session repair notice and finishes its progress token",async()=>{
 await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><SessionProvider><Probe/><InsightsScreen/></SessionProvider></ThemeProvider>);});await vi.waitFor(()=>expect(state()).toEqual({auth:"loggedIn",unlocked:true,loading:false}));await api.clearSession();
 await act(async()=>{await expect(root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh()).resolves.toBeUndefined();});
 const alert=root!.root.findAllByType(Text).find(n=>n.props.accessibilityRole==="alert");expect(alert).toBeDefined();expect(alert!.props.children).toBe("Session damaged");expect(state().loading).toBe(false);
});

it("a retired Native progress-owner delivery releases the network slot for the replacement pattern view", async () => {
  const scene = (show: boolean) => <ThemeProvider><SessionProvider><Probe/>{show && <InsightsScreen/>}</SessionProvider></ThemeProvider>;
  await act(async () => { root = ReactTestRenderer.create(scene(true)); });
  const hasObservation = () => root!.root.findAllByType(TouchableOpacity).some((node) => node.props.accessibilityLabel === "Mute this pattern — The actual native idle observation");
  await vi.waitFor(() => expect(hasObservation()).toBe(true));
  await vi.waitFor(() => expect(state().loading).toBe(false));
  let ownerEntered = false, held = false, releaseOwner!: () => void, releaseNetwork!: () => void;
  const ownerGate = new Promise<void>((resolve) => { releaseOwner = resolve; });
  const networkGate = new Promise<void>((resolve) => { releaseNetwork = resolve; });
  const get = secureStore.getItem.bind(secureStore), nativeFetch = globalThis.fetch;
  let replacementMounted = false, retiredNetworkSlot = false;
  vi.spyOn(secureStore, "getItem").mockImplementation(async (slot) => {
    const value = await get(slot);
    if (!held && slot === "@mindpattern/user_id") { held = true; ownerEntered = true; await ownerGate; }
    return value;
  });
  vi.stubGlobal("fetch", async (...args: Parameters<typeof fetch>) => {
    if (new URL(String(args[0])).pathname.endsWith("/insights")) {
      if (!replacementMounted) {
        retiredNetworkSlot = true;
        await networkGate;
        retiredNetworkSlot = false;
      } else if (retiredNetworkSlot) await networkGate;
    }
    return nativeFetch(...args);
  });
  let retired: Promise<void> | undefined;
  await act(async () => { retired = root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh(); });
  await vi.waitFor(() => expect(ownerEntered).toBe(true));
  await act(async () => root!.update(scene(false)));
  releaseOwner();
  await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
  replacementMounted = true;
  try {
    await act(async () => root!.update(scene(true)));
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 0)); });
    expect(hasObservation()).toBe(true);
    expect(state().loading).toBe(false);
  } finally {
    releaseOwner(); releaseNetwork();
    await act(async () => { await retired; });
  }
});
