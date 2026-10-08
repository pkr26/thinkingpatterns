/** Public exported screen + installed RN scheduler disposal contract.
 * Native Timing device transport is supplied; this is not an Android JVM test. */
/** Actual HTTP, credential storage, AES and encrypted feedback receipt. */
import React from "react";
import ReactTestRenderer,{act as reactAct} from "react-test-renderer";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {Text,TouchableOpacity,ScrollView,View} from "react-native";
import {api} from "../../src/api/client";
import {secureStore} from "../../src/secureStore";
import {engine} from "../../src/crypto/engine";
import {InsightsScreen,localWeekday} from "../../src/screens/InsightsScreen";
import {ThemeProvider} from "../../src/theme";
import {vault} from "../../src/vault";
import {encrypt,decrypt,buildAad} from "../../src/crypto/envelope";
import {INSIGHTS_PAYLOAD_VERSION} from "../../src/crypto/journalCrypto";
import {installLocalDataKey,__resetLocalKeyLifecycleForTests} from "../../src/localWriteGuard";
import {recordPatternMute} from "../../src/questionFeedback";
import {resetAnalysisGenerationMirrors} from "../../src/stateSeqGuard";
import {runTestControl} from "../helpers/testControl";
import {accountStorageKey} from "../../src/accountStorage";
import {recordMood,localDateISO} from "../../src/moodLog";
import storage from "../helpers/storageMock";
import {t as tr} from "../../src/strings";
import {publicSurface} from "../helpers/publicSurface";
import {assertPublicSurface} from "../helpers/publicSurfaceOracle";
import {installedNativeTiming} from "../helpers/nativeTiming";
const USER="a".repeat(32), KEY=Buffer.alloc(32,21), NEXT=Buffer.alloc(32,22);
const session={applyActiveDays:()=>{},beginProgressRead:async()=>({owner:USER,generation:0,request:0}),finishProgressRead:()=>{},unlockDays:30,touchActivity:()=>{}};
vi.mock("../../src/store",async original=>({...await original<typeof import("../../src/store")>(),useSession:()=>session}));
let root:ReturnType<typeof ReactTestRenderer.create>|undefined;
let surfaceStage = 0;
async function act<T>(operation: () => T | Promise<T>) {
 await reactAct(operation);
 if (root) assertPublicSurface(publicSurface(root), ++surfaceStage);
}
let serverPatterns:unknown[];
let serverPlain:string|undefined,serverResponse:string|undefined;
let release:()=>void=()=>{};
const flush=async()=>act(async()=>{await new Promise(resolve=>setTimeout(resolve,0));});
function words(){const flat=(v:unknown):string=>Array.isArray(v)?v.map(flat).join(""):typeof v==="string"||typeof v==="number"?String(v):"";return root!.root.findAllByType(Text).map(node=>flat(node.props.children)).join(" ");}
async function mount(check=true){await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><InsightsScreen/></ThemeProvider>);});await flush();if(check)await vi.waitFor(()=>expect(words()).toContain("Native original topic"));}
async function pressMute(){const node=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel === "Mute this pattern — Native original topic");expect(node).toBeDefined();await act(async()=>{node!.props.onPress();});}
beforeEach(async()=>{
 surfaceStage=0;vi.restoreAllMocks();storage.__reset();runTestControl(__resetLocalKeyLifecycleForTests);runTestControl(resetAnalysisGenerationMirrors);vault.lock();await api.setSession("native insights bearer",USER,"alice");vault.unlock({masterKey:Buffer.alloc(32,3),authKey:Buffer.alloc(32,4),dataKey:Buffer.from(KEY)},USER);installLocalDataKey(USER,vault.get().dataKey);
 serverPlain=undefined;serverResponse=undefined;serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:{pattern_pid:"topic:native-original"}}];
 vi.stubGlobal("fetch",async(url:string)=>{const path=new URL(url).pathname;if(!path.endsWith("/insights"))throw new Error("Unexpected Native insights path "+path);const blob=encrypt(KEY,Buffer.from(serverPlain ?? JSON.stringify({v:INSIGHTS_PAYLOAD_VERSION,stats:{patterns:serverPatterns}})),buildAad("insights",USER,"patterns")).toString("base64");const response=new Response(serverResponse ?? JSON.stringify({phase:"insight",active_days:40,days_remaining:0,blob}),{status:200});Object.defineProperty(response,"url",{value:url});return response;});
});
afterEach(async()=>{vi.unstubAllGlobals();vi.restoreAllMocks();vi.useRealTimers();release();await flush();if(root){await act(async()=>root!.unmount());root=undefined;}vi.restoreAllMocks();vi.unstubAllGlobals();vault.lock();await api.clearSession();});

it("an unmounted pattern view releases its pending Native scheduler work",async()=>{
 await mount();const device=installedNativeTiming();vi.stubGlobal("setTimeout",device.setTimeout);vi.stubGlobal("clearTimeout",device.clearTimeout);
 await pressMute();expect(words()).toContain("Muted — hidden here now");expect(device.hasActiveTimersInRange(3000)).toBe(true);
 await act(async()=>root!.unmount());root=undefined;
 expect(device.hasActiveTimersInRange(3000)).toBe(false);
 await act(async()=>device.advance(2601));
 const raw=(await storage.getItem(accountStorageKey.feedback(USER)))!;expect(JSON.parse(decrypt(KEY,Buffer.from(raw,"base64"),buildAad("feedback-local",USER)).toString("utf8"))).toEqual([expect.objectContaining({pid:"topic:native-original",mute:true})]);
 vi.unstubAllGlobals();
});

it("the installed Native scheduler releases its ordinary one-shot work after delivering the receipt",()=>{
 const device=installedNativeTiming();let receipt="pending";device.setTimeout(()=>{receipt="delivered";},2600);
 expect(device.hasActiveTimersInRange(3000)).toBe(true);device.advance(2601);expect(receipt).toBe("delivered");expect(device.hasActiveTimersInRange(3000)).toBe(false);
});
