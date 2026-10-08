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
import {nativeGrantedPress} from "../helpers/nativePressability";
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
afterEach(async()=>{vi.restoreAllMocks();vi.useRealTimers();release();await flush();if(root){await act(async()=>root!.unmount());root=undefined;}vi.restoreAllMocks();vi.unstubAllGlobals();vault.lock();await api.clearSession();});
it("an acknowledged Native mute queues a decryptable receipt under the current account key",async()=>{
 await mount();await pressMute();await flush();expect(words()).not.toContain("Native original topic");expect(words()).toContain("Show muted (1)");const raw=await storage.getItem(accountStorageKey.feedback(USER));expect(raw).toBeTruthy();const values=JSON.parse(decrypt(KEY,Buffer.from(raw!,"base64"),buildAad("feedback-local",USER)).toString("utf8"));expect(values).toEqual([expect.objectContaining({pid:"topic:native-original",mute:true})]);
});
it("a pending Native mute cannot append its old pattern into a replacement vault's feedback receipt",async()=>{
 await mount();let entered=false,first=true;const pending=new Promise<void>(resolve=>{release=resolve;});const get=storage.getItem.bind(storage);vi.spyOn(storage,"getItem").mockImplementation(async name=>{const result=await get(name);if(name==="@mindpattern/user_id"&&first){first=false;entered=true;await pending;}return result;});
 await pressMute();await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{vault.unlock({masterKey:Buffer.alloc(32,5),authKey:Buffer.alloc(32,6),dataKey:Buffer.from(NEXT)},USER);installLocalDataKey(USER,vault.get().dataKey);root!.unmount();root=undefined;});await recordPatternMute(NEXT,USER,"topic:replacement",false);const before=await get(accountStorageKey.feedback(USER));release();await flush();expect(await get(accountStorageKey.feedback(USER))).toBe(before);expect(vault.get().dataKey).toEqual(NEXT);
});
it.each(["confidence","occurrences","detail"] as const)("authenticated Native JSON exponent overflow in %s cannot become measured evidence",async field=>{
 const raw=field==="detail"?'"detail":{"sample_days":1e999,"p_value":1e999}':JSON.stringify(field)+':1e999';serverPlain='{"v":'+INSIGHTS_PAYLOAD_VERSION+',"stats":{"patterns":[{"kind":"topic","label":"Native original topic",'+raw+'}]}}';await mount();expect(words()).toContain("0 mentions · observation strength 0%");expect(words()).not.toContain("Infinity");if(field==="detail"){const why=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Why am I seeing this? Evidence for this pattern")!;await act(async()=>why.props.onPress());expect(words()).not.toContain("Based on");expect(words()).not.toContain("Technical details");}
});
it.each(["is_new","sensitive","presence","muted"])("an authenticated Native %s string cannot become a boolean disclosure flag",async field=>{
 serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:{[field]:"yes",pattern_pid:"topic:native-original",direction:{bad:"shape"},sample_days:{bad:17},first_seen:17}}];await mount();expect(words()).not.toContain(" · new");expect(words()).not.toContain("A difficult thought");expect(words()).not.toContain("Show muted");expect(words()).toContain("7 mentions · observation strength 40%");
});
it("an actual Native HTTP exponent overflow cannot become a remaining-day progress count",async()=>{serverResponse='{"phase":"baseline","active_days":3,"days_remaining":1e999}';await mount(false);expect(words()).toContain("Keep writing");expect(words()).not.toContain("Infinity");expect(words()).toContain("0 days");});
it("an authenticated Native null detail remains a readable ordinary card",async()=>{serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:null}];await mount();expect(words()).toContain("7 mentions · observation strength 40%");});
it("accepted finite Native statistics cannot overflow their percentage formatter",async()=>{serverPatterns=[{kind:"temporal",label:"Native original topic",occurrences:7,confidence:.4,detail:{day:"Tuesday",day_fraction:1e308,base_rate:1e308}}];await mount();const why=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Why am I seeing this? Evidence for this pattern")!;await act(async()=>why.props.onPress());expect(words()).not.toContain("Infinity");expect(words()).toContain("—%");});
it("an authenticated Native muted sensitive card keeps its support pointer without quoting the label",async()=>{
 serverPatterns=[{kind:"rumination",label:"Native original topic",occurrences:7,confidence:.4,detail:{sensitive:true,muted:true,pattern_pid:"sensitive-native"}}];await mount(false);
 expect(words()).not.toContain("Native original topic");expect(words()).not.toContain("Show muted");expect(words()).not.toContain("7 mentions");expect(words()).toContain("Support resources");
 expect(root!.root.findAllByType(TouchableOpacity).some(node=>node.props.accessibilityLabel?.startsWith("Mute this pattern"))).toBe(false);
});
it("a Native ordinary server mute stays hidden until its disclosure opens and unmute queues an actual false receipt",async()=>{
 serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:{muted:true,pattern_pid:"topic:native-original"}}];await mount(false);expect(words()).not.toContain("Native original topic");expect(words()).toContain("Show muted (1)");
 const disclosure=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel?.startsWith("Show muted patterns"))!;expect(disclosure).toBeDefined();await act(async()=>disclosure.props.onPress());expect(words()).toContain("Native original topic");
 const unmute=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel?.startsWith("Unmute this pattern"))!;expect(unmute).toBeDefined();await act(async()=>unmute.props.onPress());await flush();
 const raw=await storage.getItem(accountStorageKey.feedback(USER));expect(raw).toBeTruthy();expect(JSON.parse(decrypt(KEY,Buffer.from(raw!,"base64"),buildAad("feedback-local",USER)).toString("utf8"))).toEqual([expect.objectContaining({pid:"topic:native-original",mute:false})]);
});
it("an authenticated Native card without a stable identifier cannot create a false mute receipt",async()=>{
 serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4}];await mount();await pressMute();await flush();expect(words()).not.toContain("Muted — hidden here now");expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();
});
it("an authenticated Native unknown kind renders the honest generic kind and default observed state",async()=>{
 serverPatterns=[{kind:"future_native_kind",label:"Native original topic",occurrences:7,confidence:.4,detail:{pattern_state:"future_native_state",pattern_pid:"future:native"}}];await mount();expect(words()).toContain("PATTERN");expect(words()).toContain("observed");
});
it("an actual Native unknown response phase publishes a retryable error before rendering the authenticated cards",async()=>{
 serverResponse=JSON.stringify({phase:"future_native_phase",active_days:40,days_remaining:0});await mount(false);expect(words()).not.toContain("Native original topic");expect(words()).toContain("phase");expect(root!.root.findAllByType(TouchableOpacity).some(node=>node.props.accessibilityLabel==="Try loading your patterns again")).toBe(true);
});
it.each(["baseline","insight"] as const)("the Native %s phase shows its independently stored three-day mood trend",async phase=>{
 const now=new Date(),yesterday=new Date(now),before=new Date(now);yesterday.setDate(now.getDate()-1);before.setDate(now.getDate()-2);for(const[date,value]of [[localDateISO(before),-.8],[localDateISO(yesterday),0],[localDateISO(now),.8]] as const)await recordMood(KEY,USER,date,value);if(phase==="baseline")serverResponse=JSON.stringify({phase,active_days:3,days_remaining:27});await mount(phase==="insight");await vi.waitFor(()=>expect(words()).toContain("Your mood, this month"));const image=root!.root.findAllByType(View).find(n=>n.props.accessibilityRole==="image")!;expect(image).toBeDefined();expect(image.props.accessibilityLabel).toContain("3 days");expect(image.props.accessibilityLabel).toContain("rising");expect(image.props.accessibilityLabel).toContain("positive");const heights=image.findAllByType(View).flatMap(n=>Array.isArray(n.props.style)?n.props.style:[n.props.style]).filter(s=>s?.height!=null).map(s=>s.height);expect(heights).toContain(16);expect(heights).toContain(3);
});
it("an older Native response cannot overwrite a newer pull-to-refresh pattern list",async()=>{
 await mount();let entered=false,finish!:()=>void;const gate=new Promise<void>(resolve=>{finish=resolve;release=resolve;});const fetchNative=globalThis.fetch;let first=true;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{const response=await fetchNative(...args);if(first){first=false;entered=true;await gate;}return response;});const refresh=()=>root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();let old:Promise<void>|undefined;await act(async()=>{old=refresh();});await vi.waitFor(()=>expect(entered).toBe(true));serverPatterns=[{kind:"topic",label:"The newer Native topic owns this view",occurrences:9,confidence:.7,detail:{pattern_pid:"topic:newer-native"}}];await act(async()=>{await refresh();});await vi.waitFor(()=>expect(words()).toContain("The newer Native topic owns this view"));finish();await act(async()=>old);await flush();expect(words()).toContain("The newer Native topic owns this view");expect(words()).not.toContain("Native original topic");
});
it("mixed Native muted and sensitive cards disclose only the single ordinary muted pattern",async()=>{
 serverPatterns=[{kind:"topic",label:"Native visible ordinary",occurrences:2,confidence:.4,detail:{pattern_pid:"visible"}},{kind:"topic",label:"Native hidden ordinary",occurrences:3,confidence:.5,detail:{muted:true,pattern_pid:"hidden"}},{kind:"rumination",label:"Native protected sensitive label",occurrences:4,confidence:.6,detail:{sensitive:true,muted:true,pattern_pid:"protected"}},{kind:"rumination",label:"Native other sensitive label",occurrences:5,confidence:.7,detail:{sensitive:true,pattern_pid:"other-protected"}}];await mount(false);expect(words()).toContain("Show muted (1)");expect(words()).toContain("Native visible ordinary");expect(words()).not.toContain("Native hidden ordinary");expect(words()).not.toContain("Native protected sensitive label");expect(words()).not.toContain("Native other sensitive label");const disclosure=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel?.startsWith("Show muted patterns"))!;await act(async()=>disclosure.props.onPress());expect(words()).toContain("Hide muted (1)");expect(words().split("Native hidden ordinary")).toHaveLength(2);expect(words().split("Native visible ordinary")).toHaveLength(2);expect(words()).not.toContain("Native protected sensitive label");expect(words()).not.toContain("Native other sensitive label");expect(root!.root.findAllByType(TouchableOpacity).filter(n=>n.props.accessibilityLabel?.startsWith("Unmute this pattern"))).toHaveLength(1);
});
it("a newer Native mute confirmation remains visible until its own expiration",async()=>{
 serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:{pattern_pid:"topic:native-original"}},{kind:"topic",label:"Native second topic",occurrences:8,confidence:.5,detail:{pattern_pid:"topic:native-second"}}];await mount();vi.useFakeTimers();await pressMute();await act(async()=>vi.advanceTimersByTimeAsync(1500));const second=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Mute this pattern — Native second topic")!;await act(async()=>second.props.onPress());await act(async()=>vi.advanceTimersByTimeAsync(1101));expect(words()).toContain("Muted — hidden here now");await act(async()=>vi.advanceTimersByTimeAsync(1500));expect(words()).not.toContain("Muted — hidden here now");vi.useRealTimers();
});
it("a Native overlong pattern id stores only its bounded authenticated feedback identifier",async()=>{
 const pid="native-bounded-id-"+"x".repeat(180);serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:{pattern_pid:pid}}];await mount();await pressMute();await flush();const raw=(await storage.getItem(accountStorageKey.feedback(USER)))!;expect(JSON.parse(decrypt(KEY,Buffer.from(raw,"base64"),buildAad("feedback-local",USER)).toString("utf8"))).toMatchObject([{pid:pid.slice(0,128),mute:true}]);
});
it("bounded Native future-kind metadata preserves the currently open evidence panel across a refresh",async()=>{
 const pattern={kind:"x".repeat(64)+"a",label:"Native original topic",occurrences:7,confidence:.4,detail:{pattern_pid:"bounded-future",sample_days:9}};serverPatterns=[pattern];await mount();const why=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Why am I seeing this? Evidence for this pattern")!;await act(async()=>why.props.onPress());expect(words()).toContain("Evidence window");serverPatterns=[{...pattern,kind:"x".repeat(64)+"b"}];await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await flush();expect(words()).toContain("Evidence window");
});

it.each(["baseline","insight"] as const)("an authenticated Native other-language analysis in %s shows only its phase-appropriate disclosure",async phase=>{
 const payload={v:INSIGHTS_PAYLOAD_VERSION,stats:{language:"other",patterns:serverPatterns}};serverResponse=JSON.stringify({phase,active_days:40,days_remaining:0,blob:encrypt(KEY,Buffer.from(JSON.stringify(payload)),buildAad("insights",USER,"patterns")).toString("base64")});await mount(false);if(phase==="insight"){expect(words()).toContain(tr("insights.languageTitle"));expect(words()).toContain(tr("insights.languageBody"));}else{expect(words()).not.toContain(tr("insights.languageTitle"));expect(words()).not.toContain(tr("insights.languageBody"));}
});
it("two actual encrypted Native mood days cannot be presented as a month trend",async()=>{
 const now=new Date(),before=new Date(now);before.setDate(now.getDate()-1);await recordMood(KEY,USER,localDateISO(before),-.8);await recordMood(KEY,USER,localDateISO(now),.8);await mount();expect(root!.root.findAllByType(View).some(n=>n.props.accessibilityRole==="image")).toBe(false);expect(words()).not.toContain(tr("insights.moodMonth"));
});
it("an actual encrypted three-day Native mood trend includes its local-only receipt explanation",async()=>{
 const now=new Date();for(let index=0;index<3;index++){const date=new Date(now);date.setDate(now.getDate()-index);await recordMood(KEY,USER,localDateISO(date),index/2);}await mount();await vi.waitFor(()=>expect(words()).toContain(tr("insights.moodMonthNote")));expect(root!.root.findAllByType(View).some(n=>n.props.accessibilityRole==="image")).toBe(true);
});
it("an authenticated Native empty pattern result presents the exact evidence explanation without a false muted section",async()=>{
 serverPatterns=[];await mount(false);expect(words()).toContain(tr("insights.nothingSolidTitle"));expect(words()).toContain(tr("insights.noEvidenceBody"));expect(words()).not.toContain(tr("insights.allMutedBody"));expect(root!.root.findAllByType(TouchableOpacity).some(n=>n.props.accessibilityLabel?.startsWith("Show muted patterns"))).toBe(false);
});
it("an authenticated legacy Native baseline blob cannot expose an insight-phase muted pattern section",async()=>{
 const payload={v:INSIGHTS_PAYLOAD_VERSION,stats:{patterns:[{kind:"topic",label:"The old Native muted pattern",occurrences:3,confidence:.5,detail:{muted:true,pattern_pid:"old-muted"}}]}};serverResponse=JSON.stringify({phase:"baseline",active_days:3,days_remaining:27,blob:encrypt(KEY,Buffer.from(JSON.stringify(payload)),buildAad("insights",USER,"patterns")).toString("base64")});await mount(false);expect(words()).toContain("Keep writing");expect(words()).not.toContain("The old Native muted pattern");expect(root!.root.findAllByType(TouchableOpacity).some(n=>n.props.accessibilityLabel?.startsWith("Show muted patterns"))).toBe(false);
});
it("an authenticated Native silence count without an observation count renders its explicit unknown placeholder",async()=>{
 serverPatterns=[{kind:"absence",label:"Native original topic",occurrences:7,confidence:.4,detail:{silences:3}}];await mount();const why=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Why am I seeing this? Evidence for this pattern")!;await act(async()=>why.props.onPress());expect(words()).toContain(tr("insights.ev.silentDaysValue",{silences:3,observed:"?",rate:tr("insights.ev.unavailable")}));
});
it.each(["sleep_quality","tag"])("authenticated Native %s metadata cannot turn a non-temporal card into a weekday claim",async source=>{
 serverPatterns=[{kind:"topic",label:"Native original topic",occurrences:7,confidence:.4,detail:source==="sleep_quality"?{channel:source,day:"Monday"}:{source,day:"Monday"}}];await mount();expect(words()).toContain(tr("insights.desc.topicSteady",{label:"Native original topic",share:""}));expect(words()).not.toContain(source==="sleep_quality"?tr("insights.desc.sleepTemporal",{day:"Monday"}):tr("insights.desc.tagTemporal",{label:"Native original topic",day:"Monday"}));
});
it("a finite Native Intl weekday refusal preserves the raw authenticated weekday in the public evidence",async()=>{
 serverPatterns=[{kind:"temporal",label:"Native original topic",occurrences:7,confidence:.4,detail:{day:"Monday",day_fraction:.5,base_rate:.2}}];vi.spyOn(Date.prototype,"toLocaleDateString").mockImplementation(()=>{throw new Error("Native Intl weekday locale data is unavailable");});expect(localWeekday("Monday")).toBe("Monday");await mount();const why=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Why am I seeing this? Evidence for this pattern")!;await act(async()=>why.props.onPress());expect(words()).toContain(tr("insights.ev.concentrationValue",{share:"50",day:"Monday",baseline:"20%"}));
});
it("multiple Native muted rows keep their actual labels and public unmute actions after removal and reorder",async()=>{
 const card=(label:string,pid:string)=>({kind:"topic",label,occurrences:3,confidence:.5,detail:{muted:true,pattern_pid:pid}});serverPatterns=[card("Native muted first","first"),card("Native muted middle","middle"),card("Native muted last","last")];await mount(false);const open=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel?.startsWith("Show muted patterns"))!;await act(async()=>open.props.onPress());const middle=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Unmute this pattern — Native muted middle")!;await act(async()=>middle.props.onPress());await flush();serverPatterns=[card("Native muted last","last"),card("Native muted first","first")];await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await flush();expect(words().split("Native muted first")).toHaveLength(2);expect(words().split("Native muted last")).toHaveLength(2);expect(words()).not.toContain("Native muted middle");const last=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Unmute this pattern — Native muted last")!;await act(async()=>last.props.onPress());await flush();const raw=(await storage.getItem(accountStorageKey.feedback(USER)))!;expect(JSON.parse(decrypt(KEY,Buffer.from(raw,"base64"),buildAad("feedback-local",USER)).toString("utf8"))).toMatchObject([{pid:"middle",mute:false},{pid:"last",mute:false}]);
});

it("overlapping Native pattern loads cannot persist a retired generation after the view unmounts",async()=>{
 await mount();await secureStore.setItem(accountStorageKey.stateSequence(USER),"9");const nativeFetch=globalThis.fetch;let reached=0,oldEntered=false,newEntered=false,releaseOld!:()=>void,releaseNew!:()=>void;const oldGate=new Promise<void>(resolve=>{releaseOld=resolve;}),newGate=new Promise<void>(resolve=>{releaseNew=resolve;});release=()=>{releaseOld();releaseNew();};vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{const response=await nativeFetch(...args);const ordinal=++reached;if(ordinal<=2){const read=response.json.bind(response);response.json=async()=>{const answer=await read();if(ordinal===1){oldEntered=true;await oldGate;}else{newEntered=true;await newGate;}return answer;};}return response;});
 const payload={v:INSIGHTS_PAYLOAD_VERSION,state_seq:900,stats:{patterns:[{kind:"topic",label:"The retired generation must never be pinned",occurrences:4,confidence:.5}]}};serverResponse=JSON.stringify({phase:"insight",active_days:40,days_remaining:0,state_seq:900,blob:encrypt(KEY,Buffer.from(JSON.stringify(payload)),buildAad("insights",USER,"patterns")).toString("base64")});let old:Promise<void>|undefined,fresh:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(oldEntered).toBe(true));await act(async()=>{fresh=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(newEntered).toBe(true));await act(async()=>root!.unmount());root=undefined;releaseOld();await act(async()=>old);expect(await secureStore.getItem(accountStorageKey.stateSequence(USER))).toBe("9");releaseNew();await act(async()=>fresh);expect(await secureStore.getItem(accountStorageKey.stateSequence(USER))).toBe("9");
});

it("a Native mute admitted under retired credentials cannot append after a same-key account reauthentication",async()=>{
 await mount();let entered=false,first=true;const pending=new Promise<void>(resolve=>{release=resolve;});const get=storage.getItem.bind(storage);vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(first&&slot==="@mindpattern/user_id"){first=false;entered=true;await pending;}return value;});await pressMute();await vi.waitFor(()=>expect(entered).toBe(true));await api.setSession("newly authenticated Native bearer",USER,"alice");expect(vault.get().dataKey).toEqual(KEY);release();await flush();expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();expect(words()).toContain("Muted — hidden here now");
});
it("an authentic stale Native account-id receipt cannot attribute the current pattern to another owner",async()=>{
 await mount();const other="b".repeat(32);await secureStore.setItem("@mindpattern/user_id",other);await pressMute();await flush();expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();expect(await storage.getItem(accountStorageKey.feedback(other))).toBeNull();expect(words()).toContain("Muted — hidden here now");
});

it("newly published Native credentials cannot attribute the retained old-vault pattern to the new account",async()=>{
 await mount();const other="b".repeat(32);await api.setSession("the newly published OTHER Native bearer",other,"bob");expect(vault.ownerUserId()).toBe(USER);expect(vault.get().dataKey).toEqual(KEY);await pressMute();await flush();expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();expect(await storage.getItem(accountStorageKey.feedback(other))).toBeNull();
});

it.each([1,3])("a superseded Native load at account-read checkpoint %s cannot hide current cards or pin its retired generation",async checkpoint=>{
 await mount();const responseFor=(label:string,phase:string,seq:number)=>JSON.stringify({phase,active_days:phase==="baseline"?4:40,days_remaining:phase==="baseline"?26:0,state_seq:seq,blob:encrypt(KEY,Buffer.from(JSON.stringify({v:INSIGHTS_PAYLOAD_VERSION,state_seq:seq,stats:{patterns:[{kind:"topic",label,occurrences:7,confidence:.4}]}})),buildAad("insights",USER,"patterns")).toString("base64")});serverResponse=responseFor("The retired Native response", "baseline",900);let entered=false,finish!:()=>void,count=0,stopped=false;const gate=new Promise<void>(resolve=>{finish=resolve;release=resolve;});const get=secureStore.getItem.bind(secureStore);vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(!stopped&&slot==="@mindpattern/user_id"&&++count===checkpoint){stopped=true;entered=true;await gate;}return value;});let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));serverResponse=responseFor("The current Native checkpoint view", "insight",11);await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(words()).toContain("The current Native checkpoint view"));expect(await get(accountStorageKey.stateSequence(USER))).toBe("11");finish();await act(async()=>old);await flush();expect(words()).toContain("The current Native checkpoint view");expect(await get(accountStorageKey.stateSequence(USER))).toBe("11");
});

it.each(["read","write"] as const)("overlapping accepted Native generations cannot lower the durable high-water receipt after a held old %s",async boundary=>{
 await mount();await secureStore.setItem(accountStorageKey.stateSequence(USER),"9");const responseFor=(label:string,seq:number)=>JSON.stringify({phase:"insight",active_days:40,days_remaining:0,state_seq:seq,blob:encrypt(KEY,Buffer.from(JSON.stringify({v:INSIGHTS_PAYLOAD_VERSION,state_seq:seq,stats:{patterns:[{kind:"topic",label,occurrences:7,confidence:.4}]}})),buildAad("insights",USER,"patterns")).toString("base64")});let entered=false,finish!:()=>void,first=true;const gate=new Promise<void>(resolve=>{finish=resolve;release=resolve;});const get=secureStore.getItem.bind(secureStore),set=secureStore.setItem.bind(secureStore);if(boundary==="read")vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(first&&slot===accountStorageKey.stateSequence(USER)){first=false;entered=true;await gate;}return value;});else vi.spyOn(secureStore,"setItem").mockImplementation(async(slot,value)=>{if(first&&slot===accountStorageKey.stateSequence(USER)){first=false;entered=true;await gate;}return set(slot,value);});serverResponse=responseFor("The superseded Native generation eleven",11);let old:Promise<void>|undefined,fresh:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));serverResponse=responseFor("The latest Native generation twelve",12);await act(async()=>{fresh=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await flush();finish();await act(async()=>{await old;await fresh;});await flush();expect(words()).toContain("The latest Native generation twelve");expect(words()).not.toContain("The superseded Native generation eleven");expect(await get(accountStorageKey.stateSequence(USER))).toBe("12");runTestControl(resetAnalysisGenerationMirrors);serverResponse=responseFor("The replayed Native generation eleven",11);await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await flush();expect(words()).not.toContain("The replayed Native generation eleven");expect(words()).toContain("freshness check");
});
it("a superseded Native high-water completion cannot publish its cards while the newer generation's physical receipt is still held",async()=>{
 await mount();await secureStore.setItem(accountStorageKey.stateSequence(USER),"9");const responseFor=(label:string,seq:number)=>JSON.stringify({phase:"insight",active_days:40,days_remaining:0,state_seq:seq,blob:encrypt(KEY,Buffer.from(JSON.stringify({v:INSIGHTS_PAYLOAD_VERSION,state_seq:seq,stats:{patterns:[{kind:"topic",label,occurrences:7,confidence:.4}]}})),buildAad("insights",USER,"patterns")).toString("base64")});let oldEntered=false,newEntered=false,releaseOld!:()=>void,releaseNew!:()=>void;const oldGate=new Promise<void>(r=>{releaseOld=r;}),newGate=new Promise<void>(r=>{releaseNew=r;});release=()=>{releaseOld();releaseNew();};const set=secureStore.setItem.bind(secureStore);vi.spyOn(secureStore,"setItem").mockImplementation(async(slot,value)=>{if(slot===accountStorageKey.stateSequence(USER)&&value==="11"){oldEntered=true;await oldGate;}if(slot===accountStorageKey.stateSequence(USER)&&value==="12"){newEntered=true;await newGate;}return set(slot,value);});serverResponse=responseFor("The superseded Native eleven must stay private",11);let old:Promise<void>|undefined,fresh:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(oldEntered).toBe(true));serverResponse=responseFor("The accepted Native twelve owns this view",12);await act(async()=>{fresh=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});releaseOld();await vi.waitFor(()=>expect(newEntered).toBe(true));await flush();expect(words()).toContain("Native original topic");expect(words()).not.toContain("The superseded Native eleven must stay private");expect(root!.root.findByType(ScrollView).props.refreshControl.props.refreshing).toBe(true);releaseNew();await act(async()=>{await old;await fresh;});expect(words()).toContain("The accepted Native twelve owns this view");
});
it("a missing Native owner at the mood checkpoint cannot turn a locked baseline vault into a visible load failure",async()=>{
 await mount();serverResponse=JSON.stringify({phase:"baseline",active_days:3,days_remaining:27});const get=secureStore.getItem.bind(secureStore);let reads=0;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{if(slot==="@mindpattern/user_id"&&++reads===3){await secureStore.removeItem(slot);vault.lock();}return get(slot);});await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});expect(words()).toContain("Keep writing");expect(root!.root.findAllByType(Text).some(n=>n.props.accessibilityRole==="alert")).toBe(false);
});
it("a replacement Native pattern view can acknowledge and expire a mute after the old view retires",async()=>{
 await mount();vi.useFakeTimers();await pressMute();await act(async()=>root!.unmount());root=undefined;
 serverPatterns=[{kind:"topic",label:"The replacement Native timer observation",occurrences:5,confidence:.6,detail:{pattern_pid:"replacement:native-timer"}}];await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><InsightsScreen/></ThemeProvider>);});await act(async()=>vi.advanceTimersByTimeAsync(0));expect(words()).toContain("The replacement Native timer observation");const mute=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Mute this pattern — The replacement Native timer observation")!;expect(mute).toBeDefined();await act(async()=>mute.props.onPress());expect(words()).toContain("Muted — hidden here now");await act(async()=>vi.advanceTimersByTimeAsync(2601));expect(words()).not.toContain("Muted — hidden here now");const raw=(await storage.getItem(accountStorageKey.feedback(USER)))!;expect(JSON.parse(decrypt(KEY,Buffer.from(raw,"base64"),buildAad("feedback-local",USER)).toString("utf8"))).toEqual(expect.arrayContaining([expect.objectContaining({pid:"replacement:native-timer",mute:true})]));
});

it("an actual Native mute lookup cannot append feedback after its view retires under the same account and physical key", async () => {
  await mount();
  let entered = false;
  let held = false;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  const get = storage.getItem.bind(storage);
  vi.spyOn(storage, "getItem").mockImplementation(async (slot) => {
    const value = await get(slot);
    if (!held && slot === "@mindpattern/user_id") {
      held = true;
      entered = true;
      await pending;
    }
    return value;
  });
  await pressMute();
  await vi.waitFor(() => expect(entered).toBe(true));
  const admittedKey = vault.get().dataKey;
  await act(async () => { root!.unmount(); root = undefined; });
  expect(vault.ownerUserId()).toBe(USER);
  expect(vault.get().dataKey).toBe(admittedKey);
  release();
  await flush();
  expect(await storage.getItem(accountStorageKey.feedback(USER))).toBeNull();
});

it("a Native mute already waiting for its encrypted feedback read cannot commit after the view retires", async () => {
  await recordPatternMute(KEY, USER, "topic:prior-acknowledged", true);
  await mount();
  const slot = accountStorageKey.feedback(USER);
  const get = storage.getItem.bind(storage);
  const before = await get(slot);
  let entered = false;
  let held = false;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const value = await get(name);
    if (!held && name === slot) {
      held = true;
      entered = true;
      await pending;
    }
    return value;
  });
  await pressMute();
  await vi.waitFor(() => expect(entered).toBe(true));
  await act(async () => { root!.unmount(); root = undefined; });
  release();
  await flush();
  expect(await get(slot)).toBe(before);
});

it("a same-account Native zero-valued adopted key cannot receive a mute captured under the prior physical key", async () => {
  await mount();
  const captured = vault.get().dataKey;
  const get = storage.getItem.bind(storage);
  let entered = false, first = true;
  const pending = new Promise<void>((resolve) => { release = resolve; });
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const value = await get(name);
    if (first && name === "@mindpattern/user_id") { first = false; entered = true; await pending; }
    return value;
  });
  await pressMute();
  await vi.waitFor(() => expect(entered).toBe(true));
  const next = Buffer.alloc(32);
  await act(async () => {
    vault.unlock({masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: next}, USER);
    installLocalDataKey(USER, next);
  });
  expect(captured.every((value) => value === 0)).toBe(true);
  expect(vault.get().dataKey).toBe(next);
  release();
  await flush();
  expect(await get(accountStorageKey.feedback(USER))).toBeNull();
});

it.each(["streak", "moods"] as const)("a superseded Native %s completion stays unpublished while the current local read is unavailable", async (kind) => {
  const now = new Date();
  for (let index = 0; index < 3; index++) {
    const day = new Date(now); day.setDate(now.getDate() - (2 - index));
    await recordMood(KEY, USER, localDateISO(day), index === 0 ? -.8 : .8);
  }
  const slot = accountStorageKey.moodLog(USER), get = storage.getItem.bind(storage);
  let ordinal = 0, oldEntered = false, nextEntered = false;
  let releaseOld!: () => void, releaseNext!: () => void;
  const oldGate = new Promise<void>((resolve) => { releaseOld = resolve; });
  const nextGate = new Promise<void>((resolve) => { releaseNext = resolve; });
  release = () => { releaseOld(); releaseNext(); };
  const oldRead = kind === "streak" ? 1 : 2;
  vi.spyOn(storage, "getItem").mockImplementation(async (name) => {
    const value = await get(name);
    if (name === slot) {
      ordinal++;
      if (ordinal === oldRead) { oldEntered = true; await oldGate; }
      else if (ordinal === oldRead + 1) { nextEntered = true; await nextGate; }
    }
    return value;
  });
  await mount();
  await vi.waitFor(() => expect(oldEntered).toBe(true));
  serverResponse = JSON.stringify({phase: "baseline", active_days: 11, days_remaining: 19});
  await act(async () => { await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh(); });
  expect(words()).toContain("19 days");
  releaseOld();
  await flush();
  await vi.waitFor(() => expect(nextEntered).toBe(true));
  if (kind === "moods") expect(root!.root.findAllByType(View).some((node) => node.props.accessibilityRole === "image")).toBe(false);
  else expect(words()).not.toContain(tr("common.streakMany", {count: 3}));
  releaseNext();
  await flush();
});

it("the first Native pattern frame does not start an unrequested pull-to-refresh spinner",async()=>{
 let firstFrame:unknown;function Parent(){React.useLayoutEffect(()=>{firstFrame=root!.root.findByType(ScrollView).props.refreshControl.props.refreshing;},[]);return <InsightsScreen/>;}await act(async()=>{root=ReactTestRenderer.create(<ThemeProvider><Parent/></ThemeProvider>);});await flush();expect(firstFrame).toBe(false);expect(words()).toContain("Native original topic");
});

it("a superseded Native mood-owner delivery cannot reserve the local log reader needed by the current trend",async()=>{
 await mount();const uid=secureStore.getItem.bind(secureStore),get=storage.getItem.bind(storage),slot=accountStorageKey.moodLog(USER);let ordinal=0,ownerEntered=false,releaseOwner!:()=>void,releaseMood!:()=>void;const ownerGate=new Promise<void>(resolve=>{releaseOwner=resolve;}),moodGate=new Promise<void>(resolve=>{releaseMood=resolve;});release=()=>{releaseOwner();releaseMood();};vi.spyOn(secureStore,"getItem").mockImplementation(async name=>{const value=await uid(name);if(name==="@mindpattern/user_id"&&++ordinal===3){ownerEntered=true;await ownerGate;}return value;});let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(ownerEntered).toBe(true));serverResponse=JSON.stringify({phase:"baseline",active_days:11,days_remaining:19});await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await flush();const now=new Date();for(let i=0;i<3;i++){const day=new Date(now);day.setDate(now.getDate()-i);await recordMood(KEY,USER,localDateISO(day),i/2);}let first=true;vi.spyOn(storage,"getItem").mockImplementation(async name=>{const value=await get(name);if(first&&name===slot){first=false;await moodGate;}return value;});releaseOwner();await flush();await old;first=false;await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await flush();try{expect(root!.root.findAllByType(View).some(n=>n.props.accessibilityRole==="image")).toBe(true);}finally{releaseMood();await flush();}
});

it("a superseded Native decrypt-owner delivery cannot raise the generation mark above the accepted replacement response",async()=>{
 let sequence=9;vi.stubGlobal("fetch",async(url:string)=>{const payload={v:INSIGHTS_PAYLOAD_VERSION,state_seq:sequence,stats:{patterns:[{kind:"topic",label:"Native generation "+sequence,occurrences:7,confidence:.4,detail:{pattern_pid:"topic:generation"}}]}};const blob=encrypt(KEY,Buffer.from(JSON.stringify(payload)),buildAad("insights",USER,"patterns")).toString("base64"),response=new Response(JSON.stringify({phase:"insight",active_days:40,days_remaining:0,state_seq:sequence,blob}));Object.defineProperty(response,"url",{value:url});return response;});await mount(false);expect(words()).toContain("Native generation 9");const get=secureStore.getItem.bind(secureStore);let ordinal=0,entered=false;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(slot==="@mindpattern/user_id"&&++ordinal===4){entered=true;await gate;}return value;});sequence=900;let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));sequence=11;await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});expect(words()).toContain("Native generation 11");release();await flush();await old;await act(async()=>{await root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});expect(root!.root.findAllByType(Text).some(n=>n.props.accessibilityRole==="alert")).toBe(false);expect(words()).toContain("Native generation 11");
});

it("a missing actual Native owner at the encrypted blob boundary produces the session repair result",async()=>{
 const get=secureStore.getItem.bind(secureStore);let ordinal=0;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{if(slot==="@mindpattern/user_id"&&++ordinal===4){await secureStore.removeItem(slot);return null;}return get(slot);});await mount(false);expect(words()).not.toContain("Native original topic");expect(root!.root.findAllByType(Text).some(n=>n.props.accessibilityRole==="alert")).toBe(true);expect(await get("@mindpattern/user_id")).toBeNull();
});
it("an admitted Native mute delivered in the restricted-vault frame cannot reserve credentials needed by the replacement view",async()=>{
 await mount();const button=root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel==="Mute this pattern — Native original topic")!,gesture=nativeGrantedPress(button.props),get=secureStore.getItem.bind(secureStore);let replacement=false,retiredSlot=false;const gate=new Promise<void>(resolve=>{release=resolve;});vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{if(slot==="@mindpattern/user_id"){if(!replacement){retiredSlot=true;await gate;retiredSlot=false;}else if(retiredSlot)await gate;}return get(slot);});try{await act(async()=>{vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32,8),dataKey:Buffer.from(KEY)},USER,{writeSuspended:true});gesture.release();root!.unmount();root=undefined;});gesture.dispose();replacement=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32,9),dataKey:Buffer.from(KEY)},USER);installLocalDataKey(USER,vault.get().dataKey);await mount(false);expect(words()).toContain("Native original topic");}finally{gesture.dispose();release();await flush();}
});
it.each(["summary", "owner"] as const)("a retired Native %s delivery cannot occupy the credential slot needed by the replacement pattern view",async stage=>{
 await mount();const get=secureStore.getItem.bind(secureStore),nativeFetch=globalThis.fetch;let entered=false,ordinal=0,armed=false,replacement=false,retiredSlot=false,releaseDelivery!:()=>void,releaseCredentials!:()=>void;const deliveryGate=new Promise<void>(resolve=>{releaseDelivery=resolve;}),credentialGate=new Promise<void>(resolve=>{releaseCredentials=resolve;});release=()=>{releaseDelivery();releaseCredentials();};vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(slot==="@mindpattern/user_id"){ordinal++;if(stage==="owner"&&ordinal===2){entered=true;await deliveryGate;}else if(armed){if(!replacement){retiredSlot=true;await credentialGate;retiredSlot=false;}else if(retiredSlot)await credentialGate;}}return value;});if(stage==="summary"){let first=true;vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{const response=await nativeFetch(...args);if(first){first=false;const read=response.json.bind(response);response.json=async()=>{const value=await read();entered=true;await deliveryGate;return value;};}return response;});}let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{root!.unmount();root=undefined;});armed=true;releaseDelivery();await flush();replacement=true;try{await mount(false);expect(words()).toContain("Native original topic");}finally{releaseCredentials();await old;await flush();}
});
it("an authenticated foreign-AAD carrier remains an authentication failure when the Native account receipt disappears",async()=>{
 const blob=encrypt(KEY,Buffer.from(JSON.stringify({v:INSIGHTS_PAYLOAD_VERSION,stats:{patterns:serverPatterns}})),buildAad("insights","Stryker was here!","patterns")).toString("base64");serverResponse=JSON.stringify({phase:"insight",active_days:40,days_remaining:0,blob});const get=secureStore.getItem.bind(secureStore);let ordinal=0;vi.spyOn(secureStore,"getItem").mockImplementation(async slot=>{if(slot==="@mindpattern/user_id"&&++ordinal===4){await secureStore.removeItem(slot);return null;}return get(slot);});await mount(false);const alert=root!.root.findAllByType(Text).find(n=>n.props.accessibilityRole==="alert")!;expect(alert).toBeDefined();expect(alert.props.children).toBe("blob failed authentication");expect(words()).not.toContain("Native original topic");
});

it.each(["origin","bearer","owner","username"] as const)("a Native summary request retired at its %s provider boundary does not occupy the replacement view's credential lane",async stage=>{
 await mount();const get=secureStore.getItem.bind(secureStore),read=storage.getItem.bind(storage);let entered=false,retired=false,replacement=false,first=true,releaseHeld!:()=>void,releaseBlocked!:()=>void,lane:Promise<unknown>=Promise.resolve();const held=new Promise<void>(resolve=>{releaseHeld=resolve;}),blocked=new Promise<void>(resolve=>{releaseBlocked=resolve;});release=()=>{releaseHeld();releaseBlocked();};const target=stage==="bearer"?"@mindpattern/token":stage==="owner"?"@mindpattern/user_id":"@mindpattern/username";
 vi.spyOn(secureStore,"getItem").mockImplementation(name=>{const obsolete=retired&&!replacement,pending=lane.then(async()=>{const value=await get(name);if(stage!=="origin"&&first&&name===target){first=false;entered=true;await held;}else if(obsolete)await blocked;return value;});lane=pending.then(()=>{},()=>{});return pending;});
 if(stage==="origin")vi.spyOn(storage,"getItem").mockImplementation(async name=>{const raw=await read(name);if(first&&name==="@mindpattern/base_url"){first=false;entered=true;await held;}return raw;});let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{root!.unmount();root=undefined;});retired=true;releaseHeld();await new Promise(resolve=>setTimeout(resolve,0));replacement=true;
 try{await mount(false);expect(words()).toContain("Native original topic");}finally{releaseBlocked();await old;await flush();}
});

it.each(Array.from({length:32},(_,i)=>i+1))("a Native summary body retired at %i completion handoffs leaves the replacement pattern's owner-read lane available",async hops=>{
 await mount();const get=secureStore.getItem.bind(secureStore),nativeFetch=globalThis.fetch;let first=true,retired=false,replacement=false,entered=false,releaseBody!:()=>void,releaseBlocked!:()=>void,lane:Promise<unknown>=Promise.resolve();const body=new Promise<void>(resolve=>{releaseBody=resolve;}),blocked=new Promise<void>(resolve=>{releaseBlocked=resolve;});release=()=>{releaseBody();releaseBlocked();};vi.spyOn(secureStore,"getItem").mockImplementation(name=>{const obsolete=retired&&!replacement,pending=lane.then(async()=>{const value=await get(name);if(obsolete)await blocked;return value;});lane=pending.then(()=>{},()=>{});return pending;});vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{const response=await nativeFetch(...args);if(first){first=false;const read=response.json.bind(response);response.json=async()=>{const value=await read();entered=true;await body;let remaining=hops;const step=()=>{if(--remaining>0)queueMicrotask(step);else{retired=true;reactAct(()=>{root!.unmount();root=undefined;});}};queueMicrotask(step);return value;};}return response;});let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));releaseBody();await new Promise(resolve=>setTimeout(resolve,0));expect(retired).toBe(true);replacement=true;try{await mount(false);expect(words()).toContain("Native original topic");}finally{releaseBlocked();await old;await flush();}
});

it("a retired Native payload account receipt leaves cipher capacity for the current pattern view",async()=>{
 await mount();const get=secureStore.getItem.bind(secureStore);let ordinal=0,entered=false,releaseHeld!:()=>void;const held=new Promise<void>(resolve=>{releaseHeld=resolve;});release=releaseHeld;vi.spyOn(secureStore,"getItem").mockImplementation(async name=>{const raw=await get(name);if(name==="@mindpattern/user_id"&&++ordinal===4){entered=true;await held;}return raw;});let old:Promise<void>|undefined;await act(async()=>{old=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{root!.unmount();root=undefined;});const contexts:Array<WeakRef<object>>=[],borrow=<T extends object>(create:()=>T):T=>{if(contexts.filter(ref=>ref.deref()!==undefined).length>=9)throw new Error("The Native cipher contexts remain occupied until host collection");const value=create();contexts.push(new WeakRef(value));return value;},decipher=engine.createDecipheriv.bind(engine),hash=engine.createHash.bind(engine);vi.spyOn(engine,"createDecipheriv").mockImplementation((...args)=>borrow(()=>decipher(...args)));vi.spyOn(engine,"createHash").mockImplementation((...args)=>borrow(()=>hash(...args)));releaseHeld();await old;await flush();try{await mount(false);expect(words()).toContain("Native original topic");}finally{releaseHeld();await flush();}
});
it.each(Array.from({length:32},(_,i)=>i+1))("a Native freshness receipt at %i completion handoffs preserves the accepted pattern while a new refresh is pending",async hops=>{
 await mount();serverPatterns=[{kind:"topic",label:"The earlier Native receipt candidate",occurrences:7,confidence:.4}];const get=secureStore.getItem.bind(secureStore),nativeFetch=globalThis.fetch;let first=true,entered=false,newEntered=false,second=false,releaseOld!:()=>void,releaseFresh!:()=>void;const oldGate=new Promise<void>(resolve=>{releaseOld=resolve;}),freshGate=new Promise<void>(resolve=>{releaseFresh=resolve;});release=()=>{releaseOld();releaseFresh();};let newer:Promise<void>=Promise.resolve();vi.spyOn(secureStore,"getItem").mockImplementation(async name=>{const raw=await get(name);if(first&&name===accountStorageKey.stateSequence(USER)){first=false;entered=true;await oldGate;let remaining=hops;const step=()=>{if(--remaining>0)queueMicrotask(step);else{second=true;serverPatterns=[{kind:"topic",label:"The current Native refresh candidate",occurrences:7,confidence:.4}];reactAct(()=>{newer=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});}};queueMicrotask(step);}return raw;});vi.stubGlobal("fetch",async(...args:Parameters<typeof fetch>)=>{const response=await nativeFetch(...args);if(second){const read=response.json.bind(response);response.json=async()=>{const value=await read();newEntered=true;await freshGate;return value;};}return response;});let older:Promise<void>|undefined;await act(async()=>{older=root!.root.findByType(ScrollView).props.refreshControl.props.onRefresh();});await vi.waitFor(()=>expect(entered).toBe(true));releaseOld();await vi.waitFor(()=>expect(newEntered).toBe(true));await flush();expect(words()).not.toContain("The current Native refresh candidate");releaseFresh();await act(async()=>{await Promise.all([older,newer]);});await flush();expect(words()).toContain("The current Native refresh candidate");
});
