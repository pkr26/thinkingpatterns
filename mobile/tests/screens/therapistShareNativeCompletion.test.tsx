import crypto from "node:crypto";
import React from "react";
import ReactTestRenderer,{act} from "react-test-renderer";
import {afterEach,beforeEach,describe,expect,it,vi} from "vitest";
import {Alert,Switch,Text,TextInput,TouchableOpacity} from "react-native";
import {TherapistShareScreen} from "../../src/screens/TherapistShareScreen";
import {api,getBaseUrl,setBaseUrl,SHARING_DISCLOSURE_VERSION} from "../../src/api/client";
import {vault} from "../../src/vault";
import {SessionProvider,useSession} from "../../src/store";
import {emitAppState} from "../helpers/rnMock";
import {setSecureStoreBackend} from "../../src/secureStore";
import {__resetLocalKeyLifecycleForTests} from "../../src/localWriteGuard";
import {runTestControl} from "../helpers/testControl";
import {nativeGrantedPress} from "../helpers/nativePressability";
import {engine} from "../helpers/nodeEngine";
import storage from "../helpers/storageMock";

(globalThis as {IS_REACT_ACT_ENVIRONMENT?:boolean}).IS_REACT_ACT_ENVIRONMENT=true;
const USER="c".repeat(32),THERAPIST="d".repeat(32),CONSENT="a".repeat(32),SECOND="b".repeat(32),DATA=Buffer.alloc(32,7),SALT=Buffer.alloc(16,5),PASSWORD="Native therapist password 2026!";
const master=crypto.pbkdf2Sync(PASSWORD,SALT,600000,32,"sha256"),AUTH=Buffer.from(crypto.hkdfSync("sha256",master,Buffer.alloc(32),"mindpattern/auth/v1",32));
const therapist=crypto.generateKeyPairSync("ec",{namedCurve:"prime256v1"}),PUBLIC=therapist.publicKey.export({format:"der",type:"spki"}).toString("base64");
const fingerprint=crypto.createHash("sha256").update(Buffer.from(PUBLIC,"base64")).digest("hex").slice(0,16);
type Consent={id:string;therapist_id:string;display_name:string;username:string;status:string;granted_at:string;revoked_at:string|null;share_voice?:boolean};
const consent=(id=CONSENT,name="Dr. Native",voice=false):Consent=>({id,therapist_id:THERAPIST,display_name:name,username:"native-therapist",status:"active",granted_at:"2026-09-01T10:00:00Z",revoked_at:null,share_voice:voice});
let root:ReturnType<typeof ReactTestRenderer.create>|undefined,consents:Consent[],policy:boolean,disclosure:string,sas:unknown,lookupStatus:number,actionStatus:number,actionError:unknown,serverData:Buffer,metaUnavailable:boolean;
let serverFingerprint:unknown,pairingGeneration:number,livePairingCodes:Set<string>;
let nativeGate:((path:string,method:string)=>Promise<void>)|undefined;
let nativeCompletion:((path:string)=>void)|undefined;
const nav={navigate:vi.fn(),goBack:vi.fn()};
function response(url:string,value:unknown,status=200){const result=new Response(JSON.stringify(value),{status,headers:{"Content-Type":"application/json","X-Consents-Revision":"1"}});Object.defineProperty(result,"url",{value:url});const read=result.json.bind(result);result.json=async()=>{const answer=await read();nativeCompletion?.(new URL(url).pathname);return answer;};return result;}
function unwrap(body:Record<string,any>):Buffer{
 const ephemeral=Buffer.from(body.ephemeral_pub,"base64"),shared=crypto.diffieHellman({privateKey:therapist.privateKey,publicKey:crypto.createPublicKey({key:ephemeral,format:"der",type:"spki"})});
 const kek=Buffer.from(crypto.hkdfSync("sha256",shared,Buffer.concat([ephemeral,Buffer.from(PUBLIC,"base64")]),"mindpattern/wrap/v1",32)),blob=Buffer.from(body.wrapped_key,"base64"),cipher=crypto.createDecipheriv("aes-256-gcm",kek,blob.subarray(0,12));
 cipher.setAAD(Buffer.from(JSON.stringify(["consent-wrap",USER,THERAPIST])));cipher.setAuthTag(blob.subarray(-16));return Buffer.concat([cipher.update(blob.subarray(12,-16)),cipher.final()]);
}
function installServer(){vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{
 const path=new URL(url).pathname,method=init.method??"GET",body=init.body?JSON.parse(init.body as string):{};
 await nativeGate?.(path,method);
 if(path.endsWith("/meta")){if(metaUnavailable){metaUnavailable=false;return response(url,{detail:"Native policy provider unavailable"},503);}return response(url,{sharing_available:policy,sharing_disclosure_version:disclosure});}
 if(path.endsWith("/pairing/lookup"))return lookupStatus===200&&livePairingCodes.has(body.code)?response(url,{therapist_id:THERAPIST,display_name:"Dr. Native",wrap_pub_key:PUBLIC,wrap_key_fingerprint:serverFingerprint,sas}):response(url,{detail:"Native pairing provider unavailable"},lookupStatus===200?404:lookupStatus);
 if(path.endsWith("/consents")&&method==="GET")return response(url,consents);
 if(new Headers(init.headers).get("X-Account-Verifier")!==AUTH.toString("base64"))return response(url,{detail:"Password proof refused",code:"verification_failed"},403);
 if(actionStatus!==200)return response(url,actionError,actionStatus);
 if(path.endsWith("/consents")&&method==="POST"){
  if(!livePairingCodes.has(body.code))return response(url,{detail:"Pairing code not found"},404);
  if(consents.some(item=>item.id===CONSENT&&item.status==="active"))return response(url,{detail:"Pairing code already consumed"},409);
  expect(livePairingCodes.has(body.code)).toBe(true);livePairingCodes.delete(body.code);expect(body.disclosure).toBe(SHARING_DISCLOSURE_VERSION);expect(unwrap(body)).toEqual(serverData);
  consents=[consent(),...consents.filter(item=>item.id!==CONSENT)];return response(url,consents[0]);
 }
 const id=path.split("/").at(method==="PUT"?-2:-1);
 if(path.endsWith("/share-voice")){consents=consents.map(item=>item.id===id?{...item,share_voice:body.enabled}:item);return response(url,consents.find(item=>item.id===id));}
 if(method==="DELETE"){consents=consents.map(item=>item.id===id?{...item,status:"revoked",revoked_at:"2026-10-05T10:00:00Z"}:item);return response(url,{});}
 return response(url,{});
});}
async function flush(){await act(async()=>{for(let turn=0;turn<80;turn++)await Promise.resolve();});}
function NativeProtectedRoute(){const session=useSession();return session.authStatus==="loggedIn"&&session.unlocked?<TherapistShareScreen navigation={nav}/>:<Text>Native sharing route locked</Text>;}
async function mount(protectedRoute=false){await act(async()=>{root=ReactTestRenderer.create(protectedRoute?<SessionProvider><NativeProtectedRoute/></SessionProvider>:<TherapistShareScreen navigation={nav}/>);});await flush();}
function text(){return root!.root.findAllByType(Text).map(node=>node.props.children).flat(Infinity).filter(value=>typeof value==="string"||typeof value==="number").join(" ");}
function button(label:string){const result=root!.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel===label);if(!result)throw Error(`missing Native action ${label}: ${text()}`);return result;}
function nativeTap(node:ReactTestRenderer.ReactTestInstance){let result:unknown;const touch=nativeGrantedPress({disabled:node.props.disabled,onPress:()=>{result=node.props.onPress();}});touch.release();touch.dispose();return result;}
async function press(label:string){const node=button(label);expect(node.props.disabled).not.toBe(true);await act(async()=>{void nativeTap(node);});await flush();}
async function fill(placeholder:string,value:string){const node=root!.root.findAllByType(TextInput).find(node=>node.props.placeholder===placeholder);if(!node)throw Error(`missing Native field ${placeholder}`);await act(async()=>node.props.onChangeText(value));}
async function choose(label:string){const choices=Alert.alert.mock.lastCall?.[2]as Array<{text:string;onPress?:()=>void}>|undefined,choice=choices?.find(item=>item.text===label);if(!choice)throw Error(`missing Native dialog choice ${label}`);await act(async()=>choice.onPress?.());await flush();}
async function lookup(){const currentCode=`${7+pairingGeneration++}X2KQM4N`;await fill("e.g. 7X2KQM4N",`  ${currentCode}  `);await press("Find my therapist");}
async function grantCard(){await lookup();await press("Share with Dr. Native");await choose("Fingerprints match — continue");}
async function confirm(){await fill("password",PASSWORD);const confirm=button("Confirm with password");await act(async()=>{await nativeTap(confirm);});await flush();}
beforeEach(async()=>{
 vi.useRealTimers();vi.restoreAllMocks();storage.__reset();runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();
 await api.setSession("Native sharing bearer",USER,"native-patient");await api.cacheSalt("native-patient",SALT.toString("base64"));vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(AUTH),dataKey:Buffer.from(DATA)},USER);
 consents=[];policy=true;disclosure=SHARING_DISCLOSURE_VERSION;sas="123 456";serverFingerprint=fingerprint;pairingGeneration=0;livePairingCodes=new Set(["7X2KQM4N","8X2KQM4N","9X2KQM4N"]);lookupStatus=200;actionStatus=200;actionError={detail:"Native sharing provider unavailable"};serverData=DATA;metaUnavailable=false;nativeGate=undefined;nativeCompletion=undefined;Alert.alert.mockClear();nav.navigate.mockClear();nav.goBack.mockClear();installServer();
});
afterEach(async()=>{if(root){await act(async()=>{root!.unmount();root=undefined;});}vi.restoreAllMocks();vault.lock();await api.clearSession();vi.unstubAllGlobals();});
describe("Native therapist sharing completion",()=>{
 it("a same-origin Native server save releases a retired lookup so the still-mounted route can retry",async()=>{
  await mount();let entered=false,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async path=>{if(path.endsWith("/pairing/lookup")){entered=true;await held;}};await lookup();expect(entered).toBe(true);await setBaseUrl(await getBaseUrl());release();await flush();expect(text()).not.toContain("Looking up");nativeGate=undefined;await press("Find my therapist");expect(text()).toContain("Dr. Native");
 });
 it("a same-origin Native server save clears the retired password proof and keeps confirmation retryable",async()=>{
  await mount();await grantCard();await fill("password",PASSWORD);const derive=engine.pbkdf2;let entered=false,release!:()=>void;vi.spyOn(engine,"pbkdf2").mockImplementation((password,salt,cost,length,digest,done)=>derive(password,salt,cost,length,digest,(error,value)=>{entered=true;release=()=>done(error,value);}));let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(entered).toBe(true));Alert.alert.mockClear();await setBaseUrl(await getBaseUrl());release();await pending;await flush();expect(Alert.alert.mock.calls).toEqual([]);expect(text()).not.toContain("Verifying");expect(root!.root.findAllByType(TextInput).find(node=>node.props.placeholder==="password")!.props.value).toBe("");expect(consents).toEqual([]);vi.restoreAllMocks();await confirm();expect(consents).toEqual([consent()]);
 });

 it("a retained Native password tap behind an actual background lock cannot dispatch a sharing request",async()=>{
  await mount(true);await grantCard();await fill("password",PASSWORD);const node=button("Confirm with password");let pending:unknown;const touch=nativeGrantedPress({disabled:node.props.disabled,onPress:()=>{pending=node.props.onPress();}});Alert.alert.mockClear();await act(async()=>{emitAppState("background");touch.configure({disabled:button("Confirm with password").props.disabled,onPress:()=>{pending=button("Confirm with password").props.onPress();}});touch.release();touch.dispose();await pending;});await flush();expect(Alert.alert.mock.calls).toEqual([]);expect(consents).toEqual([]);expect(text()).toContain("Native sharing route locked");
 });

 it("a numeric Native fingerprint cannot masquerade as a string mismatch",async()=>{
  serverFingerprint=1000000000000000;await mount();await lookup();expect(root!.root.findAllByType(Text).filter(node=>node.props.accessibilityRole==="alert")).toEqual([]);
 });
 it("a current Native password card stays hidden when an earlier completed grant refresh disables sharing",async()=>{
  await mount();await grantCard();let release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async path=>{if(path.endsWith("/meta"))await held;};await confirm();await grantCard();expect(root!.root.findAllByType(TextInput).filter(node=>node.props.placeholder==="password")).toHaveLength(1);policy=false;release();await flush();expect(text()).toContain("Therapist sharing unavailable");expect(root!.root.findAllByType(TextInput).filter(node=>node.props.placeholder==="password")).toEqual([]);
 });
 it("a late Native pairing answer stays hidden after the previous grant refresh disables sharing",async()=>{
  await mount();await grantCard();let releaseMeta!:()=>void,releaseLookup!:()=>void;const metaHeld=new Promise<void>(resolve=>releaseMeta=resolve),lookupHeld=new Promise<void>(resolve=>releaseLookup=resolve);nativeGate=async path=>{if(path.endsWith("/meta"))await metaHeld;if(path.endsWith("/pairing/lookup"))await lookupHeld;};await confirm();await lookup();policy=false;releaseMeta();await flush();expect(text()).toContain("Therapist sharing unavailable");releaseLookup();await flush();expect(text()).not.toContain("Dr. Native");
 });
 it("a Native policy outage after a stale disclosure hides the obsolete terms card",async()=>{
  disclosure="v4";consents=[consent()];await mount();expect(text()).toContain("Sharing terms updated");await press("Stop sharing");await choose("Stop sharing");metaUnavailable=true;await confirm();expect(text()).toContain("Can’t reach the server");expect(text()).not.toContain("Sharing terms updated");
 });

 it.each(["route","session"]as const)("a failed Native lookup retired by its %s cannot publish a global alert",async retirement=>{
  await mount();let entered=false,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async path=>{if(path.endsWith("/pairing/lookup")){entered=true;await held;}};lookupStatus=503;
  await lookup();expect(entered).toBe(true);if(retirement==="route")await act(async()=>{root!.unmount();root=undefined;});else await api.setSession("replacement Native same-account bearer",USER,"native-patient");Alert.alert.mockClear();release();await flush();expect(Alert.alert.mock.calls).toEqual([]);
 });
 for(const phase of [1,2])it(`Native pairing body phase ${phase} cannot publish an old lookup into a replacement session`,async()=>{
  await mount();let adoption:Promise<void>|undefined;nativeCompletion=path=>{if(path.endsWith("/pairing/lookup")){let delivery=Promise.resolve();for(let turn=0;turn<phase;turn++)delivery=delivery.then(()=>undefined);void delivery.then(()=>{adoption=api.setSession("replacement Native pairing bearer",USER,"native-patient");});}};
  await lookup();await adoption;await flush();expect(text()).not.toContain("Dr. Native");expect(Alert.alert.mock.calls).toEqual([]);
 });
 it("the first Native sharing commit contains checking rather than a transient unreachable error",async()=>{
  let first:string|undefined;function FirstCommit(){React.useLayoutEffect(()=>{first=text();},[]);return <TherapistShareScreen navigation={nav}/>;}
  await act(async()=>{root=ReactTestRenderer.create(<FirstCommit/>);});expect(first).not.toContain("Can’t reach the server");await flush();
 });
 it("a Native disclosure conflict refreshes the stale sharing policy before another grant is offered",async()=>{
  await mount();await grantCard();disclosure="v4";actionStatus=409;actionError={detail:"Sharing terms changed",code:"disclosure_outdated"};await confirm();expect(text()).toContain("Sharing terms updated");expect(text()).not.toContain("Add your therapist");
 });
 it.each([401,403])("Native verified action status %i retains its complete user guidance",async status=>{
  consents=[consent()];await mount();await press("Stop sharing");await choose("Stop sharing");actionStatus=status;actionError={detail:"Proof refused",...(status===403?{code:"verification_failed"}:{})};await confirm();expect(Alert.alert.mock.lastCall?.[1]).not.toBe("");expect(Alert.alert.mock.lastCall?.[0]).toBe(status===401?"Session expired":"That password didn't match");
 });
 it.each(["disabled","failed"]as const)("a Native %s policy clears the old recipient before an independently admitted second completion reloads",async policyResult=>{
  consents=[consent(CONSENT,"Dr. Native"),consent(SECOND,"Dr. Other")];await mount();let metaCount=0,releaseFirstMeta!:()=>void,releaseSecondAction!:()=>void,releaseList!:()=>void;const firstMeta=new Promise<void>(resolve=>releaseFirstMeta=resolve),secondAction=new Promise<void>(resolve=>releaseSecondAction=resolve),list=new Promise<void>(resolve=>releaseList=resolve);let firstAction=true,actionEntered=false,listEntered=false;
  nativeGate=async(path,method)=>{if(path.endsWith("/meta")&&++metaCount===1)await firstMeta;if(method==="DELETE"){if(firstAction)firstAction=false;else{actionEntered=true;await secondAction;}}if(path.endsWith("/consents")&&method==="GET"&&metaCount>1){listEntered=true;await list;}};
  await press("Stop sharing");await choose("Stop sharing");await confirm();const secondStop=root!.root.findAllByType(TouchableOpacity).filter(node=>node.props.accessibilityLabel==="Stop sharing")[1]!;await act(async()=>{nativeTap(secondStop);});await choose("Stop sharing");await fill("password",PASSWORD);let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(actionEntered).toBe(true));if(policyResult==="disabled")policy=false;else metaUnavailable=true;releaseFirstMeta();await flush();expect(text()).toContain(policyResult==="disabled"?"Therapist sharing unavailable":"Can’t reach the server");policy=true;releaseSecondAction();await pending;await flush();expect(listEntered).toBe(true);expect(text()).not.toContain("Dr. Other");expect(text()).not.toContain("Stopped");expect(text()).not.toContain("Couldn’t load who you are sharing with");releaseList();await flush();expect(text()).toContain("Dr. Other");
 });
 it("an independently admitted Native completion hides a previous outage while its new availability check is pending",async()=>{
  consents=[consent(CONSENT,"Dr. Native"),consent(SECOND,"Dr. Other")];await mount();let metaCount=0,releaseFirstMeta!:()=>void,releaseSecondMeta!:()=>void,releaseSecondAction!:()=>void;const firstMeta=new Promise<void>(resolve=>releaseFirstMeta=resolve),secondMeta=new Promise<void>(resolve=>releaseSecondMeta=resolve),secondAction=new Promise<void>(resolve=>releaseSecondAction=resolve);let firstAction=true,actionEntered=false;
  nativeGate=async(path,method)=>{if(path.endsWith("/meta")){if(++metaCount===1)await firstMeta;else await secondMeta;}if(method==="DELETE"){if(firstAction)firstAction=false;else{actionEntered=true;await secondAction;}}};await press("Stop sharing");await choose("Stop sharing");await confirm();const secondStop=root!.root.findAllByType(TouchableOpacity).filter(node=>node.props.accessibilityLabel==="Stop sharing")[1]!;await act(async()=>{nativeTap(secondStop);});await choose("Stop sharing");await fill("password",PASSWORD);let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(actionEntered).toBe(true));metaUnavailable=true;releaseFirstMeta();await flush();expect(text()).toContain("Can’t reach the server");releaseSecondAction();await pending;await flush();expect(text()).not.toContain("Can’t reach the server");releaseSecondMeta();await flush();
 });
 it("a Native JSON array cannot become an attested string match code",async()=>{sas=["123 456"];await mount();await lookup();await press("Share with Dr. Native");expect(Alert.alert.mock.lastCall?.[1]).not.toContain("Match code:");});
 it("two Native lookup releases in the same uncommitted host frame cannot publish a second answer",async()=>{
  await mount();await fill("e.g. 7X2KQM4N","7X2KQM4N");const node=button("Find my therapist");let first=true,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async path=>{if(path.endsWith("/pairing/lookup")&&first){first=false;await held;}};await act(async()=>{nativeTap(node);nativeTap(node);});await flush();expect(text()).not.toContain("Dr. Native");release();await flush();expect(text()).toContain("Dr. Native");
 });
 it("Native consent details delivered after sharing is disabled stay hidden",async()=>{
  consents=[consent(SECOND,"Dr. Other")];let first=true,release!:()=>void,entered=false;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async(path,method)=>{if(path.endsWith("/consents")&&method==="GET"&&first){first=false;entered=true;await held;}};
  await mount();expect(entered).toBe(true);await grantCard();policy=false;await confirm();expect(text()).toContain("Therapist sharing unavailable");release();await flush();expect(text()).not.toContain("Dr. Native");expect(text()).not.toContain("Stopped");
 });
 it("a failed Native consent answer delivered after sharing is disabled cannot show a list failure",async()=>{
  let first=true,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async(path,method)=>{if(path.endsWith("/consents")&&method==="GET"&&first){first=false;await held;throw new TypeError("Native consent provider unavailable");}};
  await mount();await grantCard();policy=false;await confirm();release();await flush();expect(text()).toContain("Therapist sharing unavailable");expect(text()).not.toContain("Couldn’t load who you are sharing with");
 });
 it("Native policy becoming unavailable after a grant hides its old recipient list",async()=>{
  consents=[consent(SECOND,"Dr. Other")];await mount();await grantCard();policy=false;await confirm();expect(text()).toContain("Therapist sharing unavailable");expect(text()).not.toContain("Dr. Other");
 });
 it.each(["grant","revoke","voice"]as const)("Native %s completion cannot publish after the sharing route closes",async action=>{
  if(action!=="grant")consents=[consent()];await mount();
  if(action==="grant")await grantCard();else if(action==="revoke"){await press("Stop sharing");await choose("Stop sharing");}else{await act(async()=>root!.root.findByType(Switch).props.onValueChange(true));await choose("Continue");}
  await fill("password",PASSWORD);let entered=false,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async(path,method)=>{if(path.includes("/consents")&&method!=="GET"){entered=true;await held;}};
  let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(entered).toBe(true));
  await act(async()=>{root!.unmount();root=undefined;});Alert.alert.mockClear();metaUnavailable=true;release();await pending;await flush();expect(Alert.alert.mock.calls).toEqual([]);nativeGate=undefined;await mount();expect(text()).toContain("Can’t reach the server");
 });
 it("a Native sharing refusal cannot publish a retired password dialog",async()=>{
  await mount();await grantCard();await fill("password",PASSWORD);actionStatus=503;let entered=false,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async(path,method)=>{if(path.endsWith("/consents")&&method==="POST"){entered=true;await held;}};
  let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{root!.unmount();root=undefined;});Alert.alert.mockClear();release();await pending;await flush();expect(Alert.alert.mock.calls).toEqual([]);
 });
 it("Native password derivation completion cannot revoke after its route was canceled",async()=>{
  consents=[consent()];await mount();await press("Stop sharing");await choose("Stop sharing");await fill("password",PASSWORD);
  const derive=engine.pbkdf2;let entered=false,release!:()=>void;vi.spyOn(engine,"pbkdf2").mockImplementation((password,salt,cost,length,digest,done)=>derive(password,salt,cost,length,digest,(error,value)=>{entered=true;release=()=>done(error,value);}));
  let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(entered).toBe(true));await act(async()=>{root!.unmount();root=undefined;});release();await pending;await flush();expect((await api.listConsents())[0]?.status).toBe("active");
 });
 it("Native availability checking never flashes an unreachable policy before its first answer",async()=>{
  let release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async path=>{if(path.endsWith("/meta"))await held;};await mount();expect(text()).not.toContain("Can’t reach the server");release();await flush();expect(text()).toContain("Add your therapist");
 });
 it("a delayed first Native consent page never claims a failure or stopped sharing",async()=>{
  let release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async(path,method)=>{if(path.endsWith("/consents")&&method==="GET")await held;};await mount();expect(text()).not.toContain("Stopped");expect(text()).not.toContain("Couldn’t load who you are sharing with");release();await flush();expect(text()).toContain("You are not sharing with anyone");
 });
 it("a Native grant clears its password before another recipient confirmation opens",async()=>{
  await mount();await grantCard();await confirm();await grantCard();expect(root!.root.findAllByType(TextInput).find(node=>node.props.placeholder==="password")!.props.value).toBe("");
 });
 it("Native password-card cancellation clears its value before the next confirmation",async()=>{
  await mount();await grantCard();await fill("password",PASSWORD);await press("Cancel");await press("Share with Dr. Native");await choose("Fingerprints match — continue");expect(root!.root.findAllByType(TextInput).find(node=>node.props.placeholder==="password")!.props.value).toBe("");
 });
 it("a missing Native account id preserves its specific local failure before wrapping",async()=>{
  await mount();await grantCard();await storage.removeItem("@mindpattern/user_id");await confirm();expect(Alert.alert.mock.lastCall?.[1]).toBe("Something went wrong — try again.");expect(consents).toEqual([]);
 });
 it.each([403,409,503])("Native disclosure detail at status %i is classified only as a real conflict",async status=>{
  await mount();await grantCard();actionStatus=status;actionError={detail:"Native disclosure changed"};await confirm();expect(Alert.alert.mock.lastCall?.[0]).toBe(status===409?"Sharing terms updated":status===403?"That password didn't match":"Could not complete");
 });
 it.each(["Native disclosure provider refused",""])("a finite Native P256 provider failure %j keeps its honest local completion copy",async message=>{
  await mount();await grantCard();vi.spyOn(engine,"diffieHellman").mockImplementationOnce(()=>{throw new Error(message);});await confirm();expect(Alert.alert.mock.lastCall?.[0]).toBe("Could not complete");expect(Alert.alert.mock.lastCall?.[1]).toBe("Something went wrong — try again.");
 });
 it("Native password proof grants an independently authenticated wrap and renders the recipient's name",async()=>{await mount();await grantCard();await confirm();expect(await api.listConsents()).toEqual([consent()]);expect(Alert.alert.mock.lastCall?.[0]).toBe("Sharing started");expect(Alert.alert.mock.lastCall?.[1]).toContain("Dr. Native");expect(text()).toContain("Dr. Native");});
 it("Native grant confirmation renders the whole disclosure, fingerprint, match code and cancel choice",async()=>{
  await mount();await lookup();await press("Share with Dr. Native");const dialog=Alert.alert.mock.lastCall!;expect(dialog[1]).toContain("123 456");expect(dialog[1]).toContain("journal");const hex=crypto.createHash("sha256").update(Buffer.from(PUBLIC,"base64")).digest("hex").slice(0,32).toUpperCase().match(/.{4}/g)!.join(" ");expect(dialog[1]).toContain(hex);
  expect(dialog[2]).toEqual(expect.arrayContaining([expect.objectContaining({text:"Cancel",style:"cancel"}),expect.objectContaining({text:"They don’t match",style:"destructive"})]));await choose("They don’t match");expect(Alert.alert.mock.lastCall?.[1]).not.toBe("");
 });
 it.each([undefined,"x123 456","123 456x",123456,"123456",{},""])("Native absent or invalid SAS %j cannot appear in the confirmation",async value=>{sas=value;await mount();await lookup();await press("Share with Dr. Native");expect(String(Alert.alert.mock.lastCall?.[1])).not.toContain("Match code:");expect(String(Alert.alert.mock.lastCall?.[1])).not.toContain("Stryker was here");});
 it("Native whitespace pairing input stays disabled until a real code exists",async()=>{await mount();await fill("e.g. 7X2KQM4N","   ");expect(button("Find my therapist").props.disabled).toBe(true);});
 it.each([401,404,503])("Native pairing %i uses its honest public failure body",async status=>{lookupStatus=status;await mount();await lookup();const alert=Alert.alert.mock.lastCall!;expect(alert[1]).not.toBe("");expect(alert[0]).toBe(status===401?"Session expired":status===404?"Code not found":"Couldn’t look up the code");});
 it("Native revoke keeps both calm confirmations and the final revoke body",async()=>{consents=[consent()];await mount();await press("Stop sharing");expect(Alert.alert.mock.lastCall?.[1]).not.toBe("");expect(Alert.alert.mock.lastCall?.[2]).toEqual(expect.arrayContaining([expect.objectContaining({text:"Cancel",style:"cancel"}),expect.objectContaining({text:"Stop sharing",style:"destructive"})]));await choose("Stop sharing");await confirm();expect((await api.listConsents())[0]?.status).toBe("revoked");expect(Alert.alert.mock.lastCall?.[1]).not.toBe("");});
 it.each([false,true])("Native voice sharing %s changes only its selected recipient before the delayed server refresh",async enabled=>{
  consents=[consent(CONSENT,"Dr. Native",!enabled),consent(SECOND,"Dr. Other",!enabled)];await mount();const choices=root!.root.findAllByType(Switch);await act(async()=>choices[0]!.props.onValueChange(enabled));expect(Alert.alert.mock.lastCall?.[1]).not.toBe("");expect(Alert.alert.mock.lastCall?.[2]).toEqual(expect.arrayContaining([expect.objectContaining({text:"Cancel",style:"cancel"})]));await choose("Continue");
  let release!:()=>void,entered=false;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async(path,method)=>{if(path.endsWith("/consents")&&method==="GET"){entered=true;await held;}};await confirm();expect(entered).toBe(true);const switches=root!.root.findAllByType(Switch);expect(switches[0]!.props.value).toBe(enabled);expect(switches[1]!.props.value).toBe(!enabled);release();await flush();
 });
 it("Native malformed consent timestamps keep their safe literal fallback",async()=>{consents=[{...consent(),granted_at:"Native malformed date"}];await mount();expect(text()).toContain("Native malformed date");expect(text()).not.toContain("Invalid Date");});
 it("installed Native press cleanup drops a granted password touch when its route closes",async()=>{
  await mount();await grantCard();await fill("password",PASSWORD);const node=button("Confirm with password"),touch=nativeGrantedPress(node.props);await act(async()=>{root!.unmount();root=undefined;touch.dispose();});touch.release();await flush();expect(await api.listConsents()).toEqual([]);
 });
 it("a Native account-id delivery cannot hand the replacement key to an old sharing confirmation",async()=>{
  await mount();await grantCard();await fill("password",PASSWORD);let release!:()=>void,entered=false,armed=true;const held=new Promise<void>(resolve=>release=resolve),read=storage.getItem;
  vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(armed&&key==="@mindpattern/user_id"){armed=false;entered=true;await held;}return value;});
  let pending!:Promise<void>;await act(async()=>{pending=nativeTap(button("Confirm with password"))as Promise<void>;});await vi.waitFor(()=>expect(entered).toBe(true));
  await api.setSession("replacement Native sharing bearer",USER,"native-patient");serverData=Buffer.alloc(32,11);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(AUTH),dataKey:Buffer.from(serverData)},USER);
  Alert.alert.mockClear();release();await pending;await flush();expect(await api.listConsents()).toEqual([]);expect(Alert.alert.mock.calls).toEqual([]);
 });
 it("a failed Native pairing lookup cannot publish an alert after its route closes",async()=>{
  await mount();let entered=false,release!:()=>void;const held=new Promise<void>(resolve=>release=resolve);nativeGate=async path=>{if(path.endsWith("/pairing/lookup")){entered=true;await held;}};lookupStatus=503;
  await lookup();expect(entered).toBe(true);await act(async()=>{root!.unmount();root=undefined;});await api.setSession("replacement Native lookup bearer",USER,"native-patient");Alert.alert.mockClear();release();await flush();expect(Alert.alert.mock.calls).toEqual([]);
 });
 it("two Native confirm deliveries consume a pairing code once and leave its success message",async()=>{
  await mount();await grantCard();await fill("password",PASSWORD);const node=button("Confirm with password");
  await act(async()=>{await Promise.all([nativeTap(node),nativeTap(node)]);});await flush();expect(Alert.alert.mock.lastCall?.[0]).toBe("Sharing started");expect(Alert.alert.mock.calls.filter(call=>call[0]==="Sharing started")).toHaveLength(1);
 });
});
