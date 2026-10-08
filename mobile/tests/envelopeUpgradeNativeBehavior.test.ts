/** Real HTTP possession receipts, native credentials, and independently read AES envelopes. */
import crypto from "node:crypto";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {api} from "../src/api/client";
import {upgradeKeyProtection} from "../src/envelopeUpgrade";
import {vault} from "../src/vault";
import {installLocalDataKey,__resetLocalKeyLifecycleForTests} from "../src/localWriteGuard";
import {setSecureStoreBackend} from "../src/secureStore";
import {runTestControl} from "./helpers/testControl";
import storage from "./helpers/storageMock";
import * as keychain from "./helpers/keychainMock";
const USER="a".repeat(32),PASSWORD="Native upgrade wrapping password",SALT=Buffer.alloc(16,4),DATA=Buffer.alloc(32,75),NEXT=Buffer.alloc(32,76),PROOF="Native acknowledged password proof";
const INPUT={username:"alice",userId:USER,password:PASSWORD,verifierB64:PROOF};
let delivered:Buffer[],envelope:Record<string,any>|null,metadataAnswered:boolean;
const releases:Array<()=>void>=[];
function hold(){let entered=false,release!:()=>void;const pending=new Promise<void>(resolve=>{release=resolve;});releases.push(release);return{run:async()=>{entered=true;await pending;},entered:()=>entered,release};}
beforeEach(async()=>{
 vi.restoreAllMocks();storage.__reset();keychain.__reset();runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();await api.setSession("Native upgrade bearer",USER,"alice");vault.unlock({masterKey:Buffer.alloc(32,1),authKey:Buffer.alloc(32,2),dataKey:Buffer.from(DATA)},USER);installLocalDataKey(USER,vault.get().dataKey);delivered=[];envelope=null;metadataAnswered=false;
 vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{const path=new URL(url).pathname;let body:unknown={};
  if(path.endsWith("/auth/key-envelope")){body={key_scheme:"v1",salt:SALT.toString("base64"),kdf_params:null,wrapped_data_key:null};metadataAnswered=true;}
  else if(path.endsWith("/processing/sessions")){delivered.push(Buffer.from(JSON.parse(String(init.body)).data_key,"base64"));body={session_token:"Native upgrade possession token"};}
  else if(path.endsWith("/account/key-envelope/upgrade")){expect(new Headers(init.headers).get("X-Account-Verifier")).toBe(PROOF);expect(new Headers(init.headers).get("X-Processing-Token")).toBe("Native upgrade possession token");envelope=JSON.parse(String(init.body));}
  else throw new Error("Unexpected Native upgrade route "+path);
  const response=new Response(JSON.stringify(body),{status:200});Object.defineProperty(response,"url",{value:url});return response;
 });
});
afterEach(async()=>{for(const release of releases.splice(0))release();vi.restoreAllMocks();vault.lock();await api.clearSession();vi.unstubAllGlobals();});
it("a Native accepted upgrade stores an envelope that independently preserves the journal key",async()=>{
 expect(await upgradeKeyProtection(INPUT)).toEqual({ok:true,already:false});expect(delivered).toEqual([DATA]);expect(envelope).toBeTruthy();const saved=envelope!,params=saved.kdf_params,master=crypto.pbkdf2Sync(PASSWORD,SALT,params.iterations,32,"sha256"),kek=Buffer.from(crypto.hkdfSync("sha256",master,SALT,"mindpattern/envelope/v2",32)),wire=Buffer.from(saved.wrapped_data_key,"base64"),reader=crypto.createDecipheriv("aes-256-gcm",kek,wire.subarray(0,12));reader.setAAD(Buffer.from(JSON.stringify({context:"envelope",kdf_params:params,username:"alice"})));reader.setAuthTag(wire.subarray(-16));expect(Buffer.concat([reader.update(wire.subarray(12,-16)),reader.final()])).toEqual(DATA);master.fill(0);kek.fill(0);expect(vault.get().dataKey).toEqual(DATA);
});
it("a held Native processing-origin read cannot send a superseded generation of the same account's key",async()=>{
 const held=hold(),get=storage.getItem.bind(storage);let first=true;vi.spyOn(storage,"getItem").mockImplementation(async slot=>{const value=await get(slot);if(metadataAnswered&&slot==="@mindpattern/base_url"&&first){first=false;await held.run();}return value;});const pending=upgradeKeyProtection(INPUT);await vi.waitFor(()=>expect(held.entered()).toBe(true));vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32),dataKey:Buffer.from(NEXT)},USER);installLocalDataKey(USER,vault.get().dataKey);held.release();expect((await pending).ok).toBe(false);expect(delivered).toEqual([]);expect(envelope).toBeNull();expect(vault.get().dataKey).toEqual(NEXT);
});
