import crypto from "node:crypto";
import { afterEach,beforeEach,expect,it,vi } from "vitest";
import { api,DEFAULT_BASE_URL } from "../src/api/client";
import { rotatePassword } from "../src/rotation";
import { vault } from "../src/vault";
import { engine } from "./helpers/nodeEngine";
import storage from "./helpers/storageMock";
import * as files from "./helpers/expoFsMock";
import { secureStore,setSecureStoreBackend } from "../src/secureStore";
import { runTestControl } from "./helpers/testControl";
import { __resetLocalKeyLifecycleForTests,localWriteScopeEpoch } from "../src/localWriteGuard";
import { emptySafetyPlan,loadSafetyPlan,saveSafetyPlan } from "../src/safetyPlan";
import { pendingLocalRekey,prepareLocalRekey,localRekeyRequest,storeLocalRekeyRequest,storeLocalRekeyTokens } from "../src/localRekey";
import * as journalCrypto from "../src/crypto/journalCrypto";
import * as kdf from "../src/crypto/kdf";
import * as keyEnvelope from "../src/crypto/keyEnvelope";
import { accountStorageKey } from "../src/accountStorage";
import { enableBiometricUnlock,hasBiometricUnlock,unwrapBiometricDataKey } from "../src/biometricUnlock";
import { storeUnlockProof,unlockProofExists } from "../src/unlockProof";
import * as keychain from "./helpers/keychainMock";
import { observeEntryVersions,knownEntryVersion,resetEntryVersionMirrors } from "../src/entryVersions";

const USER="e".repeat(32),SALT=Buffer.alloc(16,3),OLD="old account password",NEW="a fresh account password 42!",RANDOM_DATA=Buffer.alloc(32,7);
function derive(password:string,salt:Buffer,iterations=600000){const master=crypto.pbkdf2Sync(password,salt,iterations,32,"sha256");return {masterKey:master,authKey:Buffer.from(crypto.hkdfSync("sha256",master,Buffer.alloc(0),Buffer.from("mindpattern/auth/v1"),32)),dataKey:Buffer.from(crypto.hkdfSync("sha256",master,Buffer.alloc(0),Buffer.from("mindpattern/data/v1"),32))};}
const OLD_KEYS=derive(OLD,SALT);
function wrap(password:string,salt:Buffer,iterations:number){const master=crypto.pbkdf2Sync(password,salt,iterations,32,"sha256"),key=Buffer.from(crypto.hkdfSync("sha256",master,salt,Buffer.from("mindpattern/envelope/v2"),32)),nonce=Buffer.alloc(12,6),cipher=crypto.createCipheriv("aes-256-gcm",key,nonce);cipher.setAAD(Buffer.from(JSON.stringify({context:"envelope",kdf_params:{algorithm:"pbkdf2-sha256",version:1,iterations},username:"alice"})));return Buffer.concat([nonce,cipher.update(RANDOM_DATA),cipher.final(),cipher.getAuthTag()]).toString("base64");}
const input={username:"alice",userId:USER,oldPassword:OLD,newPassword:NEW};
let scheme:"v1"|"v2",iterations:number,verifier:string,envelopeError:number,processingError:number,processingCode:string,passwordError:number,passwordCode:string,rekeyError:number,loginError:number,legacy:boolean,corruptEnvelope:boolean,atomic:boolean;
let passwordBody:any,rekeyBody:any,paths:string[],processingKeys:string[],rekeyResult:Record<string,unknown>;
let envelopeOverride:unknown,consents:any[],loginUser:string,rekeyCode:string,rekeyAttempts:number,expireRetry:boolean;
let saltError:number,saltValue:unknown,rekeyNoContent:boolean;
beforeEach(async()=>{
 vi.restoreAllMocks();storage.__reset();files.__resetFiles();keychain.__reset();runTestControl(resetEntryVersionMirrors);runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);vault.lock();
 scheme="v1";iterations=600000;verifier=OLD_KEYS.authKey.toString("base64");envelopeError=processingError=passwordError=rekeyError=loginError=0;processingCode=passwordCode="";legacy=corruptEnvelope=false;atomic=true;passwordBody=rekeyBody=null;paths=[];processingKeys=[];rekeyResult={entries:"3",insights:"2",measures:"1",consents_rewrapped:0,recovery_invalidated:true};
 envelopeOverride=undefined;consents=[];loginUser=USER;rekeyCode="";rekeyAttempts=0;expireRetry=false;
 saltError=0;saltValue=SALT.toString("base64");rekeyNoContent=false;
 await api.setSession("old-bearer",USER,"alice");await api.cacheSalt("alice",SALT.toString("base64"));
 vault.unlock({masterKey:Buffer.from(OLD_KEYS.masterKey),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.from(OLD_KEYS.dataKey)},USER);
 vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{
  const path=new URL(url).pathname;paths.push(path);const body=init.body?JSON.parse(String(init.body)):null;let value:any={},status=200;
  if(path.endsWith("/auth/key-envelope")){status=envelopeError||(legacy?404:200);value=status===200?(envelopeOverride??{key_scheme:scheme,salt:SALT.toString("base64"),kdf_params:scheme==="v2"?{algorithm:"pbkdf2-sha256",version:1,iterations}:null,wrapped_data_key:scheme==="v2"?wrap(corruptEnvelope?"another password":OLD,SALT,iterations):null}):{detail:"envelope unavailable"};}
  else if(path.endsWith("/processing/sessions")){status=processingError||200;processingKeys.push(body.data_key);value=status===200?{session_token:"processing-"+processingKeys.length}:{detail:"untrusted processing failure",code:processingCode};}
  else if(path.endsWith("/account/password")){passwordBody=body;status=passwordError||200;value=status===200?{}:{detail:"untrusted password failure",code:passwordCode};if(status===200)verifier=body.new_verifier;}
  else if(path.endsWith("/processing/rekey")){rekeyBody=body;status=(expireRetry&&++rekeyAttempts===2?403:rekeyError)||200;value=status===200?{credential_rotated:atomic,operation_id:body.operation_id,...rekeyResult}:{detail:"untrusted rekey failure",code:expireRetry?"processing_session_invalid":rekeyCode};if(status===200&&atomic)verifier=body.new_verifier;}
  else if(path.endsWith("/auth/login")){status=loginError||(body.verifier===verifier?200:401);value=status===200?{token:"new-bearer",user_id:loginUser}:{detail:"relogin unavailable"};}
  else if(path.endsWith("/auth/salt")){status=saltError||200;value=status===200?{salt:saltValue}:{detail:"untrusted salt failure"};}
  else if(path.endsWith("/consents"))value=consents;
  else throw new Error("unexpected native route "+path);
  const result=rekeyNoContent&&path.endsWith("/processing/rekey")?new Response(null,{status:204}):new Response(JSON.stringify(value),{status});Object.defineProperty(result,"url",{value:url});return result;
 }));
});
afterEach(async()=>{vi.restoreAllMocks();vault.lock();await api.clearSession();vi.unstubAllGlobals();});
function v2(cost=600000){scheme="v2";iterations=cost;vault.unlock({masterKey:Buffer.from(OLD_KEYS.masterKey),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.from(RANDOM_DATA)},USER);}
it("completes the v1 atomic transaction and keeps authored local content decryptable with the new password",async()=>{
 await saveSafetyPlan(vault.get().dataKey,USER,{...emptySafetyPlan(),warningSigns:"Retained authored warning signs"});
 const result=await rotatePassword(input);expect(result).toEqual({ok:true,scheme:"v1",sessionScope:localWriteScopeEpoch(),counts:{entries:3,insights:2,measures:1},rewrapped:0,rewrapFailures:[],recoveryInvalidated:true});
 const fresh=derive(NEW,Buffer.from(rekeyBody.new_salt,"base64"));expect(rekeyBody.new_verifier).toBe(fresh.authKey.toString("base64"));expect(processingKeys).toEqual([OLD_KEYS.dataKey.toString("base64"),fresh.dataKey.toString("base64")]);
 expect(await loadSafetyPlan(fresh.dataKey,USER)).toEqual({...emptySafetyPlan(),warningSigns:"Retained authored warning signs"});expect(await pendingLocalRekey(USER)).toBe(false);expect(vault.isUnlocked()).toBe(false);expect(await api.login("alice",fresh.authKey.toString("base64"))).toEqual({token:"new-bearer",user_id:USER});
});
it.each([600000,800000])("keeps a v2 account with an envelope cost of %s usable through the shipped fresh-login derivation",async cost=>{
 v2(cost);const result=await rotatePassword(input);expect(result).toMatchObject({ok:true,scheme:"v2",sessionScope:localWriteScopeEpoch(),counts:{entries:0,insights:0,measures:0},rewrapped:0,rewrapFailures:[]});
 expect(vault.get().dataKey).toEqual(RANDOM_DATA);expect(processingKeys).toEqual([RANDOM_DATA.toString("base64")]);expect(rekeyBody).toBeNull();
 const salt=Buffer.from(passwordBody.new_salt,"base64"),fresh=derive(NEW,salt);expect(await api.login("alice",fresh.authKey.toString("base64"))).toEqual({token:"new-bearer",user_id:USER});expect(vault.get().authKey).toEqual(fresh.authKey);
 const blob=Buffer.from(passwordBody.wrapped_data_key,"base64"),master=crypto.pbkdf2Sync(NEW,salt,cost,32,"sha256"),key=Buffer.from(crypto.hkdfSync("sha256",master,salt,Buffer.from("mindpattern/envelope/v2"),32)),reader=crypto.createDecipheriv("aes-256-gcm",key,blob.subarray(0,12));reader.setAAD(Buffer.from(JSON.stringify({context:"envelope",kdf_params:{algorithm:"pbkdf2-sha256",version:1,iterations:cost},username:"alice"})));reader.setAuthTag(blob.subarray(-16));expect(Buffer.concat([reader.update(blob.subarray(12,-16)),reader.final()])).toEqual(RANDOM_DATA);
});
it("supports the pre-envelope server through the v1 atomic protocol",async()=>{legacy=true;expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(rekeyBody).not.toBeNull();});
it("reports a native envelope server failure without starting a server-side key change",async()=>{envelopeError=500;expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline"});expect(processingKeys).toEqual([]);});
it("reports an authenticated but unusable v2 envelope as a password failure without dispatching possession proof",async()=>{v2();corruptEnvelope=true;expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"wrong-password"});expect(processingKeys).toEqual([]);});
it.each([[403,"processing_session_invalid"],[500,""]])("refuses the native v2 possession probe (%s %s)",async(status,code)=>{
 v2();processingError=status as number;processingCode=code as string;const result=await rotatePassword(input);expect(result).toMatchObject({ok:false,stage:"credential",reason:"server"});if(code)expect(result).toHaveProperty("detail","the server could not verify this device's encryption key session — unlock again and retry the password change");else expect(result).toHaveProperty("detail",undefined);expect(passwordBody).toBeNull();
});
it.each([[422,"processing_session_required","server"],[403,"processing_session_invalid","server"],[403,"verification_failed","wrong-password"],[500,"","server"]])("classifies the v2 atomic refusal (%s %s)",async(status,code,reason)=>{
 v2();passwordError=status as number;passwordCode=code as string;expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"credential",reason});expect(paths.some(path=>path.endsWith("/auth/login"))).toBe(false);
});
it.each(["v1","v2"] as const)("retains the new %s unlock salt and locks on failed relogin after commit",async target=>{
 if(target==="v2")v2();loginError=500;expect(await rotatePassword(input)).toEqual({ok:false,stage:"relogin",reason:"server"});expect(vault.isUnlocked()).toBe(false);expect(await api.getCachedSalt("alice")).toBe((target==="v2"?passwordBody:rekeyBody).new_salt);
});
it.each([403,500])("retains the prepared checkpoint after a native v1 transaction refusal (%s)",async status=>{
 rekeyError=status;expect(await rotatePassword(input)).toEqual({ok:false,stage:"rekey",reason:status===403?"wrong-password":"server",detail:undefined});expect(await pendingLocalRekey(USER)).toBe(true);expect(vault.isUnlocked()).toBe(false);
});
it("refuses a server acknowledgement that did not atomically rotate the credential",async()=>{atomic=false;expect(await rotatePassword(input)).toEqual({ok:false,stage:"rekey",reason:"offline",detail:"The server does not support atomic password rotation; update the server before retrying"});expect(await pendingLocalRekey(USER)).toBe(true);});
it.each(["v1","v2"] as const)("reports unavailable native randomness as a typed %s failure",async target=>{
 if(target==="v2")v2();vi.spyOn(engine,"randomBytes").mockImplementation(()=>{throw new Error("native entropy unavailable");});expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"verify",reason:"offline",detail:"native entropy unavailable"});expect(processingKeys).toEqual([]);
});
it("refuses a locked or mismatched starting vault without consulting the transport",async()=>{
 vault.lock();expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(paths).toEqual([]);
 vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.from(OLD_KEYS.dataKey)},"f".repeat(32));expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(paths).toEqual([]);
});
it("classifies a missing password as a failed proof before envelope transport",async()=>{
 expect(await rotatePassword({...input,oldPassword:""})).toEqual({ok:false,stage:"verify",reason:"wrong-password"});expect(paths).toEqual([]);
});
it.each([{key_scheme:"v2",salt:SALT.toString("base64"),kdf_params:{algorithm:"argon2id",version:1,iterations:600000},wrapped_data_key:Buffer.alloc(60).toString("base64")},{key_scheme:"v3",salt:SALT.toString("base64"),kdf_params:null,wrapped_data_key:null}])("reports an unsupported native envelope honestly (%j)",async envelope=>{
 envelopeOverride=envelope;expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:"this account's key envelope uses parameters this app cannot derive — update the app before changing the password"});expect(processingKeys).toEqual([]);
});
it("classifies an unavailable native envelope cipher without claiming a wrong password",async()=>{
 v2();const create=engine.createDecipheriv;
 vi.spyOn(engine,"createDecipheriv").mockImplementation((...args)=>{const native=create(...args);const aad=native.setAAD.bind(native);native.setAAD=((value:Buffer,...rest:any[])=>{if(value.toString().includes('"context":"envelope"'))throw new Error("native envelope cipher unavailable");return aad(value,...rest);}) as typeof native.setAAD;return native;});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:"the stored key envelope is malformed"});expect(processingKeys).toEqual([]);
});
it.each(["v1","v2"] as const)("erases every owned %s derivation after completion and keeps adopted keys independent",async target=>{
 if(target==="v2")v2();const deriveKeys=journalCrypto.deriveKeysAsync,deriveMaster=kdf.deriveMasterKeyAsync,kek=keyEnvelope.envelopeKek,unwrap=keyEnvelope.unwrapDataKey;
 const owned:Buffer[]=[];
 vi.spyOn(journalCrypto,"deriveKeysAsync").mockImplementation(async(...args)=>{const keys=await deriveKeys(...args);owned.push(keys.masterKey,keys.authKey,keys.dataKey);return keys;});
 vi.spyOn(kdf,"deriveMasterKeyAsync").mockImplementation(async(...args)=>{const key=await deriveMaster(...args);owned.push(key);return key;});
 vi.spyOn(keyEnvelope,"envelopeKek").mockImplementation((...args)=>{const key=kek(...args);owned.push(key);return key;});
 vi.spyOn(keyEnvelope,"unwrapDataKey").mockImplementation((...args)=>{const key=unwrap(...args);owned.push(key);return key;});
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:target});expect(owned.length).toBeGreaterThan(0);for(const key of owned)expect(key).toEqual(Buffer.alloc(key.length));if(target==="v2")expect(vault.get().dataKey).toEqual(RANDOM_DATA);
});
it.each(["v1","v2"] as const)("erases owned %s key material after a native provider refuses wrapping",async target=>{
 if(target==="v2")v2();const deriveKeys=journalCrypto.deriveKeysAsync,owned:Buffer[]=[];
 vi.spyOn(journalCrypto,"deriveKeysAsync").mockImplementation(async(...args)=>{const keys=await deriveKeys(...args);owned.push(keys.masterKey,keys.authKey,keys.dataKey);return keys;});
 const create=engine.createCipheriv;vi.spyOn(engine,"createCipheriv").mockImplementation((...args)=>{const native=create(...args),aad=native.setAAD.bind(native);native.setAAD=((value:Buffer,...rest:any[])=>{if(value.toString().includes(target==="v2"?'"context":"envelope"':'"local-rekey"'))throw new Error("native wrap unavailable");return aad(value,...rest);}) as typeof native.setAAD;return native;});
 expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"verify",reason:target==="v2"?"offline":"queue-blocked"});for(const key of owned)expect(key).toEqual(Buffer.alloc(key.length));
});
it.each(["v1","v2"] as const)("retires a %s relogin that returned a different account before adopting its credential",async target=>{
 if(target==="v2")v2();loginUser="f".repeat(32);expect(await rotatePassword(input)).toEqual({ok:false,stage:"relogin",reason:"server"});expect(await api.getUserId()).toBe(USER);expect(vault.isUnlocked()).toBe(false);
});
it.each(["v1","v2"] as const)("removes an existing %s biometric wrap after a failed postcommit relogin",async target=>{
 if(target==="v2")v2();await enableBiometricUnlock(USER,vault.get().dataKey);expect(await hasBiometricUnlock(USER)).toBe(true);loginError=500;expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"relogin"});expect(await hasBiometricUnlock(USER)).toBe(false);
});
it.each(["invalid","unavailable"])("replaces an %s pending native salt with a correctly sized fresh value",async mode=>{
 const slot=accountStorageKey.pendingRotationSalt(USER);if(mode==="invalid")await storage.setItem(slot,Buffer.alloc(15,1).toString("base64"));else {const read=storage.getItem;vi.spyOn(storage,"getItem").mockImplementation(async key=>{if(key===slot)throw new Error("native pending salt unavailable");return read(key);});}
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(Buffer.from(rekeyBody.new_salt,"base64")).toHaveLength(16);
});
it("uses a retained retry salt exactly and removes it only after full completion",async()=>{
 const salt=Buffer.alloc(16,12),slot=accountStorageKey.pendingRotationSalt(USER);await storage.setItem(slot,salt.toString("base64"));expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(rekeyBody.new_salt).toBe(salt.toString("base64"));expect(await storage.getItem(slot)).toBeNull();
});
it("refetches a salt cache that disappeared after the actual old-password proof",async()=>{
 const read=api.getCachedSalt;let reads=0;vi.spyOn(api,"getCachedSalt").mockImplementation(async username=>{const salt=await read(username);if(++reads===1)await api.clearCachedSalt(username);return salt;});
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(paths.filter(path=>path.endsWith("/auth/salt"))).toHaveLength(1);expect(await api.getCachedSalt("alice")).toBe(rekeyBody.new_salt);
});
it("retains a stable checkpoint while refreshing expired native processing headers",async()=>{
 expireRetry=true;rekeyError=500;expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"rekey",reason:"server"});const oldBody=structuredClone(rekeyBody);
 vault.unlock({masterKey:Buffer.from(OLD_KEYS.masterKey),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.from(OLD_KEYS.dataKey)},USER);rekeyError=0;
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(rekeyBody).toEqual(oldBody);expect(processingKeys).toHaveLength(4);expect(await pendingLocalRekey(USER)).toBe(false);
});
it.each(["server refusal","native transport failure"])("retains the same prepared rotation without refreshing headers after a retry's %s",async fault=>{
 rekeyError=500;expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"rekey",reason:"server"});const oldBody=structuredClone(rekeyBody);vault.unlock({masterKey:Buffer.from(OLD_KEYS.masterKey),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.from(OLD_KEYS.dataKey)},USER);
 if(fault==="native transport failure"){const transport=fetch;vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{if(new URL(url).pathname.endsWith("/processing/rekey"))throw new Error("native retry connection unavailable");return transport(url,init);});}
 expect(await rotatePassword(input)).toMatchObject({ok:false,stage:"rekey",reason:"server"});expect(processingKeys).toHaveLength(2);expect(rekeyBody).toEqual(oldBody);expect(await pendingLocalRekey(USER)).toBe(true);
});
const therapist=crypto.generateKeyPairSync("ec",{namedCurve:"prime256v1"}),therapistId="f".repeat(32),therapistPublic=therapist.publicKey.export({type:"spki",format:"der"}).toString("base64");
function consent(status="active",publicKey:string|undefined=therapistPublic){return {id:"a".repeat(32),therapist_id:therapistId,display_name:"Therapist",username:"therapist",status,granted_at:"2026-10-05T00:00:00Z",revoked_at:null,...(publicKey===undefined?{}:{therapist_wrap_pub_key:publicKey})};}
it("atomically rewraps only active therapist grants and reports the server's bounded count",async()=>{
 consents=[consent(),{...consent("revoked"),id:"b".repeat(32)}];rekeyResult.consents_rewrapped=1;expect(await rotatePassword(input)).toMatchObject({ok:true,rewrapped:1});expect(rekeyBody.consent_wraps).toHaveLength(1);
 const wrap=rekeyBody.consent_wraps[0],ephemeral=Buffer.from(wrap.ephemeral_pub,"base64"),shared=crypto.diffieHellman({privateKey:therapist.privateKey,publicKey:crypto.createPublicKey({key:ephemeral,type:"spki",format:"der"})}),key=Buffer.from(crypto.hkdfSync("sha256",shared,Buffer.concat([ephemeral,Buffer.from(therapistPublic,"base64")]),Buffer.from("mindpattern/wrap/v1"),32)),blob=Buffer.from(wrap.wrapped_key,"base64"),reader=crypto.createDecipheriv("aes-256-gcm",key,blob.subarray(0,12));reader.setAuthTag(blob.subarray(-16));reader.setAAD(Buffer.from(JSON.stringify(["consent-wrap",USER,therapistId])));const current=derive(NEW,Buffer.from(rekeyBody.new_salt,"base64"));expect(Buffer.concat([reader.update(blob.subarray(12,-16)),reader.final()])).toEqual(current.dataKey);expect(wrap).toMatchObject({consent_id:"a".repeat(32),therapist_wrap_pub_key:therapistPublic});
});
it.each(["absent","malformed"])("refuses a retained active grant with an %s native public key",async mode=>{
 consents=[mode==="absent"?{...consent(),therapist_wrap_pub_key:undefined}:consent("active","invalid")];expect(await rotatePassword(input)).toEqual({ok:false,stage:"rewrap",reason:"offline",detail:mode==="absent"?"An active sharing grant has no current public key":"therapist public key has the wrong format"});expect(rekeyBody).toBeNull();
});
it.each([-1,0.5,2,null,"1"])("bounds an untrusted native consent count %j using the submitted wraps",async count=>{
 consents=[consent()];rekeyResult.consents_rewrapped=count;expect(await rotatePassword(input)).toMatchObject({ok:true,rewrapped:1});
});
it("refuses a native transaction acknowledgement for a different UUID",async()=>{
 rekeyResult.operation_id="wrong-operation";expect(await rotatePassword(input)).toEqual({ok:false,stage:"rekey",reason:"offline",detail:"The server does not support atomic password rotation; update the server before retrying"});expect(await pendingLocalRekey(USER)).toBe(true);
});
it.each(["envelope","processing","password","consents","rekey"])("retires an old native %s failure before returning its previous-account error context",async stage=>{
 const route=stage==="envelope"?"/auth/key-envelope":stage==="processing"?"/processing/sessions":stage==="password"?"/account/password":stage==="consents"?"/consents":"/processing/rekey";
 if(stage==="processing"||stage==="password")v2();if(stage==="envelope")envelopeError=500;if(stage==="processing"){processingError=403;processingCode="processing_session_invalid";}if(stage==="password"){passwordError=403;passwordCode="verification_failed";}if(stage==="rekey")rekeyError=500;
 const transport=fetch;let release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
 vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{const response=stage==="consents"&&new URL(url).pathname.endsWith(route)?new Response('{"detail":"untrusted consent failure"}',{status:500}):await transport(url,init);if(new URL(url).pathname.endsWith(route)){ready();await new Promise<void>(resolve=>{release=resolve;});}return response;}));
 const pending=rotatePassword(input);await Promise.race([started,pending]);
 const replacement={masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)};vault.unlock(replacement,USER);
 try{release?.();expect(await pending).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toBe(replacement.dataKey);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));}finally{release?.();await pending;}
});
it.each(["auth key","biometric data key"])("retires an envelope response when only its original %s allocation was replaced",async slot=>{
 v2();envelopeError=500;const transport=fetch;let release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
 vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{const response=await transport(url,init);if(new URL(url).pathname.endsWith("/auth/key-envelope")){ready();await new Promise<void>(resolve=>{release=resolve;});}return response;}));
 const pending=rotatePassword(input);await Promise.race([started,pending]);const previous=vault.get();
 if(slot==="auth key")vault.adoptAuthKey(Buffer.from(previous.authKey));
 else vault.unlock({masterKey:Buffer.alloc(32),authKey:previous.authKey,dataKey:Buffer.alloc(32,13)},USER,{authKeyKnown:false});
 const replacement=vault.get();try{release?.();expect(await pending).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toBe(replacement.dataKey);expect(vault.get().authKey).toBe(replacement.authKey);}finally{release?.();await pending;}
});
it.each(["salt failure","missing username"])("reports an unavailable actual password proof (%s)",async mode=>{
 if(mode==="salt failure"){await api.clearCachedSalt("alice");saltError=503;}else await secureStore.removeItem("@mindpattern/username");
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline"});expect(processingKeys).toEqual([]);
});
it.each(["native failure","missing salt"])("reports an unavailable salt after a completed password proof (%s)",async mode=>{
 const read=api.getCachedSalt;let reads=0;vi.spyOn(api,"getCachedSalt").mockImplementation(async username=>{const value=await read(username);if(++reads===1)await api.clearCachedSalt(username);return value;});if(mode==="native failure")saltError=503;else saltValue=null;
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline"});expect(processingKeys).toEqual([]);
});
it.each(["processing","password","rekey","relogin"])("reports a typed server failure after an actual native %s body read fails",async stage=>{
 if(stage==="processing"||stage==="password")v2();const route=stage==="processing"?"/processing/sessions":stage==="password"?"/account/password":stage==="rekey"?"/processing/rekey":"/auth/login";
 const transport=fetch;vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{if(new URL(url).pathname.endsWith(route)){const response=new Response(new ReadableStream<Uint8Array>({start(controller){controller.error(new Error("native response body unavailable"));}}));Object.defineProperty(response,"url",{value:url});return response;}return transport(url,init);}));
 const result=await rotatePassword(input);expect(result).toEqual(stage==="relogin"?{ok:false,stage:"relogin",reason:"server"}:{ok:false,stage:stage==="rekey"?"rekey":"credential",reason:"server",detail:undefined});
});
it("reports an unauthenticated native atomic acknowledgement without exposing an internal null dereference",async()=>{
 rekeyNoContent=true;expect(await rotatePassword(input)).toEqual({ok:false,stage:"rekey",reason:"offline",detail:"The server does not support atomic password rotation; update the server before retrying"});expect(await pendingLocalRekey(USER)).toBe(true);
});
it.each(["current","retired"])("preserves a committed checkpoint after a %s native authored-store failure",async mode=>{
 const slot=accountStorageKey.safetyPlan(USER);await saveSafetyPlan(vault.get().dataKey,USER,{...emptySafetyPlan(),warningSigns:"Retained authored safety plan"});const write=storage.setItem;let replacement:ReturnType<typeof vault.get>|undefined;
 vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{if(key===slot){if(mode==="retired"){vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);replacement=vault.get();}throw new Error("native authored write unavailable");}return write(key,value);});
 expect(await rotatePassword(input)).toEqual(mode==="retired"?{ok:false,stage:"verify",reason:"server",detail:undefined}:{ok:false,stage:"credential",reason:"offline",detail:"native authored write unavailable"});expect(await pendingLocalRekey(USER)).toBe(true);if(replacement)expect(vault.get().dataKey).toBe(replacement.dataKey);
});
it.each(["processing","password","rekey","relogin"])("retains the public %s failure context when its native origin metadata becomes unavailable",async stage=>{
 if(stage==="processing"||stage==="password")v2();const name=stage==="processing"?"openProcessingSession":stage==="password"?"changePassword":stage==="rekey"?"rekeyStoredData":"login";
 const operation=api[name],read=storage.getItem;let admitted=false;
 vi.spyOn(api,name).mockImplementation(((...args:any[])=>{admitted=true;return (operation as (...values:any[])=>Promise<unknown>)(...args);}) as any);
 vi.spyOn(storage,"getItem").mockImplementation(async key=>{if(admitted&&key==="@mindpattern/base_url")throw new Error("native origin metadata unavailable");return read(key);});
 expect(await rotatePassword(input)).toEqual(stage==="relogin"?{ok:false,stage:"relogin",reason:"offline"}:{ok:false,stage:stage==="rekey"?"rekey":"credential",reason:"offline",detail:"native origin metadata unavailable"});
});
it.each(["cached salt refreshed","old bearer expired"])("resumes an independently prepared native checkpoint when its %s",async mode=>{
 const salt=Buffer.alloc(16,12),keys=derive(NEW,salt);await storage.setItem(accountStorageKey.pendingRotationSalt(USER),salt.toString("base64"));await prepareLocalRekey(USER,OLD_KEYS.dataKey,keys.dataKey,{oldSaltB64:SALT.toString("base64")});
 if(mode==="cached salt refreshed")await api.cacheSalt("alice",salt.toString("base64"));
 else{const checkpoint=await localRekeyRequest(USER,keys.dataKey),body={operation_id:checkpoint.operationId,new_salt:salt.toString("base64"),new_verifier:keys.authKey.toString("base64"),consent_wraps:[]};const old=(await api.openProcessingSession(OLD_KEYS.dataKey.toString("base64"))).session_token,next=(await api.openProcessingSession(keys.dataKey.toString("base64"))).session_token;await storeLocalRekeyRequest(USER,keys.dataKey,body);await storeLocalRekeyTokens(USER,keys.dataKey,{old,next});await api.rekeyStoredData(old,next,OLD_KEYS.authKey.toString("base64"),body);envelopeError=401;const transport=fetch;vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{if(["/auth/key-envelope","/consents","/processing/sessions"].some(route=>new URL(url).pathname.endsWith(route))){const response=new Response('{"detail":"old bearer expired"}',{status:401});Object.defineProperty(response,"url",{value:url});return response;}return transport(url,init);}));}
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(rekeyBody.new_salt).toBe(salt.toString("base64"));expect(await pendingLocalRekey(USER)).toBe(false);
});
it.each(Array.from({length:12},(_,i)=>i+1))("retires native envelope completion at browser microtask %s before a later unavailable KDF provider can change its error context",async turns=>{
 v2();let retired=false;const json=Response.prototype.json;
 vi.spyOn(Response.prototype,"json").mockImplementation(async function(this:Response){const data=await json.call(this);if(this.url.endsWith("/auth/key-envelope")){let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}};queueMicrotask(next);}return data;});
 const pbkdf=engine.pbkdf2;vi.spyOn(engine,"pbkdf2").mockImplementation(((...args:any[])=>{if(retired)throw new Error("native KDF provider unavailable");return (pbkdf as (...values:any[])=>unknown)(...args);}) as any);
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});
it("clears the former offline proof, biometric wrap and pending salt after a completed native v1 rotation",async()=>{
 await storeUnlockProof(vault.get().dataKey,USER);await enableBiometricUnlock(USER,vault.get().dataKey);
 expect(await unlockProofExists(USER)).toBe(true);expect(await hasBiometricUnlock(USER)).toBe(true);
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});
 expect(await unlockProofExists(USER)).toBe(false);expect(await hasBiometricUnlock(USER)).toBe(false);expect(await storage.getItem(accountStorageKey.pendingRotationSalt(USER))).toBeNull();
});
it.each(["v1","v2"] as const)("accepts a native biometric %s unlock after verifying and adopting its real password proof",async target=>{
 if(target==="v2")v2();await enableBiometricUnlock(USER,vault.get().dataKey);vault.lock();const dataKey=await unwrapBiometricDataKey(USER);expect(dataKey).not.toBeNull();
 vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32),dataKey:dataKey!},USER,{authKeyKnown:false});
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:target});expect(paths.filter(path=>path.endsWith("/auth/login"))).toHaveLength(2);
 if(target==="v2"){expect(vault.get().authKeyKnown).toBe(true);expect(vault.get().dataKey).toEqual(RANDOM_DATA);}
});
it("retires a failed native biometric password proof when its auth-key allocation was replaced",async()=>{
 v2();await enableBiometricUnlock(USER,vault.get().dataKey);vault.lock();const dataKey=await unwrapBiometricDataKey(USER);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32),dataKey:dataKey!},USER,{authKeyKnown:false});
 loginError=500;const transport=fetch;let replacement:ReturnType<typeof vault.get>|undefined;
 vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{const response=await transport(url,init);if(new URL(url).pathname.endsWith("/auth/login")){vault.adoptAuthKey(Buffer.from(OLD_KEYS.authKey));replacement=vault.get();}return response;}));
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(replacement).toBeDefined();expect(vault.get().authKey).toBe(replacement!.authKey);expect(paths.some(path=>path.endsWith("/auth/key-envelope"))).toBe(false);
});
it("erases the actual old v2 master allocation after its native unwrap provider fails",async()=>{
 v2();const deriveMaster=kdf.deriveMasterKeyAsync,owned:Buffer[]=[];
 vi.spyOn(kdf,"deriveMasterKeyAsync").mockImplementation(async(...args)=>{const key=await deriveMaster(...args);owned.push(key);return key;});
 const create=engine.createDecipheriv;vi.spyOn(engine,"createDecipheriv").mockImplementation((...args)=>{const native=create(...args),aad=native.setAAD.bind(native);native.setAAD=((value:Buffer,...rest:any[])=>{if(value.toString().includes('"context":"envelope"'))throw new Error("native envelope cipher unavailable");return aad(value,...rest);}) as typeof native.setAAD;return native;});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:"the stored key envelope is malformed"});expect(owned.length).toBeGreaterThan(0);for(const key of owned)expect(key).toEqual(Buffer.alloc(32));
});
it.each(Array.from({length:12},(_,i)=>i+1))("rejects a native password proof after auth-key replacement at completion microtask %s",async turns=>{
 v2();const pbkdf=engine.pbkdf2;let first=true,retired=false;
 vi.spyOn(engine,"pbkdf2").mockImplementation(((...args:any[])=>{const callback=args.pop();return (pbkdf as (...values:any[])=>unknown)(...args,(error:Error|null,key:Buffer)=>{callback(error,key);if(first){first=false;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.adoptAuthKey(Buffer.from(OLD_KEYS.authKey));}};queueMicrotask(next);}});}) as any);
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(retired).toBe(true);expect(vault.get().dataKey).toEqual(RANDOM_DATA);expect(vault.get().authKey).toEqual(OLD_KEYS.authKey);
});
it.each(["v1","v2"] as const)("refuses a retired %s native KDF failure without returning its former-account context",async target=>{
 if(target==="v2")v2();const pbkdf=engine.pbkdf2;let calls=0;
 vi.spyOn(engine,"pbkdf2").mockImplementation(((...args:any[])=>{const callback=args.pop();const current=++calls;return (pbkdf as (...values:any[])=>unknown)(...args,(error:Error|null,key:Buffer)=>{if(current===2){key?.fill(0);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);callback(new Error("native KDF provider unavailable"),undefined);}else callback(error,key);});}) as any);
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));expect(processingKeys).toEqual([]);
});
it.each(["v1","v2"] as const)("reports a current %s native KDF failure as a typed local error",async target=>{
 if(target==="v2")v2();const pbkdf=engine.pbkdf2;let calls=0;
 vi.spyOn(engine,"pbkdf2").mockImplementation(((...args:any[])=>{if(++calls===2)throw new Error("native KDF provider unavailable");return (pbkdf as (...values:any[])=>unknown)(...args);}) as any);
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline",detail:"native KDF provider unavailable"});expect(processingKeys).toEqual([]);
});
it("refuses a v2 native possession requirement with its exact public recovery instruction",async()=>{
 v2();passwordError=422;passwordCode="processing_session_required";expect(await rotatePassword(input)).toEqual({ok:false,stage:"credential",reason:"server",detail:"the server could not verify this device's encryption key session — unlock again and retry the password change"});
});
it("retains the generic v2 native failure when an invalid-session code has a different HTTP status",async()=>{
 v2();passwordError=400;passwordCode="processing_session_invalid";expect(await rotatePassword(input)).toEqual({ok:false,stage:"credential",reason:"server",detail:undefined});
});
it("refuses a native consent-list failure before preparing the atomic v1 request",async()=>{
 const transport=fetch;vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{if(new URL(url).pathname.endsWith("/consents")){const response=new Response('{"detail":"untrusted consent failure"}',{status:500});Object.defineProperty(response,"url",{value:url});return response;}return transport(url,init);}));
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"rewrap",reason:"server",detail:undefined});expect(rekeyBody).toBeNull();
});
it("refuses rotation when a refreshed native salt cannot be cached",async()=>{
 const read=api.getCachedSalt;let reads=0;vi.spyOn(api,"getCachedSalt").mockImplementation(async username=>{const salt=await read(username);if(++reads===1)await api.clearCachedSalt(username);return salt;});
 const write=storage.setItem;vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{if(key==="@mindpattern/salt_YWxpY2U")throw new Error("native salt cache unavailable");return write(key,value);});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline"});expect(processingKeys).toEqual([]);
});
it("locks the old native vault before consent preparation can wait on the server",async()=>{
 const transport=fetch;let release:()=>void=()=>{},ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
 vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{const response=await transport(url,init);if(new URL(url).pathname.endsWith("/consents")){ready();await new Promise<void>(resolve=>{release=resolve;});}return response;}));const pending=rotatePassword(input);await Promise.race([started,pending]);
 try{expect(vault.isUnlocked()).toBe(false);}finally{release();await pending;}
});
it.each([false,undefined])("reports a native recovery-kit invalidation acknowledgement of %j honestly",async value=>{
 rekeyResult.recovery_invalidated=value;expect(await rotatePassword(input)).toMatchObject({ok:true,recoveryInvalidated:false});
});
it("refuses the native checkpoint's next durable revision before any server mutation if storage fails",async()=>{
 const write=secureStore.setItem;let chunks=0;vi.spyOn(secureStore,"setItem").mockImplementation(async(key,value)=>{if(key.includes(".chunk.")&&++chunks===2)throw new Error("native checkpoint revision unavailable");return write(key,value);});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline",detail:"native checkpoint revision unavailable"});expect(processingKeys).toEqual([]);expect(rekeyBody).toBeNull();
});
it.each(Array.from({length:8},(_,i)=>i+1))("refuses to adopt a v2 credential after native envelope-cache completion microtask %s replaces its vault",async turns=>{
 v2();const write=storage.setItem;let retired=false;
 vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{await write(key,value);if(key==="@mindpattern/keyenvelope_YWxpY2U"){let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}};queueMicrotask(next);}});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(retired).toBe(true);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));expect(vault.get().authKey).toEqual(OLD_KEYS.authKey);
});
it("recovers the exact native transaction after its commit acknowledgement was lost and the public salt cache refreshed",async()=>{
 const transport=fetch;let committed=false;
 vi.stubGlobal("fetch",vi.fn(async(url:string,init:RequestInit)=>{const path=new URL(url).pathname;if(committed&&["/auth/key-envelope","/consents","/processing/sessions"].some(route=>path.endsWith(route))){const response=new Response('{"detail":"old bearer expired"}',{status:401});Object.defineProperty(response,"url",{value:url});return response;}const response=await transport(url,init);if(path.endsWith("/processing/rekey")&&!committed){committed=true;const lost=new Response('{"detail":"gateway acknowledgement unavailable"}',{status:500});Object.defineProperty(lost,"url",{value:url});return lost;}return response;}));
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"rekey",reason:"server",detail:undefined});expect(await pendingLocalRekey(USER)).toBe(true);const body=structuredClone(rekeyBody);
 await api.cacheSalt("alice",body.new_salt);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.from(OLD_KEYS.dataKey)},USER);
 expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});expect(rekeyBody).toEqual(body);expect(await pendingLocalRekey(USER)).toBe(false);
});
it("makes a completed v2 rotation usable from the native cached unlock salt",async()=>{
 v2();expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v2"});const cached=await api.getCachedSalt("alice");expect(cached).toBe(passwordBody.new_salt);const fresh=derive(NEW,Buffer.from(cached!,"base64"));expect(await api.login("alice",fresh.authKey.toString("base64"))).toEqual({token:"new-bearer",user_id:USER});
});
it("reports an unreadable device-sealed checkpoint as a typed local failure before password verification",async()=>{
 await secureStore.setItem(accountStorageKey.localRekey(new URL(DEFAULT_BASE_URL).origin,USER),JSON.stringify({revision:"damaged",parts:0}));expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline",detail:"Invalid rekey checkpoint index"});expect(processingKeys).toEqual([]);
});
it.each(Array.from({length:12},(_,i)=>i+1))("retires a native biometric proof after data-key replacement at completion microtask %s",async turns=>{
 v2();await enableBiometricUnlock(USER,vault.get().dataKey);vault.lock();const dataKey=await unwrapBiometricDataKey(USER);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.alloc(32),dataKey:dataKey!},USER,{authKeyKnown:false});
 const json=Response.prototype.json;let scheduled=false;
 vi.spyOn(Response.prototype,"json").mockImplementation(async function(this:Response){const data=await json.call(this);if(this.url.endsWith("/auth/login")&&!scheduled){scheduled=true;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER,{authKeyKnown:false});};queueMicrotask(next);}return data;});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));expect(passwordBody).toBeNull();
});
it.each(Array.from({length:8},(_,i)=>i+1))("retires a native v1 completion after biometric cleanup microtask %s replaces its vault",async turns=>{
 await enableBiometricUnlock(USER,vault.get().dataKey);const remove=storage.removeItem;let scheduled=false;
 vi.spyOn(storage,"removeItem").mockImplementation(async key=>{await remove(key);if(key===accountStorageKey.biometricOwner(USER)&&!scheduled){scheduled=true;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);};queueMicrotask(next);}});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});
// Retire before the next native provider is admitted. Later completion
// turns legitimately wait for already admitted PBKDF2, which is not cancellable.
// Preserve the wider discovery baseline; it earns no mutation observations.
const retirementPhases=[{phase:"v1 old derivation",count:7},{phase:"v1 new derivation",count:10},{phase:"v2 old derivation",count:5},{phase:"v2 wrapping derivation",count:2}] as const;
it.each(retirementPhases.flatMap(({phase,count})=>Array.from({length:count},(_,i)=>({phase,turns:i+1}))))("settles a retired native $phase at completion microtask $turns before an unavailable later crypto provider can hold it open",async({phase,turns})=>{
 if(phase.startsWith("v2"))v2();let retired=false,ready!:()=>void,release:()=>void=()=>{};const retirement=new Promise<void>(resolve=>{ready=resolve;});
 const retire=()=>{let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);ready();}};queueMicrotask(next);};
 const read=storage.getItem;let salts=0;
 vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(phase==="v1 old derivation"&&key==="@mindpattern/salt_YWxpY2U"&&++salts===2)retire();if(phase==="v1 new derivation"&&key===accountStorageKey.pendingRotationSalt(USER))retire();return value;});
 const json=Response.prototype.json;vi.spyOn(Response.prototype,"json").mockImplementation(async function(this:Response){const value=await json.call(this);if(phase==="v2 old derivation"&&this.url.endsWith("/auth/key-envelope"))retire();return value;});
 const pbkdf=engine.pbkdf2;let calls=0;
 vi.spyOn(engine,"pbkdf2").mockImplementation(((...args:any[])=>{const callback=args.pop();const call=++calls;const deliver=(error:Error|null,key:Buffer)=>{callback(error,key);if(phase==="v2 wrapping derivation"&&call===3)retire();};if(retired){release=()=>{(pbkdf as(...values:any[])=>unknown)(...args,deliver);};return;}return (pbkdf as(...values:any[])=>unknown)(...args,deliver);}) as any);
 let settled=false;const pending=rotatePassword(input).then(result=>{settled=true;return result;});await Promise.race([retirement,pending]);
 try{for(let i=0;i<256;i++)await Promise.resolve();expect(retired).toBe(true);expect(settled).toBe(true);expect(await pending).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));}finally{release();await pending;}
});
it("retires a native v2 cipher authentication error before classifying its previous envelope",async()=>{
 v2();const create=engine.createDecipheriv;vi.spyOn(engine,"createDecipheriv").mockImplementation((...args)=>{const native=create(...args),aad=native.setAAD.bind(native);native.setAAD=((value:Buffer,...rest:any[])=>{if(value.toString().includes('"context":"envelope"')){vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);throw new Error("native envelope cipher unavailable");}return aad(value,...rest);}) as typeof native.setAAD;return native;});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});
it("locks an old v1 vault after native salt entropy fails following password derivation",async()=>{
 vi.spyOn(engine,"randomBytes").mockImplementation(()=>{throw new Error("native entropy unavailable");});expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"offline",detail:"native entropy unavailable"});expect(vault.isUnlocked()).toBe(false);
});
it("refuses a retired native checkpoint preparation failure before returning queue-retry context",async()=>{
 const write=secureStore.setItem;let chunks=0;vi.spyOn(secureStore,"setItem").mockImplementation(async(key,value)=>{if(key.includes(".chunk.")&&++chunks===2){vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);throw new Error("native checkpoint revision unavailable");}return write(key,value);});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});
it("refuses replacement native credentials even when the old vault allocations are still intact",async()=>{
 const transport=fetch;vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{const response=await transport(url,init);if(new URL(url).pathname.endsWith("/auth/key-envelope"))await api.setSession("replacement-bearer",USER,"alice");return response;});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement-bearer");expect(vault.get().dataKey).toEqual(OLD_KEYS.dataKey);expect(passwordBody).toBeNull();expect(rekeyBody).toBeNull();
});
it("retires native final cleanup before publishing a previously captured successful rotation receipt",async()=>{
 await enableBiometricUnlock(USER,vault.get().dataKey);const remove=storage.removeItem;let removals=0,release!:()=>void,ready!:()=>void;const started=new Promise<void>(resolve=>{ready=resolve;});
 vi.spyOn(storage,"removeItem").mockImplementation(async key=>{await remove(key);if(key===accountStorageKey.biometricOwner(USER)&&++removals===2){ready();await new Promise<void>(resolve=>{release=resolve;});}});
 const pending=rotatePassword(input);await Promise.race([started,pending]);vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);
 try{release?.();expect(await pending).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));}finally{release?.();await pending;}
});
it.each(Array.from({length:12},(_,i)=>i+1))("retires a native initial-checkpoint receipt at microtask %s before unavailable new password work is admitted",async turns=>{
 let retired=false,ready!:()=>void,release:()=>void=()=>{},scheduled=false;const retirement=new Promise<void>(resolve=>{ready=resolve;});const read=storage.getItem;
 vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(key===accountStorageKey.localRekey(new URL(DEFAULT_BASE_URL).origin,USER)&&!scheduled){scheduled=true;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);ready();}};queueMicrotask(next);}return value;});
 const pbkdf=engine.pbkdf2;vi.spyOn(engine,"pbkdf2").mockImplementation(((...args:any[])=>{if(retired){release=()=>{(pbkdf as(...values:any[])=>unknown)(...args);};return;}return (pbkdf as(...values:any[])=>unknown)(...args);}) as any);
 let settled=false;const pending=rotatePassword(input).then(result=>{settled=true;return result;});await Promise.race([retirement,pending]);try{for(let i=0;i<256;i++)await Promise.resolve();expect(retired).toBe(true);expect(settled).toBe(true);expect(await pending).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));}finally{release();await pending;}
});
it.each(["v1","v2"] as const)("preserves a replacement %s login when a native relogin response retires before session adoption",async scheme=>{
 if(scheme==="v2")v2();const json=Response.prototype.json;vi.spyOn(Response.prototype,"json").mockImplementation(async function(this:Response){const value=await json.call(this);if(this.url.endsWith("/auth/login")){await api.setSession("replacement-bearer",USER,"alice");vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}return value;});expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(await secureStore.getItem("@mindpattern/token")).toBe("replacement-bearer");expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});
it.each((["v1","v2"] as const).flatMap(scheme=>Array.from({length:4},(_,index)=>[scheme,index+1] as const)))("preserves native vault custody at %s relogin delivery microtask %s",async(scheme,turns)=>{
 if(scheme==="v2")v2();let retired=false;const json=Response.prototype.json;vi.spyOn(Response.prototype,"json").mockImplementation(async function(this:Response){const value=await json.call(this);if(this.url.endsWith("/auth/login")){let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}};queueMicrotask(next);}return value;});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(retired).toBe(true);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));expect(await secureStore.getItem("@mindpattern/token")).toBe("old-bearer");
});
it.each(Array.from({length:4},(_,i)=>i+1))("refuses native envelope admission after checkpoint retirement at completion microtask %s",async turns=>{
 let reads=0,retired=false,ready!:()=>void,release:()=>void=()=>{};const retirement=new Promise<void>(resolve=>{ready=resolve;});const read=storage.getItem,transport=fetch;
 vi.spyOn(storage,"getItem").mockImplementation(async key=>{const value=await read(key);if(key===accountStorageKey.localRekey(new URL(DEFAULT_BASE_URL).origin,USER)&&++reads===2){let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);ready();}};queueMicrotask(next);}return value;});
 vi.stubGlobal("fetch",async(url:string,init:RequestInit)=>{if(retired&&new URL(url).pathname.endsWith("/auth/key-envelope"))await new Promise<void>(resolve=>{release=resolve;});return transport(url,init);});
 let settled=false;const pending=rotatePassword(input).then(result=>{settled=true;return result;});await Promise.race([retirement,pending]);try{for(let i=0;i<256;i++)await Promise.resolve();expect(retired).toBe(true);expect(settled).toBe(true);expect(await pending).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));}finally{release();await pending;}
});
it("preserves an authenticated in-process rollback floor across rotation after native guard persistence fails",async()=>{
 const write=storage.setItem,slot=accountStorageKey.entryVersions(USER);const failure=vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{if(key===slot)throw new Error("native guard storage unavailable");return write(key,value);});await expect(observeEntryVersions(USER,vault.get().dataKey,[{clientEntryId:"remembered-entry",contentVersion:7}])).resolves.toEqual({rolledBack:[],advanced:true});failure.mockRestore();expect(await knownEntryVersion(USER,OLD_KEYS.dataKey,"remembered-entry")).toBe(7);expect(await storage.getItem(slot)).toBeNull();expect(await rotatePassword(input)).toMatchObject({ok:true,scheme:"v1"});const fresh=derive(NEW,Buffer.from(rekeyBody.new_salt,"base64"));expect(await knownEntryVersion(USER,fresh.dataKey,"remembered-entry")).toBe(7);
});
it.each(Array.from({length:12},(_,i)=>i+1))("retires failed native v2 relogin cleanup at biometric-removal delivery microtask %s",async turns=>{
 v2();loginError=500;await enableBiometricUnlock(USER,vault.get().dataKey);const remove=storage.removeItem;let retired=false,scheduled=false;vi.spyOn(storage,"removeItem").mockImplementation(async key=>{await remove(key);if(key===accountStorageKey.biometricOwner(USER)&&!scheduled){scheduled=true;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}};queueMicrotask(next);}});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(retired).toBe(true);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});
it.each(Array.from({length:24},(_,i)=>i+1))("preserves a replacement native vault after failed relogin's cache-envelope delivery microtask %s",async turns=>{
 v2();loginError=500;let retired=false,scheduled=false;const write=storage.setItem;vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{await write(key,value);if(key.startsWith("@mindpattern/keyenvelope_")&&!scheduled){scheduled=true;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}};queueMicrotask(next);}});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(retired).toBe(true);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));
});

it.each(Array.from({length:16},(_,i)=>i+1))("preserves native unlock cache custody at relogin username-delivery microtask %s",async turns=>{
 v2();let retired=false,scheduled=false;const write=storage.setItem;vi.spyOn(storage,"setItem").mockImplementation(async(key,value)=>{await write(key,value);if(key==="@mindpattern/username"&&!scheduled){scheduled=true;let remaining=turns;const next=()=>{if(--remaining>0)queueMicrotask(next);else{retired=true;vault.unlock({masterKey:Buffer.alloc(32),authKey:Buffer.from(OLD_KEYS.authKey),dataKey:Buffer.alloc(32,13)},USER);}};queueMicrotask(next);}});
 expect(await rotatePassword(input)).toEqual({ok:false,stage:"verify",reason:"server",detail:undefined});expect(retired).toBe(true);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,13));expect(await api.getCachedSalt("alice")).toBe(SALT.toString("base64"));
});
