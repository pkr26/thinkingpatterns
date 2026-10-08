import crypto from "node:crypto";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { api, setBaseUrl } from "../src/api/client";
import { buildRegistrationEnvelope, cacheEnvelope, cachedEnvelope, clearCachedEnvelope, fetchEnvelope, sanitizeEnvelopeResponse, unwrapSessionDataKey, type EnvelopeInfo } from "../src/keyScheme";
import { engine } from "./helpers/nodeEngine";
import storage from "./helpers/storageMock";
import { setSecureStoreBackend } from "../src/secureStore";
import { __resetLocalKeyLifecycleForTests } from "../src/localWriteGuard";
import { runTestControl } from "./helpers/testControl";

const USER="a".repeat(32), PASSWORD="correct envelope password", SALT=Buffer.alloc(16,3);
const PARAMS={algorithm:"pbkdf2-sha256" as const,version:1,iterations:100000};
const DATA=Buffer.alloc(32,7);
function master(salt=SALT,iterations=PARAMS.iterations){return crypto.pbkdf2Sync(PASSWORD,salt,iterations,32,"sha256");}
function kek(key:Buffer,salt=SALT){return Buffer.from(crypto.hkdfSync("sha256",key,salt,Buffer.from("mindpattern/envelope/v2"),32));}
function aad(iterations:number,username="alice"){return Buffer.from(JSON.stringify({context:"envelope",kdf_params:{algorithm:"pbkdf2-sha256",version:1,iterations},username}));}
function seal(salt=SALT,iterations=PARAMS.iterations):EnvelopeInfo{
  const nonce=Buffer.alloc(12,9),cipher=crypto.createCipheriv("aes-256-gcm",kek(master(salt,iterations),salt),nonce);cipher.setAAD(aad(iterations));
  return {scheme:"v2",saltB64:salt.toString("base64"),kdfParams:{...PARAMS,iterations},wrappedB64:Buffer.concat([nonce,cipher.update(DATA),cipher.final(),cipher.getAuthTag()]).toString("base64")};
}
const ENVELOPE=seal();
function response(value:unknown,status=200){const result=new Response(JSON.stringify(value),{status});Object.defineProperty(result,"url",{value:"http://localhost:8000/api/v1/auth/key-envelope"});return result;}
function wire(envelope=ENVELOPE){return {key_scheme:envelope.scheme,salt:envelope.saltB64,kdf_params:envelope.kdfParams,wrapped_data_key:envelope.wrappedB64};}
beforeEach(async()=>{vi.restoreAllMocks();storage.__reset();runTestControl(setSecureStoreBackend,null);runTestControl(__resetLocalKeyLifecycleForTests);await api.setSession("envelope-token",USER,"alice");});
afterEach(async()=>{vi.restoreAllMocks();await api.clearSession();vi.unstubAllGlobals();});

it.each([null,undefined,0,"envelope",[],{},{salt:3,key_scheme:"v1"},{salt:Buffer.alloc(7).toString("base64"),key_scheme:"v1"},{...wire(),key_scheme:"v3"},{...wire(),kdf_params:null},{...wire(),kdf_params:{...PARAMS,algorithm:"argon2id"}},{...wire(),kdf_params:{...PARAMS,extra:1}},{...wire(),wrapped_data_key:0},{...wire(),wrapped_data_key:Buffer.alloc(59).toString("base64")},{...wire(),wrapped_data_key:Buffer.alloc(61).toString("base64")}])("refuses an unusable server envelope %j",raw=>{expect(sanitizeEnvelopeResponse(raw)).toBeNull();});
it("accepts the minimum salt and ignores inert v1 envelope extras",()=>{
  const salt=Buffer.alloc(8,2).toString("base64");
  expect(sanitizeEnvelopeResponse({key_scheme:"v1",salt,kdf_params:"untrusted",wrapped_data_key:7})).toEqual({scheme:"v1",saltB64:salt,kdfParams:null,wrappedB64:null});
  expect(sanitizeEnvelopeResponse(wire())).toEqual(ENVELOPE);
});
it.each([404,400,500])("keeps HTTP %s envelope availability distinct from unusable answered data",async status=>{
  vi.stubGlobal("fetch",vi.fn(async()=>response({detail:"server unavailable"},status)));
  expect(await fetchEnvelope()).toEqual({status:status===404?"legacy":"unreachable"});
});
it("keeps a native connection failure retryable",async()=>{vi.stubGlobal("fetch",vi.fn(async()=>{throw new TypeError("native connection failed");}));expect(await fetchEnvelope()).toEqual({status:"unreachable"});});
it.each(["valid","invalid"])("classifies an answered %s envelope",async kind=>{vi.stubGlobal("fetch",vi.fn(async()=>response(kind==="valid"?wire():{key_scheme:"v3"})));expect(await fetchEnvelope()).toEqual(kind==="valid"?{status:"ok",envelope:ENVELOPE}:{status:"invalid"});});

it("creates fresh storage keys that the independent server envelope reader can open",async()=>{
  const first=await buildRegistrationEnvelope(PASSWORD,SALT,"alice"),second=await buildRegistrationEnvelope(PASSWORD,SALT,"alice");
  expect(first.kdfParams).toEqual({algorithm:"pbkdf2-sha256",version:1,iterations:600000});expect(first.dataKey).toHaveLength(32);
  expect(second.dataKey.equals(first.dataKey)).toBe(false);expect(second.wrappedB64).not.toBe(first.wrappedB64);
  for(const result of [first,second]){const blob=Buffer.from(result.wrappedB64,"base64");expect(blob).toHaveLength(60);const reader=crypto.createDecipheriv("aes-256-gcm",kek(master(SALT,600000)),blob.subarray(0,12));reader.setAAD(aad(600000));reader.setAuthTag(blob.subarray(-16));expect(Buffer.concat([reader.update(blob.subarray(12,-16)),reader.final()])).toEqual(result.dataKey);}
});
it("erases owned registration derivations after native wrapping succeeds",async()=>{
  const hkdf=engine.hkdfSync,cipher=engine.createCipheriv,observed:Buffer[]=[];
  vi.spyOn(engine,"hkdfSync").mockImplementation((...args)=>{observed.push(args[1] as Buffer);return hkdf(...args);});
  vi.spyOn(engine,"createCipheriv").mockImplementation((...args)=>{observed.push(args[1]);return cipher(...args);});
  const result=await buildRegistrationEnvelope(PASSWORD,SALT,"alice");expect(observed).toHaveLength(2);for(const key of observed)expect(key).toEqual(Buffer.alloc(32));expect(result.dataKey.equals(Buffer.alloc(32))).toBe(false);
});
it("erases an unreturned fresh data key when the native wrapping provider fails",async()=>{
  const cipher=engine.createCipheriv;let retained:Buffer|undefined;
  vi.spyOn(engine,"createCipheriv").mockImplementation((...args)=>{const native=cipher(...args);native.update=(value:Buffer)=>{retained=value;throw new Error("native cipher update failed");};return native;});
  await expect(buildRegistrationEnvelope(PASSWORD,SALT,"alice")).rejects.toThrow("native cipher update failed");
  expect(retained).toBeDefined();expect(retained).toEqual(Buffer.alloc(32));
});
it("reuses a matching borrowed master without erasing it",async()=>{
  const borrowed=master(),original=Buffer.from(borrowed);const result=await unwrapSessionDataKey({password:"deliberately wrong",username:"alice",envelope:ENVELOPE,derivedMaster:{key:borrowed,saltB64:ENVELOPE.saltB64,iterations:100000}});
  expect(result).toEqual({ok:true,dataKey:DATA});expect(borrowed).toEqual(original);
});
it("opens an independently wrapped envelope with the minimum eight-byte salt",async()=>{
  const envelope=seal(Buffer.alloc(8,3));
  expect(await unwrapSessionDataKey({password:PASSWORD,username:"alice",envelope})).toEqual({ok:true,dataKey:DATA});
});
it("refuses impossible wrapped material even when the native derivation provider is unavailable",async()=>{
  vi.spyOn(engine,"hkdfSync").mockImplementation(()=>{throw new Error("native HKDF unavailable");});
  expect(await unwrapSessionDataKey({password:PASSWORD,username:"alice",envelope:{...ENVELOPE,wrappedB64:Buffer.alloc(59).toString("base64")}})).toEqual({ok:false,reason:"bad-envelope"});
});
it("keeps a native cipher-initialization failure on the typed unusable-envelope surface",async()=>{
  vi.spyOn(engine,"createDecipheriv").mockImplementation(()=>{throw new Error("native AES provider unavailable");});
  expect(await unwrapSessionDataKey({password:PASSWORD,username:"alice",envelope:ENVELOPE})).toEqual({ok:false,reason:"bad-envelope"});
});
it.each(["omitted","null","salt","iterations"])("derives an owned master for a %s handoff and wipes its native provider buffers",async mode=>{
  const borrowed=Buffer.alloc(32,8),hkdf=engine.hkdfSync,cipher=engine.createDecipheriv,observed:Buffer[]=[];
  vi.spyOn(engine,"hkdfSync").mockImplementation((...args)=>{observed.push(args[1] as Buffer);return hkdf(...args);});
  vi.spyOn(engine,"createDecipheriv").mockImplementation((...args)=>{observed.push(args[1]);return cipher(...args);});
  const derivedMaster=mode==="null"?null:mode==="omitted"?undefined:{key:borrowed,saltB64:mode==="salt"?Buffer.alloc(16,4).toString("base64"):ENVELOPE.saltB64,iterations:mode==="iterations"?600000:100000};
  expect(await unwrapSessionDataKey({password:PASSWORD,username:"alice",envelope:ENVELOPE,derivedMaster})).toEqual({ok:true,dataKey:DATA});expect(borrowed).toEqual(Buffer.alloc(32,8));expect(observed).toHaveLength(2);for(const key of observed)expect(key).toEqual(Buffer.alloc(32));
});
it.each([{...ENVELOPE,scheme:"v1" as const},{...ENVELOPE,kdfParams:null},{...ENVELOPE,wrappedB64:null},{...ENVELOPE,saltB64:Buffer.alloc(7).toString("base64")},{...ENVELOPE,wrappedB64:Buffer.alloc(59).toString("base64")}])("refuses malformed unlock material before derivation %j",async envelope=>{expect(await unwrapSessionDataKey({password:PASSWORD,username:"alice",envelope})).toEqual({ok:false,reason:"bad-envelope"});});
it.each(["password","username","tag"])("reports an authenticated envelope mismatch for %s",async kind=>{
  const envelope={...ENVELOPE};if(kind==="tag"){const blob=Buffer.from(envelope.wrappedB64!,"base64");blob[59]^=1;envelope.wrappedB64=blob.toString("base64");}
  expect(await unwrapSessionDataKey({password:kind==="password"?"wrong":PASSWORD,username:kind==="username"?"bob":"alice",envelope})).toEqual({ok:false,reason:"tamper"});
});
it.each(["v1","v2"] as const)("retains an origin-bound %s envelope for offline unlock and removes it on request",async scheme=>{
  const envelope:EnvelopeInfo=scheme==="v1"?{scheme,saltB64:ENVELOPE.saltB64,kdfParams:null,wrappedB64:null}:ENVELOPE;
  expect(await cachedEnvelope("alice")).toBeNull();await cacheEnvelope("alice",envelope);expect(await cachedEnvelope("alice")).toEqual(envelope);
  await clearCachedEnvelope("alice");expect(await cachedEnvelope("alice")).toBeNull();
  await cacheEnvelope("alice",envelope);await setBaseUrl("https://another.example");expect(await cachedEnvelope("alice")).toBeNull();
  await setBaseUrl("http://127.0.0.1:8000");expect(await cachedEnvelope("alice")).toBeNull();
});
it.each([{...ENVELOPE,kdfParams:{...PARAMS,iterations:99999}},{...ENVELOPE,kdfParams:{...PARAMS,iterations:10000001}},{...ENVELOPE,wrappedB64:Buffer.alloc(59).toString("base64")}])("refuses an installed corrupt cached envelope %j",async envelope=>{await api.cacheKeyEnvelope("alice",envelope);expect(await cachedEnvelope("alice")).toBeNull();});
