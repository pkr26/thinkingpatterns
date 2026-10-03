import React from "react";
import { afterEach,beforeEach,describe,expect,it,vi } from "vitest";
import { Alert } from "react-native";
vi.mock("../../src/api/client",async importOriginal=>{
 const actual=await importOriginal<typeof import("../../src/api/client")>();
 const {makeApiMock}=await import("../helpers/apiMock");
 return {...actual,api:{...makeApiMock(),recoverLogin:vi.fn(),resetPasswordWithRecovery:vi.fn(async()=>({}))}};
});
vi.mock("../../src/crypto/MindPatternCrypto",async importOriginal=>({...await importOriginal<typeof import("../../src/crypto/MindPatternCrypto")>(),deriveKeysAsync:vi.fn()}));
vi.mock("../../src/crypto/kdf",async importOriginal=>({...await importOriginal<typeof import("../../src/crypto/kdf")>(),deriveMasterKeyAsync:vi.fn()}));
vi.mock("../../src/unlockProof",()=>({storeUnlockProof:vi.fn(async()=>{}),verifyUnlockProof:vi.fn(async()=>"ok"),clearUnlockProof:vi.fn(async()=>{}),unlockProofExists:vi.fn(async()=>false)}));
vi.mock("../../src/localRekey",()=>({resumeLocalRekey:vi.fn(async()=>{}),pendingLocalRekey:vi.fn(async()=>false),pendingLocalRekeyOldSalt:vi.fn(async()=>null)}));
vi.mock("../../src/biometricUnlock",()=>({biometricsSupported:vi.fn(async()=>true),hasBiometricUnlock:vi.fn(async()=>true),unwrapBiometricDataKey:vi.fn(),disableBiometricUnlock:vi.fn(async()=>{})}));
const session=vi.hoisted(()=>({markLoggedIn:vi.fn(),refreshActiveDays:vi.fn(async()=>{}),signOut:vi.fn(async()=>{})}));
vi.mock("../../src/store",()=>({useSession:()=>session}));
import {api} from "../../src/api/client";
import {deriveKeysAsync} from "../../src/crypto/MindPatternCrypto";
import {deriveMasterKeyAsync} from "../../src/crypto/kdf";
import {unwrapBiometricDataKey} from "../../src/biometricUnlock";
import {vault} from "../../src/vault";
import {changeLocalOrigin,changeLocalSessionOwner,__resetLocalKeyLifecycleForTests} from "../../src/localWriteGuard";
import {LoginScreen} from "../../src/screens/LoginScreen";
import {UnlockScreen} from "../../src/screens/UnlockScreen";
import {recoverAccountWithKey} from "../../src/recoveryFlow";
import {sealDataKeyForRecoveryV2} from "../../src/crypto/recovery";
import {render,typeInto,firePress,flush,act,inputByPlaceholder} from "../helpers/rtr";
import {resetApi} from "../helpers/apiMock";
const A="user-1",B="user-2";
function deferred<T>(){let resolve!:(value:T)=>void;const promise=new Promise<T>(r=>{resolve=r;});return {promise,resolve};}
function keys(value=3){return {masterKey:Buffer.alloc(32,value),authKey:Buffer.alloc(32,value),dataKey:Buffer.alloc(32,value)};}
const roots:Array<Awaited<ReturnType<typeof render>>>=[];
beforeEach(()=>{resetApi(api as never);__resetLocalKeyLifecycleForTests();vault.lock();vi.mocked(deriveKeysAsync).mockReset();vi.mocked(deriveMasterKeyAsync).mockReset();vi.mocked(unwrapBiometricDataKey).mockReset();vi.mocked(api.recoverLogin).mockReset();session.markLoggedIn.mockClear();session.refreshActiveDays.mockClear();Alert.alert.mockClear();});
afterEach(async()=>{await act(async()=>{for(const root of roots)root.unmount();});roots.length=0;});
async function login(){const root=await render(<LoginScreen navigation={{navigate:vi.fn()}}/>);roots.push(root);await typeInto(root,"username","alice");await typeInto(root,"password","Correct horse!");return root;}
describe("authentication attempt custody",()=>{
 it("does not dispatch an old-origin verifier after suspended login derivation",async()=>{
  const gate=deferred<ReturnType<typeof keys>>(),owned=keys();vi.mocked(deriveKeysAsync).mockImplementation(()=>gate.promise);
  const root=await login();await firePress(root,"Sign in");await flush();changeLocalOrigin();
  await act(async()=>{gate.resolve(owned);});await flush();
  expect(api.login).not.toHaveBeenCalled();expect(vault.isUnlocked()).toBe(false);expect(owned.dataKey.every(byte=>byte===0)).toBe(true);
 });
 it("does not reinstall a biometric key after unmount and replacement login",async()=>{
  const gate=deferred<Buffer|null>(),owned=Buffer.alloc(32,5);vi.mocked(unwrapBiometricDataKey).mockImplementation(()=>gate.promise);
  const root=await render(<UnlockScreen navigation={{navigate:vi.fn()}}/>);roots.push(root);await flush();await firePress(root,"Unlock with biometrics");await flush();
  await act(async()=>root.unmount());changeLocalSessionOwner(B);vault.unlock(keys(9),B);
  await act(async()=>{gate.resolve(owned);});await flush();
  expect(vault.ownerUserId()).toBe(B);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,9));expect(owned.every(byte=>byte===0)).toBe(true);
 });
 it("does not lock a replacement vault when a stale password derivation fails",async()=>{
  const gate=deferred<ReturnType<typeof keys>>();vi.mocked(deriveKeysAsync).mockImplementation(()=>gate.promise);
  const root=await render(<UnlockScreen navigation={{navigate:vi.fn()}}/>);roots.push(root);await typeInto(root,"password","Correct horse!");
  await act(async()=>{void inputByPlaceholder(root,"password").props.onSubmitEditing();});await flush();
  expect(deriveKeysAsync).toHaveBeenCalledTimes(1);
  await act(async()=>root.unmount());changeLocalSessionOwner(B);vault.unlock(keys(9),B);
  await act(async()=>{gate.resolve(keys());});await flush();
  expect(vault.ownerUserId()).toBe(B);expect(vault.get().dataKey).toEqual(Buffer.alloc(32,9));
 });
 it("does not reset or clear a replacement session after suspended recovery derivation",async()=>{
  const recovery=Buffer.alloc(32,7),data=Buffer.alloc(32,8),gate=deferred<Buffer>(),master=Buffer.alloc(32,6);
  vi.mocked(api.recoverLogin).mockResolvedValue({token:"recovery-token",user_id:A,username:"alice",recovery_scheme:"v2",recovery_wrapped_data_key:sealDataKeyForRecoveryV2(recovery,data,A).toString("base64")} as never);
  vi.mocked(deriveMasterKeyAsync).mockImplementation(()=>gate.promise);
  const pending=recoverAccountWithKey("alice",recovery.toString("base64"),"New credential long!").catch(error=>error);await flush();
  changeLocalOrigin();changeLocalSessionOwner(B);await act(async()=>{gate.resolve(master);});await flush();
  expect(await pending).toBeInstanceOf(Error);expect(api.resetPasswordWithRecovery).not.toHaveBeenCalled();expect(api.clearSession).not.toHaveBeenCalled();expect(master.every(byte=>byte===0)).toBe(true);
 });
});
