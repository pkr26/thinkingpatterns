import { drainPortalDraftWritesForTests, runTestControl } from "./helpers/testControl";
import { afterEach,describe,it,expect,vi } from "vitest";
import { act } from "react";
import { PatientsView } from "../src/views/PatientsView";
import { rawMatchSpans } from "../src/views/PatientView";
import { api,auth,clearSession } from "../src/api";
import { deriveMasterKey,derivePortalKeys,generateTherapistKeyPair,unlockWrapPrivateKeyWithNotesKey,encryptNote,decryptNoteAny,toBase64,fromBase64,openNotesKeyring,wipeNotesKeyring,openSealedPrivateKey,sealPrivateKeyForUpload } from "../src/crypto";
import { loadPortalDraft,savePortalDraft } from "../src/noteDrafts";
import { setKvBackendForTests,StorageReadError } from "../src/kvstore";
import { render,press,typeInto,flush,textOf } from "./helpers/rtr";
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();clearSession();});
const THERAPIST="a".repeat(32),PATIENT="b".repeat(32),USERNAME="drportal",PW="copper-orchard-current!";
async function fixture(){const salt=new Uint8Array(16).fill(7);const keys=await derivePortalKeys(await deriveMasterKey(PW,salt));const pair=await generateTherapistKeyPair(keys.wrapKek,USERNAME);const unlocked=await unlockWrapPrivateKeyWithNotesKey(keys.wrapKek,pair.wrapKeyBlobB64,USERNAME);return {salt,keys,pair,unlocked};}
const patient={user_id:PATIENT,username:"patient",status:"active",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:null,wrapped_key:null};
async function securityRoot(f:Awaited<ReturnType<typeof fixture>>){
 vi.spyOn(auth,"saltFor").mockResolvedValue({salt:toBase64(f.salt)});
 const me={user_id:THERAPIST,username:USERNAME,display_name:"Doctor",wrap_pub_key:f.pair.publicKeySpkiB64,wrap_key_blob:f.pair.wrapKeyBlobB64,custody_version:0,notes_keyring_blob:null as string|null};
 vi.spyOn(api,"me").mockImplementation(async()=>me);vi.spyOn(api,"patients").mockResolvedValue([patient]);
 const root=await render(<PatientsView displayName="Doctor" session={{username:USERNAME,userId:THERAPIST,noteKey:f.keys.noteKey,noteKeyV2:f.unlocked.noteKeyV2,privateKey:f.unlocked.privateKey,publicKeyB64:f.pair.publicKeySpkiB64}} onOpen={()=>{}} onSignOut={()=>{}} onSessionsEnded={()=>{}}/>);await flush();await press(root,"Show account security");return {root,me};
}
describe("real crypto notes custody",()=>{
 it("repairs a legacy interrupted private wrap only after confirming custody for both password generations and historical revisions",async()=>{
  const f=await fixture();const pendingSalt=new Uint8Array(16).fill(9);const intended=await derivePortalKeys(await deriveMasterKey("intended-orchard-willow!",pendingSalt));
  const privateBytes=await openSealedPrivateKey(f.keys.wrapKek,f.pair.wrapKeyBlobB64,USERNAME);if(!privateBytes)throw new Error("fixture failed");
  const pendingWrap=await sealPrivateKeyForUpload(intended.wrapKek,privateBytes,USERNAME);privateBytes.fill(0);
  const old=await encryptNote(f.keys.noteKey,THERAPIST,PATIENT,"note","old password revision");const newer=await encryptNote(intended.noteKey,THERAPIST,PATIENT,"note","interrupted generation text");
  const saltSlot=`mindpattern.interruptedRotateSalt.${THERAPIST}`;window.sessionStorage.setItem(saltSlot,toBase64(pendingSalt));
  const {root,me}=await securityRoot(f);me.wrap_key_blob=pendingWrap;
  vi.spyOn(api,"notes").mockResolvedValue({notes:[{id:"n",client_note_id:"note",blob:newer.blobB64,pattern_pid:null,created_at:"2026-09-01",updated_at:"2026-09-02",version:2}],nextOffset:null,revision:"R1"});vi.spyOn(api,"noteRevisions").mockResolvedValue([{id:"r",blob:old.blobB64,created_at:"2026-09-01"}]);
  const installed=vi.spyOn(api,"installNotesCustody").mockImplementation(async value=>{me.notes_keyring_blob=value.notes_keyring_blob;me.custody_version=value.custody_version;return null;});const rotated=vi.spyOn(api,"rotateWrapKey").mockResolvedValue(null);const credential=vi.spyOn(api,"changePasswordAtomic");
  await typeInto(root,"the one you sign in with",PW);await typeInto(root,"The password you were changing to","intended-orchard-willow!");await press(root,"Recover sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("sealed under your current sign-in password again"),{timeout:5000});
  expect(installed.mock.invocationCallOrder[0]).toBeLessThan(rotated.mock.invocationCallOrder[0]!);expect(rotated.mock.calls[0]![1]).toBe(f.pair.publicKeySpkiB64);expect(rotated.mock.calls[0]![3]).toBe(1);expect(credential).not.toHaveBeenCalled();expect(window.sessionStorage.getItem(saltSlot)).toBeNull();
  const ring=await openNotesKeyring(f.keys.wrapKek,THERAPIST,me.notes_keyring_blob!);await expect(decryptNoteAny(ring.active,f.keys.noteKey,THERAPIST,PATIENT,"note",old.blobB64,ring.historical)).resolves.toBe("old password revision");await expect(decryptNoteAny(ring.active,f.keys.noteKey,THERAPIST,PATIENT,"note",newer.blobB64,ring.historical)).resolves.toBe("interrupted generation text");
  const repaired=await unlockWrapPrivateKeyWithNotesKey(f.keys.wrapKek,rotated.mock.calls[0]![2],USERNAME);expect(toBase64(repaired.noteKeyV2)).toBe(toBase64(f.unlocked.noteKeyV2));wipeNotesKeyring(ring);await act(async()=>root.unmount());
 });
 it("fresh-login password custody unlocks all legacy/v2 notes and revisions without rewriting any ciphertext",async()=>{
  const f=await fixture(); const legacy=await encryptNote(f.keys.noteKey,THERAPIST,PATIENT,"legacy","legacy clinical text");const v2=await encryptNote(f.unlocked.noteKeyV2,THERAPIST,PATIENT,"identity","v2 clinical text");const revision=await encryptNote(f.keys.noteKey,THERAPIST,PATIENT,"identity","old clinical revision");
  const {root}=await securityRoot(f);
  const rows=[{id:"n1",client_note_id:"legacy",blob:legacy.blobB64},{id:"n2",client_note_id:"identity",blob:v2.blobB64}].map(row=>({...row,pattern_pid:null,created_at:"2026-09-01",updated_at:"2026-09-01",version:1}));
  vi.spyOn(api,"notes").mockResolvedValue({notes:rows,nextOffset:null,revision:"R1"});vi.spyOn(api,"noteRevisions").mockImplementation(async id=>id==="n2"?[{id:"rev1",blob:revision.blobB64,created_at:"2026-09-01"}]:[]);
  const atomic=vi.spyOn(api,"changePasswordAtomic").mockResolvedValue(null);const separate=vi.spyOn(api,"rotateWrapKey");const rewrite=vi.spyOn(api,"rekeyNotes");
  await typeInto(root,"Current password",PW);await typeInto(root,"New password","fresh-copper-willow-Strong!");await typeInto(root,"Repeat new password","fresh-copper-willow-Strong!");await press(root,"Change password");await vi.waitFor(()=>expect(atomic).toHaveBeenCalledTimes(1),{timeout:5000});
  const payload=atomic.mock.calls[0]![0];expect(payload.wrap_pub_key).toBe(f.pair.publicKeySpkiB64);expect(payload.custody_version).toBe(1);expect(separate).not.toHaveBeenCalled();expect(rewrite).not.toHaveBeenCalled();
  const fresh=await derivePortalKeys(await deriveMasterKey("fresh-copper-willow-Strong!",fromBase64(payload.new_salt)));const unlocked=await unlockWrapPrivateKeyWithNotesKey(fresh.wrapKek,payload.wrap_key_blob,USERNAME);const ring=await openNotesKeyring(fresh.wrapKek,THERAPIST,payload.notes_keyring_blob);
  await expect(decryptNoteAny(ring.active,fresh.noteKey,THERAPIST,PATIENT,"legacy",legacy.blobB64,ring.historical)).resolves.toBe("legacy clinical text");
  await expect(decryptNoteAny(ring.active,fresh.noteKey,THERAPIST,PATIENT,"identity",v2.blobB64,ring.historical)).resolves.toBe("v2 clinical text");
  await expect(decryptNoteAny(ring.active,fresh.noteKey,THERAPIST,PATIENT,"identity",revision.blobB64,ring.historical)).resolves.toBe("old clinical revision");
  expect(toBase64(unlocked.noteKeyV2)).toBe(toBase64(f.unlocked.noteKeyV2));await expect(openNotesKeyring(fresh.wrapKek,"another-owner",payload.notes_keyring_blob)).rejects.toThrow();wipeNotesKeyring(ring);await act(async()=>root.unmount());
 });
 it("publishes a replacement sharing identity only after durable custody confirmation; fresh login still opens identity notes",async()=>{
  const f=await fixture();const saved=await encryptNote(f.unlocked.noteKeyV2,THERAPIST,PATIENT,"v2-note","permanent chart text");const {root,me}=await securityRoot(f);
  vi.spyOn(api,"notes").mockResolvedValue({notes:[{id:"n",client_note_id:"v2-note",blob:saved.blobB64,pattern_pid:null,created_at:"2026-09-01",updated_at:"2026-09-01",version:1}],nextOffset:null,revision:"R1"});vi.spyOn(api,"noteRevisions").mockResolvedValue([]);
  const installed=vi.spyOn(api,"installNotesCustody").mockImplementation(async value=>{me.notes_keyring_blob=value.notes_keyring_blob;me.custody_version=value.custody_version;return null;});const rotated=vi.spyOn(api,"rotateWrapKey").mockResolvedValue(null);
  await typeInto(root,"Current password (to authorize rotation)",PW);await act(async()=>{root.root.findAllByType("input").find(n=>n.props["aria-label"]==="Confirm sharing-key rotation")!.props.onChange({target:{checked:true}});});await press(root,"Rotate sharing key");await vi.waitFor(()=>expect(rotated).toHaveBeenCalledTimes(1),{timeout:5000});
  expect(installed.mock.invocationCallOrder[0]).toBeLessThan(rotated.mock.invocationCallOrder[0]!);expect(rotated.mock.calls[0]![3]).toBe(1);
  const next=await unlockWrapPrivateKeyWithNotesKey(f.keys.wrapKek,rotated.mock.calls[0]![2],USERNAME);expect(toBase64(next.noteKeyV2)).not.toBe(toBase64(f.unlocked.noteKeyV2));const ring=await openNotesKeyring(f.keys.wrapKek,THERAPIST,me.notes_keyring_blob!);
  await expect(decryptNoteAny(ring.active,f.keys.noteKey,THERAPIST,PATIENT,"v2-note",saved.blobB64,ring.historical)).resolves.toBe("permanent chart text");wipeNotesKeyring(ring);await act(async()=>root.unmount());
 });
 it("fails closed if any historical revision cannot authenticate",async()=>{
  const f=await fixture();const note=await encryptNote(f.unlocked.noteKeyV2,THERAPIST,PATIENT,"note","valid current");const {root}=await securityRoot(f);vi.spyOn(api,"notes").mockResolvedValue({notes:[{id:"n",client_note_id:"note",blob:note.blobB64,pattern_pid:null,created_at:"2026-09-01",updated_at:"2026-09-01",version:2}],nextOffset:null});vi.spyOn(api,"noteRevisions").mockResolvedValue([{id:"rev1",blob:"Y29ycnVwdA==",created_at:"2026-09-01"}]);const atomic=vi.spyOn(api,"changePasswordAtomic").mockResolvedValue(null);
  await typeInto(root,"Current password",PW);await typeInto(root,"New password","fresh-copper-willow-Strong!");await typeInto(root,"Repeat new password","fresh-copper-willow-Strong!");await press(root,"Change password");await vi.waitFor(()=>expect(textOf(root)).toContain("could not be authenticated"),{timeout:5000});expect(atomic).not.toHaveBeenCalled();await act(async()=>root.unmount());
 });
 it("encrypts pattern-scoped drafts and exact retry bodies, rejects wrong account/patient, and reports failed storage reads",async()=>{
  const key=new Uint8Array(32).fill(7);const map=new Map<string,string>();runTestControl(setKvBackendForTests, {getItem:async id=>map.get(id)??null,setItem:async(id,value)=>{map.set(id,value);},removeItem:async id=>{map.delete(id);}});
  const state={text:{general:"private general", "topic:work":"private work", "topic:family":"private family"},editing:{id:"n",text:"private edit"},pending:{general:{client_note_id:"exact-id",blob:"ciphertext",text:"private general",pattern_pid:null}}};
  await savePortalDraft(THERAPIST,PATIENT,key,state);expect([...map.values()].join("")).not.toContain("private");expect(await loadPortalDraft(THERAPIST,PATIENT,[key])).toEqual(state);expect(await loadPortalDraft("other",PATIENT,[key])).toBeNull();
  map.set(`portal.draft.${THERAPIST}.other`,map.values().next().value!);await expect(loadPortalDraft(THERAPIST,"other",[key])).rejects.toThrow("authenticated");runTestControl(setKvBackendForTests, {getItem:async()=>{throw new Error("blocked");},setItem:async()=>{},removeItem:async()=>{}});await expect(loadPortalDraft(THERAPIST,PATIENT,[key])).rejects.toBeInstanceOf(StorageReadError);
 });
 it("drains queued draft writes before a test backend generation is replaced",async()=>{
  const key=new Uint8Array(32).fill(8);const first=new Map<string,string>();const successor=new Map<string,string>();let writes=0;let release!:()=>void;const gate=new Promise<void>(resolve=>{release=resolve;});
  runTestControl(setKvBackendForTests, {getItem:async id=>first.get(id)??null,setItem:async(id,value)=>{writes+=1;if(writes===1)await gate;first.set(id,value);},removeItem:async id=>{first.delete(id);}});
  const one=savePortalDraft(THERAPIST,PATIENT,key,{text:{general:"first generation"},editing:null,pending:{}});
  await vi.waitFor(()=>expect(writes).toBe(1));
  const two=savePortalDraft(THERAPIST,PATIENT,key,{text:{general:"final generation"},editing:null,pending:{}});
  const drained=drainPortalDraftWritesForTests();release();await Promise.all([one,two,drained]);
  runTestControl(setKvBackendForTests, {getItem:async id=>successor.get(id)??null,setItem:async(id,value)=>{successor.set(id,value);},removeItem:async id=>{successor.delete(id);}});
  await Promise.resolve();expect(writes).toBe(2);expect(first.size).toBe(1);expect(successor.size).toBe(0);
 });
 it("maps emoji-prefixed highlights to UTF-16 offsets",()=>{const text="😀 work";expect(rawMatchSpans(text,"work")).toEqual([[3,7]]);expect(text.slice(3,7)).toBe("work");});
});
