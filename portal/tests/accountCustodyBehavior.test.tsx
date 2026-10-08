import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { publicSurface } from "./helpers/publicSurface";
import { flush, press, render, textOf, typeInto } from "./helpers/rtr";

const fixtures = vi.hoisted(() => ({ secret: "JBSWY3DPEHPK3PXP", codes: ["A2B3C4D5E6", "F7G8H9J2K3"] }));
vi.mock("../src/api", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return { ...actual,
    auth: { ...actual.auth, saltFor: vi.fn(async () => ({ salt: "QUJDREVGR0hJSktMTU5P" })) },
    api: { ...actual.api,
      patients: vi.fn(async () => []),
      me: vi.fn(async () => ({ username: "drportal", display_name: "Dr. Portal", totp_enabled: false, wrap_pub_key: "P".repeat(124), wrap_key_blob: "sealed" })),
      totpSetup: vi.fn(async () => ({ secret_base32: fixtures.secret, otpauth_uri: `otpauth://totp/Fathom:drportal?secret=${fixtures.secret}&issuer=Fathom` })),
      totpEnable: vi.fn(async () => ({ backup_codes: fixtures.codes })),
      totpDisable: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      pairingSas: vi.fn(async () => ({ sas: "123456", wrap_key_fingerprint: "0123456789abcdef", expires_in: 900 })),
      accessLog: vi.fn(async () => [{ at: "2026-09-30T12:00:00Z", action: "patient_insights", patient_name: "patienta" }, { at: "2026-09-29T12:00:00Z", action: "rotate_wrap_key", patient_name: null }]),
      notes: vi.fn(async()=>({notes:[],nextOffset:null})),
      noteRevisions: vi.fn(async()=>[]),
      changePasswordAtomic: vi.fn(async()=>null),
      installNotesCustody: vi.fn(async()=>null),
      rotateWrapKey: vi.fn(async()=>null),
    },
  };
});
vi.mock("../src/crypto", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  return { ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    derivePortalKeys: vi.fn(async () => ({ authKey: new Uint8Array(32), wrapKek: new Uint8Array(32), noteKey: new Uint8Array(32) })),
  };
});
const { PatientsView } = await import("../src/views/PatientsView");
const { api } = await import("../src/api");
const cryptography = await import("../src/crypto");
const session = { username: "drportal", userId: "therapist-presentation", noteKey: new Uint8Array(32), noteKeyV2: new Uint8Array(32), privateKey: {} as CryptoKey, publicKeyB64: "P".repeat(124) };
const {act}=await import("react");
const {ApiError}=await import("../src/api");
const realCrypto=await vi.importActual<typeof import("../src/crypto")>("../src/crypto");
const patient={user_id:"clinical-patient",username:"patienta",status:"revoked",granted_at:"2026-09-01",revoked_at:"2026-09-02",ephemeral_pub:null,wrapped_key:null};
const rawPrivate=new Uint8Array(64).fill(17);
let currentKeys:{authKey:Uint8Array<ArrayBuffer>;wrapKek:Uint8Array<ArrayBuffer>;noteKey:Uint8Array<ArrayBuffer>};
let newKeys:typeof currentKeys;
let currentRing:import("../src/crypto").NotesKeyring;
let identity:Uint8Array<ArrayBuffer>;
let originalNotes:Array<{id:string;client_note_id:string;blob:string;created_at:string;updated_at:string;version:number;pattern_pid:null}>;
let heldPrivate:Uint8Array<ArrayBuffer>[];
let heldIdentity:Uint8Array<ArrayBuffer>[];
let heldRings:import("../src/crypto").NotesKeyring[];
const ready=async()=>{const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await flush();await press(root,"Show account security");await flush();return root;};
const output=(root:Awaited<ReturnType<typeof render>>,name:string)=>expect(publicSurface(root.toJSON())).toMatchSnapshot(name);
beforeEach(async()=>{
 vi.clearAllMocks();window.sessionStorage.clear();window.localStorage.clear();
 currentKeys={authKey:new Uint8Array(32).fill(1),wrapKek:new Uint8Array(32).fill(2),noteKey:new Uint8Array(32).fill(3)};
 newKeys={authKey:new Uint8Array(32).fill(4),wrapKek:new Uint8Array(32).fill(5),noteKey:new Uint8Array(32).fill(6)};
 currentRing={active:new Uint8Array(32).fill(7),historical:[new Uint8Array(32).fill(8)]};
 identity=await cryptography.noteKeyV2FromPrivateKey(rawPrivate);
 originalNotes=[];
 for(const [index,key] of [currentKeys.noteKey,identity,currentRing.active,currentRing.historical[0]!].entries()){
  const row=await cryptography.encryptNote(key,session.userId,patient.user_id,`client-${index}`,`Verified clinical note ${index}`);
  originalNotes.push({id:`note-${index}`,client_note_id:row.clientNoteId,blob:row.blobB64,created_at:"2026-09-01",updated_at:"2026-09-01",version:1,pattern_pid:null});
 }
 const blob=await cryptography.sealNotesKeyring(currentKeys.wrapKek,session.userId,currentRing);
 vi.mocked(api.me).mockReset().mockResolvedValue({username:"drportal",display_name:"Dr. Portal",totp_enabled:false,wrap_pub_key:"public",wrap_key_blob:"sealed-private",notes_keyring_blob:blob,custody_version:4});
 vi.mocked(api.patients).mockReset().mockResolvedValue([patient]);
 vi.mocked(api.notes).mockReset().mockResolvedValue({notes:originalNotes,nextOffset:null,revision:"17"});
 vi.mocked(api.noteRevisions).mockReset().mockResolvedValue([]);
 vi.mocked(api.changePasswordAtomic).mockReset().mockResolvedValue(null);
 vi.mocked(api.installNotesCustody).mockReset().mockResolvedValue(null);
 vi.mocked(api.rotateWrapKey).mockReset().mockResolvedValue(null);
 vi.mocked(cryptography.derivePortalKeys).mockReset().mockResolvedValueOnce(currentKeys).mockResolvedValueOnce(newKeys);
 heldPrivate=[];heldIdentity=[];heldRings=[];
 vi.spyOn(cryptography,"openSealedPrivateKey").mockImplementation(async()=>{const value=new Uint8Array(rawPrivate);heldPrivate.push(value);return value;});
 const actualIdentity=cryptography.noteKeyV2FromPrivateKey;
 vi.spyOn(cryptography,"noteKeyV2FromPrivateKey").mockImplementation(async(...args)=>{const key=await actualIdentity(...args);heldIdentity.push(key);return key;});
 const actualRing=cryptography.openNotesKeyring;
 vi.spyOn(cryptography,"openNotesKeyring").mockImplementation(async(...args)=>{const ring=await actualRing(...args);heldRings.push(ring);return ring;});
});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();});
async function passwordFields(root:Awaited<ReturnType<typeof render>>) {
 await typeInto(root,"Current password","current-password");await typeInto(root,"New password","Strong!pass123");await typeInto(root,"Repeat new password","Strong!pass123");
}

it("retires the provider-held fresh password salt before awaiting account metadata",async()=>{
 const root=await ready();await passwordFields(root);
 const salt=new Uint8Array(16).fill(23);vi.spyOn(await import("../src/platform"),"randomBytes").mockReturnValueOnce(salt);
 let release!:(value:Awaited<ReturnType<typeof api.me>>)=>void;const metadata=await api.me();vi.mocked(api.me).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 await press(root,"Change password");await vi.waitFor(()=>expect(release).toBeDefined());
 try{expect(salt.every(byte=>byte===0)).toBe(true);}finally{release(metadata);await flush(12);}
});

it.each(["recover","rotate"])("drops the borrowed current verifier before %s waits for private-key authentication",async mode=>{
 if(mode==="recover")window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");
 const root=await ready();
 if(mode==="recover"){await typeInto(root,"Current password (the one you sign in with)","current-password");await typeInto(root,"The password you were changing to","intended-password");}
 else{await typeInto(root,"Current password (to authorize rotation)","current-password");const check=root.root.findAllByType("input").find(node=>node.props["aria-label"]==="Confirm sharing-key rotation")!;await act(async()=>check.props.onChange({target:{checked:true}}));}
 let release!:(value:null)=>void;vi.mocked(cryptography.openSealedPrivateKey).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 await press(root,mode==="recover"?"Recover sharing key":"Rotate sharing key");await vi.waitFor(()=>expect(release).toBeDefined());
 try{expect(currentKeys.authKey.every(byte=>byte===0)).toBe(true);const progress=root.root.findAllByType("button").find(node=>node.children.join("")=== (mode==="recover"?"Recovering…":"Rotating…"));expect(progress).toBeDefined();expect(progress!.props.disabled).toBe(true);}finally{release(null);await flush(8);}
});

it.each(["salt","derivation"])("clears password authorization after a native %s failure before a private key exists",async stage=>{
 const root=await ready();await passwordFields(root);
 if(stage==="salt")vi.mocked((await import("../src/api")).auth.saltFor).mockRejectedValueOnce(new Error("salt endpoint unavailable"));
 else vi.mocked(cryptography.deriveMasterKey).mockRejectedValueOnce(new Error("native derivation unavailable"));
 await press(root,"Change password");await vi.waitFor(()=>expect(textOf(root)).toContain(stage==="salt"?"salt endpoint unavailable":"native derivation unavailable"));
 expect(root.root.findAllByType("input").filter(node=>node.props.type==="password").every(node=>node.props.value==="")).toBe(true);
 expect(root.root.findAllByType("button").find(node=>String(node.props.children)==="Changing…")).toBeUndefined();
 expect(api.changePasswordAtomic).not.toHaveBeenCalled();
});

it("uses safe recovery copy when private-key authentication rejects a non-Error value",async()=>{
 window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");const root=await ready();await typeInto(root,"Current password (the one you sign in with)","current-password");await typeInto(root,"The password you were changing to","intended-password");
 vi.mocked(cryptography.openSealedPrivateKey).mockRejectedValueOnce(null);await press(root,"Recover sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("could not recover the sharing key"));expect(api.rotateWrapKey).not.toHaveBeenCalled();
});

it("authenticates legacy repair custody sealed under the intended password when the current password cannot open it",async()=>{
 window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");
 const original=await api.me();let server={...original,notes_keyring_blob:await realCrypto.sealNotesKeyring(newKeys.wrapKek,session.userId,currentRing)};vi.mocked(api.me).mockImplementation(async()=>server);
 vi.mocked(api.installNotesCustody).mockImplementation(async payload=>{server={...server,notes_keyring_blob:payload.notes_keyring_blob,custody_version:payload.custody_version};return null;});
 const root=await ready();await typeInto(root,"Current password (the one you sign in with)","current-password");await typeInto(root,"The password you were changing to","intended-password");await press(root,"Recover sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("Sharing key recovered"));
 const reopened=await realCrypto.openNotesKeyring(new Uint8Array(32).fill(2),session.userId,server.notes_keyring_blob);for(const [index,row] of originalNotes.entries())await expect(realCrypto.decryptNoteAny(reopened.active,reopened.historical[0]!,session.userId,patient.user_id,row.client_note_id,row.blob,reopened.historical)).resolves.toBe(`Verified clinical note ${index}`);realCrypto.wipeNotesKeyring(reopened);
});

it("ends the session after an atomic password change when only the sign-out callback is supplied",async()=>{
 const ended:string[]=[];const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{ended.push("signed out");}}/>);await flush();await press(root,"Show account security");await passwordFields(root);await press(root,"Change password");await vi.waitFor(()=>expect(ended).toEqual(["signed out"]));expect(api.changePasswordAtomic).toHaveBeenCalledOnce();
});
it("preserves current, identity and historical note ciphertext through an atomic password change",async()=>{
 let uploaded!:Parameters<typeof api.changePasswordAtomic>[0];let release!:()=>void;
 vi.mocked(api.changePasswordAtomic).mockImplementationOnce(async payload=>{uploaded=payload;await new Promise<void>(resolve=>{release=resolve;});return null;});
 const root=await ready();await passwordFields(root);await press(root,"Change password");
 await vi.waitFor(()=>expect(uploaded).toBeDefined());
 try {
  output(root,"password change pending");
  expect(currentKeys.authKey.every(value=>value===0)).toBe(true);expect(newKeys.authKey.every(value=>value===0)).toBe(true);
  expect(uploaded).toMatchObject({expected_custody_version:4,custody_version:5,verifier:cryptography.toBase64(new Uint8Array(32).fill(1)),new_verifier:cryptography.toBase64(new Uint8Array(32).fill(4)),wrap_pub_key:"public"});
  const restored=await realCrypto.openNotesKeyring(newKeys.wrapKek,session.userId,uploaded.notes_keyring_blob);
  for(const [index,row] of originalNotes.entries())await expect(cryptography.decryptNoteAny(restored.active,restored.historical[0]!,session.userId,patient.user_id,row.client_note_id,row.blob,restored.historical)).resolves.toBe(`Verified clinical note ${index}`);
  const privateAgain=await realCrypto.openSealedPrivateKey(newKeys.wrapKek,uploaded.wrap_key_blob,session.username);expect(privateAgain).toEqual(rawPrivate);privateAgain?.fill(0);realCrypto.wipeNotesKeyring(restored);
 }finally{release();await flush(10);}
 output(root,"successful password change clears all password fields");
 for(const key of [...Object.values(currentKeys),...Object.values(newKeys),...heldIdentity,...heldPrivate,...heldRings.flatMap(ring=>[ring.active,...ring.historical])])expect(key.every(value=>value===0)).toBe(true);
});
it.each(["note","revision"])("refuses to change a credential if a historical %s cannot be authenticated",async scope=>{
 if(scope==="note")vi.mocked(api.notes).mockResolvedValue({notes:[{...originalNotes[0]!,blob:cryptography.toBase64(new Uint8Array(40))}],nextOffset:null});
 else vi.mocked(api.noteRevisions).mockResolvedValue([{id:"revision",blob:cryptography.toBase64(new Uint8Array(40)),created_at:"2026-09-01"}]);
 const root=await ready();await passwordFields(root);await press(root,"Change password");await vi.waitFor(()=>expect(textOf(root)).toContain("This note could not be authenticated with the account's notes custody. It was not changed."));
 expect(api.changePasswordAtomic).not.toHaveBeenCalled();output(root,"rejected custody preserves the unchanged record");
});
it("reports exhausted lost-response retries and preserves a bounded attempt count",async()=>{
 let calls=0;vi.mocked(api.changePasswordAtomic).mockImplementation(async()=>{if(++calls<=4)throw new ApiError(503,"offline");return null;});
 const root=await ready();await passwordFields(root);await press(root,"Change password");await vi.waitFor(()=>expect(textOf(root)).toContain("server is busy — try again"));
 expect(api.changePasswordAtomic).toHaveBeenCalledTimes(4);output(root,"bounded retry failure");
});
it("renders a repairable interrupted change and drops both entered passwords on failure",async()=>{
 window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");
 const root=await ready();await typeInto(root,"Current password (the one you sign in with)","current-password");await typeInto(root,"The password you were changing to","intended-password");
 vi.spyOn(cryptography,"openSealedPrivateKey").mockResolvedValueOnce(null);
 await press(root,"Recover sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("the second password did not unlock"));output(root,"failed sharing-key repair clears entered passwords");
});
it("clears suspected-compromise confirmation after a failed rotation",async()=>{
 const root=await ready();await typeInto(root,"Current password (to authorize rotation)","current-password");
 const check=root.root.findAllByType("input").find(node=>node.props["aria-label"]==="Confirm sharing-key rotation")!;await act(async()=>check.props.onChange({target:{checked:true}}));
 vi.mocked(api.installNotesCustody).mockRejectedValueOnce(null);await press(root,"Rotate sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("could not rotate the sharing key"));output(root,"rotation failure resets authorization");
});

it("repairs legacy interrupted custody without losing notes from either password",async()=>{
  const intended=await realCrypto.encryptNote(newKeys.noteKey,session.userId,patient.user_id,"intended-note","Clinical text from interrupted password");
  originalNotes.push({...originalNotes[0]!,id:"intended",client_note_id:intended.clientNoteId,blob:intended.blobB64});
  window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");
  const original=await api.me();let server={...original};
  vi.mocked(api.me).mockImplementation(async()=>server);
  let installed!:Parameters<typeof api.installNotesCustody>[0];
  vi.mocked(api.installNotesCustody).mockImplementation(async payload=>{installed=payload;server={...server,notes_keyring_blob:payload.notes_keyring_blob,custody_version:payload.custody_version};return null;});
  vi.mocked(api.rotateWrapKey).mockImplementation(async(_verifier,_public,_private,version)=>{expect(version).toBe(server.custody_version);return null;});
  const root=await ready();await typeInto(root,"Current password (the one you sign in with)","current-password");await typeInto(root,"The password you were changing to","intended-password");
  await press(root,"Recover sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("Sharing key recovered"));
  const restored=await realCrypto.openNotesKeyring(new Uint8Array(32).fill(2),session.userId,installed.notes_keyring_blob);
  await expect(realCrypto.decryptNoteAny(restored.active,restored.historical[0]!,session.userId,patient.user_id,intended.clientNoteId,intended.blobB64,restored.historical)).resolves.toBe("Clinical text from interrupted password");
  realCrypto.wipeNotesKeyring(restored);
  expect(window.sessionStorage.getItem(`mindpattern.interruptedRotateSalt.${session.userId}`)).toBeNull();output(root,"recovered custody clears repair salt and passwords");
  for(const key of [...Object.values(currentKeys),...Object.values(newKeys),...heldIdentity,...heldPrivate,...heldRings.flatMap(ring=>[ring.active,...ring.historical])])expect(key.every(value=>value===0)).toBe(true);
});

it.each(["blob","version"] as const)("requires a confirmed %s before rotating the sharing identity",async mismatch=>{
  const original=await api.me();let server={...original};vi.mocked(api.me).mockImplementation(async()=>server);
  vi.mocked(api.installNotesCustody).mockImplementation(async payload=>{server={...server,notes_keyring_blob:mismatch==="blob"?"different-ciphertext":payload.notes_keyring_blob,custody_version:mismatch==="version"?payload.expected_custody_version:payload.custody_version};return null;});
  const root=await ready();await typeInto(root,"Current password (to authorize rotation)","current-password");
  const check=root.root.findAllByType("input").find(node=>node.props["aria-label"]==="Confirm sharing-key rotation")!;await act(async()=>check.props.onChange({target:{checked:true}}));
  await press(root,"Rotate sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("Notes custody was not confirmed — sharing identity was not changed."));
  expect(api.rotateWrapKey).not.toHaveBeenCalled();output(root,"unconfirmed custody cannot rotate identity");
});

it("refuses an indefinitely continuing custody listing after its last permitted page",async()=>{
 vi.spyOn(cryptography,"decryptNoteAny").mockResolvedValue("Verified clinical note");const accessed:number[]=[];vi.mocked(api.notes).mockImplementation(async(_patient,params)=>{const offset=params?.offset??0;accessed.push(offset);if(offset>=500)throw new Error("Unexpected page after custody limit");return {notes:[originalNotes[0]!],nextOffset:offset+1,revision:"17"};});const root=await ready();await passwordFields(root);await press(root,"Change password");await vi.waitFor(()=>expect(textOf(root)).toContain("Notes custody verification exceeded its limit — nothing was changed."));expect(accessed).toHaveLength(500);expect(accessed.at(-1)).toBe(499);expect(api.changePasswordAtomic).not.toHaveBeenCalled();
});

it.each(["session-end callback", "sign-out callback"])("rotates confirmed custody, retires all provider-held secrets and issues the %s",async callback=>{
 const original=await api.me();let server={...original};vi.mocked(api.me).mockImplementation(async()=>server);vi.mocked(api.installNotesCustody).mockImplementation(async payload=>{server={...server,notes_keyring_blob:payload.notes_keyring_blob,custody_version:payload.custody_version};return null;});const ended:string[]=[];
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{ended.push("sign out");}} {...(callback==="session-end callback"?{onSessionsEnded:()=>{ended.push("sessions ended");}}:{})}/>);await flush();await press(root,"Show account security");await typeInto(root,"Current password (to authorize rotation)","current-password");const check=root.root.findAllByType("input").find(node=>node.props["aria-label"]==="Confirm sharing-key rotation")!;await act(async()=>check.props.onChange({target:{checked:true}}));
 await press(root,"Rotate sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("Sharing identity rotated."));expect(ended).toEqual([callback==="session-end callback"?"sessions ended":"sign out"]);expect(api.rotateWrapKey).toHaveBeenCalledWith(expect.any(String),expect.any(String),expect.any(String),5);
 for(const key of [...Object.values(currentKeys),...heldIdentity,...heldPrivate,...heldRings.flatMap(ring=>[ring.active,...ring.historical])])expect(key.every(value=>value===0)).toBe(true);output(root,"confirmed rotation retires custody and authorization controls");
});

it("reports an ordinary failed password unlock before any sharing-identity rotation",async()=>{
 vi.mocked(cryptography.openSealedPrivateKey).mockResolvedValueOnce(null);const root=await ready();await typeInto(root,"Current password (to authorize rotation)","wrong-password");const check=root.root.findAllByType("input").find(node=>node.props["aria-label"]==="Confirm sharing-key rotation")!;await act(async()=>check.props.onChange({target:{checked:true}}));await press(root,"Rotate sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("The current password did not unlock your sharing identity — nothing was changed."));expect(api.rotateWrapKey).not.toHaveBeenCalled();output(root,"password unlock failure cannot rotate sharing identity");
});

it.each(["blob","version"] as const)("requires a confirmed repaired %s before replacing the sharing wrapper",async mismatch=>{
 window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");const original=await api.me();let server={...original};vi.mocked(api.me).mockImplementation(async()=>server);vi.mocked(api.installNotesCustody).mockImplementation(async payload=>{server={...server,notes_keyring_blob:mismatch==="blob"?"different-ciphertext":payload.notes_keyring_blob,custody_version:mismatch==="version"?payload.expected_custody_version:payload.custody_version};return null;});const root=await ready();await typeInto(root,"Current password (the one you sign in with)","current-password");await typeInto(root,"The password you were changing to","intended-password");await press(root,"Recover sharing key");await vi.waitFor(()=>expect(textOf(root)).toContain("Notes custody was not confirmed — sharing identity was not changed."));expect(api.rotateWrapKey).not.toHaveBeenCalled();expect(window.sessionStorage.getItem(`mindpattern.interruptedRotateSalt.${session.userId}`)).not.toBeNull();
});
