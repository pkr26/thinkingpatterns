/**
 * App shell state machine: login -> unlock -> patients -> patient, and the
 * honest failure paths (role rejection at login is in views.test; here the
 * unlock failure and sign-out loop).
 */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act } from "react";
import { getEventListeners } from "node:events";
import { publicSurface } from "./helpers/publicSurface";

vi.mock("../src/api", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api")>();
  return {
    ...actual,
    auth: {
      meta: vi.fn(async () => ({ sharing_available: true })),
      saltFor: vi.fn(async () => ({ salt: "QUJDREVGR0hJSktMTU5P" })),
      login: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
      logoutBearer: vi.fn(async () => null),
      registerTherapist: vi.fn(async () => ({ token: "tok", user_id: "therapist-1", expires_in: 900, role: "therapist" })),
    },
    api: {
      me: vi.fn(async () => ({
        username: "drportal",
        display_name: "Dr. Portal",
        wrap_pub_key: "P".repeat(124),
        wrap_key_blob: "KQ==",
      })),
      // 2026-09-26 audit M-P1: lockDown fires this best-effort before the
      // local teardown on every lock route (sign-out, idle, 401, bfcache).
      logout: vi.fn(async () => null),
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({
        phase: "baseline", active_days: 0, streak: 0, days_remaining: 30, blob: null, state_seq: 0,
      })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      totpSetup: vi.fn(async () => ({ secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:test" })),
      totpEnable: vi.fn(async () => ({ backup_codes: ["ABCDE12345", "FGHIJ67890"] })),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  const decryptNoteMock = vi.fn(async () => "");
  return {
    ...actual,
    deriveMasterKey: vi.fn(async () => new Uint8Array(32)),
    // Audit fix P-1 (2026-09-20): the verifier is raw bytes (base64 derived
    // only at the send); key generation returns the sealed blob directly.
    derivePortalKeys: vi.fn(async () => ({
      authKey: new Uint8Array(32),
      wrapKek: new Uint8Array(32),
      noteKey: new Uint8Array(32),
      noteKeyV2: new Uint8Array(32),
    })),
    generateTherapistKeyPair: vi.fn(async () => ({
      publicKeySpkiB64: "P".repeat(124),
      wrapKeyBlobB64: "SEALED==",
    })),
    unlockWrapPrivateKey: vi.fn(async () => ({ algorithm: { name: "ECDH" } })),
    unlockWrapPrivateKeyWithNotesKey: vi.fn(async () => ({
      privateKey: { algorithm: { name: "ECDH" } } as unknown as CryptoKey,
      noteKeyV2: new Uint8Array(32),
    })),
    unwrapPatientDataKey: vi.fn(async () => new Uint8Array(32)),
    decryptInsights: vi.fn(async () => ({ stats: { patterns: [] } })),
    decryptEntry: vi.fn(async () => ({ text: "" })),
    encryptNote: vi.fn(async () => ({ blobB64: "S==" })),
    decryptNote: decryptNoteMock,
    decryptNoteAny: vi.fn(async (...args: unknown[]) =>
      decryptNoteMock(...(args.slice(1) as Parameters<typeof decryptNoteMock>)),
    ),
  };
});

const { api, clearSession, hasSession } = await import("../src/api");
const { App } = await import("../src/App");
const { render, flush, textOf, press, typeInto } = await import("./helpers/rtr");

beforeEach(()=>{vi.clearAllMocks();clearSession();window.localStorage.clear();window.sessionStorage.clear();window.location.hash="";});
afterEach(()=>{vi.restoreAllMocks();vi.unstubAllGlobals();vi.useRealTimers();});
async function login(){const root=await render(<App/>);await typeInto(root,"Username","drportal");await typeInto(root,"Password","pw");await press(root,"Sign in");await flush();return root;}
it("opens with a clean public sign-in surface",async()=>{
 const root=await render(<App/>);expect(publicSurface(root.toJSON())).toMatchSnapshot("empty authenticated shell sign-in");
});
it("writes accessible chart navigation to browser history and restores the caseload hash on Back",async()=>{
 const location={origin:"http://localhost:5173",hash:""};
 const original=window;vi.stubGlobal("window",{...original,location,history:{pushState:(_state:unknown,_title:string,hash:string)=>{location.hash=hash;}}});
 const patient={user_id:"accessible-patient",username:"patienta",status:"revoked",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:null,wrapped_key:null};
 vi.mocked(api.patients).mockResolvedValueOnce([patient]);const root=await login();await press(root,"Open my notes");await flush();expect(location.hash).toBe("#/patient/accessible-patient");
 await press(root,"Back to patients");await flush();expect(location.hash).toBe("#/patients");
});
it("clears both metadata stores and interrupted repair state on explicit chart sign-out",async()=>{
 const patient={user_id:"accessible-patient",username:"patienta",status:"revoked",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:null,wrapped_key:null};
 vi.mocked(api.patients).mockResolvedValueOnce([patient]);const root=await login();await press(root,"Open my notes");await flush();
 for(const storage of [window.localStorage,window.sessionStorage]){storage.setItem("mindpattern.lastVisit.therapist-1.accessible-patient","2026-09-30");storage.setItem("unrelated.application","keep");}
 window.sessionStorage.setItem("mindpattern.interruptedRotateSalt.therapist-1","repair");
 await press(root,"Sign out");await flush();
 for(const storage of [window.localStorage,window.sessionStorage]){expect(storage.getItem("mindpattern.lastVisit.therapist-1.accessible-patient")).toBeNull();expect(storage.getItem("unrelated.application")).toBe("keep");}
 expect(window.sessionStorage.getItem("mindpattern.interruptedRotateSalt.therapist-1")).toBeNull();expect(hasSession()).toBe(false);
});
it("scrubs local fallback anchors during idle lock and authenticated shell teardown",async()=>{
 const original=window;vi.stubGlobal("window",{...original,sessionStorage:{setItem(){throw new Error("denied");},getItem:()=>null,removeItem:()=>{},length:0,key:()=>null}});
 vi.useFakeTimers();const root=await login();await flush();expect(textOf(root)).toContain("Patients — Dr. Portal");
 window.localStorage.setItem("mindpattern.lastVisit.therapist-1.patient","2026-09-30");
 await act(async()=>{vi.advanceTimersByTime(10*60*1000);});await flush();expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.patient")).toBeNull();
 vi.useRealTimers();const again=await login();await vi.waitFor(()=>expect(textOf(again)).toContain("Patients — Dr. Portal"));window.localStorage.setItem("mindpattern.lastVisit.therapist-1.patient","2026-09-30");await act(async()=>again.unmount());expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.patient")).toBeNull();
});
it("does not adopt a retired shell's late custody while a replacement shell has a new session",async()=>{
 const provider=vi.mocked(await import("../src/crypto"));const wrap=new Uint8Array(32).fill(2),note=new Uint8Array(32).fill(3),identity=new Uint8Array(32).fill(4),active=new Uint8Array(32).fill(5),historical=new Uint8Array(32).fill(6);
 provider.derivePortalKeys.mockResolvedValueOnce({authKey:new Uint8Array(32).fill(1),wrapKek:wrap,noteKey:note});
 vi.mocked(api.me).mockResolvedValueOnce({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:"public",wrap_key_blob:"sealed",notes_keyring_blob:"custody",custody_version:4});
 let release!:(value:{privateKey:CryptoKey,noteKeyV2:Uint8Array<ArrayBuffer>})=>void;provider.unlockWrapPrivateKeyWithNotesKey.mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 const ring=vi.spyOn(provider,"openNotesKeyring").mockResolvedValueOnce({active,historical:[historical]});
 const retired=await login();await act(async()=>retired.unmount());const replacement=await login();await vi.waitFor(()=>expect(textOf(replacement)).toContain("Patients — Dr. Portal"));expect(hasSession()).toBe(true);
 try{release({privateKey:{} as CryptoKey,noteKeyV2:identity});await flush(12);for(const key of [wrap,note,identity,active,historical])expect(key.every(value=>value===0)).toBe(true);expect(textOf(replacement)).toContain("Patients — Dr. Portal");}finally{release({privateKey:{} as CryptoKey,noteKeyV2:identity});ring.mockRestore();await flush();}
});

it("releases the host's navigation and interaction callbacks and idle timer on shell teardown",async()=>{
 const original=window,originalDocument=document;const hostWindow=new EventTarget(),hostDocument=new EventTarget();
 vi.stubGlobal("window",{...original,addEventListener:hostWindow.addEventListener.bind(hostWindow),removeEventListener:hostWindow.removeEventListener.bind(hostWindow),dispatchEvent:hostWindow.dispatchEvent.bind(hostWindow)});
 vi.stubGlobal("document",{...originalDocument,addEventListener:hostDocument.addEventListener.bind(hostDocument),removeEventListener:hostDocument.removeEventListener.bind(hostDocument),dispatchEvent:hostDocument.dispatchEvent.bind(hostDocument)});
 vi.useFakeTimers();const root=await login();await flush();expect(textOf(root)).toContain("Patients — Dr. Portal");expect(vi.getTimerCount()).toBeGreaterThan(0);await act(async()=>root.unmount());
 for(const name of ["click","keydown","scroll","wheel","touchstart","pageshow","popstate","hashchange"])expect(getEventListeners(hostWindow,name)).toHaveLength(0);expect(getEventListeners(hostDocument,"visibilitychange")).toHaveLength(0);expect(vi.getTimerCount()).toBe(0);
});

it("locks immediately when a previously hidden chart reaches exactly the inactivity boundary",async()=>{
 vi.useFakeTimers();const root=await login();await flush();(document as unknown as {hidden:boolean}).hidden=true;document.dispatchEvent(new Event("visibilitychange"));
 vi.setSystemTime(Date.now()+10*60*1000);(document as unknown as {hidden:boolean}).hidden=false;await act(async()=>{document.dispatchEvent(new Event("visibilitychange"));});await flush();expect(hasSession()).toBe(false);expect(textOf(root)).toContain("Locked after inactivity — sign in again to continue.");
});

it("keeps an active foreground chart open when visibility is reported without a preceding hide",async()=>{
 const root=await login();await flush();(document as unknown as {hidden:boolean}).hidden=false;await act(async()=>document.dispatchEvent(new Event("visibilitychange")));await flush();expect(hasSession()).toBe(true);expect(textOf(root)).toContain("Patients — Dr. Portal");
});

it.each(["session", "fallback"])("ends an in-progress %s unlock on a persisted page restore before any portal custody has been adopted",async storage=>{
 if(storage==="fallback"){const original=window;vi.stubGlobal("window",{...original,sessionStorage:{setItem(){throw new Error("denied");},getItem:()=>null,removeItem:()=>{},length:0,key:()=>null}});}
 let release!:(value:Awaited<ReturnType<typeof api.me>>)=>void;vi.mocked(api.me).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));const root=await login();try{await act(async()=>window.dispatchEvent(Object.assign(new Event("pageshow"),{persisted:true})));await flush();expect(hasSession()).toBe(false);expect(textOf(root)).toContain("Restored from the browser cache — sign in again.");}finally{release({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:"public",wrap_key_blob:"sealed"});await flush();}
});

it("tears down an unauthenticated fallback shell without touching unrelated durable records",async()=>{
 const original=window;vi.stubGlobal("window",{...original,sessionStorage:{setItem(){throw new Error("denied");},getItem:()=>null,removeItem:()=>{},length:0,key:()=>null}});window.localStorage.setItem("unrelated.application","keep");const root=await render(<App/>);await act(async()=>root.unmount());expect(window.localStorage.getItem("unrelated.application")).toBe("keep");
});

it.each(["opaque failure","local failure"])("retires the minted bearer and reports an unlock %s",async mode=>{
 vi.mocked(api.me).mockRejectedValueOnce(mode==="opaque failure"?null:new Error("local unlock failed"));const root=await login();await flush();expect(hasSession()).toBe(false);expect(textOf(root)).toContain(mode==="opaque failure"?"could not unlock your sharing key":"local unlock failed");expect(textOf(root)).toContain("Sign in");
});

it("uses current custody metadata for a version-fenced clinical note after account unlock",async()=>{
 const provider=vi.mocked(await import("../src/crypto"));vi.mocked(api.me).mockResolvedValueOnce({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:"public",wrap_key_blob:"sealed",notes_keyring_blob:"custody",custody_version:4});const ring=vi.spyOn(provider,"openNotesKeyring").mockResolvedValueOnce({active:new Uint8Array(32).fill(5),historical:[]});
 vi.mocked(api.patients).mockResolvedValueOnce([{user_id:"accessible-patient",username:"patienta",status:"revoked",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:null,wrapped_key:null}]);const root=await login();await press(root,"Open my notes");await flush();const draft=root.root.findAllByType("textarea").find(n=>n.props.placeholder==="Note about this patient…")!;await act(async()=>draft.props.onChange({target:{value:"Clinical note with custody fence"}}));vi.mocked(api.createNote).mockResolvedValueOnce({id:"saved",client_note_id:"created",blob:"sealed",created_at:"2026-10-05",updated_at:"2026-10-05",version:1,pattern_pid:null});await press(root,"Save note");await vi.waitFor(()=>expect(api.createNote).toHaveBeenCalledWith("accessible-patient",expect.objectContaining({custody_version:4})));ring.mockRestore();
});

it("clears explicit caseload sign-out anchors from both host stores",async()=>{
 const root=await login();for(const store of [window.localStorage,window.sessionStorage])store.setItem("mindpattern.lastVisit.therapist-1.patient","2026-09-30");await press(root,"Sign out");await flush();for(const store of [window.localStorage,window.sessionStorage])expect(store.getItem("mindpattern.lastVisit.therapist-1.patient")).toBeNull();expect(hasSession()).toBe(false);
});

it("honors the child account-custody session-end event and renders the new-password sign-in notice",async()=>{
 const root=await login();const {PatientsView}=await import("../src/views/PatientsView");await act(async()=>root.root.findByType(PatientsView).props.onSessionsEnded());await flush();expect(hasSession()).toBe(false);expect(textOf(root)).toContain("Password changed. Every session — including this one — has ended; sign in with your new password.");expect(textOf(root)).toContain("Sign in");
});

it.each(["missing","failure"])("returns safely to the caseload for a history chart %s",async mode=>{
 const root=await login();if(mode==="failure")vi.mocked(api.patients).mockRejectedValueOnce(null);else vi.mocked(api.patients).mockResolvedValueOnce([]);window.location.hash="#/patient/unavailable";await act(async()=>{window.dispatchEvent(new Event("hashchange"));});await flush();expect(textOf(root)).toContain(mode==="failure"?"The patient could not be opened. Retry when connected.":"That patient is not available to this account.");expect(textOf(root)).toContain("Patients — Dr. Portal");
});

it.each(["resolve","reject"])("ignores an older chart history %s after a new route settles",async result=>{
 const root=await login();let resolve!:(rows:Awaited<ReturnType<typeof api.patients>>)=>void,reject!:(error:unknown)=>void;vi.mocked(api.patients).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));window.location.hash="#/patient/older";await act(async()=>{window.dispatchEvent(new Event("hashchange"));});window.location.hash="";await act(async()=>{window.dispatchEvent(new Event("hashchange"));});
 try{if(result==="resolve")resolve([]);else reject(null);await flush();expect(textOf(root)).not.toContain("That patient is not available");expect(textOf(root)).not.toContain("The patient could not be opened");expect(textOf(root)).toContain("Patients — Dr. Portal");}finally{resolve([]);await flush();}
});

it("wipes provider-held identity notes if opening the account keyring fails after unwrap",async()=>{
 const provider=vi.mocked(await import("../src/crypto"));const identity=new Uint8Array(32).fill(19),wrap=new Uint8Array(32).fill(20),note=new Uint8Array(32).fill(21);
 provider.derivePortalKeys.mockResolvedValueOnce({authKey:new Uint8Array(32).fill(18),wrapKek:wrap,noteKey:note});provider.unlockWrapPrivateKeyWithNotesKey.mockResolvedValueOnce({privateKey:{} as CryptoKey,noteKeyV2:identity});
 vi.mocked(api.me).mockResolvedValueOnce({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:"public",wrap_key_blob:"sealed",notes_keyring_blob:"keyring",custody_version:4});vi.spyOn(provider,"openNotesKeyring").mockRejectedValueOnce(new Error("Account custody could not be opened"));
 const root=await login();await flush(8);expect(textOf(root)).toContain("Account custody could not be opened");expect(hasSession()).toBe(false);for(const key of [identity,wrap,note])expect(key.every(value=>value===0)).toBe(true);
});

it("clears the previous unlock error while a fresh sign-in unlock is still pending",async()=>{
 vi.mocked(api.me).mockRejectedValueOnce(new Error("First unlock failed"));const root=await login();expect(textOf(root)).toContain("First unlock failed");let release!:(value:Awaited<ReturnType<typeof api.me>>)=>void;vi.mocked(api.me).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 await typeInto(root,"Password","retry password");await press(root,"Sign in");await flush();try{expect(textOf(root)).not.toContain("First unlock failed");expect(textOf(root)).toContain("Signing in…");expect(publicSurface(root.toJSON())).toMatchSnapshot("fresh pending unlock has no previous error");}finally{release({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:"public",wrap_key_blob:"sealed"});await flush();}
});

it.each(["profile", "unwrap"])("keeps a replacement session alive when a retired shell's pending %s fails",async stage=>{
 const provider=vi.mocked(await import("../src/crypto"));let reject!:(error:unknown)=>void;if(stage==="profile")vi.mocked(api.me).mockImplementationOnce(()=>new Promise((_yes,no)=>{reject=no;}));else provider.unlockWrapPrivateKeyWithNotesKey.mockImplementationOnce(()=>new Promise((_yes,no)=>{reject=no;}));const retired=await login();await act(async()=>retired.unmount());const replacement=await login();await vi.waitFor(()=>expect(textOf(replacement)).toContain("Patients — Dr. Portal"));try{reject(new Error("retired unlock failure"));await flush(12);expect(hasSession()).toBe(true);expect(textOf(replacement)).toContain("Patients — Dr. Portal");}finally{reject(new Error("retired unlock failure"));await flush();}
});

it("preserves unrelated local application records when a fallback session retires",async()=>{
 const original=window;vi.stubGlobal("window",{...original,sessionStorage:{setItem(){throw new Error("denied");},getItem:()=>null,removeItem:()=>{},length:0,key:()=>null}});vi.useFakeTimers();const root=await login();expect(textOf(root)).toContain("Patients — Dr. Portal");window.localStorage.setItem("mindpattern.lastVisit.therapist-1.patient","2026-09-30");window.localStorage.setItem("unrelated.application","keep");await act(async()=>vi.advanceTimersByTime(600_000));await flush();expect(window.localStorage.getItem("unrelated.application")).toBe("keep");expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.patient")).toBeNull();
 const next=await render(<App/>);await typeInto(next,"Username","drportal");await typeInto(next,"Password","pw");await press(next,"Sign in");await flush();window.localStorage.setItem("mindpattern.lastVisit.therapist-1.patient","2026-09-30");await act(async()=>next.unmount());expect(window.localStorage.getItem("unrelated.application")).toBe("keep");expect(window.localStorage.getItem("mindpattern.lastVisit.therapist-1.patient")).toBeNull();
});

it("preserves a dormant local review anchor across a session-backed idle lock before the host disables session storage",async()=>{
 vi.useFakeTimers();await login();const key="mindpattern.lastVisit.therapist-1.patient";window.localStorage.setItem(key,"2026-09-25");window.sessionStorage.setItem(key,"2026-09-30");await act(async()=>vi.advanceTimersByTime(600_000));await flush();const original=window;vi.stubGlobal("window",{...original,sessionStorage:{setItem(){throw new Error("host blocked session storage");},getItem:()=>null,removeItem:()=>{},length:0,key:()=>null}});const {visitAnchorStore}=await import("../src/platform");expect(visitAnchorStore.get(key)).toBe("2026-09-25");
});

it("recovers from a failed patient chart when history opens a different accessible patient",async()=>{
 const module=await import("../src/views/PatientView"),actual=module.PatientView;vi.spyOn(module,"PatientView").mockImplementation(props=>{if(props.patient.user_id==="broken-patient")throw new Error("chart failed");return actual(props);});
 const broken={user_id:"broken-patient",username:"broken",status:"revoked",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:null,wrapped_key:null},healthy={...broken,user_id:"healthy-patient",username:"healthy"};vi.mocked(api.patients).mockResolvedValueOnce([broken,healthy]);const root=await login();
 vi.mocked(api.patients).mockResolvedValueOnce([broken,healthy]);window.location.hash="#/patient/broken-patient";await act(async()=>{window.dispatchEvent(new Event("hashchange"));});await flush();expect(textOf(root)).toContain("Something went wrong");
 vi.mocked(api.patients).mockResolvedValueOnce([broken,healthy]);window.location.hash="#/patient/healthy-patient";await act(async()=>{window.dispatchEvent(new Event("hashchange"));});await flush();expect(textOf(root)).toContain("healthy");expect(textOf(root)).not.toContain("Something went wrong");
});

it.each(["resolve","reject"])("retires an older pending chart history %s when the clinician signs out",async result=>{
 const root=await login();let resolve!:(rows:Awaited<ReturnType<typeof api.patients>>)=>void,reject!:(error:unknown)=>void;vi.mocked(api.patients).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));window.location.hash="#/patient/older";await act(async()=>{window.dispatchEvent(new Event("hashchange"));});await press(root,"Sign out");await flush();
 try{if(result==="resolve")resolve([]);else reject(null);await flush();expect(hasSession()).toBe(false);expect(textOf(root)).toContain("Signed out. Your in-memory keys were cleared.");expect(textOf(root)).not.toContain("That patient is not available");expect(textOf(root)).not.toContain("The patient could not be opened");}finally{resolve([]);await flush();}
});
