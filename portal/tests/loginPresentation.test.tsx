/**
 * View behavior with mocked api/crypto layers (the crypto itself is
 * pinned by tests/crypto.test.ts against the real WebCrypto): login and
 * registration flows, the patients list + pairing code, and the patient
 * view — pattern cards, the sensitive non-quoting card, the evidence
 * drill-down, and notes.
 */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
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
      patients: vi.fn(async () => []),
      patientInsights: vi.fn(async () => ({
        phase: "insight", active_days: 45, streak: 3, days_remaining: 0, blob: "BLOB==",
        // 2026-09-26 audit L: the echoed generation now travels with every
        // insights summary; the default payload below decrypts to seq 7.
        state_seq: 7,
      })),
      patientEntries: vi.fn(async () => ({ entries: [], nextOffset: null })),
      notes: vi.fn(async () => ({ notes: [], nextOffset: null })),
      noteRevisions: vi.fn(async () => []),
      createNote: vi.fn(async () => ({})),
      updateNote: vi.fn(async () => ({})),
      deleteNote: vi.fn(async () => null),
      newPairingCode: vi.fn(async () => ({ code: "7X2KQM4N", expires_in: 900 })),
      pairingSas: vi.fn(async () => ({ sas: "482 913", wrap_key_fingerprint: "a1b2c3d4e5f60718", expires_in: 900 })),
      patientMeasures: vi.fn(async () => ({ measures: [], nextOffset: null })),
      totpSetup: vi.fn(async () => ({ secret_base32: "JBSWY3DPEHPK3PXP", otpauth_uri: "otpauth://totp/Fathom:test" })),
      totpEnable: vi.fn(async () => ({ backup_codes: ["ABCDE12345", "FGHIJ67890"] })),
    },
  };
});

vi.mock("../src/crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto")>();
  const decryptNoteMock = vi.fn(async () => "existing note text");
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
    decryptCaseloadSummary: vi.fn(async () => null),
    decryptMeasure: vi.fn(async () => null),
    decryptInsights: vi.fn(async () => ({
      // 2026-09-26 audit L: matches the default patientInsights echo above.
      state_seq: 7,
      stats: {
        patterns: [
          { kind: "temporal", label: "work", occurrences: 9, confidence: 0.8, detail: { day: "Sunday", pattern_pid: "temporal:work", pattern_state: "confirmed", evidence_dates: ["2026-09-01", "2026-09-08"], first_seen: "2026-08-20", last_seen: "2026-09-08" } },
          { kind: "recurring_phrase", label: "can't sleep", occurrences: 4, confidence: 0.5, detail: { sensitive: true, pattern_pid: "recurring_phrase:x", evidence_dates: ["2026-09-02"] } },
          { kind: "mood_correlation", label: "family", occurrences: 6, confidence: 0.7, detail: { direction: "higher", mood_delta: -0.3, pattern_pid: "mood_correlation:family", evidence_dates: ["2026-09-03"] } },
          { kind: "link", label: "sleep", occurrences: 5, confidence: 0.6, detail: { lag_days: 2, direction: "lower", pattern_pid: "link:sleep", evidence_dates: ["2026-09-04"] } },
          { kind: "temporal", label: "gym", occurrences: 4, confidence: 0.4, detail: { pattern_pid: "temporal:gym", evidence_dates: ["2026-09-05"] } },
          { kind: "mood_shift", label: "", occurrences: 1, confidence: 0.3, detail: { direction: "lower", pattern_pid: "mood_shift:lower", evidence_dates: ["2026-09-06"] } },
        ],
      },
    })),
    decryptEntry: vi.fn(async (_key: unknown, _uid: string, entry: { client_entry_id: string }) => ({
      text: `decrypted ${entry.client_entry_id}`,
      sentiment: entry.client_entry_id === "e-1" ? 0.25 : null,
    })),
    encryptNote: vi.fn(async () => ({ blobB64: "SEALEDNOTE==" })),
    decryptNote: decryptNoteMock,
    decryptNoteAny: vi.fn(async (...args: unknown[]) =>
      decryptNoteMock(...(args.slice(1,6) as Parameters<typeof decryptNoteMock>)),
    ),
  };
});

const {auth,api,ApiError,clearSession,hasSession}=await import("../src/api");
const {LoginView,passwordStrength}=await import("../src/views/LoginView");
const provider=vi.mocked(await import("../src/crypto"));
const {render,flush,press,typeInto}=await import("./helpers/rtr");
const {act}=await import("react");
const token={token:"bearer",user_id:"therapist-1",expires_in:900,role:"therapist"};
const rootView=()=>render(<LoginView onReady={async()=>{}}/>);
const output=(root:Awaited<ReturnType<typeof render>>,name:string)=>expect(publicSurface(root.toJSON())).toMatchSnapshot(name);
beforeEach(()=>{
 vi.clearAllMocks();clearSession();
 vi.mocked(auth.meta).mockReset().mockResolvedValue({sharing_available:true});
 vi.mocked(auth.login).mockReset().mockResolvedValue(token);
 vi.mocked(auth.registerTherapist).mockReset().mockResolvedValue(token);
 vi.mocked(auth.saltFor).mockReset().mockResolvedValue({salt:"QUJDREVGR0hJSktMTU5P"});
 provider.deriveMasterKey.mockReset().mockImplementation(async()=>new Uint8Array(32).fill(12));
 provider.derivePortalKeys.mockReset().mockImplementation(async()=>({authKey:new Uint8Array(32).fill(13),noteKey:new Uint8Array(32).fill(14),wrapKek:new Uint8Array(32).fill(15)}));
 vi.mocked(api.totpSetup).mockReset().mockResolvedValue({secret_base32:"JBSWY3DPEHPK3PXP",otpauth_uri:"otpauth://totp/Fathom:test"});
 vi.mocked(api.totpEnable).mockReset().mockResolvedValue({backup_codes:["ABCDE12345","FGHIJ67890"]});
});
afterEach(()=>{clearSession();vi.unstubAllGlobals();});
async function credentials(root:Awaited<ReturnType<typeof render>>) {await typeInto(root,"Username","drportal");await typeInto(root,"Password","Strong!pass123");}
async function registration(root:Awaited<ReturnType<typeof render>>) {
 await press(root,"Create a therapist account instead");await flush();await typeInto(root,"Your name","Dr. Example");await credentials(root);await typeInto(root,"Repeat password","Strong!pass123");
 const checkbox=root.root.findAllByType("input").find(n=>n.props.type==="checkbox")!;
 await act(async()=>checkbox.props.onChange({target:{checked:true}}));
}
it.each(["resolve", "reject"])("does not replace or clear a newer session when a retired sign-in %s arrives",async outcome=>{
 const actual=await vi.importActual<typeof import("../src/api")>("../src/api");let resolve!:(value:typeof token)=>void,reject!:(error:unknown)=>void;vi.mocked(auth.login).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));const handoffs:unknown[]=[];const root=await render(<LoginView onReady={async keys=>{handoffs.push(keys);}}/>);await credentials(root);await press(root,"Sign in");await flush();await act(async()=>root.unmount());actual.setSession("replacement-bearer","https://clinic.example");
 try{if(outcome==="resolve")resolve({...token,token:"retired-bearer"});else reject(new ApiError(401,"invalid credentials","invalid_credentials"));await flush(12);expect(handoffs).toEqual([]);expect(actual.hasSession()).toBe(true);const requests:Array<{url:string,bearer:string|null}>=[];vi.stubGlobal("fetch",async(url:RequestInfo|URL,init?:RequestInit)=>{requests.push({url:String(url),bearer:new Headers(init?.headers).get("Authorization")});return new Response("[]",{status:200,headers:{"Content-Type":"application/json"}});});await expect(actual.api.accessLog()).resolves.toEqual([]);expect(requests).toEqual([{url:"https://clinic.example/api/v1/therapist/access-log?limit=100",bearer:"Bearer replacement-bearer"}]);}finally{resolve({...token,token:"retired-bearer"});await flush();}
});

it.each(["resolve", "reject"])("retires a late registration %s without clearing a replacement session or borrowing its handoff",async outcome=>{
 const actual=await vi.importActual<typeof import("../src/api")>("../src/api");let resolve!:(value:typeof token)=>void,reject!:(error:unknown)=>void;vi.mocked(auth.registerTherapist).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));const keys={authKey:new Uint8Array(32).fill(31),wrapKek:new Uint8Array(32).fill(32),noteKey:new Uint8Array(32).fill(33)};provider.derivePortalKeys.mockResolvedValueOnce(keys);const handoffs:unknown[]=[];const root=await render(<LoginView onReady={async supplied=>{handoffs.push(supplied);}}/>);await registration(root);await press(root,"Create account");await flush();await act(async()=>root.unmount());actual.setSession("replacement-bearer","https://clinic.example");try{if(outcome==="resolve")resolve({...token,token:"retired-registration-bearer"});else reject(new ApiError(500,"late registration failure"));await flush(12);expect(handoffs).toEqual([]);expect(actual.hasSession()).toBe(true);for(const key of Object.values(keys))expect(key.every(byte=>byte===0)).toBe(true);}finally{resolve({...token,token:"retired-registration-bearer"});await flush();}
});

it.each(["signin", "register"])("retires a late mandatory MFA setup from %s without handing off or retaining borrowed keys",async mode=>{
 const actual=await vi.importActual<typeof import("../src/api")>("../src/api");vi.mocked(mode==="signin"?auth.login:auth.registerTherapist).mockResolvedValueOnce({...token,mfa_enrollment_required:true});let release!:(value:Awaited<ReturnType<typeof api.totpSetup>>)=>void;vi.mocked(api.totpSetup).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));const keys={authKey:new Uint8Array(32).fill(34),wrapKek:new Uint8Array(32).fill(35),noteKey:new Uint8Array(32).fill(36)};provider.derivePortalKeys.mockResolvedValueOnce(keys);const handoffs:unknown[]=[];const root=await render(<LoginView onReady={async supplied=>{handoffs.push(supplied);}}/>);if(mode==="signin"){await credentials(root);await press(root,"Sign in");}else{await registration(root);await press(root,"Create account");}await flush();await act(async()=>root.unmount());actual.setSession("replacement-bearer","https://clinic.example");try{release({secret_base32:"JBSWY3DPEHPK3PXP",otpauth_uri:"otpauth://totp/Fathom:test"});await flush(12);expect(handoffs).toEqual([]);expect(actual.hasSession()).toBe(true);for(const key of Object.values(keys))expect(key.every(byte=>byte===0)).toBe(true);}finally{release({secret_base32:"JBSWY3DPEHPK3PXP",otpauth_uri:"otpauth://totp/Fathom:test"});await flush();}
});
it("shows an empty second-factor field when the server first requires it and retires it when changing form modes",async()=>{
 const root=await rootView();await credentials(root);vi.mocked(auth.login).mockRejectedValueOnce(new ApiError(401,"second factor required","totp_required"));await press(root,"Sign in");await flush();output(root,"first second-factor challenge keeps password and empty code");
 await typeInto(root,"Authenticator code (or recovery code)","123456");await press(root,"Create a therapist account instead");await flush();output(root,"registration retires the sign-in factor and error");await press(root,"Back to sign in");await flush();output(root,"return from registration keeps no old sign-in factor");
});

it("clears a cancelled mandatory MFA code before a new enrollment starts",async()=>{
 vi.mocked(auth.login).mockResolvedValue({...token,mfa_enrollment_required:true});const root=await rootView();await credentials(root);await press(root,"Sign in");await flush();await typeInto(root,"Authenticator code","123456");await press(root,"Cancel and sign out");await flush();await typeInto(root,"Password","new sign-in password");await press(root,"Sign in");await flush();output(root,"new mandatory enrollment begins with an empty code");
});

it("does not send another bearer revocation after a failed MFA handoff has already retired it",async()=>{
 vi.mocked(auth.login).mockResolvedValueOnce({...token,mfa_enrollment_required:true});const revocations:string[]=[];vi.mocked(auth.logoutBearer).mockImplementation(async(_base,bearer)=>{revocations.push(bearer);return null;});
 const root=await render(<LoginView onReady={async()=>{throw new Error("shell unavailable");}}/>);await credentials(root);await press(root,"Sign in");await flush();await typeInto(root,"Authenticator code","123456");await press(root,"Enable two-factor authentication");await flush();await press(root,"I saved the codes — continue");await flush();expect(revocations).toEqual([token.token]);await press(root,"I saved the codes — return to sign in");await flush();expect(revocations).toEqual([token.token]);
});
it("renders empty login, registration and all missing-field gates",async()=>{
 const root=await rootView();output(root,"empty login");await press(root,"Create a therapist account instead");await flush();expect(root.root.findAllByType("input").find(node=>node.props.type==="checkbox")!.props.checked).toBe(false);output(root,"empty registration");
 await typeInto(root,"Username","doctor");output(root,"username alone");await typeInto(root,"Password","Strong!pass123");output(root,"confirmation and age missing");await typeInto(root,"Repeat password","Strong!pass123");output(root,"age missing");
});
it.each([0,403,409,429,500,501,400])("shows actionable registration failure %i and clears submission secrets",async status=>{
 const root=await rootView();await registration(root);await typeInto(root,"Clinician enrollment token","  organization-secret  ");
 vi.mocked(auth.registerTherapist).mockRejectedValueOnce(new ApiError(status,"untrusted server words"));
 await press(root,"Create account");await flush();output(root,"registration failure");expect(hasSession()).toBe(false);
});
it.each([0,429,500,501,400])("shows actionable sign-in failure %i and clears the submitted password",async status=>{
 const root=await rootView();await credentials(root);vi.mocked(auth.login).mockRejectedValueOnce(new ApiError(status,"untrusted server words"));
 await press(root,"Sign in");await flush();output(root,"sign-in failure");expect(hasSession()).toBe(false);
});
it("reports unavailable enrollment-policy lookup and disables registration",async()=>{
 vi.mocked(auth.meta).mockRejectedValueOnce(null);const root=await rootView();await press(root,"Create a therapist account instead");await flush();output(root,"policy unavailable");
});
it("keeps an unresolved policy visible and abandons it when returning to sign-in",async()=>{
 let release!:(policy:{sharing_available:boolean})=>void;vi.mocked(auth.meta).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 const root=await rootView();await press(root,"Create a therapist account instead");await flush();output(root,"checking policy");
 await press(root,"Back to sign in");release({sharing_available:false});await flush();output(root,"abandoned policy cannot affect sign-in");
});
it.each(["", "123456", "Aa0!Aa0!Aa0!", "lowercaselettersx", "OneStrongPass!123"])("shows password strength for %j",async password=>{
 const root=await rootView();await press(root,"Create a therapist account instead");await flush();await typeInto(root,"Password",password);output(root,"registration strength and policy");
});
it.each([["",0],["Aa0!Aa0!Aa0",1],["Aa0!Aa0!Aa0!",3],["lowercaselettersx",4],["OneStrongPass!123",4],["AAAAAAAAAAAA",2],["xpassword!123ABC",2],["aaaB3!different",3]] as const)("scores exact policy boundary %j as %i",(password,score)=>{expect(passwordStrength(password)).toBe(score);});
it("keeps pending sign-in and account-creation actions visible while the provider is working",async()=>{
 let release!:(value:typeof token)=>void;vi.mocked(auth.login).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 const root=await rootView();await credentials(root);await press(root,"Sign in");await flush();try{output(root,"sign-in pending");}finally{release(token);await flush();}
});
it("renders an unconfigured host without collecting credentials",async()=>{
 vi.stubGlobal("window",{location:{origin:"http://untrusted.example"}});const root=await rootView();output(root,"host origin rejected");
});
it("clears every provider-held registration key after a failed handoff",async()=>{
 const master=new Uint8Array(32).fill(9),authKey=new Uint8Array(32).fill(10),wrapKek=new Uint8Array(32).fill(11),noteKey=new Uint8Array(32).fill(12);
 provider.deriveMasterKey.mockResolvedValueOnce(master);provider.derivePortalKeys.mockResolvedValueOnce({authKey,wrapKek,noteKey});
 const root=await render(<LoginView onReady={async()=>{throw new Error("local handoff rejected");}}/>);await registration(root);await press(root,"Create account");await flush();
 for(const key of [master,authKey,wrapKek,noteKey])expect(key.every(value=>value===0)).toBe(true);output(root,"failed handoff leaves no live credentials");
});
it("shows a failed mandatory enrollment confirmation without retaining a submitted code",async()=>{
 vi.mocked(auth.login).mockResolvedValueOnce({...token,mfa_enrollment_required:true});
 const root=await rootView();await credentials(root);await press(root,"Sign in");await flush();output(root,"enrollment starts without a submitted code");
 await typeInto(root,"Authenticator code","a1234567b");output(root,"digits-only bounded code");vi.mocked(api.totpEnable).mockRejectedValueOnce(null);await press(root,"Enable two-factor authentication");await flush();output(root,"failed confirmation and wiped code");
});

it.each(["signin", "register"])("enables mandatory MFA for %s and hands off complete acknowledged credentials",async mode=>{
 const keys={authKey:new Uint8Array(32).fill(2),wrapKek:new Uint8Array(32).fill(3),noteKey:new Uint8Array(32).fill(4)};provider.derivePortalKeys.mockResolvedValueOnce(keys);
 vi.mocked(mode==="signin"?auth.login:auth.registerTherapist).mockResolvedValueOnce({...token,mfa_enrollment_required:true});let release!:()=>void;
 const adopted:unknown[]=[];const root=await render(<LoginView onReady={async(...args)=>{adopted.push(args);await new Promise<void>(resolve=>{release=resolve;});}}/>);
 if(mode==="signin"){await credentials(root);await press(root,"Sign in");}else{await registration(root);await press(root,"Create account");}await flush();expect(keys.authKey.every(byte=>byte===0)).toBe(true);expect(keys.wrapKek.every(byte=>byte===3)).toBe(true);expect(keys.noteKey.every(byte=>byte===4)).toBe(true);
 await typeInto(root,"Authenticator code","123456");let enabled!:(value:{backup_codes:string[]})=>void;vi.mocked(api.totpEnable).mockImplementationOnce(()=>new Promise(resolve=>{enabled=resolve;}));await press(root,"Enable two-factor authentication");await flush();output(root,"enrollment confirmation pending");enabled({backup_codes:["ABCDEF1234","GHIJKL5678"]});await flush();output(root,"backup codes await acknowledgement");await press(root,"I saved the codes — continue");await flush();
 try{output(root,"portal handoff pending");expect(adopted).toHaveLength(1);const [receivedKeys,receivedToken,base]=(adopted[0] as [import("../src/views/LoginView").PortalKeys,typeof token&{mfa_enrollment_required:boolean},string]);expect(receivedKeys.userId).toBe(token.user_id);expect(receivedKeys.noteKey).toBe(keys.noteKey);expect(receivedKeys.wrapKek).toBe(keys.wrapKek);expect(receivedToken).toMatchObject({...token,mfa_enrollment_required:false});expect(base).toBe("http://localhost:5173");}finally{release();await flush();}
 output(root,"completed enrollment clears setup surface");
});

it.each(["signin", "register"])("ends the locally installed bearer when mandatory MFA setup fails during %s",async mode=>{
 vi.mocked(mode==="signin"?auth.login:auth.registerTherapist).mockResolvedValueOnce({...token,mfa_enrollment_required:true});vi.mocked(api.totpSetup).mockRejectedValueOnce(new Error("Enrollment setup unavailable"));const root=await rootView();if(mode==="signin"){await credentials(root);await press(root,"Sign in");}else{await registration(root);await press(root,"Create account");}await flush(8);expect(hasSession()).toBe(false);expect(root.root.findAllByType("input").find(node=>node.props.autoComplete==="current-password"||node.props.autoComplete==="new-password")!.props.value).toBe("");
});

it("starts a later second-factor challenge with an empty field after returning from registration",async()=>{
 const root=await rootView();await credentials(root);vi.mocked(auth.login).mockRejectedValueOnce(new ApiError(401,"second factor required","totp_required"));await press(root,"Sign in");await flush();await typeInto(root,"Authenticator code (or recovery code)","123456");await press(root,"Create a therapist account instead");await press(root,"Back to sign in");await typeInto(root,"Password","second sign-in");vi.mocked(auth.login).mockRejectedValueOnce(new ApiError(401,"second factor required","totp_required"));await press(root,"Sign in");await flush();const factor=root.root.findAllByType("input").find(node=>node.props.autoComplete==="one-time-code")!;expect(factor.props.value).toBe("");
});

it.each(["username", "confirmation"])("keeps a host-requested incomplete registration submit inert when %s is missing",async missing=>{
 const root=await rootView();await registration(root);await typeInto(root,missing==="username"?"Username":"Repeat password","");const before=vi.mocked(auth.registerTherapist).mock.calls.length;await act(async()=>root.root.findByType("form").props.onSubmit({preventDefault(){}}));await flush();expect(vi.mocked(auth.registerTherapist).mock.calls.length).toBe(before);expect(hasSession()).toBe(false);
});

it("keeps a second host-requested sign-in submit inert while its first request is pending",async()=>{
 let release!:(value:typeof token)=>void;vi.mocked(auth.login).mockImplementation(()=>new Promise(resolve=>{release=resolve;}));const root=await rootView();await credentials(root);await press(root,"Sign in");await flush();try{await act(async()=>root.root.findByType("form").props.onSubmit({preventDefault(){}}));await flush();expect(vi.mocked(auth.login).mock.calls).toHaveLength(1);}finally{release(token);await flush();}
});

it.each(["cancel setup", "failed handoff", "cancel after failure"])("retires caller-held mandatory MFA custody on %s",async mode=>{
 const keys={authKey:new Uint8Array(32).fill(2),wrapKek:new Uint8Array(32).fill(3),noteKey:new Uint8Array(32).fill(4)};provider.derivePortalKeys.mockResolvedValueOnce(keys);vi.mocked(auth.login).mockResolvedValueOnce({...token,mfa_enrollment_required:true});
 const root=await render(<LoginView onReady={async()=>{throw new Error("shell failed");}}/>);await credentials(root);await press(root,"Sign in");await flush();
 if(mode!=="cancel setup"){await typeInto(root,"Authenticator code","123456");await press(root,"Enable two-factor authentication");await flush();await press(root,"I saved the codes — continue");await flush();output(root,"failed handoff preserves only recovery codes");}
 if(mode!=="failed handoff"){await press(root,mode==="cancel setup"?"Cancel and sign out":"I saved the codes — return to sign in");await flush();output(root,"cancelled enrollment returns to clean sign-in");}
 expect(hasSession()).toBe(false);for(const key of Object.values(keys))expect(key.every(byte=>byte===0)).toBe(true);
});

it("shows pending account creation and clears the host's registration salt before credential handoff",async()=>{
 const heldSalt:Uint8Array[]=[];const random=vi.spyOn(globalThis.crypto,"getRandomValues");random.mockImplementation(array=>{const bytes=array as Uint8Array<ArrayBuffer>;bytes.fill(7);heldSalt.push(bytes);return array;});let release!:(value:typeof token)=>void;vi.mocked(auth.registerTherapist).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 const root=await rootView();await registration(root);await press(root,"Create account");await flush();try{output(root,"registration request pending");expect(heldSalt).toHaveLength(1);expect(heldSalt[0]!.every(byte=>byte===0)).toBe(true);}finally{release(token);await flush();random.mockRestore();}
});

it.each(["reject", "resolve"])("ignores an older abandoned enrollment-policy %s after a new policy succeeds",async result=>{
 let resolve!:(value:{sharing_available:boolean})=>void,reject!:(error:unknown)=>void;vi.mocked(auth.meta).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));const root=await rootView();await press(root,"Create a therapist account instead");await press(root,"Back to sign in");await press(root,"Create a therapist account instead");await flush();if(result==="resolve")resolve({sharing_available:false});else reject(null);await flush();output(root,"new confirmed policy survives old response");
});

it.each(["username", "password", "confirmation", "age", "policy unavailable"])("renders the isolated missing registration %s gate",async missing=>{
 const root=await rootView();if(missing==="policy unavailable")vi.mocked(auth.meta).mockResolvedValueOnce({sharing_available:false});await registration(root);
 if(missing==="username")await typeInto(root,"Username","");if(missing==="password")await typeInto(root,"Password","");if(missing==="confirmation")await typeInto(root,"Repeat password","");if(missing==="age")await act(async()=>root.root.findAllByType("input").find(n=>n.props.type==="checkbox")!.props.onChange({target:{checked:false}}));output(root,"complete registration except isolated gate");
});

it.each(["sixteenlettersaa", "aaQwerty0123!"])("renders exact password strength and allows the authored passphrase %s",async password=>{
 const root=await rootView();await registration(root);await typeInto(root,"Password",password);await typeInto(root,"Repeat password",password);output(root,"complete registration with exact valid password");expect(passwordStrength(password)).toBe(password.length===16?4:3);
});

it.each([" 123456 ", "xyz123456", "123456!", "ABCDEFGHIJ", "abc1234567"])("preserves bounded authenticator or recovery input %j",async code=>{
 const root=await rootView();await credentials(root);vi.mocked(auth.login).mockRejectedValueOnce(new ApiError(401,"second factor required","totp_required"));await press(root,"Sign in");await flush();await typeInto(root,"Authenticator code (or recovery code)",code);output(root,"second-factor input and verification gate");
});
