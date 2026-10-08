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

const {api}=await import("../src/api");
const {PatientsView,resetScanConfirmation}=await import("../src/views/PatientsView");
const provider=vi.mocked(await import("../src/crypto"));
const {render,flush,textOf,press}=await import("./helpers/rtr");
const {act}=await import("react");
const session={username:"drportal",userId:"therapist-1",noteKey:new Uint8Array(32),noteKeyV2:new Uint8Array(32),privateKey:{} as CryptoKey,publicKeyB64:"public"};
const row=(id:string,name:string,date:string,extra:Partial<import("../src/api").Patient>={}):import("../src/api").Patient=>({user_id:id,username:name,status:"active",granted_at:date,revoked_at:null,ephemeral_pub:"public",wrapped_key:"sealed",summary_blob:"summary",summary_eph_pub:"public",summary_updated_at:"2026-09-30T00:00:00Z",...extra});
const patients=[row("a","Zulu","2026-09-02",{share_voice:true}),row("b","Alpha","2026-09-04",{share_voice:false}),row("c","Middle","2026-09-03"),row("d","Dormant","2026-09-01",{status:"revoked",revoked_at:null,share_voice:true})];
const output=(root:Awaited<ReturnType<typeof render>>,name:string)=>expect(publicSurface(root.toJSON())).toMatchSnapshot(name);
beforeEach(()=>{vi.clearAllMocks();resetScanConfirmation();window.sessionStorage.clear();window.localStorage.clear();vi.useFakeTimers({toFake:["Date"]});vi.setSystemTime(new Date("2026-10-05T00:00:00Z"));
 vi.mocked(api.patients).mockReset().mockResolvedValue(patients);
 vi.mocked(api.patientInsights).mockReset().mockResolvedValue({phase:"insight",active_days:45,streak:3,days_remaining:0,blob:"sealed",state_seq:7});
 provider.decryptCaseloadSummary.mockReset().mockImplementation(async(_key,_pub,_eph,_owner,id)=>({patterns:id==="a"?1:id==="b"?0:3,sensitive:id==="a",newest:null,forDate:"2026-09-29"}));
 provider.decryptInsights.mockReset().mockImplementation(async(_key,id)=>({state_seq:7,stats:{patterns:id==="b"?[]:[{kind:"topic",label:"work",occurrences:4,confidence:0.7,detail:{sensitive:id==="a",first_seen:"2026-09-30"}},{kind:"temporal",label:"sleep",occurrences:3,confidence:0.6,detail:{first_seen:"2026-09-29"}}]}}));
 provider.unwrapPatientDataKey.mockReset().mockImplementation(async()=>new Uint8Array(32).fill(11));
});
afterEach(()=>{vi.useRealTimers();vi.restoreAllMocks();});
async function caseload(){const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await flush(10);await vi.waitFor(()=>expect(textOf(root)).toContain("1 pattern as of"));return root;}
it("renders consent grants and summary dates, then searches and orders the same accessible patients",async()=>{
 const root=await caseload();output(root,"newest share and stopped consent");
 await act(async()=>root.root.findByType("select").props.onChange({target:{value:"username"}}));output(root,"alphabetical caseload");
 const input=root.root.findAllByType("input").find(n=>n.props["aria-label"]==="Search patients by username")!;
 await act(async()=>input.props.onChange({target:{value:"  ALPHA  "}}));output(root,"trimmed case-insensitive search");
 await act(async()=>input.props.onChange({target:{value:"unknown"}}));output(root,"empty filtered caseload");
});
it("acknowledges the scan footprint, displays current triage counts and retains exact reviewed-date deltas",async()=>{
 window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.a","2026-09-29");
 const root=await caseload();await press(root,"Scan caseload for triage");output(root,"scan requires permission for server audit footprint");
 await press(root,"Start the triage scan");await flush(12);output(root,"fresh scan replaces older summaries");
 await act(async()=>root.root.findByType("select").props.onChange({target:{value:"triage"}}));output(root,"sensitive-first then new-since-reviewed order");
});
it("makes a failed scan row honest while preserving its older encrypted summary",async()=>{
 const root=await caseload();provider.decryptInsights.mockRejectedValueOnce(new Error("failed auth"));await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(12);output(root,"failed patient scan retains dated summary");
});
it("shows scanning progress and stops further patient reads when the clinician leaves",async()=>{
 let release!:(value:Awaited<ReturnType<typeof api.patientInsights>>)=>void;vi.mocked(api.patientInsights).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 const root=await caseload();await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush();output(root,"scan pending");
 await act(async()=>root.unmount());release({phase:"insight",active_days:1,streak:0,days_remaining:0,blob:"sealed",state_seq:7});await flush(8);expect(api.patientInsights).toHaveBeenCalledTimes(1);expect(provider.decryptInsights).not.toHaveBeenCalled();
});
it.each(["invalid",null])("uses authenticated payload date when summary update timestamp is %s",async date=>{
 vi.mocked(api.patients).mockResolvedValueOnce(patients.map(p=>({...p,summary_updated_at:date})));output(await caseload(),"invalid timestamp falls back to authenticated date");
});

it("names every sensitive patient with plural grammar and preserves a failed scan's earlier warning",async()=>{
 provider.decryptCaseloadSummary.mockImplementation(async(_key,_pub,_eph,_owner,id)=>({patterns:1,sensitive:id!=="b",newest:null,forDate:"2026-09-29"}));const root=await caseload();output(root,"two sensitive patients before scan");provider.decryptInsights.mockRejectedValue(new Error("unavailable pattern data"));await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(12);output(root,"plural warning remains after failed scan");
});

it("lets a successful empty scan replace an older sensitive summary",async()=>{
 provider.decryptInsights.mockResolvedValue({state_seq:7,stats:{patterns:[]}});const root=await caseload();expect(textOf(root)).toContain("1 of your patients has a sensitive card");await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(12);expect(textOf(root)).not.toContain("has a sensitive card");expect(textOf(root)).not.toContain("have sensitive cards");output(root,"zero-pattern scan overrides older warning");
});

it.each(["baseline","absent ciphertext","missing public key","missing wrapped key"])("scans %s without inventing a clinical pattern",async mode=>{
 const selected=patients.map(patient=>mode==="missing public key"?{...patient,ephemeral_pub:null}:mode==="missing wrapped key"?{...patient,wrapped_key:null}:patient);vi.mocked(api.patients).mockResolvedValueOnce(selected);
 if(mode==="baseline")vi.mocked(api.patientInsights).mockResolvedValue({phase:"baseline",active_days:0,streak:0,days_remaining:30,blob:"sealed",state_seq:7});if(mode==="absent ciphertext")vi.mocked(api.patientInsights).mockResolvedValue({phase:"insight",active_days:0,streak:0,days_remaining:0,blob:null,state_seq:7});
 const root=await caseload();await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(12);output(root,"scan honestly records zero available patterns");
});

it("does not retain any provider-held patient key after a failed or successful scan",async()=>{
 const keys:Uint8Array[]=[];provider.unwrapPatientDataKey.mockImplementation(async()=>{const key=new Uint8Array(32).fill(18);keys.push(key);return key;});provider.decryptInsights.mockRejectedValueOnce(new Error("one patient's ciphertext failed authentication"));const root=await caseload();await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(16);expect(keys).toHaveLength(3);for(const key of keys)expect(key.every(byte=>byte===0)).toBe(true);expect(textOf(root)).toContain("1 pattern as of 2026-09-29");output(root,"failed scan preserves older summary while keys retire");
});

it("reports an authenticated summary with no supplied date as unknown",async()=>{
 vi.mocked(api.patients).mockResolvedValueOnce(patients.map(patient=>({...patient,summary_updated_at:null})));provider.decryptCaseloadSummary.mockImplementation(async()=>({patterns:1,sensitive:false,newest:null,forDate:null}));const root=await caseload();expect(textOf(root)).toContain("1 pattern as of an unknown date");output(root,"unknown authenticated summary date");
});

it("uses the requested search spelling only after trimming it in the empty-results message",async()=>{
 const root=await caseload();const input=root.root.findAllByType("input").find(n=>n.props["aria-label"]==="Search patients by username")!;await act(async()=>input.props.onChange({target:{value:"  Nobody  "}}));expect(textOf(root)).toContain("No patients match “Nobody”.");output(root,"trimmed empty-results search spelling");
});

it("keeps the triage scan's server access footprint limited to actively sharing patients",async()=>{
 const accessed:string[]=[];vi.mocked(api.patientInsights).mockImplementation(async id=>{accessed.push(id);return {phase:"insight",active_days:45,streak:3,days_remaining:0,blob:"sealed",state_seq:7};});const root=await caseload();await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(16);expect(accessed).toEqual(["a","b","c"]);
});

it("ends the scan's server access footprint when leaving during a patient decrypt",async()=>{
 let release!:(value:Awaited<ReturnType<typeof provider.decryptInsights>>)=>void;provider.decryptInsights.mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));const root=await caseload();await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush();await act(async()=>root.unmount());try{release({state_seq:7,stats:{patterns:[]}});await flush(16);expect(vi.mocked(api.patientInsights).mock.calls.map(([id])=>id)).toEqual(["a"]);}finally{release({state_seq:7,stats:{patterns:[]}});await flush();}
});

it("uses singular fresh-scan grammar and breaks equal triage counts by the latest grant",async()=>{
 provider.decryptInsights.mockResolvedValue({state_seq:7,stats:{patterns:[{kind:"topic",label:"work",occurrences:4,confidence:0.7,detail:{first_seen:"2026-09-30"}}]}});
 const root=await caseload();await press(root,"Scan caseload for triage");await press(root,"Start the triage scan");await flush(16);expect(textOf(root)).toContain("1 pattern (scanned just now)");expect(textOf(root)).not.toContain("1 patterns (scanned just now)");
 await act(async()=>root.root.findByType("select").props.onChange({target:{value:"triage"}}));expect(root.root.findAllByType("strong").filter(node=>node.props.className==="patient-name").map(node=>node.children.join(""))).toEqual(["Alpha","Middle","Zulu"]);
});
