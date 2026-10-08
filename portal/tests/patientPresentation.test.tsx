import { runTestControl } from "./helpers/testControl";
import {setKvBackendForTests} from "../src/kvstore";
import {savePortalDraft} from "../src/noteDrafts";
/**
 * View behavior with mocked api/crypto layers (the crypto itself is
 * pinned by tests/crypto.test.ts against the real WebCrypto): login and
 * registration flows, the patients list + pairing code, and the patient
 * view — pattern cards, the sensitive non-quoting card, the evidence
 * drill-down, and notes.
 */
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act } from "react";
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
      patientAudio: vi.fn(async () => ({id:"audio-2",client_entry_id:"entry-2",duration_seconds:1,size_bytes:40,created_at:"2026-09-02",expires_at:"2026-10-07",blob:"sealed",mime_type:"audio/webm"})),
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

const { api, ApiError } = await import("../src/api");
const { PatientView, resetInsightsFreshness } = await import("../src/views/PatientView");
const provider = vi.mocked(await import("../src/crypto"));
const { render, flush, textOf, press, typeTextarea } = await import("./helpers/rtr");
const patient = {user_id:"user-1",username:"patienta",status:"active",granted_at:"2026-09-01T10:00:00Z",revoked_at:null as string|null,ephemeral_pub:"public",wrapped_key:"sealed",share_voice:true};
const session = {username:"drportal",userId:"therapist-1",noteKey:new Uint8Array(32),noteKeyV2:new Uint8Array(32),privateKey:{} as CryptoKey,publicKeyB64:"public"};
const pattern = (kind="temporal", detail:Record<string,unknown>={}): import("../src/crypto").PatternPayload => ({kind,label:"work",occurrences:4,confidence:0.75,detail:{pattern_pid:`${kind}:work`,...detail}});
const summary = {phase:"insight",active_days:45,streak:3,days_remaining:0,blob:"sealed",state_seq:7};
const note = (id="note-1",pid:string|null=null) => ({id,client_note_id:`client-${id}`,blob:"sealed",created_at:"2026-09-01T00:00:00Z",updated_at:"2026-09-02T00:00:00Z",version:2,pattern_pid:pid});
async function chart(row:import("../src/api").Patient=patient) {
  const root = await render(<PatientView patient={row} session={session} onBack={()=>{}} onSignOut={()=>{}} />);
  await flush(8);
  return root;
}
const output = (root:Awaited<ReturnType<typeof render>>, state:string) => expect(publicSurface(root.toJSON())).toMatchSnapshot(state);
beforeEach(()=>{
  vi.useFakeTimers({toFake:["Date"]});vi.setSystemTime(new Date("2026-10-05T00:00:00Z"));
  vi.clearAllMocks(); runTestControl(resetInsightsFreshness); window.sessionStorage.clear(); window.localStorage.clear();
  vi.mocked(api.patientInsights).mockReset().mockResolvedValue(summary);
  vi.mocked(api.patientEntries).mockReset().mockResolvedValue({entries:[],nextOffset:null});
  vi.mocked(api.patientMeasures).mockReset().mockResolvedValue({measures:[],nextOffset:null});
  vi.mocked(api.notes).mockReset().mockResolvedValue({notes:[],nextOffset:null});
  vi.mocked(api.noteRevisions).mockReset().mockResolvedValue([]);
  vi.mocked(api.createNote).mockReset().mockImplementation(async(_patient,payload)=>({...note("new-note"),client_note_id:payload.client_note_id,blob:payload.blob,pattern_pid:payload.pattern_pid??null,version:1}));
  provider.decryptInsights.mockReset().mockResolvedValue({state_seq:7,stats:{patterns:[pattern()]}});
  provider.decryptMeasure.mockReset().mockResolvedValue(null);
  provider.decryptEntry.mockReset().mockResolvedValue({text:"work in original words",sentiment:0.8});
  provider.decryptNoteAny.mockReset().mockImplementation(async (_active,_legacy,_owner,_patient,id)=>`Clinical text ${id}`);
  provider.encryptNote.mockReset().mockImplementation(async(_key,_owner,_patient,id)=>({clientNoteId:id,blobB64:"SEALEDNOTE=="}));
  provider.unwrapPatientDataKey.mockReset().mockImplementation(async()=>new Uint8Array(32).fill(11));
});
afterEach(()=>{vi.restoreAllMocks();vi.useRealTimers();vi.unstubAllGlobals();});

it("prints the selected pattern's own notes and preserves the sensitive card's non-quoting heading",async()=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("recurring_phrase",{sensitive:true})]}});vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("specific","recurring_phrase:work")],nextOffset:null});
 const root=await chart();await press(root,"See the evidence");await flush();expect(textOf(root)).toContain("A difficult thought has been returning");expect(textOf(root)).toContain("Therapist notes (this pattern)");expect(textOf(root)).toContain("Clinical text client-specific");
});

it("plots three chronological mood observations across the full visible chart width",async()=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-03","2026-09-01","2026-09-02"]})]}});
 vi.mocked(api.patientEntries).mockImplementationOnce(async(_id,params)=>{expect(params).toMatchObject({since:"2026-09-01",until:"2026-09-03"});return {entries:[3,1,2].map(day=>({id:`entry-${day}`,client_entry_id:`entry-${day}`,entry_date:`2026-09-0${day}`,received_at:`2026-09-0${day}`,blob:"sealed"})),nextOffset:null};});
 provider.decryptEntry.mockImplementation(async(_key,_owner,row)=>({text:"work",sentiment:Number(row.client_entry_id.at(-1))-2}));const root=await chart();await press(root,"See the evidence");await flush(10);
 const svg=root.root.findAllByType("svg").find(node=>String(node.props["aria-label"]).startsWith("Mood over the 3"))!;expect(svg.findByType("path").props.d).toBe("M0.0,45.0 L160.0,24.0 L320.0,3.0");
});

it.each([200,201])("enforces the %i-row evidence aggregate across individually permitted pages",async count=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});
 vi.mocked(api.patientEntries).mockImplementation(async(_id,params)=>{const offset=params?.offset??0,entries=Array.from({length:Math.min(25,Math.max(0,count-offset))},(_,index)=>({id:`entry-${offset+index}`,client_entry_id:`entry-${offset+index}`,entry_date:"2026-09-01",received_at:"2026-09-01",blob:"sealed"}));return {entries,nextOffset:entries.length===25?offset+25:null,revision:"17"};});
 const root=await chart();await press(root,"See the evidence");await flush(16);
 if(count===201){expect(textOf(root)).toContain("evidence window exceeds this portal's safe page limit");expect(provider.decryptEntry).not.toHaveBeenCalled();}
 else expect(provider.decryptEntry).toHaveBeenCalledTimes(200);
});

it("preserves the supplied custody generation when the note receiver requires it",async()=>{
 const owned={...session,custodyVersion:17};let accepted=false;vi.mocked(api.createNote).mockImplementationOnce(async(_patient,payload)=>{if(payload.custody_version!==17)throw new ApiError(409,"custody changed","custody_conflict");accepted=true;return {...note("custody-bound"),client_note_id:payload.client_note_id,blob:payload.blob,version:1};});
 const root=await render(<PatientView patient={{...patient,status:"revoked"}} session={owned} onBack={()=>{}} onSignOut={()=>{}}/>);await flush(8);await typeTextarea(root,"Note about this patient…","Custody-bound clinical writing");await press(root,"Save note");await vi.waitFor(()=>expect(accepted).toBe(true));expect(textOf(root)).toContain("Custody-bound clinical writing");
});

it("reports an inline measures failure when the provider rejects a non-Error value",async()=>{
 vi.mocked(api.patientMeasures).mockRejectedValueOnce(null);const root=await chart();await flush(12);expect(textOf(root)).toContain("could not load this patient's recorded measures");expect(textOf(root)).toContain("work");
});

it("reports a notes failure safely when the provider rejects a non-Error value",async()=>{
 vi.mocked(api.notes).mockRejectedValueOnce(null);const root=await chart({...patient,status:"revoked"});await flush(12);expect(textOf(root)).toContain("could not load therapist notes");expect(textOf(root)).toContain("Retry loading this patient");
});

it.each(["old notes","old notes failure","old measures","old measures failure"])("keeps a genuine chart retry authoritative after %s finishes late",async mode=>{
 let release!:(value:unknown)=>void;let reject!:(error:unknown)=>void;
 if(mode.startsWith("old notes"))vi.mocked(api.notes).mockImplementationOnce(()=>new Promise((resolve,fail)=>{release=value=>resolve(value as Awaited<ReturnType<typeof api.notes>>);reject=fail;}));
 else if(mode==="old measures failure")vi.mocked(api.patientMeasures).mockImplementationOnce(()=>new Promise((resolve,fail)=>{release=value=>resolve(value as Awaited<ReturnType<typeof api.patientMeasures>>);reject=fail;}));
 else{vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:[{id:"old-measure",client_measure_id:"old-measure",measure_date:"2026-09-01",received_at:"2026-09-01",blob:"sealed"}],nextOffset:null});provider.decryptMeasure.mockImplementationOnce(()=>new Promise((resolve,fail)=>{release=value=>resolve(value as Awaited<ReturnType<typeof provider.decryptMeasure>>);reject=fail;}));}
 vi.mocked(api.patientInsights).mockRejectedValueOnce(new ApiError(503,"temporary server fault"));const root=await chart();await vi.waitFor(()=>expect(textOf(root)).toContain("Retry loading this patient"));
 if(mode==="old measures")await vi.waitFor(()=>expect(release).toBeDefined());
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("current-note")],nextOffset:null});vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:[{id:"current-measure",client_measure_id:"current-measure",measure_date:"2026-09-02",received_at:"2026-09-02",blob:"sealed"}],nextOffset:null});provider.decryptMeasure.mockResolvedValueOnce({measure:"gad7",score:13,measureDate:"2026-09-02",completedAt:null});
 await press(root,"Retry loading this patient");await flush(16);expect(textOf(root)).toContain("Clinical text client-current-note");expect(textOf(root)).toContain("2026-09-02: 13");
 try{if(mode.endsWith("failure"))reject(new Error("retired chart read failed"));else release(mode==="old notes"?{notes:[note("retired-note")],nextOffset:null}:{measure:"gad7",score:2,measureDate:"2026-09-01",completedAt:null});await flush(16);expect(textOf(root)).toContain("Clinical text client-current-note");expect(textOf(root)).toContain("2026-09-02: 13");expect(textOf(root)).not.toContain("Clinical text client-retired-note");expect(textOf(root)).not.toContain("retired chart read failed");expect(textOf(root)).not.toContain("2026-09-01: 2");}finally{release(mode.startsWith("old notes")?{notes:[],nextOffset:null}:{measures:[],nextOffset:null});await flush();}
});

it("clears the selected evidence and printed account provenance when retrying a partially failed chart",async()=>{
 let rejectNotes!:(error:unknown)=>void;vi.mocked(api.notes).mockImplementationOnce(()=>new Promise((_resolve,reject)=>{rejectNotes=reject;}));provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{total_entries:37,active_days:19,patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});
 const root=await chart();await press(root,"See the evidence");await flush(10);expect(textOf(root)).toContain("37 entries");rejectNotes(new Error("notes temporarily unavailable"));await flush();
 let release!:(value:typeof summary)=>void;vi.mocked(api.patientInsights).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));await press(root,"Retry loading this patient");
 try{expect(textOf(root)).toContain("Loading decrypted patterns…");expect(textOf(root)).not.toContain("37 entries");expect(textOf(root)).not.toContain("Back to all patterns");expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")).toBeDefined();}finally{release(summary);await flush(10);}
});

it("restores a historical-custody draft through the real encrypted local storage interface",async()=>{
 const owned={...session,noteKey:new Uint8Array(32).fill(17),noteKeyV2:new Uint8Array(32).fill(23),historicalNoteKeys:[new Uint8Array(32).fill(31)]};await savePortalDraft(owned.userId,patient.user_id,owned.historicalNoteKeys[0]!,{text:{general:"Historical custody preserves this unsent clinical note"},pending:{},editing:null});
 const root=await render(<PatientView patient={{...patient,status:"revoked"}} session={owned} onBack={()=>{}} onSignOut={()=>{}}/>);await flush(10);await vi.waitFor(()=>expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!.props.value).toBe("Historical custody preserves this unsent clinical note"));expect(owned.historicalNoteKeys[0]!.every(byte=>byte===31)).toBe(true);
});

it("keeps local writing disabled after storage fails and restores the encrypted draft after an explicit retry",async()=>{
 const records=new Map<string,string>();let blocked=false;runTestControl(setKvBackendForTests,{getItem:async id=>{if(blocked)throw new Error("host storage unavailable");return records.get(id)??null;},setItem:async(id,value)=>{records.set(id,value);},removeItem:async id=>{records.delete(id);}});
 await savePortalDraft(session.userId,patient.user_id,session.noteKeyV2,{text:{general:"Recovered local clinical draft"},pending:{},editing:null});blocked=true;const root=await chart({...patient,status:"revoked"});await flush(12);expect(textOf(root)).toContain("Local encrypted records could not be read.");
 const composer=root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!;expect(composer.props.disabled).toBe(true);expect(root.root.findAllByType("button").find(node=>node.children.join("")==="Save note")!.props.disabled).toBe(true);
 blocked=false;await press(root,"Retry restoring encrypted draft");await vi.waitFor(()=>expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!.props.value).toBe("Recovered local clinical draft"));expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!.props.disabled).toBe(false);
});

it("does not overwrite an unreadable note from a restored edit draft",async()=>{
 await savePortalDraft(session.userId,patient.user_id,session.noteKeyV2,{text:{},pending:{},editing:{id:"unreadable-note",text:"Unsent edit kept for human recovery"}});vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("unreadable-note")],nextOffset:null});provider.decryptNoteAny.mockRejectedValueOnce(new Error("authentication failed"));
 const root=await chart({...patient,status:"revoked"});await flush(12);await press(root,"Save edit");await flush(10);expect(api.updateNote).not.toHaveBeenCalled();expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Editing note…")!.props.value).toBe("Unsent edit kept for human recovery");
});

it("serializes separate public note-history requests and leaves each completed history intact",async()=>{
 const first=note("first"),second=note("second");vi.mocked(api.notes).mockResolvedValueOnce({notes:[first,second],nextOffset:null});let release!:(value:Awaited<ReturnType<typeof api.noteRevisions>>)=>void;const reads:string[]=[];vi.mocked(api.noteRevisions).mockImplementationOnce(id=>{reads.push(id);return new Promise(resolve=>{release=resolve;});}).mockImplementation(async id=>{reads.push(id);return [{id:`revision-${id}`,blob:`old-${id}`,created_at:"2026-08-01"}];});provider.decryptNoteAny.mockImplementation(async(_active,_legacy,_owner,_patient,id,blob)=>blob.startsWith("old-")?`Prior clinical text ${id}`:`Clinical text ${id}`);
 const root=await chart({...patient,status:"revoked"});await press(root,"View history");await flush();await press(root,"View history");expect(reads).toEqual(["first"]);
 release([{id:"revision-first",blob:"old-first",created_at:"2026-08-01"}]);await flush(10);await press(root,"View history");await flush(10);expect(reads).toEqual(["first","second"]);expect(textOf(root)).toContain("Prior clinical text client-first");expect(textOf(root)).toContain("Prior clinical text client-second");
 const secondRow=root.root.findAllByType("div").find(node=>node.props.className==="entry-row"&&node.findAllByType("p").some(p=>p.children.join("").includes("Clinical text client-second")))!;await act(async()=>secondRow.findAllByType("button").find(button=>button.children.join("")==="Hide history")!.props.onClick());expect(textOf(root)).toContain("Prior clinical text client-first");expect(textOf(root)).not.toContain("Prior clinical text client-second");
});

it("retains one note's failed-history explanation when another note's history is hidden",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("first"),note("second")],nextOffset:null});vi.mocked(api.noteRevisions).mockImplementation(async id=>[{id:`revision-${id}`,blob:`bad-${id}`,created_at:"2026-08-01"}]);provider.decryptNoteAny.mockImplementation(async(_active,_legacy,_owner,_patient,id,blob)=>{if(blob.startsWith("bad-"))throw new Error("historical ciphertext authentication failed");return `Clinical text ${id}`;});
 const root=await chart({...patient,status:"revoked"});await press(root,"View history");await flush(10);await press(root,"View history");await flush(10);const failure="(earlier versions could not be decrypted)";expect(root.root.findAllByType("p").filter(node=>node.props.className==="history-line"&&node.children.join("")===failure)).toHaveLength(2);
 const secondRow=root.root.findAllByType("div").find(node=>node.props.className==="entry-row"&&node.findAllByType("p").some(p=>p.children.join("").includes("Clinical text client-second")))!;await act(async()=>secondRow.findAllByType("button").find(button=>button.children.join("")==="Hide history")!.props.onClick());expect(root.root.findAllByType("p").filter(node=>node.props.className==="history-line"&&node.children.join("")===failure)).toHaveLength(1);
});

it.each(["playing","failed"])("limits %s voice output to the one requested recording",async mode=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01","2026-09-02"]})]}});vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:[1,2].map(day=>({id:`entry-${day}`,client_entry_id:`entry-${day}`,entry_date:`2026-09-0${day}`,received_at:`2026-09-0${day}`,blob:"sealed",audio:{attachment_id:`audio-${day}`,expires_at:"2026-10-07"}})),nextOffset:null});
 const root=await chart();await press(root,"See the evidence");await flush(12);
 if(mode==="playing"){vi.spyOn(provider,"decryptAudio").mockResolvedValueOnce(new Uint8Array([82,73,70,70,1,2]));vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:one-recording");vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});}
 else vi.mocked(api.patientAudio).mockRejectedValueOnce(new ApiError(410,"expired","audio_expired"));
 await press(root,"play recording");await flush(12);
 if(mode==="playing")expect(root.root.findAllByType("audio")).toHaveLength(1);
 else expect(root.root.findAllByType("p").filter(node=>node.children.join("")==="this recording expired and was deleted")).toHaveLength(1);
});

it("preserves distinct pending requests when a legacy pattern and a modern pattern share a draft scope",async()=>{
 const legacy=pattern();delete legacy.detail.pattern_pid;const modern=pattern();provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[legacy,modern]}});
 const records=new Map<string,ReturnType<typeof note>>();let calls=0;vi.mocked(api.createNote).mockImplementation(async(_patient,payload)=>{const previous=records.get(payload.client_note_id);if(previous&&previous.pattern_pid!==(payload.pattern_pid??null))throw new ApiError(409,"note id already used","conflict");const saved=previous??{...note(`received-${records.size}`,payload.pattern_pid??null),client_note_id:payload.client_note_id,blob:payload.blob,version:1};records.set(payload.client_note_id,saved);if(calls++===0)throw new ApiError(503,"acknowledgment lost");return saved;});
 const root=await chart();await press(root,"See the evidence");await typeTextarea(root,"Note about this pattern…","The same clinical writing belongs to its selected anchor");await press(root,"Save note");await vi.waitFor(()=>expect(textOf(root)).toContain("server is busy — try again"));await press(root,"Back to all patterns");const options=root.root.findAllByType("button").filter(button=>button.children.join("")==="See the evidence");await act(async()=>options[1]!.props.onClick());await flush(8);await press(root,"Save note");await vi.waitFor(()=>expect(records.size).toBe(2));expect([...records.values()].map(row=>row.pattern_pid)).toEqual([null,"temporal:work"]);
});



it("keeps two independent notes distinct through the receiver's declared idempotency identifier contract",async()=>{
 const random=crypto.getRandomValues.bind(crypto);let issued=0;vi.spyOn(crypto,"getRandomValues").mockImplementation(array=>{const bytes=array as Uint8Array;if(bytes.length===8){bytes.fill(0);if(issued++===0){bytes[0]=1;bytes[1]=0x23;}else{bytes[0]=0x12;bytes[1]=3;}return array;}return random(array);});
 provider.encryptNote.mockImplementation(async(_key,_owner,_patient,id,text)=>({clientNoteId:id,blobB64:btoa(text)}));provider.decryptNoteAny.mockImplementation(async(_active,_legacy,_owner,_patient,_id,blob)=>atob(blob));const records=new Map<string,ReturnType<typeof note>>();vi.mocked(api.notes).mockImplementation(async()=>({notes:[...records.values()],nextOffset:null}));vi.mocked(api.createNote).mockImplementation(async(_patient,payload)=>{if(!/^[A-Za-z0-9_-]{1,64}$/.test(payload.client_note_id))throw new ApiError(422,"invalid client note identifier");const existing=records.get(payload.client_note_id);if(existing&&existing.blob!==payload.blob)throw new ApiError(409,"identifier already used","version_conflict");const row=existing??{...note(`persisted-${records.size}`),client_note_id:payload.client_note_id,blob:payload.blob,version:1};records.set(payload.client_note_id,row);return row;});
 const root=await chart({...patient,status:"revoked"});for(const text of ["First independently saved note","Second independently saved note"]){await typeTextarea(root,"Note about this patient…",text);await press(root,"Save note");await vi.waitFor(()=>expect(textOf(root)).toContain(text));await flush(8);}await act(async()=>root.unmount());const reopened=await chart({...patient,status:"revoked"});expect(textOf(reopened)).toContain("First independently saved note");expect(textOf(reopened)).toContain("Second independently saved note");
});

it("seals changed writing afresh after a failed create and restores the receiver's acknowledged text",async()=>{
 provider.encryptNote.mockImplementation(async(_key,_owner,_patient,id,text)=>({clientNoteId:id,blobB64:btoa(text)}));provider.decryptNoteAny.mockImplementation(async(_active,_legacy,_owner,_patient,_id,blob)=>atob(blob));let committed:ReturnType<typeof note>|null=null;vi.mocked(api.notes).mockImplementation(async()=>({notes:committed?[committed]:[],nextOffset:null}));vi.mocked(api.createNote).mockRejectedValueOnce(new ApiError(503,"network response lost")).mockImplementationOnce(async(_patient,payload)=>{committed={...note("acknowledged"),client_note_id:payload.client_note_id,blob:payload.blob,version:1};return committed;});
 const root=await chart({...patient,status:"revoked"});await typeTextarea(root,"Note about this patient…","First draft attempt");await press(root,"Save note");await vi.waitFor(()=>expect(textOf(root)).toContain("server is busy — try again"));await typeTextarea(root,"Note about this patient…","Revised draft after failed attempt");await press(root,"Save note");await vi.waitFor(()=>expect(committed).not.toBeNull());await flush(8);await act(async()=>root.unmount());const reopened=await chart({...patient,status:"revoked"});expect(textOf(reopened)).toContain("Revised draft after failed attempt");expect(textOf(reopened)).not.toContain("First draft attempt");
});

it.each([1000,1001])("preserves the public %i-row note aggregate bound across individually valid pages",async count=>{
 vi.mocked(api.notes).mockImplementation(async(_id,params)=>{const offset=params?.offset??0,notes=Array.from({length:Math.min(100,Math.max(0,count-offset))},(_,index)=>note(`bounded-${offset+index}`));return {notes,nextOffset:notes.length===100?offset+100:null,revision:"17"};});const root=await chart({...patient,status:"revoked"});
 if(count===1001){await vi.waitFor(()=>expect(textOf(root)).toContain("note history exceeds this portal's safe entry limit"));expect(root.root.findAllByType("p").filter(node=>String(node.props.children).startsWith("Clinical text client-bounded-"))).toHaveLength(0);}
 else await vi.waitFor(()=>expect(root.root.findAllByType("p").filter(node=>String(node.props.children).startsWith("Clinical text client-bounded-"))).toHaveLength(1000));
});

it.each(["note","measure","evidence"])("refuses a %s snapshot revision that changes across individually valid pages",async scope=>{
 if(scope==="note")vi.mocked(api.notes).mockResolvedValueOnce({notes:[note()],nextOffset:1,revision:"17"}).mockResolvedValueOnce({notes:[],nextOffset:null,revision:"18"});
 if(scope==="measure")vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:[{id:"measure",client_measure_id:"client-measure",blob:"sealed",measure_date:"2026-09-01",received_at:"2026-09-01"}],nextOffset:1,revision:"17"}).mockResolvedValueOnce({measures:[],nextOffset:null,revision:"18"});
 if(scope==="evidence"){provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:[{id:"entry",client_entry_id:"client-entry",blob:"sealed",entry_date:"2026-09-01",received_at:"2026-09-01"}],nextOffset:1,revision:"17"}).mockResolvedValueOnce({entries:[],nextOffset:null,revision:"18"});}
 const root=await chart();if(scope==="evidence")await press(root,"See the evidence");await flush(12);expect(textOf(root)).toContain(`server returned an inconsistent ${scope==='measure'?'measures':scope==='evidence'?'evidence':'note'} snapshot revision`);
});

it.each(["note","measure","evidence"])("refuses a %s revision appearing after a headerless first page",async scope=>{
 if(scope==="note")vi.mocked(api.notes).mockResolvedValueOnce({notes:[note()],nextOffset:1}).mockResolvedValueOnce({notes:[],nextOffset:null,revision:"17"});
 if(scope==="measure")vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:[{id:"measure",client_measure_id:"client-measure",blob:"sealed",measure_date:"2026-09-01",received_at:"2026-09-01"}],nextOffset:1}).mockResolvedValueOnce({measures:[],nextOffset:null,revision:"17"});
 if(scope==="evidence"){provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:[{id:"entry",client_entry_id:"client-entry",blob:"sealed",entry_date:"2026-09-01",received_at:"2026-09-01"}],nextOffset:1}).mockResolvedValueOnce({entries:[],nextOffset:null,revision:"17"});}
 const root=await chart();if(scope==="evidence")await press(root,"See the evidence");await flush(12);expect(textOf(root)).toContain(`server changed the ${scope==='measure'?'measures':scope==='evidence'?'evidence':'note'} pagination protocol mid-load`);
});

it.each([
  ["temporal",{}], ["mood_correlation",{}], ["link",{}], ["mood_shift",{}],
  ["inertia",{}], ["instability",{}], ["rumination",{}], ["recurring_phrase",{}],
  ["topic",{trend:"rising"}], ["topic",{trend:"steady"}], ["avoidance",{}], ["cadence",{}],
  ["unknown_kind",{}], ["avoidance",{silences:0,observed:10}],
  ["temporal",{day:"Tuesday",day_count:0,sample_days:8}],
  ["mood_correlation",{direction:"lower",mood_delta:0}],
  ["link",{direction:"higher",lag_days:0}], ["mood_shift",{direction:"higher"}],
] as const)("renders the complete clinical description and evidence for %s %j",async(kind,detail)=>{
  provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern(kind,detail)]}});
  const root=await chart(); output(root,"pattern card"); await press(root,"See the evidence");await flush();output(root,"selected evidence and empty entries");
});

it("orders clinical review by sensitive, down-shift, rumination and evidence density with exact provenance",async()=>{
  const patterns=[pattern("topic",{strength:0.1}),pattern("link",{strength:0.9}),pattern("temporal",{strength:0.3}),pattern("mood_shift",{direction:"higher",strength:0.4}),pattern("avoidance",{strength:0.2}),pattern("rumination",{strength:0.8}),pattern("mood_shift",{direction:"lower"}),pattern("recurring_phrase",{sensitive:true})];
  provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns,total_entries:15,active_days:10,first_date:"2026-08-01",last_date:"2026-09-10",avg_sentiment:-0.125,mood_summary:{source:"mixed",observations:12,explicit_mood:8,text_estimates:4,excluded_entries:3}}});
  output(await chart(),"clinical ordering and complete account provenance");
});

it.each(["legacy", "no observations", "empty", "baseline", "not computed"])("renders %s analysis without inventing coverage",async mode=>{
  if(mode==="baseline"||mode==="not computed")vi.mocked(api.patientInsights).mockResolvedValueOnce({...summary,blob:null,phase:mode==="baseline"?"baseline":"insight",days_remaining:4});
  else provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:mode==="empty"?{patterns:[]}:{patterns:[pattern()],...(mode==="no observations"?{mood_summary:{source:"mixed",observations:0,explicit_mood:0,text_estimates:0,excluded_entries:8}}:{})}});
  output(await chart(),mode);
});

it.each([61,62])("shows every recorded instrument and states the %i-reading trend-window truncation",async count=>{
  const readings:import("../src/crypto").MeasureReading[]=Array.from({length:count},(_,i)=>({measure:"phq9",score:i%28,item9:i===count-1?1:0,completedAt:null,measureDate:new Date(Date.UTC(2026,6,i+1)).toISOString().slice(0,10)}));
  readings.push({measure:"gad7",score:0,completedAt:null,measureDate:"2026-09-04"},{measure:"gad7",score:2,completedAt:null,measureDate:"2026-09-01"},{measure:"phq2",score:4,completedAt:null,measureDate:"2026-09-03"});
  vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:readings.map((r,i)=>({id:`m${i}`,client_measure_id:`cm${i}`,received_at:r.measureDate,measure_date:r.measureDate,blob:"sealed",created_at:r.measureDate})),nextOffset:null});
  const byDate=[...readings];provider.decryptMeasure.mockImplementation(async()=>byDate.shift()!);
  const root=await chart();await vi.waitFor(()=>expect(textOf(root)).toContain(`Recorded measures (${count+3})`));output(root,"all instruments, chronological curves, item nine and explicit omitted count");
});

async function evidence(translation: { english_text?: string | null; transcript_lang?: string } | undefined = undefined, expiresAt = "2026-10-07T00:00:00Z") {
  provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-02","2026-09-01"]})]}});
  const rows=[{id:"e2",entry_date:"2026-09-02",client_entry_id:"entry-2",blob:"sealed",received_at:"2026-09-02",audio:{attachment_id:"audio-2",expires_at:expiresAt}},{id:"e1",entry_date:"2026-09-01",client_entry_id:"entry-1",blob:"sealed",received_at:"2026-09-01"}];
  vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:rows,nextOffset:null});
  provider.decryptEntry.mockImplementation(async(_key,_owner,row)=>row.client_entry_id==="entry-2"?{text:"work dans les mots originaux",...(translation??{english_text:"work in the translated words",transcript_lang:"fr"}),sentiment:0.8}:{text:"First work day",sentiment:-0.8});
  const root=await chart();await press(root,"See the evidence");await flush(8);return root;
}

it("renders chronological mood evidence and toggles translated text back to the original language",async()=>{
  vi.useFakeTimers({toFake:["Date"]});vi.setSystemTime(new Date("2026-10-05T00:00:00Z"));
  const root=await evidence();output(root,"chronological chart and English translation");await press(root,"show original (fr)");output(root,"original French words");await press(root,"show translation");output(root,"translated again");
});

it("keeps original evidence visible when an authenticated translation is empty",async()=>{
 const root=await evidence({english_text:"",transcript_lang:"fr"});expect(textOf(root)).toContain("dans les mots originaux");expect(root.root.findAllByType("button").some(button=>String(button.props.children).includes("show original"))).toBe(false);
});

it("offers the authored original-text label when translated evidence has no language tag",async()=>{
 const root=await evidence({english_text:"work translated"});await press(root,"show original");expect(textOf(root)).toContain("dans les mots originaux");
});

it("shows zero remaining days when the public recording expiry cannot be parsed",async()=>{
 const root=await evidence(undefined,"unavailable-expiry");expect(textOf(root)).toContain("0 more day(s)");expect(textOf(root)).not.toContain("NaN");
});

it("explains a failed playback key unwrap without starting an unauthenticated player",async()=>{
 const root=await evidence();provider.unwrapPatientDataKey.mockRejectedValueOnce(new Error("encrypted key could not be opened"));await press(root,"play recording");await flush();expect(textOf(root)).toContain("could not unlock this patient's data key — sign out and back in, then retry");expect(root.root.findAllByType("audio")).toHaveLength(0);
});

it("filters the visible clinical record by a trimmed case-insensitive note search",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("one"),note("two"),note("three")],nextOffset:null});provider.decryptNoteAny.mockImplementation(async(_a,_b,_c,_d,id)=>id==="client-one"?"MixedCase target":id==="client-two"?"Another saved observation":"The remaining record");const root=await chart({...patient,status:"revoked"});const search=root.root.findAllByType("input").find(node=>node.props.placeholder==="Search notes…")!;await act(async()=>search.props.onChange({target:{value:"  mixedcase TARGET  "}}));const rows=root.root.findAllByType("div").filter(node=>node.props.className==="entry-row");expect(rows).toHaveLength(1);expect(rows[0]!.findAllByType("p")[0]!.children.join("")).toBe("MixedCase target");
});

it("keeps general and other-pattern notes outside the selected clinical pattern record",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("general"),note("matching","temporal:work"),note("other","topic:other")],nextOffset:null});const root=await chart();let rows=root.root.findAllByType("div").filter(node=>node.props.className==="entry-row");expect(rows).toHaveLength(1);expect(rows[0]!.findAllByType("p")[0]!.children.join("")).toContain("client-general");await press(root,"See the evidence");await flush();rows=root.root.findAllByType("div").filter(node=>node.props.className==="entry-row");expect(rows).toHaveLength(1);expect(rows[0]!.findAllByType("p")[0]!.children.join("")).toContain("client-matching");
});

it.each(["  ", "  clinical lead-in  "])("starts a clinical note template after draft %j without carrying trailing whitespace",async text=>{
 const root=await chart({...patient,status:"revoked"});await typeTextarea(root,"Note about this patient…",text);await press(root,"Session focus");expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!.props.value).toBe(text.trim()?`${text.trimEnd()}\nSession focus:\n- \n- \n`:"Session focus:\n- \n- \n");
});

it.each(["newest readable", "all unreadable"])("copies forward the %s saved note without replacing a draft with failed decryption text",async mode=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("old"),note("recent"),note("unreadable")],nextOffset:null});provider.decryptNoteAny.mockImplementation(async(_a,_b,_c,_d,id)=>{if(id==="client-unreadable"||mode==="all unreadable")throw new Error("note integrity failed");return id==="client-recent"?"Latest readable clinical text":"Earlier clinical text";});const root=await chart({...patient,status:"revoked"});await typeTextarea(root,"Note about this patient…","Unsent writing");await press(root,"Copy forward last note");expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!.props.value).toBe(mode==="all unreadable"?"Unsent writing":"Latest readable clinical text");
});

it.each(["success", "failure"])("retains explicit note-delete confirmation and unrelated saved notes through %s",async mode=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("delete-me"),note("keep-me")],nextOffset:null});const root=await chart({...patient,status:"revoked"});await press(root,"Delete");expect(textOf(root)).toContain("Permanently delete this note?");let resolve!:()=>void,reject!:(error:unknown)=>void;vi.mocked(api.deleteNote).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=()=>yes(null);reject=no;}));await press(root,"Confirm delete");await flush();try{const controls=root.root.findAllByType("button").filter(button=>button.props.children==="Confirm delete"||button.props.children==="Delete");expect(controls.every(button=>button.props.disabled===true)).toBe(true);if(mode==="success")resolve();else reject(null);await flush();const rows=root.root.findAllByType("div").filter(node=>node.props.className==="entry-row");expect(rows).toHaveLength(mode==="success"?1:2);expect(textOf(root)).toContain("Clinical text client-keep-me");if(mode==="failure")expect(textOf(root)).toContain("could not delete the note");else expect(textOf(root)).not.toContain("Permanently delete this note?");}finally{resolve();await flush();}
});

it("retires provider-held measure custody after decrypting a valid clinical reading",async()=>{
 const held:Uint8Array[]=[];vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:[{id:"measure",client_measure_id:"client-measure",received_at:"2026-09-03",measure_date:"2026-09-03",blob:"sealed"}],nextOffset:null});provider.unwrapPatientDataKey.mockImplementation(async()=>{const bytes=new Uint8Array(32).fill(41);held.push(bytes);return bytes;});provider.decryptMeasure.mockResolvedValueOnce({measure:"gad7",score:4,completedAt:null,measureDate:"2026-09-03"});const root=await chart();await vi.waitFor(()=>expect(textOf(root)).toContain("2026-09-03: 4"));expect(held.length).toBeGreaterThan(0);expect(held.every(bytes=>bytes.every(byte=>byte===0))).toBe(true);
});

it.each(["empty","fetch failed","decrypt failed","two revisions"])("preserves %s note history and the notes-only record",async mode=>{
  vi.mocked(api.notes).mockResolvedValueOnce({notes:[note(),note("note-2","topic:work")],nextOffset:null});
  const root=await chart({...patient,status:"revoked",revoked_at:null});
  output(root,"notes-only before history");
  if(mode==="fetch failed")vi.mocked(api.noteRevisions).mockRejectedValueOnce(null);
  else if(mode!=="empty"){
    vi.mocked(api.noteRevisions).mockResolvedValueOnce([{id:"r1",blob:"first revision",created_at:"2026-09-01"},{id:"r2",blob:"second revision",created_at:"2026-09-02"}]);
    if(mode==="decrypt failed")provider.decryptNoteAny.mockRejectedValueOnce(new Error("wrong custody"));
    else provider.decryptNoteAny.mockResolvedValueOnce("First historical clinical text").mockResolvedValueOnce("Second historical clinical text");
  }
  await press(root,"View history");await flush();output(root,"history result");await press(root,"Hide history");output(root,"history hidden");
});

it.each(["constructor", "toString", "__proto__", "hasOwnProperty", "futurepattern"])("renders a safe fallback for the declared string pattern anchor %s",async kind=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("unknown-anchor",`${kind}:coarse-id`)],nextOffset:null});const root=await chart({...patient,status:"revoked"});expect(textOf(root)).toContain("on a pattern");expect(textOf(root)).toContain("Clinical text client-unknown-anchor");
});

it.each([
  ["consent",403,"consent_voice_share_required"], ["expired",410,"audio_expired"],
  ["unconfigured",503,"audio_storage_unconfigured"],["storage failed",503,"audio_storage_failed"],
  ["missing",404,undefined],["unknown",500,undefined],
] as const)("explains %s playback failures at the evidence recording",async(_name,status,code)=>{
  const audio=vi.spyOn(api,"patientAudio").mockRejectedValueOnce(new ApiError(status,"server detail",code));
  try {const root=await evidence();await press(root,"play recording");await flush();output(root,"public recording failure");expect(root.root.findAllByType("audio")).toHaveLength(0);} finally {audio.mockRestore();}
});

it("explains tampered audio and scrubs its provider-held consent key",async()=>{
  const held=new Uint8Array(32).fill(11);provider.unwrapPatientDataKey.mockResolvedValue(held);
  const audio=vi.spyOn(api,"patientAudio").mockResolvedValueOnce({id:"audio-2",client_entry_id:"entry-2",duration_seconds:1,size_bytes:40,created_at:"2026-09-02",expires_at:"2026-10-07",blob:"sealed",mime_type:"audio/webm"});
  const decrypt=vi.spyOn(provider,"decryptAudio").mockRejectedValueOnce(Object.assign(new Error("integrity"),{name:"TamperError"}));
  try {const root=await evidence();held.fill(11);await press(root,"play recording");await flush();output(root,"tampered recording");expect(held.every(byte=>byte===0)).toBe(true);}finally{audio.mockRestore();decrypt.mockRestore();}
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

it.each(["stop", "ended", "error", "unmount"])("renders authenticated voice bytes and revokes playback on %s",async mode=>{
 const heldPlain=new Uint8Array([82,73,70,70,1,2,3,4]);const heldKey=new Uint8Array(32).fill(11);
 vi.spyOn(provider,"decryptAudio").mockResolvedValueOnce(heldPlain);
 const created:Blob[]=[];const active=new Set<string>();vi.spyOn(URL,"createObjectURL").mockImplementation(blob=>{created.push(blob as Blob);const url=`blob:voice-${created.length}`;active.add(url);return url;});vi.spyOn(URL,"revokeObjectURL").mockImplementation(url=>{active.delete(url);});
 const root=await evidence();provider.unwrapPatientDataKey.mockResolvedValueOnce(heldKey);await press(root,"play recording");await flush();
 expect(created).toHaveLength(1);expect(created[0]!.type).toBe("audio/webm");expect(new Uint8Array(await created[0]!.arrayBuffer())).toEqual(new Uint8Array([82,73,70,70,1,2,3,4]));
 expect(heldPlain.every(byte=>byte===0)).toBe(true);expect(heldKey.every(byte=>byte===0)).toBe(true);
 const player=root.root.findByType("audio");expect(player.props.src).toBe("blob:voice-1");expect(player.props.controls).toBe(true);expect(player.props.autoPlay).toBe(true);expect(textOf(root)).toContain("stop recording");
 if(mode==="stop")await press(root,"stop recording");else if(mode==="unmount")await act(async()=>root.unmount());else await act(async()=>mode==="ended"?player.props.onEnded():player.props.onError());
 await flush();expect(active.size).toBe(0);if(mode!=="unmount"){expect(root.root.findAllByType("audio")).toHaveLength(0);expect(textOf(root)).toContain(mode==="error"?"playback failed — try again":"play recording");}
});

it.each(["unlock", "decrypt", "failure"])("retires pending voice %s when its chart unmounts",async mode=>{
 const heldKey=new Uint8Array(32).fill(11),heldPlain=new Uint8Array([9,8,7]);const active=new Set<string>();vi.spyOn(URL,"createObjectURL").mockImplementation(()=>{active.add("blob:late");return "blob:late";});vi.spyOn(URL,"revokeObjectURL").mockImplementation(url=>{active.delete(url);});
 const root=await evidence();let release!:()=>void;
 if(mode==="unlock")provider.unwrapPatientDataKey.mockImplementationOnce(()=>new Promise(resolve=>{release=()=>resolve(heldKey);}));
 else {provider.unwrapPatientDataKey.mockResolvedValueOnce(heldKey);vi.spyOn(provider,"decryptAudio").mockImplementationOnce(()=>new Promise((resolve,reject)=>{release=()=>mode==="failure"?reject(new Error("late voice failure")):resolve(heldPlain);}));}
 await press(root,"play recording");await flush();await act(async()=>root.unmount());try{release();await flush(8);expect(active.size).toBe(0);expect(heldKey.every(byte=>byte===0)).toBe(true);if(mode==="decrypt")expect(heldPlain.every(byte=>byte===0)).toBe(true);}finally{release();await flush();}
});

it("clears a recording failure when a later authenticated playback succeeds",async()=>{
 const root=await evidence();vi.mocked(api.patientAudio).mockRejectedValueOnce(new ApiError(410,"gone","audio_expired"));await press(root,"play recording");await flush();expect(textOf(root)).toContain("this recording expired and was deleted");
 vi.spyOn(provider,"decryptAudio").mockResolvedValueOnce(new Uint8Array([1,2]));vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:retry");vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});await press(root,"play recording");await flush();expect(textOf(root)).not.toContain("this recording expired and was deleted");expect(root.root.findAllByType("audio")).toHaveLength(1);
});

it("keeps the caller's changed note draft while a completed save updates just its matching chart row",async()=>{
 const original=note("saved");vi.mocked(api.notes).mockResolvedValueOnce({notes:[original,note("other")],nextOffset:null});const root=await chart({...patient,status:"revoked"});
 await typeTextarea(root,"Note about this patient…","  submitted clinical text  ");let release!:(row:typeof original)=>void;vi.mocked(api.createNote).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 await press(root,"Save note");await vi.waitFor(()=>expect(api.createNote).toHaveBeenCalled());output(root,"saving note with disabled actions");await typeTextarea(root,"Note about this patient…","new draft typed during save");
 try{release({...original,client_note_id:"created-id"});await flush(8);expect(root.root.findAllByType("textarea").find(n=>n.props.placeholder==="Note about this patient…")!.props.value).toBe("new draft typed during save");expect(textOf(root)).toContain("submitted clinical text");expect(textOf(root)).toContain("Clinical text client-other");expect(textOf(root)).not.toContain("Clinical text client-saved");output(root,"completed save keeps unrelated notes and later draft");}finally{release(original);await flush();}
});

it("clears a whitespace-padded saved draft and keeps prior chart notes",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("previous")],nextOffset:null});const root=await chart({...patient,status:"revoked"});await typeTextarea(root,"Note about this patient…","  saved text  ");vi.mocked(api.createNote).mockResolvedValueOnce(note("created"));await press(root,"Save note");await vi.waitFor(()=>expect(textOf(root)).toContain("saved text"));expect(root.root.findAllByType("textarea").find(n=>n.props.placeholder==="Note about this patient…")!.props.value).toBe("");expect(textOf(root)).toContain("Clinical text client-previous");
});

it.each(["success", "later edit", "cancel", "conflict loaded", "conflict offline", "ordinary error"])("preserves versioned note editing through %s",async mode=>{
 const original=note("edit"),other=note("other");vi.mocked(api.notes).mockResolvedValueOnce({notes:[original,other],nextOffset:null});const root=await chart({...patient,status:"revoked"});await press(root,"Edit");await typeTextarea(root,"Editing note…","  submitted edit  ");
 if(mode==="cancel"){await press(root,"Cancel");expect(root.root.findAllByType("textarea").some(n=>n.props.placeholder==="Editing note…")).toBe(false);return;}
 if(mode.startsWith("conflict")){vi.mocked(api.updateNote).mockRejectedValueOnce(new ApiError(409,"conflict","version_conflict"));if(mode==="conflict offline")vi.mocked(api.notes).mockRejectedValueOnce(null);else vi.mocked(api.notes).mockResolvedValueOnce({notes:[{...original,version:3},other],nextOffset:null});}
 else if(mode==="ordinary error")vi.mocked(api.updateNote).mockRejectedValueOnce(null);
 let release!:(row:typeof original)=>void;if(mode==="success"||mode==="later edit")vi.mocked(api.updateNote).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));
 await press(root,"Save edit");await flush();if(release){output(root,"pending edit");if(mode==="later edit")await typeTextarea(root,"Editing note…","a second unsaved edit");release({...original,version:3});}
 await flush(8);if(mode==="success")expect(root.root.findAllByType("textarea").some(n=>n.props.placeholder==="Editing note…")).toBe(false);else expect(root.root.findAllByType("textarea").find(n=>n.props.placeholder==="Editing note…")!.props.value).toBe(mode==="later edit"?"a second unsaved edit":"  submitted edit  ");expect(textOf(root)).toContain("Clinical text client-other");output(root,"settled edit result");
});

it.each(["all provenance", "first date only", "last date only", "empty label"])("renders the %s clinical provenance without inventing missing facts",async mode=>{
 const fields=mode==="all provenance"?{first_date:"2026-09-01",last_date:"2026-09-30"}:mode==="first date only"?{first_date:"2026-09-01"}:mode==="last date only"?{last_date:"2026-09-30"}:{};
 const p=pattern("inertia",{sample_entries:4,sample_days:3,pattern_state:"confirmed",direction:"higher",evidence_dates:["2026-09-02"]});if(mode==="empty label")p.label="";
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[p],...fields}});const root=await chart();await press(root,"See the evidence");await flush();output(root,"complete clinical evidence provenance");
});

it.each(["2026-09-29", "2026-09-30", "2026-10-01", undefined])("compares first-seen %s to the clinician's explicit reviewed date",async first=>{
 window.sessionStorage.setItem("mindpattern.lastVisit.therapist-1.user-1","2026-09-30");provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{first_seen:first})]}});const root=await chart();output(root,"review-date clinical delta and print provenance");await press(root,"Mark reviewed (update the delta anchor)");output(root,"clinician explicitly advances reviewed anchor");
});

it.each(["old baseline", "old decrypted snapshot", "old failure"])("preserves a replacement chart load after %s settles late",async mode=>{
 let resolve!:(value:Awaited<ReturnType<typeof api.patientInsights>>)=>void,reject!:(error:unknown)=>void;vi.mocked(api.patientInsights).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));const root=await chart();provider.decryptInsights.mockResolvedValueOnce({state_seq:8,stats:{patterns:[{...pattern(),label:"Current clinical topic"}]}});vi.mocked(api.patientInsights).mockResolvedValueOnce({...summary,state_seq:8});
 await act(async()=>root.update(<PatientView patient={{...patient}} session={session} onBack={()=>{}}/>));await flush(8);expect(textOf(root)).toContain("Current clinical topic");
 try{if(mode==="old failure")reject(null);else resolve(mode==="old baseline"?{...summary,phase:"baseline",blob:null,days_remaining:17}:{...summary,state_seq:7});await flush(8);output(root,"fresh replacement chart rejects late former results");}finally{resolve(summary);await flush();}
});

it("clears old baseline and pattern surfaces while a new chart read is pending",async()=>{
 vi.mocked(api.patientInsights).mockResolvedValueOnce({...summary,phase:"baseline",blob:null,days_remaining:12});const root=await chart();let release!:(value:typeof summary)=>void;vi.mocked(api.patientInsights).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));await act(async()=>root.update(<PatientView patient={{...patient}} session={session} onBack={()=>{}}/>));await flush();try{output(root,"new loading state clears old baseline");}finally{release(summary);await flush(8);}
});

async function choose(root:Awaited<ReturnType<typeof render>>,label:string,index=0){const button=root.root.findAllByType("button").filter(node=>node.children.join("")===label)[index]!;expect(button).toBeDefined();expect(button.props.disabled).not.toBe(true);await act(async()=>button.props.onClick());}
const evidenceRow=(id:string,date="2026-09-01",audio=false)=>({id,client_entry_id:id,entry_date:date,received_at:date,blob:"sealed",...(audio?{audio:{attachment_id:`audio-${id}`,expires_at:"2026-10-07"}}:{})});

it.each(["late plaintext","late failure"])("keeps the second selected pattern authoritative after %s from the first",async mode=>{
 const first=pattern("temporal",{evidence_dates:["2026-09-01"]}),second={...pattern("temporal",{pattern_pid:"temporal:sleep",evidence_dates:["2026-09-02"]}),label:"sleep"};provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[first,second]}});
 let release!:(value:Awaited<ReturnType<typeof api.patientEntries>>)=>void,reject!:(error:unknown)=>void;vi.mocked(api.patientEntries).mockImplementationOnce(()=>new Promise((yes,no)=>{release=yes;reject=no;})).mockResolvedValueOnce({entries:[evidenceRow("current","2026-09-02")],nextOffset:null});provider.decryptEntry.mockImplementation(async(_key,_owner,row)=>({text:row.client_entry_id==="current"?"Current sleep evidence":"Retired work evidence",sentiment:0}));
 const root=await chart();await choose(root,"See the evidence");expect(textOf(root)).toContain("Decrypting the entries behind this pattern…");await press(root,"Back to all patterns");await choose(root,"See the evidence",1);await flush(10);expect(textOf(root)).toContain("Current sleep evidence");try{if(mode==="late failure")reject(new Error("Retired work read failed"));else release({entries:[evidenceRow("retired")],nextOffset:null});await flush(10);expect(textOf(root)).toContain("Current sleep evidence");expect(textOf(root)).not.toContain("Retired work evidence");expect(textOf(root)).not.toContain("Retired work read failed");}finally{release({entries:[],nextOffset:null});await flush();}
});

it("clears prior plaintext and shows honest progress while a second pattern is loading",async()=>{
 const first=pattern("temporal",{evidence_dates:["2026-09-01"]}),second={...pattern("temporal",{pattern_pid:"temporal:sleep",evidence_dates:["2026-09-02"]}),label:"sleep"};provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[first,second]}});vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:[evidenceRow("first")],nextOffset:null});provider.decryptEntry.mockResolvedValue({text:"Prior selected evidence",sentiment:0});const root=await chart();await choose(root,"See the evidence");await flush(10);expect(textOf(root)).toContain("Prior selected evidence");await press(root,"Back to all patterns");let release!:(value:Awaited<ReturnType<typeof api.patientEntries>>)=>void;vi.mocked(api.patientEntries).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));await choose(root,"See the evidence",1);try{expect(textOf(root)).toContain("Decrypting the entries behind this pattern…");expect(textOf(root)).not.toContain("Prior selected evidence");}finally{release({entries:[],nextOffset:null});await flush(10);}
});

it("does not highlight a translated coincidence when the original evidence did not match the selected label",async()=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:[evidenceRow("translated")],nextOffset:null});provider.decryptEntry.mockResolvedValueOnce({text:"Je suis fatigué",english_text:"I am tired after work",transcript_lang:"fr",sentiment:0});const root=await chart();await press(root,"See the evidence");await flush(10);expect(textOf(root)).toContain("I am tired after work");expect(root.root.findAllByType("mark")).toHaveLength(0);
});

it("explains a persisted mood-carryover note anchor in human terms",async()=>{vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("mood-carryover","inertia:coarse-topic")],nextOffset:null});const root=await chart({...patient,status:"revoked"});expect(textOf(root)).toContain("on a mood-carryover pattern");});

it.each(["new editing","chart refresh"])("disarms an old deletion confirmation on %s",async mode=>{
 vi.mocked(api.notes).mockResolvedValue({notes:[note("retained")],nextOffset:null});if(mode==="chart refresh")vi.mocked(api.patientInsights).mockRejectedValueOnce(new ApiError(503,"temporary read failure"));const root=await chart();await press(root,"Delete");expect(textOf(root)).toContain("Permanently delete this note?");if(mode==="new editing")await press(root,"Edit");else{await press(root,"Retry loading this patient");await flush(12);}expect(textOf(root)).not.toContain("Permanently delete this note?");expect(root.root.findAllByType("button").filter(node=>node.children.join("")==="Confirm delete")).toHaveLength(0);
});

it("retires the prior measures error while an explicit chart retry is pending",async()=>{
 vi.mocked(api.patientMeasures).mockRejectedValueOnce(new Error("Retired measure read failure"));vi.mocked(api.patientInsights).mockRejectedValueOnce(new ApiError(503,"temporary read failure"));const root=await chart();await flush(12);expect(textOf(root)).toContain("Retired measure read failure");let release!:(value:Awaited<ReturnType<typeof api.patientMeasures>>)=>void;vi.mocked(api.patientMeasures).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));await press(root,"Retry loading this patient");try{expect(textOf(root)).not.toContain("Retired measure read failure");}finally{release({measures:[],nextOffset:null});await flush(10);}
});

it("does not classify a general note as anchored to a legacy pattern without a pattern identifier",async()=>{
 const legacy=pattern();delete legacy.detail.pattern_pid;provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[legacy]}});vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("general",null)],nextOffset:null});const root=await chart();await press(root,"See the evidence");await flush(10);expect(textOf(root)).toContain("No notes on this pattern yet.");
});

it("shows anchored notes without claiming that the pattern has no notes",async()=>{vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("anchored","temporal:work")],nextOffset:null});const root=await chart();await press(root,"See the evidence");await flush(10);expect(textOf(root)).toContain("Clinical text client-anchored");expect(textOf(root)).not.toContain("No notes on this pattern yet.");});

it("does not reload a retired chart after its pending edit receives a version conflict",async()=>{
 vi.mocked(api.notes).mockResolvedValue({notes:[note("editing")],nextOffset:null});let reject!:(error:unknown)=>void;vi.mocked(api.updateNote).mockImplementationOnce(()=>new Promise((_yes,no)=>{reject=no;}));const root=await chart({...patient,status:"revoked"});await press(root,"Edit");await typeTextarea(root,"Editing note…","Pending clinical edit");await press(root,"Save edit");await flush(8);expect(api.updateNote).toHaveBeenCalledTimes(1);const reads=vi.mocked(api.notes).mock.calls.length;await act(async()=>root.unmount());reject(new ApiError(409,"stale version","version_conflict"));await flush(12);expect(api.notes).toHaveBeenCalledTimes(reads);
});

it.each(["late key","late failure"])("keeps a newer recording and its lease after %s from the previous recording",async mode=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01","2026-09-02"]})]}});vi.mocked(api.patientEntries).mockResolvedValueOnce({entries:[evidenceRow("first","2026-09-01",true),evidenceRow("second","2026-09-02",true)],nextOffset:null});const root=await chart();await press(root,"See the evidence");await flush(12);const leases=new Set<string>();let issued=0;vi.spyOn(URL,"createObjectURL").mockImplementation(()=>{const uri=`blob:lease-${++issued}`;leases.add(uri);return uri;});vi.spyOn(URL,"revokeObjectURL").mockImplementation(uri=>{leases.delete(uri);});vi.spyOn(provider,"decryptAudio").mockResolvedValue(new Uint8Array([1,2,3]));let release!:()=>void;
 if(mode==="late key")provider.unwrapPatientDataKey.mockImplementationOnce(()=>new Promise(resolve=>{release=()=>resolve(new Uint8Array(32).fill(13));}));else vi.mocked(api.patientAudio).mockImplementationOnce(()=>new Promise((_yes,no)=>{release=()=>no(new ApiError(410,"old audio expired","audio_expired"));}));await choose(root,"play recording");await flush(4);await choose(root,"play recording",1);await flush(12);expect(root.root.findAllByType("audio")).toHaveLength(1);const uri=root.root.findByType("audio").props.src;try{release();await flush(12);expect(root.root.findAllByType("audio")).toHaveLength(1);expect(root.root.findByType("audio").props.src).toBe(uri);expect(leases).toEqual(new Set([uri]));if(mode==="late key")expect(api.patientAudio).toHaveBeenCalledTimes(1);expect(textOf(root)).not.toContain("this recording expired and was deleted");}finally{release();await act(async()=>root.unmount());await flush();}
});

it("uses the refreshed consent key when browser history refreshes the same patient's grant",async()=>{
 const actual=await vi.importActual<typeof import("../src/crypto")>("../src/crypto");const {buildAad}=await import("../src/aad");const currentKey=new Uint8Array(32).fill(23),iv=new Uint8Array(12).fill(7),key=await crypto.subtle.importKey("raw",currentKey,"AES-GCM",false,["encrypt"]);const sealed=new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv,additionalData:buildAad("audio",patient.user_id,"voice", "1")},key,new Uint8Array([82,73,70,70])));const bytes=new Uint8Array(iv.length+sealed.length);bytes.set(iv);bytes.set(sealed,iv.length);vi.mocked(api.patientAudio).mockResolvedValue({id:"audio-voice",client_entry_id:"voice",duration_seconds:1,size_bytes:bytes.length,created_at:"2026-09-01",expires_at:"2026-10-07",blob:actual.toBase64(bytes),mime_type:"audio/webm"});vi.spyOn(provider,"decryptAudio").mockImplementation(actual.decryptAudio);provider.unwrapPatientDataKey.mockImplementation(async(_private,_ephemeral,wrapped)=>new Uint8Array(32).fill(wrapped==="refreshed-grant"?23:11));provider.decryptInsights.mockResolvedValue({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});vi.mocked(api.patientEntries).mockResolvedValue({entries:[evidenceRow("voice","2026-09-01",true)],nextOffset:null});const root=await chart();await act(async()=>root.update(<PatientView patient={{...patient,wrapped_key:"refreshed-grant"}} session={session} onBack={()=>{}}/>));await flush(12);await press(root,"See the evidence");await flush(12);vi.spyOn(URL,"createObjectURL").mockReturnValue("blob:authenticated-refreshed-voice");vi.spyOn(URL,"revokeObjectURL").mockImplementation(()=>{});await press(root,"play recording");await flush(12);expect(root.root.findAllByType("audio")).toHaveLength(1);
});

it("restores enabled chart actions after a clinical deletion settles",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("delete"),note("keep")],nextOffset:null});vi.mocked(api.deleteNote).mockResolvedValueOnce(null);const root=await chart({...patient,status:"revoked"});await press(root,"Delete");await press(root,"Confirm delete");await flush(8);expect(textOf(root)).toContain("Clinical text client-keep");expect(root.root.findAllByType("button").filter(button=>["Delete","Edit","View history"].includes(button.children.join(""))).every(button=>button.props.disabled!==true)).toBe(true);
});

it.each(["ephemeral_pub","wrapped_key"] as const)("shows the authored missing-key explanation without reading measures when the active grant lacks %s",async field=>{
 const missing={...patient,[field]:null};const root=await chart(missing);await flush(10);expect(textOf(root)).toContain("this consent carries no key material");expect(api.patientMeasures).not.toHaveBeenCalled();expect(provider.decryptInsights).not.toHaveBeenCalled();
});

it("does not decrypt a retained blob that the response identifies as outside the insight phase",async()=>{
 vi.mocked(api.patientInsights).mockResolvedValueOnce({...summary,phase:"baseline",days_remaining:12});const root=await chart();expect(textOf(root)).toContain("Still in the baseline phase — 12 active day(s) until patterns surface.");expect(textOf(root)).not.toContain("'work' concentrates");expect(provider.decryptInsights).not.toHaveBeenCalled();
});

it("does not retry a non-conflict HTTP status merely because its error code mentions a collection conflict",async()=>{
 vi.mocked(api.notes).mockRejectedValueOnce(new ApiError(503,"collection temporarily unavailable","conflict"));const root=await chart({...patient,status:"revoked"});await flush(10);expect(textOf(root)).toContain("note id already used for another patient");expect(api.notes).toHaveBeenCalledTimes(1);expect(textOf(root)).toContain("Retry loading this patient");
});

it("preserves an ordinary failed edit without issuing a conflict-only notes traversal",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("edit")],nextOffset:null});vi.mocked(api.updateNote).mockRejectedValueOnce(new ApiError(503,"save temporarily unavailable"));const root=await chart({...patient,status:"revoked"});await press(root,"Edit");await typeTextarea(root,"Editing note…","Preserved clinical edit");await press(root,"Save edit");await flush(10);expect(textOf(root)).toContain("server is busy — try again");expect(api.notes).toHaveBeenCalledTimes(1);expect(root.root.findAllByType("textarea").find(n=>n.props.placeholder==="Editing note…")!.props.value).toBe("Preserved clinical edit");
});

it.each(["other note first","deleted note"])("preserves the intended clinical comparison after a conflict when the receiver returns %s",async mode=>{
 const original=note("edit"),other=note("other");vi.mocked(api.notes).mockResolvedValueOnce({notes:[original,other],nextOffset:null}).mockResolvedValueOnce({notes:mode==="deleted note"?[other]:[other,{...original,blob:"current-clinical-version",version:3}],nextOffset:null});provider.decryptNoteAny.mockImplementation(async(_active,_legacy,_owner,_patient,id,blob)=>blob==="current-clinical-version"?"Current saved comparison for the edited note":`Clinical text ${id}`);vi.mocked(api.updateNote).mockRejectedValueOnce(new ApiError(409,"changed version","version_conflict"));const root=await chart({...patient,status:"revoked"});await press(root,"Edit");await typeTextarea(root,"Editing note…","My unsent clinical comparison");await press(root,"Save edit");await flush(12);expect(textOf(root)).toContain("Compare the current saved text below before retrying your edit.");if(mode==="other note first")expect(textOf(root)).toContain("Current saved comparison for the edited note");expect(root.root.findAllByType("textarea").find(n=>n.props.placeholder==="Editing note…")!.props.value).toBe("My unsent clinical comparison");
});

it.each([[503,"conflict"],[409,"custody_conflict"]] as const)("keeps the receiver's idempotent note after a lost acknowledgment with HTTP%i/%s",async(status,code)=>{
 const records=new Map<string,ReturnType<typeof note>>();let calls=0;vi.mocked(api.createNote).mockImplementation(async(_patient,payload)=>{const existing=records.get(payload.client_note_id);const saved=existing??{...note(`received-${records.size}`),client_note_id:payload.client_note_id,blob:payload.blob,version:1};records.set(payload.client_note_id,saved);if(calls++===0)throw new ApiError(status,"acknowledgment could not be delivered",code);return saved;});const root=await chart({...patient,status:"revoked"});await typeTextarea(root,"Note about this patient…","One acknowledged clinical note");await press(root,"Save note");await vi.waitFor(()=>expect(root.root.findAllByType("button").some(button=>button.children.join("")==="Save note"&&button.props.disabled!==true)).toBe(true));await press(root,"Save note");await vi.waitFor(()=>expect(api.createNote).toHaveBeenCalledTimes(2));expect(records.size).toBe(1);
});

it.each(["success","conflict"])("retains another composer's pending receiver identity after the current composer %s",async mode=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern()]}});const records=new Map<string,ReturnType<typeof note>>();let calls=0;vi.mocked(api.createNote).mockImplementation(async(_patient,payload)=>{calls++;if(calls===2&&mode==="conflict")throw new ApiError(409,"current note identifier conflicted","conflict");const existing=records.get(payload.client_note_id);const saved=existing??{...note(`received-${records.size}`,payload.pattern_pid??null),client_note_id:payload.client_note_id,blob:payload.blob,version:1};records.set(payload.client_note_id,saved);if(calls===1)throw new ApiError(503,"acknowledgment lost");return saved;});const root=await chart();await typeTextarea(root,"Note about this patient…","General clinical note with a lost acknowledgment");await press(root,"Save note");await vi.waitFor(()=>expect(textOf(root)).toContain("server is busy — try again"));await press(root,"See the evidence");await typeTextarea(root,"Note about this pattern…","A different anchored note");await press(root,"Save note");await vi.waitFor(()=>expect(root.root.findAllByType("button").some(button=>button.children.join("")==="Save note")).toBe(true));await press(root,"Back to all patterns");await press(root,"Save note");await vi.waitFor(()=>expect(api.createNote).toHaveBeenCalledTimes(3));expect(records.size).toBe(mode==="success"?2:1);
});

it("does not alias pending evidence ownership after browser history refreshes the same chart",async()=>{
 provider.decryptInsights.mockResolvedValue({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});let release!:(value:Awaited<ReturnType<typeof api.patientEntries>>)=>void;vi.mocked(api.patientEntries).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;})).mockResolvedValueOnce({entries:[evidenceRow("current")],nextOffset:null});provider.decryptEntry.mockImplementation(async(_key,_owner,row)=>({text:row.client_entry_id==="current"?"Current refreshed evidence":"Retired pre-refresh evidence",sentiment:0}));const root=await chart();await press(root,"See the evidence");await act(async()=>root.update(<PatientView patient={{...patient}} session={session} onBack={()=>{}}/>));await flush(12);await press(root,"See the evidence");await flush(12);try{expect(textOf(root)).toContain("Current refreshed evidence");release({entries:[evidenceRow("retired")],nextOffset:null});await flush(12);expect(textOf(root)).toContain("Current refreshed evidence");expect(textOf(root)).not.toContain("Retired pre-refresh evidence");}finally{release({entries:[],nextOffset:null});await flush();}
});

it("retains the sensitive card's honest non-quoting title before opening evidence",async()=>{
 provider.decryptInsights.mockResolvedValueOnce({state_seq:7,stats:{patterns:[pattern("recurring_phrase",{sensitive:true})]}});const root=await chart();await press(root,"See the evidence");await flush(8);expect(root.root.findAllByType("h2").some(node=>node.props.className==="card__title"&&node.children.join("")==="A difficult thought has been returning")).toBe(true);
});

it("copies forward the newest readable note when the most recent stored row cannot be decrypted",async()=>{
 vi.mocked(api.notes).mockResolvedValueOnce({notes:[note("first"),note("middle"),note("last"),note("bad")],nextOffset:null});provider.decryptNoteAny.mockImplementation(async(_a,_l,_o,_p,id)=>{if(id==="client-bad")throw new Error("cannot authenticate this row");return id==="client-last"?"Newest readable clinical note":"Earlier clinical note";});const root=await chart({...patient,status:"revoked"});await press(root,"Copy forward last note");expect(root.root.findAllByType("textarea").find(node=>node.props.placeholder==="Note about this patient…")!.props.value).toBe("Newest readable clinical note");
});

it("does not emit a native unhandled rejection when a retired voice unwrap fails",async()=>{
 const failures:unknown[]=[],observe=(error:unknown)=>{failures.push(error);};process.on("unhandledRejection",observe);let reject!:(error:unknown)=>void;try{const root=await evidence();provider.unwrapPatientDataKey.mockImplementationOnce(()=>new Promise((_resolve,no)=>{reject=no;}));await press(root,"play recording");await flush(4);await act(async()=>root.unmount());reject(new Error("the retired key cannot be opened"));await flush(12);await new Promise(resolve=>setTimeout(resolve,0));expect(failures).toEqual([]);expect(api.patientAudio).not.toHaveBeenCalled();}finally{process.removeListener("unhandledRejection",observe);}
});

it("skips a genuinely authenticated future measure schema without reporting a broken chart",async()=>{
 const actual=await vi.importActual<typeof import("../src/crypto")>("../src/crypto"),{buildAad}=await import("../src/aad");const dataKey=new Uint8Array(32).fill(11),sealed=await actual.encrypt(dataKey,new TextEncoder().encode(JSON.stringify({v:2,measure:"gad7",score:9})),buildAad("measure",patient.user_id,"future-measure"));vi.mocked(api.patientMeasures).mockResolvedValueOnce({measures:[{id:"future",client_measure_id:"future-measure",blob:actual.toBase64(sealed),received_at:"2026-09-01",measure_date:"2026-09-01"}],nextOffset:null});provider.decryptMeasure.mockImplementationOnce(actual.decryptMeasure);const root=await chart();await flush(12);expect(textOf(root)).toContain("work");expect(textOf(root)).not.toContain("Could not load this patient's recorded measures");expect(root.root.findAllByType("h2").some(node=>String(node.children.join("")).startsWith("Recorded measures"))).toBe(false);
});

it("keeps a refreshed chart loading when an earlier authenticated insight decrypt finishes",async()=>{
 let releaseOld!:(value:Awaited<ReturnType<typeof provider.decryptInsights>>)=>void;provider.decryptInsights.mockImplementationOnce(()=>new Promise(resolve=>{releaseOld=resolve;}));const root=await chart();await vi.waitFor(()=>expect(releaseOld).toBeDefined());let releaseCurrent!:(value:typeof summary)=>void;vi.mocked(api.patientInsights).mockImplementationOnce(()=>new Promise(resolve=>{releaseCurrent=resolve;}));await act(async()=>root.update(<PatientView patient={{...patient}} session={session} onBack={()=>{}}/>));await flush(8);try{expect(textOf(root)).toContain("Loading decrypted patterns…");releaseOld({state_seq:7,stats:{patterns:[pattern()]}});await flush(12);expect(textOf(root)).toContain("Loading decrypted patterns…");expect(root.root.findAllByType("button").filter(node=>node.children.join("")==="See the evidence")).toHaveLength(0);}finally{releaseOld({state_seq:7,stats:{patterns:[]}});releaseCurrent(summary);await flush(10);}
});

it("does not show an older measure failure while replacement measures are still loading",async()=>{
 let rejectOld!:(error:unknown)=>void;vi.mocked(api.patientMeasures).mockImplementationOnce(()=>new Promise((_resolve,reject)=>{rejectOld=reject;}));vi.mocked(api.patientInsights).mockRejectedValueOnce(new ApiError(503,"temporary insight failure"));const root=await chart();let releaseCurrent!:(value:Awaited<ReturnType<typeof api.patientMeasures>>)=>void;vi.mocked(api.patientMeasures).mockImplementationOnce(()=>new Promise(resolve=>{releaseCurrent=resolve;}));await press(root,"Retry loading this patient");try{rejectOld(new Error("Retired measure request failed"));await flush(12);expect(textOf(root)).not.toContain("Retired measure request failed");expect(textOf(root)).not.toContain("Could not load this patient's recorded measures");}finally{releaseCurrent({measures:[],nextOffset:null});await flush(10);}
});

it("does not publish a retired evidence failure into the live refreshed chart before another pattern is selected",async()=>{
 provider.decryptInsights.mockResolvedValue({state_seq:7,stats:{patterns:[pattern("temporal",{evidence_dates:["2026-09-01"]})]}});let rejectOld!:(error:unknown)=>void;vi.mocked(api.patientEntries).mockImplementationOnce(()=>new Promise((_resolve,reject)=>{rejectOld=reject;}));const root=await chart();await press(root,"See the evidence");await act(async()=>root.update(<PatientView patient={{...patient}} session={session} onBack={()=>{}}/>));await flush(12);expect(root.root.findAllByType("button").filter(node=>node.children.join("")==="See the evidence")).toHaveLength(1);rejectOld(new ApiError(503,"retired evidence request failed"));await flush(12);expect(textOf(root)).not.toContain("server is busy — try again");expect(root.root.findAllByType("button").filter(node=>node.children.join("")==="See the evidence")).toHaveLength(1);
});
