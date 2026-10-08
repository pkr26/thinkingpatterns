// @vitest-environment jsdom
import {act,useLayoutEffect} from "react";
import {createRoot,type Root} from "react-dom/client";
import {afterEach,expect,it,vi} from "vitest";
vi.mock("../src/api",async importOriginal=>{const actual=await importOriginal<typeof import("../src/api")>();return {...actual,api:{...actual.api,patientInsights:vi.fn(async()=>({phase:"insight",blob:"authenticated",state_seq:7,active_days:45,streak:3,days_remaining:0})),notes:vi.fn(async()=>({notes:[],nextOffset:null})),patientMeasures:vi.fn(async()=>({measures:[],nextOffset:null})),patientEntries:vi.fn(async()=>({entries:[],nextOffset:null}))}};});
vi.mock("../src/crypto",async importOriginal=>{const actual=await importOriginal<typeof import("../src/crypto")>();return {...actual,unwrapPatientDataKey:vi.fn(async()=>new Uint8Array(32)),decryptInsights:vi.fn(async()=>({state_seq:7,stats:{patterns:[{kind:"temporal",label:"work",occurrences:4,confidence:0.8,detail:{pattern_pid:"temporal:work",evidence_dates:["2026-09-01"]}}]}}))};});
const {PatientView}=await import("../src/views/PatientView"),{api}=await import("../src/api");
const session={userId:"native-handoff-therapist",username:"doctor",noteKey:new Uint8Array(32),noteKeyV2:new Uint8Array(32),privateKey:{} as CryptoKey,publicKeyB64:"public"};
const patient={user_id:"native-handoff-patient",username:"patient",status:"active",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:"public",wrapped_key:"sealed"};
let root:Root|undefined;
afterEach(async()=>{await act(async()=>root?.unmount());root=undefined;document.body.replaceChildren();vi.clearAllMocks();});
/** App.followHistory can replace the same keyed patient's row after a genuine
 * popstate access-list fetch. Observe that public DOM commit before passive
 * load effects: a still-present native evidence control must not audit a read
 * against a now-keyless grant, even during this browser event handoff. */
it.each(["ephemeral_pub","wrapped_key"] as const)("refuses an audited evidence read during native same-chart handoff without %s",async field=>{
 (globalThis as {IS_REACT_ACT_ENVIRONMENT?:boolean}).IS_REACT_ACT_ENVIRONMENT=true;
 const container=document.createElement("div");document.body.append(container);const auditedReads:string[]=[];vi.mocked(api.patientEntries).mockImplementation(async id=>{auditedReads.push(id);return {entries:[],nextOffset:null};});let admitted=0;const committedBeforePassive:string[]=[];
 function NativeChart({row,click}:{row:import("../src/api").Patient;click:boolean}){useLayoutEffect(()=>{if(!click)return;const button=[...container.querySelectorAll("button")].find(node=>node.textContent==="See the evidence");expect(button).toBeDefined();expect(button!.disabled).toBe(false);admitted++;button!.click();committedBeforePassive.push(container.textContent??"");},[row,click]);return <PatientView patient={row} session={session} onBack={()=>{}}/>;}
 root=createRoot(container);await act(async()=>root!.render(<NativeChart row={patient} click={false}/>));await vi.waitFor(()=>expect([...container.querySelectorAll("button")].some(node=>node.textContent==="See the evidence")).toBe(true));await act(async()=>root!.render(<NativeChart row={{...patient,[field]:null}} click={true}/>));expect(admitted).toBe(1);expect(auditedReads).toEqual([]);expect(committedBeforePassive).toHaveLength(1);expect(committedBeforePassive[0]).not.toContain("this consent carries no key material");expect(container.textContent).toContain("this consent carries no key material");expect([...container.querySelectorAll("button")].some(node=>node.textContent==="See the evidence")).toBe(false);
});
