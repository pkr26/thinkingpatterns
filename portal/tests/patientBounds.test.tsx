import {expect,it,vi} from "vitest";
vi.mock("../src/api",async importOriginal=>{const actual=await importOriginal<typeof import("../src/api")>();return {...actual,api:{...actual.api,notes:vi.fn(async()=>({notes:[],nextOffset:null})),patientMeasures:vi.fn(),patientInsights:vi.fn(async()=>({phase:"baseline",blob:null,state_seq:0,active_days:1,streak:1,days_remaining:30}))}};});
vi.mock("../src/crypto",async importOriginal=>{const actual=await importOriginal<typeof import("../src/crypto")>();return {...actual,unwrapPatientDataKey:vi.fn(async()=>new Uint8Array(32)),decryptMeasure:vi.fn()};});
import {api,ApiError} from "../src/api";
import {PatientView} from "../src/views/PatientView";
import {render,textOf} from "./helpers/rtr";
const patient={user_id:"bounded-patient",username:"patient",status:"active",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:"public",wrapped_key:"sealed"};
const session={userId:"bounded-therapist",username:"doctor",privateKey:{} as CryptoKey,publicKeyB64:"public",noteKey:new Uint8Array(32),noteKeyV2:new Uint8Array(32)};
it("refuses a continuing measure listing on its twenty-first individually permitted page",async()=>{
 let reads=0;vi.mocked(api.patientMeasures).mockImplementation(async(_id,params)=>{reads++;if(reads>21)throw new ApiError(503,"additional audited read refused");const offset=params?.offset??0;return {measures:Array.from({length:100},(_,index)=>({id:`measure-${offset+index}`,client_measure_id:`measure-${offset+index}`,measure_date:"2026-09-01",received_at:"2026-09-01",blob:"sealed"})),nextOffset:offset+100,revision:"17"};});const root=await render(<PatientView patient={patient} session={session} onBack={()=>{}}/>);await vi.waitFor(()=>expect(textOf(root)).toContain("measure history exceeds this portal's safe page limit"));expect(reads).toBe(21);
});
