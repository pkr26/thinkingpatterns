// @vitest-environment jsdom
import {act,useLayoutEffect} from "react";
import {createRoot,type Root} from "react-dom/client";
import {afterEach,expect,it,vi} from "vitest";
vi.mock("../src/api",async importOriginal=>{
 const actual=await importOriginal<typeof import("../src/api")>();
 return {...actual,api:{...actual.api,patients:vi.fn(async()=>[]),patientInsights:vi.fn(async()=>({phase:"baseline",active_days:0,streak:0,days_remaining:30,blob:null})),notes:vi.fn(async()=>({notes:[],nextOffset:null})),patientMeasures:vi.fn(async()=>({measures:[],nextOffset:null}))}};
});
const {PatientsView}=await import("../src/views/PatientsView");
const {PatientView}=await import("../src/views/PatientView");
const session={username:"drportal",userId:"initial-dom-clinician",noteKey:new Uint8Array(32),noteKeyV2:new Uint8Array(32),privateKey:{} as CryptoKey,publicKeyB64:"public"};
const patient={user_id:"initial-dom-patient",username:"patienta",status:"active",granted_at:"2026-09-01",revoked_at:null,ephemeral_pub:"public",wrapped_key:"sealed"};
let root:Root|undefined;
afterEach(async()=>{await act(async()=>root?.unmount());root=undefined;document.body.replaceChildren();});

it.each(["caseload","patient"])("commits an honest first %s DOM surface before any passive network effects",async view=>{
 (globalThis as {IS_REACT_ACT_ENVIRONMENT?:boolean}).IS_REACT_ACT_ENVIRONMENT=true;
 const container=document.createElement("div");document.body.append(container);let first="",alerts=-1;
 function ObserveFirstSurface(){useLayoutEffect(()=>{first=container.textContent??"";alerts=container.querySelectorAll('[role="alert"]').length;},[]);return view==="caseload"?<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>:<PatientView patient={patient} session={session} onBack={()=>{}} onSignOut={()=>{}}/>;}
 root=createRoot(container);await act(async()=>root!.render(<ObserveFirstSurface/>));
 expect(first).toContain(view==="caseload"?"Loading your caseload…":"Loading decrypted patterns…");
 expect(first).not.toContain("Retry loading");expect(alerts).toBe(0);
});
