/** Pristine comparison of original and staged App ownership fences.
 * Actual Node native fetch/HTTP/Promise plus public simulated history/pageshow
 * events; no physical BFCache or browser scheduling claim.
 */
import { createCipheriv, generateKeyPairSync, hkdfSync, pbkdf2Sync, randomBytes } from "node:crypto";

import { createServer, type Server, type ServerResponse } from "node:http";

import { act } from "react";
import RTR, { type ReactTestRenderer } from "react-test-renderer";
import { afterEach, expect, it, vi } from "vitest";
import { App } from "../src/App";
import { api, ApiError, clearSession, hasSession, type Patient } from "../src/api";

const USER="native_history_therapist", PASSWORD="correct horse battery staple", SALT="AAECAwQFBgcICQoLDA0ODw==", TOKEN="synthetic-native-history-token";
const PATIENT:Patient={user_id:"fedcba9876543210fedcba9876543210",username:"native_history_patient",status:"active",granted_at:"2026-10-08T00:00:00Z",revoked_at:null,ephemeral_pub:null,wrapped_key:null};
type Witness={ [key:string]:unknown };
let ownedRoot:ReactTestRenderer|undefined,ownedServer:Server|undefined;
let originDescriptor:PropertyDescriptor|undefined;
let releaseOwnedResponses:(()=>void)|undefined;
const text=(node:unknown):string=>typeof node==="string"?node:typeof node==="number"?String(node):Array.isArray((node as {children?:unknown[]}|null)?.children)?(node as {children:unknown[]}).children.map(text).join(""):"";
const rendered=(root:ReactTestRenderer)=>text(root.root);
const buttons=(root:ReactTestRenderer,label:string)=>root.root.findAllByType("button").filter(button=>text(button)===label);
function deferred(){let resolve!:()=>void;const promise=new Promise<void>(yes=>{resolve=yes;});return {promise,resolve};}
async function finite<T>(label:string,promise:Promise<T>):Promise<T>{let timer!:ReturnType<typeof setTimeout>;try{return await Promise.race([promise,new Promise<never>((_,reject)=>{timer=setTimeout(()=>reject(new Error(`ExecutionError: native producer completion timed out: ${label}`)),15000);})]);}finally{clearTimeout(timer);}}
async function complete(label:string,ready:()=>boolean){const until=Date.now()+15000;while(!ready()){if(Date.now()>until)throw new Error(`ExecutionError: public completion timed out: ${label}`);await act(async()=>{await new Promise<void>(resolve=>setTimeout(resolve,5));});}}
async function input(root:ReactTestRenderer,label:string,value:string){const field=root.root.findAllByType("input").find(node=>node.props["aria-label"]===label||root.root.findAllByType("label").some(parent=>text(parent)===label&&parent.props.htmlFor===node.props.id));if(!field||field.props.disabled)throw new Error(`SetupError: enabled public ${label} input missing`);await act(async()=>{field.props.onChange({target:{value}});});}
async function submit(root:ReactTestRenderer,label:string){if(buttons(root,label).length!==1||buttons(root,label)[0]!.props.disabled)throw new Error(`SetupError: enabled public ${label} form missing`);await act(async()=>{root.root.findByType("form").props.onSubmit({preventDefault(){}});});}
function fixture(){const master=pbkdf2Sync(PASSWORD,Buffer.from(SALT,"base64"),600000,32,"sha256"),auth=Buffer.from(hkdfSync("sha256",master,Buffer.alloc(32),Buffer.from("mindpattern/auth/v1"),32)),wrap=Buffer.from(hkdfSync("sha256",master,Buffer.alloc(32),Buffer.from("mindpattern/portal-wrap/v1"),32));const keys=generateKeyPairSync("ec",{namedCurve:"prime256v1"}),der=keys.privateKey.export({format:"der",type:"pkcs8"});try{const nonce=randomBytes(12),cipher=createCipheriv("aes-256-gcm",wrap,nonce);cipher.setAAD(Buffer.from(JSON.stringify(["therapist-key",USER])));return {verifier:auth.toString("base64"),publicKey:keys.publicKey.export({format:"der",type:"spki"}).toString("base64"),blob:Buffer.concat([nonce,cipher.update(der),cipher.final(),cipher.getAuthTag()]).toString("base64")};}finally{master.fill(0);auth.fill(0);wrap.fill(0);der.fill(0);}}


afterEach(async()=>{releaseOwnedResponses?.();releaseOwnedResponses=undefined;if(ownedRoot){const root=ownedRoot;ownedRoot=undefined;await act(async()=>root.unmount());}clearSession();vi.clearAllMocks();vi.restoreAllMocks();vi.unstubAllGlobals();if(originDescriptor)Object.defineProperty(window.location,"origin",originDescriptor);originDescriptor=undefined;window.location.hash="";if(ownedServer){const server=ownedServer;ownedServer=undefined;server.closeAllConnections();await finite("owned HTTP server cleanup",new Promise<void>((resolve,reject)=>server.close(error=>error?reject(error):resolve())));}});

it.each(["fulfilled-positive-control","fulfilled-with-lock","rejected-with-lock"] as const)("native authenticated history %s retains the completed public session contract",async(scenario)=>{
  vi.useRealTimers();clearSession();window.localStorage.clear();window.sessionStorage.clear();window.location.hash="";
  const witness:Witness={  };const account=fixture();
  const historyRequest=deferred(),productionSettled=deferred();let held:ServerResponse|undefined,patientRequests=0,mfa=false;
  const send=(response:ServerResponse,value:unknown,status=200)=>{response.writeHead(status,{"content-type":"application/json"});response.end(JSON.stringify(value));};
  const server=createServer(async(request,response)=>{try{let raw="";for await(const part of request)raw+=String(part);const body=raw?JSON.parse(raw) as Record<string,unknown>:{};const path=new URL(request.url!,"http://127.0.0.1").pathname;if(raw.includes(PASSWORD))throw new Error("SetupError: plaintext password crossed native HTTP");
    if(path==="/api/v1/auth/salt")return send(response,{salt:SALT});
    if(path==="/api/v1/auth/login"){if(body.username!==USER||body.verifier!==account.verifier)throw new Error("SetupError: actual600k verifier mismatch");if(body.totp_code===undefined)return send(response,{code:"totp_required",detail:"MFA required"},401);if(body.totp_code!=="123456")throw new Error("SetupError: public MFA mismatch");mfa=true;return send(response,{token:TOKEN,user_id:"0123456789abcdef0123456789abcdef",expires_in:86400,role:"therapist",mfa_enrollment_required:false});}
    if(request.headers.authorization!==`Bearer ${TOKEN}`||!mfa)throw new Error("SetupError: actual authenticated native request missing bearer/MFA");
    if(path==="/api/v1/therapist/me")return send(response,{username:USER,display_name:"Dr. Native History",wrap_pub_key:account.publicKey,wrap_key_blob:account.blob,totp_enabled:true});
    if(path==="/api/v1/therapist/patients"){patientRequests++;if(patientRequests===1)return send(response,[]);if(patientRequests!==2)throw new Error("SetupError: unexpected second history producer");held=response;historyRequest.resolve();return;}
    if(path==="/api/v1/auth/logout"){response.writeHead(204);return response.end();}
    // A successful no-lock control can mount the real chart without any
    // patient insights yet. These are genuine authored null/empty wires.
    if(path.endsWith("/insights"))return send(response,{user_id:PATIENT.user_id,encrypted_blob:null,ephemeral_pub:null,state_seq:0,updated_at:null});
    if(path.endsWith("/notes")||path.endsWith("/measures"))return send(response,[]);
    throw new Error(`SetupError: unexpected native route ${path}`);
  }catch(error){witness.transportFault=String(error);send(response,{detail:String(error)},500);}});
  ownedServer=server;await finite("owned ephemeral loopback bind",new Promise<void>((resolve,reject)=>{server.once("error",reject);server.listen(0,"127.0.0.1",resolve);}));
  const address=server.address();if(!address||typeof address==="string")throw new Error("SetupError: owned native HTTP address missing");
  originDescriptor=Object.getOwnPropertyDescriptor(window.location,"origin");Object.defineProperty(window.location,"origin",{configurable:true,value:`http://127.0.0.1:${address.port}`});
  const nativeFetch=globalThis.fetch;
  vi.spyOn(globalThis,"fetch").mockImplementation((...args)=>{const promise=nativeFetch(...args);return promise;});
  releaseOwnedResponses=()=>{if(held&&!held.writableEnded)send(held,[]);};
  {
    await act(async()=>{ownedRoot=RTR.create(<App/>);});const root=ownedRoot!;
    await input(root,"Username",USER);await input(root,"Password",PASSWORD);await submit(root,"Sign in");await complete("real mandatory MFA challenge",()=>buttons(root,"Verify code").length===1);
    if(hasSession())throw new Error("SetupError: password-only public form admitted a session");
    await input(root,"Authenticator code (or recovery code)","123456");await submit(root,"Verify code");await complete("real public caseload and initial native patient response",()=>rendered(root).includes("No patients are sharing with you yet")&&hasSession());
    const originalPatients=api.patients;let current:Promise<Patient[]>|undefined;
    vi.spyOn(api,"patients").mockImplementation(()=>{if(current)throw new Error("SetupError: more than one public history producer");const promise=originalPatients();current=promise;
      void promise.then(()=>{witness.outcome="fulfilled";publishLock();},error=>{if(!(error instanceof ApiError)||error.status!==503){witness.transportFault=String(error);productionSettled.resolve();return;}witness.outcome="rejected";publishLock();});
      return promise;
    });
    function publishLock(){if(!hasSession()){witness.transportFault="SetupError: production returned after an earlier unrelated lock";productionSettled.resolve();return;}if(scenario!=="fulfilled-positive-control"){const restore=new Event("pageshow");Object.defineProperty(restore,"persisted",{value:true});window.dispatchEvent(restore);}productionSettled.resolve();}

    await act(async()=>{
      window.location.hash=`#/patient/${PATIENT.user_id}`;window.dispatchEvent(new Event("popstate"));
      await finite("native HTTP history request received",historyRequest.promise);
      if(!held)throw new Error("SetupError: received history response handle missing");
      send(held,scenario==="rejected-with-lock"?{detail:"Owned temporary patient service refusal"}:[PATIENT],scenario==="rejected-with-lock"?503:200);
      await finite("original production patients Promise settled",productionSettled.promise);
      if(!current)throw new Error("SetupError: original production API Promise not observed");
      await current.catch(()=>undefined);await Promise.resolve();
    });
    if(witness.transportFault)throw new Error(`SetupError: ${String(witness.transportFault)}`);



    if(scenario==="fulfilled-positive-control"){expect(witness.outcome).toBe("fulfilled");expect(hasSession()).toBe(true);expect(rendered(root)).toContain(PATIENT.username);expect(buttons(root,"Sign out")).toHaveLength(1);}
    else{expect(witness.outcome).toBe(scenario==="rejected-with-lock"?"rejected":"fulfilled");expect(hasSession()).toBe(false);expect(buttons(root,"Sign in")).toHaveLength(1);expect(root.root.findAllByType("form")).toHaveLength(1);expect(rendered(root)).not.toContain("Unlocking…");expect(rendered(root)).not.toContain("Patients — Dr. Native History");}

  }
});
