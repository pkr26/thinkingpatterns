import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { publicSurface } from "./helpers/publicSurface";
import { act } from "react";
import { flush, press, render as renderRaw, textOf, typeInto } from "./helpers/rtr";

async function render(ui:React.ReactElement<{session?:unknown}>) {
  const root=await renderRaw(ui);
  if(ui.props.session) await vi.waitFor(()=>expect(root.root.findAll(n=>n.props["data-testid"]==="key-fingerprint")).toHaveLength(1));
  return root;
}

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
const platform = await import("../src/platform");
const session = { username: "drportal", userId: "therapist-presentation", noteKey: new Uint8Array(32), noteKeyV2: new Uint8Array(32), privateKey: {} as CryptoKey, publicKeyB64: "P".repeat(124) };
beforeEach(() => {
  vi.clearAllMocks(); window.sessionStorage.clear(); window.localStorage.clear(); vi.stubEnv("TZ", "UTC");
  vi.mocked(api.patients).mockReset().mockResolvedValue([]);
  vi.mocked(api.me).mockReset().mockResolvedValue({ username: "drportal", display_name: "Dr. Portal", totp_enabled: false, wrap_pub_key: "P".repeat(124), wrap_key_blob: "sealed" });
  vi.mocked(api.totpSetup).mockReset().mockResolvedValue({ secret_base32: fixtures.secret, otpauth_uri: `otpauth://totp/Fathom:drportal?secret=${fixtures.secret}&issuer=Fathom` });
  vi.mocked(api.totpEnable).mockReset().mockResolvedValue({ backup_codes: fixtures.codes });
  vi.mocked(api.totpDisable).mockReset().mockResolvedValue(null);
  vi.mocked(api.newPairingCode).mockReset().mockResolvedValue({ code: "7X2KQM4N", expires_in: 900 });
  vi.mocked(api.pairingSas).mockReset().mockResolvedValue({ sas: "123456", wrap_key_fingerprint: "0123456789abcdef", expires_in: 900 });
  vi.mocked(api.accessLog).mockReset().mockResolvedValue([{ at: "2026-09-30T12:00:00Z", action: "patient_insights", patient_name: "patienta" }, { at: "2026-09-29T12:00:00Z", action: "rotate_wrap_key", patient_name: null }]);
});
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

it("preserves the honest empty access-history result after a successful request",async()=>{
 vi.mocked(api.accessLog).mockResolvedValueOnce([]);const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);await flush();await press(root,"Load access history");await flush();expect(textOf(root)).toContain("No recorded actions yet.");
});

it("clears the previous pairing code while a replacement request is pending",async()=>{
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);await flush();await press(root,"Generate pairing code");await flush();expect(textOf(root)).toContain("7X2KQM4N");
 let release!:(value:Awaited<ReturnType<typeof api.newPairingCode>>)=>void;vi.mocked(api.newPairingCode).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));await press(root,"Generate pairing code");try{expect(textOf(root)).not.toContain("7X2KQM4N");expect(textOf(root)).toContain("Generating…");}finally{release({code:"NEWCODE1",expires_in:900});await flush();}
});

it("reports ordinary pairing authorization errors without calling them an expired code",async()=>{
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);await flush();await press(root,"Generate pairing code");await typeInto(root,"Patient's account id","patient-id");vi.mocked(api.pairingSas).mockRejectedValueOnce(new (await import("../src/api")).ApiError(403,"permission denied"));await press(root,"Show verification code");await flush();expect(textOf(root)).toContain("could not load the verification code");expect(textOf(root)).not.toContain("pairing code not found or expired");
});

it("clears clipboard feedback when shown-once recovery codes lose focus",async()=>{
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);await flush();await press(root,"Show account security");await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await typeInto(root,"Current password (to authorize setup)","current-password");await typeInto(root,"6-digit code from the app","123456");await press(root,"Enable two-factor");await flush();vi.stubGlobal("navigator",{clipboard:{writeText:vi.fn(async()=>{})}});await press(root,"Copy recovery codes");await flush();expect(textOf(root)).toContain("recovery codes copied to clipboard.");
 const block=root.root.findAllByType("div").find(node=>node.props.className==="totp-codes")!;await act(async()=>block.props.onBlur({relatedTarget:null,currentTarget:{contains:()=>false}}));expect(textOf(root)).not.toContain("recovery codes copied to clipboard.");expect(textOf(root)).not.toContain(fixtures.codes[0]);
 await typeInto(root,"Current password (to disable two-factor)","current-password");await typeInto(root,"6-digit code (to disable two-factor)","123456");await press(root,"Disable two-factor");await flush();await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();expect(root.root.findAllByType("span").filter(node=>node.props.className==="hint"&&node.props.role==="status")).toHaveLength(0);
});

it("explains a missing server fingerprint without presenting it as a failed local cross-check",async()=>{
 vi.spyOn(cryptography,"serverWrapKeyFingerprint").mockRejectedValueOnce(new Error("native digest unavailable"));vi.mocked(api.pairingSas).mockResolvedValueOnce({sas:"123456",wrap_key_fingerprint:"invalid",expires_in:900});
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);await flush();await press(root,"Generate pairing code");await typeInto(root,"Patient's account id","patient-id");await press(root,"Show verification code");await flush();expect(textOf(root)).toContain("The server sent no valid key fingerprint");expect(textOf(root)).not.toContain("This portal could not compute the fingerprint of your own sharing key");
});

it("retires the previous local comparison while a new pairing digest is pending",async()=>{
 const fingerprint=vi.spyOn(cryptography,"serverWrapKeyFingerprint").mockResolvedValueOnce("0123456789abcdef");const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);await flush();await press(root,"Generate pairing code");await typeInto(root,"Patient's account id","patient-id");await press(root,"Show verification code");await flush();expect(textOf(root)).not.toContain("KEY FINGERPRINT MISMATCH");
 let release!:(value:string)=>void;fingerprint.mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));vi.mocked(api.pairingSas).mockResolvedValueOnce({sas:"654321",wrap_key_fingerprint:"fedcba9876543210",expires_in:900});await press(root,"Show verification code");await vi.waitFor(()=>expect(release).toBeDefined());
 try{expect(textOf(root)).toContain("This portal could not compute the fingerprint of your own sharing key");expect(textOf(root)).not.toContain("KEY FINGERPRINT MISMATCH");}finally{release("fedcba9876543210");await flush();}
});

it("shows the real loading, retry and empty caseload states without exposing placeholder patients", async () => {
  let reject!: (error: unknown) => void;
  vi.mocked(api.patients).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush();
  expect(textOf(root)).toContain("Loading your caseload…");
  expect(textOf(root)).not.toContain("No patients are sharing");
  await vi.waitFor(() => expect(textOf(root)).toContain("F3EA 67E5 8DD3 DEF0 EA04 C676 CD80 7836"));
  expect(publicSurface(root.toJSON())).toMatchSnapshot("pending caseload");
  reject(null); await flush();
  expect(textOf(root)).toContain("could not load patients");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("retryable caseload failure");
  await press(root, "Retry loading patients"); await flush();
  expect(publicSurface(root.toJSON())).toMatchSnapshot("empty caseload after successful retry");
});

it("shows access-history progress and its failure without retaining stale action rows", async () => {
  let reject!: (error: unknown) => void;
  vi.mocked(api.accessLog).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }));
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush(); await press(root, "Load access history");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("pending access history");
  reject(null); await flush();
  expect(textOf(root)).toContain("could not load the access history");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("failed access history");
});

it("finishes a failed account-status read with an honest setup action", async () => {
  vi.mocked(api.me).mockRejectedValueOnce(new Error("status unavailable"));
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush(); await press(root, "Show account security"); await flush();
  expect(textOf(root)).not.toContain("Checking this account's two-factor status");
  expect(textOf(root)).toContain("Set up authenticator");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("account status failure offers setup");
});

it.each(["setup", "enable", "disable"])("reports a non-Error %s failure and drops the clinician's entered secrets", async action => {
  if (action === "disable") vi.mocked(api.me).mockResolvedValueOnce({ username: "drportal", display_name: "Dr. Portal", totp_enabled: true, wrap_pub_key: "P".repeat(124), wrap_key_blob: "sealed" });
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush(); await press(root, "Show account security"); await flush();
  if (action === "enable") {
    await typeInto(root, "Current password (to authorize setup)", "private-clinician-password");
    await press(root, "Set up authenticator"); await flush();
  }
  const label = action === "disable" ? "Current password (to disable two-factor)" : "Current password (to authorize setup)";
  await typeInto(root, label, "private-clinician-password");
  if (action !== "setup") await typeInto(root, "6-digit code", "123456");
  if (action === "setup") vi.mocked(api.totpSetup).mockRejectedValueOnce(null);
  else if (action === "enable") vi.mocked(api.totpEnable).mockRejectedValueOnce(null);
  else vi.mocked(api.totpDisable).mockRejectedValueOnce(null);
  await press(root, action === "setup" ? "Set up authenticator" : action === "enable" ? "Enable two-factor" : "Disable two-factor");
  await flush();
  expect(textOf(root)).toContain(action === "setup" ? "could not start two-factor setup" : `could not ${action} two-factor`);
  const surface = publicSurface(root.toJSON());
  expect(surface).not.toContain("private-clinician-password");
  expect(surface).not.toContain('value="123456"');
  expect(surface).toMatchSnapshot(`${action} failure clears entered secrets`);
});

it.each(["0123456789abcdef", "prefix0123456789abcdef", "0123456789abcdefsuffix", "0123456789ABCDEF", "", "fedcba9876543210"])("presents the exact pairing fingerprint outcome for %s", async reported => {
  vi.spyOn(cryptography, "serverWrapKeyFingerprint").mockResolvedValue("0123456789abcdef");
  vi.mocked(api.pairingSas).mockResolvedValueOnce({ sas: "123456", wrap_key_fingerprint: reported, expires_in: 900 });
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush(); await press(root, "Generate pairing code"); await flush();
  await typeInto(root, "Patient's account id", "  patient-id  ");
  await press(root, "Show verification code"); await flush();
  expect(api.pairingSas).toHaveBeenLastCalledWith("patient-id", "7X2KQM4N");
  expect(publicSurface(root.toJSON())).toMatchSnapshot(`pairing fingerprint ${reported || "absent"}`);
});

it("reports pairing creation and verification failures with specific safe fallback copy", async () => {
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush(); vi.mocked(api.newPairingCode).mockRejectedValueOnce(null);
  await press(root, "Generate pairing code"); await flush();
  expect(textOf(root)).toContain("could not create a pairing code");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("pairing creation failure");
  await press(root, "Generate pairing code"); await flush();
  await typeInto(root, "Patient's account id", "patient-id");
  vi.mocked(api.pairingSas).mockRejectedValueOnce(null);
  await press(root, "Show verification code"); await flush();
  expect(textOf(root)).toContain("could not load the verification code");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("pairing verification failure");
});

it("preserves account custody explanations, field accessibility, secret visibility and recovery exports", async () => {
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush();
  await press(root, "Show account security");
  await flush();
  expect(textOf(root)).toContain("Your new credential, re-wrapped sharing identity, and encrypted notes keyring commit together");
  expect(publicSurface(root.toJSON())).toMatchSnapshot("account custody and MFA setup controls");

  await typeInto(root, "Current password (to authorize setup)", "current-password");
  await press(root, "Set up authenticator");
  await flush();
  expect(textOf(root)).not.toContain(fixtures.secret);
  expect(textOf(root)).toContain("•".repeat(fixtures.secret.length));
  expect(publicSurface(root.toJSON())).toMatchSnapshot("masked enrollment secret");
  await press(root, "Show secret");
  await vi.waitFor(() => expect(root.root.findAllByType("svg")).toHaveLength(1));
  expect(textOf(root)).toContain(fixtures.secret);
  expect(publicSurface(root.toJSON())).toMatchSnapshot("locally rendered authenticator enrollment");
  const writeText = vi.fn(async () => {});
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  await press(root, "Copy secret");
  await flush();
  expect(writeText).toHaveBeenCalledExactlyOnceWith(fixtures.secret);
  expect(textOf(root)).toContain("secret copied to clipboard.");

  await typeInto(root, "Current password (to authorize setup)", "current-password");
  await typeInto(root, "6-digit code from the app", "123456");
  await press(root, "Enable two-factor");
  await flush();
  expect(textOf(root)).toContain(fixtures.codes[0]);
  expect(textOf(root)).not.toContain(fixtures.secret);
  expect(publicSurface(root.toJSON())).toMatchSnapshot("single-use recovery codes and disable controls");
  const download = vi.spyOn(platform, "downloadTextFile").mockImplementation(() => {});
  await press(root, "Download recovery codes (.txt)");
  expect(download).toHaveBeenCalledExactlyOnceWith("mindpattern-recovery-codes.txt", `Fathom therapist portal — one-time recovery codes\n\n${fixtures.codes.join("\n")}\n\nEach code works one time in place of a 6-digit sign-in code.\nThey are shown only once; keep this file somewhere safe.`);
  await press(root, "Copy recovery codes");
  await flush();
  expect(writeText).toHaveBeenLastCalledWith(fixtures.codes.join("\n"));
  await press(root, "Hide account security");
  expect(textOf(root)).not.toContain(fixtures.codes[0]);
  expect(textOf(root)).not.toContain("current-password");
});

it("presents readable access history including account-wide lifecycle rows", async () => {
  const root = await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={vi.fn()} onSignOut={vi.fn()} />);
  await flush();
  await press(root, "Load access history");
  await flush();
  expect(textOf(root)).toContain("patienta");
  const patientTime = new Date("2026-09-30T12:00:00Z").toLocaleString();
  const lifecycleTime = new Date("2026-09-29T12:00:00Z").toLocaleString();
  expect(textOf(root)).toContain(`${patientTime} — patient insights — patienta`);
  expect(textOf(root)).toContain(`${lifecycleTime} — rotate wrap key`);
  expect(publicSurface(root.toJSON()).replaceAll(patientTime, "PATIENT_ACCESS_TIMESTAMP").replaceAll(lifecycleTime, "LIFECYCLE_ACCESS_TIMESTAMP")).toMatchSnapshot("access history and lifecycle actions");
});

it("presents pending account status without assuming MFA is enabled or disabled",async()=>{
 let release!:(value:Awaited<ReturnType<typeof api.me>>)=>void;vi.mocked(api.me).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await flush();await press(root,"Show account security");await flush();try{expect(publicSurface(root.toJSON())).toMatchSnapshot("pending honest MFA account status");}finally{release({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:session.publicKeyB64,wrap_key_blob:"sealed",totp_enabled:false});await flush();}
});

it.each(["setup","enable","disable"])("shows %s administration progress and preserves host-held key hygiene",async action=>{
 const heldSalt:Uint8Array[]=[];const master=new Uint8Array(32).fill(3);const keys={authKey:new Uint8Array(32).fill(4),wrapKek:new Uint8Array(32).fill(5),noteKey:new Uint8Array(32).fill(6)};
 vi.mocked(cryptography.deriveMasterKey).mockImplementationOnce(async(_password,salt)=>{heldSalt.push(salt);return master;});vi.mocked(cryptography.derivePortalKeys).mockResolvedValueOnce(keys);
 if(action==="disable")vi.mocked(api.me).mockResolvedValueOnce({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:session.publicKeyB64,wrap_key_blob:"sealed",totp_enabled:true});const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await flush();await press(root,"Show account security");await flush();
 if(action==="enable"){await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();}
 await typeInto(root,action==="disable"?"Current password (to disable two-factor)":"Current password (to authorize setup)","current-password");if(action!=="setup")await typeInto(root,action==="disable"?"6-digit code (to disable two-factor)":"6-digit code from the app","123456");let release!:()=>void;
 if(action==="setup")vi.mocked(api.totpSetup).mockImplementationOnce(()=>new Promise(resolve=>{release=()=>resolve({secret_base32:fixtures.secret,otpauth_uri:`otpauth://totp/Fathom:test?secret=${fixtures.secret}`});}));else if(action==="enable")vi.mocked(api.totpEnable).mockImplementationOnce(()=>new Promise(resolve=>{release=()=>resolve({backup_codes:fixtures.codes});}));else vi.mocked(api.totpDisable).mockImplementationOnce(()=>new Promise(resolve=>{release=()=>resolve(null);}));
 await press(root,action==="setup"?"Set up authenticator":action==="enable"?"Enable two-factor":"Disable two-factor");await flush();try{expect(publicSurface(root.toJSON())).toMatchSnapshot("pending MFA administration");for(const key of [master,...Object.values(keys),...heldSalt])expect(key.every(byte=>byte===0)).toBe(true);}finally{release();await flush();}
 expect(publicSurface(root.toJSON())).toMatchSnapshot("completed MFA administration and cleared entered secrets");
});

it.each(["setup","enable","disable"])("requires a password and complete code before %s MFA administration",async action=>{
 if(action==="disable")vi.mocked(api.me).mockResolvedValueOnce({username:"drportal",display_name:"Dr. Portal",wrap_pub_key:session.publicKeyB64,wrap_key_blob:"sealed",totp_enabled:true});const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await flush();await press(root,"Show account security");await flush();
 if(action==="enable"){await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();}
 expect(publicSurface(root.toJSON())).toMatchSnapshot("MFA action without current password");if(action!=="setup"){await typeInto(root,action==="disable"?"Current password (to disable two-factor)":"Current password (to authorize setup)","current-password");await typeInto(root,action==="disable"?"6-digit code (to disable two-factor)":"6-digit code from the app","1a2345");expect(publicSurface(root.toJSON())).toMatchSnapshot("MFA action with incomplete normalized code");await typeInto(root,action==="disable"?"6-digit code (to disable two-factor)":"6-digit code from the app","x1234567");expect(publicSurface(root.toJSON())).toMatchSnapshot("MFA action with complete bounded code");}
});

it("refuses account-key actions while no unlocked custody session is available",async()=>{
 const root=await render(<PatientsView displayName="Dr. Portal" onOpen={()=>{}} onSignOut={()=>{}}/>);await flush();await press(root,"Show account security");await flush();expect(publicSurface(root.toJSON())).toMatchSnapshot("public caseload without unlocked custody");
});

it.each(["inside", "outside"])("retains recovery codes only while focus remains %s their custody block",async direction=>{
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await flush();await press(root,"Show account security");await flush();await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();await typeInto(root,"Current password (to authorize setup)","current-password");await typeInto(root,"6-digit code from the app","123456");await press(root,"Enable two-factor");await flush();
 const codes=root.root.findAllByType("div").find(n=>n.props["aria-label"]==="One-time recovery codes (cleared when this block loses focus)")!;await act(async()=>codes.props.onBlur({relatedTarget:direction==="inside"?{}:null,currentTarget:{contains:()=>direction==="inside"}}));expect(publicSurface(root.toJSON())).toMatchSnapshot("recovery-code custody after focus transition");
});

it("starts a new pairing comparison with no stale SAS, fingerprint or error while the server works",async()=>{
 vi.spyOn(cryptography,"serverWrapKeyFingerprint").mockResolvedValue("0123456789abcdef");const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await press(root,"Generate pairing code");await typeInto(root,"Patient's account id","patient-one");await press(root,"Show verification code");await flush();expect(textOf(root)).toContain("123456");
 let release!:(value:Awaited<ReturnType<typeof api.pairingSas>>)=>void;vi.mocked(api.pairingSas).mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;}));await typeInto(root,"Patient's account id","patient-two");await press(root,"Show verification code");await flush();try{expect(textOf(root)).not.toContain("123456");expect(publicSurface(root.toJSON())).toMatchSnapshot("fresh pairing comparison pending");}finally{release({sas:"654321",wrap_key_fingerprint:"0123456789abcdef",expires_in:900});await flush();}
 expect(textOf(root)).toContain("654321");await press(root,"Generate pairing code");await flush();expect(textOf(root)).not.toContain("654321");expect(publicSurface(root.toJSON())).toMatchSnapshot("new pairing session retires old comparison");
});

it("drops an old local pairing fingerprint when the next local fingerprint calculation fails",async()=>{
 vi.spyOn(cryptography,"serverWrapKeyFingerprint").mockResolvedValueOnce("0123456789abcdef").mockRejectedValueOnce(new Error("host digest unavailable"));const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await press(root,"Generate pairing code");await typeInto(root,"Patient's account id","first-patient");await press(root,"Show verification code");await flush();await typeInto(root,"Patient's account id","second-patient");await press(root,"Show verification code");await flush();expect(publicSurface(root.toJSON())).toMatchSnapshot("fresh pairing with unavailable local cross-check");
});

it("reports clipboard failure for shown-once recovery codes and retires it when closing security",async()=>{
 vi.stubGlobal("navigator",{clipboard:{writeText:async()=>{throw new Error("clipboard permission denied");}}});const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await press(root,"Show account security");await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();await typeInto(root,"Current password (to authorize setup)","current-password");await typeInto(root,"6-digit code from the app","123456");await press(root,"Enable two-factor");await flush();await press(root,"Copy recovery codes");await flush();expect(textOf(root)).toContain("could not copy the recovery codes — select the text and copy it manually.");await press(root,"Hide account security");await press(root,"Show account security");await flush();expect(textOf(root)).not.toContain("could not copy");expect(publicSurface(root.toJSON())).toMatchSnapshot("reopened security has no old recovery-copy note or entered secrets");
});

it("masks a freshly minted authenticator secret after the previous revealed setup was dismissed",async()=>{
 const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await press(root,"Show account security");await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();await press(root,"Show secret");await flush();expect(textOf(root)).toContain(fixtures.secret);await press(root,"Hide account security");await press(root,"Show account security");await typeInto(root,"Current password (to authorize setup)","current-password");await press(root,"Set up authenticator");await flush();expect(textOf(root)).not.toContain(fixtures.secret);expect(publicSurface(root.toJSON())).toMatchSnapshot("replacement authenticator setup starts masked");
});

it.each(["resolve","reject"])("ignores retired account-status %s after reopening security with a newer status",async result=>{
 let resolve!:(value:Awaited<ReturnType<typeof api.me>>)=>void,reject!:(error:unknown)=>void;vi.mocked(api.me).mockImplementationOnce(()=>new Promise((yes,no)=>{resolve=yes;reject=no;}));const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await press(root,"Show account security");await flush();await press(root,"Hide account security");vi.mocked(api.me).mockResolvedValueOnce({username:"drportal",display_name:"Dr. Portal",totp_enabled:true,wrap_pub_key:session.publicKeyB64,wrap_key_blob:"sealed"});await press(root,"Show account security");await flush();try{if(result==="resolve")resolve({username:"drportal",display_name:"Dr. Portal",totp_enabled:false,wrap_pub_key:session.publicKeyB64,wrap_key_blob:"sealed"});else reject(null);await flush();expect(textOf(root)).toContain("Disable two-factor");expect(textOf(root)).not.toContain("Set up authenticator");}finally{resolve({username:"drportal",display_name:"Dr. Portal",totp_enabled:true,wrap_pub_key:session.publicKeyB64,wrap_key_blob:"sealed"});await flush();}
});

it("keeps the newest public custody fingerprint when an older session's host digest finishes late",async()=>{
 let release!:(value:string)=>void;vi.spyOn(cryptography,"keyFingerprint").mockImplementationOnce(()=>new Promise(resolve=>{release=resolve;})).mockResolvedValueOnce("NEW SESSION FINGERPRINT");const root=await renderRaw(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await act(async()=>root.update(<PatientsView displayName="Dr. Portal" session={{...session,publicKeyB64:"NEW PUBLIC KEY"}} onOpen={()=>{}} onSignOut={()=>{}}/>));await flush();try{expect(textOf(root)).toContain("NEW SESSION FINGERPRINT");release("OLD SESSION FINGERPRINT");await flush();expect(textOf(root)).toContain("NEW SESSION FINGERPRINT");expect(textOf(root)).not.toContain("OLD SESSION FINGERPRINT");}finally{release("OLD SESSION FINGERPRINT");await flush();}
});

it.each([
 ["password","current"],["password","new"],["password","confirmation"],
 ["recovery","current"],["recovery","intended"],["recovery","repair state"],
 ["rotation","current"],["rotation","confirmation"],
] as const)("requires the isolated %s %s input before changing account custody",async(action,missing)=>{
 if(action==="recovery"&&missing!=="repair state")window.sessionStorage.setItem(`mindpattern.interruptedRotateSalt.${session.userId}`,"QUJDREVGR0hJSktMTU5P");const root=await render(<PatientsView displayName="Dr. Portal" session={session} onOpen={()=>{}} onSignOut={()=>{}}/>);await press(root,"Show account security");await flush();
 if(action==="password"){if(missing!=="current")await typeInto(root,"Current password","current-password");if(missing!=="new")await typeInto(root,"New password","Strong!pass123");if(missing!=="confirmation")await typeInto(root,"Repeat new password","Strong!pass123");}
 if(action==="recovery"){if(missing!=="current")await typeInto(root,"Current password (the one you sign in with)","current-password");if(missing!=="intended")await typeInto(root,"The password you were changing to","intended-password");}
 if(action==="rotation"){if(missing!=="current")await typeInto(root,"Current password (to authorize rotation)","current-password");if(missing!=="confirmation"){const checkbox=root.root.findAllByType("input").find(node=>node.props["aria-label"]==="Confirm sharing-key rotation")!;await act(async()=>checkbox.props.onChange({target:{checked:true}}));}}
 expect(publicSurface(root.toJSON())).toMatchSnapshot("isolated missing account custody input");
});
