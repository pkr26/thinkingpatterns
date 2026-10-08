/** Exported browser adapters against DOM and device-provider contracts.
 * Storage enumeration may observe a concurrent deletion: Storage.key
 * returns null for an index that no longer exists. */
import TestRenderer,{act}from"react-test-renderer";
import{afterEach,expect,it,vi}from"vitest";
import{JSDOM}from"jsdom";
import{downloadTextFile,localStore,requestAccountDownload,withLock}from"../src/platform";
import{applyLanguagePref,getLanguagePref,t}from"../src/strings";
import{crisisSmsLink,CrisisCard}from"../src/crisis";
import{vault}from"../src/vault";
afterEach(()=>{vi.unstubAllGlobals();vault.lock();});
it("hands the ticket as an actual successful form control to the browser download manager",()=>{
 const dom=new JSDOM("<!doctype html><body></body>",{url:"https://example.test"}),ticket="a".repeat(43);let body:FormData|undefined;
 vi.spyOn(dom.window.HTMLFormElement.prototype,"submit").mockImplementation(function(this:HTMLFormElement){body=new dom.window.FormData(this) as unknown as FormData;});
 vi.stubGlobal("document",dom.window.document);expect(requestAccountDownload(ticket)).toBe(true);expect(body?.get("ticket")).toBe(ticket);expect(dom.window.document.forms.length).toBe(0);dom.window.close();
});
it("removes the requested public preference without changing another application's value",()=>{
 const dom=new JSDOM("",{url:"https://example.test"});vi.stubGlobal("window",dom.window);
 localStore.set("mindpattern.language.pref","es");expect(localStore.get("mindpattern.language.pref")).toBe("es");localStore.remove("mindpattern.language.pref");expect(localStore.get("mindpattern.language.pref")).toBeNull();
 dom.window.localStorage.setItem("Stryker was here","keep-other-application");dom.window.localStorage.setItem("mindpattern.theme","dark");localStore.removePrefix("mindpattern.");expect(dom.window.localStorage.getItem("mindpattern.theme")).toBeNull();expect(dom.window.localStorage.getItem("Stryker was here")).toBe("keep-other-application");dom.window.close();
});
it("continues metadata removal when a native key enumeration reports a concurrent missing slot",()=>{
 const values=new Map([["old-first","a"],["old-second","b"]]);const nativeStorage={get length(){return values.size;},key:(index:number)=>{if(index===0){values.clear();const reported=null;values.set("other.application","keep");values.set("mindpattern.language.pref","es");return reported;}return [...values.keys()][index]??null;},removeItem:(key:string)=>{values.delete(key);}};
 vi.stubGlobal("window",{localStorage:nativeStorage});localStore.removePrefix("mindpattern.");expect(values.has("mindpattern.language.pref")).toBe(false);
});
it("preserves a preference appended after the final reported enumeration length",()=>{
 const values=new Map([["mindpattern.theme","dark"]]);let deliveredFirstKey=false,appended=false;const nativeStorage={get length(){const reported=values.size;if(deliveredFirstKey&&!appended){appended=true;values.set("mindpattern.language.pref","es");}return reported;},key:(index:number)=>{deliveredFirstKey=true;return [...values.keys()][index]??null;},removeItem:(key:string)=>{values.delete(key);}};
 vi.stubGlobal("window",{localStorage:nativeStorage});localStore.removePrefix("mindpattern.");expect(values.has("mindpattern.theme")).toBe(false);expect(values.get("mindpattern.language.pref")).toBe("es");
});
it("returns the stated native-download failure receipt when the Blob provider refuses allocation",()=>{
 vi.stubGlobal("window",{document:{createElement:()=>({click:()=>{}})}});vi.stubGlobal("URL",{createObjectURL:()=>{throw new Error("Native Blob allocation refused");},revokeObjectURL:()=>{}});expect(downloadTextFile("encrypted.json","{}","application/json")).toBe(false);
});
it("fails with the actionable locking receipt when navigator is absent",async()=>{
 vi.stubGlobal("navigator",undefined);await expect(withLock("private-journal",async()=>"saved")).rejects.toThrow("Safe shared storage locking is unavailable");
});
it("changes the public locale without a document capability",()=>{
 vi.stubGlobal("document",undefined);expect(()=>applyLanguagePref("es")).not.toThrow();expect(getLanguagePref()).toBe("es");
});
it("keeps the legacy SMS body separator when the native URL constructor is unavailable",()=>{
 vi.stubGlobal("URL",undefined);expect(crisisSmsLink()).toBe("sms:741741&body=HOME");
});
it("does not advertise a safety-plan action without an installed destination callback",async()=>{
 vault.unlock({authKey:new Uint8Array(32),dataKey:new Uint8Array(32)},"a".repeat(32));let root:ReturnType<typeof TestRenderer.create>;await act(async()=>{root=TestRenderer.create(<CrisisCard onClose={()=>{}}/>);});const rendered=JSON.stringify(root!.toJSON());expect(rendered).not.toContain(t("crisis.makePlan"));await act(async()=>root!.unmount());
});
it("retains browser storage methods when the module is first admitted",async()=>{
 vi.resetModules();const{localStore:fresh}=await import("../src/platform");const dom=new JSDOM("",{url:"https://example.test"});vi.stubGlobal("window",dom.window);fresh.set("mindpattern.language.pref","es");expect(fresh.get("mindpattern.language.pref")).toBe("es");dom.window.close();
});
it("boots the language module without a document capability",async()=>{
 vi.resetModules();vi.stubGlobal("document",undefined);const strings=await import("../src/strings");expect(strings.getLanguagePref()).toMatch(/^(auto|en|es)$/);
});
it("encodes the public entry identifier from exactly nine random bytes without padding",async()=>{
 vi.resetModules();vi.stubGlobal("crypto",{getRandomValues:(bytes:Uint8Array)=>{bytes.set([1,2,3,4,5,6,7,8,9]);return bytes;}});const{newClientEntryId}=await import("../src/entryId");expect(newClientEntryId("2026-10-07")).toBe("e-2026-10-07-AQIDBAUGBwgJ");
});
it("constructs the public canonical authenticated record binding",async()=>{
 const{buildAad}=await import("../src/crypto/aad");expect(new TextDecoder().decode(buildAad("user","entry"))).toBe('["user","entry"]');
});
