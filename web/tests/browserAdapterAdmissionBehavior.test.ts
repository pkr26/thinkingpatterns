import{afterEach,expect,it,vi}from"vitest";
import{JSDOM}from"jsdom";
afterEach(()=>vi.unstubAllGlobals());
it("admits the complete public browser storage adapter on first import",async()=>{
 vi.resetModules();const dom=new JSDOM("",{url:"https://example.test"});vi.stubGlobal("window",dom.window);const{localStore}=await import("../src/platform");localStore.set("mindpattern.language.pref","es");expect(localStore.get("mindpattern.language.pref")).toBe("es");localStore.remove("mindpattern.language.pref");expect(dom.window.localStorage.getItem("mindpattern.language.pref")).toBeNull();dom.window.close();
});
it("admits the public locale module with no document",async()=>{
 vi.resetModules();vi.stubGlobal("document",undefined);const strings=await import("../src/strings");strings.applyLanguagePref("es");expect(strings.getLanguagePref()).toBe("es");
});
