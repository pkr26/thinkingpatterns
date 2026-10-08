/** Public Crisis resources and optional encrypted-plan navigation against
 * the actual vault. Linked Native views/Linking are supplied by the runner. */
import React from "react";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {CrisisScreen} from "../../src/screens/CrisisScreen";
import {ThemeProvider} from "../../src/theme";
import {vault} from "../../src/vault";
import {render,flush,textOf,act} from "../helpers/rtr";
import {nativeGrantedPress} from "../helpers/nativePressability";
import {TouchableOpacity} from "react-native";
const USER="a".repeat(32);
beforeEach(()=>vault.lock());
afterEach(()=>vault.lock());
it.each(["locked","unlocked","bare"] as const)("the Native %s Crisis view keeps resources available and exposes only its supported plan destination",async mode=>{
 if(mode!=="locked")vault.unlock({masterKey:Buffer.alloc(32,1),authKey:Buffer.alloc(32,2),dataKey:Buffer.alloc(32,3)},USER);
 const navigation={navigate:vi.fn()};const root=await render(<ThemeProvider><CrisisScreen navigation={mode==="bare"?undefined:navigation}/></ThemeProvider>);await flush();
 expect(textOf(root)).toContain("Call or text 988");expect(textOf(root)).toContain("Open findahelpline.com");
 if(mode==="unlocked"){
  const host=root.root.findAllByType(TouchableOpacity).find(node=>node.props.accessibilityLabel==="Make a safety plan — private, encrypted on this device")!;expect(host).toBeDefined();const tap=nativeGrantedPress(host.props);
  try{await act(async()=>{tap.release();});}finally{tap.dispose();}
  expect(navigation.navigate).toHaveBeenCalledWith("SafetyPlan");
 }else{expect(textOf(root)).not.toContain("Make a safety plan");expect(navigation.navigate).not.toHaveBeenCalled();}
 await act(async()=>root.unmount());
});
