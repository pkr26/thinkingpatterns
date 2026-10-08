/** Public subscription contract exercised by a rendered Native route consumer.
 * The Notifee seam supplies PRESS payloads; its module is the only OS substitute.
 * Disposal remains observable while the user stays on the visible journal. */
import React from "react";
import ReactTestRenderer,{act} from "react-test-renderer";
import {beforeEach,afterEach,it,expect,vi} from "vitest";
import {Text,TouchableOpacity} from "react-native";
import {subscribeNotificationRoutes,takePendingNotificationRoute,notifyNavigationReady,hasPendingNotificationRoute} from "../src/notificationRoute";
import {startNotificationPressRouting} from "../src/nativeFeatures";
let nativePress:((event:any)=>void)|undefined;
vi.mock("@notifee/react-native",()=>({default:{getInitialNotification:async()=>null,onForegroundEvent:(callback:(event:any)=>void)=>{nativePress=callback;return()=>{nativePress=undefined;};}},EventType:{PRESS:1}}));
let root:ReturnType<typeof ReactTestRenderer.create>|undefined,dispose:(()=>void)|null=null;
function RouteConsumer(){
 const[screen,setScreen]=React.useState("Entry"),[listening,setListening]=React.useState(true);
 React.useEffect(()=>listening?subscribeNotificationRoutes(()=>setScreen(takePendingNotificationRoute()??"Entry")):undefined,[listening]);
 return <><Text accessibilityRole="header">Destination: {screen}</Text><TouchableOpacity accessibilityLabel="Stop opening notification destinations" onPress={()=>setListening(false)}><Text>Stay here</Text></TouchableOpacity><TouchableOpacity accessibilityLabel="Resume opening notification destinations" onPress={()=>setListening(true)}><Text>Follow taps</Text></TouchableOpacity><TouchableOpacity accessibilityLabel="Return to journal" onPress={()=>setScreen("Entry")}><Text>Journal</Text></TouchableOpacity></>;
}
function words(){return root!.root.findAllByType(Text).map(n=>React.Children.toArray(n.props.children).join("")).join(" ");}
async function emit(id:unknown){await act(async()=>nativePress!({type:1,detail:{notification:{id}}}));}
async function press(label:string){await act(async()=>root!.root.findAllByType(TouchableOpacity).find(n=>n.props.accessibilityLabel===label)!.props.onPress());}
beforeEach(async()=>{takePendingNotificationRoute();nativePress=undefined;dispose=await startNotificationPressRouting();expect(dispose).toBeTypeOf("function");await act(async()=>{root=ReactTestRenderer.create(<RouteConsumer/>);});});
afterEach(async()=>{if(root){await act(async()=>root!.unmount());root=undefined;}dispose?.();dispose=null;takePendingNotificationRoute();});
it("Native notification destinations stop following taps after the visible consumer's preference disposes its subscription",async()=>{
 await emit("mindpattern-measure-reminder");expect(words()).toContain("Destination: Measures");await press("Return to journal");await press("Stop opening notification destinations");expect(words()).toContain("Destination: Entry");
 await emit("mindpattern-measure-reminder");expect(words()).toContain("Destination: Entry");expect(takePendingNotificationRoute()).toBe("Measures");
});
it("an unrelated Native tap cannot erase an already queued valid destination",async()=>{
 await press("Stop opening notification destinations");await emit("mindpattern-measure-reminder");await emit("daily-journal-reminder");expect(takePendingNotificationRoute()).toBe("Measures");expect(words()).toContain("Destination: Entry");
});
it("Native navigation-ready without a waiting tap keeps the consumed destination visible",async()=>{
 await emit("mindpattern-measure-reminder");expect(words()).toContain("Destination: Measures");expect(takePendingNotificationRoute()).toBeNull();await act(async()=>notifyNavigationReady());expect(words()).toContain("Destination: Measures");
});

it("an unrelated Native tap alone leaves the journal and pending-state observer unchanged",async()=>{await emit("daily-journal-reminder");expect(words()).toContain("Destination: Entry");expect(hasPendingNotificationRoute()).toBe(false);});
it("a queued Native tap opens its destination when the container becomes ready after subscription resumes",async()=>{await press("Stop opening notification destinations");await emit("mindpattern-measure-reminder");expect(hasPendingNotificationRoute()).toBe(true);await press("Resume opening notification destinations");expect(words()).toContain("Destination: Entry");await act(async()=>notifyNavigationReady());expect(words()).toContain("Destination: Measures");expect(hasPendingNotificationRoute()).toBe(false);});
