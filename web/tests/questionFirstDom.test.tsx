// @vitest-environment jsdom
import {act,useLayoutEffect} from "react";
import {createRoot,type Root} from "react-dom/client";
import {afterEach,expect,it} from "vitest";
import {QuestionView} from "../src/views/Question";
import {vault} from "../src/vault";
import {installSession,jsonResponse,resetTestState,stubFetch} from "./helpers/api";
let root:Root|undefined;
afterEach(async()=>{await act(async()=>root?.unmount());document.body.replaceChildren();});
it("the first native question commit has no fabricated error alert",async()=>{resetTestState();installSession("a".repeat(32));vault.unlock({authKey:new Uint8Array(32).fill(6),dataKey:new Uint8Array(32).fill(6)},"a".repeat(32));stubFetch(()=>jsonResponse({code:"not_found"},{status:404}));const container=document.createElement("div");document.body.append(container);let alerts:string[]=[];function Observer(){useLayoutEffect(()=>{alerts=[...container.querySelectorAll('[role="alert"]')].map(n=>n.textContent??"");},[]);return <QuestionView onRefreshed={()=>{}}/>;}root=createRoot(container);await act(async()=>root!.render(<Observer/>));expect(alerts).toEqual([]);});
