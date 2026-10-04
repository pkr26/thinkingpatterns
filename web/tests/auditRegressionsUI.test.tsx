import { afterEach,beforeEach,describe,it,expect,vi } from 'vitest';
import { act } from 'react';
import { EntryView } from '../src/views/Entry';
import { PatternsView } from '../src/views/Patterns';
import { SafetyPlanView } from '../src/views/SafetyPlan';
import { ShareView } from '../src/views/Share';
import { saveSafetyPlan, EMPTY_SAFETY_PLAN } from '../src/safetyPlan';
import { kv } from '../src/kvstore';
import { api } from '../src/api/client';
import { buildAad } from '../src/crypto/aad';
import { encrypt,toBase64 } from '../src/crypto/core';
import { vault } from '../src/vault';
import { setKvBackendForTests } from '../src/kvstore';
import { installSession,resetTestState,jsonResponse,stubFetch } from './helpers/api';
import { render,press,typeArea,typeInto,settle,textOf } from './helpers/rtr';
function deferred<T>(){let resolve!:(x:T)=>void;let promise=new Promise<T>(r=>resolve=r);return {promise,resolve};}
beforeEach(()=>{resetTestState();installSession('audit-user');vault.unlock({authKey:new Uint8Array(32).fill(6),dataKey:new Uint8Array(32).fill(6)},'audit-user');});
afterEach(()=>{vi.unstubAllGlobals();vi.restoreAllMocks();setKvBackendForTests(null);});
describe('independent UI custody probes',()=>{
 it('editing a pairing code invalidates a lookup that is still awaiting its response',async()=>{
  const pending=deferred<Awaited<ReturnType<typeof api.pairingLookup>>>();
  const lookup=vi.spyOn(api,'pairingLookup').mockImplementationOnce(()=>pending.promise).mockResolvedValue({therapist_id:'new-therapist',display_name:'New Doctor',wrap_pub_key:toBase64(new Uint8Array(91).fill(4))});
  vi.spyOn(api,'listConsents').mockResolvedValue([]);
  const root=await render(<ShareView/>);
  await typeInto(root,'Pairing code','OLD12345');await press(root,'Look up');
  expect(lookup).toHaveBeenCalledWith('OLD12345');
  await typeInto(root,'Pairing code','NEW12345');
  await act(async()=>pending.resolve({therapist_id:'old-therapist',display_name:'Old Doctor',wrap_pub_key:toBase64(new Uint8Array(91).fill(3))}));
  await settle(20,3);
  expect(textOf(root)).not.toContain('Old Doctor');
  expect(root.root.findAllByType('input').filter(node=>node.props.type==='checkbox')).toHaveLength(0);
  await press(root,'Look up');await settle(20,3);expect(lookup).toHaveBeenLastCalledWith('NEW12345');expect(textOf(root)).toContain('New Doctor');
  await act(async()=>root.unmount());
 });
 it('changing a pairing code during key wrapping stops the unconfirmed grant before dispatch',async()=>{
  const sharing=await import('../src/crypto/sharing');
  const pending=deferred<Awaited<ReturnType<typeof sharing.wrapDataKeyForTherapist>>>();
  const wrap=vi.spyOn(sharing,'wrapDataKeyForTherapist').mockImplementationOnce(()=>pending.promise);
  const grant=vi.spyOn(api,'grantConsent').mockResolvedValue({id:'unused',therapist_id:'old-therapist',display_name:'Old Doctor',username:'old-doctor',status:'active',granted_at:'2026-10-03T00:00:00Z',revoked_at:null});
  vi.spyOn(api,'pairingLookup').mockResolvedValue({therapist_id:'old-therapist',display_name:'Old Doctor',wrap_pub_key:toBase64(new Uint8Array(91).fill(3))});
  vi.spyOn(api,'listConsents').mockResolvedValue([]);
  const root=await render(<ShareView/>);await typeInto(root,'Pairing code','OLD12345');await press(root,'Look up');await settle(20,3);
  for(const checkbox of root.root.findAllByType('input').filter(node=>node.props.type==='checkbox'))await act(async()=>checkbox.props.onChange({target:{checked:true}}));
  await press(root,'Confirm and share');expect(wrap).toHaveBeenCalledTimes(1);
  await typeInto(root,'Pairing code','NEW12345');
  await act(async()=>pending.resolve({ephemeralPubB64:'ephemeral',wrappedKeyB64:'wrapped'}));await settle(20,3);
  expect(grant).not.toHaveBeenCalled();await act(async()=>root.unmount());
 });
 it('failed safety-plan reads cannot overwrite stored data and a retry preserves typed fields while restoring untouched fields',async()=>{
  await saveSafetyPlan(vault.get().dataKey,'audit-user',{...EMPTY_SAFETY_PLAN,warningSigns:'stored warning',helpers:'stored support contact'});
  const original=await kv.getItem('mindpattern.safetyPlan.audit-user');let fail=true;
  const get=vi.spyOn(kv,'getItem').mockImplementation(async key=>{if(fail)throw new Error('device read blocked');return key==='mindpattern.safetyPlan.audit-user'?original:null;});
  const root=await render(<SafetyPlanView onCrisis={()=>{}}/>);await settle(10,2);
  expect(textOf(root)).toContain('device read blocked');
  const area=root.root.findAllByType('textarea')[0]!;
  await act(async()=>{area.props.onChange({target:{value:'new warning typed during hydration'}});});
  await press(root,'Save my plan');expect(textOf(root)).toContain('Restore the existing encrypted plan');
  fail=false;await press(root,'Retry restoring saved plan');await settle(10,2);
  const areas=root.root.findAllByType('textarea');expect(areas[0]!.props.value).toBe('new warning typed during hydration');expect(areas[3]!.props.value).toBe('stored support contact');expect(areas[0]!.props.maxLength).toBe(4000);
  get.mockRestore();expect(await kv.getItem('mindpattern.safetyPlan.audit-user')).toBe(original);await act(async()=>root.unmount());
 });
 it('edits made while a save is pending are preserved after the submitted entry commits',async()=>{
  const sent=deferred<{id:string}>();const create=vi.spyOn(api,'createEntry').mockImplementation(()=>sent.promise);
  stubFetch(()=>jsonResponse({detail:'unmatched'},{status:404}));const root=await render(<EntryView onSaved={()=>{}}/>);
  await typeArea(root,'How was today?','original saved text');await press(root,'Save entry');await settle(20,3);expect(create).toHaveBeenCalledTimes(1);
  await typeArea(root,'How was today?','new writing during pending save');expect(root.root.findAllByType('textarea')[0]!.props.value).toContain('new writing');
  await act(async()=>{sent.resolve({id:'saved'});});await settle(20,3);expect(root.root.findAllByType('textarea')[0]!.props.value).toBe('new writing during pending save');await act(async()=>root.unmount());
 });
 it('actual pattern rendering uses the exact validated generation without a second fetch',async()=>{
  const key=new Uint8Array(32).fill(6);const response=async(seq:number,label:string)=>({phase:'insight',active_days:40,streak:1,days_remaining:0,state_seq:seq,blob:toBase64(await encrypt(key,new TextEncoder().encode(JSON.stringify({v:2,state_seq:seq,stats:{patterns:[{kind:'topic',label,occurrences:9,confidence:.9,detail:{pattern_pid:'topic:a',sample_days:40}}]}})),buildAad('insights','audit-user','patterns')))});
  const current=await response(20,'CURRENT GENERATION'),replay=await response(1,'REPLAYED OLD GENERATION');let n=0;vi.spyOn(api,'insights').mockImplementation(async()=>n++===0?current:replay);
  const root=await render(<PatternsView onCrisis={()=>{}}/>);await settle(20,4);expect(n).toBe(1);expect(textOf(root)).toContain('CURRENT GENERATION');expect(textOf(root)).not.toContain('freshness check');await act(async()=>root.unmount());
 });
});
