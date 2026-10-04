// @ts-nocheck
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { kv,setKvBackendForTests } from '../src/kvstore';
import { stageLocalErasure,confirmLocalErasure,confirmRemoteLocalErasure,pendingLocalErasures,resumeConfirmedErasures } from '../src/localErasure';
import { KEY_BOUND_OWNER_PREFIXES,METADATA_OWNER_PREFIXES } from '../src/ownerStorage';
let records:Map<string,string>;let fail:string;
beforeEach(()=>{records=new Map();fail='';setKvBackendForTests({getItem:async key=>records.get(key)??null,setItem:async(key,value)=>{records.set(key,value);},removeItem:async key=>{if(key===fail)throw new Error('denied');records.delete(key);},compareAndSet:async(key,before,after)=>{if((records.get(key)??null)!==before)return false;records.set(key,after);return true;},keys:async()=>[...records.keys()]});window.localStorage.clear();window.sessionStorage.clear();});
afterEach(()=>{setKvBackendForTests(null);vi.restoreAllMocks();});
describe('account-specific erasure checkpoints',()=>{
 it('stages before deletion, retains failed committed cleanup, resumes after restart, and preserves every other account',async()=>{
  const owner='deleted-user',other='other-user';const own=`mindpattern.safetyPlan.${owner}`,foreign=`mindpattern.safetyPlan.${other}`;
  await kv.setItem(own,'own encrypted plan');await kv.setItem(foreign,'other encrypted plan');window.localStorage.setItem(`mindpattern.onboarding.v1.${owner}`,'done');window.localStorage.setItem(`mindpattern.onboarding.v1.${other}`,'done');
  const registered=[...KEY_BOUND_OWNER_PREFIXES,...METADATA_OWNER_PREFIXES].map(prefix=>`${prefix}${owner}`);
  for(const key of registered)await kv.setItem(key,`owned:${key}`);
  const scope=btoa(`http://localhost:5173\0${owner}`).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  const queue=`mindpattern/queue.v1.items.${scope}`;const evictions=`mindpattern/queue.v1.evictions.${scope}`;
  await kv.setItem(queue,'encrypted queued entry');await kv.setItem(evictions,JSON.stringify({rejected:2,quarantine:1}));
  await stageLocalErasure(owner);expect((await pendingLocalErasures())[0]?.remoteConfirmed).toBe(false);await resumeConfirmedErasures();expect(await kv.getItem(own)).not.toBeNull();
  fail=own;await expect(confirmLocalErasure(owner)).rejects.toThrow('deletion did not finish');expect((await pendingLocalErasures())[0]?.remoteConfirmed).toBe(true);expect(await kv.getItem(foreign)).toBe('other encrypted plan');
  fail='';await resumeConfirmedErasures();expect(await kv.getItem(own)).toBeNull();for(const key of registered)expect(await kv.getItem(key)).toBeNull();expect(await kv.getItem(queue)).toBeNull();expect(await kv.getItem(evictions)).toBeNull();expect(await pendingLocalErasures()).toEqual([]);expect(await kv.getItem(foreign)).toBe('other encrypted plan');expect(window.localStorage.getItem(`mindpattern.onboarding.v1.${other}`)).toBe('done');expect(window.localStorage.getItem(`mindpattern.onboarding.v1.${owner}`)).toBeNull();
 });
 it('keeps unconfirmed requests and refuses corrupted cross-account key registries',async()=>{
  await kv.setItem('mindpattern.draft.active.keep-user','private draft');await stageLocalErasure('keep-user');await stageLocalErasure('keep-user');expect(await resumeConfirmedErasures()).toHaveLength(1);expect(await kv.getItem('mindpattern.draft.active.keep-user')).toBe('private draft');
  await kv.setItem('mindpattern.erase.bad-user',JSON.stringify({v:1,owner:'bad-user',remoteConfirmed:true,keys:['mindpattern.draft.active.keep-user']}));await expect(resumeConfirmedErasures()).rejects.toThrow('unreadable');expect(await kv.getItem('mindpattern.draft.active.keep-user')).toBe('private draft');
 });
 it('persists authenticated remote death as confirmed before retryable cleanup',async()=>{
  const owner='remote-deleted',slot=`mindpattern.safetyPlan.${owner}`;await kv.setItem(slot,'encrypted plan');fail=slot;
  await expect(confirmRemoteLocalErasure(owner)).rejects.toThrow('deletion did not finish');
  expect(await pendingLocalErasures()).toEqual([expect.objectContaining({owner,remoteConfirmed:true})]);
  fail='';await resumeConfirmedErasures();expect(await kv.getItem(slot)).toBeNull();expect(await pendingLocalErasures()).toEqual([]);
 });
});
