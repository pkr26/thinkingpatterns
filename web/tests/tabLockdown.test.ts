import {afterEach,describe,it,expect,vi} from 'vitest';
afterEach(()=>vi.unstubAllGlobals());
describe('browser channel object ownership',()=>{
 it('receives the established cross-page wire channel and rejects malformed or unrelated broadcasts',async()=>{
  const channels=new Set<Channel>();
  class Channel {onmessage:((event:{data:unknown})=>void)|null=null;constructor(readonly name:string){channels.add(this);}postMessage(data:unknown){for(const channel of channels)if(channel!==this&&channel.name===this.name)channel.onmessage?.({data});}close(){channels.delete(this);}}
  vi.stubGlobal('BroadcastChannel',Channel);vi.resetModules();const module=await import('../src/tabLockdown');const lock=vi.fn();const unsubscribe=module.subscribeTabLockdown(lock);
  const olderPage=new Channel('mindpattern-session-lockdown');
  for(const data of [null,undefined,{},'rotation',{reason:'other'},{reason:false}])expect(()=>olderPage.postMessage(data)).not.toThrow();
  expect(lock).not.toHaveBeenCalled();olderPage.postMessage({reason:'rotation',source_id:'independent-page'});expect(lock).toHaveBeenCalledExactlyOnceWith('rotation');
  unsubscribe();olderPage.postMessage({reason:'rotation',source_id:'independent-page'});expect(lock).toHaveBeenCalledOnce();olderPage.close();
 });
 it.each([undefined,null,0,'unavailable',{}])('is optional when the browser exposes no usable channel constructor: %j',async candidate=>{
  vi.stubGlobal('BroadcastChannel',candidate);vi.resetModules();const module=await import('../src/tabLockdown');const handler=vi.fn();expect(()=>module.broadcastTabLockdown('rotation')).not.toThrow();expect(()=>module.subscribeTabLockdown(handler)()).not.toThrow();expect(handler).not.toHaveBeenCalled();
 });
 it('ignores delivery from its own separate sender channel while other pages lock',async()=>{
  const channels=new Set<Channel>();
  class Channel {onmessage:((event:{data:unknown})=>void)|null=null;constructor(readonly name:string){channels.add(this);}postMessage(data:unknown){for(const channel of channels)if(channel!==this && channel.name===this.name)channel.onmessage?.({data});}close(){channels.delete(this);}}
  vi.stubGlobal('BroadcastChannel',Channel);
  vi.resetModules();const first=await import('../src/tabLockdown');const own=vi.fn();const unsubscribeOwn=first.subscribeTabLockdown(own);
  first.broadcastTabLockdown('rotation');expect(own).not.toHaveBeenCalled();
  vi.resetModules();const second=await import('../src/tabLockdown');const other=vi.fn();const unsubscribeOther=second.subscribeTabLockdown(other);
  first.broadcastTabLockdown('rotation');expect(own).not.toHaveBeenCalled();expect(other).toHaveBeenCalledOnce();
  second.broadcastTabLockdown('rotation');expect(own).toHaveBeenCalledOnce();expect(other).toHaveBeenCalledOnce();
  unsubscribeOwn();unsubscribeOther();expect(channels.size).toBe(0);
 });
});
