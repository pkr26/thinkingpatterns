import {afterEach,describe,it,expect,vi} from 'vitest';
afterEach(()=>vi.unstubAllGlobals());
describe('browser channel object ownership',()=>{
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
