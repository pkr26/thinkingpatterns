/** Durable, account-specific local erasure after acknowledged remote deletion. */
import { kv,writeGenerationKey } from './kvstore';
import { withLock } from './platform';
import { resetEntryVersionMirrors } from './entryVersions';
export interface ErasureTombstone { v:1; owner:string; remoteConfirmed:boolean; keys:string[] }
const prefix='mindpattern.erase.';
function owned(key:string,owner:string):boolean {
 if(key===writeGenerationKey(owner))return false; // minimal durable deleted-generation fence
 if (key.startsWith('mindpattern.') && key.endsWith(`.${owner}`) && !key.startsWith(prefix)) return true;
 const match=/^mindpattern\/queue\.v1\.(?:items|rejected|quarantine)\.([A-Za-z0-9_-]+)$/.exec(key);
 if (!match) return false;
 try { const binary=atob(match[1]!.replace(/-/g,'+').replace(/_/g,'/'));const decoded=new TextDecoder().decode(Uint8Array.from(binary,char=>char.charCodeAt(0)));return decoded.slice(decoded.indexOf('\0')+1)===owner && decoded.includes('\0'); }
 catch {return false;}
}
function parse(raw:string,id:string):ErasureTombstone {
 const row=JSON.parse(raw) as ErasureTombstone;
 if(row.v!==1 || !row.owner || `${prefix}${row.owner}`!==id || typeof row.remoteConfirmed!=='boolean' || !Array.isArray(row.keys) || row.keys.some(key=>typeof key!=='string' || !owned(key,row.owner))) throw new Error('An unfinished deletion record is unreadable. Local records have been retained.');
 return row;
}
export async function stageLocalErasure(owner:string):Promise<void> {
 await withLock('account-erasure',async()=>{
  const id=`${prefix}${owner}`;const raw=await kv.getItem(id);
  if(raw!==null){parse(raw,id);return;}
  const keys=(await kv.keys()).filter(key=>owned(key,owner));
  await kv.setItem(id,JSON.stringify({v:1,owner,remoteConfirmed:false,keys}));
 });
}
function clearOwnedPreferences(owner:string):void {
 if(typeof window==='undefined') return;
 for(const storage of [window.localStorage,window.sessionStorage]){
  const keys=[];
  for(let i=0;i<storage.length;i++){const key=storage.key(i);if(key?.startsWith('mindpattern.') && key.endsWith(`.${owner}`))keys.push(key);}
  for(const key of keys)storage.removeItem(key);
 }
}
async function erase(row:ErasureTombstone):Promise<void> {
 await kv.markOwnerErased(row.owner);
 // Refresh the registry before erasure to include late owner-scoped writes.
 const keys=new Set([...row.keys,...(await kv.keys()).filter(key=>owned(key,row.owner))]);
 for(const key of keys)await kv.removeItem(key);
 clearOwnedPreferences(row.owner);
 resetEntryVersionMirrors();
 await kv.removeItem(`${prefix}${row.owner}`); // last commit acknowledges completion
}
export async function confirmLocalErasure(owner:string):Promise<void> {
 await withLock('account-erasure',async()=>{
  const id=`${prefix}${owner}`;const raw=await kv.getItem(id);if(raw===null)return;
  const row=parse(raw,id);row.remoteConfirmed=true;
  await kv.setItem(id,JSON.stringify(row));
  await erase(row);
 });
}
export async function pendingLocalErasures():Promise<ErasureTombstone[]> {
 const rows=[];
 for(const id of (await kv.keys()).filter(key=>key.startsWith(prefix))){const raw=await kv.getItem(id);if(raw!==null)rows.push(parse(raw,id));}
 return rows;
}
export async function resumeConfirmedErasures():Promise<ErasureTombstone[]> {
 const initial=await pendingLocalErasures();
 if(!initial.some(row=>row.remoteConfirmed))return initial;
 return withLock('account-erasure',async()=>{
  for(const row of await pendingLocalErasures())if(row.remoteConfirmed)await erase(row);
  return pendingLocalErasures();
 });
}
