/** Durable, account-bound checkpoint for a local data-key migration.
 * Original values remain untouched until the remote credential/corpus commit.
 * The journal retains originals and the old key encrypted under the new key;
 * partial local commits can therefore resume after a fresh new-password login.
 */
import { buildAad } from "./crypto/aad";
import { decrypt, encrypt, fromBase64, toBase64, zeroize, type Bytes } from "./crypto/core";
import { kv, newWriteGeneration, writeGenerationKey, type WritePermit } from "./kvstore";
import { resetEntryVersionMirrors } from "./entryVersions";
import { withLock, randomBytes } from "./platform";

export interface RotationCredential {
  operation_id: string;
  new_salt: string;
  new_verifier: string;
  new_wrapped_data_key?: string;
  new_kdf_params?: Record<string, unknown>;
  consent_wraps?: Array<{ consent_id: string; therapist_wrap_pub_key: string; ephemeral_pub: string; wrapped_key: string }>;
}
interface Journal { v: 1; owner: string; credential: RotationCredential; old_key: string; records: Array<{ key: string; before: string; after: string }>; generationBefore?:string|null; generationAfter?:string }
const slot = (owner: string) => `mindpattern.localRotation.${owner}`;
const saltSlot = (owner: string) => `mindpattern.rotationSalt.${owner}`;
const seedSlot = (owner: string) => `mindpattern.rotationSeed.${owner}`;

export async function rotationDataKey(owner: string, newMasterKey: Bytes): Promise<Bytes> {
  const raw = await kv.getItem(seedSlot(owner));
  const aad = buildAad("local-rotation-seed",owner);
  if (raw) {
    const bytes = await decrypt(newMasterKey,fromBase64(raw),aad);
    if (bytes.length !== 32) { zeroize(bytes); throw new Error("Stored rotation key is invalid."); }
    return bytes;
  }
  const bytes = randomBytes(32);
  try { await kv.setItem(seedSlot(owner),toBase64(await encrypt(newMasterKey,bytes,aad))); return bytes; }
  catch (error) { zeroize(bytes); throw error; }
}

export async function rotationSalt(owner: string, legacy: string | null): Promise<Bytes> {
  const stored = await kv.getItem(saltSlot(owner));
  if (stored) { const bytes = fromBase64(stored); if (bytes.length !== 16) throw new Error("Stored rotation salt is invalid; keep local data for recovery."); return bytes; }
  const salt = legacy ? fromBase64(legacy) : randomBytes(16);
  if (salt.length !== 16) throw new Error("Rotation salt is invalid.");
  await kv.setItem(saltSlot(owner), toBase64(salt));
  return salt;
}

async function openJournal(owner: string, key: Bytes, raw: string): Promise<Journal> {
  let plain: Bytes | null = null;
  try {
    plain = await decrypt(key, fromBase64(raw), buildAad("local-rotation", owner));
    const journal = JSON.parse(new TextDecoder().decode(plain)) as Journal;
    if (journal.v !== 1 || journal.owner !== owner || !journal.credential?.operation_id || !Array.isArray(journal.records) || fromBase64(journal.old_key).length !== 32) throw new Error("Invalid migration journal.");
    return journal;
  } finally { zeroize(plain); }
}

export async function stageLocalRotation(owner: string, oldKey: Bytes, newKey: Bytes, credential: RotationCredential): Promise<RotationCredential> {
  return withLock("local-rotation", async () => {
    const previous = await kv.getItem(slot(owner));
    if (previous) {
      try { return (await openJournal(owner,newKey,previous)).credential; }
      catch { throw new Error("A pending key change uses its original new password. Repeat that exact password in Settings; the encrypted checkpoint is retained."); }
    }
    const permit=await kv.captureWritePermit(owner,oldKey);
    const generationAfter=await newWriteGeneration(owner,newKey);
    const stores: Array<[string,string]> = [
      [`mindpattern.draft.active.${owner}`, "draft"], [`mindpattern.safetyPlan.${owner}`, "safety-plan"],
      [`mindpattern.moodlog.${owner}`, "moodlog"], [`mindpattern.feedback.${owner}`, "feedback-local"],
      [`mindpattern.pendingMeasure.${owner}`, "pending-measure"], [`mindpattern.patternMutes.v1.${owner}`, "pattern-mutes"],
      [`mindpattern.entryVersions.${owner}`, "entry-versions"], [`mindpattern.entryV2Bound.${owner}`, "entry-v2-bound"],
    ];
    const records: Journal["records"] = [];
    for (const [key,domain] of stores) {
      const before = await kv.getItem(key); if (before === null) continue;
      let plain: Bytes | null = null;
      try {
        const aad = buildAad(domain, owner); plain = await decrypt(oldKey,fromBase64(before),aad);
        records.push({key,before,after:toBase64(await encrypt(newKey,plain,aad))});
      } finally { zeroize(plain); }
    }
    // Queue values are JSON containers whose entry blobs have individual AAD.
    for (const key of await kv.keys()) {
      if (!/^mindpattern\/queue\.v1\.(items|rejected)\./.test(key)) continue;
      const before = await kv.getItem(key); if (before === null) continue;
      const parsed = JSON.parse(before); const items = Array.isArray(parsed) ? parsed : parsed.items;
      if (!Array.isArray(items)) throw new Error("A local queue is unreadable; keep it for recovery before rotating keys.");
      if (!items.some(item => item?.userId === owner)) continue;
      const afterItems = [];
      for (const item of items) {
        if (item?.userId !== owner) { afterItems.push(item); continue; }
        if (typeof item.clientEntryId !== "string" || typeof item.blobB64 !== "string") throw new Error("A queued entry is malformed; rotation has not started.");
        let resealed: string | null = null;
        for (const aad of [buildAad("entry",owner,item.clientEntryId,"1"),buildAad("entry",owner,item.clientEntryId)]) {
          let plain: Bytes | null = null;
          try { plain = await decrypt(oldKey,fromBase64(item.blobB64),aad); resealed = toBase64(await encrypt(newKey,plain,aad)); break; }
          catch { /* Try the historical entry binding. */ }
          finally { zeroize(plain); }
        }
        if (!resealed) throw new Error("A queued entry cannot be authenticated; rotation has not started.");
        afterItems.push({...item,blobB64:resealed});
      }
      records.push({key,before,after:JSON.stringify(Array.isArray(parsed) ? afterItems : {...parsed,items:afterItems})});
    }
    const journal: Journal = {v:1,owner,credential,old_key:toBase64(oldKey),records,generationBefore:permit.generation,generationAfter};
    const plain = new TextEncoder().encode(JSON.stringify(journal));
    try { await kv.setItem(slot(owner),toBase64(await encrypt(newKey,plain,buildAad("local-rotation",owner)))); }
    finally { zeroize(plain); }
    return credential;
  });
}

export async function resumeLocalRotation(owner: string, newKey: Bytes, confirmedRemoteSalt: string): Promise<void> {
  await withLock("local-rotation", async () => {
    const raw = await kv.getItem(slot(owner)); if (raw === null) return;
    const journal = await openJournal(owner,newKey,raw);
    if (confirmedRemoteSalt !== journal.credential.new_salt) throw new Error("The remote credential change has not been confirmed. Keep the encrypted checkpoint and repeat the same password change before applying local records.");
    // Upgrade an older checkpoint durably before advancing its generation.
    // This preserves every before/after branch and makes restart idempotent.
    if(journal.generationBefore===undefined || typeof journal.generationAfter!=="string"){
      journal.generationBefore=(await kv.captureWritePermit(owner)).generation;
      journal.generationAfter=await newWriteGeneration(owner,newKey);
      const plain=new TextEncoder().encode(JSON.stringify(journal));
      try {if(!await kv.compareAndSetForMigration(slot(owner),raw,toBase64(await encrypt(newKey,plain,buildAad("local-rotation",owner)))))throw new Error("The migration checkpoint changed; encrypted originals were retained.");}
      finally {zeroize(plain);}
    }
    const generationKey=writeGenerationKey(owner),currentGeneration=await kv.getItem(generationKey);
    if(currentGeneration!==journal.generationAfter && !await kv.compareAndSetForMigration(generationKey,journal.generationBefore,journal.generationAfter))throw new Error("The account writing generation changed; migration records were retained.");
    const permit:WritePermit={owner,generation:journal.generationAfter,keyBound:true};
    for (const record of journal.records) {
      const current = await kv.getItem(record.key);
      if (current === record.after) continue; // durable checkpoint already landed
      if (current !== record.before) throw new Error("Local writing changed during migration. Its encrypted originals are retained; resolve this conflict before editing.");
      if(!await kv.compareAndSetForMigration(record.key,record.before,record.after,permit))throw new Error("Local writing changed during migration. Its encrypted originals are retained; resolve this conflict before editing.");
    }
    resetEntryVersionMirrors();
    await kv.removeItem(saltSlot(owner));
    await kv.removeItem(seedSlot(owner));
    await kv.removeItem(slot(owner)); // only after every durable destination commit
  });
}

export async function hasLocalRotation(owner: string): Promise<boolean> { return (await kv.getItem(slot(owner))) !== null; }
