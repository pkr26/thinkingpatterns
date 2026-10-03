/** One encrypted active typed-editor draft per account/server. Storage
 * failures and unreadable ciphertext never become an empty draft. */
import AsyncStorage from "@react-native-async-storage/async-storage";
import { canonicalOrigin, getBaseUrl } from "./api/client";
import { captureLocalWritePermit, assertLocalWritePermit, commitLocalWrite } from "./localRekey";
import { engine } from "./crypto/engine";
import { buildAad, decrypt, encrypt } from "./crypto/envelope";

export const JOURNAL_DRAFT_PREFIX = "@mindpattern/journal-draft.v1.";
export interface JournalDraft {
  v: 1; editorId: string; revision: number; text: string;
  mood: number | null; energy: number | null; sleep: number | null; tags: string[];
}
export interface JournalDraftScope { userId: string; origin: string; slot: string }
export interface LoadedJournalDraft { draft: JournalDraft; ciphertext: string }
export class JournalDraftUnreadableError extends Error {
  constructor() { super("The previous encrypted draft could not be read; its ciphertext was retained"); }
}
export class JournalDraftConflictError extends Error {
  constructor() { super("Another editor changed this draft; its ciphertext was retained"); }
}
let writes: Promise<unknown> = Promise.resolve();
const acknowledged = new Map<string, number>();
function serialized<T>(run: () => Promise<T>): Promise<T> {
  const result = writes.then(run, run); writes = result.catch(() => {}); return result;
}
export async function waitJournalDraftWrites(): Promise<void> { await writes; }
export function newJournalDraft(): JournalDraft {
  return { v: 1, editorId: Buffer.from(engine.randomBytes(16)).toString("hex"), revision: 0, text: "", mood: null, energy: null, sleep: null, tags: [] };
}
export async function journalDraftScope(userId: string): Promise<JournalDraftScope> {
  const origin = canonicalOrigin(new URL(await getBaseUrl()).origin);
  return { userId, origin, slot: `${JOURNAL_DRAFT_PREFIX}${Buffer.from(`${origin}\0${userId}`).toString("base64url")}` };
}
function checkScope(scope: JournalDraftScope): void {
  if (!scope.userId || canonicalOrigin(new URL(scope.origin).origin) !== scope.origin || scope.slot !== `${JOURNAL_DRAFT_PREFIX}${Buffer.from(`${scope.origin}\0${scope.userId}`).toString("base64url")}`) throw new Error("Invalid draft account/server scope");
}
function valid(value: unknown): value is JournalDraft {
  if (!value || typeof value !== "object") return false;
  const d = value as JournalDraft;
  const rating = (n: unknown, low: number, high: number) => n === null || (typeof n === "number" && Number.isFinite(n) && n >= low && n <= high);
  return d.v === 1 && /^[a-f0-9]{32}$/.test(d.editorId) && Number.isSafeInteger(d.revision) && d.revision >= 0 && typeof d.text === "string" && d.text.length <= 100_000 && rating(d.mood, -1, 1) && rating(d.energy, -1, 5) && rating(d.sleep, 1, 5) && Array.isArray(d.tags) && d.tags.length <= 200 && d.tags.every(t => typeof t === "string" && t.length <= 200);
}
function open(key: Buffer, scope: JournalDraftScope, raw: string): JournalDraft {
  let plain: Buffer | null = null;
  try {
    plain = decrypt(key, Buffer.from(raw, "base64"), buildAad("journal-draft", scope.userId, scope.origin));
    const value: unknown = JSON.parse(plain.toString("utf8"));
    if (!valid(value)) throw new JournalDraftUnreadableError();
    return value;
  } catch { throw new JournalDraftUnreadableError(); }
  finally { plain?.fill(0); }
}
const ackKey = (scope: JournalDraftScope, editorId: string) => `${scope.slot}\0${editorId}`;
export async function loadJournalDraft(key: Buffer, scope: JournalDraftScope): Promise<LoadedJournalDraft | null> {
  checkScope(scope); const copy = Buffer.from(key);
  try {
    await waitJournalDraftWrites();
    const raw = await AsyncStorage.getItem(scope.slot); if (raw === null) return null;
    const draft = open(copy, scope, raw);
    return { draft, ciphertext: raw };
  } finally { copy.fill(0); }
}
/** Same-editor revisions are monotonic. A different editor can replace a
 * readable older draft only after an explicit compare-and-swap choice. */
export function saveJournalDraft(key: Buffer, scope: JournalDraftScope, draft: JournalDraft, replaceCiphertext?: string): Promise<"saved" | "superseded"> {
  checkScope(scope); const permit = captureLocalWritePermit(scope.userId, key);
  if (!valid(draft)) return Promise.reject(new Error("Invalid journal draft"));
  const copy = Buffer.from(key), snapshot = { ...draft, tags: [...draft.tags] };
  return serialized(async () => {
    let plain: Buffer | null = null;
    try {
      assertLocalWritePermit(permit);
      if ((acknowledged.get(ackKey(scope, snapshot.editorId)) ?? -1) >= snapshot.revision) return "superseded";
      const raw = await AsyncStorage.getItem(scope.slot);
      if (raw !== null) {
        const current = open(copy, scope, raw);
        if (current.editorId !== snapshot.editorId && raw !== replaceCiphertext) throw new JournalDraftConflictError();
        if (current.editorId === snapshot.editorId && current.revision > snapshot.revision) return "superseded";
        if (current.editorId === snapshot.editorId && current.revision === snapshot.revision) {
          if (JSON.stringify(current) !== JSON.stringify(snapshot)) throw new JournalDraftConflictError();
          return "saved";
        }
      } else if (replaceCiphertext !== undefined) throw new JournalDraftConflictError();
      plain = Buffer.from(JSON.stringify(snapshot));
      const blob = encrypt(copy, plain, buildAad("journal-draft", scope.userId, scope.origin));
      assertLocalWritePermit(permit);
      if ((acknowledged.get(ackKey(scope, snapshot.editorId)) ?? -1) >= snapshot.revision) return "superseded";
      await commitLocalWrite(permit, () => AsyncStorage.setItem(scope.slot, blob.toString("base64")));
      return "saved";
    } finally { copy.fill(0); plain?.fill(0); }
  });
}
/** Call only after the entry has durable server/outbox custody. A late
 * completion may remove older revisions of the same editor, never new edits. */
export function acknowledgeJournalDraft(key: Buffer, scope: JournalDraftScope, editorId: string, revision: number): Promise<boolean> {
  checkScope(scope); const permit = captureLocalWritePermit(scope.userId, key);
  const marker = ackKey(scope, editorId);
  acknowledged.set(marker, Math.max(revision, acknowledged.get(marker) ?? -1));
  const copy = Buffer.from(key);
  return serialized(async () => {
    try {
      assertLocalWritePermit(permit);
      const raw = await AsyncStorage.getItem(scope.slot); if (raw === null) return true;
      const current = open(copy, scope, raw);
      if (current.editorId !== editorId || current.revision > revision) return false;
      assertLocalWritePermit(permit);
      await commitLocalWrite(permit, () => AsyncStorage.removeItem(scope.slot)); return true;
    } finally { copy.fill(0); }
  });
}
export async function clearJournalDraft(userId: string): Promise<void> {
  const scope = await journalDraftScope(userId);
  await serialized(async () => { await AsyncStorage.removeItem(scope.slot); });
}
export function __resetJournalDraftRuntimeForTests(): void { acknowledged.clear(); writes = Promise.resolve(); }
