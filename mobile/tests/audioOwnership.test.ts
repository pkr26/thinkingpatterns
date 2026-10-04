import { afterEach, beforeEach, expect, it, vi } from "vitest";
import storage from "./helpers/storageMock";
import * as fs from "./helpers/expoFsMock";
import * as Sharing from "./helpers/expoSharingMock";
import { api, canonicalOrigin, getBaseUrl } from "../src/api/client";
import { setSecureStoreBackend } from "../src/secureStore";
import { prepareLocalRekey, __resetLocalKeyLifecycleForTests } from "../src/localRekey";
import { enqueueAudio, exportSavedAudio, listSavedAudio, removeSavedAudio, flushAudioQueue } from "../src/audioQueue";
import { encryptAudio } from "../src/crypto/journalCrypto";
import { eraseDeletedAccountLocals } from "../src/accountErasure";

vi.mock("../src/nativeFeatures", () => ({ cancelDailyReminder: vi.fn(async () => true), cancelMeasureReminder: vi.fn(async () => true) }));
const USER = "11111111111111111111111111111111", OTHER = "22222222222222222222222222222222";
const KEY = Buffer.alloc(32, 5), SALT = Buffer.alloc(16, 7).toString("base64");
function deferred<T = void>() { let resolve!: (value: T | PromiseLike<T>) => void; const promise = new Promise<T>(r => { resolve = r; }); return { promise, resolve }; }
async function seed(id = "saved") {
  await enqueueAudio({ userId: USER, clientEntryId: id, ...encryptAudio({ dataKey: KEY }, USER, id, Buffer.from("private recording")), mime: "audio/m4a", durationSeconds: 4 });
}
beforeEach(async () => {
  vi.restoreAllMocks(); storage.__reset(); fs.__resetFiles(); __resetLocalKeyLifecycleForTests(); setSecureStoreBackend(null);
  Sharing.shareAsync.mockClear(); Sharing.isAvailableAsync.mockResolvedValue(true);
  await api.setSession("owner-token", USER, "alice");
  await api.cacheKeyEnvelope("alice", { scheme: "v1", saltB64: SALT, kdfParams: null, wrappedB64: null });
});
afterEach(() => { vi.restoreAllMocks(); });

it("account erasure wins an export suspended before native file creation and sharing", async () => {
  await seed(); const started = deferred(), release = deferred<boolean>();
  Sharing.isAvailableAsync.mockImplementationOnce(async () => { started.resolve(); return release.promise; });
  const exporting = exportSavedAudio(USER, "saved").catch(e => e);
  await started.promise;
  expect(await eraseDeletedAccountLocals(USER, "alice", { preserveSession: true })).toEqual([]);
  const writesAfterErasure = fs.writeAsStringAsync.mock.calls.length;
  release.resolve(true);
  expect(await exporting).toBeInstanceOf(Error);
  expect(Sharing.shareAsync).not.toHaveBeenCalled();
  expect(fs.writeAsStringAsync).toHaveBeenCalledTimes(writesAfterErasure);
  expect(await listSavedAudio(USER)).toEqual([]);
});

it("a saved-recording removal cannot continue after its initial origin lookup spans account replacement", async () => {
  await seed(); const previous = (await listSavedAudio(USER))[0]!;
  const original = storage.getItem, started = deferred(), release = deferred(); let once = true;
  vi.spyOn(storage, "getItem").mockImplementation(async slot => {
    const value = await original(slot);
    if (slot === "@mindpattern/base_url" && once) { once = false; started.resolve(); await release.promise; }
    return value;
  });
  const removing = removeSavedAudio(USER, previous.id, previous.revision).catch(e => e);
  await started.promise; await api.setSession("replacement-token", OTHER, "bob"); release.resolve();
  expect(await removing).toBeInstanceOf(Error);
  expect(await listSavedAudio(USER)).toHaveLength(1);
});

it("erasure drains an already submitted export file write before removing the scoped directory", async () => {
  await seed(); const original = fs.writeAsStringAsync.getMockImplementation()!, started = deferred(), release = deferred();
  fs.writeAsStringAsync.mockImplementationOnce(async (uri, content) => {
    started.resolve(); await release.promise; return original(uri, content);
  });
  const exporting = exportSavedAudio(USER, "saved").catch(e => e); await started.promise;
  let erased = false;
  const erasure = eraseDeletedAccountLocals(USER, "alice", { preserveSession: true }).then(result => { erased = true; return result; });
  await new Promise<void>(r => setImmediate(r)); expect(erased).toBe(false);
  release.resolve(); expect(await exporting).toBeInstanceOf(Error); expect(await erasure).toEqual([]);
  const uri = fs.writeAsStringAsync.mock.calls.at(-1)![0];
  expect(fs.__hasFile(uri)).toBe(false); expect(Sharing.shareAsync).not.toHaveBeenCalled();
});

it("erasure drains a legacy recording migration already writing a native file", async () => {
  await storage.setItem(`@mindpattern/audioqueue.v1:${canonicalOrigin(await getBaseUrl())}:${USER}:legacy`, JSON.stringify({ blobB64: "retained legacy ciphertext", mime: "audio/m4a", durationSeconds: 4, queuedAt: Date.now() }));
  const original = fs.writeAsStringAsync.getMockImplementation()!, started = deferred(), release = deferred();
  fs.writeAsStringAsync.mockImplementationOnce(async (uri, content) => {
    started.resolve(); await release.promise; return original(uri, content);
  });
  const flushing = flushAudioQueue().catch(e => e); await started.promise;
  let erased = false;
  const erasure = eraseDeletedAccountLocals(USER, "alice", { preserveSession: true }).then(result => { erased = true; return result; });
  await new Promise<void>(r => setImmediate(r)); const finishedBeforeNativeWrite = erased;
  release.resolve(); await flushing; expect(await erasure).toEqual([]);
  expect(finishedBeforeNativeWrite).toBe(false);
  expect(fs.__hasFile(fs.writeAsStringAsync.mock.calls.at(-1)![0])).toBe(false);
  expect(await listSavedAudio(USER)).toEqual([]);
});

it("failed preparation cleans every staged recording file when a later retained take cannot decrypt", async () => {
  await seed("a-readable");
  await enqueueAudio({ userId: USER, clientEntryId: "b-unreadable", blobB64: "broken ciphertext", mime: "audio/m4a", durationSeconds: 4 });
  const priorWrites = fs.writeAsStringAsync.mock.calls.length;
  await expect(prepareLocalRekey(USER, KEY, Buffer.alloc(32, 9))).rejects.toThrow();
  const staged = fs.writeAsStringAsync.mock.calls.slice(priorWrites).map(([uri]) => uri);
  expect(staged).toHaveLength(1);
  for (const uri of staged) expect(fs.__hasFile(uri)).toBe(false);
  expect(await listSavedAudio(USER)).toHaveLength(2);
});
