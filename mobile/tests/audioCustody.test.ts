import { beforeEach, expect, it, vi } from "vitest";
vi.mock("../src/api/client", async importOriginal => {
  const actual = await importOriginal<typeof import("../src/api/client")>();
  const { makeApiMock } = await import("./helpers/apiMock");
  return { ...actual, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});
vi.mock("../src/offlineQueue", () => ({ prepareQueueRekey: vi.fn(async () => []), abortInFlightFlush: vi.fn(), flushQueue: vi.fn(async () => 0), pendingEntryIds: vi.fn(async () => []) }));
const { api } = await import("../src/api/client");
const { enqueueAudio, flushAudioQueue, retryAudioQueue, listSavedAudio, exportSavedAudio, removeSavedAudio, clearAudioQueue } = await import("../src/audioQueue");
const { encryptAudio, decryptAudio, deriveKeysAsync } = await import("../src/crypto/MindPatternCrypto");
const { __resetLocalKeyLifecycleForTests } = await import("../src/localRekey");
const { resetApi, SALT_B64 } = await import("./helpers/apiMock");
const storage = (await import("./helpers/storageMock")).default;
const fs = await import("./helpers/expoFsMock");
const Sharing = await import("./helpers/expoSharingMock");
const password = "export fixture password";
const key = (await deriveKeysAsync(password, Buffer.from(SALT_B64, "base64"))).dataKey, user = "user-1";
beforeEach(() => { __resetLocalKeyLifecycleForTests(); resetApi(api as never); storage.__reset(); fs.__resetFiles(); Sharing.shareAsync.mockClear(); Sharing.isAvailableAsync.mockResolvedValue(true); });
it("a recording acquired before parent commit stays encrypted and never uploads without its parent", async () => {
  const blob = encryptAudio({ dataKey: key }, user, "parent:one", Buffer.from("my spoken words"));
  await enqueueAudio({ userId: user, clientEntryId: "parent:one", ...blob, mime: "audio/m4a", durationSeconds: 4, parentPending: true });
  expect(await flushAudioQueue()).toBe(0);
  expect(api.uploadAudioAttachment).not.toHaveBeenCalled();
  await retryAudioQueue(user); // absent parent cannot release custody
  expect(await listSavedAudio(user)).toEqual([expect.objectContaining({ id: "parent:one", needsAttention: true })]);
  vi.mocked(api.getEntry).mockResolvedValue({ client_entry_id: "parent:one" } as never);
  await retryAudioQueue(user); // response lost after parent commit can heal
  expect(api.uploadAudioAttachment).toHaveBeenCalledTimes(1);
  expect(await listSavedAudio(user)).toEqual([]);
});
it("exports one self-contained encrypted recording through native file sharing and preserves custody", async () => {
  const plain = Buffer.from("private recording");
  await enqueueAudio({ userId: user, clientEntryId: "recording", ...encryptAudio({ dataKey: key }, user, "recording", plain), mime: "audio/m4a", durationSeconds: 5 });
  vi.mocked(api.getCachedSalt).mockResolvedValue(SALT_B64);
  await exportSavedAudio(user, "recording");
  const uri = Sharing.shareAsync.mock.calls[0]![0];
  const json = await fs.readAsStringAsync(uri);
  expect(json).not.toContain("private recording");
  expect(json).not.toContain(key.toString("base64"));
  const bundle = JSON.parse(json);
  expect(bundle).toMatchObject({ version: 2, username: "alice", user_id: user, salt: SALT_B64, key_scheme: "v1" });
  expect(bundle.audio[0]).toMatchObject({ mime_type: "audio/m4a", content_version: 1, client_entry_id: "recording" });
  expect(decryptAudio({ dataKey: key }, user, "recording", bundle.audio[0].blob)).toEqual(plain);
  expect(await listSavedAudio(user)).toHaveLength(1);
  await clearAudioQueue(user);
  expect(fs.__hasFile(uri)).toBe(false);
});
it("a destructive confirmation cannot erase a replacement recording revision", async () => {
  const enqueue = () => enqueueAudio({ userId: user, clientEntryId: "same", ...encryptAudio({ dataKey: key }, user, "same", Buffer.from("voice")), mime: "audio/m4a", durationSeconds: 4 });
  await enqueue(); const before = (await listSavedAudio(user))[0]!;
  await enqueue();
  await expect(removeSavedAudio(user, "same", before.revision)).rejects.toThrow("changed");
  expect(await listSavedAudio(user)).toHaveLength(1);
  const after = (await listSavedAudio(user))[0]!;
  await removeSavedAudio(user, "same", after.revision);
  expect(await listSavedAudio(user)).toEqual([]);
});
