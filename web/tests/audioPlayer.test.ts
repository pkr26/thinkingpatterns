import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { playAttachment } from "../src/audio/player";
import { decryptAudio, encryptAudio } from "../src/crypto/patient";

vi.mock("../src/crypto/patient", async (original) => {
  const actual = await original<typeof import("../src/crypto/patient")>();
  return { ...actual, decryptAudio: vi.fn(actual.decryptAudio) };
});

const dataKey = new Uint8Array(new ArrayBuffer(32)).fill(17);
const audio = new Uint8Array([4, 17, 23, 42, 99]);
beforeEach(() => { vi.mocked(decryptAudio).mockClear(); });
afterEach(() => { vi.restoreAllMocks(); });

async function options() {
  const { blobB64 } = await encryptAudio(dataKey, "audio-owner", "audio-entry", audio);
  return {
    dataKey, userId: "audio-owner", clientEntryId: "audio-entry",
    fetchBlob: vi.fn(async () => ({ blob: blobB64, mime_type: "audio/webm", duration_seconds: 7 })),
  };
}

describe("kept recording playback lifecycle", () => {
  it("transfers the decrypted audio into a correctly typed playback Blob and revokes only once", async () => {
    let playback: Blob | undefined;
    const create = vi.spyOn(URL, "createObjectURL").mockImplementation((blob) => {
      if (!(blob instanceof Blob)) throw new Error("Audio playback requires a Blob");
      playback = blob;
      return "blob:kept-recording";
    });
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    const request = await options();
    const playing = await playAttachment(request);
    expect(request.fetchBlob).toHaveBeenCalledOnce();
    expect(create).toHaveBeenCalledOnce();
    expect(playback!.type).toBe("audio/webm");
    expect(new Uint8Array(await playback!.arrayBuffer())).toEqual(audio);
    expect(playing.url).toBe("blob:kept-recording");
    expect(playing.mime).toBe("audio/webm");
    expect(playing.durationSeconds).toBe(7);
    // decryptAudio returns a caller-owned buffer. Playback must erase that
    // public API result after the browser Blob has copied its contents.
    const returned = await vi.mocked(decryptAudio).mock.results[0]!.value;
    expect(Array.from(returned as Uint8Array)).toEqual([0, 0, 0, 0, 0]);
    playing.release();
    playing.release();
    expect(revoke).toHaveBeenCalledExactlyOnceWith("blob:kept-recording");
  });

  it("erases the returned plaintext even if browser playback allocation fails", async () => {
    vi.spyOn(URL, "createObjectURL").mockImplementation(() => { throw new Error("allocation denied"); });
    const revoke = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    await expect(playAttachment(await options())).rejects.toThrow("allocation denied");
    const returned = await vi.mocked(decryptAudio).mock.results[0]!.value;
    expect(Array.from(returned as Uint8Array)).toEqual([0, 0, 0, 0, 0]);
    expect(revoke).not.toHaveBeenCalled();
  });

  it("does not allocate a playback resource after a failed fetch or authentication", async () => {
    const create = vi.spyOn(URL, "createObjectURL");
    const request = await options();
    request.fetchBlob.mockRejectedValueOnce(new Error("offline"));
    await expect(playAttachment(request)).rejects.toThrow("offline");
    await expect(playAttachment({ ...request, userId: "wrong-owner" })).rejects.toThrow();
    expect(create).not.toHaveBeenCalled();
  });
});
