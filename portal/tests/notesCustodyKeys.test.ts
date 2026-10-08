import { expect, it } from "vitest";
import { createNotesKeyring, decrypt, decryptNoteAny, encrypt, encryptNote, fromBase64, includeNotesCustodyKey, openNotesKeyring, sealNotesKeyring, toBase64, wipeNotesKeyring, type NotesKeyring } from "../src/crypto";
const kek = new Uint8Array(32).fill(5);
const key = (value: number) => new Uint8Array(32).fill(value);
const owner = "therapist-custody";
const aad = new TextEncoder().encode(JSON.stringify(["portal-notes-keyring", owner, "v1"]));
it("preserves authenticated stored notes and reports exhausted custody without altering their encrypted record", async () => {
  const sealed = await encryptNote(key(3), owner, "patient-custody", "note-custody", "Preserved clinical note");
  await expect(decryptNoteAny(key(1), key(2), owner, "patient-custody", "note-custody", sealed.blobB64)).rejects.toMatchObject({
    message: "This note could not be authenticated with the account's notes custody. It was not changed.",
  });
  await expect(decryptNoteAny(key(1), key(2), owner, "patient-custody", "note-custody", sealed.blobB64, [key(3)])).resolves.toBe("Preserved clinical note");
});
async function sealRaw(row: unknown) {
  return toBase64(await encrypt(kek, new TextEncoder().encode(JSON.stringify(row)), aad));
}

it("creates fresh active custody while independently retaining both existing note keys", () => {
  const legacy = key(7), identity = key(9);
  const ring = createNotesKeyring(legacy, identity), second = createNotesKeyring(legacy, identity);
  expect(ring.active).toHaveLength(32);
  expect(ring.active).not.toEqual(new Uint8Array(32));
  expect(ring.active).not.toEqual(second.active);
  expect(ring.historical).toEqual([legacy, identity]);
  expect(ring.historical[0]).not.toBe(legacy);
  expect(ring.historical[1]).not.toBe(identity);
  wipeNotesKeyring(ring);
  expect(ring.active).toEqual(new Uint8Array(32));
  expect(ring.historical).toEqual([new Uint8Array(32), new Uint8Array(32)]);
  expect(legacy).toEqual(key(7));
  expect(identity).toEqual(key(9));
  expect(() => { wipeNotesKeyring(null); wipeNotesKeyring(undefined); }).not.toThrow();
});

it("deduplicates active and historical keys and copies each newly retained custody key", () => {
  const ring: NotesKeyring = { active: key(1), historical: [key(2)] };
  includeNotesCustodyKey(ring, key(1));
  includeNotesCustodyKey(ring, key(2));
  expect(ring.historical).toEqual([key(2)]);
  const fresh = key(3);
  includeNotesCustodyKey(ring, fresh);
  expect(ring.historical).toEqual([key(2), key(3)]);
  fresh.fill(0);
  expect(ring.historical[1]).toEqual(key(3));
  expect(() => includeNotesCustodyKey(ring, new Uint8Array(31))).toThrow("verified key retirement");
  expect(ring.historical).toEqual([key(2), key(3)]);
  const nearActive = key(1); nearActive[31] = 9;
  const nearHistorical = key(2); nearHistorical[31] = 9;
  includeNotesCustodyKey(ring, nearActive);
  includeNotesCustodyKey(ring, nearHistorical);
  expect(ring.historical).toEqual([key(2), key(3), nearActive, nearHistorical]);
  const malformedNearActive = new Uint8Array(33).fill(1);
  expect(() => includeNotesCustodyKey(ring, malformedNearActive)).toThrow("verified key retirement");
});

it("preserves the full 512-key custody boundary and requires retirement before another rotation", async () => {
  const historical = Array.from({ length: 512 }, () => key(2));
  const ring = { active: key(1), historical };
  const blob = await sealNotesKeyring(kek, owner, ring);
  await expect(openNotesKeyring(kek, owner, blob)).resolves.toEqual(ring);
  const plain = await decrypt(kek, fromBase64(blob), aad);
  expect(JSON.parse(new TextDecoder().decode(plain))).toEqual({ v: 1, active: toBase64(key(1)), historical: historical.map(toBase64) });
  expect(() => includeNotesCustodyKey(ring, key(3))).toThrow("verified key retirement");
  expect(ring.historical).toHaveLength(512);
  // A known key remains usable at capacity without consuming another slot.
  expect(() => includeNotesCustodyKey(ring, key(2))).not.toThrow();
  await expect(sealNotesKeyring(kek, owner, { ...ring, historical: [...historical, key(3)] })).rejects.toThrow("Invalid notes custody");
  await expect(openNotesKeyring(kek, "other-therapist", blob)).rejects.toThrow();
});

it("allows an empty historical keyring and accepts the last available retained-key slot", async () => {
  const ring = { active: key(1), historical: [] as Uint8Array<ArrayBuffer>[] };
  await expect(openNotesKeyring(kek, owner, await sealNotesKeyring(kek, owner, ring))).resolves.toEqual(ring);
  const last = { active: key(1), historical: Array.from({ length: 511 }, () => key(2)) };
  includeNotesCustodyKey(last, key(3));
  expect(last.historical).toHaveLength(512);
  expect(last.historical[511]).toEqual(key(3));
});

it.each([
  null, 42, [], {}, { v: 2, active: toBase64(key(1)), historical: [] },
  { v: 1, active: 42, historical: [] }, { v: 1, active: toBase64(key(1)), historical: {} },
  { v: 1, active: toBase64(new Uint8Array(31)), historical: [] },
  { v: 1, active: toBase64(key(1)).slice(0, -1), historical: [] },
  { v: 1, active: toBase64(key(1)), historical: [42] },
  { v: 1, active: toBase64(key(1)), historical: [toBase64(new Uint8Array(31))] },
  { v: 1, active: toBase64(key(1)), historical: Array(513).fill(toBase64(key(2))) },
].map((row, index) => ({ row, index, message: index < 2 ? "Invalid notes custody." : [7, 8, 9, 10].includes(index) ? "Invalid notes custody key." : "Unsupported notes custody." })))("rejects authenticated malformed custody schema $index", async ({ row, message }) => {
  await expect(openNotesKeyring(kek, owner, await sealRaw(row))).rejects.toMatchObject({ message });
});

it("refuses malformed keys before serializing a custody keyring", async () => {
  await expect(sealNotesKeyring(kek, owner, { active: new Uint8Array(31), historical: [] })).rejects.toThrow("Invalid notes custody");
  await expect(sealNotesKeyring(kek, owner, { active: key(1), historical: [new Uint8Array(31)] })).rejects.toThrow("Invalid notes custody");
  await expect(openNotesKeyring(kek, owner, await sealRaw({ v: 1, active: toBase64(key(1)), historical: [{}] }))).rejects.toMatchObject({ message: "Invalid notes custody key." });
});
