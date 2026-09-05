/**
 * C1: the sealed unlock proof. Offline unlock must VERIFY the password —
 * the seal only opens under the correct data key.
 */
import { beforeEach, describe, expect, it } from "vitest";
import storage from "./helpers/storageMock";
import { storeUnlockProof, verifyUnlockProof, clearUnlockProof, unlockProofExists } from "../src/unlockProof";
import { buildAad, encrypt } from "../src/crypto/envelope";

const dataKey = Buffer.alloc(32, 7);
const wrongKey = Buffer.alloc(32, 8);

beforeEach(() => {
  storage.__reset();
});

describe("unlockProof", () => {
  it("round-trips: a stored proof verifies under the same data key", async () => {
    expect(await verifyUnlockProof(dataKey, "u1")).toBe("absent");
    await storeUnlockProof(dataKey, "u1");
    expect(await unlockProofExists("u1")).toBe(true);
    expect(await verifyUnlockProof(dataKey, "u1")).toBe("ok");
  });

  it("a wrong data key fails the AEAD authentication — never 'ok'", async () => {
    await storeUnlockProof(dataKey, "u1");
    expect(await verifyUnlockProof(wrongKey, "u1")).toBe("wrong");
  });

  it("proofs are account-scoped and clearable", async () => {
    await storeUnlockProof(dataKey, "u1");
    expect(await verifyUnlockProof(dataKey, "u2")).toBe("absent");
    await clearUnlockProof("u1");
    expect(await verifyUnlockProof(dataKey, "u1")).toBe("absent");
  });

  it("stores ciphertext, not a plaintext marker (tamper = wrong, not ok)", async () => {
    await storeUnlockProof(dataKey, "u1");
    const raw = await storage.getItem("@mindpattern/unlockproof_u1");
    expect(raw).not.toContain("mindpattern-unlock-proof");
    // A tampered blob must fail authentication, never verify.
    const tampered = encrypt(wrongKey, Buffer.from("x"), buildAad("unlockproof", "u1")).toString("base64");
    await storage.setItem("@mindpattern/unlockproof_u1", tampered);
    expect(await verifyUnlockProof(dataKey, "u1")).toBe("wrong");
  });

  it("corrupt base64 reads as wrong, not a crash", async () => {
    await storage.setItem("@mindpattern/unlockproof_u1", "!!!not base64!!!");
    expect(await verifyUnlockProof(dataKey, "u1")).toBe("wrong");
  });
});
