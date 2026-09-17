/**
 * Question feedback (2026-09-17): encrypted pending taps → opaque recompute
 * blob → cleared after consumption. The real envelope encrypts.
 */
import { beforeEach, describe, expect, it } from "vitest";

const { vault } = await import("../src/vault");
const { recordFeedbackTap, buildFeedbackBlob, clearFeedback } = await import("../src/questionFeedback");
const envelope = await import("../src/crypto/envelope");

const DATA_KEY = Buffer.alloc(32, 5);
const USER = "user-1";

beforeEach(async () => {
  const storage = (await import("./helpers/storageMock")).default;
  storage.__reset();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: DATA_KEY }, USER);
});

describe("questionFeedback", () => {
  it("round-trips taps through the encrypted store into the server blob shape", async () => {
    await recordFeedbackTap(DATA_KEY, USER, "temporal:work", true);
    await recordFeedbackTap(DATA_KEY, USER, "link:family", false);
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).toBeTruthy();
    const plain = envelope.decrypt(
      DATA_KEY,
      Buffer.from(blob!, "base64"),
      envelope.buildAad("feedback", USER),
    );
    const parsed = JSON.parse(plain.toString("utf8"));
    expect(parsed.feedback).toEqual([
      { pid: "temporal:work", resonated: true },
      { pid: "link:family", resonated: false },
    ]);
  });

  it("no pending taps yield no blob (recompute body stays empty)", async () => {
    expect(await buildFeedbackBlob(DATA_KEY, USER)).toBeNull();
  });

  it("clearFeedback empties the queue", async () => {
    await recordFeedbackTap(DATA_KEY, USER, "temporal:work", true);
    await clearFeedback(USER);
    expect(await buildFeedbackBlob(DATA_KEY, USER)).toBeNull();
  });

  it("a wrong key degrades to empty (disposable metadata, never a lockout)", async () => {
    await recordFeedbackTap(DATA_KEY, USER, "temporal:work", true);
    const other = Buffer.alloc(32, 9);
    expect(await buildFeedbackBlob(other, USER)).toBeNull();
  });
});
