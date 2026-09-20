/**
 * Question feedback (2026-09-17): encrypted pending taps → opaque recompute
 * blob → cleared after consumption. The real envelope encrypts.
 */
import { beforeEach, describe, expect, it } from "vitest";

const { vault } = await import("../src/vault");
const { recordFeedbackTap, recordPatternMute, buildFeedbackBlob, clearFeedback } = await import("../src/questionFeedback");
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

describe("pattern mutes riding the feedback channel (2026-09-19)", () => {
  it("partitions mutes and unmutes into their own blob lists", async () => {
    await recordFeedbackTap(DATA_KEY, USER, "temporal:work", true);
    await recordPatternMute(DATA_KEY, USER, "topic:guitar", true);
    await recordPatternMute(DATA_KEY, USER, "topic:taxes", true);
    await recordPatternMute(DATA_KEY, USER, "topic:guitar", false);
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).toBeTruthy();
    const plain = envelope.decrypt(
      DATA_KEY,
      Buffer.from(blob!, "base64"),
      envelope.buildAad("feedback", USER),
    );
    const parsed = JSON.parse(plain.toString("utf8"));
    expect(parsed.feedback).toEqual([{ pid: "temporal:work", resonated: true }]);
    // Last write wins per pid: guitar was muted then unmuted.
    expect(parsed.muted).toEqual(["topic:taxes"]);
    expect(parsed.unmuted).toEqual(["topic:guitar"]);
  });

  it("a mute-only queue still ships a blob", async () => {
    await recordPatternMute(DATA_KEY, USER, "rumination:abc123", true);
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).toBeTruthy();
    const plain = envelope.decrypt(
      DATA_KEY,
      Buffer.from(blob!, "base64"),
      envelope.buildAad("feedback", USER),
    );
    const parsed = JSON.parse(plain.toString("utf8"));
    expect(parsed.feedback).toEqual([]);
    expect(parsed.muted).toEqual(["rumination:abc123"]);
  });

  it("clearFeedback empties mute events with the taps", async () => {
    await recordPatternMute(DATA_KEY, USER, "topic:guitar", true);
    await clearFeedback(USER);
    expect(await buildFeedbackBlob(DATA_KEY, USER)).toBeNull();
  });
});

describe("M-35: serialized appends (same-frame taps cannot lose events)", () => {
  it("two events issued in the same tick with a gated first read BOTH persist", async () => {
    const storage = (await import("./helpers/storageMock")).default;
    const originalGetItem = storage.getItem.bind(storage);
    let gated = true;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    (storage as { getItem: typeof storage.getItem }).getItem = async (k: string) => {
      if (gated) {
        gated = false;
        await gate;
      }
      return originalGetItem(k);
    };
    try {
      const tap = recordFeedbackTap(DATA_KEY, USER, "temporal:work", true);
      const mute = recordPatternMute(DATA_KEY, USER, "topic:guitar", true);
      await Promise.resolve(); // the first append's gated read is in flight
      release();
      await Promise.all([tap, mute]);
    } finally {
      (storage as { getItem: typeof storage.getItem }).getItem = originalGetItem;
    }
    const blob = await buildFeedbackBlob(DATA_KEY, USER);
    expect(blob).toBeTruthy();
    const plain = envelope.decrypt(
      DATA_KEY,
      Buffer.from(blob!, "base64"),
      envelope.buildAad("feedback", USER),
    );
    const parsed = JSON.parse(plain.toString("utf8"));
    // Without the mutex, the second append read the same (empty) pending
    // list and the last write dropped the first event.
    expect(parsed.feedback).toEqual([{ pid: "temporal:work", resonated: true }]);
    expect(parsed.muted).toEqual(["topic:guitar"]);
  });
});
