/**
 * Frontend mutation campaign 2026-09-22 — survivor pins (mobile).
 *
 * Fresh full-tree Stryker run (15,990 mutants, 83.86% raw — see
 * redteam/mutation_campaign_2026-09-22_frontend/REPORT.md). These pins kill
 * the genuine survivors in the safety- and contract-critical logic modules:
 * the crisis matcher's entire normalization surface (homoglyph and leet
 * folding tables, mark folding, script boundaries, token joining), the
 * measure registry's scoring/validation contracts, the entry-version
 * monotonicity mirror, and the password-rotation stage/reason mapping.
 * Screen-level presentation survivors are documented in the report.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";

import {
  detectCrisisLanguage,
  matchVariants,
  matchesCrisisSuppress,
  normalizeCrisisText,
} from "../src/crisisDetect";
import {
  INSTRUMENTS,
  MEASURE_IDS,
  maxScoreForMeasure,
  measureComplete,
  measurePayload,
  measureScore,
  safetyItemEndorsed,
} from "../src/measures";
import {
  forgetAllEntryVersions,
  knownEntryVersion,
  observeEntryVersions,
  resetEntryVersionMirrors,
} from "../src/entryVersions";
import storage from "./helpers/storageMock";

// ---------------------------------------------------------------------------
// crisisDetect — the normalization contract, table by table
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: crisis normalization", () => {
  it("folds every homoglyph entry in the Latin-lookalike table", () => {
    // [lookalike, expected ASCII fold]. з folds to "3" first, then the leet
    // pass (digit between letters) carries it to "e".
    const table: Array<[string, string]> = [
      ["\u0430", "a"], ["\u0441", "c"], ["\u0441", "c"], ["\u0435", "e"], ["\u043e", "o"],
      ["\u0440", "p"], ["\u0445", "x"], ["\u0443", "y"], ["\u0456", "i"], ["\u0455", "s"],
      ["\u0458", "j"], ["\u04bb", "h"], ["\u0501", "d"], ["\u0261", "g"], ["\u051b", "q"],
      ["\u051d", "w"], ["\u0475", "v"], ["\u0437", "e"], ["\u043a", "k"], ["\u043c", "m"],
      ["\u0131", "i"], ["\u03bf", "o"], ["\u03b1", "a"], ["\u03b5", "e"], ["\u03b9", "i"],
      ["\u03ba", "k"], ["\u03c1", "p"], ["\u03c4", "t"], ["\u03c5", "u"], ["\u03bd", "v"],
      ["\u03bc", "m"], ["\u03b7", "n"], ["\u03c9", "w"], ["\u03c2", "s"], ["\u03c3", "s"],
      ["\u03f2", "c"],
    ];
    for (const [lookalike, expected] of table) {
      expect(normalizeCrisisText(`z${lookalike}z`), `U+${lookalike.codePointAt(0)!.toString(16)}`).toBe(`z${expected}z`);
    }
    // The point of the table: a disguised crisis phrase still fires.
    expect(detectCrisisLanguage("ѕuicide")).toBe(true); // Cyrillic ѕ
    expect(detectCrisisLanguage("кіll myself")).toBe(true); // Cyrillic к + і
  });

  it("folds every leet mapping in all three positions, and only those", () => {
    const leet: Record<string, string> = {
      "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "!": "i", "$": "s",
    };
    for (const [digit, letter] of Object.entries(leet)) {
      expect(normalizeCrisisText(`k${digit}ll`), `middle ${digit}`).toBe(`k${letter}ll`);
      expect(normalizeCrisisText(`${digit}uicide`), `leading ${digit}`).toBe(`${letter}uicide`);
      expect(normalizeCrisisText(`suicid${digit}`), `trailing ${digit}`).toBe(`suicid${letter}`);
    }
    // Multi-digit trailing runs and the fixed-point loop ("su1c1de" needs
    // two passes).
    expect(normalizeCrisisText("su1c1de")).toBe("suicide");
    expect(normalizeCrisisText("d13")).toBe("die");
    // Ambiguous digits stay digits: 2/6/9 are deliberately unmapped, and a
    // standalone "2" folds to "to" only at the token level.
    expect(normalizeCrisisText("grade6test")).toBe("grade6test");
    expect(normalizeCrisisText("i want 2 die")).toBe("i want to die");
  });

  it("folds Latin combining marks only off Latin bases", () => {
    expect(normalizeCrisisText("suicidé")).toBe("suicide");
    expect(normalizeCrisisText("café")).toBe("cafe");
    expect(normalizeCrisisText("dyịng")).toBe("dying");
    // A Devanagari base is NOT stripped of its marks (non-Latin patterns
    // must keep their shape).
    expect(normalizeCrisisText("विचार")).toBe("विचार");
  });

  it("separates script boundaries and normalizes the curly apostrophe", () => {
    expect(normalizeCrisisText("suicide\u092e")).toBe("suicide \u092e");
    expect(normalizeCrisisText("\u092esuicide")).toBe("\u092e suicide");
    expect(normalizeCrisisText("don\u2019t")).toBe("don't");
    expect(detectCrisisLanguage("i can\u2019t go on")).toBe(true);
  });

  it("punctuation becomes spaces and tokens collapse", () => {
    expect(normalizeCrisisText("kill,myself")).toBe("kill myself");
    expect(normalizeCrisisText("kill-myself")).toBe("kill myself");
    expect(normalizeCrisisText("kill  myself")).toBe("kill myself");
    expect(normalizeCrisisText("s.u.i.c.i.d.e")).toBe("suicide");
  });

  it("single-letter runs join at exactly four, ASCII a..z only", () => {
    expect(normalizeCrisisText("s u i c i d e")).toBe("suicide");
    expect(normalizeCrisisText("a b c d")).toBe("abcd"); // the exact join threshold
    expect(normalizeCrisisText("u s a won gold")).toBe("u s a won gold"); // 3 stays prose
    expect(normalizeCrisisText("a b c z")).toBe("abcz"); // both endpoints count
    expect(normalizeCrisisText("s u i c i d \u4e2d e")).toBe("suicid \u4e2d e"); // CJK breaks the run
  });

  it("both tiers are case-insensitive; the suppress tier is strictly wider", () => {
    expect(detectCrisisLanguage("I WANT TO KILL MYSELF")).toBe(true);
    expect(detectCrisisLanguage("Suicide")).toBe(true);
    // A suppress-extra-only phrase: "cutting" fires the suppress tier but
    // stays below the dialog tier.
    expect(matchesCrisisSuppress("the cutting stopped last week")).toBe(true);
    expect(detectCrisisLanguage("the cutting stopped last week")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// crisisDetect — round 2: the deeper pipeline and tier arms
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22 round 2: crisis pipeline arms", () => {
  it("the leet trail regex folds multi-digit runs and punctuation-edge digits", () => {
    expect(normalizeCrisisText("grad13x")).toBe("gradiex"); // loop folds digit runs letter-adjacent on both sides
    expect(normalizeCrisisText("suicid3.")).toBe("suicide"); // lookahead accepts any non-letter (not just end)
    expect(normalizeCrisisText("suicid3 my")).toBe("suicide my");
  });

  it("empty tokens never reach the join (consecutive separators collapse)", () => {
    expect(normalizeCrisisText("kill -- myself")).toBe("kill myself");
    expect(normalizeCrisisText("kill\n\t myself")).toBe("kill myself");
  });

  it("non-ASCII single characters are never joinable single letters", () => {
    expect(normalizeCrisisText("\u4e2d \u4e2d \u4e2d \u4e2d")).toBe("\u4e2d \u4e2d \u4e2d \u4e2d");
  });

  it("Greek accents and Hangul never fold through the Latin-mark path", () => {
    expect(normalizeCrisisText("\u03ac")).toBe("\u03ac"); // Greek ά carries its mark
    expect(normalizeCrisisText("\uac00")).toBe("\uac00"); // composed Hangul
  });

  it("orphanGlue: 1-3 runs glue forward, >=4 runs join standalone, trailing runs too", () => {
    expect(matchVariants("k ill myself")[1]).toBe("kill myself");
    expect(matchVariants("k i ll myself")[1]).toBe("kill myself");
    expect(matchVariants("a b c d end")[1]).toBe("abcd end");
    expect(matchVariants("k y s")[1]).toBe("kys");
  });

  it("benign compounds mask hyphenated forms, every occurrence, and stay benign when letter-doubled", () => {
    expect(detectCrisisLanguage("suicide-silence")).toBe(false); // the hyphenated band name
    expect(matchesCrisisSuppress("suicide-silence")).toBe(false);
    expect(detectCrisisLanguage("suicide squad suicide squad")).toBe(false); // global mask
    expect(detectCrisisLanguage("suiciide squad")).toBe(false); // masked in the folded channel too
    expect(detectCrisisLanguage("\u81ea\u6740\u9884\u9632")).toBe(false); // CJK compound masks (non-\b path)
  });

  it("masking separates with a space, never deletes — neighbors keep their boundaries", () => {
    // If the mask DELETED instead, "cutting [mask] board" would glue to
    // "cuttingboard" and the anchored concat twin would go quiet.
    expect(matchesCrisisSuppress("cutting suicide squad board")).toBe(true);
  });

  it("the folded channel catches letter-doubling the canonical tiers cannot", () => {
    expect(matchesCrisisSuppress("cuttting myself")).toBe(true);
    expect(detectCrisisLanguage("kiill myself")).toBe(true);
    expect(detectCrisisLanguage("suiccide")).toBe(true);
  });

  it("the primary/orphan channel is load-bearing: concat twins cannot fire on it", () => {
    // "off myself" matches only the space-aware pattern — the concat twin
    // "of(?:ing)?myself" cannot match "offmyself".
    expect(detectCrisisLanguage("off myself")).toBe(true);
    expect(detectCrisisLanguage("k ill myself")).toBe(true); // orphan variant channel
  });
});

// ---------------------------------------------------------------------------
// measures — the scoring and validation contracts
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: measure registry", () => {
  it("carries the exact instrument structure", () => {
    expect(MEASURE_IDS).toEqual(["phq9", "gad7", "phq2"]);
    expect(INSTRUMENTS.phq9).toMatchObject({ id: "phq9", items: 9, maxScore: 27, safetyItemIndex: 8 });
    expect(INSTRUMENTS.gad7).toMatchObject({ id: "gad7", items: 7, maxScore: 21 });
    expect(INSTRUMENTS.phq2).toMatchObject({ id: "phq2", items: 2, maxScore: 6 });
    expect(maxScoreForMeasure("phq9")).toBe(27);
    expect(maxScoreForMeasure("gad7")).toBe(21);
    expect(maxScoreForMeasure("phq2")).toBe(6);
    expect(maxScoreForMeasure("future9")).toBeNull();
    expect(maxScoreForMeasure(9)).toBeNull();
  });

  it("scores exactly the instrument's items, clamped and capped", () => {
    expect(measureScore("phq9", Array(9).fill(3))).toBe(27);
    expect(measureScore("phq9", Array(9).fill(0))).toBe(0);
    expect(measureScore("phq9", Array(9).fill(null))).toBe(0); // unanswered = 0
    expect(measureScore("phq9", Array(9).fill(2))).toBe(18);
    // Out-of-scale values clamp to the 0-3 option range, never contaminate.
    expect(measureScore("phq2", [9, -4])).toBe(3);
    expect(measureScore("phq2", [3, 3])).toBe(6);
    // Longer response arrays score only the first `items` entries.
    expect(measureScore("phq2", [3, 3, 3, 3])).toBe(6);
    expect(measureScore("gad7", Array(7).fill(1))).toBe(7);
  });

  it("completion requires every item answered, exactly", () => {
    expect(measureComplete("phq9", Array(9).fill(0))).toBe(true);
    expect(measureComplete("phq9", Array(8).fill(0))).toBe(false);
    expect(measureComplete("phq9", Array(10).fill(0))).toBe(false);
    expect(measureComplete("phq9", [...Array(8).fill(0), null])).toBe(false);
    expect(measureComplete("phq2", [0, 0])).toBe(true);
    expect(measureComplete("phq2", [1, null])).toBe(false);
  });

  it("the safety item fires on any endorsement above zero", () => {
    const responses = Array<number | null>(9).fill(0);
    expect(safetyItemEndorsed("phq9", responses)).toBe(false);
    responses[8] = 1;
    expect(safetyItemEndorsed("phq9", responses)).toBe(true);
    responses[8] = 0;
    expect(safetyItemEndorsed("phq9", responses)).toBe(false);
    responses[8] = null;
    expect(safetyItemEndorsed("phq9", responses)).toBe(false);
    // Instruments without a safety item never endorse.
    expect(safetyItemEndorsed("gad7", Array(7).fill(3))).toBe(false);
    expect(safetyItemEndorsed("phq2", [3, 3])).toBe(false);
  });

  it("the payload carries the portal's exact contract shape", () => {
    const payload = JSON.parse(measurePayload("phq2", [2, 1], "2026-09-22"));
    expect(payload).toEqual({ v: 1, measure: "phq2", score: 3, completed_at: "2026-09-22" });
  });
});

// ---------------------------------------------------------------------------
// entryVersions — the monotonicity mirror
// ---------------------------------------------------------------------------

describe("mutation pins 2026-09-22: entry version mirror", () => {
  const key = Buffer.alloc(32, 7);
  const rows = (spec: Array<[string, number]>) =>
    spec.map(([clientEntryId, contentVersion]) => ({ clientEntryId, contentVersion }));

  beforeEach(() => {
    resetEntryVersionMirrors();
    storage.__reset();
  });

  it("ignores malformed rows and advances monotonically", async () => {
    const first = await observeEntryVersions("u1", key, rows([["e1", 2], ["e2", 3]]));
    expect(first).toEqual({ rolledBack: [], advanced: true });
    expect(await knownEntryVersion("u1", key, "e1")).toBe(2);

    // A lower version is a rollback, never a regression of the mirror.
    const second = await observeEntryVersions("u1", key, rows([["e1", 1]]));
    expect(second).toEqual({ rolledBack: ["e1"], advanced: false });
    expect(await knownEntryVersion("u1", key, "e1")).toBe(2);

    // Malformed rows (non-integer, sub-1) are skipped entirely.
    const third = await observeEntryVersions("u1", key, rows([["e2", 0], ["e1", 1.5], ["e3", 4]]));
    expect(third.rolledBack).toEqual([]);
    expect(await knownEntryVersion("u1", key, "e2")).toBe(3);
    expect(await knownEntryVersion("u1", key, "e3")).toBe(4);

    expect(await knownEntryVersion("u1", key, "never-seen")).toBeNull();
  });

  it("forgetAll drops every mark for the user", async () => {
    await observeEntryVersions("u1", key, rows([["e1", 5]]));
    await forgetAllEntryVersions("u1");
    expect(await knownEntryVersion("u1", key, "e1")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// rotation — stage and reason mapping
// ---------------------------------------------------------------------------

vi.mock("../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/api/client")>();
  return {
    ...actual,
    api: {
      getCachedSalt: vi.fn(async () => "U0FMVFNLQVM="),
      saltFor: vi.fn(async () => ({ salt: "U0FMVFNLQVM=" })),
      cacheSalt: vi.fn(async () => undefined),
      openProcessingSession: vi.fn(async (keyB64: string) => ({ session_token: `tok-${keyB64.slice(0, 4)}` })),
      rekeyStoredData: vi.fn(async () => ({ entries: 3, insights: 1, measures: 2 })),
      listEntriesPage: vi.fn(async () => ({ entries: [] })),
      listConsents: vi.fn(async () => []),
      rewrapConsent: vi.fn(async () => undefined),
      rotateCredential: vi.fn(async () => undefined),
      login: vi.fn(async () => ({ token: "fresh", user_id: "uid-1" })),
      setSession: vi.fn(async () => undefined),
    },
  };
});

vi.mock("../src/reauth", () => ({
  verifyPasswordForVault: vi.fn(),
}));
vi.mock("../src/crypto/MindPatternCrypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/crypto/MindPatternCrypto")>();
  return {
    ...actual,
    decryptEntry: vi.fn(),
    deriveKeysAsync: vi.fn(async (password: string) => ({
      authKey: Buffer.alloc(32, 1),
      dataKey: Buffer.alloc(32, password.length),
    })),
  };
});
vi.mock("../src/crypto/sharing", () => ({
  wrapDataKeyForTherapist: vi.fn(() => ({ ephemeralPubB64: "e", wrappedKeyB64: "w" })),
}));
vi.mock("../src/questionFeedback", () => ({ clearFeedback: vi.fn(async () => undefined) }));
vi.mock("../src/unlockProof", () => ({ clearUnlockProof: vi.fn(async () => undefined) }));
vi.mock("../src/vault", () => ({ vault: { lock: vi.fn() } }));
vi.mock("../src/biometricUnlock", () => ({ disableBiometricUnlock: vi.fn(async () => undefined) }));

const { api, ApiError } = await import("../src/api/client");
const mockedApi = vi.mocked(api);
const mockedReauth = vi.mocked((await import("../src/reauth")).verifyPasswordForVault);
const mockedCrypto = vi.mocked(await import("../src/crypto/MindPatternCrypto"));
const { rotatePassword } = await import("../src/rotation");

describe("mutation pins 2026-09-22: password rotation stages", () => {
  const input = { username: "alice", userId: "uid-1", oldPassword: "old-password-x", newPassword: "new-password-y" };

  beforeEach(() => {
    // clearAllMocks only clears call history; implementations set by earlier
    // tests survive it. Reset and re-default every seam this suite overrides.
    vi.clearAllMocks();
    mockedApi.getCachedSalt.mockReset().mockResolvedValue("U0FMVFNLQVM=");
    mockedApi.saltFor.mockReset().mockResolvedValue({ salt: "U0FMVFNLQVM=" });
    mockedApi.cacheSalt.mockReset().mockResolvedValue(undefined);
    mockedApi.openProcessingSession.mockReset().mockImplementation(async (keyB64: string) => ({ session_token: `tok-${keyB64.slice(0, 4)}` }));
    mockedApi.rekeyStoredData.mockReset().mockResolvedValue({ entries: 3, insights: 1, measures: 2 });
    mockedApi.listEntriesPage.mockReset().mockResolvedValue({ entries: [] });
    mockedApi.listConsents.mockReset().mockResolvedValue([]);
    mockedApi.rewrapConsent.mockReset().mockResolvedValue(undefined);
    mockedApi.rotateCredential.mockReset().mockResolvedValue(undefined);
    mockedApi.login.mockReset().mockResolvedValue({ token: "fresh", user_id: "uid-1" });
    mockedApi.setSession.mockReset().mockResolvedValue(undefined);
    mockedReauth.mockReset().mockResolvedValue({ ok: true, verifierB64: "VkVSSUZJRVI=", salt: "U0FMVFNLQVM=" } as never);
    mockedCrypto.deriveKeysAsync.mockReset().mockImplementation(async (password: string) => ({
      authKey: Buffer.alloc(32, 1),
      dataKey: Buffer.alloc(32, password.length),
    }));
    mockedCrypto.decryptEntry.mockReset();
    resetEntryVersionMirrors();
    storage.__reset();
  });

  it("a wrong old password fails at the verify stage with the honest reason", async () => {
    mockedReauth.mockResolvedValue({ ok: false, reason: "wrong-password" } as never);
    await expect(rotatePassword(input)).resolves.toEqual({ ok: false, stage: "verify", reason: "wrong-password" });
    expect(mockedApi.rekeyStoredData).not.toHaveBeenCalled();
  });

  it("an offline re-auth maps to the offline reason, never wrong-password", async () => {
    mockedReauth.mockResolvedValue({ ok: false, reason: "offline" } as never);
    await expect(rotatePassword(input)).resolves.toEqual({ ok: false, stage: "verify", reason: "offline" });
  });

  it("a salt that cannot be fetched fails closed at verify/offline", async () => {
    mockedApi.getCachedSalt.mockResolvedValue(null);
    mockedApi.saltFor.mockRejectedValue(new Error("network down"));
    await expect(rotatePassword(input)).resolves.toEqual({ ok: false, stage: "verify", reason: "offline" });
  });

  it("rekey_key_mismatch with a readable journal finishes the rotation", async () => {
    mockedApi.rekeyStoredData.mockRejectedValue(Object.assign(
      new ApiError(409, "already rekeyed"), { code: "rekey_key_mismatch" }));
    mockedCrypto.decryptEntry.mockImplementation(() => Buffer.from("ok"));
    mockedApi.listEntriesPage.mockResolvedValue({
      entries: [{ clientEntryId: "e1", blob: "blob", contentVersion: 1 }],
    } as never);
    const outcome = await rotatePassword(input);
    expect(outcome).toMatchObject({ ok: true, counts: { entries: 0, insights: 0, measures: 0 }, rewrapped: 0 });
    expect(mockedApi.rotateCredential).toHaveBeenCalledTimes(1); // finished the ladder
  });

  it("rekey_key_mismatch with an unreadable journal reports already-rotated-unverifiable", async () => {
    mockedApi.rekeyStoredData.mockRejectedValue(Object.assign(
      new ApiError(409, "already rekeyed"), { code: "rekey_key_mismatch" }));
    mockedCrypto.decryptEntry.mockImplementation(() => { throw new Error("not under this key"); });
    mockedApi.listEntriesPage.mockResolvedValue({
      entries: [{ clientEntryId: "e1", blob: "blob", contentVersion: 1 }],
    } as never);
    const outcome = await rotatePassword(input);
    expect(outcome).toMatchObject({
      ok: false, stage: "rekey", reason: "already-rotated-unverifiable",
      detail: expect.stringContaining("rotated to a different new password"),
    });
    expect(mockedApi.rotateCredential).not.toHaveBeenCalled();
  });

  it("a 403 from the rekey step maps to wrong-password; other API errors to server", async () => {
    mockedApi.rekeyStoredData.mockRejectedValue(new ApiError(403, "verifier rejected"));
    await expect(rotatePassword(input)).resolves.toMatchObject({ ok: false, stage: "rekey", reason: "wrong-password" });
    mockedApi.rekeyStoredData.mockRejectedValue(new ApiError(500, "boom"));
    await expect(rotatePassword(input)).resolves.toMatchObject({ ok: false, stage: "rekey", reason: "server" });
    mockedApi.rekeyStoredData.mockRejectedValue(new Error("offline"));
    await expect(rotatePassword(input)).resolves.toMatchObject({ ok: false, stage: "rekey", reason: "offline" });
  });

  it("a failed credential rotation locks the vault and reports the stage", async () => {
    const { vault } = await import("../src/vault");
    mockedApi.rotateCredential.mockRejectedValue(new ApiError(503, "busy"));
    await expect(rotatePassword(input)).resolves.toMatchObject({ ok: false, stage: "credential", reason: "server" });
    expect(vault.lock).toHaveBeenCalled();
  });

  it("a happy rotation rewraps every active consent and skips the inactive/keyless", async () => {
    mockedApi.listConsents.mockResolvedValue([
      { id: "c1", status: "active", therapist_wrap_pub_key: "PUB", therapist_id: "t1", display_name: "Dr. One", username: "dr1" },
      { id: "c2", status: "revoked", therapist_wrap_pub_key: "PUB", therapist_id: "t2", display_name: "Dr. Two", username: "dr2" },
      { id: "c3", status: "active", therapist_wrap_pub_key: null, therapist_id: "t3", display_name: "Dr. Three", username: "dr3" },
      { id: "c4", status: "active", therapist_wrap_pub_key: "PUB", therapist_id: "t4", display_name: "", username: "dr4" },
    ] as never);
    mockedApi.rewrapConsent.mockRejectedValue(new Error("one grant failed"));
    const outcome = await rotatePassword(input);
    expect(outcome).toMatchObject({ ok: true, rewrapped: 0 });
    if (outcome.ok) {
      expect(outcome.rewrapFailures).toEqual(["Dr. One", "dr4"]); // c2/c3 never attempted
    }
    expect(mockedApi.rewrapConsent).toHaveBeenCalledTimes(2);
  });
});
