/** Direct React Activity host with controlled native storage; not a device-navigation test. */
import { beforeEach, expect, it, vi } from "vitest";
import React from "react";

vi.mock("../../src/api/client", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/api/client")>();
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ...actual, ApiError, api: makeApiMock() };
});
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity: () => {}, unlockDays: 30 }) };
});

const { api } = await import("../../src/api/client");
const { QuestionScreen } = await import("../../src/screens/QuestionScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { textOf, touchableByLabel } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");
const storage = (await import("../helpers/storageMock")).default;
const dataKey = Buffer.alloc(32, 5);
const FOR_DATE = "2026-09-03";
const questionBlob = (question: string, forDate: string, patternPid: string): string =>
  encrypt(dataKey, Buffer.from(JSON.stringify({ for_date: forDate, question, pattern_pid: patternPid })), buildAad("question", "user-1", forDate)).toString("base64");

beforeEach(async () => {
  const { __setLocaleForTests } = await import("../../src/strings"); __setLocaleForTests("en");
  resetApi(api as never);
  storage.__reset();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey: Buffer.from(dataKey) }, "user-1");
});

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
const responseText = "What repeats?";
const feedbackKey = "@mindpattern/question_feedback.user-1";
const failureCopyText = "Your answer stays on this device; it could not be saved just now.";
const uncertainCopyText = "Your answer may have been saved. To avoid a duplicate, it cannot be sent again right now.";

type GateKind = "read" | "write" | "writeThenReject" | "rejectDispatchedWrite";
async function activityFixture(kind: GateKind = "read") {
  const { Activity } = await import("react");
  const { default: RTR, act } = await import("react-test-renderer");
  const feedbackModule = await import("../../src/questionFeedback");
  const realRecord = feedbackModule.beginFeedbackTap;
  const records: Array<{settled: Promise<"resolved" | "rejected">}> = [];
  const record = vi.spyOn(feedbackModule, "beginFeedbackTap").mockImplementation((...args) => {
    const attempt = realRecord(...args);
    records.push({settled: attempt.result.then(() => "resolved" as const, () => "rejected" as const)});
    return attempt;
  });
  vi.mocked(api.insights).mockResolvedValue({ phase: "insight", active_days: 31, days_remaining: 0 } as never);
  vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob(responseText, FOR_DATE, "pid-1") } as never);
  let release!: () => void, reject!: (reason: Error) => void, entered!: () => void;
  const blocked = new Promise<void>((resolve, fail) => { release = resolve; reject = fail; });
  const started = new Promise<void>(resolve => { entered = resolve; });
  const get0 = storage.getItem.bind(storage), set0 = storage.setItem.bind(storage);
  let held = false;
  const get = vi.spyOn(storage, "getItem").mockImplementation(async (key) => {
    if (kind === "read" && key === feedbackKey && !held) { held = true; entered(); await blocked; }
    return get0(key);
  });
  const set = vi.spyOn(storage, "setItem").mockImplementation(async (key, value) => {
    if (key === feedbackKey && !held && (kind === "writeThenReject" || kind === "rejectDispatchedWrite")) {
      held = true;
      if (kind === "writeThenReject") await set0(key, value);
      entered(); await blocked;
      throw new Error("native write acknowledgment unavailable");
    }
    if (kind === "write" && key === feedbackKey && !held) { held = true; entered(); await blocked; }
    return set0(key, value);
  });
  const nav = { navigate: vi.fn() };
  const view = (mode: "visible" | "hidden") => <Activity mode={mode}><QuestionScreen navigation={nav} /></Activity>;
  let root!: ReturnType<typeof RTR.create>;
  const settle = async () => { for (let n = 0; n < 4; n++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); };
  await act(async () => { root = RTR.create(view("visible")); });
  await settle(); expect(textOf(root)).toContain(responseText);
  return {
    root, records, started, release, reject,
    settle,
    async press(label: string) { await act(async () => { touchableByLabel(root, label).props.onPress(); }); },
    async setMode(mode: "visible" | "hidden") { await act(async () => root.update(view(mode))); await settle(); },
    async finishRecord(index: number) { let result!: "resolved" | "rejected"; await act(async () => { result = await records[index]!.settled; }); await settle(); return result; },
    async cleanup() { release(); await Promise.allSettled(records.map(row => row.settled)); await settle(); get.mockRestore(); set.mockRestore(); record.mockRestore(); await act(async () => root.unmount()); },
  };
}

it("restores feedback retry when its rejected save settles after Activity reappears", async () => {
  const h = await activityFixture();
  try {
    await h.press("This resonated"); await h.started;
    await h.setMode("hidden"); await h.setMode("visible");
    expect(textOf(h.root)).toContain(responseText); h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(await storage.getItem(feedbackKey)).toBeNull();
    expect(textOf(h.root)).toContain("This resonated");
    expect(textOf(h.root)).toContain(failureCopyText);
    await h.press("This resonated"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(await storage.getItem(feedbackKey)).not.toBeNull();
  } finally { await h.cleanup(); }
}, 10000);

it("restores feedback retry when its rejected save settles while Activity is hidden", async () => {
  const h = await activityFixture();
  try {
    await h.press("This resonated"); await h.started;
    await h.setMode("hidden"); h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    await h.setMode("visible");
    expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).toContain("This resonated");
    expect(await storage.getItem(feedbackKey)).toBeNull();
    await h.press("Not me"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(await storage.getItem(feedbackKey)).not.toBeNull();
  } finally { await h.cleanup(); }
}, 10000);

it("does not restore old feedback or show its failure on a successor question", async () => {
  const h = await activityFixture();
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("A newer question?", FOR_DATE, "pid-2") } as never);
    await h.setMode("visible"); expect(textOf(h.root)).toContain("A newer question?");
    await h.press("Not me"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(textOf(h.root)).not.toContain(failureCopyText); expect(textOf(h.root)).not.toContain("Not me");
    const { decrypt } = await import("../../src/crypto/envelope");
    const stored = (await storage.getItem(feedbackKey))!;
    const plain = decrypt(dataKey, Buffer.from(stored, "base64"), buildAad("feedback-local", "user-1"));
    expect(JSON.parse(plain.toString("utf8"))).toMatchObject([{pid: "pid-2", resonated: false}]);
  } finally { await h.cleanup(); }
}, 10000);

it("does not reopen feedback when the in-flight committed save succeeds after reappearance", async () => {
  const h = await activityFixture("write");
  try {
    await h.press("This resonated"); await h.started;
    await h.setMode("hidden"); await h.setMode("visible"); h.release();
    expect(await h.finishRecord(0)).toBe("resolved");
    expect(await storage.getItem(feedbackKey)).not.toBeNull();
    expect(textOf(h.root)).not.toContain("This resonated"); expect(textOf(h.root)).not.toContain(failureCopyText);
  } finally { await h.cleanup(); }
}, 10000);

it("does not publish an old account feedback failure into a successor account", async () => {
  const h = await activityFixture();
  const nextKey = Buffer.alloc(32, 88), nextOwner = "user-2";
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    const nextBlob = encrypt(nextKey, Buffer.from(JSON.stringify({ for_date: FOR_DATE, question: "Next account question?", pattern_pid: "pid-b" })), buildAad("question", nextOwner, FOR_DATE)).toString("base64");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: Buffer.from(nextKey) }, nextOwner);
    vi.mocked(api.getUserId).mockResolvedValue(nextOwner);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: nextBlob } as never);
    await h.setMode("visible"); expect(textOf(h.root)).toContain("Next account question?");
    await h.press("Not me"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(textOf(h.root)).not.toContain(failureCopyText); expect(textOf(h.root)).not.toContain("Not me");
    const raw = await storage.getItem("@mindpattern/question_feedback.user-2"); expect(raw).not.toBeNull();
    const { decrypt } = await import("../../src/crypto/envelope");
    const decoded = decrypt(nextKey, Buffer.from(raw!, "base64"), buildAad("feedback-local", nextOwner));
    expect(JSON.parse(decoded.toString("utf8"))).toMatchObject([{pid: "pid-b", resonated: false}]);
    expect(await storage.getItem(feedbackKey)).toBeNull();
  } finally { await h.cleanup(); nextKey.fill(0); }
}, 10000);

it("keeps the normal visible feedback failure and retry behavior", async () => {
  const h = await activityFixture();
  try {
    await h.press("This resonated"); await h.started; h.reject(new Error("storage unavailable"));
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain(failureCopyText); expect(textOf(h.root)).toContain("This resonated");
    await h.press("Not me"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(await storage.getItem(feedbackKey)).not.toBeNull();
  } finally { await h.cleanup(); }
}, 10000);

it("drops a hidden deferred failure before a successor account becomes visible", async () => {
  const h = await activityFixture();
  const nextKey = Buffer.alloc(32, 89), nextOwner = "user-2";
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    const blob = encrypt(nextKey, Buffer.from(JSON.stringify({ for_date: FOR_DATE, question: "Next account question?", pattern_pid: "pid-b" })), buildAad("question", nextOwner, FOR_DATE)).toString("base64");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: Buffer.from(nextKey) }, nextOwner);
    vi.mocked(api.getUserId).mockResolvedValue(nextOwner);
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob } as never);
    await h.setMode("visible");
    expect(textOf(h.root)).toContain("Next account question?"); expect(textOf(h.root)).not.toContain(failureCopyText);
    await h.press("Not me"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(await storage.getItem("@mindpattern/question_feedback.user-2")).not.toBeNull();
    expect(await storage.getItem(feedbackKey)).toBeNull();
  } finally { await h.cleanup(); nextKey.fill(0); }
}, 10000);

it.each(["writeThenReject", "rejectDispatchedWrite"] as const)("does not reopen an ambiguous dispatched feedback write: %s", async (kind) => {
  const h = await activityFixture(kind);
  try {
    await h.press("This resonated"); await h.started;
    await h.setMode("hidden"); await h.setMode("visible"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).not.toContain("This resonated");
    expect(textOf(h.root)).not.toContain(failureCopyText);
    expect(textOf(h.root)).toContain(uncertainCopyText);
    const raw = await storage.getItem(feedbackKey);
    if (kind === "writeThenReject") {
      expect(raw).not.toBeNull();
      const { decrypt } = await import("../../src/crypto/envelope");
      const plain = decrypt(dataKey, Buffer.from(raw!, "base64"), buildAad("feedback-local", "user-1"));
      const events = JSON.parse(plain.toString("utf8"));
      expect(events).toMatchObject([{pid: "pid-1", resonated: true}]); expect(events).toHaveLength(1);
    } else expect(raw).toBeNull();
  } finally { await h.cleanup(); }
}, 10000);

it("drops a deferred failure after the same account installs a replacement key generation", async () => {
  const h = await activityFixture();
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(dataKey) }, "user-1");
    await h.setMode("visible");
    expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).not.toContain(failureCopyText);
    expect(textOf(h.root)).toContain("This resonated");
    expect(await storage.getItem(feedbackKey)).toBeNull();
  } finally { await h.cleanup(); }
}, 10000);

it("marks write dispatch only immediately before the native storage call", async () => {
  const { beginFeedbackTap } = await import("../../src/questionFeedback");
  const read = vi.spyOn(storage, "getItem").mockRejectedValueOnce(new Error("read failed"));
  try {
    const noWrite = beginFeedbackTap(vault.get().dataKey, "user-1", "pid-1", true, () => true);
    await expect(noWrite.result).rejects.toThrow("read failed");
    expect(noWrite.status.dispatched).toBe(false);
    let dispatchedWrite!: ReturnType<typeof beginFeedbackTap>;
    const write = vi.spyOn(storage, "setItem").mockImplementationOnce(async () => {
      expect(dispatchedWrite.status.dispatched).toBe(true);
      throw new Error("write acknowledgment failed");
    });
    try {
      dispatchedWrite = beginFeedbackTap(vault.get().dataKey, "user-1", "pid-1", true, () => true);
      await expect(dispatchedWrite.result).rejects.toThrow("write acknowledgment failed");
      expect(dispatchedWrite.status.dispatched).toBe(true);
    } finally { write.mockRestore(); }
  } finally { read.mockRestore(); }
});

it("changes the opaque vault generation on key replacement and lock, but not auth-key adoption", () => {
  const first = vault.dataKeyGeneration();
  vault.adoptAuthKey(Buffer.alloc(32, 14)); expect(vault.dataKeyGeneration()).toBe(first);
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(dataKey) }, "user-1");
  const replacement = vault.dataKeyGeneration(); expect(replacement).not.toBe(first);
  vault.lock(); expect(vault.dataKeyGeneration()).not.toBe(replacement);
});

it("keeps the visible answer latched with honest uncertainty after write-then-reject", async () => {
  const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain(uncertainCopyText); expect(textOf(h.root)).not.toContain("This resonated");
    const raw = (await storage.getItem(feedbackKey))!;
    const { decrypt } = await import("../../src/crypto/envelope");
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", "user-1"));
    expect(JSON.parse(plain.toString("utf8"))).toHaveLength(1);
  } finally { await h.cleanup(); }
}, 10000);

it("shows the uncertain result in Spanish without reopening retry", async () => {
  const { __setLocaleForTests, t } = await import("../../src/strings"); __setLocaleForTests("es");
  const h = await activityFixture("writeThenReject");
  try {
    await h.press(t("question.resonated")); await h.started; h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain("Es posible que se haya guardado su respuesta. Para evitar duplicados, no puede volver a enviarla ahora.");
    expect(textOf(h.root)).not.toContain(t("question.resonated"));
  } finally { await h.cleanup(); __setLocaleForTests("en"); }
}, 10000);

it("does not carry a hidden old-account latch into an identical successor question", async () => {
  const h = await activityFixture();
  const nextOwner = "user-2", nextKey = Buffer.alloc(32, 90);
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    const blob = encrypt(nextKey, Buffer.from(JSON.stringify({ for_date: FOR_DATE, question: responseText, pattern_pid: "pid-1" })), buildAad("question", nextOwner, FOR_DATE)).toString("base64");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: Buffer.from(nextKey) }, nextOwner);
    vi.mocked(api.getUserId).mockResolvedValue(nextOwner); vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob } as never);
    await h.setMode("visible"); expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).toContain("This resonated");
    await h.press("Not me"); h.release(); expect(await h.finishRecord(0)).toBe("rejected"); expect(await h.finishRecord(1)).toBe("resolved");
    expect(textOf(h.root)).not.toContain(failureCopyText); expect(textOf(h.root)).not.toContain(uncertainCopyText);
    expect(await storage.getItem(feedbackKey)).toBeNull(); expect(await storage.getItem("@mindpattern/question_feedback.user-2")).not.toBeNull();
  } finally { await h.cleanup(); nextKey.fill(0); }
}, 10000);

it("keeps a dispatched same-account tap latched across a hidden vault replacement", async () => {
  const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(dataKey) }, "user-1");
    await h.setMode("visible"); expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).not.toContain("This resonated");
    h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).not.toContain("This resonated"); expect(textOf(h.root)).toContain(uncertainCopyText);
    const raw = (await storage.getItem(feedbackKey))!; const { decrypt } = await import("../../src/crypto/envelope");
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", "user-1"));
    expect(JSON.parse(plain.toString("utf8"))).toHaveLength(1);
  } finally { await h.cleanup(); }
}, 10000);

it("releases a same-account replacement latch only after the old pre-write attempt fails", async () => {
  const h = await activityFixture();
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(dataKey) }, "user-1");
    await h.setMode("visible"); expect(textOf(h.root)).not.toContain("This resonated");
    h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain("This resonated"); expect(textOf(h.root)).not.toContain(failureCopyText);
    expect(await storage.getItem(feedbackKey)).toBeNull();
  } finally { await h.cleanup(); }
}, 10000);

it("shows uncertain feedback after a dispatched rejection settles while hidden", async () => {
  const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    await h.setMode("visible");
    expect(textOf(h.root)).toContain(uncertainCopyText); expect(textOf(h.root)).not.toContain("This resonated");
  } finally { await h.cleanup(); }
}, 10000);

it("does not transfer a hidden uncertain notice to a new account", async () => {
  const h = await activityFixture("writeThenReject");
  const nextOwner = "user-2", nextKey = Buffer.alloc(32, 91);
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden"); h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    const blob = encrypt(nextKey, Buffer.from(JSON.stringify({ for_date: FOR_DATE, question: responseText, pattern_pid: "pid-1" })), buildAad("question", nextOwner, FOR_DATE)).toString("base64");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 9), dataKey: Buffer.from(nextKey) }, nextOwner);
    vi.mocked(api.getUserId).mockResolvedValue(nextOwner); vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob } as never);
    await h.setMode("visible");
    expect(textOf(h.root)).toContain("This resonated"); expect(textOf(h.root)).not.toContain(uncertainCopyText);
  } finally { await h.cleanup(); nextKey.fill(0); }
}, 10000);

it("keeps an ambiguous answer latched after an actual same-account encrypted queue rekey", async () => {
  const { __resetLocalKeyLifecycleForTests, assertLocalWritesAllowed } = await import("../../src/localWriteGuard");
  const { prepareLocalRekey, markLocalRekeyPhase, resumeLocalRekey } = await import("../../src/localRekey");
  const { setSecureStoreBackend } = await import("../../src/secureStore");
  const { runTestControl } = await import("../helpers/testControl");
  runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(setSecureStoreBackend, null);
  const h = await activityFixture("writeThenReject");
  const nextKey = Buffer.alloc(32, 92);
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    const before = (await storage.getItem(feedbackKey))!;
    let prepared = false;
    const preparing = prepareLocalRekey("user-1", dataKey, nextKey).then(() => { prepared = true; });
    void preparing.catch(() => {});
    await vi.waitFor(() => expect(() => assertLocalWritesAllowed("user-1")).toThrow());
    expect(prepared).toBe(false); h.release();
    expect(await h.finishRecord(0)).toBe("rejected"); await preparing;
    await markLocalRekeyPhase("user-1", "credential");
    await resumeLocalRekey("user-1", nextKey);
    const after = (await storage.getItem(feedbackKey))!; expect(after).not.toBe(before);
    const { decrypt } = await import("../../src/crypto/envelope");
    const plain = decrypt(nextKey, Buffer.from(after, "base64"), buildAad("feedback-local", "user-1"));
    expect(JSON.parse(plain.toString("utf8"))).toMatchObject([{pid: "pid-1", resonated: true}]);
    expect(JSON.parse(plain.toString("utf8"))).toHaveLength(1);
    const blob = encrypt(nextKey, Buffer.from(JSON.stringify({ for_date: FOR_DATE, question: responseText, pattern_pid: "pid-1" })), buildAad("question", "user-1", FOR_DATE)).toString("base64");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(nextKey) }, "user-1");
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob } as never);
    await h.setMode("visible"); expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).not.toContain("This resonated"); expect(textOf(h.root)).toContain(uncertainCopyText);
  } finally { await h.cleanup(); nextKey.fill(0); runTestControl(__resetLocalKeyLifecycleForTests); runTestControl(setSecureStoreBackend, null); }
}, 20000);

it("keeps an uncertain answer latched when recompute returns the same question", async () => {
  const { ApiError } = await import("../../src/api/client");
  const { decrypt } = await import("../../src/crypto/envelope");
  const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    vi.mocked(api.questionToday).mockRejectedValueOnce(new ApiError(404, "no stored question"));
    await h.press("Refresh"); await h.settle(); expect(api.recompute).toHaveBeenCalledTimes(1);
    const sent = vi.mocked(api.recompute).mock.calls[0]![1]; expect(typeof sent).toBe("string");
    const plain = decrypt(dataKey, Buffer.from(sent as string, "base64"), buildAad("feedback", "user-1", new Date().toISOString().slice(0, 10)));
    expect(JSON.parse(plain.toString("utf8")).feedback).toMatchObject([{pid: "pid-1", resonated: true}]);
    expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).toContain(uncertainCopyText);
    expect(textOf(h.root)).not.toContain("This resonated");
  } finally { await h.cleanup(); }
}, 10000);

it("allows a new answer when recompute returns a different question after uncertainty", async () => {
  const { ApiError } = await import("../../src/api/client"); const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    vi.mocked(api.questionToday).mockRejectedValueOnce(new ApiError(404, "no stored question")).mockResolvedValueOnce({ for_date: FOR_DATE, blob: questionBlob("A different question?", FOR_DATE, "pid-2") } as never);
    await h.press("Refresh"); await h.settle();
    expect(textOf(h.root)).toContain("A different question?"); expect(textOf(h.root)).toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);
  } finally { await h.cleanup(); }
}, 10000);

it("preserves the ordinary fresh-question reset after an acknowledged feedback save", async () => {
  const { ApiError } = await import("../../src/api/client"); const h = await activityFixture("write");
  try {
    await h.press("This resonated"); await h.started; h.release(); expect(await h.finishRecord(0)).toBe("resolved");
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    vi.mocked(api.questionToday).mockRejectedValueOnce(new ApiError(404, "no stored question"));
    await h.press("Refresh"); await h.settle();
    expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);
  } finally { await h.cleanup(); }
}, 10000);

it("keeps an in-flight dispatched answer latched through same-question recompute", async () => {
  const { ApiError } = await import("../../src/api/client"); const h = await activityFixture("write");
  try {
    await h.press("This resonated"); await h.started;
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    vi.mocked(api.questionToday).mockRejectedValueOnce(new ApiError(404, "no stored question"));
    await h.press("Refresh"); await h.settle(); expect(api.recompute).toHaveBeenCalledTimes(1);
    expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).not.toContain("This resonated");
    h.release(); expect(await h.finishRecord(0)).toBe("resolved");
    expect(textOf(h.root)).not.toContain("This resonated");
  } finally { await h.cleanup(); }
}, 10000);

it("does not transfer an uncertain old answer to a different reloaded question", async () => {
  const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; await h.setMode("hidden");
    vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 2), dataKey: Buffer.from(dataKey) }, "user-1");
    vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("A different question?", FOR_DATE, "pid-2") } as never);
    await h.setMode("visible"); h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain("A different question?"); expect(textOf(h.root)).toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);
  } finally { await h.cleanup(); }
}, 10000);

it("allows a new answer for the same text and pid on a different server date", async () => {
  const { ApiError } = await import("../../src/api/client"); const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    const nextDate = "2026-09-04";
    vi.mocked(api.questionToday).mockRejectedValueOnce(new ApiError(404, "no stored question")).mockResolvedValueOnce({ for_date: nextDate, blob: questionBlob(responseText, nextDate, "pid-1") } as never);
    await h.press("Refresh"); await h.settle();
    expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);
  } finally { await h.cleanup(); }
}, 10000);

it("does not reopen an uncertain same-content answer when the returned date is empty", async () => {
  const { ApiError } = await import("../../src/api/client"); const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; h.release(); expect(await h.finishRecord(0)).toBe("rejected");
    await storage.setItem("@mindpattern/keyship_consent_user-1", "1");
    vi.mocked(api.questionToday).mockRejectedValueOnce(new ApiError(404, "no stored question")).mockResolvedValueOnce({ for_date: "", blob: questionBlob(responseText, "", "pid-1") } as never);
    await h.press("Refresh"); await h.settle();
    expect(textOf(h.root)).toContain(responseText); expect(textOf(h.root)).not.toContain("This resonated");
  } finally { await h.cleanup(); }
}, 10000);


it("reloads after Activity reappears while an older phase request is pending", async () => {
  const { Activity } = await import("react");
  const { default: RTR, act } = await import("react-test-renderer");
  let release!: (value: any) => void;
  const held = new Promise<any>(resolve => { release = resolve; });
  const requests: Promise<any>[] = [];
  vi.mocked(api.insights).mockImplementation(() => {
    const promise = requests.length === 0 ? held : Promise.resolve({ phase: "insight", active_days: 31, days_remaining: 0 });
    requests.push(promise);
    return promise as never;
  });
  vi.mocked(api.questionToday).mockResolvedValue({ for_date: FOR_DATE, blob: questionBlob("Current question?", FOR_DATE, "current-pid") } as never);
  const view = (mode: "visible" | "hidden") => <Activity mode={mode}><QuestionScreen navigation={{ navigate: vi.fn() }} /></Activity>;
  const settle = async () => { for (let n = 0; n < 4; n++) await act(async () => { await new Promise(resolve => setTimeout(resolve, 0)); }); };
  let root!: ReturnType<typeof RTR.create>;
  await act(async () => { root = RTR.create(view("visible")); });
  try {
    expect(requests).toHaveLength(1);
    await act(async () => { root.update(view("hidden")); });
    await act(async () => { root.update(view("visible")); });
    await settle();
    expect(requests).toHaveLength(2);
    expect(textOf(root)).toContain("Current question?");
    await act(async () => { release({ phase: "baseline", active_days: 1, days_remaining: 29 }); await Promise.allSettled(requests); });
    await settle();
    expect(textOf(root)).toContain("Current question?");
  } finally {
    release({ phase: "baseline", active_days: 1, days_remaining: 29 });
    await act(async () => { await Promise.allSettled(requests); });
    await settle();
    await act(async () => { root.unmount(); });
  }
}, 10000);


it("a stored next-day question with unchanged text permits one new feedback answer without recomputation", async () => {
  const h = await activityFixture("writeThenReject");
  try {
    await h.press("This resonated"); await h.started; h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain(uncertainCopyText);
    expect(textOf(h.root)).not.toContain("This resonated");

    const nextDate = "2026-09-04";
    vi.mocked(api.questionToday).mockResolvedValue({
      for_date: nextDate, blob: questionBlob(responseText, nextDate, "pid-1"),
    } as never);
    await h.press("Refresh"); await h.settle();
    expect(api.recompute).not.toHaveBeenCalled();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);

    await h.press("Not me");
    expect(await h.finishRecord(1)).toBe("resolved");
    const { decrypt } = await import("../../src/crypto/envelope");
    const raw = (await storage.getItem(feedbackKey))!;
    const plain = decrypt(dataKey, Buffer.from(raw, "base64"), buildAad("feedback-local", "user-1"));
    const events = JSON.parse(plain.toString("utf8"));
    expect(events).toHaveLength(2);
    expect(events).toMatchObject([{ pid: "pid-1", resonated: true }, { pid: "pid-1", resonated: false }]);
    expect(textOf(h.root)).not.toContain("This resonated");
  } finally { await h.cleanup(); }
}, 10000);


it("an uncertain undated question stays latched when a later stored response supplies a date", async () => {
  const h = await activityFixture("writeThenReject");
  try {
    // An undated stored question does not prove which day its answer belongs to.
    vi.mocked(api.questionToday).mockResolvedValue({
      for_date: "", blob: questionBlob(responseText, "", "pid-1"),
    } as never);
    await h.press("Refresh"); await h.settle();
    await h.press("This resonated"); await h.started; h.release();
    expect(await h.finishRecord(0)).toBe("rejected");
    expect(textOf(h.root)).toContain(uncertainCopyText);
    expect(textOf(h.root)).not.toContain("This resonated");
    const retained = await storage.getItem(feedbackKey);

    const dated = "2026-09-04";
    vi.mocked(api.questionToday).mockResolvedValue({
      for_date: dated, blob: questionBlob(responseText, dated, "pid-1"),
    } as never);
    await h.press("Refresh"); await h.settle();
    expect(api.questionToday).toHaveBeenCalledTimes(3);
    expect(api.recompute).not.toHaveBeenCalled();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).not.toContain("This resonated");
    expect(await storage.getItem(feedbackKey)).toBe(retained);
    const { decrypt } = await import("../../src/crypto/envelope");
    const plain = decrypt(dataKey, Buffer.from(retained!, "base64"), buildAad("feedback-local", "user-1"));
    const events = JSON.parse(plain.toString("utf8"));
    expect(events).toHaveLength(1);
    expect(events).toMatchObject([{ pid: "pid-1", resonated: true }]);
  } finally { await h.cleanup(); }
}, 10000);


it("an acknowledged feedback write stays certain after Activity reappears and the stored question refreshes", async () => {
  const h = await activityFixture("write");
  try {
    await h.press("This resonated"); await h.started;
    await h.setMode("hidden"); await h.setMode("visible");
    h.release(); expect(await h.finishRecord(0)).toBe("resolved");
    expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).not.toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);
    const retained = await storage.getItem(feedbackKey);
    expect(retained).not.toBeNull();

    await h.press("Refresh"); await h.settle();
    expect(api.recompute).not.toHaveBeenCalled();
    expect(api.openProcessingSession).not.toHaveBeenCalled();
    expect(textOf(h.root)).toContain(responseText);
    expect(textOf(h.root)).not.toContain("This resonated");
    expect(textOf(h.root)).not.toContain(uncertainCopyText);
    expect(await storage.getItem(feedbackKey)).toBe(retained);
    const { decrypt } = await import("../../src/crypto/envelope");
    const plain = decrypt(dataKey, Buffer.from(retained!, "base64"), buildAad("feedback-local", "user-1"));
    const events = JSON.parse(plain.toString("utf8"));
    expect(events).toHaveLength(1);
    expect(events).toMatchObject([{ pid: "pid-1", resonated: true }]);
  } finally { await h.cleanup(); }
}, 10000);
