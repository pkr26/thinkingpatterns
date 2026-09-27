/**
 * The MBC measures module (2026-09-19): PHQ-9 scoring/safety semantics,
 * the crypto envelope (patient-side encrypt → server → decrypt), and the
 * Measures screen flow (record, history render, item-9 support pointer,
 * offline honesty). Real envelope crypto throughout.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { Alert } from "react-native";

vi.mock("../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("./helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

const touchActivity = vi.fn();
vi.mock("../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../src/store")>();
  return { ...actual, useSession: () => ({ touchActivity }) };
});

const { api, ApiError } = await import("../src/api/client");
const { MeasuresScreen } = await import("../src/screens/MeasuresScreen");
const { vault } = await import("../src/vault");
const { buildAad, decrypt, encrypt } = await import("../src/crypto/envelope");
const {
  PHQ9_ITEMS,
  phq9Score,
  phq9Complete,
  phq9Item9Endorsed,
  phq9Payload,
} = await import("../src/phq9");
const { render, flush, textOf, pressLabel, touchableByLabel, act } = await import("./helpers/rtr");
const { resetApi } = await import("./helpers/apiMock");
const storage = (await import("./helpers/storageMock")).default;

const dataKey = Buffer.alloc(32, 7);
const USER = "user-1";

function measureRow(id: string, score: number, date: string): { client_measure_id: string; blob: string; measure_date: string } {
  const blob = encrypt(
    dataKey,
    Buffer.from(JSON.stringify({ v: 1, measure: "phq9", score, completed_at: date }), "utf8"),
    buildAad("measure", USER, id),
  ).toString("base64");
  return { client_measure_id: id, blob, measure_date: date };
}

beforeEach(() => {
  resetApi(api as never);
  Alert.alert.mockClear();
  touchActivity.mockClear();
  storage.__reset();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey }, USER);
  vi.mocked(api.listMeasures).mockReset();
  vi.mocked(api.listMeasures).mockResolvedValue([] as never);
  vi.mocked(api.createMeasure).mockReset();
  vi.mocked(api.createMeasure).mockResolvedValue({} as never);
});


/** Fire onPress on the option with a given accessibilityLabel (the option
 *  labels live on the touchable, not the text). */
async function pressOption(root: Awaited<ReturnType<typeof render>>, label: string): Promise<void> {
  const { TouchableOpacity } = await import("react-native");
  const node = root.root.findAllByType(TouchableOpacity).find((n) => n.props.accessibilityLabel === label);
  if (!node) throw new Error(`no touchable with a11y label ${JSON.stringify(label)}`);
  await act(async () => {
    void node.props.onPress?.();
  });
}

describe("PHQ-9 semantics", () => {
  it("scores the standard sum, clamped to the instrument range", () => {
    expect(phq9Score(PHQ9_ITEMS.map(() => null))).toBe(0);
    expect(phq9Score(PHQ9_ITEMS.map(() => 3))).toBe(27);
    expect(phq9Score([1, 2, 3, 0, 1, 2, 0, 0, 1])).toBe(10);
  });
  it("completion requires every item; item 9 endorsement is detected", () => {
    const partial = PHQ9_ITEMS.map(() => 0) as Array<number | null>;
    partial[8] = null;
    expect(phq9Complete(partial)).toBe(false);
    expect(phq9Complete(PHQ9_ITEMS.map(() => 0))).toBe(true);
    expect(phq9Item9Endorsed(PHQ9_ITEMS.map(() => 0))).toBe(false);
    expect(phq9Item9Endorsed([0, 0, 0, 0, 0, 0, 0, 0, 1])).toBe(true);
  });
  it("the payload contract matches the portal's parser", () => {
    const payload = JSON.parse(phq9Payload([1, 1, 1, 1, 1, 1, 1, 1, 1], "2026-09-19"));
    // 2026-09-27 clinical contract: the RAW item-9 response rides next to
    // the score (an endorsed item 9 mandates follow-up regardless of the
    // total), and the key ORDER is the wire contract.
    expect(payload).toEqual({ v: 1, measure: "phq9", score: 9, item9: 1, completed_at: "2026-09-19" });
    expect(Object.keys(payload)).toEqual(["v", "measure", "score", "item9", "completed_at"]);
    // The item-9 field is the raw pick, clamped to the 0–3 scale, never
    // reinterpreted; a low total with an endorsed item 9 stays endorsive.
    const split = JSON.parse(phq9Payload([0, 0, 0, 0, 0, 0, 0, 0, 2], "2026-09-27"));
    expect(split).toEqual({ v: 1, measure: "phq9", score: 2, item9: 2, completed_at: "2026-09-27" });
    const clamped = JSON.parse(phq9Payload([3, 3, 3, 3, 3, 3, 3, 3, 99], "2026-09-27"));
    expect(clamped.item9).toBe(3);
    // An unanswered item 9 (the scorer's leniency path) omits the field —
    // payloads without item9 remain valid on every reader.
    expect(JSON.parse(phq9Payload([0, 0, 0, 0, 0, 0, 0, 0, null], "2026-09-27"))).toEqual({
      v: 1, measure: "phq9", score: 0, completed_at: "2026-09-27",
    });
  });
});

describe("MeasuresScreen", () => {
  it("renders decrypted history from the patient's own key", async () => {
    vi.mocked(api.listMeasures).mockResolvedValue([
      measureRow("m-2", 9, "2026-09-18"),
      measureRow("m-1", 14, "2026-09-11"),
    ] as never);
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(textOf(root)).toContain("Your recorded scores");
    // 2026-09-26 audit LOW: the history line maps instrument ids through the
    // measures.select.* labels and formats dates locale-aware — no raw
    // "phq9 2026-09-18: 9" implementation vocabulary.
    expect(textOf(root)).toContain("PHQ-9 (depression, 9 items) Friday, September 18, 2026: 9");
    expect(textOf(root)).toContain("September 11, 2026: 14");
    expect(textOf(root)).not.toContain("2026-09-18: 9");
    expect(textOf(root)).toContain("never interprets it");
  });

  it("an unreadable row degrades to a skipped entry, never a crash", async () => {
    vi.mocked(api.listMeasures).mockResolvedValue([
      { client_measure_id: "m-x", blob: "AAAA", measure_date: "2026-09-18" },
      measureRow("m-1", 5, "2026-09-11"),
    ] as never);
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(textOf(root)).toContain("September 11, 2026: 5");
    expect(textOf(root)).not.toContain("2026-09-18");
  });

  it("records a completed questionnaire as an encrypted server blob", async () => {
    const nav = { navigate: vi.fn(), goBack: vi.fn() };
    const root = await render(<MeasuresScreen navigation={nav} />);
    await flush();
    // Submit is disabled until every item has a pick.
    expect(touchableByLabel(root, "Record this check-in").props.disabled).toBe(true);
    // Answer all nine items: zeros except item 3 = 2.
    for (let i = 0; i < PHQ9_ITEMS.length; i++) {
      const label = `Question ${i + 1}: ${i === 3 ? "More than half the days" : "Not at all"}`;
      await pressOption(root, label);
    }
    expect(touchableByLabel(root, "Record this check-in").props.disabled).toBe(false);
    await pressLabel(root, "Record this check-in");
    await flush();
    expect(api.createMeasure).toHaveBeenCalledTimes(1);
    const [clientId, blobB64, date] = vi.mocked(api.createMeasure).mock.calls[0] as unknown as [
      string, string, string,
    ];
    expect(clientId.startsWith("m-")).toBe(true);
    const plain = decrypt(dataKey, Buffer.from(blobB64, "base64"), buildAad("measure", USER, clientId));
    expect(JSON.parse(plain.toString("utf8"))).toEqual({
      v: 1, measure: "phq9", score: 2, item9: 0, completed_at: date,
    });
    // Item 9 was NOT endorsed: no support dialog.
    expect(Alert.alert).not.toHaveBeenCalled();
  });

  it("item 9 endorsement points at support only AFTER the save lands", async () => {
    vi.mocked(api.createMeasure).mockRejectedValueOnce(new ApiError(0, "offline"));
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    for (let i = 0; i < PHQ9_ITEMS.length; i++) {
      const label = `Question ${i + 1}: ${i === 8 ? "Several days" : "Not at all"}`;
      await pressOption(root, label);
    }
    await pressLabel(root, "Record this check-in");
    await flush();
    // 2026-09-26 audit LOW: an offline failure is a quiet INLINE status now
    // (never a modal), the picks stay selected and the Record button stays
    // enabled — that is the retry affordance until connectivity returns.
    expect(Alert.alert).not.toHaveBeenCalledWith("Not recorded", expect.anything());
    expect(textOf(root)).toContain("Recording needs a connection right now. Your picks are still on screen.");
    expect(touchableByLabel(root, "Record this check-in").props.disabled).toBe(false);
    // The picks really are still there (item 9 still selected for retry).
    expect(Alert.alert).not.toHaveBeenCalledWith("Support is available", expect.anything());

    // Retry succeeds: now the calm support pointer fires.
    await pressLabel(root, "Record this check-in");
    await flush();
    expect(Alert.alert).toHaveBeenCalledWith(
      "Support is available",
      expect.stringContaining("you do not have to carry it alone"),
      expect.anything(),
    );
  });

  it("a duplicate id (409) is treated as recorded, not an error", async () => {
    vi.mocked(api.createMeasure).mockRejectedValueOnce(
      Object.assign(new ApiError(409, "conflict"), { code: "conflict" }),
    );
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    for (let i = 0; i < PHQ9_ITEMS.length; i++) {
      await pressOption(root, `Question ${i + 1}: Not at all`);
    }
    await pressLabel(root, "Record this check-in");
    await flush();
    expect(textOf(root)).toContain("Already recorded");
    expect(Alert.alert).not.toHaveBeenCalledWith("Not recorded", expect.anything());
  });

  it("offline history load says so honestly", async () => {
    vi.mocked(api.listMeasures).mockRejectedValue(new ApiError(0, "offline"));
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(textOf(root)).toContain("needs a connection");
  });

  // M-16 regression (2026-09-20): the whole screen — including the PHQ-9
  // item and option labels, the most safety-adjacent string class — used
  // to be hardcoded English; everything resolves through t() now.
  it("renders the questionnaire in Spanish under the es locale (M-16)", async () => {
    const { __setLocaleForTests } = await import("../src/strings");
    __setLocaleForTests("es");
    try {
      const nav = { navigate: vi.fn(), goBack: vi.fn() };
      const root = await render(<MeasuresScreen navigation={nav} />);
      await flush();
      const text = textOf(root);
      // The stem and the standard Spanish PHQ-9 wording.
      expect(text).toContain("Durante las últimas 2 semanas, ¿con qué frecuencia le han molestado los siguientes problemas?");
      expect(text).toContain("1. Poco interés o placer en hacer las cosas");
      expect(text).toContain("9. Pensar que estaría mejor muerto/a o en lastimarse de alguna manera");
      // The safety-item note rides along, localized.
      expect(text).toContain("pregunta de seguridad");
      // Option labels resolve per locale — the submit gate keys off them.
      expect(text).toContain("Para nada");
      expect(text).toContain("Casi todos los días");
      expect(text).toContain("Registrar este registro");
      // English is gone.
      expect(text).not.toContain("Over the last 2 weeks");
      expect(text).not.toContain("Not at all");
      // The crisis dialog copy is Spanish too (safety class).
      for (let i = 0; i < PHQ9_ITEMS.length; i++) {
        await pressOption(root, `Pregunta ${i + 1}: ${i === 8 ? "Varios días" : "Para nada"}`);
      }
      await pressLabel(root, "Registrar este registro");
      await flush();
      expect(Alert.alert).toHaveBeenCalledWith(
        "Hay apoyo disponible",
        expect.stringContaining("no tiene que cargarlo en soledad"),
        expect.anything(),
      );
      expect(nav.navigate).not.toHaveBeenCalledWith("Crisis"); // dismissible, not auto
    } finally {
      __setLocaleForTests("en");
    }
  });

  it("P3: the multi-instrument registry — GAD-7 and PHQ-2 semantics", async () => {
    const {
      INSTRUMENTS,
      measureScore,
      measureComplete,
      measurePayload,
      safetyItemEndorsed,
      maxScoreForMeasure,
    } = await import("../src/measures");
    expect(INSTRUMENTS.gad7.items).toBe(7);
    expect(INSTRUMENTS.phq2.items).toBe(2);
    // Score ceilings clamp per instrument, never the phq9 scale.
    expect(measureScore("gad7", [3, 3, 3, 3, 3, 3, 3])).toBe(21);
    expect(measureScore("gad7", [2, 2, 2, 2, 2, 2, 2])).toBe(14);
    expect(measureScore("phq2", [3, 3])).toBe(6);
    expect(measureScore("phq2", [1, 2])).toBe(3);
    // Completion gates per item count.
    expect(measureComplete("gad7", [0, 0, 0, 0, 0, 0, 0])).toBe(true);
    expect(measureComplete("gad7", [0, 0, 0, 0, 0, 0, null])).toBe(false);
    expect(measureComplete("phq2", [0, 1])).toBe(true);
    // Only the PHQ-9 carries a safety item.
    expect(safetyItemEndorsed("gad7", [3, 3, 3, 3, 3, 3, 3])).toBe(false);
    expect(safetyItemEndorsed("phq2", [3, 3])).toBe(false);
    expect(safetyItemEndorsed("phq9", [0, 0, 0, 0, 0, 0, 0, 0, 1])).toBe(true);
    // The payload names its instrument (the portal groups by it) — and only
    // the PHQ-9 carries item9 (GAD-7/PHQ-2 have no safety item; their
    // payloads never gain the field).
    const gad = JSON.parse(measurePayload("gad7", [1, 1, 1, 1, 1, 1, 1], "2026-09-21"));
    expect(gad).toEqual({ v: 1, measure: "gad7", score: 7, completed_at: "2026-09-21" });
    expect("item9" in gad).toBe(false);
    const phq2 = JSON.parse(measurePayload("phq2", [2, 1], "2026-09-21"));
    expect(phq2).toEqual({ v: 1, measure: "phq2", score: 3, completed_at: "2026-09-21" });
    expect("item9" in phq2).toBe(false);
    // History clamping is instrument-aware; unknown names skip.
    expect(maxScoreForMeasure("gad7")).toBe(21);
    expect(maxScoreForMeasure("phq2")).toBe(6);
    expect(maxScoreForMeasure("future-instrument")).toBeNull();
    expect(maxScoreForMeasure(42)).toBeNull();
    // 2026-09-26 audit LOW: inherited property names must read as unknown —
    // `"constructor" in INSTRUMENTS` used to return undefined (≠ null),
    // defeating the caller's null gate and producing a NaN share.
    expect(maxScoreForMeasure("constructor")).toBeNull();
    expect(maxScoreForMeasure("toString")).toBeNull();
    expect(maxScoreForMeasure("__proto__")).toBeNull();
    // Every instrument's item copy exists in BOTH locale catalogs.
    const { enCatalog, esCatalog } = await import("../src/strings");
    for (const id of ["phq9", "gad7", "phq2"] as const) {
      for (let i = 1; i <= INSTRUMENTS[id].items; i++) {
        expect(enCatalog[`measures.${id}.item${i}`]?.length).toBeGreaterThan(10);
        expect(esCatalog[`measures.${id}.item${i}`]?.length).toBeGreaterThan(10);
      }
      expect(enCatalog[`measures.select.${id}`]?.length).toBeGreaterThan(5);
      expect(esCatalog[`measures.select.${id}`]?.length).toBeGreaterThan(5);
    }
    for (const v of [0, 1, 2, 3]) {
      expect(enCatalog[`measures.option${v}`]?.length).toBeGreaterThan(3);
      expect(esCatalog[`measures.option${v}`]?.length).toBeGreaterThan(3);
    }
  });

  it("phq9.ts owns structure only — display copy lives in the locale catalogs", async () => {
    // The item list still has exactly nine entries and the scorer, gates
    // and payload contract are untouched by the i18n move.
    expect(PHQ9_ITEMS).toHaveLength(9);
    expect(phq9Score([3, 3, 3, 3, 3, 3, 3, 3, 3])).toBe(27);
    const { t } = await import("../src/strings");
    for (let i = 1; i <= 9; i++) {
      expect(t(`measures.phq9.item${i}`).length).toBeGreaterThan(10);
    }
    for (const v of [0, 1, 2, 3]) {
      expect(t(`measures.phq9.option${v}`).length).toBeGreaterThan(3);
    }
  });
});

describe("MeasuresScreen status line auto-clears (2026-09-26 audit LOW)", () => {
  it("a transient status clears itself after the app-wide 2.6s inline-status lifetime", async () => {
    // An offline submit failure raises the inline status (see the retry-
    // affordance test above); the same line must not linger forever.
    vi.mocked(api.createMeasure).mockRejectedValueOnce(new ApiError(0, "offline"));
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    for (let i = 0; i < PHQ9_ITEMS.length; i++) {
      await pressOption(root, `Question ${i + 1}: Not at all`);
    }
    // Fake timers BEFORE the submit, so the dismissal timer registers on the
    // fake clock and can be advanced deterministically (the submit path is
    // promise-only; flush() after the press would deadlock under fakes) —
    // the InsightsScreen auto-dismiss idiom.
    vi.useFakeTimers();
    try {
      await pressLabel(root, "Record this check-in");
      expect(textOf(root)).toContain("Your picks are still on screen.");
      const { act } = await import("./helpers/rtr");
      await act(async () => {
        vi.advanceTimersByTime(2_600);
      });
      expect(textOf(root)).not.toContain("Your picks are still on screen.");
    } finally {
      vi.useRealTimers();
    }
  });
});

// 2026-09-26 audit LOW: completed answers must survive a failed send and
// the screen unmounting (offline submit, or the vault lock a background
// triggers) — persisted {kind, clientMeasureId, picks, date} under the
// data key, retried on the next mount under the SAME client_measure_id
// (POST /measures is idempotent by that id server-side).
describe("MeasuresScreen pending-measure persistence (2026-09-26 audit LOW)", () => {
  /** Complete the nine PHQ-9 items with zeros and submit. */
  async function completeAndSubmit(root: Awaited<ReturnType<typeof render>>): Promise<void> {
    for (let i = 0; i < PHQ9_ITEMS.length; i++) {
      await pressOption(root, `Question ${i + 1}: Not at all`);
    }
    await pressLabel(root, "Record this check-in");
    await flush();
  }

  it("offline fail → remount → restores the picks and retries under the SAME id → clears the record", async () => {
    const { loadPendingMeasure } = await import("../src/pendingMeasure");
    // First mount: the send fails offline.
    vi.mocked(api.createMeasure).mockRejectedValueOnce(new ApiError(0, "offline"));
    const first = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    await completeAndSubmit(first);
    expect(api.createMeasure).toHaveBeenCalledTimes(1);
    const firstId = (vi.mocked(api.createMeasure).mock.calls[0] as unknown as [string])[0];
    expect(textOf(first)).toContain("Recording needs a connection right now.");
    // The completed record is durable, encrypted under the data key.
    const stored = await loadPendingMeasure(dataKey, USER);
    expect(stored).toMatchObject({ kind: "phq9", clientMeasureId: firstId, date: stored?.date });
    expect(stored?.picks).toEqual(PHQ9_ITEMS.map(() => 0));
    // Remount (app restart / relock after backgrounding): the mount retry
    // restores the answers and re-sends the SAME idempotency key.
    await act(async () => {
      first.unmount();
    });
    vi.mocked(api.createMeasure).mockResolvedValue({} as never);
    const second = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(api.createMeasure).toHaveBeenCalledTimes(2);
    expect((vi.mocked(api.createMeasure).mock.calls[1] as unknown as [string])[0]).toBe(firstId);
    // Success clears the record and resets the answers (Record disabled
    // again until every item is re-answered).
    expect(await loadPendingMeasure(dataKey, USER)).toBeNull();
    expect(touchableByLabel(second, "Record this check-in").props.disabled).toBe(true);
    expect(textOf(second)).toContain("Recorded — encrypted, as always.");
  });

  it("a retry that answers 409 (the first send HAD landed) is 'already recorded' and clears the record too", async () => {
    const { loadPendingMeasure } = await import("../src/pendingMeasure");
    vi.mocked(api.createMeasure).mockRejectedValueOnce(new ApiError(0, "offline"));
    const first = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    await completeAndSubmit(first);
    await act(async () => {
      first.unmount();
    });
    // The offline failure was a timeout AFTER the server committed: the
    // retry answers 409, which must read as recorded — not as an error,
    // and not as a reason to keep retrying every mount.
    vi.mocked(api.createMeasure).mockRejectedValueOnce(
      Object.assign(new ApiError(409, "measure already exists"), { code: "conflict" }),
    );
    const second = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(api.createMeasure).toHaveBeenCalledTimes(2);
    expect(textOf(second)).toContain("Already recorded — refreshing.");
    expect(await loadPendingMeasure(dataKey, USER)).toBeNull();
    expect(touchableByLabel(second, "Record this check-in").props.disabled).toBe(true);
  });

  it("a manual re-tap after an offline failure reuses the SAME id (idempotent retry affordance)", async () => {
    vi.mocked(api.createMeasure).mockRejectedValueOnce(new ApiError(0, "offline"));
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    await completeAndSubmit(root);
    // Connectivity returns; the same tap re-submits the same picks under
    // the same id — a fresh id here could record the answers twice.
    vi.mocked(api.createMeasure).mockResolvedValue({} as never);
    await pressLabel(root, "Record this check-in");
    await flush();
    expect(api.createMeasure).toHaveBeenCalledTimes(2);
    const ids = (vi.mocked(api.createMeasure).mock.calls as unknown as [string][])
      .map((call) => call[0]);
    expect(new Set(ids).size).toBe(1);
    expect(textOf(root)).toContain("Recorded — encrypted, as always.");
  });

  // 2026-09-27 item9 contract: the pending record's PICKS are the single
  // source of the payload (item9 = picks[8]) — every attempt of one
  // questionnaire, including the mount-retry of a persisted record, must
  // ship the SAME item9 the user picked (no drift between attempts).
  it("a persisted pending record re-derives item9 from the SAME picks on every retry", async () => {
    const { loadPendingMeasure } = await import("../src/pendingMeasure");
    vi.mocked(api.createMeasure).mockRejectedValueOnce(new ApiError(0, "offline"));
    const first = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    for (let i = 0; i < PHQ9_ITEMS.length; i++) {
      await pressOption(first, `Question ${i + 1}: ${i === 8 ? "More than half the days" : "Not at all"}`);
    }
    await pressLabel(first, "Record this check-in");
    await flush();
    const stored = await loadPendingMeasure(dataKey, USER);
    expect(stored?.picks[8]).toBe(2);
    // The first (failed) attempt's payload carried item9 = 2 from the picks.
    const firstBlob = (vi.mocked(api.createMeasure).mock.calls[0] as unknown as [string, string])[1];
    const firstPlain = JSON.parse(
      decrypt(dataKey, Buffer.from(firstBlob, "base64"), buildAad("measure", USER, stored!.clientMeasureId)).toString("utf8"),
    ) as { item9?: number };
    expect(firstPlain.item9).toBe(2);
    // Remount → the retry restores the SAME picks and ships the SAME item9.
    await act(async () => {
      first.unmount();
    });
    vi.mocked(api.createMeasure).mockResolvedValue({} as never);
    const second = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(api.createMeasure).toHaveBeenCalledTimes(2);
    const retryBlob = (vi.mocked(api.createMeasure).mock.calls[1] as unknown as [string, string])[1];
    const retryPlain = JSON.parse(
      decrypt(dataKey, Buffer.from(retryBlob, "base64"), buildAad("measure", USER, stored!.clientMeasureId)).toString("utf8"),
    ) as { item9?: number };
    expect(retryPlain.item9).toBe(2);
    expect(retryPlain.item9).toBe(stored?.picks[8]);
  });

  // The storage discipline (reminders.ts idiom): everything read back from
  // storage is validated in full — a hostile or half-written record is
  // null, never an out-of-range pick reaching the send path.
  describe("pendingMeasure storage discipline", () => {
    const good = {
      kind: "phq9",
      clientMeasureId: "m-2026-09-26-abc",
      picks: PHQ9_ITEMS.map(() => 2),
      date: "2026-09-26",
    };

    function plant(raw: string): Promise<void> {
      return storage.setItem(`@mindpattern/pending_measure_${USER}`, raw);
    }

    it("round-trips under the data key and refuses every other key", async () => {
      const { savePendingMeasure, loadPendingMeasure } = await import("../src/pendingMeasure");
      await savePendingMeasure(dataKey, USER, good);
      expect(await loadPendingMeasure(dataKey, USER)).toEqual(good);
      // A different key (account switch / rotation) never reads it…
      expect(await loadPendingMeasure(Buffer.alloc(32, 8), USER)).toBeNull();
      // …and tampered bytes at the slot read as absent, never as a guess.
      await plant("AAAA");
      expect(await loadPendingMeasure(dataKey, USER)).toBeNull();
    });

    it("corrupt/foreign records degrade to null (never a partial questionnaire)", async () => {
      const { loadPendingMeasure } = await import("../src/pendingMeasure");
      const seal = (value: unknown): Promise<void> =>
        plant(
          encrypt(dataKey, Buffer.from(JSON.stringify(value), "utf8"), buildAad("pending-measure", USER)).toString("base64"),
        );
      // A valid envelope with a hostile/half-written RECORD inside: each
      // violates the instrument contract and must read as absent.
      for (const bad of [
        { ...good, kind: "not-an-instrument" },
        { ...good, clientMeasureId: "" },
        { ...good, clientMeasureId: "x".repeat(129) },
        { ...good, picks: [0, 0] }, // wrong item count
        { ...good, picks: PHQ9_ITEMS.map(() => 9) }, // off the 0..3 scale
        { ...good, picks: PHQ9_ITEMS.map(() => Number.NaN) },
        { ...good, date: "09/26/2026" }, // not ISO date-granular
        { kind: 42, clientMeasureId: "m-1", picks: [0], date: "2026-09-26" },
      ]) {
        await seal(bad);
        expect(await loadPendingMeasure(dataKey, USER)).toBeNull();
      }
      // And the wrong AAD context (a blob sealed for another purpose):
      await plant(
        encrypt(dataKey, Buffer.from(JSON.stringify(good), "utf8"), buildAad("measure", USER, good.clientMeasureId)).toString("base64"),
      );
      expect(await loadPendingMeasure(dataKey, USER)).toBeNull();
    });
  });
});
