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
  return { ApiError, api: makeApiMock() };
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
    expect(payload).toEqual({ v: 1, measure: "phq9", score: 9, completed_at: "2026-09-19" });
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
    expect(textOf(root)).toContain("2026-09-18: 9");
    expect(textOf(root)).toContain("2026-09-11: 14");
    expect(textOf(root)).toContain("never interprets it");
  });

  it("an unreadable row degrades to a skipped entry, never a crash", async () => {
    vi.mocked(api.listMeasures).mockResolvedValue([
      { client_measure_id: "m-x", blob: "AAAA", measure_date: "2026-09-18" },
      measureRow("m-1", 5, "2026-09-11"),
    ] as never);
    const root = await render(<MeasuresScreen navigation={{ navigate: vi.fn(), goBack: vi.fn() }} />);
    await flush();
    expect(textOf(root)).toContain("2026-09-11: 5");
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
      v: 1, measure: "phq9", score: 2, completed_at: date,
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
    // Save failed offline: the dialog must NOT have fired (never before saving).
    expect(Alert.alert).toHaveBeenCalledWith("Not recorded", expect.stringContaining("connection"));
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
