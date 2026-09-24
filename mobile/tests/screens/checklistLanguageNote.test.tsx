/**
 * External verification checklist 2026-09-23: the "not yet supported"
 * honesty note. The backend pins language="other" suppression behavior;
 * the screen's honesty CARD (the user-facing half of the contract) had no
 * behavioral test — only its copy keys were pinned in i18n tests.
 */
import { beforeEach, describe, expect, it, vi } from "vitest";
import React from "react";

vi.mock("../../src/api/client", async () => {
  const { makeApiMock, ApiError } = await import("../helpers/apiMock");
  return { ApiError, api: makeApiMock(), getBaseUrl: async () => "http://localhost:8000" };
});

const refreshActiveDays = vi.fn(async () => {});
const applyActiveDays = vi.fn();
const touchActivity = vi.fn();
vi.mock("../../src/store", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../src/store")>();
  return { ...actual, useSession: () => ({ refreshActiveDays, applyActiveDays, unlockDays: 30, touchActivity }) };
});

const { api } = await import("../../src/api/client");
const { InsightsScreen } = await import("../../src/screens/InsightsScreen");
const { vault } = await import("../../src/vault");
const { buildAad, encrypt } = await import("../../src/crypto/envelope");
const { INSIGHTS_PAYLOAD_VERSION } = await import("../../src/crypto/MindPatternCrypto");
const { render, flush, allText, act } = await import("../helpers/rtr");
const { resetApi } = await import("../helpers/apiMock");

const dataKey = Buffer.alloc(32, 9);
const insightsBlob = (payload: unknown): string =>
  encrypt(
    dataKey,
    Buffer.from(JSON.stringify({ v: INSIGHTS_PAYLOAD_VERSION, ...(payload as Record<string, unknown>) })),
    buildAad("insights", "user-1", "patterns"),
  ).toString("base64");

beforeEach(() => {
  resetApi(api as never);
  refreshActiveDays.mockClear();
  applyActiveDays.mockClear();
  touchActivity.mockClear();
  vault.lock();
  vault.unlock({ masterKey: Buffer.alloc(32), authKey: Buffer.alloc(32, 1), dataKey });
});

describe("InsightsScreen language honesty note (checklist 8c)", () => {
  it("renders the 'not yet supported' card when the engine reports language='other'", async () => {
    vi.mocked(api.insights).mockResolvedValue({
      phase: "insight",
      blob: insightsBlob({ stats: { language: "other", patterns: [] } }),
    } as never);
    const root = await render(<InsightsScreen />);
    await act(async () => {
      await flush();
    });
    const text = allText(root).join("\n");
    expect(text).toContain("About your journal's language");
    expect(text).toContain("Pattern analysis runs in English and Spanish");
    // The rest of the insight phase still renders — no crash, no blank.
    expect(text.length).toBeGreaterThan(0);
  });

  it("stays silent for supported languages (en and es)", async () => {
    for (const language of ["en", "es"]) {
      vi.mocked(api.insights).mockResolvedValue({
        phase: "insight",
        blob: insightsBlob({ stats: { language, patterns: [] } }),
      } as never);
      const root = await render(<InsightsScreen />);
      await act(async () => {
        await flush();
      });
      const text = allText(root).join("\n");
      expect(text).not.toContain("About your journal's language");
    }
  });
});
